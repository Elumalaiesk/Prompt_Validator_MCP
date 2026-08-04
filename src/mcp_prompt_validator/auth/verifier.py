"""DatabaseTokenVerifier — the custom FastMCP TokenVerifier for permanent keys.

This keeps the MCP server strictly a Resource Server (validate-only): it never
issues tokens, it only verifies inbound bearer credentials against the database.

On each request FastMCP calls `verify_token(token)`; we:
  1. hash the presented token and look it up (indexed, single query);
  2. reject if unknown, revoked, expired, or the user is inactive;
  3. enforce the audience (the token's resource must match this server);
  4. load the user's role + permitted tool tags and encode them into scopes;
  5. return an AccessToken carrying identity (claims/subject) + authz (scopes).

Loading permissions per request (rather than caching) makes both revocation and
permission changes take effect immediately.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from ..db.base import session_scope
from ..db.models import ApiToken, User
from ..logging_setup import get_logger
from ._compat import AccessToken, TokenVerifier, build_access_token
from .scopes import encode_scopes
from .tokens import hash_token

log = get_logger(__name__)


class DatabaseTokenVerifier(TokenVerifier):
    """Validate opaque permanent tokens against the database."""

    def __init__(
        self,
        *,
        resource_server_url: str,
        required_scopes: list[str] | None = None,
    ) -> None:
        # FastMCP's TokenVerifier base has varied constructor signatures across
        # versions; initialise it defensively and keep our own attributes too.
        try:
            super().__init__(required_scopes=required_scopes)  # type: ignore[call-arg]
        except TypeError:
            try:
                super().__init__()  # type: ignore[misc]
            except Exception:  # pragma: no cover
                pass
        self.resource_server_url = resource_server_url
        self.required_scopes = required_scopes or []

    async def verify_token(self, token: str) -> AccessToken | None:
        token_hash = hash_token(token)
        now = datetime.now(timezone.utc)

        async with session_scope() as session:
            stmt = (
                select(ApiToken)
                .where(ApiToken.token_hash == token_hash)
                .options(selectinload(ApiToken.user).selectinload(User.role))
            )
            token_row = (await session.execute(stmt)).scalar_one_or_none()

            if token_row is None:
                log.info("auth: unknown token (prefix lookup miss)")
                return None
            if token_row.revoked_at is not None:
                log.info("auth: revoked token id=%s", token_row.id)
                return None
            if token_row.expires_at is not None and _aware(token_row.expires_at) <= now:
                log.info("auth: expired token id=%s", token_row.id)
                return None

            user = token_row.user
            if user is None or not user.is_active:
                log.info("auth: inactive/missing user for token id=%s", token_row.id)
                return None

            role = user.role
            scopes = encode_scopes(role.name, role.is_admin)

            # Best-effort last-used timestamp (committed by session_scope).
            token_row.last_used_at = now

            claims = {
                "sub": str(user.id),
                "username": user.username,
                "role": role.name,
                "email": user.email,
                "token_id": token_row.id,
                "token_name": token_row.name,
            }

            log.debug("auth: ok user=%s role=%s", user.username, role.name)
            return build_access_token(
                token=token,
                client_id=user.username,
                scopes=scopes,
                expires_at=(
                    int(_aware(token_row.expires_at).timestamp())
                    if token_row.expires_at
                    else None
                ),
                resource=self.resource_server_url,
                subject=str(user.id),
                claims=claims,
            )


def _aware(dt: datetime) -> datetime:
    """Treat naive DB timestamps as UTC so comparisons never raise."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
