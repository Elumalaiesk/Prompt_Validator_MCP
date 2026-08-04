"""Admin tools (tag: "admin") — manage RBAC, users, tokens and JWTs at runtime.

The RBAC data operations delegate to `rbac.service`, the same layer the web
dashboard uses, so tool and dashboard behaviour never diverge.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..audit import record
from ..db.base import session_scope
from ..db.models import ApiToken
from ..identity import current_identity
from ..rbac import service as rbac_service
from ..skills.registry import register_skill


def register_admin_tools(mcp: Any) -> None:
    async def list_roles() -> list[dict]:
        """List the two fixed roles (admin, std_user) and their admin flag."""
        return await rbac_service.list_roles()

    async def list_users() -> list[dict]:
        """List all users with role, active flag, and token count."""
        return await rbac_service.list_users()

    async def create_user(username: str, role_name: str = "std_user", email: str | None = None) -> dict:
        """Create a user (defaults to the std_user role)."""
        result = await rbac_service.create_user(username, role_name, email)
        await _audit("admin.create_user", {"username": username, "role": role_name})
        return result

    async def mint_user_token(username: str, token_name: str = "default") -> dict:
        """Mint a permanent OPAQUE token for a user (auth_mode="opaque"). Returned
        once; only the hash is stored."""
        result = await rbac_service.mint_opaque_token(username, token_name)
        await _audit("admin.mint_token", {"username": username, "token_name": token_name})
        return result

    async def revoke_token(token_id: int) -> dict:
        """Revoke an opaque token by id (takes effect immediately)."""
        async with session_scope() as session:
            tok = await session.get(ApiToken, token_id)
            if tok is None:
                return {"ok": False, "error": f"token {token_id} not found"}
            tok.revoked_at = datetime.now(timezone.utc)
        await _audit("admin.revoke_token", {"token_id": token_id})
        return {"ok": True, "token_id": token_id}

    # --- JWT management (auth_mode="jwt") ---------------------------------
    async def issue_user_jwt(
        username: str, ttl_seconds: int | None = None, name: str = "default"
    ) -> dict:
        """Issue a signed JWT for a user. Returned ONCE. Claims encode the user's
        role and permitted tags, so access is enforced per-user."""
        from ..auth.jwt_service import issue_for_user

        result = await issue_for_user(username, name=name, ttl_seconds=ttl_seconds)
        await _audit(
            "admin.issue_jwt",
            {"username": username, "name": name, "jti": result.get("jti"), "ok": result["ok"]},
        )
        return result

    async def list_user_jwts(username: str | None = None) -> list[dict]:
        """List issued JWT grants (optionally filtered by username)."""
        from ..auth.jwt_service import list_grants

        return await list_grants(username)

    async def revoke_jwt(jti: str) -> dict:
        """Revoke an issued JWT by its jti (denylisted within the cache TTL)."""
        from ..auth.revocation import revoke_jti

        ok = await revoke_jti(jti)
        await _audit("admin.revoke_jwt", {"jti": jti, "ok": ok})
        return {"ok": ok, "jti": jti}

    for fn, name in [
        (list_roles, "list_roles"),
        (list_users, "list_users"),
        (create_user, "create_user"),
        (mint_user_token, "mint_user_token"),
        (revoke_token, "revoke_token"),
        (issue_user_jwt, "issue_user_jwt"),
        (list_user_jwts, "list_user_jwts"),
        (revoke_jwt, "revoke_jwt"),
    ]:
        register_skill(mcp, fn, name=name, tags={"admin"})


async def _audit(action: str, detail: dict) -> None:
    ident = current_identity()
    await record(
        action=action,
        username=ident.get("username"),
        token_id=ident.get("token_id"),
        decision="ok",
        detail=detail,
    )
