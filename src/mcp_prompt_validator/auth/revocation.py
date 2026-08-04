"""JWT revocation denylist.

JWTs are stateless, so revocation needs a server-side signal. We keep the set of
revoked `jti`s (from `jwt_grants.revoked_at`) in memory, refreshed at most every
`ttl` seconds, so the per-request check is a cheap set membership test rather
than a database round-trip.
"""

from __future__ import annotations

import time

from sqlalchemy import select, update

from ..db.base import session_scope
from ..db.models import JwtGrant


class RevocationCache:
    def __init__(self, ttl: float = 30.0) -> None:
        self.ttl = ttl
        self._revoked: set[str] = set()
        self._loaded_at: float = 0.0

    async def _refresh(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and self._loaded_at and (now - self._loaded_at) < self.ttl:
            return
        async with session_scope() as session:
            rows = await session.execute(
                select(JwtGrant.jti).where(JwtGrant.revoked_at.is_not(None))
            )
            self._revoked = {r[0] for r in rows.all()}
        self._loaded_at = now

    async def is_revoked(self, jti: str | None) -> bool:
        if not jti:
            return False
        await self._refresh()
        return jti in self._revoked


async def revoke_jti(jti: str) -> bool:
    """Mark a jti revoked. Returns True if a matching grant was updated."""
    async with session_scope() as session:
        result = await session.execute(
            update(JwtGrant)
            .where(JwtGrant.jti == jti, JwtGrant.revoked_at.is_(None))
            .values(revoked_at=_now())
        )
        return (result.rowcount or 0) > 0


def _now():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)
