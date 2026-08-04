"""Issue / list JWT grants for users (used by the admin tool and the CLI)."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from ..config import get_settings
from ..db.base import session_scope
from ..db.models import JwtGrant, User
from .jwt_issuer import issue_jwt, new_jti
from .jwt_keys import get_key_material


async def issue_for_user(
    username: str, name: str = "default", ttl_seconds: int | None = None
) -> dict:
    """Mint a JWT for `username`. Returns the token once, plus its metadata."""
    settings = get_settings()
    sign_key, _verify = get_key_material(settings)
    ttl = settings.jwt_default_ttl if ttl_seconds is None else ttl_seconds

    async with session_scope() as session:
        user = (
            await session.execute(
                select(User).where(User.username == username).options(selectinload(User.role))
            )
        ).scalar_one_or_none()
        if user is None:
            return {"ok": False, "error": f"user '{username}' not found"}
        if not user.is_active:
            return {"ok": False, "error": f"user '{username}' is inactive"}

        role = user.role
        jti = new_jti()
        issued = issue_jwt(
            sign_key=sign_key,
            algorithm=settings.jwt_algorithm,
            issuer=settings.jwt_issuer,
            audience=settings.effective_audience,
            subject=str(user.id),
            username=user.username,
            email=user.email,
            role_name=role.name,
            is_admin=role.is_admin,
            ttl_seconds=ttl,
            jti=jti,
            name=name,
        )
        expires_dt = (
            datetime.fromtimestamp(issued.expires_at, tz=timezone.utc)
            if issued.expires_at
            else None
        )
        session.add(JwtGrant(jti=jti, user_id=user.id, name=name, expires_at=expires_dt))

    return {
        "ok": True,
        "username": username,
        "role": role.name,
        "token": issued.token,
        "jti": jti,
        "expires_at": issued.expires_at,
        "algorithm": settings.jwt_algorithm,
    }


async def list_grants(username: str | None = None) -> list[dict]:
    async with session_scope() as session:
        rows = (
            await session.execute(select(JwtGrant).options(selectinload(JwtGrant.user)))
        ).scalars().all()
        out = []
        for g in rows:
            uname = g.user.username if g.user else None
            if username and uname != username:
                continue
            out.append(
                {
                    "jti": g.jti,
                    "username": uname,
                    "name": g.name,
                    "issued_at": g.issued_at.isoformat() if g.issued_at else None,
                    "expires_at": g.expires_at.isoformat() if g.expires_at else None,
                    "revoked": g.is_revoked,
                }
            )
        return out
