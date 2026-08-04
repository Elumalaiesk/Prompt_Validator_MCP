"""Seed the two fixed roles (admin, std_user) and an initial admin user + credential.

Idempotent. Prints a freshly issued admin credential (shown once):
  * auth_mode="jwt"    -> a signed admin JWT;
  * auth_mode="opaque" -> an opaque permanent token.

Usage:
    python -m mcp_prompt_validator.scripts.seed
    mpv-seed
"""

from __future__ import annotations

import asyncio
import secrets

from sqlalchemy import select

from ..auth.passwords import hash_password
from ..auth.tokens import mint_token
from ..config import get_settings
from ..db.base import create_all, dispose_engine, session_scope
from ..db.models import ApiToken, Role, User

# role name -> is_admin. Only two roles exist: admin bypasses all tool gating;
# std_user may call anything not tagged "admin" (skills/registry.py).
DEFAULT_ROLES: dict[str, bool] = {
    "admin": True,
    "std_user": False,
}


async def _ensure_roles_and_admin() -> str | None:
    """Ensure roles + the admin user exist. Returns a freshly generated admin
    dashboard password if one was just set, else None (nothing changed)."""
    generated_password: str | None = None
    async with session_scope() as session:
        for name, is_admin in DEFAULT_ROLES.items():
            role = (
                await session.execute(select(Role).where(Role.name == name))
            ).scalar_one_or_none()
            if role is None:
                session.add(Role(name=name, is_admin=is_admin, description=f"{name} role"))

        admin_role = (
            await session.execute(select(Role).where(Role.name == "admin"))
        ).scalar_one()
        admin = (
            await session.execute(select(User).where(User.username == "admin"))
        ).scalar_one_or_none()
        if admin is None:
            generated_password = secrets.token_urlsafe(12)
            session.add(
                User(
                    username="admin",
                    email=None,
                    role_id=admin_role.id,
                    password_hash=hash_password(generated_password),
                )
            )
        elif admin.password_hash is None:
            generated_password = secrets.token_urlsafe(12)
            admin.password_hash = hash_password(generated_password)

    return generated_password


async def _bootstrap_credential() -> None:
    settings = get_settings()
    if settings.auth_mode == "jwt":
        from ..auth.jwt_service import issue_for_user, list_grants

        if await list_grants("admin"):
            print("Admin already has JWT grants; skipping issue.")
            return
        result = await issue_for_user("admin", name="bootstrap")
        if result.get("ok"):
            print("\n=== Bootstrap admin JWT (store now; shown once) ===")
            print(result["token"])
            print(f"alg={result['algorithm']} jti={result['jti']} exp={result['expires_at']}")
            print("===================================================\n")
        else:
            print(f"Failed to issue admin JWT: {result.get('error')}")
        return

    # opaque mode
    async with session_scope() as session:
        admin = (
            await session.execute(select(User).where(User.username == "admin"))
        ).scalar_one()
        has_token = (
            await session.execute(select(ApiToken).where(ApiToken.user_id == admin.id))
        ).first()
        if has_token is not None:
            print("Admin already has a token; skipping mint.")
            return
        minted = mint_token(settings.token_prefix)
        session.add(
            ApiToken(
                user_id=admin.id,
                name="bootstrap",
                token_hash=minted.token_hash,
                prefix=minted.prefix,
            )
        )
        print("\n=== Bootstrap admin token (store now; shown once) ===")
        print(minted.plaintext)
        print("=====================================================\n")


async def _seed() -> None:
    await create_all()
    generated_password = await _ensure_roles_and_admin()
    await _bootstrap_credential()
    if generated_password:
        print("\n=== Bootstrap admin dashboard password (store now; shown once) ===")
        print(f"username=admin  password={generated_password}")
        print("=====================================================================\n")
    await dispose_engine()
    print("Seed complete. Roles:", ", ".join(DEFAULT_ROLES))


def main() -> None:
    asyncio.run(_seed())


if __name__ == "__main__":
    main()
