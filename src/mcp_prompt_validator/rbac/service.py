"""RBAC data operations shared by the MCP admin tools and the web dashboard.

One source of truth so the tool surface and the dashboard never diverge. Only
two roles exist: "admin" (bypasses all tool gating) and "std_user" (may call
any tool not tagged "admin" — see `skills/registry.py::tool_permitted`). There
is no per-role tag editing; role only distinguishes admin vs everyone else.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from ..auth.passwords import hash_password, verify_password
from ..auth.tokens import mint_token
from ..config import get_settings
from ..db.base import session_scope
from ..db.models import ApiToken, Role, User


async def list_roles() -> list[dict]:
    async with session_scope() as session:
        rows = (await session.execute(select(Role))).scalars().all()
        return [
            {"name": r.name, "is_admin": r.is_admin, "description": r.description}
            for r in rows
        ]


async def list_users() -> list[dict]:
    async with session_scope() as session:
        rows = (
            await session.execute(select(User).options(selectinload(User.role)))
        ).scalars().all()
        out = []
        for u in rows:
            role = u.role
            tokens = (
                await session.execute(
                    select(func.count(ApiToken.id)).where(ApiToken.user_id == u.id)
                )
            ).scalar_one()
            out.append(
                {
                    "id": u.id,
                    "username": u.username,
                    "email": u.email,
                    "role": role.name,
                    "is_admin": role.is_admin,
                    "is_active": u.is_active,
                    "tokens": tokens,
                    "has_password": bool(u.password_hash),
                    "required_template": u.required_template,
                }
            )
        return out


async def create_user(
    username: str,
    role_name: str = "std_user",
    email: str | None = None,
    password: str | None = None,
) -> dict:
    async with session_scope() as session:
        role = await _role_by_name(session, role_name)
        if role is None:
            return {"ok": False, "error": f"role '{role_name}' not found"}
        dup = (
            await session.execute(select(User).where(User.username == username))
        ).scalar_one_or_none()
        if dup is not None:
            return {"ok": False, "error": f"user '{username}' already exists"}
        session.add(
            User(
                username=username,
                email=email,
                role_id=role.id,
                password_hash=hash_password(password) if password else None,
            )
        )
    return {"ok": True, "username": username, "role": role_name}


async def mint_opaque_token(username: str, token_name: str = "default") -> dict:
    """Mint a permanent OPAQUE token for a user (auth_mode="opaque"). Returned
    once; only the hash is stored. Shared by the admin tool and the dashboard."""
    settings = get_settings()
    async with session_scope() as session:
        user = (
            await session.execute(select(User).where(User.username == username))
        ).scalar_one_or_none()
        if user is None:
            return {"ok": False, "error": f"user '{username}' not found"}
        minted = mint_token(settings.token_prefix)
        session.add(
            ApiToken(
                user_id=user.id,
                name=token_name,
                token_hash=minted.token_hash,
                prefix=minted.prefix,
            )
        )
    return {
        "ok": True,
        "username": username,
        "token": minted.plaintext,
        "prefix": minted.prefix,
        "warning": "Store this now; it will not be shown again.",
    }


async def verify_dashboard_login(username: str, password: str) -> dict | None:
    """Check a username/password pair for dashboard sign-in.

    Returns {"username", "role", "is_admin"} on success, None otherwise. Only
    admin-role users may sign in — the dashboard is an admin surface.
    """
    async with session_scope() as session:
        user = (
            await session.execute(
                select(User).options(selectinload(User.role)).where(User.username == username)
            )
        ).scalar_one_or_none()
        if user is None or not user.is_active or not verify_password(password, user.password_hash):
            return None
        if not user.role.is_admin:
            return None
        return {"username": user.username, "role": user.role.name, "is_admin": True}


async def set_password(username: str, password: str) -> dict:
    if not password or len(password) < 8:
        return {"ok": False, "error": "password must be at least 8 characters"}
    async with session_scope() as session:
        user = (
            await session.execute(select(User).where(User.username == username))
        ).scalar_one_or_none()
        if user is None:
            return {"ok": False, "error": f"user '{username}' not found"}
        user.password_hash = hash_password(password)
    return {"ok": True, "username": username}


async def get_required_template(username: str) -> str | None:
    """The template every prompt from `username` must conform to, or None.

    Called on every validation request, so it stays a single indexed lookup on
    `users.username` and returns None for unknown users rather than raising —
    an unresolvable caller must not take the validation path down with it.
    """
    if not username:
        return None
    async with session_scope() as session:
        return (
            await session.execute(
                select(User.required_template).where(User.username == username)
            )
        ).scalar_one_or_none()


async def set_required_template(username: str, template_name: str | None) -> dict:
    """Make `template_name` mandatory for `username` (None clears it).

    The template is validated as visible to that user at assignment time, so a
    typo surfaces here in the dashboard rather than as a permanent block on
    every prompt the user sends.
    """
    from ..prompts import service as prompt_service

    name = (template_name or "").strip() or None
    # Resolved before opening the write session — `get_for_user` opens its own.
    if name is not None and await prompt_service.get_for_user(name, username) is None:
        return {
            "ok": False,
            "error": f"template '{name}' is not enabled or not visible to '{username}'",
        }
    async with session_scope() as session:
        user = (
            await session.execute(select(User).where(User.username == username))
        ).scalar_one_or_none()
        if user is None:
            return {"ok": False, "error": f"user '{username}' not found"}
        user.required_template = name
    return {"ok": True, "username": username, "required_template": name}


async def _role_by_name(session, name: str) -> Role | None:
    return (
        await session.execute(select(Role).where(Role.name == name))
    ).scalar_one_or_none()
