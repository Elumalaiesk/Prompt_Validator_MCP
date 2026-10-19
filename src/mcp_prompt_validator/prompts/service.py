"""Prompt-template CRUD + per-user visibility, shared by dashboard and tools."""

from __future__ import annotations

from sqlalchemy import or_, select
from sqlalchemy.orm import selectinload

from ..db.base import session_scope
from ..db.models import PromptTemplate, User
from .render import declared_variables


def _to_dict(t: PromptTemplate, include_body: bool = True) -> dict:
    d = {
        "id": t.id,
        "name": t.name,
        "description": t.description,
        "owner_user_id": t.owner_user_id,
        "owner": t.owner.username if t.owner else None,
        "is_global": t.is_global,
        "enabled": t.enabled,
        "variables": declared_variables(t.body),
    }
    if include_body:
        d["body"] = t.body
    return d


async def list_all() -> list[dict]:
    """Every template (admin/dashboard view)."""
    async with session_scope() as session:
        rows = (
            await session.execute(
                select(PromptTemplate).options(selectinload(PromptTemplate.owner))
            )
        ).scalars().all()
        return [_to_dict(t) for t in rows]


async def list_for_user(username: str) -> list[dict]:
    """Templates a user may use: their own OR global, and enabled."""
    async with session_scope() as session:
        user = (
            await session.execute(select(User).where(User.username == username))
        ).scalar_one_or_none()
        user_id = user.id if user else None
        stmt = (
            select(PromptTemplate)
            .options(selectinload(PromptTemplate.owner))
            .where(
                PromptTemplate.enabled.is_(True),
                or_(
                    PromptTemplate.is_global.is_(True),
                    PromptTemplate.owner_user_id == user_id,
                ),
            )
        )
        rows = (await session.execute(stmt)).scalars().all()
        return [_to_dict(t) for t in rows]


async def get_for_user(name: str, username: str) -> dict | None:
    """Fetch one visible template (own or global) by name."""
    async with session_scope() as session:
        user = (
            await session.execute(select(User).where(User.username == username))
        ).scalar_one_or_none()
        user_id = user.id if user else None
        stmt = (
            select(PromptTemplate)
            .options(selectinload(PromptTemplate.owner))
            .where(
                PromptTemplate.name == name,
                PromptTemplate.enabled.is_(True),
                or_(
                    PromptTemplate.is_global.is_(True),
                    PromptTemplate.owner_user_id == user_id,
                ),
            )
            # Prefer a user's own template over a same-named global one.
            .order_by(PromptTemplate.owner_user_id.is_(None))
        )
        t = (await session.execute(stmt)).scalars().first()
        return _to_dict(t) if t else None


async def create(
    *,
    name: str,
    body: str,
    description: str = "",
    owner_username: str | None = None,
    is_global: bool = False,
    enabled: bool = True,
) -> dict:
    async with session_scope() as session:
        owner_id = None
        if owner_username:
            owner = (
                await session.execute(select(User).where(User.username == owner_username))
            ).scalar_one_or_none()
            if owner is None:
                return {"ok": False, "error": f"user '{owner_username}' not found"}
            owner_id = owner.id
        if not is_global and owner_id is None:
            return {"ok": False, "error": "template must have an owner or be global"}

        template = PromptTemplate(
            name=name,
            body=body,
            description=description,
            owner_user_id=owner_id,
            is_global=is_global,
            enabled=enabled,
        )
        session.add(template)
        await session.flush()
        tid = template.id
    return {"ok": True, "id": tid, "name": name, "is_global": is_global}


async def set_global(template_id: int, value: bool) -> dict:
    return await update(template_id, is_global=value)


async def set_enabled(template_id: int, value: bool) -> dict:
    return await update(template_id, enabled=value)


async def update(template_id: int, **fields) -> dict:
    """Patch the given columns on one template.

    `name` is deliberately not editable through the dashboard: users reference a
    template by name (`users.required_template` stores the name, not an FK — see
    `db/models.py`), so a rename would silently orphan every user pinned to it
    and block their every prompt. Callers pass description/body only.
    """
    async with session_scope() as session:
        t = await session.get(PromptTemplate, template_id)
        if t is None:
            return {"ok": False, "error": f"template {template_id} not found"}
        for k, v in fields.items():
            setattr(t, k, v)
    return {"ok": True, "id": template_id, **fields}


async def delete(template_id: int) -> dict:
    async with session_scope() as session:
        t = await session.get(PromptTemplate, template_id)
        if t is None:
            return {"ok": False, "error": f"template {template_id} not found"}
        await session.delete(t)
    return {"ok": True, "id": template_id}
