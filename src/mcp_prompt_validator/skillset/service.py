"""Skill-document CRUD + per-user visibility, shared by dashboard and MCP tools.

A `Skill` is admin-authored Markdown content (name, one-line description, full
body) — think a database-backed `SKILL.md`.

Visibility mirrors prompt templates: a caller sees a skill if it is **theirs**
or marked **global**, and enabled. The scoping lives in the SQL `WHERE` clause
of every read used by the tool surface, so an unassigned name is
indistinguishable from a non-existent one — guessing a skill name cannot leak a
body. `list_all()` is the unscoped admin/dashboard view and must never be
reached from a tool handler.
"""

from __future__ import annotations

from sqlalchemy import or_, select
from sqlalchemy.orm import selectinload

from ..db.base import session_scope
from ..db.models import Skill, User


def _to_dict(s: Skill, include_body: bool = True) -> dict:
    d = {
        "id": s.id,
        "name": s.name,
        "description": s.description,
        "owner_user_id": s.owner_user_id,
        "owner": s.owner.username if s.owner else None,
        "is_global": s.is_global,
        "enabled": s.enabled,
    }
    if include_body:
        d["body"] = s.body
    return d


async def _user_id(session, username: str | None) -> int | None:
    if not username:
        return None
    user = (
        await session.execute(select(User).where(User.username == username))
    ).scalar_one_or_none()
    return user.id if user else None


def _visible_to(user_id: int | None):
    """SQL predicate for "this caller may see the row".

    An unknown caller (no matching user row) gets globals only — comparing
    `owner_user_id == None` would render as `IS NULL` and match ownerless rows,
    so the ownership arm is dropped entirely rather than left to fail open.
    """
    if user_id is None:
        return Skill.is_global.is_(True)
    return or_(Skill.is_global.is_(True), Skill.owner_user_id == user_id)


async def list_all() -> list[dict]:
    """Every skill, including disabled ones (admin/dashboard view only)."""
    async with session_scope() as session:
        rows = (
            await session.execute(select(Skill).options(selectinload(Skill.owner)))
        ).scalars().all()
        return [_to_dict(s) for s in rows]


async def list_for_user(username: str) -> list[dict]:
    """Skills a user may discover: their own OR global, and enabled.

    Returns name + description only — discovery stays cheap, and the agent
    fetches a full body through `get_for_user` when it decides a skill applies.
    """
    async with session_scope() as session:
        user_id = await _user_id(session, username)
        stmt = select(Skill).where(Skill.enabled.is_(True), _visible_to(user_id))
        rows = (await session.execute(stmt)).scalars().all()
        return [{"name": s.name, "description": s.description} for s in rows]


async def get_for_user(name: str, username: str) -> dict | None:
    """Fetch one visible skill's full body by name (own or global), else None."""
    async with session_scope() as session:
        user_id = await _user_id(session, username)
        stmt = (
            select(Skill)
            .where(
                Skill.name == name,
                Skill.enabled.is_(True),
                _visible_to(user_id),
            )
            # Prefer a user's own skill over a same-named global one.
            .order_by(Skill.owner_user_id.is_(None))
        )
        s = (await session.execute(stmt)).scalars().first()
        if s is None:
            return None
        return {
            "name": s.name,
            "description": s.description,
            "body": s.body,
            "is_global": s.is_global,
        }


async def create(
    *,
    name: str,
    description: str = "",
    body: str = "",
    owner_username: str | None = None,
    is_global: bool = False,
    enabled: bool = True,
) -> dict:
    async with session_scope() as session:
        owner_id = None
        if owner_username:
            owner_id = await _user_id(session, owner_username)
            if owner_id is None:
                return {"ok": False, "error": f"user '{owner_username}' not found"}
        if not is_global and owner_id is None:
            return {"ok": False, "error": "skill must have an owner or be global"}

        # Names are unique per scope, not globally: one global "x" and one "x"
        # per owner. Same-scope duplicates would make `get_for_user` ambiguous.
        dup = (
            await session.execute(
                select(Skill).where(Skill.name == name, Skill.owner_user_id == owner_id)
            )
        ).scalar_one_or_none()
        if dup is not None:
            scope = "globally" if owner_id is None else f"for user '{owner_username}'"
            return {"ok": False, "error": f"skill '{name}' already exists {scope}"}

        skill = Skill(
            name=name,
            description=description,
            body=body,
            owner_user_id=owner_id,
            is_global=is_global,
            enabled=enabled,
        )
        session.add(skill)
        await session.flush()
        sid = skill.id
    return {"ok": True, "id": sid, "name": name, "is_global": is_global}


async def update(skill_id: int, **fields) -> dict:
    async with session_scope() as session:
        s = await session.get(Skill, skill_id)
        if s is None:
            return {"ok": False, "error": f"skill {skill_id} not found"}
        for k, v in fields.items():
            setattr(s, k, v)
    return {"ok": True, "id": skill_id, **fields}


async def set_global(skill_id: int, value: bool) -> dict:
    return await update(skill_id, is_global=value)


async def set_enabled(skill_id: int, value: bool) -> dict:
    return await update(skill_id, enabled=value)


async def delete(skill_id: int) -> dict:
    async with session_scope() as session:
        s = await session.get(Skill, skill_id)
        if s is None:
            return {"ok": False, "error": f"skill {skill_id} not found"}
        await session.delete(s)
    return {"ok": True, "id": skill_id}
