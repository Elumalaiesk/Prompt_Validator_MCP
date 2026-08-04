"""Tests for the agent-facing skill tools (`list_skills` / `get_skill`).

Exercises the handlers registered on the MCP surface rather than the service
underneath, so the identity plumbing and the fail-closed no-identity paths are
covered too.
"""

from __future__ import annotations

from mcp_prompt_validator.skillset import service as ss
from mcp_prompt_validator.tools import skill_content_tools as sct


class _FakeMCP:
    """Captures the callables `register_skill_content_tools` registers."""

    def __init__(self):
        self.tools: dict = {}

    def tool(self, *, name, tags=None, description=None):
        def deco(fn):
            self.tools[name] = fn
            return fn

        return deco


def _handlers():
    mcp = _FakeMCP()
    sct.register_skill_content_tools(mcp)
    return mcp.tools["list_skills"], mcp.tools["get_skill"]


async def _seed_user(username, role_name="std_user"):
    from mcp_prompt_validator.db.base import session_scope
    from mcp_prompt_validator.db.models import Role, User
    from sqlalchemy import select

    async with session_scope() as s:
        role = (
            await s.execute(select(Role).where(Role.name == role_name))
        ).scalar_one_or_none()
        if role is None:
            role = Role(name=role_name, is_admin=False, description="")
            s.add(role)
            await s.flush()
        s.add(User(username=username, role_id=role.id))


def _as(monkeypatch, username):
    """Pretend the current caller is `username` (or nobody, if None)."""
    ident = {} if username is None else {"username": username, "token_id": 1}
    monkeypatch.setattr(sct, "current_identity", lambda: ident)


async def test_no_identity_yields_nothing(db, monkeypatch):
    list_skills, get_skill = _handlers()
    await ss.create(name="g", body="shared", is_global=True)
    _as(monkeypatch, None)

    assert await list_skills() == []
    assert (await get_skill("g"))["ok"] is False


async def test_agent_sees_own_and_global_only(db, monkeypatch):
    list_skills, get_skill = _handlers()
    await _seed_user("alice")
    await _seed_user("bob")
    await ss.create(name="g", description="shared", body="G", is_global=True)
    await ss.create(name="alice-only", description="mine", body="A", owner_username="alice")

    _as(monkeypatch, "alice")
    assert {s["name"] for s in await list_skills()} == {"g", "alice-only"}
    assert (await get_skill("alice-only"))["body"] == "A"

    _as(monkeypatch, "bob")
    assert {s["name"] for s in await list_skills()} == {"g"}
    # Bob knows the name but is not assigned it -> indistinguishable from absent.
    denied = await get_skill("alice-only")
    assert denied["ok"] is False and "not found" in denied["error"]


async def test_listing_is_discovery_only(db, monkeypatch):
    """list_skills must stay cheap: no bodies in the discovery payload."""
    list_skills, _ = _handlers()
    await _seed_user("alice")
    await ss.create(name="t", description="d", body="SENSITIVE", owner_username="alice")
    _as(monkeypatch, "alice")

    listed = await list_skills()
    assert listed == [{"name": "t", "description": "d"}]


async def test_get_skill_writes_audit_rows(db, monkeypatch):
    from mcp_prompt_validator.db.base import session_scope
    from mcp_prompt_validator.db.models import AuditLog
    from sqlalchemy import select

    _, get_skill = _handlers()
    await _seed_user("alice")
    await ss.create(name="t", body="x", owner_username="alice")
    _as(monkeypatch, "alice")

    await get_skill("t")            # allow
    await get_skill("nope")         # deny

    async with session_scope() as s:
        rows = (
            await s.execute(select(AuditLog).where(AuditLog.action == "skill.read"))
        ).scalars().all()
        decisions = sorted(r.decision for r in rows)
    assert decisions == ["allow", "deny"]
