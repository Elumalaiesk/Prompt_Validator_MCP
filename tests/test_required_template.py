"""Tests for server-enforced template conformance (users.required_template).

The point of the feature is that a client CANNOT bypass conformance by omitting
`template_name`, so the central cases here are "caller sent nothing" and
"caller sent something else".
"""

from __future__ import annotations

from mcp_prompt_validator.prompts import service as ps
from mcp_prompt_validator.rbac import service as rs
from mcp_prompt_validator.tools import validation_tools as vt

TEMPLATE_BODY = "## Objective\n{{ objective }}\n## Scope\n{{ scope }}"
CONFORMING = "## Objective\nShip login\n## Scope\nWeb only"
NOT_CONFORMING = "Create login page with buttons"


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
    monkeypatch.setattr(
        vt, "current_identity", lambda: {"username": username, "token_id": 1}
    )


async def test_default_is_opt_in(db):
    await _seed_user("alice")
    assert await rs.get_required_template("alice") is None


async def test_set_and_clear(db):
    await _seed_user("alice")
    await ps.create(name="spec", body=TEMPLATE_BODY, owner_username="alice")

    assert (await rs.set_required_template("alice", "spec"))["ok"]
    assert await rs.get_required_template("alice") == "spec"

    assert (await rs.set_required_template("alice", None))["ok"]
    assert await rs.get_required_template("alice") is None


async def test_cannot_require_an_invisible_template(db):
    """A typo must fail at assignment, not block every later prompt."""
    await _seed_user("alice")
    await _seed_user("bob")
    await ps.create(name="spec", body=TEMPLATE_BODY, owner_username="alice")

    assert not (await rs.set_required_template("bob", "spec"))["ok"]      # not bob's
    assert not (await rs.set_required_template("alice", "typo"))["ok"]    # nonexistent
    assert await rs.get_required_template("bob") is None


async def test_cannot_require_for_unknown_user(db):
    await ps.create(name="g", body=TEMPLATE_BODY, is_global=True)
    assert not (await rs.set_required_template("ghost", "g"))["ok"]


async def test_ctx_injects_required_when_caller_sends_nothing(db, monkeypatch):
    """The core bypass: caller omits template_name entirely."""
    await _seed_user("alice")
    await ps.create(name="spec", body=TEMPLATE_BODY, owner_username="alice")
    await rs.set_required_template("alice", "spec")
    _as(monkeypatch, "alice")

    ctx = await vt._build_ctx()               # no template_name argument
    assert ctx["template_name"] == "spec"     # injected by the server
    assert ctx["template_required"] == "spec"
    assert ctx["template_requested"] is None


async def test_required_overrides_a_different_requested_template(db, monkeypatch):
    """Naming another template must not redirect the check."""
    await _seed_user("alice")
    await ps.create(name="spec", body=TEMPLATE_BODY, owner_username="alice")
    await ps.create(name="loose", body="anything", owner_username="alice")
    await rs.set_required_template("alice", "spec")
    _as(monkeypatch, "alice")

    ctx = await vt._build_ctx("loose")
    assert ctx["template_name"] == "spec"
    assert ctx["template_requested"] == "loose"


async def test_without_requirement_caller_choice_is_honoured(db, monkeypatch):
    await _seed_user("alice")
    await ps.create(name="spec", body=TEMPLATE_BODY, owner_username="alice")
    _as(monkeypatch, "alice")

    assert (await vt._build_ctx())["template_name"] is None
    assert (await vt._build_ctx("spec"))["template_name"] == "spec"


async def test_no_identity_yields_no_requirement(db, monkeypatch):
    monkeypatch.setattr(vt, "current_identity", lambda: {})
    ctx = await vt._build_ctx()
    assert ctx["username"] is None
    assert ctx["template_required"] is None


async def test_conformance_verdict_end_to_end(db, monkeypatch):
    """With a requirement set, a bare prompt blocks and a conforming one passes."""
    from mcp_prompt_validator.validation.validators.template_conformance import (
        TemplateConformanceValidator,
    )

    await _seed_user("alice")
    await ps.create(name="spec", body=TEMPLATE_BODY, owner_username="alice")
    await rs.set_required_template("alice", "spec")
    _as(monkeypatch, "alice")

    ctx = await vt._build_ctx()
    v = TemplateConformanceValidator()

    bad = await v.validate(NOT_CONFORMING, ctx)
    assert not bad.passed
    assert bad.metadata["missing_segments"] == ["## Objective", "## Scope"]

    good = await v.validate(CONFORMING, ctx)
    assert good.passed
