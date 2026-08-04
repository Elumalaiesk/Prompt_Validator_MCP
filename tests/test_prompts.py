"""Tests for prompt-template rendering, CRUD and per-user visibility."""

from __future__ import annotations

import pytest

pytest.importorskip("jinja2")

from mcp_prompt_validator.prompts import service as ps  # noqa: E402
from mcp_prompt_validator.prompts.render import (  # noqa: E402
    PromptRenderError,
    declared_variables,
    render_prompt,
)


def test_render_fills_variables():
    assert render_prompt("Hello {{ name }}!", {"name": "Alice"}) == "Hello Alice!"


def test_render_missing_variable_raises():
    with pytest.raises(PromptRenderError):
        render_prompt("Hello {{ name }}!", {})


def test_declared_variables():
    assert declared_variables("{{ a }} and {{ b }}") == ["a", "b"]


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


async def test_global_vs_owned_visibility(db):
    await _seed_user("alice")
    await _seed_user("bob")

    assert (await ps.create(name="g", body="hi {{ x }}", is_global=True))["ok"]
    assert (await ps.create(name="secret", body="private", owner_username="alice"))["ok"]

    alice = {p["name"] for p in await ps.list_for_user("alice")}
    bob = {p["name"] for p in await ps.list_for_user("bob")}

    assert alice == {"g", "secret"}   # own + global
    assert bob == {"g"}               # global only


async def test_create_requires_owner_or_global(db):
    res = await ps.create(name="orphan", body="x", is_global=False, owner_username=None)
    assert not res["ok"]


async def test_toggle_enabled_hides_template(db):
    await _seed_user("alice")
    created = await ps.create(name="t", body="x", owner_username="alice")
    tid = created["id"]

    assert {p["name"] for p in await ps.list_for_user("alice")} == {"t"}
    await ps.set_enabled(tid, False)
    assert await ps.list_for_user("alice") == []


async def test_set_global_exposes_to_all(db):
    await _seed_user("alice")
    await _seed_user("bob")
    created = await ps.create(name="promoted", body="x", owner_username="alice")
    assert {p["name"] for p in await ps.list_for_user("bob")} == set()

    await ps.set_global(created["id"], True)
    assert "promoted" in {p["name"] for p in await ps.list_for_user("bob")}


async def test_delete(db):
    await _seed_user("alice")
    created = await ps.create(name="tmp", body="x", owner_username="alice")
    assert (await ps.delete(created["id"]))["ok"]
    assert await ps.list_for_user("alice") == []
