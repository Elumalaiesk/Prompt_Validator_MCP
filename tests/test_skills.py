"""Tests for skill-document CRUD and per-user visibility."""

from __future__ import annotations

from mcp_prompt_validator.skillset import service as ss


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

    assert (await ss.create(name="g", body="shared", is_global=True))["ok"]
    assert (await ss.create(name="secret", body="private", owner_username="alice"))["ok"]

    alice = {s["name"] for s in await ss.list_for_user("alice")}
    bob = {s["name"] for s in await ss.list_for_user("bob")}

    assert alice == {"g", "secret"}   # own + global
    assert bob == {"g"}               # global only


async def test_get_for_user_hides_other_users_skill(db):
    """Guessing a skill name must not leak a body — the core of the fix."""
    await _seed_user("alice")
    await _seed_user("bob")
    await ss.create(name="secret", body="private", owner_username="alice")

    assert (await ss.get_for_user("secret", "alice"))["body"] == "private"
    assert await ss.get_for_user("secret", "bob") is None


async def test_unknown_caller_sees_only_globals(db):
    await _seed_user("alice")
    await ss.create(name="g", body="shared", is_global=True)
    await ss.create(name="owned", body="private", owner_username="alice")

    assert {s["name"] for s in await ss.list_for_user("ghost")} == {"g"}
    assert await ss.get_for_user("owned", "ghost") is None


async def test_own_skill_shadows_same_named_global(db):
    await _seed_user("alice")
    await ss.create(name="review", body="GLOBAL", is_global=True)
    await ss.create(name="review", body="MINE", owner_username="alice")

    assert (await ss.get_for_user("review", "alice"))["body"] == "MINE"
    await _seed_user("bob")
    assert (await ss.get_for_user("review", "bob"))["body"] == "GLOBAL"


async def test_create_requires_owner_or_global(db):
    res = await ss.create(name="orphan", body="x", is_global=False, owner_username=None)
    assert not res["ok"]


async def test_create_rejects_unknown_owner(db):
    res = await ss.create(name="x", body="x", owner_username="nobody")
    assert not res["ok"]


async def test_duplicate_name_allowed_across_owners_not_within(db):
    await _seed_user("alice")
    await _seed_user("bob")

    assert (await ss.create(name="dup", body="a", owner_username="alice"))["ok"]
    assert (await ss.create(name="dup", body="b", owner_username="bob"))["ok"]
    # Same name, same owner -> rejected (would make get_for_user ambiguous).
    assert not (await ss.create(name="dup", body="c", owner_username="alice"))["ok"]


async def test_toggle_enabled_hides_skill(db):
    await _seed_user("alice")
    created = await ss.create(name="t", body="x", owner_username="alice")

    assert {s["name"] for s in await ss.list_for_user("alice")} == {"t"}
    await ss.set_enabled(created["id"], False)
    assert await ss.list_for_user("alice") == []
    assert await ss.get_for_user("t", "alice") is None


async def test_set_global_exposes_to_all(db):
    await _seed_user("alice")
    await _seed_user("bob")
    created = await ss.create(name="promoted", body="x", owner_username="alice")
    assert {s["name"] for s in await ss.list_for_user("bob")} == set()

    await ss.set_global(created["id"], True)
    assert "promoted" in {s["name"] for s in await ss.list_for_user("bob")}


async def test_listing_never_leaks_bodies(db):
    await _seed_user("alice")
    await ss.create(name="t", description="d", body="SENSITIVE", owner_username="alice")
    listed = await ss.list_for_user("alice")
    assert listed == [{"name": "t", "description": "d"}]


async def test_delete(db):
    await _seed_user("alice")
    created = await ss.create(name="tmp", body="x", owner_username="alice")
    assert (await ss.delete(created["id"]))["ok"]
    assert await ss.list_for_user("alice") == []
