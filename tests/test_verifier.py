"""End-to-end tests for DatabaseTokenVerifier against a SQLite database.

Skipped automatically if the `mcp` SDK (which provides AccessToken) is not
installed, so the lightweight test run stays green without the MCP stack.
"""

from __future__ import annotations

import pytest

pytest.importorskip("mcp")  # AccessToken comes from the mcp SDK (a fastmcp dep)

from datetime import datetime, timezone  # noqa: E402

from mcp_prompt_validator.auth.tokens import mint_token  # noqa: E402
from mcp_prompt_validator.auth.verifier import DatabaseTokenVerifier  # noqa: E402
from mcp_prompt_validator.db.base import session_scope  # noqa: E402
from mcp_prompt_validator.db.models import ApiToken, Role, User  # noqa: E402


async def _seed_user(role_name="std_user", is_admin=False):
    async with session_scope() as s:
        role = Role(name=role_name, is_admin=is_admin, description="")
        s.add(role)
        await s.flush()
        user = User(username="u1", role_id=role.id)
        s.add(user)
        await s.flush()
        minted = mint_token("mpv_")
        s.add(
            ApiToken(
                user_id=user.id,
                name="t",
                token_hash=minted.token_hash,
                prefix=minted.prefix,
            )
        )
        return minted.plaintext


async def test_verify_valid_token(db):
    token = await _seed_user()
    verifier = DatabaseTokenVerifier(resource_server_url="http://localhost:8000")
    at = await verifier.verify_token(token)
    assert at is not None
    assert "role:std_user" in at.scopes
    assert at.client_id == "u1"


async def test_verify_admin_scope(db):
    token = await _seed_user(role_name="admin", is_admin=True)
    verifier = DatabaseTokenVerifier(resource_server_url="http://localhost:8000")
    at = await verifier.verify_token(token)
    assert at is not None
    assert "admin" in at.scopes


async def test_verify_unknown_token(db):
    verifier = DatabaseTokenVerifier(resource_server_url="http://localhost:8000")
    assert await verifier.verify_token("mpv_does_not_exist") is None


async def test_verify_revoked_token(db):
    token = await _seed_user()
    async with session_scope() as s:
        from sqlalchemy import update

        await s.execute(update(ApiToken).values(revoked_at=datetime.now(timezone.utc)))
    verifier = DatabaseTokenVerifier(resource_server_url="http://localhost:8000")
    assert await verifier.verify_token(token) is None
