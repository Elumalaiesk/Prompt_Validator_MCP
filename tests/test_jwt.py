"""Tests for JWT issuing, revocation, and (if fastmcp present) verification."""

from __future__ import annotations

import pytest

pytest.importorskip("jwt")
pytest.importorskip("cryptography")

import jwt as pyjwt  # noqa: E402

from mcp_prompt_validator.auth.jwt_issuer import issue_jwt  # noqa: E402
from mcp_prompt_validator.auth.jwt_keys import get_key_material, reset_cache  # noqa: E402
from mcp_prompt_validator.config import get_settings  # noqa: E402


async def _seed_user(username="u1", role_name="std_user", is_admin=False):
    from mcp_prompt_validator.db.base import session_scope
    from mcp_prompt_validator.db.models import Role, User

    async with session_scope() as s:
        role = Role(name=role_name, is_admin=is_admin, description="")
        s.add(role)
        await s.flush()
        s.add(User(username=username, role_id=role.id))


def test_issue_and_decode_roundtrip():
    reset_cache()
    settings = get_settings()
    sign_key, verify_key = get_key_material(settings)
    issued = issue_jwt(
        sign_key=sign_key,
        algorithm=settings.jwt_algorithm,
        issuer=settings.jwt_issuer,
        audience=settings.effective_audience,
        subject="42",
        username="alice",
        email="a@example.com",
        role_name="std_user",
        is_admin=False,
        ttl_seconds=3600,
    )
    decoded = pyjwt.decode(
        issued.token,
        verify_key,
        algorithms=[settings.jwt_algorithm],
        audience=settings.effective_audience,
        issuer=settings.jwt_issuer,
    )
    assert decoded["sub"] == "42"
    assert decoded["role"] == "std_user"
    assert "role:std_user" in decoded["scopes"]
    assert decoded["jti"] == issued.jti


async def test_issue_for_user_and_revoke(db):
    from mcp_prompt_validator.auth.jwt_service import issue_for_user, list_grants
    from mcp_prompt_validator.auth.revocation import RevocationCache, revoke_jti

    await _seed_user()
    result = await issue_for_user("u1", name="ci")
    assert result["ok"]
    assert result["token"]
    jti = result["jti"]

    grants = await list_grants("u1")
    assert any(g["jti"] == jti for g in grants)

    cache = RevocationCache(ttl=0.0)  # ttl 0 -> always refresh
    assert not await cache.is_revoked(jti)

    assert await revoke_jti(jti) is True
    assert await cache.is_revoked(jti) is True


async def test_revocable_verifier_roundtrip(db):
    pytest.importorskip("fastmcp")
    from mcp_prompt_validator.auth.jwt_service import issue_for_user
    from mcp_prompt_validator.auth.revocation import revoke_jti

    try:
        from mcp_prompt_validator.auth.jwt_verifier import build_jwt_verifier
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"JWTVerifier import unavailable: {exc}")

    await _seed_user()
    issued = await issue_for_user("u1")
    token = issued["token"]

    try:
        verifier = build_jwt_verifier(get_settings())
    except Exception as exc:  # API drift across fastmcp versions
        pytest.skip(f"JWTVerifier construction failed on this version: {exc}")

    access = await verifier.verify_token(token)
    assert access is not None
    assert "role:std_user" in access.scopes

    await revoke_jti(issued["jti"])
    # Fresh verifier so its revocation cache reloads immediately.
    verifier2 = build_jwt_verifier(get_settings())
    assert await verifier2.verify_token(token) is None
