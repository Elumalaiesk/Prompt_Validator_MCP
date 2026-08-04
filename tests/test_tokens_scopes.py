"""Unit tests for token hashing and scope encoding (no external deps)."""

from __future__ import annotations

from mcp_prompt_validator.auth.scopes import (
    encode_scopes,
    is_admin_from_scopes,
    role_from_scopes,
)
from mcp_prompt_validator.auth.tokens import hash_token, mint_token, tokens_equal


def test_hash_is_deterministic_and_hex():
    h1 = hash_token("mpv_abc")
    h2 = hash_token("mpv_abc")
    assert h1 == h2
    assert len(h1) == 64
    assert tokens_equal(h1, h2)
    assert not tokens_equal(h1, hash_token("mpv_xyz"))


def test_mint_token_shape():
    minted = mint_token("mpv_")
    assert minted.plaintext.startswith("mpv_")
    assert minted.token_hash == hash_token(minted.plaintext)
    assert minted.plaintext.startswith(minted.prefix)
    # Two mints must differ.
    assert mint_token("mpv_").plaintext != minted.plaintext


def test_encode_and_decode_scopes():
    scopes = encode_scopes("std_user", is_admin=False)
    assert "role:std_user" in scopes
    assert "admin" not in scopes
    assert role_from_scopes(scopes) == "std_user"
    assert not is_admin_from_scopes(scopes)


def test_admin_scope():
    scopes = encode_scopes("admin", is_admin=True)
    assert is_admin_from_scopes(scopes)
