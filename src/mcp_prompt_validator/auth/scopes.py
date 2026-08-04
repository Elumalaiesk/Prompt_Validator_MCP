"""Scope encoding shared by the token verifier and the RBAC middleware.

We encode identity/authorisation into the OAuth `scopes` list on the AccessToken
because `scopes` is guaranteed present across every FastMCP/mcp version (unlike
the newer `claims`/`subject` fields). Only two roles exist — "admin" and
"std_user" — so the scheme is minimal:

    role:<name>   -- the caller's role (exactly one)
    admin         -- present iff the role is an admin (bypasses all tool gating)

A std_user may call any tool not tagged "admin" (see `skills/registry.py`).
"""

from __future__ import annotations

ADMIN_SCOPE = "admin"
_ROLE_PREFIX = "role:"


def encode_scopes(role_name: str, is_admin: bool) -> list[str]:
    scopes = [f"{_ROLE_PREFIX}{role_name}"]
    if is_admin:
        scopes.append(ADMIN_SCOPE)
    return scopes


def role_from_scopes(scopes: list[str]) -> str | None:
    for s in scopes:
        if s.startswith(_ROLE_PREFIX):
            return s[len(_ROLE_PREFIX) :]
    return None


def is_admin_from_scopes(scopes: list[str]) -> bool:
    return ADMIN_SCOPE in scopes
