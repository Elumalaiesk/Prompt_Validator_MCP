"""Read the current caller's identity inside a tool handler.

Wraps FastMCP's request-scoped `get_access_token()` and normalises the fields
we care about, tolerating versions where `claims`/`subject` are absent.
"""

from __future__ import annotations

from typing import Any

from .auth.scopes import is_admin_from_scopes, role_from_scopes

try:
    from fastmcp.server.dependencies import get_access_token  # type: ignore
except Exception:  # pragma: no cover
    try:
        from mcp.server.auth.middleware.auth_context import get_access_token  # type: ignore
    except Exception:  # pragma: no cover
        def get_access_token():  # type: ignore
            return None


def current_identity() -> dict[str, Any]:
    """Return {username, token_id, role, scopes, is_admin} or {}."""
    try:
        token = get_access_token()
    except Exception:
        token = None
    if token is None:
        return {}

    scopes = list(getattr(token, "scopes", []) or [])
    claims = getattr(token, "claims", None) or {}
    return {
        "username": getattr(token, "client_id", None) or claims.get("username"),
        "email": claims.get("email"),
        "token_id": claims.get("token_id"),
        "role": claims.get("role") or role_from_scopes(scopes),
        "scopes": scopes,
        "is_admin": is_admin_from_scopes(scopes),
    }
