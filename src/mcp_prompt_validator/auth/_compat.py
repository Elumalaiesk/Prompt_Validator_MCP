"""Version-resilient imports for the FastMCP / mcp auth base types.

These are the ONLY version-sensitive imports in the codebase. FastMCP re-exports
the underlying `mcp` SDK provider types, and the exact module paths have shifted
across FastMCP 2.11 -> 3.x. We resolve them defensively here so the rest of the
app imports from one place. If you pin a specific FastMCP version you can replace
this shim with a single direct import.

Exposed:
    TokenVerifier   -- base class to subclass; override `async verify_token`.
    AccessToken     -- the model returned by verify_token / read via get_access_token.
    build_access_token(**kwargs) -- construct an AccessToken tolerant of field
                                    differences across versions.
"""

from __future__ import annotations

from typing import Any

# --- TokenVerifier base ----------------------------------------------------
try:  # FastMCP >= 2.11 public surface
    from fastmcp.server.auth import TokenVerifier  # type: ignore
except Exception:  # pragma: no cover - fall back across layouts
    try:
        from fastmcp.server.auth.auth import TokenVerifier  # type: ignore
    except Exception:
        from mcp.server.auth.provider import TokenVerifier  # type: ignore

# --- AccessToken model -----------------------------------------------------
try:  # canonical model lives in the mcp SDK
    from mcp.server.auth.provider import AccessToken  # type: ignore
except Exception:  # pragma: no cover
    from fastmcp.server.auth import AccessToken  # type: ignore


def _model_fields(model: type) -> set[str]:
    """Field names for a pydantic v2 (model_fields) or v1 (__fields__) model."""
    fields = getattr(model, "model_fields", None)
    if fields is not None:
        return set(fields.keys())
    return set(getattr(model, "__fields__", {}).keys())


def build_access_token(**kwargs: Any) -> "AccessToken":
    """Build an AccessToken, dropping kwargs the installed version doesn't define.

    `subject` and `claims` were added to the mcp SDK AccessToken relatively
    recently; on older versions we silently omit them (the identity is still
    fully recoverable from `client_id` and `scopes`).
    """
    allowed = _model_fields(AccessToken)
    filtered = {k: v for k, v in kwargs.items() if k in allowed}
    return AccessToken(**filtered)


__all__ = ["TokenVerifier", "AccessToken", "build_access_token"]
