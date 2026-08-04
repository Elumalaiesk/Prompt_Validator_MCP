"""RBACMiddleware — enforces per-role tool visibility and execution.

Two hooks, one source of truth (`skills.registry`):
  * on_list_tools : filters the advertised tool list so each caller only *sees*
                    the tools their role permits (dynamic skill supply).
  * on_call_tool  : blocks execution of any tool the role may not call — the
                    enforcement backstop, since list-filtering alone is only
                    discovery-hiding (a client can still guess a tool name).

Identity comes from the AccessToken produced by DatabaseTokenVerifier, read via
FastMCP's request-scoped `get_access_token()` dependency.
"""

from __future__ import annotations

from ..auth.scopes import is_admin_from_scopes, role_from_scopes
from ..logging_setup import get_logger
from ..skills.registry import tags_for, tool_permitted

log = get_logger(__name__)

# --- Version-resilient FastMCP imports ------------------------------------
try:
    from fastmcp.server.middleware import Middleware, MiddlewareContext  # type: ignore
except Exception:  # pragma: no cover
    from fastmcp.server.middleware.middleware import (  # type: ignore
        Middleware,
        MiddlewareContext,
    )

try:
    from fastmcp.server.dependencies import get_access_token  # type: ignore
except Exception:  # pragma: no cover
    from mcp.server.auth.middleware.auth_context import get_access_token  # type: ignore

try:
    from fastmcp.exceptions import ToolError  # type: ignore
except Exception:  # pragma: no cover

    class ToolError(Exception):  # type: ignore
        """Fallback if the exception type moves."""


def _tags_of(tool: object) -> set[str]:
    """Best-effort tag extraction for a FastMCP Tool object."""
    tags = getattr(tool, "tags", None)
    if tags:
        return set(tags)
    name = getattr(tool, "name", None) or getattr(tool, "key", None)
    return tags_for(name) if name else set()


class RBACMiddleware(Middleware):
    async def on_list_tools(self, context: "MiddlewareContext", call_next):  # noqa: ANN001
        tools = await call_next(context)
        token = _safe_token()
        if token is None:
            # No identity on an authenticated transport -> advertise nothing.
            return []
        is_admin = is_admin_from_scopes(token.scopes)
        visible = [t for t in tools if tool_permitted(_tags_of(t), is_admin)]
        log.debug(
            "list_tools: role=%s sees %d/%d tools",
            role_from_scopes(token.scopes),
            len(visible),
            len(tools),
        )
        return visible

    async def on_call_tool(self, context: "MiddlewareContext", call_next):  # noqa: ANN001
        name = getattr(context.message, "name", None) or ""
        token = _safe_token()
        if token is None:
            raise ToolError("Authentication required.")

        is_admin = is_admin_from_scopes(token.scopes)
        tags = tags_for(name)

        if not tool_permitted(tags, is_admin):
            # Import locally to avoid a hard import cycle at module load.
            from ..audit import record

            claims = getattr(token, "claims", None) or {}
            await record(
                action="access.deny",
                username=getattr(token, "client_id", None),
                token_id=claims.get("token_id"),
                tool_name=name,
                decision="deny",
                detail={"required_tags": sorted(tags), "role": role_from_scopes(token.scopes)},
            )
            log.info(
                "call_tool DENY user=%s role=%s tool=%s",
                getattr(token, "client_id", "?"),
                role_from_scopes(token.scopes),
                name,
            )
            raise ToolError(
                f"Access denied: your role is not permitted to call '{name}'."
            )

        return await call_next(context)


def _safe_token():
    """Return the current AccessToken or None (never raises)."""
    try:
        return get_access_token()
    except Exception:
        return None
