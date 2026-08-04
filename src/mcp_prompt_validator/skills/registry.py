"""Skill registry: register MCP tools with tags and remember name->tags.

FastMCP's own `Tool.tags` are available inside `on_list_tools`, but for the
`on_call_tool` enforcement hook we need to map a *tool name* to its tags without
depending on FastMCP internals (which differ across versions). So every skill is
registered through `register_skill`, which both:
  * registers the callable with FastMCP via `mcp.tool(...)`, and
  * records `name -> tags` in the module-level `TOOL_TAGS` map.

`TOOL_TAGS` is the single source of truth the RBAC middleware consults, so the
list-filtering hook and the call-blocking hook can never diverge.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

# name -> required tags. RBAC allows a call if the caller holds any of these tags
# (or is admin). Populated at import time as tool modules register their skills.
TOOL_TAGS: dict[str, set[str]] = {}


def register_skill(
    mcp: Any,
    fn: Callable[..., Any],
    *,
    name: str | None = None,
    tags: set[str],
    description: str | None = None,
) -> Callable[..., Any]:
    """Register `fn` as an MCP tool tagged with `tags` and record its tags."""
    tool_name = name or fn.__name__
    TOOL_TAGS[tool_name] = set(tags)
    decorator = mcp.tool(name=tool_name, tags=set(tags), description=description)
    return decorator(fn)


def tags_for(tool_name: str) -> set[str]:
    """Tags required by a tool (empty set if unknown -> treated as deny)."""
    return TOOL_TAGS.get(tool_name, set())


def tool_permitted(tool_tags: set[str], is_admin: bool) -> bool:
    """Core visibility/authorisation rule, shared by both RBAC hooks.

    Only two roles exist: admin (sees/calls everything) and std_user (everyone
    else). A std_user may call any tool except ones tagged "admin".
    """
    if is_admin:
        return True
    if not tool_tags:
        # Untagged tools are denied by default (fail closed).
        return False
    return "admin" not in tool_tags


def reset_registry() -> None:
    """Clear the registry (used by tests that rebuild the server)."""
    TOOL_TAGS.clear()
