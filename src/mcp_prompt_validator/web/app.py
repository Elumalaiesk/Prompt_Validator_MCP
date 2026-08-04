"""Compose one ASGI app that serves both the MCP endpoint and the dashboard.

The FastMCP Streamable-HTTP app is mounted at "/" (it handles the configured
MCP path internally); the dashboard routes are registered first so they take
precedence. The MCP app's lifespan is propagated to the parent Starlette app so
the MCP session manager starts correctly (a known mounting requirement).
"""

from __future__ import annotations

from typing import Any

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.routing import Mount

from ..config import Settings
from .dashboard import build_dashboard_routes


def build_web_app(mcp: Any, settings: Settings) -> Starlette:
    try:
        mcp_app = mcp.http_app(path=settings.mcp_path)
    except TypeError:  # pragma: no cover - older signature
        mcp_app = mcp.http_app()

    routes = build_dashboard_routes(settings)
    routes.append(Mount("/", app=mcp_app))

    return Starlette(
        routes=routes,
        middleware=[
            Middleware(
                SessionMiddleware,
                secret_key=settings.dashboard_secret,
                session_cookie="mpv_admin",
                same_site="lax",
                https_only=False,
            )
        ],
        lifespan=getattr(mcp_app, "lifespan", None),
    )
