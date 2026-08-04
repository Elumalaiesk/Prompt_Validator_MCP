"""Server assembly + entrypoint.

Wires the pieces together:
    FastMCP(auth=<DatabaseTokenVerifier | RemoteAuthProvider>)
      + RBACMiddleware
      + validation tools + admin tools

and serves them over Streamable HTTP. `build_server()` is factored out so tests
can construct the app without starting the network transport.
"""

from __future__ import annotations

import asyncio
from typing import Any

from .auth.verifier import DatabaseTokenVerifier
from .config import Settings, get_settings
from .logging_setup import configure_logging, get_logger
from .rbac.middleware import RBACMiddleware
from .tools.admin_tools import register_admin_tools
from .tools.validation_tools import register_validation_tools
from .validation.base import build_default_validators
from .validation.policy import Aggregator
from .validation.runner import ValidationRunner

log = get_logger(__name__)

try:
    from fastmcp import FastMCP  # type: ignore
except Exception:  # pragma: no cover - only at runtime when installed
    FastMCP = None  # type: ignore


def build_token_verifier(settings: Settings):
    """Return the underlying TokenVerifier (used by FastMCP auth and the
    dashboard login), independent of any discovery wrapper."""
    if settings.auth_mode == "jwt":
        from .auth.jwt_verifier import build_jwt_verifier

        return build_jwt_verifier(settings)
    return DatabaseTokenVerifier(resource_server_url=settings.resource_server_url)


def build_auth(settings: Settings):
    """Return the auth provider for FastMCP based on `auth_mode`.

    * "jwt"    -> RevocableJWTVerifier (this server issues + verifies signed
                  JWTs; RBAC is driven by the token's scopes).
    * "opaque" -> DatabaseTokenVerifier, optionally wrapped in RemoteAuthProvider
                  for RFC 9728 discovery.
    """
    verifier = build_token_verifier(settings)
    if (
        settings.auth_mode == "opaque"
        and settings.publish_discovery
        and settings.authorization_server_url
    ):
        try:
            from fastmcp.server.auth import RemoteAuthProvider  # type: ignore

            return RemoteAuthProvider(
                token_verifier=verifier,
                authorization_servers=[settings.authorization_server_url],
                base_url=settings.resource_server_url,
            )
        except Exception as exc:  # pragma: no cover
            log.warning("RemoteAuthProvider unavailable (%s); using bare verifier", exc)
    return verifier


def build_runner(settings: Settings) -> ValidationRunner:
    return ValidationRunner(
        build_default_validators(settings),
        Aggregator(),
        timeout=settings.validator_timeout,
        fail_mode=settings.validator_fail_mode,
    )


def build_server(settings: Settings | None = None) -> tuple[Any, ValidationRunner]:
    settings = settings or get_settings()
    if FastMCP is None:
        raise RuntimeError(
            "fastmcp is not installed. Install with `pip install .[ml]` (or `.[dev]`)."
        )
    mcp = FastMCP(name="prompt-validator", auth=build_auth(settings))
    mcp.add_middleware(RBACMiddleware())

    runner = build_runner(settings)
    register_validation_tools(mcp, runner)
    register_admin_tools(mcp)
    from .tools.prompt_tools import register_prompt_tools
    from .tools.skill_content_tools import register_skill_content_tools

    register_prompt_tools(mcp)
    register_skill_content_tools(mcp)
    return mcp, runner


async def initialize(settings: Settings, runner: ValidationRunner) -> None:
    """Startup work: optional table creation + model preloading."""
    if settings.auto_create_tables:
        from .db.base import create_all

        await create_all()
        log.info("auto-created database tables")
    if settings.preload_models:
        await runner.preload_all()


async def _serve(settings: Settings) -> None:
    mcp, runner = build_server(settings)
    await initialize(settings, runner)

    if settings.dashboard_enabled:
        # Serve the MCP endpoint AND the admin dashboard from one ASGI app.
        from .web.app import build_web_app

        app = build_web_app(mcp, settings)
        import uvicorn

        log.info(
            "serving MCP at http://%s:%s%s  |  dashboard at %s",
            settings.host,
            settings.port,
            settings.mcp_path,
            settings.dashboard_path,
        )
        config = uvicorn.Config(
            app, host=settings.host, port=settings.port, log_level=settings.log_level.lower()
        )
        await uvicorn.Server(config).serve()
        return

    log.info(
        "serving MCP (Streamable HTTP) at http://%s:%s%s",
        settings.host,
        settings.port,
        settings.mcp_path,
    )
    base_kwargs = {"transport": "http", "host": settings.host, "port": settings.port}
    # `path` is accepted by newer FastMCP; fall back gracefully if not.
    try:
        await mcp.run_async(path=settings.mcp_path, **base_kwargs)
    except TypeError:
        await mcp.run_async(**base_kwargs)


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    asyncio.run(_serve(settings))


if __name__ == "__main__":
    main()
