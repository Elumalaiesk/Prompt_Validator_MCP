"""Test configuration.

Runs against a throwaway SQLite file (via aiosqlite) so the suite needs neither
Postgres nor the heavy ML stack. Environment is set *before* the app package is
imported so `get_settings()` picks it up.
"""

from __future__ import annotations

import os
import pathlib
import tempfile

_TMP = pathlib.Path(tempfile.gettempdir()) / "mpv_test.sqlite"

os.environ["MPV_DATABASE_URL"] = f"sqlite+aiosqlite:///{_TMP.as_posix()}"
os.environ["MPV_PRELOAD_MODELS"] = "false"
os.environ["MPV_AUTO_CREATE_TABLES"] = "true"
# Keep auto-generated JWT test keys out of the repo tree.
os.environ["MPV_JWT_KEYS_DIR"] = str(pathlib.Path(tempfile.gettempdir()) / "mpv_test_keys")
os.environ["MPV_JWT_ISSUER"] = "mpv-test"
os.environ["MPV_JWT_AUDIENCE"] = "http://test"

import pytest_asyncio  # noqa: E402


@pytest_asyncio.fixture
async def db():
    """Fresh schema per test."""
    from mcp_prompt_validator.db.base import create_all, dispose_engine

    if _TMP.exists():
        _TMP.unlink()
    await create_all()
    try:
        yield
    finally:
        await dispose_engine()
