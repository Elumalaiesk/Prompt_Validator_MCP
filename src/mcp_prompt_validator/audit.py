"""Audit logging helper — append-only records of access decisions and runs.

Audit writes must never break the request they describe, so all failures here
are swallowed (and logged) rather than propagated.
"""

from __future__ import annotations

from typing import Any

from .db.base import session_scope
from .db.models import AuditLog
from .logging_setup import get_logger

log = get_logger(__name__)


async def record(
    *,
    action: str,
    username: str | None = None,
    token_id: int | None = None,
    tool_name: str | None = None,
    decision: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    try:
        async with session_scope() as session:
            session.add(
                AuditLog(
                    action=action,
                    username=username,
                    token_id=token_id,
                    tool_name=tool_name,
                    decision=decision,
                    detail=detail or {},
                )
            )
    except Exception as exc:  # pragma: no cover - audit must not break requests
        log.warning("audit write failed (%s): %s", action, exc)
