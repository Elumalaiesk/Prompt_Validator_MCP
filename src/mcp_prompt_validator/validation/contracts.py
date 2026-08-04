"""Typed contracts shared across the validation pipeline (pydantic v2)."""

from __future__ import annotations

from enum import IntEnum
from typing import Literal, Optional

from pydantic import BaseModel, Field


class Severity(IntEnum):
    """Ordered severity so the aggregator can take a simple max()."""

    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50


# What the caller should do with the prompt.
Action = Literal["allow", "flag", "redact", "block"]


class Finding(BaseModel):
    """One detector's verdict for one category."""

    category: str
    detector: str
    passed: bool
    severity: Severity = Severity.INFO
    score: Optional[float] = None
    reasons: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


class Verdict(BaseModel):
    """Aggregated result returned to the MCP caller."""

    passed: bool
    action: Action
    max_severity: Severity
    findings: list[Finding] = Field(default_factory=list)
    redacted_prompt: Optional[str] = None
    elapsed_ms: float = 0.0
    # categories that were actually run (useful when the caller filters).
    categories_run: list[str] = Field(default_factory=list)
