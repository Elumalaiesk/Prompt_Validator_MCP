"""Tests for the aggregation policy (action precedence + pass/fail)."""

from __future__ import annotations

from mcp_prompt_validator.validation.contracts import Finding, Severity
from mcp_prompt_validator.validation.policy import Aggregator


def _f(category, passed, severity=Severity.MEDIUM):
    return Finding(category=category, detector="t", passed=passed, severity=severity)


def test_all_pass_is_allow():
    agg = Aggregator()
    v = agg.aggregate(
        [_f("secrets", True), _f("toxicity", True)],
        categories_run=["secrets", "toxicity"],
        elapsed_ms=1.0,
    )
    assert v.action == "allow"
    assert v.passed


def test_secret_blocks():
    agg = Aggregator()
    v = agg.aggregate(
        [_f("secrets", False, Severity.HIGH)], categories_run=["secrets"], elapsed_ms=1.0
    )
    assert v.action == "block"
    assert not v.passed
    assert v.max_severity == Severity.HIGH


def test_pii_redacts_and_block_wins():
    agg = Aggregator()
    findings = [_f("pii", False), _f("injection", False, Severity.HIGH)]
    v = agg.aggregate(
        findings,
        categories_run=["pii", "injection"],
        elapsed_ms=1.0,
        redacted_prompt="[REDACTED]",
    )
    # injection -> block outranks pii -> redact
    assert v.action == "block"
    # redacted_prompt only surfaces when the overall action is redact
    assert v.redacted_prompt is None


def test_pii_only_redacts():
    agg = Aggregator()
    v = agg.aggregate(
        [_f("pii", False)],
        categories_run=["pii"],
        elapsed_ms=1.0,
        redacted_prompt="[REDACTED]",
    )
    assert v.action == "redact"
    assert not v.passed
    assert v.redacted_prompt == "[REDACTED]"


def test_toxicity_flag_is_passable():
    agg = Aggregator()
    v = agg.aggregate([_f("toxicity", False)], categories_run=["toxicity"], elapsed_ms=1.0)
    assert v.action == "flag"
    assert v.passed  # flag is advisory, still usable
