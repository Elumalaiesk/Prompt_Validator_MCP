"""Tests for caller-facing response shaping (pass/fail + worst failure only)."""

from __future__ import annotations

import pytest

from mcp_prompt_validator.validation.contracts import Finding, Severity, Verdict
from mcp_prompt_validator.validation.response import summarize

ALL_CATEGORIES = ["secrets", "schema", "template_conformance", "injection", "toxicity"]


def _verdict(*findings, passed=None, action="block", redacted=None):
    fs = list(findings)
    ok = all(f.passed for f in fs) if passed is None else passed
    return Verdict(
        passed=ok,
        action="allow" if ok else action,
        max_severity=max([f.severity for f in fs], default=Severity.INFO),
        findings=fs,
        redacted_prompt=redacted,
        categories_run=ALL_CATEGORIES,
    )


def _ok(category):
    return Finding(category=category, detector=f"{category}.d", passed=True)


def _bad(category, severity=Severity.HIGH, reasons=None, metadata=None):
    return Finding(
        category=category,
        detector=f"{category}.d",
        passed=False,
        severity=severity,
        # `is None`, not `or` — an explicitly empty list is a case under test.
        reasons=["something is wrong"] if reasons is None else reasons,
        metadata=metadata or {},
    )


def test_pass_response_is_bare():
    out = summarize(_verdict(_ok("secrets"), _ok("schema")))
    assert out == {"passed": True, "status": "validation passed", "action": "allow"}


def test_pass_response_leaks_nothing():
    out = summarize(_verdict(_ok("pii"), _ok("secrets")))
    blob = repr(out)
    for leaked in ("detector", "reasons", "score", "severity", "categories"):
        assert leaked not in blob


def test_fail_shape_is_a_single_object():
    out = summarize(_verdict(_ok("schema"), _bad("template_conformance")))
    assert set(out) == {"passed", "status", "action", "failed"}
    assert isinstance(out["failed"], dict)
    assert set(out["failed"]) == {"category", "severity", "reasons"}
    assert out["status"] == "validation failed"
    assert "suggestion" not in out["failed"]


def test_template_reason_is_generic():
    """Must not name the template or echo its section headings back."""
    out = summarize(
        _verdict(
            _bad(
                "template_conformance",
                reasons=["prompt does not conform to template 'spec-template'"],
                metadata={"missing_segments": ["## Objective", "## Scope"]},
            )
        )
    )
    assert out["failed"]["reasons"] == ["prompt does not match the expected structure"]
    blob = repr(out)
    assert "spec-template" not in blob and "## Objective" not in blob


def test_secrets_reason_names_the_credential_type():
    out = summarize(
        _verdict(
            _bad(
                "secrets",
                reasons=["possible secret(s): aws_access_key_id"],
                metadata={"types": ["aws_access_key_id"]},
            )
        )
    )
    assert out["failed"]["category"] == "secrets"
    assert out["failed"]["reasons"] == ["possible secret(s): aws_access_key_id"]


def test_injection_reason_passes_through():
    out = summarize(
        _verdict(_bad("injection", reasons=["instruction override: 'ignore previous'"]))
    )
    assert out["failed"]["reasons"] == ["instruction override: 'ignore previous'"]


def test_pii_reason_names_entity_types():
    out = summarize(_verdict(_bad("pii", reasons=["PII detected: EMAIL_ADDRESS, PERSON"])))
    assert "EMAIL_ADDRESS" in out["failed"]["reasons"][0]


def test_secrets_wins_over_template_at_equal_severity():
    """A leaked key must not be hidden behind a structural complaint."""
    out = summarize(
        _verdict(
            _bad("template_conformance", severity=Severity.HIGH),
            _bad("secrets", severity=Severity.HIGH, reasons=["possible secret(s): aws_key"]),
        )
    )
    assert out["failed"]["category"] == "secrets"


def test_higher_severity_beats_category_priority():
    out = summarize(
        _verdict(
            _bad("secrets", severity=Severity.LOW),
            _bad("injection", severity=Severity.CRITICAL),
        )
    )
    assert out["failed"]["category"] == "injection"


def test_severity_labels_cover_every_valid_value():
    for sev, label in [
        (Severity.INFO, "info"), (Severity.LOW, "low"), (Severity.MEDIUM, "medium"),
        (Severity.HIGH, "high"), (Severity.CRITICAL, "critical"),
    ]:
        out = summarize(_verdict(_bad("secrets", severity=sev)))
        assert out["failed"]["severity"] == label


def test_unknown_category_still_reported():
    out = summarize(_verdict(_bad("brand_new_check", reasons=["nope"])))
    assert out["failed"]["category"] == "brand_new_check"
    assert out["failed"]["reasons"] == ["nope"]


def test_finding_with_no_reasons_gets_a_placeholder():
    out = summarize(_verdict(_bad("toxicity", reasons=[])))
    assert out["failed"]["reasons"] == ["toxicity check failed"]


def test_redacted_prompt_only_present_when_produced():
    assert "redacted_prompt" not in summarize(_verdict(_bad("secrets")))
    out = summarize(_verdict(_bad("pii"), action="redact", redacted="hi <EMAIL>"))
    assert out["redacted_prompt"] == "hi <EMAIL>"


def test_failed_key_absent_when_verdict_has_no_failed_finding():
    """Defensive: a not-passed verdict with no failing finding must not KeyError."""
    out = summarize(_verdict(_ok("secrets"), passed=False))
    assert out["passed"] is False and "failed" not in out


def test_severity_outside_the_enum_is_rejected_upstream():
    with pytest.raises(Exception):
        Finding(category="x", detector="x.d", passed=False, severity=33)
