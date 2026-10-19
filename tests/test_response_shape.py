"""Tests for caller-facing response shaping (pass/fail + failed categories)."""

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


def _template_bad(missing=None, severity=Severity.HIGH):
    metadata = {"missing_segments": missing} if missing is not None else {}
    return _bad("template_conformance", severity=severity, metadata=metadata)


def test_pass_response_is_bare():
    out = summarize(_verdict(_ok("secrets"), _ok("schema")))
    assert out == {"passed": True, "status": "validation passed", "action": "allow"}


def test_pass_response_leaks_nothing():
    out = summarize(_verdict(_ok("pii"), _ok("secrets")))
    blob = repr(out)
    for leaked in ("detector", "reasons", "score", "severity", "categories"):
        assert leaked not in blob


def test_fail_shape_lists_each_failed_category():
    out = summarize(_verdict(_ok("schema"), _template_bad(["## Objective"])))
    assert set(out) == {"passed", "status", "action", "failed", "suggestion"}
    assert isinstance(out["failed"], list)
    assert len(out["failed"]) == 1
    assert set(out["failed"][0]) == {"category", "severity", "reasons", "missing_fields"}
    assert out["failed"][0]["category"] == "template_conformance"
    assert out["status"] == "validation failed"


def test_all_failed_categories_reported_worst_first():
    out = summarize(
        _verdict(
            _bad("secrets", severity=Severity.MEDIUM),
            _bad("injection", severity=Severity.CRITICAL),
            _template_bad(),
        )
    )
    assert [f["category"] for f in out["failed"]] == [
        "injection",
        "template_conformance",
        "secrets",
    ]


def test_duplicate_category_kept_once():
    """Two failing findings in the same category collapse into one entry."""
    out = summarize(
        _verdict(
            _bad("secrets", severity=Severity.LOW, reasons=["first"]),
            _bad("secrets", severity=Severity.HIGH, reasons=["second"]),
        )
    )
    assert len(out["failed"]) == 1
    assert out["failed"][0]["category"] == "secrets"
    assert out["failed"][0]["reasons"] == ["second"]  # the worst one wins


def test_template_entry_lists_missing_fields_but_never_the_name():
    out = summarize(
        _verdict(
            _bad(
                "template_conformance",
                reasons=["prompt does not conform to template 'spec-template'"],
                metadata={"missing_segments": ["## Objective", "## Scope"]},
            )
        )
    )
    entry = out["failed"][0]
    assert entry["reasons"] == ["prompt does not match the expected structure"]
    assert entry["missing_fields"] == ["## Objective", "## Scope"]
    blob = repr(out)
    assert "spec-template" not in blob


def test_long_missing_fields_are_trimmed():
    long_segment = "x" * 500
    out = summarize(_verdict(_template_bad([long_segment])))
    trimmed = out["failed"][0]["missing_fields"][0]
    assert len(trimmed) <= 140 and trimmed.endswith("…")


def test_template_entry_omits_missing_fields_when_absent():
    out = summarize(_verdict(_template_bad()))
    assert "missing_fields" not in out["failed"][0]


def test_template_not_found_reason_is_distinct():
    """No missing segments means the template could not be used (e.g. not
    found) — report that, not a structural mismatch."""
    out = summarize(_verdict(_template_bad()))
    entry = out["failed"][0]
    assert entry["reasons"] == ["template not found or not visible to the caller"]
    assert "missing_fields" not in entry


def test_suggestion_names_failed_categories():
    out = summarize(
        _verdict(
            _bad("secrets", severity=Severity.HIGH),
            _bad("injection", severity=Severity.HIGH),
        )
    )
    assert out["suggestion"] == "Your description failed in secrets and prompt injection."


def test_suggestion_mentions_missing_fields_when_template_fails():
    out = summarize(
        _verdict(
            _bad("injection", severity=Severity.HIGH),
            _template_bad(["## Objective", "## Scope"]),
        )
    )
    assert out["suggestion"] == (
        "Your description failed in prompt injection. "
        "It also doesn't match the attached template structure — include the missing fields below."
    )


def test_suggestion_with_only_template_failure_has_no_also():
    out = summarize(_verdict(_template_bad(["## Objective"])))
    assert out["suggestion"] == (
        "It doesn't match the attached template structure — include the missing fields below."
    )


def test_suggestion_skips_template_sentence_when_no_missing_segments():
    """A template failure without missing segments (e.g. template not found)
    must not point the caller at a list that is not there."""
    out = summarize(_verdict(_template_bad()))
    assert out["suggestion"] == "Your description failed in template structure."


def test_suggestion_unknown_category_label_falls_back():
    out = summarize(_verdict(_bad("brand_new_check", reasons=["nope"])))
    assert out["suggestion"] == "Your description failed in brand new check."


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
    assert out["failed"][0]["category"] == "secrets"
    assert out["failed"][0]["reasons"] == ["possible secret(s): aws_access_key_id"]


def test_injection_reason_passes_through():
    out = summarize(
        _verdict(_bad("injection", reasons=["instruction override: 'ignore previous'"]))
    )
    assert out["failed"][0]["reasons"] == ["instruction override: 'ignore previous'"]


def test_pii_reason_names_entity_types():
    out = summarize(_verdict(_bad("pii", reasons=["PII detected: EMAIL_ADDRESS, PERSON"])))
    assert "EMAIL_ADDRESS" in out["failed"][0]["reasons"][0]


def test_secrets_wins_over_template_at_equal_severity():
    """A leaked key must not be hidden behind a structural complaint."""
    out = summarize(
        _verdict(
            _template_bad(),
            _bad("secrets", severity=Severity.HIGH, reasons=["possible secret(s): aws_key"]),
        )
    )
    assert out["failed"][0]["category"] == "secrets"


def test_higher_severity_beats_category_priority():
    out = summarize(
        _verdict(
            _bad("secrets", severity=Severity.LOW),
            _bad("injection", severity=Severity.CRITICAL),
        )
    )
    assert out["failed"][0]["category"] == "injection"


def test_severity_labels_cover_every_valid_value():
    for sev, label in [
        (Severity.INFO, "info"), (Severity.LOW, "low"), (Severity.MEDIUM, "medium"),
        (Severity.HIGH, "high"), (Severity.CRITICAL, "critical"),
    ]:
        out = summarize(_verdict(_bad("secrets", severity=sev)))
        assert out["failed"][0]["severity"] == label


def test_unknown_category_still_reported():
    out = summarize(_verdict(_bad("brand_new_check", reasons=["nope"])))
    assert out["failed"][0]["category"] == "brand_new_check"
    assert out["failed"][0]["reasons"] == ["nope"]


def test_finding_with_no_reasons_gets_a_placeholder():
    out = summarize(_verdict(_bad("toxicity", reasons=[])))
    assert out["failed"][0]["reasons"] == ["toxicity check failed"]


def test_redacted_prompt_only_present_when_produced():
    assert "redacted_prompt" not in summarize(_verdict(_bad("secrets")))
    out = summarize(_verdict(_bad("pii"), action="redact", redacted="hi <EMAIL>"))
    assert out["redacted_prompt"] == "hi <EMAIL>"


def test_failed_key_absent_when_verdict_has_no_failed_finding():
    """Defensive: a not-passed verdict with no failing finding must not KeyError."""
    out = summarize(_verdict(_ok("secrets"), passed=False))
    assert out["passed"] is False
    assert "failed" not in out and "suggestion" not in out


def test_severity_outside_the_enum_is_rejected_upstream():
    with pytest.raises(Exception):
        Finding(category="x", detector="x.d", passed=False, severity=33)
