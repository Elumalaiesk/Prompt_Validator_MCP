"""Caller-facing response shaping.

Every validator always runs (see `runner.ValidationRunner.run`); this module only
decides how much of the result the caller is told:

  * passed -> a bare confirmation.
  * failed -> one `failed` object: the category, its severity, and the reasons.

Deliberately minimal. The complete run — every finding, passing ones included,
with scores, the template name and its missing segments — is written to
`audit_logs.detail`, which is the record to consult when a caller reports an
unexpected block.

Two rules for anything added here:
  * Findings carry type LABELS, never matched values (secrets reports
    `{"types": ["aws_access_key_id"]}`, PII reports `{"entities": ["EMAIL_ADDRESS"]}`),
    so reasons are safe to echo. Never interpolate the prompt text.
  * Template conformance reasons stay generic — naming the template or listing
    its section headings hands the caller the approved structure.
"""

from __future__ import annotations

from .contracts import Finding, Severity, Verdict

_SEVERITY_NAMES = {
    Severity.INFO: "info",
    Severity.LOW: "low",
    Severity.MEDIUM: "medium",
    Severity.HIGH: "high",
    Severity.CRITICAL: "critical",
}

# Tie-break order when several categories fail at the same severity: only one
# `failed` object is returned, so the most urgent category has to win. A leaked
# credential must never be hidden behind a structural complaint — a prompt that
# both breaks the template AND carries an AWS key reports the key.
_CATEGORY_PRIORITY = [
    "secrets",
    "pii",
    "injection",
    "banned_topics",
    "toxicity",
    "template_conformance",
    "schema",
]

# Structural mismatch is reported without naming the template or its headings.
_GENERIC_REASONS = {
    "template_conformance": ["prompt does not match the expected structure"],
}


def _rank(f: Finding) -> tuple[int, int]:
    """Sort key: highest severity first, then category urgency."""
    try:
        priority = _CATEGORY_PRIORITY.index(f.category)
    except ValueError:
        priority = len(_CATEGORY_PRIORITY)  # unknown category sorts last
    return (-int(f.severity), priority)


def _reasons(f: Finding) -> list[str]:
    """The detector's reasons, or a generic line for categories we don't detail.

    Secrets, PII, injection, toxicity and banned-topics pass through unchanged —
    those reasons name the credential type, entity type or triggered heuristic,
    which is what makes a failure actionable.
    """
    if f.category in _GENERIC_REASONS:
        return list(_GENERIC_REASONS[f.category])
    if not f.reasons:
        return [f"{f.category} check failed"]
    return list(f.reasons)


def summarize(verdict: Verdict) -> dict:
    """Reduce a full Verdict to pass/fail plus the single worst failure."""
    if verdict.passed:
        return {
            "passed": True,
            "status": "validation passed",
            "action": verdict.action,
        }

    failures = sorted((f for f in verdict.findings if not f.passed), key=_rank)
    out: dict = {
        "passed": False,
        "status": "validation failed",
        "action": verdict.action,
    }
    if failures:
        worst = failures[0]
        out["failed"] = {
            "category": worst.category,
            "severity": _SEVERITY_NAMES.get(worst.severity, str(int(worst.severity))),
            "reasons": _reasons(worst),
        }
    # Present only when the policy chose redaction over an outright block —
    # without it a `redact` action gives the caller nothing to send onward.
    if verdict.redacted_prompt is not None:
        out["redacted_prompt"] = verdict.redacted_prompt
    return out
