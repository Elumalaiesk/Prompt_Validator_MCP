"""Caller-facing response shaping.

Every validator always runs (see `runner.ValidationRunner.run`); this module only
decides how much of the result the caller is told:

  * passed -> a bare confirmation.
  * failed -> a `failed` list, one entry per failed category ordered worst-first
    (highest severity, then category urgency), each with its severity and the
    reasons for that category, plus a top-level `suggestion` that names the
    failed categories in plain English and points at what to fix.

The complete run — every finding, passing ones included, with scores, the
template name and its missing segments — is written to `audit_logs.detail`,
which is the record to consult when a caller reports an unexpected block.

Two rules for anything added here:
  * Findings carry type LABELS, never matched values (secrets reports
    `{"types": ["aws_access_key_id"]}`, PII reports `{"entities": ["EMAIL_ADDRESS"]}`),
    so reasons are safe to echo. Never interpolate the prompt text.
  * The template NAME is never echoed. The literal segments the prompt is
    missing are listed as `missing_fields` on the template_conformance entry:
    the caller supplied the template, so those segments are already known to
    them — and without them a structural failure is not actionable.
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

# Tie-break order when several categories fail at the same severity. A leaked
# credential must never be hidden behind a structural complaint — a prompt that
# both breaks the template AND carries an AWS key lists secrets first.
_CATEGORY_PRIORITY = [
    "secrets",
    "pii",
    "injection",
    "banned_topics",
    "toxicity",
    "template_conformance",
    "schema",
]

# Plain-English names used in the suggestion message.
_CATEGORY_LABELS = {
    "secrets": "secrets",
    "pii": "PII",
    "injection": "prompt injection",
    "banned_topics": "banned topics",
    "toxicity": "toxicity",
    "template_conformance": "template structure",
    "schema": "schema validation",
}

# Missing template segments longer than this are trimmed in the response so a
# template with prose blocks does not bloat the caller-facing payload.
_MAX_FIELD_LEN = 140


def _rank(f: Finding) -> tuple[int, int]:
    """Sort key: highest severity first, then category urgency."""
    try:
        priority = _CATEGORY_PRIORITY.index(f.category)
    except ValueError:
        priority = len(_CATEGORY_PRIORITY)  # unknown category sorts last
    return (-int(f.severity), priority)


def _label(category: str) -> str:
    """Human-readable category name for the suggestion message."""
    return _CATEGORY_LABELS.get(category, category.replace("_", " "))


def _join(items: list[str]) -> str:
    """'a, b and c' — natural English for the suggestion message."""
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + " and " + items[-1]


def _reasons(f: Finding) -> list[str]:
    """The detector's reasons, or a generic line for categories we don't detail.

    Secrets, PII, injection, toxicity and banned-topics pass through unchanged —
    those reasons name the credential type, entity type or triggered heuristic,
    which is what makes a failure actionable. Template reasons stay generic:
    a structural mismatch is one message, a template that could not be used is
    another, and neither ever names the template.
    """
    if f.category == "template_conformance":
        if f.metadata.get("missing_segments"):
            return ["prompt does not match the expected structure"]
        return ["template not found or not visible to the caller"]
    if not f.reasons:
        return [f"{f.category} check failed"]
    return list(f.reasons)


def _trim_field(field: str) -> str:
    field = field.strip()
    if len(field) <= _MAX_FIELD_LEN:
        return field
    return field[:_MAX_FIELD_LEN - 1].rstrip() + "…"


def _failed_entry(f: Finding) -> dict:
    """One entry of the `failed` list: category, severity, reasons, and the
    template's missing fields when a structural check failed."""
    entry = {
        "category": f.category,
        "severity": _SEVERITY_NAMES.get(f.severity, str(int(f.severity))),
        "reasons": _reasons(f),
    }
    if f.category == "template_conformance":
        missing = f.metadata.get("missing_segments")
        if missing:
            entry["missing_fields"] = [_trim_field(m) for m in missing]
    return entry


def _suggestion(failures: list[Finding]) -> str:
    """One concise, actionable sentence naming every failed category.

    e.g. "Your description failed in prompt injection and secrets. It also
    doesn't match the attached template structure — include the missing fields
    below."
    """
    content: list[Finding] = []
    template_missing = False
    for f in failures:
        if f.category == "template_conformance" and f.metadata.get("missing_segments"):
            # Structural failures with concrete missing fields get their own
            # dedicated sentence (and the fields are listed on the entry).
            template_missing = True
        else:
            content.append(f)
    parts = []
    if content:
        labels = [_label(f.category) for f in content]
        parts.append(f"Your description failed in {_join(labels)}.")
    if template_missing:
        lead = "It also doesn't" if content else "It doesn't"
        parts.append(
            f"{lead} match the attached template structure — include the missing fields below."
        )
    return " ".join(parts)


def summarize(verdict: Verdict) -> dict:
    """Reduce a full Verdict to pass/fail plus every failed category."""
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
        # One entry per category — the sorted order keeps the worst finding of
        # each category first.
        deduped: list[Finding] = []
        seen: set[str] = set()
        for f in failures:
            if f.category not in seen:
                seen.add(f.category)
                deduped.append(f)
        out["failed"] = [_failed_entry(f) for f in deduped]
        out["suggestion"] = _suggestion(deduped)
    # Present only when the policy chose redaction over an outright block —
    # without it a `redact` action gives the caller nothing to send onward.
    if verdict.redacted_prompt is not None:
        out["redacted_prompt"] = verdict.redacted_prompt
    return out
