"""Aggregation policy: turn per-category Findings into one Verdict + Action.

Each category maps to an `on_fail` action. The overall action is the most
severe action across all failed findings, using the precedence:

    block  >  redact  >  flag  >  allow

`passed` is True only when the prompt is usable as-is (allow or flag). A
`redact` outcome means the original is not acceptable but a sanitised version
can be produced; `block` means reject outright.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .contracts import Action, Finding, Severity, Verdict

_PRECEDENCE: dict[Action, int] = {"allow": 0, "flag": 1, "redact": 2, "block": 3}


@dataclass(frozen=True)
class CategoryPolicy:
    on_fail: Action = "block"


# Sensible, security-leaning defaults. Override per deployment if needed.
DEFAULT_POLICY: dict[str, CategoryPolicy] = {
    "injection": CategoryPolicy(on_fail="block"),
    "secrets": CategoryPolicy(on_fail="block"),
    "banned_topics": CategoryPolicy(on_fail="block"),
    "schema": CategoryPolicy(on_fail="block"),
    "pii": CategoryPolicy(on_fail="redact"),
    "toxicity": CategoryPolicy(on_fail="flag"),
    "template_conformance": CategoryPolicy(on_fail="block"),
}


@dataclass
class Aggregator:
    policy: dict[str, CategoryPolicy] = field(default_factory=lambda: dict(DEFAULT_POLICY))

    def action_for(self, finding: Finding) -> Action:
        if finding.passed:
            return "allow"
        return self.policy.get(finding.category, CategoryPolicy()).on_fail

    def aggregate(
        self,
        findings: list[Finding],
        *,
        categories_run: list[str],
        elapsed_ms: float,
        redacted_prompt: str | None = None,
    ) -> Verdict:
        overall: Action = "allow"
        max_sev = Severity.INFO
        for f in findings:
            act = self.action_for(f)
            if _PRECEDENCE[act] > _PRECEDENCE[overall]:
                overall = act
            if not f.passed and f.severity > max_sev:
                max_sev = f.severity

        passed = overall in ("allow", "flag")
        return Verdict(
            passed=passed,
            action=overall,
            max_severity=max_sev,
            findings=findings,
            redacted_prompt=redacted_prompt if overall == "redact" else None,
            elapsed_ms=round(elapsed_ms, 2),
            categories_run=categories_run,
        )

    def needs_redaction(self, findings: list[Finding]) -> bool:
        return any(self.action_for(f) == "redact" for f in findings)
