"""Secrets / credential detection (dependency-free, regex-based).

A curated set of high-precision patterns for the credential shapes that most
commonly leak in prompts. Detected secret *types* are reported; the secret
*values* are never echoed back. `redact()` masks matches in place.
"""

from __future__ import annotations

import re

from ..base import Validator, register
from ..contracts import Finding, Severity

# (label, severity, compiled pattern). Order roughly by specificity.
_PATTERNS: list[tuple[str, Severity, re.Pattern[str]]] = [
    ("private_key", Severity.CRITICAL,
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("aws_access_key_id", Severity.HIGH, re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_access_key", Severity.HIGH,
     re.compile(r"(?i)aws(.{0,20})?(secret|access).{0,3}[:=]\s*[\"']?[A-Za-z0-9/+=]{40}")),
    ("github_pat", Severity.HIGH, re.compile(r"\bghp_[0-9A-Za-z]{36}\b")),
    ("github_fine_grained_pat", Severity.HIGH, re.compile(r"\bgithub_pat_[0-9A-Za-z_]{22,}\b")),
    ("slack_token", Severity.HIGH, re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("google_api_key", Severity.HIGH, re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("openai_api_key", Severity.HIGH, re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("jwt", Severity.MEDIUM,
     re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")),
    ("generic_assigned_secret", Severity.MEDIUM,
     re.compile(r"(?i)\b(api[_-]?key|secret|passwd|password|token)\b\s*[:=]\s*[\"']?[^\s\"']{8,}")),
]

_REDACT_MASK = "[REDACTED_SECRET]"


@register
class SecretsValidator(Validator):
    name = "secrets.regex"
    category = "secrets"
    default_severity = Severity.HIGH

    async def validate(self, prompt: str, ctx: dict) -> Finding:
        hits: list[str] = []
        worst = Severity.INFO
        for label, sev, pat in _PATTERNS:
            if pat.search(prompt):
                hits.append(label)
                worst = max(worst, sev)
        if not hits:
            return self._pass(score=0.0)
        return self._fail(
            severity=worst,
            score=1.0,
            reasons=[f"possible secret(s): {', '.join(sorted(set(hits)))}"],
            metadata={"types": sorted(set(hits))},
        )

    async def redact(self, prompt: str) -> str | None:
        text = prompt
        changed = False
        for _label, _sev, pat in _PATTERNS:
            text, n = pat.subn(_REDACT_MASK, text)
            changed = changed or n > 0
        return text if changed else None
