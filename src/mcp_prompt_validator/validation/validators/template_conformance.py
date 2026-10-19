"""Template-conformance check: does the submitted prompt derive from an
approved prompt template?

Structural, not semantic: the template's literal (non-variable) text segments
must all appear in the prompt, in order. Cheap and deterministic -- no ML/LLM
call. Only meaningful when the caller passes a `template_name` (via
`validate_prompt`'s `template_name` argument, threaded through as
`ctx["template_name"]`); otherwise this is a no-op pass, so it's safe to
always include in the default pipeline.

Matching is whitespace-insensitive: runs of whitespace in both the template
segment and the prompt collapse to a single space before comparison. Authors
paste prompts out of ticket trackers and markdown editors that freely add or
drop blank lines, and a template like "## Steps\n1. {{ step }}" would otherwise
reject an identically-structured prompt purely for having a blank line after the
heading. Whitespace carries no structural meaning here, so enforcing it only
produced false blocks.
"""

from __future__ import annotations

import re

from ...prompts import service as prompt_service
from ...prompts.render import literal_segments
from ..base import Validator, register
from ..contracts import Finding, Severity

_WHITESPACE = re.compile(r"\s+")


def _normalize(text: str) -> str:
    """Collapse whitespace runs to a single space so layout differences (blank
    lines, hard line breaks, indentation) do not affect the match."""
    return _WHITESPACE.sub(" ", text).strip()


@register
class TemplateConformanceValidator(Validator):
    name = "template_conformance.structural"
    category = "template_conformance"
    default_severity = Severity.HIGH

    async def validate(self, prompt: str, ctx: dict) -> Finding:
        template_name = ctx.get("template_name")
        if not template_name:
            return self._pass(reasons=["no template specified"])

        template = await prompt_service.get_for_user(template_name, ctx.get("username"))
        if template is None:
            return self._fail(
                reasons=[f"template '{template_name}' not found or not visible to caller"],
                metadata={"template": template_name},
            )

        haystack = _normalize(prompt)
        missing: list[str] = []
        pos = 0
        for seg in literal_segments(template["body"]):
            needle = _normalize(seg)
            if not needle:
                continue
            idx = haystack.find(needle, pos)
            if idx == -1:
                # Reported verbatim from the template, not normalized, so the
                # caller sees the field exactly as the template declares it.
                missing.append(seg)
            else:
                pos = idx + len(needle)

        if missing:
            return self._fail(
                reasons=[f"prompt does not conform to template '{template_name}'"],
                metadata={"template": template_name, "missing_segments": missing},
            )
        return self._pass(
            reasons=[f"conforms to template '{template_name}'"],
            metadata={"template": template_name},
        )
