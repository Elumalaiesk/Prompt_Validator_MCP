"""Template-conformance check: does the submitted prompt derive from an
approved prompt template?

Structural, not semantic: the template's literal (non-variable) text segments
must all appear in the prompt, in order. Cheap and deterministic -- no ML/LLM
call. Only meaningful when the caller passes a `template_name` (via
`validate_prompt`'s `template_name` argument, threaded through as
`ctx["template_name"]`); otherwise this is a no-op pass, so it's safe to
always include in the default pipeline.
"""

from __future__ import annotations

from ...prompts import service as prompt_service
from ...prompts.render import literal_segments
from ..base import Validator, register
from ..contracts import Finding, Severity


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

        segments = literal_segments(template["body"])
        missing: list[str] = []
        pos = 0
        for seg in segments:
            idx = prompt.find(seg, pos)
            if idx == -1:
                missing.append(seg)
            else:
                pos = idx + len(seg)

        if missing:
            return self._fail(
                reasons=[f"prompt does not conform to template '{template_name}'"],
                metadata={"template": template_name, "missing_segments": missing},
            )
        return self._pass(
            reasons=[f"conforms to template '{template_name}'"],
            metadata={"template": template_name},
        )
