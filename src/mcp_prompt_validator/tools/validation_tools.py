"""Validator-facing tools (tag: "validator", plus "public" info tools).

Available to any authenticated user (std_user or admin) — only tools tagged
"admin" are restricted to the admin role.
"""

from __future__ import annotations

from typing import Any

from ..audit import record
from ..config import get_settings
from ..identity import current_identity
from ..rbac import service as rbac_service
from ..skills.registry import TOOL_TAGS, register_skill
from ..validation.response import summarize
from ..validation.runner import ValidationRunner


def _shape(verdict) -> dict:
    """Full verdict or pass/fail summary, per `validation_response_mode`."""
    if get_settings().validation_response_mode == "full":
        return verdict.model_dump(mode="json")
    return summarize(verdict)


def _effective_categories(requested: list[str] | None) -> list[str] | None:
    """None (= run everything) unless partial validation is explicitly allowed.

    Every validator must run, so a caller-supplied filter is dropped by default.
    Honouring it would let a client silently skip checks — the same hole the
    optional `template_name` created.
    """
    if get_settings().enforce_all_categories:
        return None
    return requested


async def _build_ctx(template_name: str | None = None, **extra) -> dict:
    """Assemble the validator context for the current caller.

    A `required_template` on the user WINS over whatever the client sent. That
    ordering is the whole point: template conformance used to be skipped
    silently whenever the caller omitted `template_name`, which made a policy
    opt-out by accident. With a required template set, the server supplies it on
    every call, so a client can neither disable the check by omitting the
    argument nor redirect it by naming a different template.
    """
    ident = current_identity()
    username = ident.get("username")
    required = await rbac_service.get_required_template(username) if username else None
    return {
        "template_name": required or template_name,
        "username": username,
        # Recorded in the audit trail so a pass can be told apart from a
        # not-checked, and an override attempt is visible after the fact.
        "template_required": required,
        "template_requested": template_name,
        **extra,
    }


def register_validation_tools(mcp: Any, runner: ValidationRunner) -> None:
    async def validate_prompt(
        prompt: str, categories: list[str] | None = None, template_name: str | None = None
    ) -> dict:
        """Validate a prompt against the full policy. Every check always runs.

        On success returns `{passed: true, status: "validation passed"}`.
        On failure returns `{passed: false, status: "validation failed"}` plus a
        `failed` list naming each failed category (ordered worst-first) with the
        reasons, a top-level `suggestion` for fixing the prompt, and — when the
        attached template is not met — the missing template fields on the
        `template_conformance` entry. Fix the highest-severity entry first and
        re-validate.

        `categories` is ignored unless the server permits partial validation.
        `template_name` requires the prompt to derive from one of your (or a
        global) approved templates; if an administrator assigned you a REQUIRED
        template it is applied automatically and takes precedence.
        """
        ctx = await _build_ctx(template_name, requested_categories=categories)
        verdict = await runner.run(
            prompt, categories=_effective_categories(categories), extra_ctx=ctx
        )
        await _audit(verdict, "validate_prompt", ctx)
        return _shape(verdict)

    async def validate_prompts(prompts: list[str]) -> list[dict]:
        """Batch variant of validate_prompt. Validates each prompt with the full
        policy and returns a list of verdicts in the same order.

        Any REQUIRED template assigned to you applies to every prompt in the batch.
        """
        # Resolved once: the required template cannot change mid-batch, and this
        # keeps the lookup off the per-prompt path.
        ctx = await _build_ctx()
        verdicts = []
        for p in prompts:
            v = await runner.run(p, extra_ctx=ctx)
            verdicts.append(_shape(v))
        await record(
            action="tool.call",
            username=ctx["username"],
            token_id=current_identity().get("token_id"),
            tool_name="validate_prompts",
            decision="batch",
            detail={
                "count": len(prompts),
                "blocked": sum(1 for v in verdicts if not v["passed"]),
                "template_required": ctx["template_required"],
            },
        )
        return verdicts

    async def validate_structured(prompt: str, json_schema: dict) -> dict:
        """Validate that `prompt` is valid JSON conforming to `json_schema`
        (JSON Schema draft 2020-12), in addition to the standard safety checks.

        Any REQUIRED template assigned to you is enforced here too.
        """
        ctx = await _build_ctx(json_schema=json_schema)
        verdict = await runner.run(prompt, extra_ctx=ctx)
        await _audit(verdict, "validate_structured", ctx)
        return _shape(verdict)

    async def redact_prompt(prompt: str) -> dict:
        """Return a redacted copy of the prompt with PII and secrets masked,
        alongside the findings that triggered redaction."""
        verdict = await runner.run(prompt, categories=["pii", "secrets"])
        await _audit(verdict, "redact_prompt")
        return {
            "redacted_prompt": verdict.redacted_prompt or prompt,
            "changed": verdict.redacted_prompt is not None,
            "findings": [f.model_dump(mode="json") for f in verdict.findings],
        }

    async def whoami() -> dict:
        """Return the authenticated caller's identity, role and permitted tags."""
        return current_identity()

    async def list_available_skills() -> list[dict]:
        """List the tools the current caller is permitted to use."""
        ident = current_identity()
        is_admin = bool(ident.get("is_admin"))
        skills = []
        for name, tags in sorted(TOOL_TAGS.items()):
            if is_admin or "admin" not in tags:
                skills.append({"name": name, "tags": sorted(tags)})
        return skills

    # --- register with tags -----------------------------------------------
    register_skill(mcp, validate_prompt, name="validate_prompt", tags={"validator"})
    register_skill(mcp, validate_prompts, name="validate_prompts", tags={"validator"})
    register_skill(mcp, validate_structured, name="validate_structured", tags={"validator"})
    register_skill(mcp, redact_prompt, name="redact_prompt", tags={"validator", "pii"})
    register_skill(mcp, whoami, name="whoami", tags={"public"})
    register_skill(mcp, list_available_skills, name="list_available_skills", tags={"public"})


async def _audit(verdict, tool_name: str, ctx: dict | None = None) -> None:
    ident = current_identity()
    detail = {
        "passed": verdict.passed,
        "max_severity": int(verdict.max_severity),
        "categories": verdict.categories_run,
        "elapsed_ms": round(verdict.elapsed_ms, 1),
        # The caller now only receives failed categories, so the log is the sole
        # record of the whole run. Findings carry type labels (e.g. "EMAIL_ADDRESS",
        # "aws_access_key"), never matched values, so this is safe to persist —
        # keep it that way and never add the prompt text here.
        "findings": [
            {
                "category": f.category,
                "detector": f.detector,
                "passed": f.passed,
                "severity": int(f.severity),
                "score": f.score,
                "reasons": f.reasons,
                "metadata": f.metadata,
            }
            for f in verdict.findings
        ],
    }
    if ctx:
        # Distinguishes "conformance passed" from "conformance was never checked",
        # which both previously logged an identical categories list.
        detail["template_enforced"] = ctx.get("template_required")
        detail["template_checked"] = ctx.get("template_name")
        requested = ctx.get("requested_categories")
        if requested:
            # A dropped filter is a bypass attempt worth seeing in the trail.
            detail["categories_requested"] = requested
    await record(
        action="tool.call",
        username=ident.get("username"),
        token_id=ident.get("token_id"),
        tool_name=tool_name,
        decision=verdict.action,
        detail=detail,
    )
