"""Prompt-template tools (tag: "public") — per-user + global templates.

A caller sees only their own templates plus any marked global, mirroring the
dynamic skill supply but for prompts.
"""

from __future__ import annotations

from typing import Any

from ..identity import current_identity
from ..prompts import service as prompt_service
from ..prompts.render import PromptRenderError, render_prompt
from ..skills.registry import register_skill


def register_prompt_tools(mcp: Any) -> None:
    async def list_prompt_templates() -> list[dict]:
        """List prompt templates available to you (your own + global ones)."""
        ident = current_identity()
        username = ident.get("username")
        if not username:
            return []
        # Do not leak template bodies in the listing; names/description/vars only.
        return [
            {k: v for k, v in t.items() if k != "body"}
            for t in await prompt_service.list_for_user(username)
        ]

    async def render_prompt_template(name: str, variables: dict | None = None) -> dict:
        """Render one of your (or a global) prompt templates by name, filling in
        the given Jinja2 variables. Returns the rendered text."""
        ident = current_identity()
        username = ident.get("username")
        if not username:
            return {"ok": False, "error": "authentication required"}
        template = await prompt_service.get_for_user(name, username)
        if template is None:
            return {"ok": False, "error": f"prompt template '{name}' not found"}
        try:
            text = render_prompt(template["body"], variables or {})
        except PromptRenderError as exc:
            return {
                "ok": False,
                "error": f"render failed: {exc}",
                "variables": template.get("variables", []),
            }
        return {
            "ok": True,
            "name": name,
            "is_global": template["is_global"],
            "rendered": text,
        }

    register_skill(mcp, list_prompt_templates, name="list_prompt_templates", tags={"public"})
    register_skill(mcp, render_prompt_template, name="render_prompt_template", tags={"public"})
