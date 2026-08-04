"""Skill-document tools (tag: "public") — per-user + global Markdown "skills".

Every MCP client is a user, so a connecting agent can discover the skill.md
documents assigned to it (`list_skills`) and fetch one (`get_skill`). A caller
sees only their own skills plus any marked global, mirroring the prompt-template
supply. This is content served through the tool surface, distinct from
`skills/registry.py::TOOL_TAGS`, which gates the *tools themselves*.

Tools (not MCP prompts/resources) on purpose: an agent has to be able to reach
for a skill autonomously, and `prompts/*` + `resources/*` surface in clients as
user-initiated pickers.
"""

from __future__ import annotations

from typing import Any

from ..audit import record
from ..identity import current_identity
from ..skills.registry import register_skill
from ..skillset import service as skill_service


def register_skill_content_tools(mcp: Any) -> None:
    async def list_skills() -> list[dict]:
        """List the skill documents available to you (yours + global ones).

        Returns name + description only. Call `get_skill` for the full body once
        you have decided a skill applies.
        """
        ident = current_identity()
        username = ident.get("username")
        if not username:
            return []
        return await skill_service.list_for_user(username)

    async def get_skill(name: str) -> dict:
        """Fetch one of your (or a global) skill documents' full Markdown body."""
        ident = current_identity()
        username = ident.get("username")
        if not username:
            return {"ok": False, "error": "authentication required"}

        skill = await skill_service.get_for_user(name, username)
        if skill is None:
            # Same response whether the skill does not exist or is not assigned
            # to this caller — do not confirm the existence of others' skills.
            await record(
                action="skill.read",
                username=username,
                token_id=ident.get("token_id"),
                tool_name="get_skill",
                decision="deny",
                detail={"skill": name, "reason": "not found or not assigned"},
            )
            return {"ok": False, "error": f"skill '{name}' not found"}

        await record(
            action="skill.read",
            username=username,
            token_id=ident.get("token_id"),
            tool_name="get_skill",
            decision="allow",
            detail={"skill": name, "is_global": skill["is_global"]},
        )
        return {"ok": True, **skill}

    register_skill(mcp, list_skills, name="list_skills", tags={"public"})
    register_skill(mcp, get_skill, name="get_skill", tags={"public"})
