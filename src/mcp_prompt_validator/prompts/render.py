"""Safe Jinja2 rendering for user-supplied prompt templates.

Templates come from users, so they are rendered in a SandboxedEnvironment
(blocks access to unsafe attributes/callables) with autoescape off (prompts are
plain text, not HTML) and undefined variables raising, so callers get a clear
error rather than a silently blank prompt.
"""

from __future__ import annotations

from jinja2 import StrictUndefined
from jinja2.exceptions import TemplateError
from jinja2.sandbox import SandboxedEnvironment

_ENV = SandboxedEnvironment(autoescape=False, undefined=StrictUndefined)


class PromptRenderError(ValueError):
    """Raised when a template fails to render (bad syntax or missing variable)."""


def render_prompt(body: str, variables: dict | None = None) -> str:
    try:
        template = _ENV.from_string(body)
        return template.render(**(variables or {}))
    except TemplateError as exc:
        raise PromptRenderError(str(exc)) from exc


def declared_variables(body: str) -> list[str]:
    """Best-effort list of the variables a template references (for the UI)."""
    from jinja2 import meta

    try:
        ast = _ENV.parse(body)
        return sorted(meta.find_undeclared_variables(ast))
    except TemplateError:
        return []


def literal_segments(body: str) -> list[str]:
    """The template's literal (non-variable) text chunks, in order.

    Used for structural template-conformance checks (see
    `validation/validators/template_conformance.py`): a prompt "derives from"
    this template if all of these segments appear in it, in order.
    """
    from jinja2 import nodes

    try:
        ast = _ENV.parse(body)
    except TemplateError:
        return []
    return [n.data.strip() for n in ast.find_all(nodes.TemplateData) if n.data.strip()]
