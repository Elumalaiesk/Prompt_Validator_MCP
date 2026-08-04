"""Length / format / schema validation.

Checks (in order):
  1. character length vs max_chars;
  2. token length vs max_tokens (tiktoken; falls back to a chars/4 estimate);
  3. optional JSON-Schema conformance when the caller supplies `json_schema`
     in the context (the prompt is parsed as JSON and validated), or requires
     JSON via `require_json`.
"""

from __future__ import annotations

import asyncio
import json

from ..base import Validator, register
from ..contracts import Finding, Severity


@register
class SchemaValidator(Validator):
    name = "schema.length_format"
    category = "schema"
    default_severity = Severity.MEDIUM

    def __init__(
        self,
        max_chars: int = 20_000,
        max_tokens: int = 6_000,
        encoding_name: str = "cl100k_base",
    ) -> None:
        self.max_chars = max_chars
        self.max_tokens = max_tokens
        self.encoding_name = encoding_name
        self._encoding = None  # lazy tiktoken encoding

    async def preload(self) -> None:
        await asyncio.to_thread(self._load_encoding)

    def _load_encoding(self) -> None:
        try:
            import tiktoken

            self._encoding = tiktoken.get_encoding(self.encoding_name)
        except Exception:
            self._encoding = None  # fall back to estimate

    def _count_tokens(self, text: str) -> int:
        if self._encoding is None:
            self._load_encoding()
        if self._encoding is not None:
            return len(self._encoding.encode(text))
        return max(1, len(text) // 4)  # rough estimate

    async def validate(self, prompt: str, ctx: dict) -> Finding:
        reasons: list[str] = []
        metadata: dict = {}

        n_chars = len(prompt)
        metadata["chars"] = n_chars
        if n_chars > self.max_chars:
            reasons.append(f"length {n_chars} chars exceeds max {self.max_chars}")

        n_tokens = await asyncio.to_thread(self._count_tokens, prompt)
        metadata["tokens"] = n_tokens
        if n_tokens > self.max_tokens:
            reasons.append(f"length {n_tokens} tokens exceeds max {self.max_tokens}")

        # Optional JSON / schema checks driven by the tool caller.
        json_schema = ctx.get("json_schema")
        require_json = bool(ctx.get("require_json") or json_schema)
        if require_json:
            parsed, err = _try_parse_json(prompt)
            if err:
                reasons.append(f"expected valid JSON: {err}")
            elif json_schema is not None:
                schema_err = await asyncio.to_thread(_validate_schema, parsed, json_schema)
                if schema_err:
                    reasons.append(f"schema violation: {schema_err}")

        if reasons:
            return self._fail(severity=Severity.MEDIUM, reasons=reasons, metadata=metadata)
        return self._pass(metadata=metadata)


def _try_parse_json(text: str):
    try:
        return json.loads(text), None
    except json.JSONDecodeError as exc:
        return None, str(exc)


def _validate_schema(instance, schema) -> str | None:
    try:
        import jsonschema

        jsonschema.validate(instance=instance, schema=schema)
        return None
    except Exception as exc:  # jsonschema.ValidationError or import error
        return str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
