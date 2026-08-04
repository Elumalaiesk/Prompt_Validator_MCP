"""PII detection & redaction via Microsoft Presidio.

If Presidio (and its spaCy model) are not installed, the validator disables
itself at preload so the pipeline still runs the other categories. In the
production image the [ml] extra + `en_core_web_lg` are installed.
"""

from __future__ import annotations

import asyncio

from ...logging_setup import get_logger
from ..base import Validator, register
from ..contracts import Finding, Severity

log = get_logger(__name__)


@register
class PresidioPIIValidator(Validator):
    name = "pii.presidio"
    category = "pii"
    default_severity = Severity.MEDIUM

    def __init__(self, threshold: float = 0.5, spacy_model: str = "en_core_web_lg") -> None:
        self.threshold = threshold
        self.spacy_model = spacy_model
        self._analyzer = None
        self._anonymizer = None

    async def preload(self) -> None:
        await asyncio.to_thread(self._load)

    def _load(self) -> None:
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_anonymizer import AnonymizerEngine
        except Exception as exc:
            self.enabled = False
            log.warning("Presidio unavailable; PII validator disabled (%s)", exc)
            return
        # Default engine loads en_core_web_lg. For a different spaCy model, wire
        # a NlpEngineProvider here; kept simple to match the documented default.
        self._analyzer = AnalyzerEngine()
        self._anonymizer = AnonymizerEngine()

    def _ensure(self) -> bool:
        if self._analyzer is None and self.enabled:
            self._load()
        return self.enabled and self._analyzer is not None

    async def validate(self, prompt: str, ctx: dict) -> Finding:
        if not await asyncio.to_thread(self._ensure):
            return self._pass(reasons=["PII detector unavailable"])
        results = await asyncio.to_thread(
            self._analyzer.analyze, text=prompt, language="en"
        )
        hits = [r for r in results if r.score >= self.threshold]
        if not hits:
            return self._pass(score=0.0)
        entities = sorted({r.entity_type for r in hits})
        return self._fail(
            score=max(r.score for r in hits),
            reasons=[f"PII detected: {', '.join(entities)}"],
            metadata={"entities": entities, "count": len(hits)},
        )

    async def redact(self, prompt: str) -> str | None:
        if not await asyncio.to_thread(self._ensure):
            return None
        results = await asyncio.to_thread(
            self._analyzer.analyze, text=prompt, language="en"
        )
        if not results:
            return None
        anonymized = await asyncio.to_thread(
            lambda: self._anonymizer.anonymize(text=prompt, analyzer_results=results)
        )
        return anonymized.text
