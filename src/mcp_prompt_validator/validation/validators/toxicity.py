"""Profanity / toxicity detection.

Two-stage, cost-aware:
  * fast gate  -- `better-profanity` wordlist match (always available, core dep).
  * ML stage   -- Detoxify transformer scores (optional [ml] extra). When
                  present it is authoritative; the score drives severity.

If Detoxify is unavailable the fast gate still provides a lexical signal.
"""

from __future__ import annotations

import asyncio

from ...logging_setup import get_logger
from ..base import Validator, register
from ..contracts import Finding, Severity

log = get_logger(__name__)


@register
class ToxicityValidator(Validator):
    name = "toxicity.detoxify"
    category = "toxicity"
    default_severity = Severity.MEDIUM

    def __init__(
        self, model_variant: str = "original", threshold: float = 0.6, use_model: bool = True
    ) -> None:
        self.model_variant = model_variant
        self.threshold = threshold
        self.use_model = use_model
        self._model = None
        self._model_available = use_model
        self._profanity = None

    async def preload(self) -> None:
        await asyncio.to_thread(self._load)

    def _load(self) -> None:
        # Fast lexical gate (core dependency).
        try:
            from better_profanity import profanity

            profanity.load_censor_words()
            self._profanity = profanity
        except Exception as exc:  # pragma: no cover
            log.warning("better-profanity unavailable (%s)", exc)
        if not self.use_model:
            return
        # ML model (optional).
        try:
            from detoxify import Detoxify

            self._model = Detoxify(self.model_variant)
        except Exception as exc:
            self._model_available = False
            log.warning("Detoxify unavailable; lexical gate only (%s)", exc)

    def _scores(self, prompt: str) -> dict[str, float] | None:
        if self._model is None:
            if not self._model_available:
                return None
            self._load()
            if self._model is None:
                return None
        raw = self._model.predict(prompt[:4000])
        return {k: float(v) for k, v in raw.items()}

    async def validate(self, prompt: str, ctx: dict) -> Finding:
        if self._profanity is None and self._model is None:
            await asyncio.to_thread(self._load)

        profane = bool(self._profanity and self._profanity.contains_profanity(prompt))
        scores = await asyncio.to_thread(self._scores, prompt)

        if scores is not None:
            tox = scores.get("toxicity", 0.0)
            flagged = tox >= self.threshold
            if not flagged:
                return self._pass(score=tox, metadata={"scores": _round(scores)})
            severity = Severity.HIGH if tox >= 0.85 else Severity.MEDIUM
            return self._fail(
                severity=severity,
                score=tox,
                reasons=[f"toxicity score {tox:.2f} >= {self.threshold}"],
                metadata={"scores": _round(scores)},
            )

        # ML unavailable: rely on the lexical gate.
        if profane:
            return self._fail(
                severity=Severity.MEDIUM,
                score=1.0,
                reasons=["profanity detected (lexical gate; ML model unavailable)"],
                metadata={"lexical": True},
            )
        return self._pass(reasons=["lexical gate only (ML model unavailable)"])


def _round(scores: dict[str, float]) -> dict[str, float]:
    return {k: round(v, 3) for k, v in scores.items()}
