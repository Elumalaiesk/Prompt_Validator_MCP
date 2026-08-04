"""Banned-topics detection via zero-shot NLI classification.

Uses a zero-shot-classification pipeline (default facebook/bart-large-mnli) to
score the prompt against a configurable list of banned topic labels. Any label
scoring >= threshold flags the prompt. Disables itself if transformers is
absent.
"""

from __future__ import annotations

import asyncio

from ...logging_setup import get_logger
from ..base import Validator, register
from ..contracts import Finding, Severity

log = get_logger(__name__)


@register
class BannedTopicsValidator(Validator):
    name = "banned_topics.zeroshot"
    category = "banned_topics"
    default_severity = Severity.HIGH

    def __init__(
        self,
        model_id: str = "facebook/bart-large-mnli",
        topics: list[str] | None = None,
        threshold: float = 0.75,
    ) -> None:
        self.model_id = model_id
        self.topics = list(topics or [])
        self.threshold = threshold
        self._clf = None

    async def preload(self) -> None:
        if not self.topics:
            self.enabled = False
            return
        await asyncio.to_thread(self._load)

    def _load(self) -> None:
        try:
            from transformers import pipeline

            self._clf = pipeline("zero-shot-classification", model=self.model_id)
        except Exception as exc:
            self.enabled = False
            log.warning("banned-topics model unavailable; validator disabled (%s)", exc)

    def _classify(self, prompt: str) -> list[tuple[str, float]]:
        if self._clf is None:
            self._load()
        if self._clf is None:
            return []
        out = self._clf(prompt[:4000], candidate_labels=self.topics, multi_label=True)
        return list(zip(out["labels"], out["scores"]))

    async def validate(self, prompt: str, ctx: dict) -> Finding:
        if not self.enabled or not self.topics:
            return self._pass(reasons=["banned-topics detector unavailable"])
        scored = await asyncio.to_thread(self._classify, prompt)
        flagged = [(label, score) for label, score in scored if score >= self.threshold]
        if not flagged:
            top = max((s for _, s in scored), default=0.0)
            return self._pass(score=top)
        labels = [lbl for lbl, _ in flagged]
        return self._fail(
            severity=Severity.HIGH,
            score=max(s for _, s in flagged),
            reasons=[f"banned topic(s): {', '.join(labels)}"],
            metadata={"topics": {lbl: round(s, 3) for lbl, s in flagged}},
        )
