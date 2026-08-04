"""Prompt-injection / jailbreak detection.

Combines two signals:
  * heuristics  -- always on; regex patterns for instruction-override and
                   role/delimiter manipulation. Cheap and dependency-free.
  * ML classifier -- optional; a HF text-classification model (default
                   Meta Llama-Prompt-Guard-2). Loaded lazily via transformers.

A prompt is flagged if the model score >= threshold OR a heuristic matches.
The two signals are complementary: heuristics catch the obvious, the model
catches the subtle, and neither alone is trusted (classifiers over-flag benign
technical prompts, so heuristics give an explainable second opinion).
"""

from __future__ import annotations

import asyncio
import re

from ...logging_setup import get_logger
from ..base import Validator, register
from ..contracts import Finding, Severity

log = get_logger(__name__)

_HEURISTICS: list[tuple[str, re.Pattern[str]]] = [
    ("ignore_previous", re.compile(r"(?i)\bignore\s+(?:all\s+)?(?:the\s+)?previous\s+instructions?")),
    ("disregard_above", re.compile(r"(?i)\bdisregard\s+(?:the\s+)?(?:above|prior|earlier)")),
    ("reveal_system_prompt", re.compile(r"(?i)\b(?:reveal|show|print|repeat)\b.{0,30}\b(?:system\s+prompt|instructions?)")),
    ("role_override", re.compile(r"(?i)\byou\s+are\s+now\b|\bact\s+as\b|\bpretend\s+to\s+be\b")),
    ("developer_mode", re.compile(r"(?i)\b(?:developer\s+mode|dan\s+mode|jailbreak)\b")),
    ("system_role_injection", re.compile(r"(?i)(?:^|\n)\s*(?:system|assistant)\s*[:\]]")),
    ("override_rules", re.compile(r"(?i)\b(?:no\s+longer\s+bound|forget\s+(?:all\s+)?(?:your\s+)?rules|without\s+any\s+restrictions)\b")),
]


@register
class PromptInjectionValidator(Validator):
    name = "injection.prompt_guard"
    category = "injection"
    default_severity = Severity.HIGH

    def __init__(
        self,
        model_id: str = "meta-llama/Llama-Prompt-Guard-2-86M",
        threshold: float = 0.8,
        use_model: bool = True,
    ) -> None:
        self.model_id = model_id
        self.threshold = threshold
        self.use_model = use_model
        self._clf = None
        # Heuristics run even if the model is absent/disabled.
        self._model_available = use_model

    async def preload(self) -> None:
        if not self.use_model:
            return
        await asyncio.to_thread(self._load)

    def _load(self) -> None:
        try:
            from transformers import pipeline

            self._clf = pipeline("text-classification", model=self.model_id, truncation=True)
        except Exception as exc:
            self._model_available = False
            log.warning("injection model unavailable; heuristics-only (%s)", exc)

    def _model_score(self, prompt: str) -> float | None:
        if self._clf is None:
            if not self._model_available:
                return None
            self._load()
            if self._clf is None:
                return None
        out = self._clf(prompt[:4000])
        # HF text-classification returns [{'label': ..., 'score': ...}]
        if not out:
            return None
        top = out[0]
        label = str(top.get("label", "")).upper()
        score = float(top.get("score", 0.0))
        # Map to probability-of-attack. Prompt-Guard style labels vary; treat
        # anything not clearly "benign"/"label_0" as the attack probability.
        if label in ("BENIGN", "SAFE", "LABEL_0", "NEGATIVE"):
            return 1.0 - score
        return score

    async def validate(self, prompt: str, ctx: dict) -> Finding:
        heuristic_hits = [name for name, pat in _HEURISTICS if pat.search(prompt)]
        model_score = await asyncio.to_thread(self._model_score, prompt)

        flagged = bool(heuristic_hits) or (model_score is not None and model_score >= self.threshold)
        if not flagged:
            return self._pass(score=model_score or 0.0)

        reasons: list[str] = []
        if model_score is not None and model_score >= self.threshold:
            reasons.append(f"injection classifier score {model_score:.2f} >= {self.threshold}")
        if heuristic_hits:
            reasons.append(f"heuristic patterns: {', '.join(heuristic_hits)}")
        return self._fail(
            severity=Severity.HIGH,
            score=model_score,
            reasons=reasons,
            metadata={"heuristics": heuristic_hits, "model_available": self._model_available},
        )
