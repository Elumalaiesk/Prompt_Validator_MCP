"""ValidationRunner — runs validators concurrently and aggregates the verdict.

Each validator runs under a per-validator timeout. A timeout or exception does
not crash the run: it becomes a fail-safe Finding (HIGH severity, not passed) by
default, or a fail-open pass if configured. Redaction (for PII/secrets) is
applied after aggregation, only when the policy calls for it.
"""

from __future__ import annotations

import asyncio
import time

from ..logging_setup import get_logger
from .base import Validator
from .contracts import Finding, Severity, Verdict
from .policy import Aggregator

log = get_logger(__name__)


class ValidationRunner:
    def __init__(
        self,
        validators: list[Validator],
        aggregator: Aggregator | None = None,
        *,
        timeout: float = 8.0,
        fail_mode: str = "safe",
    ) -> None:
        self.validators = list(validators)
        self.aggregator = aggregator or Aggregator()
        self.timeout = timeout
        self.fail_mode = fail_mode
        self._preloaded = False

    async def preload_all(self) -> None:
        await asyncio.gather(*(self._safe_preload(v) for v in self.validators))
        self._preloaded = True
        log.info("preloaded %d validators", len(self.validators))

    async def _safe_preload(self, v: Validator) -> None:
        try:
            await v.preload()
        except Exception as exc:  # pragma: no cover - model load failures
            log.warning("preload failed for %s: %s", v.name, exc)

    async def run(
        self,
        prompt: str,
        categories: list[str] | None = None,
        extra_ctx: dict | None = None,
    ) -> Verdict:
        t0 = time.perf_counter()
        wanted = set(categories) if categories else None
        active = [
            v
            for v in self.validators
            if v.enabled and (wanted is None or v.category in wanted)
        ]
        ctx = extra_ctx or {}

        results = await asyncio.gather(*(self._run_one(v, prompt, ctx) for v in active))

        redacted: str | None = None
        if self.aggregator.needs_redaction(results):
            redacted = await self._redact(prompt, active, results)

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return self.aggregator.aggregate(
            list(results),
            categories_run=[v.category for v in active],
            elapsed_ms=elapsed_ms,
            redacted_prompt=redacted,
        )

    async def _run_one(self, v: Validator, prompt: str, ctx: dict) -> Finding:
        try:
            return await asyncio.wait_for(v.validate(prompt, ctx), timeout=self.timeout)
        except asyncio.TimeoutError:
            return self._fail_safe(v, "timeout")
        except Exception as exc:  # noqa: BLE001 - deliberately broad; fail safe
            return self._fail_safe(v, f"error: {exc}")

    def _fail_safe(self, v: Validator, reason: str) -> Finding:
        if self.fail_mode == "open":
            return Finding(
                category=v.category,
                detector=v.name,
                passed=True,
                severity=Severity.INFO,
                reasons=[f"validator unavailable ({reason}); failed open"],
            )
        return Finding(
            category=v.category,
            detector=v.name,
            passed=False,
            severity=Severity.HIGH,
            reasons=[f"validator error ({reason}); failed safe"],
        )

    async def _redact(
        self, prompt: str, active: list[Validator], results: list[Finding]
    ) -> str:
        text = prompt
        failed_cats = {f.category for f in results if not f.passed}
        for v in active:
            if v.category in failed_cats:
                try:
                    red = await v.redact(text)
                    if red is not None:
                        text = red
                except Exception as exc:  # pragma: no cover
                    log.warning("redact failed for %s: %s", v.name, exc)
        return text
