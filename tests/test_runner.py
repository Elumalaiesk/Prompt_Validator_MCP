"""Tests for the ValidationRunner (concurrency, fail-safe, redaction wiring)."""

from __future__ import annotations

import asyncio

from mcp_prompt_validator.validation.base import Validator
from mcp_prompt_validator.validation.contracts import Severity
from mcp_prompt_validator.validation.runner import ValidationRunner


class _Pass(Validator):
    name = "test.pass"
    category = "toxicity"

    async def validate(self, prompt, ctx):
        return self._pass()


class _Boom(Validator):
    name = "test.boom"
    category = "injection"

    async def validate(self, prompt, ctx):
        raise RuntimeError("kaboom")


class _Slow(Validator):
    name = "test.slow"
    category = "banned_topics"

    async def validate(self, prompt, ctx):
        await asyncio.sleep(5)
        return self._pass()


async def test_runner_aggregates_pass():
    runner = ValidationRunner([_Pass()])
    v = await runner.run("hello")
    assert v.passed
    assert v.action == "allow"


async def test_runner_fail_safe_on_exception():
    runner = ValidationRunner([_Boom()], fail_mode="safe")
    v = await runner.run("hello")
    assert not v.passed
    assert v.max_severity == Severity.HIGH
    assert v.action == "block"  # injection -> block


async def test_runner_fail_open():
    runner = ValidationRunner([_Boom()], fail_mode="open")
    v = await runner.run("hello")
    assert v.passed


async def test_runner_timeout_is_failsafe():
    runner = ValidationRunner([_Slow()], timeout=0.05, fail_mode="safe")
    v = await runner.run("hello")
    assert not v.passed
    assert any("timeout" in r for f in v.findings for r in f.reasons)


async def test_category_filter():
    runner = ValidationRunner([_Pass(), _Boom()])
    v = await runner.run("hello", categories=["toxicity"])
    assert v.categories_run == ["toxicity"]
    assert v.passed
