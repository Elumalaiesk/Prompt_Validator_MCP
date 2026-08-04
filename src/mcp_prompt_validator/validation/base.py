"""Validator base class + a simple registry.

Adding a new policy category is: subclass `Validator`, implement `validate`
(and optionally `preload`/`redact`), and register it. No orchestrator changes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable

from .contracts import Finding, Severity


class Validator(ABC):
    """One detector for one category.

    Subclasses set `name`, `category`, `default_severity`. Heavy/blocking work
    (ML inference, model loading) MUST be wrapped in `asyncio.to_thread` inside
    `validate`/`preload` so the event loop is never blocked.
    """

    name: str = "validator"
    category: str = "generic"
    default_severity: Severity = Severity.MEDIUM
    enabled: bool = True

    async def preload(self) -> None:
        """Optional: load models once at startup. Default is a no-op."""
        return None

    @abstractmethod
    async def validate(self, prompt: str, ctx: dict) -> Finding:
        """Return a Finding for `prompt`. Must not raise for normal input."""

    async def redact(self, prompt: str) -> str | None:
        """Optional: return a redacted version of the prompt (PII/secrets)."""
        return None

    # -- helpers for subclasses --------------------------------------------
    def _pass(self, **kw) -> Finding:
        return Finding(category=self.category, detector=self.name, passed=True, **kw)

    def _fail(self, severity: Severity | None = None, **kw) -> Finding:
        return Finding(
            category=self.category,
            detector=self.name,
            passed=False,
            severity=severity or self.default_severity,
            **kw,
        )


# --- registry --------------------------------------------------------------
_REGISTRY: dict[str, type[Validator]] = {}


def register(cls: type[Validator]) -> type[Validator]:
    """Class decorator: register a validator implementation by its `name`."""
    _REGISTRY[cls.name] = cls
    return cls


def registered() -> dict[str, type[Validator]]:
    return dict(_REGISTRY)


def build_default_validators(settings) -> list[Validator]:  # noqa: ANN001
    """Instantiate the standard set of validators from settings.

    Imported lazily so importing this module never pulls in the heavy ML deps.
    """
    from .validators.banned_topics import BannedTopicsValidator
    from .validators.injection import PromptInjectionValidator
    from .validators.pii import PresidioPIIValidator
    from .validators.schema import SchemaValidator
    from .validators.secrets import SecretsValidator
    from .validators.template_conformance import TemplateConformanceValidator
    from .validators.toxicity import ToxicityValidator

    validators: list[Validator] = [
        SecretsValidator(),
        SchemaValidator(
            max_chars=settings.max_chars,
            max_tokens=settings.max_tokens,
            encoding_name=settings.tiktoken_encoding,
        ),
        # No-op unless the caller passes template_name; cheap, no ML/DB write.
        TemplateConformanceValidator(),
        # Regex heuristics always run; the ML classifier is opt-in via
        # enable_injection_model (skips the model entirely, no download).
        PromptInjectionValidator(
            model_id=settings.injection_model,
            threshold=settings.injection_threshold,
            use_model=settings.enable_injection_model,
        ),
        # Lexical profanity gate always runs; Detoxify is opt-in via
        # enable_toxicity_model (skips the model entirely, no download).
        ToxicityValidator(
            model_variant=settings.toxicity_model,
            threshold=settings.toxicity_threshold,
            use_model=settings.enable_toxicity_model,
        ),
    ]
    # PII and banned-topics have no non-ML mode, so a disabled toggle skips
    # constructing them entirely -- no download attempt, no timeout risk.
    if settings.enable_pii_model:
        validators.append(
            PresidioPIIValidator(threshold=settings.pii_threshold, spacy_model=settings.spacy_model)
        )
    if settings.enable_banned_topics_model:
        validators.append(
            BannedTopicsValidator(
                model_id=settings.banned_topics_model,
                topics=settings.banned_topics,
                threshold=settings.banned_topics_threshold,
            )
        )
    return validators


# Convenience alias so callers can type `Validator`-shaped factories.
ValidatorFactory = Callable[[], Validator]
