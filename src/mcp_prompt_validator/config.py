"""Application settings, loaded from environment / .env (all vars prefixed MPV_).

Uses pydantic-settings so configuration is typed, validated, and documented in
one place. `get_settings()` is cached so the whole app shares one instance.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="MPV_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Database ----------------------------------------------------------
    database_url: str = "postgresql+asyncpg://mpv:mpv@localhost:5432/mpv"
    # Create tables on startup instead of running Alembic. Handy for local dev;
    # production should use `alembic upgrade head`.
    auto_create_tables: bool = False

    # --- HTTP transport ----------------------------------------------------
    host: str = "0.0.0.0"
    port: int = 8000
    mcp_path: str = "/mcp"
    resource_server_url: str = "http://localhost:8000"
    authorization_server_url: str = ""
    publish_discovery: bool = True

    # --- Auth / tokens -----------------------------------------------------
    # "jwt"    : server issues + verifies signed JWTs (per-user, RBAC via scopes).
    # "opaque" : server issues + verifies opaque permanent keys (DB lookup).
    auth_mode: str = "jwt"
    token_prefix: str = "mpv_"

    # --- JWT (auth_mode="jwt") --------------------------------------------
    jwt_algorithm: str = "RS256"          # RS256 (asymmetric) or HS256 (shared secret)
    jwt_issuer: str = "mcp-prompt-validator"
    jwt_audience: str = ""                # defaults to resource_server_url if blank
    # Key material. Provide inline PEM, a path, or let dev auto-generate.
    jwt_private_key: str = ""
    jwt_private_key_path: str = ""
    jwt_public_key: str = ""
    jwt_public_key_path: str = ""
    jwt_keys_dir: str = "./keys"          # where auto-generated keys are stored/reused
    jwt_auto_generate_keys: bool = True   # dev convenience; disable in prod
    jwt_hs_secret: str = ""               # shared secret when jwt_algorithm=HS256
    # Default token lifetime in seconds. 0 => no expiry ("permanent"; warned).
    jwt_default_ttl: int = 31_536_000     # 365 days
    # How long (seconds) the revocation denylist is cached in-memory.
    revocation_cache_ttl: float = 30.0

    # --- Validator behaviour ----------------------------------------------
    preload_models: bool = True
    validator_timeout: float = 8.0
    validator_fail_mode: str = "safe"  # "safe" | "open"

    # How much of the verdict the caller is told. Every validator runs either
    # way; this only shapes the response.
    #   "summary" -> pass: a bare confirmation;
    #                fail: the failed categories + rewrite suggestions.
    #   "full"    -> the complete Verdict, including passing findings and scores.
    validation_response_mode: str = "summary"
    # When True, a caller-supplied `categories` filter is IGNORED and the whole
    # policy always runs. Leaving a client able to narrow the category list is
    # the same class of hole as an optional template_name: policy the caller can
    # switch off. Set False only if you deliberately want partial validation.
    enforce_all_categories: bool = True

    # Per-category ML model toggles. False = skip entirely, no download/load
    # attempt at all (not even lazily) — use when you don't want the multi-GB
    # model downloads (PII/banned-topics/toxicity) or just want the cheap,
    # dependency-free regex heuristics (injection, secrets, schema).
    # Injection heuristics (regex) always run regardless of this flag; this
    # only controls whether the ML classifier is also consulted.
    enable_injection_model: bool = True
    enable_pii_model: bool = True
    enable_banned_topics_model: bool = True
    enable_toxicity_model: bool = True

    # Model ids.
    injection_model: str = "meta-llama/Llama-Prompt-Guard-2-86M"
    banned_topics_model: str = "facebook/bart-large-mnli"
    toxicity_model: str = "original"
    spacy_model: str = "en_core_web_lg"

    # Thresholds.
    pii_threshold: float = 0.5
    injection_threshold: float = 0.8
    banned_topics_threshold: float = 0.75
    toxicity_threshold: float = 0.6

    # Length limits.
    max_chars: int = 20_000
    max_tokens: int = 6_000
    tiktoken_encoding: str = "cl100k_base"

    banned_topics: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: [
            "violence",
            "self-harm",
            "illegal weapons",
            "malware",
            "child sexual content",
        ]
    )

    # --- Admin dashboard ---------------------------------------------------
    dashboard_enabled: bool = True
    dashboard_path: str = "/admin"
    # Secret used to sign the dashboard session cookie. MUST be overridden in prod.
    dashboard_secret: str = "change-me-in-production"

    # --- Logging -----------------------------------------------------------
    log_level: str = "INFO"

    @field_validator("banned_topics", mode="before")
    @classmethod
    def _split_topics(cls, v: object) -> object:
        """Allow the env var to be a comma-separated string."""
        if isinstance(v, str):
            return [t.strip() for t in v.split(",") if t.strip()]
        return v

    @field_validator("validator_fail_mode")
    @classmethod
    def _check_fail_mode(cls, v: str) -> str:
        if v not in ("safe", "open"):
            raise ValueError("validator_fail_mode must be 'safe' or 'open'")
        return v

    @field_validator("auth_mode")
    @classmethod
    def _check_auth_mode(cls, v: str) -> str:
        if v not in ("jwt", "opaque"):
            raise ValueError("auth_mode must be 'jwt' or 'opaque'")
        return v

    @property
    def effective_audience(self) -> str:
        return self.jwt_audience or self.resource_server_url


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
