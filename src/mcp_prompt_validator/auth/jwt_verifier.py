"""RevocableJWTVerifier — FastMCP's JWTVerifier + a revocation denylist check.

FastMCP's JWTVerifier validates signature, issuer, audience and expiry, and
builds the AccessToken (scopes come from the token's `scope`/`scopes` claim).
We subclass it to add a `jti` denylist check so issued tokens can be revoked
before they expire.
"""

from __future__ import annotations

from ..logging_setup import get_logger
from .jwt_keys import get_key_material
from .revocation import RevocationCache

log = get_logger(__name__)

# JWTVerifier moved modules across versions; resolve defensively.
try:
    from fastmcp.server.auth.providers.jwt import JWTVerifier  # type: ignore
except Exception:  # pragma: no cover
    from fastmcp.server.auth import JWTVerifier  # type: ignore


class RevocableJWTVerifier(JWTVerifier):
    def __init__(
        self,
        *,
        revocation_cache: RevocationCache,
        public_key: str,
        issuer: str,
        audience: str,
        algorithm: str,
    ) -> None:
        self._init_super(public_key=public_key, issuer=issuer, audience=audience, algorithm=algorithm)
        # Use object.__setattr__ so this works even if JWTVerifier is a pydantic
        # model that would otherwise reject an undeclared attribute.
        object.__setattr__(self, "_revocation", revocation_cache)

    def _init_super(self, *, public_key: str, issuer: str, audience: str, algorithm: str) -> None:
        # JWTVerifier's exact kwargs vary across releases (algorithm vs
        # algorithms, etc.); try the known shapes in order.
        attempts = [
            {"public_key": public_key, "issuer": issuer, "audience": audience, "algorithm": algorithm},
            {"public_key": public_key, "issuer": issuer, "audience": audience, "algorithms": [algorithm]},
            {"public_key": public_key, "issuer": issuer, "audience": audience},
        ]
        last_err: Exception | None = None
        for kwargs in attempts:
            try:
                super().__init__(**kwargs)  # type: ignore[misc]
                return
            except TypeError as exc:
                last_err = exc
        raise RuntimeError(f"Could not initialise JWTVerifier: {last_err}")

    async def verify_token(self, token: str):
        access = await super().verify_token(token)
        if access is None:
            return None
        revocation = object.__getattribute__(self, "_revocation")
        jti = _extract_jti(access, token)
        if await revocation.is_revoked(jti):
            log.info("auth: revoked JWT jti=%s", jti)
            return None
        return access


def _extract_jti(access, token: str) -> str | None:
    claims = getattr(access, "claims", None) or {}
    jti = claims.get("jti")
    if jti:
        return jti
    # Fall back to decoding (signature already validated by the parent).
    try:
        import jwt as pyjwt

        decoded = pyjwt.decode(token, options={"verify_signature": False})
        return decoded.get("jti")
    except Exception:
        return None


def build_jwt_verifier(settings):  # noqa: ANN001
    _sign_key, verify_key = get_key_material(settings)
    cache = RevocationCache(settings.revocation_cache_ttl)
    verifier = RevocableJWTVerifier(
        revocation_cache=cache,
        public_key=verify_key,
        issuer=settings.jwt_issuer,
        audience=settings.effective_audience,
        algorithm=settings.jwt_algorithm,
    )
    if settings.jwt_default_ttl == 0:
        log.warning(
            "MPV_JWT_DEFAULT_TTL=0: issuing non-expiring JWTs. Prefer a finite "
            "lifetime and rely on revocation only as a backstop."
        )
    return verifier
