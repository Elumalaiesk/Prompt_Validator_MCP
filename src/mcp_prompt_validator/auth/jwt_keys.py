"""JWT signing/verification key material.

Resolution order for RS256 (asymmetric):
  1. inline PEM in settings (jwt_private_key / jwt_public_key);
  2. PEM file paths (jwt_private_key_path / jwt_public_key_path);
  3. reuse a previously generated pair in jwt_keys_dir;
  4. if jwt_auto_generate_keys: generate a 2048-bit RSA pair, persist it, reuse.

For HS256 (symmetric) the shared secret (jwt_hs_secret, or jwt_private_key) is
used as both the signing and verification key.

Returns `(sign_key, verify_key)`:
  * `sign_key`   is passed to PyJWT when issuing;
  * `verify_key` is passed to FastMCP's JWTVerifier.
"""

from __future__ import annotations

import pathlib

from ..logging_setup import get_logger

log = get_logger(__name__)

# Cache resolved material so we do not regenerate keys per call (which would
# invalidate already-issued tokens).
_CACHE: dict[str, tuple[str, str]] = {}


def _read(path: str) -> str:
    return pathlib.Path(path).read_text(encoding="utf-8") if path else ""


def _generate_rsa() -> tuple[str, str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return private_pem, public_pem


def get_key_material(settings) -> tuple[str, str]:  # noqa: ANN001
    cache_key = f"{settings.jwt_algorithm}:{settings.jwt_keys_dir}"
    if cache_key in _CACHE:
        return _CACHE[cache_key]

    if settings.jwt_algorithm.startswith("HS"):
        secret = settings.jwt_hs_secret or settings.jwt_private_key
        if not secret:
            raise RuntimeError(
                "HS256 selected but no shared secret set (MPV_JWT_HS_SECRET)."
            )
        _CACHE[cache_key] = (secret, secret)
        return _CACHE[cache_key]

    # RS256 / asymmetric.
    private_pem = settings.jwt_private_key or _read(settings.jwt_private_key_path)
    public_pem = settings.jwt_public_key or _read(settings.jwt_public_key_path)

    if not (private_pem and public_pem):
        keys_dir = pathlib.Path(settings.jwt_keys_dir)
        priv_file = keys_dir / "private.pem"
        pub_file = keys_dir / "public.pem"
        if priv_file.exists() and pub_file.exists():
            private_pem = priv_file.read_text(encoding="utf-8")
            public_pem = pub_file.read_text(encoding="utf-8")
        elif settings.jwt_auto_generate_keys:
            log.warning(
                "No JWT keys configured; generating an RSA keypair in %s "
                "(set explicit keys for production).",
                keys_dir,
            )
            private_pem, public_pem = _generate_rsa()
            keys_dir.mkdir(parents=True, exist_ok=True)
            priv_file.write_text(private_pem, encoding="utf-8")
            pub_file.write_text(public_pem, encoding="utf-8")
        else:
            raise RuntimeError(
                "No JWT keys configured and auto-generation is disabled. "
                "Set MPV_JWT_PRIVATE_KEY(_PATH) and MPV_JWT_PUBLIC_KEY(_PATH)."
            )

    _CACHE[cache_key] = (private_pem, public_pem)
    return _CACHE[cache_key]


def reset_cache() -> None:
    _CACHE.clear()
