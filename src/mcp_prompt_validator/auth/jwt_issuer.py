"""Issue signed JWTs for users.

The issued token encodes identity (sub/username/email/role) and authorisation
(role, plus "admin" if applicable, as OAuth `scope`), so the RBAC middleware —
which reads `AccessToken.scopes` — enforces per-user access with no extra
lookups.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

import jwt as pyjwt

from .scopes import encode_scopes


@dataclass(frozen=True)
class IssuedJWT:
    token: str
    jti: str
    expires_at: int | None  # epoch seconds, or None for no expiry


def new_jti() -> str:
    return uuid.uuid4().hex


def issue_jwt(
    *,
    sign_key: str,
    algorithm: str,
    issuer: str,
    audience: str,
    subject: str,
    username: str,
    email: str | None,
    role_name: str,
    is_admin: bool,
    ttl_seconds: int,
    jti: str | None = None,
    name: str = "default",
) -> IssuedJWT:
    now = int(time.time())
    jti = jti or new_jti()
    scopes = encode_scopes(role_name, is_admin)

    payload: dict = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "client_id": username,  # some verifiers map client_id from this claim
        "username": username,
        "email": email,
        "role": role_name,
        # Provide both forms so the verifier populates AccessToken.scopes
        # regardless of whether it reads `scope` (string) or `scopes` (list).
        "scope": " ".join(scopes),
        "scopes": scopes,
        "iat": now,
        "nbf": now,
        "jti": jti,
        "name": name,
    }
    expires_at: int | None = None
    if ttl_seconds and ttl_seconds > 0:
        expires_at = now + ttl_seconds
        payload["exp"] = expires_at

    token = pyjwt.encode(payload, sign_key, algorithm=algorithm)
    # PyJWT<2 returns bytes; normalise to str.
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return IssuedJWT(token=token, jti=jti, expires_at=expires_at)
