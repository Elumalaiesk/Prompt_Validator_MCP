"""Dashboard password hashing (stdlib-only, no new dependency).

Stored form: `pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>`. PBKDF2-HMAC-SHA256
is in `hashlib` on every supported Python, so this needs nothing beyond the
standard library (unlike bcrypt/argon2, which would add a dependency for a
single-purpose dashboard login).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

_ALGO = "pbkdf2_sha256"
_ITERATIONS = 260_000
_SALT_BYTES = 16


def hash_password(password: str) -> str:
    salt = secrets.token_hex(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), _ITERATIONS)
    return f"{_ALGO}${_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, stored: str | None) -> bool:
    if not stored:
        return False
    try:
        algo, iterations_s, salt, hash_hex = stored.split("$")
        if algo != _ALGO:
            return False
        iterations = int(iterations_s)
    except ValueError:
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), iterations)
    return hmac.compare_digest(digest.hex(), hash_hex)
