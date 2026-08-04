"""Permanent-token minting and hashing helpers.

Token shape:  <prefix><43-char url-safe secret>   e.g.  mpv_Xy7...  (256 bits)

Only the SHA-256 hex digest of the *full* token is stored. Verification hashes
the presented token and compares in constant time. This means:
  * a database leak does not expose usable tokens;
  * tokens are long-lived ("permanent") but individually revocable;
  * lookup is a single indexed equality query on the hash.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

# Number of random bytes -> ~43 url-safe chars, 256 bits of entropy.
_SECRET_BYTES = 32
# How many leading characters of the token we keep for display/UX.
_PREFIX_DISPLAY_LEN = 12


@dataclass(frozen=True)
class MintedToken:
    """The result of minting a token. `plaintext` is shown to the user once."""

    plaintext: str
    token_hash: str
    prefix: str


def hash_token(token: str) -> str:
    """SHA-256 hex digest of the full token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def tokens_equal(a_hash: str, b_hash: str) -> bool:
    """Constant-time comparison of two hex digests."""
    return hmac.compare_digest(a_hash, b_hash)


def mint_token(token_prefix: str = "mpv_") -> MintedToken:
    """Generate a fresh permanent token."""
    secret = secrets.token_urlsafe(_SECRET_BYTES)
    plaintext = f"{token_prefix}{secret}"
    return MintedToken(
        plaintext=plaintext,
        token_hash=hash_token(plaintext),
        prefix=plaintext[:_PREFIX_DISPLAY_LEN],
    )
