"""Issue a signed JWT for an existing user.

Usage:
    python -m mcp_prompt_validator.scripts.issue_jwt <username> [--ttl N] [--name label]
    mpv-issue-jwt analyst-bot --ttl 3600 --name ci

--ttl is in seconds; 0 means no expiry. Omit --ttl to use MPV_JWT_DEFAULT_TTL.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from ..auth.jwt_service import issue_for_user
from ..db.base import dispose_engine


async def _run(username: str, name: str, ttl: int | None) -> int:
    result = await issue_for_user(username, name=name, ttl_seconds=ttl)
    await dispose_engine()
    if not result.get("ok"):
        print(f"error: {result.get('error')}", file=sys.stderr)
        return 2
    print("\n=== JWT (store now; shown once) ===")
    print(result["token"])
    print(
        f"user={result['username']} role={result['role']} "
        f"alg={result['algorithm']} jti={result['jti']} exp={result['expires_at']}"
    )
    print("===================================\n")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Issue a JWT for a user.")
    parser.add_argument("username")
    parser.add_argument("--name", default="default", help="label for the grant")
    parser.add_argument(
        "--ttl",
        type=int,
        default=None,
        help="lifetime in seconds (0 = no expiry); omit for server default",
    )
    args = parser.parse_args()
    raise SystemExit(asyncio.run(_run(args.username, args.name, args.ttl)))


if __name__ == "__main__":
    main()
