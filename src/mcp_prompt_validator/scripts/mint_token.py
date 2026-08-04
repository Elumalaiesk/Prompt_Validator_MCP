"""Mint a permanent token for an existing user.

Usage:
    python -m mcp_prompt_validator.scripts.mint_token <username> [--name label]
    mpv-mint-token <username> --name ci-runner
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from sqlalchemy import select

from ..auth.tokens import mint_token
from ..config import get_settings
from ..db.base import dispose_engine, session_scope
from ..db.models import ApiToken, User


async def _mint(username: str, name: str) -> int:
    settings = get_settings()
    async with session_scope() as session:
        user = (
            await session.execute(select(User).where(User.username == username))
        ).scalar_one_or_none()
        if user is None:
            print(f"error: user '{username}' not found", file=sys.stderr)
            return 2
        minted = mint_token(settings.token_prefix)
        session.add(
            ApiToken(
                user_id=user.id,
                name=name,
                token_hash=minted.token_hash,
                prefix=minted.prefix,
            )
        )
        print("\n=== Token (store now; shown once) ===")
        print(minted.plaintext)
        print(f"user={username} name={name} prefix={minted.prefix}")
        print("=====================================\n")
    await dispose_engine()
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Mint a permanent MCP token for a user.")
    parser.add_argument("username")
    parser.add_argument("--name", default="default", help="label for the token")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(_mint(args.username, args.name)))


if __name__ == "__main__":
    main()
