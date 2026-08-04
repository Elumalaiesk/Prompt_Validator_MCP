"""Create (or update) an admin user with a dashboard username/password login.

Usage:
    python -m mcp_prompt_validator.scripts.create_admin <username> [--password PW] [--email EMAIL]
    mpv-create-admin <username> --password "S3cret!23"

If --password is omitted, you'll be prompted (input hidden). If the username
already exists, its role is promoted to "admin" and its password is (re)set;
otherwise a new admin user is created. Requires the "admin" role to already
exist (created by `mpv-seed`).
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys

from sqlalchemy import select

from ..auth.passwords import hash_password
from ..db.base import dispose_engine, session_scope
from ..db.models import Role, User

_MIN_PASSWORD_LEN = 8


async def _create_admin(username: str, password: str, email: str | None) -> int:
    if len(password) < _MIN_PASSWORD_LEN:
        print(f"error: password must be at least {_MIN_PASSWORD_LEN} characters", file=sys.stderr)
        return 2

    async with session_scope() as session:
        admin_role = (
            await session.execute(select(Role).where(Role.name == "admin"))
        ).scalar_one_or_none()
        if admin_role is None:
            print(
                "error: no 'admin' role found. Run `mpv-seed` first to create baseline roles.",
                file=sys.stderr,
            )
            return 2

        user = (
            await session.execute(select(User).where(User.username == username))
        ).scalar_one_or_none()
        if user is None:
            session.add(
                User(
                    username=username,
                    email=email,
                    role_id=admin_role.id,
                    password_hash=hash_password(password),
                )
            )
            action = "created"
        else:
            user.role_id = admin_role.id
            user.password_hash = hash_password(password)
            if email:
                user.email = email
            action = "updated"

    await dispose_engine()
    print(f"\nAdmin user {action}: username={username}")
    print("Sign in at the dashboard (default path /admin) with this username and password.\n")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create or update an admin user with a dashboard username/password login."
    )
    parser.add_argument("username")
    parser.add_argument("--password", help="admin password (omit to be prompted)")
    parser.add_argument("--email", default=None, help="optional email")
    args = parser.parse_args()

    password = args.password
    if not password:
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("error: passwords do not match", file=sys.stderr)
            raise SystemExit(2)

    raise SystemExit(asyncio.run(_create_admin(args.username, password, args.email)))


if __name__ == "__main__":
    main()
