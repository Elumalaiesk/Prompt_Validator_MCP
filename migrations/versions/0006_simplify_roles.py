"""Simplify to 2 fixed roles (admin, std_user); drop per-role permission tables

Only "admin" and "std_user" remain. Any other role's users are reassigned to
"std_user" and the extra role rows are removed. Per-role tag/skill permission
tables are dropped entirely — role only distinguishes admin vs everyone else
now (see skills/registry.py::tool_permitted).

Revision ID: 0006
Revises: 0005
Create Date: 2026-07-24
"""

from alembic import op
import sqlalchemy as sa

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_table("role_skill_permissions")
    op.drop_table("role_tag_permissions")

    conn = op.get_bind()
    meta = sa.MetaData()
    roles = sa.Table("roles", meta, autoload_with=conn)
    users = sa.Table("users", meta, autoload_with=conn)

    std_id = conn.execute(
        sa.select(roles.c.id).where(roles.c.name == "std_user")
    ).scalar_one_or_none()
    if std_id is None:
        conn.execute(
            roles.insert().values(name="std_user", description="std_user role", is_admin=False)
        )
        std_id = conn.execute(
            sa.select(roles.c.id).where(roles.c.name == "std_user")
        ).scalar_one()

    legacy_ids = [
        row[0]
        for row in conn.execute(
            sa.select(roles.c.id).where(~roles.c.name.in_(["admin", "std_user"]))
        ).all()
    ]
    if legacy_ids:
        conn.execute(users.update().where(users.c.role_id.in_(legacy_ids)).values(role_id=std_id))
        conn.execute(roles.delete().where(roles.c.id.in_(legacy_ids)))


def downgrade() -> None:
    op.create_table(
        "role_tag_permissions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("role_id", sa.Integer(), nullable=False),
        sa.Column("tag", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("role_id", "tag", name="uq_role_tag"),
    )
    op.create_index("ix_role_tag_permissions_role_id", "role_tag_permissions", ["role_id"])
    op.create_index("ix_role_tag_permissions_tag", "role_tag_permissions", ["tag"])

    op.create_table(
        "role_skill_permissions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("role_id", sa.Integer(), nullable=False),
        sa.Column("skill_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["skill_id"], ["skills.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("role_id", "skill_id", name="uq_role_skill"),
    )
    op.create_index("ix_role_skill_permissions_role_id", "role_skill_permissions", ["role_id"])
    op.create_index("ix_role_skill_permissions_skill_id", "role_skill_permissions", ["skill_id"])
