"""skills + role_skill_permissions (admin-authored skill.md content per role)

Revision ID: 0005
Revises: 0004
Create Date: 2026-07-24
"""

from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "skills",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("body", sa.Text(), nullable=False, server_default=""),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_skills_name", "skills", ["name"], unique=True)

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


def downgrade() -> None:
    op.drop_table("role_skill_permissions")
    op.drop_table("skills")
