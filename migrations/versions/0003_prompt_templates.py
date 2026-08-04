"""prompt_templates table (per-user + global Jinja2 prompt templates)

Revision ID: 0003
Revises: 0002
Create Date: 2026-07-23
"""

from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "prompt_templates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("body", sa.Text(), nullable=False, server_default=""),
        sa.Column("owner_user_id", sa.Integer(), nullable=True),
        sa.Column("is_global", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["owner_user_id"], ["users.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_prompt_templates_owner", "prompt_templates", ["owner_user_id"])
    op.create_index("ix_prompt_templates_name", "prompt_templates", ["name"])


def downgrade() -> None:
    op.drop_table("prompt_templates")
