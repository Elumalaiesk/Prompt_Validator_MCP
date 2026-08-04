"""jwt_grants table (issued-JWT tracking + revocation denylist)

Revision ID: 0002
Revises: 0001
Create Date: 2026-07-23
"""

from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "jwt_grants",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("jti", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False, server_default="default"),
        sa.Column("issued_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_jwt_grants_jti", "jwt_grants", ["jti"], unique=True)
    op.create_index("ix_jwt_grants_user_id", "jwt_grants", ["user_id"])


def downgrade() -> None:
    op.drop_table("jwt_grants")
