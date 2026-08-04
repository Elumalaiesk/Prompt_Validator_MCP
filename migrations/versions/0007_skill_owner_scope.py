"""Per-user skill scoping: skills.owner_user_id + skills.is_global

Brings `skills` in line with `prompt_templates`: a skill is either owned by one
user (private) or marked global (visible to all). Before this revision every
enabled skill was served to every authenticated caller, so existing rows are
backfilled with is_global=True to preserve current behaviour exactly.

`ix_skills_name` loses its UNIQUE constraint — two users may each own a skill
called "code-review". Uniqueness is now enforced per (name, owner) in
`skillset/service.py::create`.

Revision ID: 0007
Revises: 0006
Create Date: 2026-07-29
"""

from alembic import op
import sqlalchemy as sa

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("skills") as batch:
        batch.add_column(sa.Column("owner_user_id", sa.Integer(), nullable=True))
        batch.add_column(
            sa.Column("is_global", sa.Boolean(), nullable=False, server_default=sa.false())
        )
        batch.create_foreign_key(
            "fk_skills_owner_user_id", "users", ["owner_user_id"], ["id"], ondelete="CASCADE"
        )

    # Pre-existing skills were visible to everyone; keep them that way.
    skills = sa.table("skills", sa.column("is_global", sa.Boolean))
    op.execute(skills.update().values(is_global=True))

    # Names are only unique per owner from now on.
    op.drop_index("ix_skills_name", table_name="skills")
    op.create_index("ix_skills_name", "skills", ["name"])
    op.create_index("ix_skills_owner", "skills", ["owner_user_id"])


def downgrade() -> None:
    op.drop_index("ix_skills_owner", table_name="skills")
    op.drop_index("ix_skills_name", table_name="skills")

    # A unique name is only restorable if no duplicates were created meanwhile;
    # drop the per-owner rows that would violate it, keeping the lowest id.
    op.execute(
        "DELETE FROM skills WHERE id NOT IN (SELECT MIN(id) FROM skills GROUP BY name)"
    )
    op.create_index("ix_skills_name", "skills", ["name"], unique=True)

    with op.batch_alter_table("skills") as batch:
        batch.drop_constraint("fk_skills_owner_user_id", type_="foreignkey")
        batch.drop_column("is_global")
        batch.drop_column("owner_user_id")
