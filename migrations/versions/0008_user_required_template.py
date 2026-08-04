"""users.required_template — server-enforced template conformance

Before this revision, template conformance ran only when the CALLER passed
`template_name` to `validate_prompt`; omitting it produced a silent pass
("no template specified"). That made the policy opt-out by accident — any client
could skip it by dropping one optional argument.

With `required_template` set on a user, the server injects that template name
into the validation context on every call from that user, so conformance is
checked whether or not the client cooperates. NULL preserves the old opt-in
behaviour, so this migration changes no existing user's outcome.

Revision ID: 0008
Revises: 0007
Create Date: 2026-07-31
"""

from alembic import op
import sqlalchemy as sa

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("required_template", sa.String(length=128), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "required_template")
