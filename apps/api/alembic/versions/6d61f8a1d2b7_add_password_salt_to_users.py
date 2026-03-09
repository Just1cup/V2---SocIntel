"""add password salt to users

Revision ID: 6d61f8a1d2b7
Revises: 3f12071b1eb4
Create Date: 2026-03-09 14:05:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "6d61f8a1d2b7"
down_revision: str | None = "3f12071b1eb4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("password_salt", sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "password_salt")
