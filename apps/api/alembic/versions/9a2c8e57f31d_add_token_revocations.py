
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "9a2c8e57f31d"
down_revision: str | None = "6d61f8a1d2b7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "token_revocations",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("jti", sa.String(length=128), nullable=True),
        sa.Column("user_id", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_token_revocations_expires_at"), "token_revocations", ["expires_at"], unique=False)
    op.create_index(op.f("ix_token_revocations_jti"), "token_revocations", ["jti"], unique=False)
    op.create_index(op.f("ix_token_revocations_tenant_id"), "token_revocations", ["tenant_id"], unique=False)
    op.create_index(op.f("ix_token_revocations_token_hash"), "token_revocations", ["token_hash"], unique=True)
    op.create_index(op.f("ix_token_revocations_user_id"), "token_revocations", ["user_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_token_revocations_user_id"), table_name="token_revocations")
    op.drop_index(op.f("ix_token_revocations_token_hash"), table_name="token_revocations")
    op.drop_index(op.f("ix_token_revocations_tenant_id"), table_name="token_revocations")
    op.drop_index(op.f("ix_token_revocations_jti"), table_name="token_revocations")
    op.drop_index(op.f("ix_token_revocations_expires_at"), table_name="token_revocations")
    op.drop_table("token_revocations")
