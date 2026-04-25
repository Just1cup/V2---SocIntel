"""decommission cases feature

Revision ID: c7b8f4a92d31
Revises: 9a2c8e57f31d
Create Date: 2026-04-24
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "c7b8f4a92d31"
down_revision: str | None = "9a2c8e57f31d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _table_exists(table_name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(table_name)


def _column_exists(table_name: str, column_name: str) -> bool:
    if not _table_exists(table_name):
        return False
    return column_name in {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table_name)}


def _drop_fk_if_exists(table_name: str, constraint_name: str) -> None:
    if not _table_exists(table_name):
        return
    foreign_keys = sa.inspect(op.get_bind()).get_foreign_keys(table_name)
    if any(foreign_key["name"] == constraint_name for foreign_key in foreign_keys):
        op.drop_constraint(constraint_name, table_name, type_="foreignkey")


def _drop_index_if_exists(table_name: str, index_name: str) -> None:
    if not _table_exists(table_name):
        return
    indexes = sa.inspect(op.get_bind()).get_indexes(table_name)
    if any(index["name"] == index_name for index in indexes):
        op.drop_index(index_name, table_name=table_name)


def upgrade() -> None:
    _drop_fk_if_exists("search_history", "search_history_investigation_id_fkey")
    _drop_fk_if_exists("search_history", "search_history_case_id_fkey")
    _drop_index_if_exists("search_history", "ix_search_history_investigation_id")
    _drop_index_if_exists("search_history", "ix_search_history_case_id")
    if _column_exists("search_history", "investigation_id"):
        op.drop_column("search_history", "investigation_id")
    if _column_exists("search_history", "case_id"):
        op.drop_column("search_history", "case_id")

    _drop_fk_if_exists("analysis_jobs", "analysis_jobs_investigation_id_fkey")
    _drop_fk_if_exists("analysis_jobs", "analysis_jobs_case_id_fkey")
    _drop_index_if_exists("analysis_jobs", "ix_analysis_jobs_investigation_id")
    _drop_index_if_exists("analysis_jobs", "ix_analysis_jobs_case_id")
    if _column_exists("analysis_jobs", "investigation_id"):
        op.drop_column("analysis_jobs", "investigation_id")
    if _column_exists("analysis_jobs", "case_id"):
        op.drop_column("analysis_jobs", "case_id")

    _drop_index_if_exists("investigations", "ix_investigations_tenant_id")
    _drop_index_if_exists("investigations", "ix_investigations_status")
    _drop_index_if_exists("investigations", "ix_investigations_owner_user_id")
    _drop_index_if_exists("investigations", "ix_investigations_case_id")
    if _table_exists("investigations"):
        op.drop_table("investigations")

    _drop_index_if_exists("cases", "ix_cases_visibility")
    _drop_index_if_exists("cases", "ix_cases_tenant_id")
    _drop_index_if_exists("cases", "ix_cases_team_id")
    _drop_index_if_exists("cases", "ix_cases_owner_user_id")
    if _table_exists("cases"):
        op.drop_table("cases")


def downgrade() -> None:
    op.create_table(
        "cases",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("owner_user_id", sa.String(length=64), nullable=False),
        sa.Column("team_id", sa.String(length=64), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.String(length=2000), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("visibility", sa.String(length=32), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["owner_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_cases_owner_user_id"), "cases", ["owner_user_id"], unique=False)
    op.create_index(op.f("ix_cases_team_id"), "cases", ["team_id"], unique=False)
    op.create_index(op.f("ix_cases_tenant_id"), "cases", ["tenant_id"], unique=False)
    op.create_index(op.f("ix_cases_visibility"), "cases", ["visibility"], unique=False)

    op.create_table(
        "investigations",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("case_id", sa.String(length=64), nullable=False),
        sa.Column("owner_user_id", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("summary", sa.String(length=4000), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"]),
        sa.ForeignKeyConstraint(["owner_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_investigations_case_id"), "investigations", ["case_id"], unique=False)
    op.create_index(op.f("ix_investigations_owner_user_id"), "investigations", ["owner_user_id"], unique=False)
    op.create_index(op.f("ix_investigations_status"), "investigations", ["status"], unique=False)
    op.create_index(op.f("ix_investigations_tenant_id"), "investigations", ["tenant_id"], unique=False)

    op.add_column("analysis_jobs", sa.Column("case_id", sa.String(length=64), nullable=True))
    op.add_column("analysis_jobs", sa.Column("investigation_id", sa.String(length=64), nullable=True))
    op.create_index(op.f("ix_analysis_jobs_case_id"), "analysis_jobs", ["case_id"], unique=False)
    op.create_index(op.f("ix_analysis_jobs_investigation_id"), "analysis_jobs", ["investigation_id"], unique=False)
    op.create_foreign_key("analysis_jobs_case_id_fkey", "analysis_jobs", "cases", ["case_id"], ["id"])
    op.create_foreign_key(
        "analysis_jobs_investigation_id_fkey",
        "analysis_jobs",
        "investigations",
        ["investigation_id"],
        ["id"],
    )

    op.add_column("search_history", sa.Column("case_id", sa.String(length=64), nullable=True))
    op.add_column("search_history", sa.Column("investigation_id", sa.String(length=64), nullable=True))
    op.create_index(op.f("ix_search_history_case_id"), "search_history", ["case_id"], unique=False)
    op.create_index(op.f("ix_search_history_investigation_id"), "search_history", ["investigation_id"], unique=False)
    op.create_foreign_key("search_history_case_id_fkey", "search_history", "cases", ["case_id"], ["id"])
    op.create_foreign_key(
        "search_history_investigation_id_fkey",
        "search_history",
        "investigations",
        ["investigation_id"],
        ["id"],
    )
