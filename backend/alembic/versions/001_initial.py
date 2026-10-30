"""initial schema

Revision ID: 001
Revises:
Create Date: 2026-10-26
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("client_id", sa.String(length=36), nullable=False, index=True),
        sa.Column("display_url", sa.String(length=512), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False, index=True),
        sa.Column("url_hash", sa.String(length=64), nullable=False, index=True),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("risk_classification", sa.String(length=32), nullable=False, index=True),
        sa.Column("status", sa.String(length=32), nullable=False, index=True),
        sa.Column("persisted", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("result_json", sa.Text(), nullable=False),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("scan_id", sa.String(length=36), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("finding_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("evidence_summary", sa.Text(), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
    )
    op.create_table(
        "provider_results",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("scan_id", sa.String(length=36), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("threat_categories", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("error", sa.String(length=128), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("provider_results")
    op.drop_table("findings")
    op.drop_table("scans")
