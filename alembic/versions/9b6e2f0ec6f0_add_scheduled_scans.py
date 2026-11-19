"""add_scheduled_scans

Revision ID: 9b6e2f0ec6f0
Revises: bde235d6015f
Create Date: 2026-11-19 10:59:05.351188

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = '9b6e2f0ec6f0'
down_revision: str | None = 'bde235d6015f'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Create scheduled_scans table
    op.create_table(
        "scheduled_scans",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("cron_expression", sa.String(100), nullable=False),
        sa.Column("status", sa.String(20), server_default="active", nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            onupdate=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="CASCADE"),
        sa.CheckConstraint(
            "status IN ('active', 'paused', 'disabled')", name=op.f("ck_scheduled_scans_status")
        ),
        sa.CheckConstraint(
            "cron_expression IS NOT NULL", name=op.f("ck_scheduled_scans_cron_required")
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_scheduled_scans_target_id"), "scheduled_scans", ["target_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f('ix_scheduled_scans_target_id'), table_name='scheduled_scans')
    op.drop_table('scheduled_scans')