"""scans and vulnerabilities tables

Revision ID: 0002_scans_vulnerabilities
Revises: 0001_initial
Create Date: 2026-01-02 00:00:00

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0002_scans_vulnerabilities"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column(
            "status",
            sa.String(length=20),
            server_default=sa.text("'pending'"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed')",
            name="ck_scans_status",
        ),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_scans_target_id"), "scans", ["target_id"], unique=False)

    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=512), nullable=False),
        sa.Column("risk", sa.String(length=20), nullable=False),
        sa.Column("confidence", sa.String(length=50), nullable=True),
        sa.Column("description", sa.String(length=4000), nullable=True),
        sa.Column("solution", sa.String(length=4000), nullable=True),
        sa.Column("evidence", sa.String(length=4000), nullable=True),
        sa.CheckConstraint(
            "risk IN ('High', 'Medium', 'Low', 'Info')",
            name="ck_vulnerabilities_risk",
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_vulnerabilities_scan_id"), "vulnerabilities", ["scan_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_vulnerabilities_scan_id"), table_name="vulnerabilities")
    op.drop_table("vulnerabilities")
    op.drop_index(op.f("ix_scans_target_id"), table_name="scans")
    op.drop_table("scans")