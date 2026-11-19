"""add cve and remediation fields to vulnerabilities

Revision ID: 6baa5bc7777b
Revises: 0002_scans_vulnerabilities
Create Date: 2026-11-16 16:02:56.184587

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "6baa5bc7777b"
down_revision: str | None = "0002_scans_vulnerabilities"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("vulnerabilities") as batch_op:
        batch_op.add_column(sa.Column("cve_id", sa.String(length=20), nullable=True))
        batch_op.add_column(sa.Column("cvss_score", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("cvss_severity", sa.String(length=10), nullable=True))
        batch_op.add_column(
            sa.Column("remediation_code", sa.Text(), nullable=True)
        )
        batch_op.create_check_constraint(
            "ck_vulnerabilities_cvss_severity",
            "cvss_severity IN ('Critical', 'High', 'Medium', 'Low', 'Info')",
        )


def downgrade() -> None:
    with op.batch_alter_table("vulnerabilities") as batch_op:
        batch_op.drop_constraint("ck_vulnerabilities_cvss_severity")
        batch_op.drop_column("remediation_code")
        batch_op.drop_column("cvss_severity")
        batch_op.drop_column("cvss_score")
        batch_op.drop_column("cve_id")
