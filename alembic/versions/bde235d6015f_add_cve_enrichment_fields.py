"""add_cve_enrichment_fields

Revision ID: bde235d6015f
Revises: 6baa5bc7777b
Create Date: 2026-11-19 10:47:20.888980

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = 'bde235d6015f'
down_revision: str | None = '6baa5bc7777b'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Add new columns to vulnerabilities table
    op.add_column("vulnerabilities", sa.Column("cvss_vector", sa.String(200), nullable=True))
    op.add_column("vulnerabilities", sa.Column("cvss_details", sa.Text(), nullable=True))
    op.add_column("vulnerabilities", sa.Column("cwes", sa.String(500), nullable=True))
    op.add_column("vulnerabilities", sa.Column("references", sa.Text(), nullable=True))
    op.add_column("vulnerabilities", sa.Column("vendor_advisories", sa.Text(), nullable=True))
    op.add_column(
        "vulnerabilities",
        sa.Column("exploit_available", sa.Boolean(), nullable=False, server_default="0"),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("published_date", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("last_modified_date", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("vulnerabilities", "last_modified_date")
    op.drop_column("vulnerabilities", "published_date")
    op.drop_column("vulnerabilities", "exploit_available")
    op.drop_column("vulnerabilities", "vendor_advisories")
    op.drop_column("vulnerabilities", "references")
    op.drop_column("vulnerabilities", "cwes")
    op.drop_column("vulnerabilities", "cvss_details")
    op.drop_column("vulnerabilities", "cvss_vector")