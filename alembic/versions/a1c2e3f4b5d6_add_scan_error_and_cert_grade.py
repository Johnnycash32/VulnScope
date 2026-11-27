"""add scan error_message and certwatch ssl_grade

Revision ID: a1c2e3f4b5d6
Revises: 0778f951ee2a
Create Date: 2026-11-27 15:20:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = 'a1c2e3f4b5d6'
down_revision: str | None = '0778f951ee2a'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('scans', sa.Column('error_message', sa.Text(), nullable=True))
    op.add_column('cert_watches', sa.Column('ssl_grade', sa.String(length=4), nullable=True))


def downgrade() -> None:
    op.drop_column('cert_watches', 'ssl_grade')
    op.drop_column('scans', 'error_message')