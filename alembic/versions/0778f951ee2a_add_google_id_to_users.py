"""add google_id to users

Revision ID: 0778f951ee2a
Revises: 2f68fa9b2a21
Create Date: 2026-11-26 12:49:36.450396

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = '0778f951ee2a'
down_revision: str | None = '2f68fa9b2a21'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('users', sa.Column('google_id', sa.String(length=255), nullable=True))
    op.create_index(op.f('ix_users_google_id'), 'users', ['google_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_users_google_id'), table_name='users')
    op.drop_column('users', 'google_id')