"""baseline — represents the existing TSG schema (apply via `alembic stamp 0001`)

Revision ID: 0001
Revises:
Create Date: 2026-07-01
"""
revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Intentionally empty. The TSG schema already exists (§7 reuse-not-recreate);
    # this revision is stamped, not run, to mark the forward-migration baseline.
    pass


def downgrade() -> None:
    pass
