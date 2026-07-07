"""M7 — Subsystem_Stage_State lease columns for the reaper ([R1])

Revision ID: 0007
Revises: 0006
"""
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE Subsystem_Stage_State ADD LeaseExpiresAt datetime2 NULL, HeartbeatAt datetime2 NULL")


def downgrade() -> None:
    op.execute("ALTER TABLE Subsystem_Stage_State DROP COLUMN LeaseExpiresAt, HeartbeatAt")
