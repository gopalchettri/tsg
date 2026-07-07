"""M8 — Subsystem_Stage_State.AttemptCount for the poison-terminal stage-claim cap

Revision ID: 0008
Revises: 0007
"""
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE Subsystem_Stage_State ADD AttemptCount int NOT NULL CONSTRAINT DF_SSS_AttemptCount DEFAULT 0")


def downgrade() -> None:
    op.execute("ALTER TABLE Subsystem_Stage_State DROP CONSTRAINT DF_SSS_AttemptCount")
    op.execute("ALTER TABLE Subsystem_Stage_State DROP COLUMN AttemptCount")
