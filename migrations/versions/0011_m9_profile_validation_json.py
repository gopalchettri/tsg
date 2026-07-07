"""M9 — Subsystem_Profile.ValidationJSON (§5.2 deterministic structural/consistency
validation result; mirrors Threat_Scenario_Output.ValidationJSON)

Revision ID: 0011
Revises: 0010
"""
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE Subsystem_Profile ADD ValidationJSON nvarchar(max) NULL")


def downgrade() -> None:
    op.execute("ALTER TABLE Subsystem_Profile DROP COLUMN ValidationJSON")
