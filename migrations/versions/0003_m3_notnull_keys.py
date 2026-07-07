"""M3 — Scenario_Session.EntityID / AssetExternalID → NOT NULL ([R7] isolation + lock keys)

Revision ID: 0003
Revises: 0002
"""
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Fail loudly if the data isn't clean — backfill/quarantine NULLs before applying.
    op.execute(
        "IF EXISTS (SELECT 1 FROM Scenario_Session WHERE EntityID IS NULL OR AssetExternalID IS NULL) "
        "THROW 50000, 'M3: Scenario_Session has NULL EntityID/AssetExternalID — "
        "backfill or quarantine before applying', 1;"
    )
    op.execute("ALTER TABLE Scenario_Session ALTER COLUMN EntityID nvarchar(200) NOT NULL")
    op.execute("ALTER TABLE Scenario_Session ALTER COLUMN AssetExternalID nvarchar(200) NOT NULL")


def downgrade() -> None:
    op.execute("ALTER TABLE Scenario_Session ALTER COLUMN EntityID nvarchar(200) NULL")
    op.execute("ALTER TABLE Scenario_Session ALTER COLUMN AssetExternalID nvarchar(200) NULL")
