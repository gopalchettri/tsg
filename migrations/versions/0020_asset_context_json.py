"""Scenario_Session.AssetContextJSON (UI-supplied asset-level context: cii_asset_description,
critical_service, sector, sub_sector, data_handled) — same nullable-JSON-blob pattern as
SectorIDsJSON (0013).

Revision ID: 0020
Revises: 0019
"""
from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE Scenario_Session ADD AssetContextJSON nvarchar(max) NULL")


def downgrade() -> None:
    op.execute("ALTER TABLE Scenario_Session DROP COLUMN AssetContextJSON")
