"""R6 — Scenario_Session.SectorIDsJSON (SDD §8.4 sector-aware grounding): persists the
sector_ids gather_asset_details computes at session-creation time so the async pipeline/cascade
workers — which only have the loaded session row, not the original request — can pass the
real list into grounding.find_threat_in_library() instead of the hardcoded [] the two call sites used before
this fix. NULL (pre-migration rows, or a session created with no `sector` request param)
means the same thing [] always meant: masters filtered to global/NULL SectorID only —
unchanged default behavior, not a new one.

Revision ID: 0013
Revises: 0012
"""
from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE Scenario_Session ADD SectorIDsJSON nvarchar(max) NULL")


def downgrade() -> None:
    op.execute("ALTER TABLE Scenario_Session DROP COLUMN SectorIDsJSON")
