"""Rename Scenario_Session.AssetExternalID -> AssetID (2026-07-09 clarity fix).

`AssetExternalID` said "external" for no reason anyone could point at — the column only
ever holds `str(CreateSessionBody.asset_id)`, the platform's own `ctm_scan_entity.id`.
Renamed to `AssetID` to match the API field it mirrors.

A column rename, not an add+backfill+drop: `sp_rename` preserves the data and the
`UX_Session_ActiveAsset(EntityID, AssetExternalID)` filtered unique index, which binds to
column_id rather than name (its `WHERE SessionStatus = 'active'` predicate never names the
column). Migrations 0003/0004 still say `AssetExternalID` and are left alone — an applied
migration records what happened, and rewriting it would leave already-upgraded databases
disagreeing with the chain.

Revision ID: 0021
Revises: 0020
"""
from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("EXEC sp_rename 'dbo.Scenario_Session.AssetExternalID', 'AssetID', 'COLUMN'")


def downgrade() -> None:
    op.execute("EXEC sp_rename 'dbo.Scenario_Session.AssetID', 'AssetExternalID', 'COLUMN'")
