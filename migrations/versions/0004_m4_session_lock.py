"""M4 — filtered UNIQUE session lock: one active session per (entity, asset) (§6)

Revision ID: 0004
Revises: 0003
"""
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # NULL-safe because EntityID/AssetExternalID are NOT NULL (M3). A concurrent
    # second active INSERT for the same asset fails here → app maps to 409.
    op.execute(
        "CREATE UNIQUE INDEX UX_Session_ActiveAsset ON Scenario_Session(EntityID, AssetExternalID) "
        "WHERE SessionStatus = 'active'"
    )


def downgrade() -> None:
    op.execute("DROP INDEX UX_Session_ActiveAsset ON Scenario_Session")
