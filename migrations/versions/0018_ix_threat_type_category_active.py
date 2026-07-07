"""Supporting index for Threat_Type lookups scoped by category + sector.

`get_possible_types()` (app/pipeline/grounding.py) filters active Threat_Type rows by
PrimaryThreatCategoryID and SectorID on every grounding call — this index gives that
filter a direct path instead of a table scan, filtered the same way as the M2 natural-key
indexes (IsActive/IsDeleted) so soft-deleted/inactive rows never bloat it.

Revision ID: 0018
Revises: 0017
"""
from alembic import op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "CREATE INDEX IX_ThreatType_Category_Active "
        "ON Threat_Type(PrimaryThreatCategoryID, SectorID) "
        "WHERE IsActive = 1 AND IsDeleted = 0"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IX_ThreatType_Category_Active ON Threat_Type")
