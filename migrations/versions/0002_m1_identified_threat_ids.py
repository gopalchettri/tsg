"""M1 — Identified_Threat match-by-id columns (blocks match-by-id + promote re-point)

Revision ID: 0002
Revises: 0001
"""
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # App-enforced ids (not DB FKs, §7.7): the grounded match snaps to an id, not a name.
    op.execute("ALTER TABLE Identified_Threat ADD ThreatTypeID INT NULL, ThreatCatalogueID INT NULL")


def downgrade() -> None:
    op.execute("ALTER TABLE Identified_Threat DROP COLUMN ThreatTypeID, ThreatCatalogueID")
