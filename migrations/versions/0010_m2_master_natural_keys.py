"""M2 — natural-key UNIQUE on Threat_Type / Threat_Catalogue / Threat_Actor.
Guards safe concurrent library promotion (no duplicate masters) ahead of the
(not-yet-built) auto-promote-on-accept feature (R10). Filtered on
IsActive=1 AND IsDeleted=0 so a soft-deleted master's name becomes reusable.

Revision ID: 0010
Revises: 0009
"""
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "CREATE UNIQUE INDEX UX_ThreatType_NaturalKey "
        "ON Threat_Type(ThreatTypeName, PrimaryThreatCategoryID, SectorID) "
        "WHERE IsActive = 1 AND IsDeleted = 0"
    )
    op.execute(
        "CREATE UNIQUE INDEX UX_ThreatCatalogue_NaturalKey "
        "ON Threat_Catalogue(ThreatTypeID, ThreatName, SectorID) "
        "WHERE IsActive = 1 AND IsDeleted = 0"
    )
    op.execute(
        "CREATE UNIQUE INDEX UX_ThreatActor_NaturalKey "
        "ON Threat_Actor(ThreatActorName) "
        "WHERE IsActive = 1 AND IsDeleted = 0"
    )


def downgrade() -> None:
    op.execute("DROP INDEX UX_ThreatActor_NaturalKey ON Threat_Actor")
    op.execute("DROP INDEX UX_ThreatCatalogue_NaturalKey ON Threat_Catalogue")
    op.execute("DROP INDEX UX_ThreatType_NaturalKey ON Threat_Type")
