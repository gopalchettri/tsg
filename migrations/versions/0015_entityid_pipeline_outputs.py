"""EntityID on Identified_Threat / Threat_Scenario_Output — heal bootstrap-created DBs.

models.py declares EntityID (nvarchar(200) NULL) on both tables as baseline schema, but
bootstrap_schema.sql omitted it on exactly these two tables until 2026-07-03, so any
database stood up from an older script version lacks the column — and a full-row SELECT
(cascade.py::recheck_threat_in_library reads the whole Identified_Threat row) fails with
"Invalid column name 'EntityID'" the first time a threat regenerates. Guarded ADDs: a
no-op on EYShield-baseline databases, which always had the columns.

Revision ID: 0015
Revises: 0014
"""
from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "IF COL_LENGTH('dbo.Identified_Threat', 'EntityID') IS NULL "
        "ALTER TABLE Identified_Threat ADD EntityID nvarchar(200) NULL"
    )
    op.execute(
        "IF COL_LENGTH('dbo.Threat_Scenario_Output', 'EntityID') IS NULL "
        "ALTER TABLE Threat_Scenario_Output ADD EntityID nvarchar(200) NULL"
    )


def downgrade() -> None:
    # Deliberate no-op: on an EYShield-baseline DB these columns pre-existed this
    # migration (baseline schema models.py always declared), so dropping them here
    # would destroy baseline schema — unlike 0013, whose column was born in the
    # migration. The upgrade is a guarded no-op wherever the columns already exist,
    # so there is nothing this migration owns that a downgrade should remove.
    pass
