"""EntityID/UserID on the 3 pipeline-output tables (Scoped_Threat, Identified_Threat,
Threat_Scenario_Output) — close the entity-isolation asymmetry Scoped_Threat had
(the only output table without EntityID at all), and add UserID (provenance-only,
matching Scenario_Session/Prompt_Log) to all three so every pipeline-output row can
be traced back to who/which entity produced it.

Identified_Threat/Threat_Scenario_Output already have EntityID (migration 0015), but
it was never populated by app code — see app/pipeline/tasks.py's row-builder
functions, fixed alongside this migration to actually pass entity_id/user_id from
scenario_session. This migration only adds the columns; guarded ADDs are a no-op on
any column that already exists.

Revision ID: 0026
Revises: 0025
"""
from alembic import op

revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None

_ADDS = [
    ("Scoped_Threat", "EntityID"),
    ("Scoped_Threat", "UserID"),
    ("Identified_Threat", "UserID"),
    ("Threat_Scenario_Output", "UserID"),
]


def upgrade() -> None:
    for table, col in _ADDS:
        op.execute(
            f"IF COL_LENGTH('dbo.{table}', '{col}') IS NULL "
            f"ALTER TABLE {table} ADD {col} nvarchar(200) NULL"
        )


def downgrade() -> None:
    # Deliberate no-op, same reasoning as 0015: once models.py declares these as
    # baseline schema, dropping them here on downgrade would destroy baseline
    # schema on any database where they were never migration-born.
    pass
