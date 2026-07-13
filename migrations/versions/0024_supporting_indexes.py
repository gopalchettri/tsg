"""Supporting indexes for the hot-path filters this session's model-vs-DDL
cross-check found running unindexed (2026-07-12).

Every table below had either zero secondary index (only its clustered GUID
PK, which no real query filters on) or an existing index that doesn't cover
the columns actually filtered. Confirmed by reading every real call site
against each table, adversarially re-verified independently:

- `Subsystem_Stage_State` -- ~15 call sites (dal.py claim_stage/acquire_lock/
  release_lock/finish_stage/stage_rows/subsystem_ids_at_level/next_epoch/
  reset_stage_for_regen, sessions.py, reaper.py, tasks.py) all filter
  SessionID(+SubsystemID+Level); none touch the PK (StateID, a random GUID).
- `Scenario_Session` -- `dal.latest_completed_session` (the R13 downstream
  contract's hot path, hit on every `GET /assets/{id}/accepted-scenarios`)
  filters (EntityID, AssetID, SessionStatus='completed') ordered by
  CompletedAt DESC; the only similar index (`UX_Session_ActiveAsset`) is
  filtered to SessionStatus='active' and cannot be used for a 'completed'
  query (a SQL Server filtered index requires the query predicate to
  logically subsume the index's filter predicate).
- `Identified_Threat` / `Scoped_Threat` -- both append-only (Superseded
  rows are marked, never deleted), and every `supersede`/`active_threats`/
  `active_scoped_threat_ids`/`supersede_by_threats`/`get_current_rows` call
  filters (SessionID, SubsystemID, Superseded=0); neither table has any
  secondary index at all.
- `Threat_Scenario_Output` -- its one secondary index
  (`UX_Scenario_ActiveIdentity`, SessionID+IdentityHash) doesn't cover
  SubsystemID, so `supersede`/`supersede_by_scoped_threats` (every
  Stage-2/regen write) residual-scan every active row for the session.

All 5 are pure performance indexes (no uniqueness semantics), guarded
IF NOT EXISTS in bootstrap_schema.sql/production_setup.sql for idempotent
re-run, mirrored here for a database managed via Alembic instead.

Revision ID: 0024
Revises: 0023
"""
from alembic import op

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "CREATE INDEX IX_SubsystemStageState_SessionSubLevel "
        "ON Subsystem_Stage_State(SessionID, SubsystemID, Level)"
    )
    op.execute(
        "CREATE INDEX IX_Session_CompletedByAsset "
        "ON Scenario_Session(EntityID, AssetID, CompletedAt DESC) "
        "WHERE SessionStatus = 'completed'"
    )
    op.execute(
        "CREATE INDEX IX_IdentifiedThreat_SessionSubActive "
        "ON Identified_Threat(SessionID, SubsystemID) "
        "WHERE Superseded = 0"
    )
    op.execute(
        "CREATE INDEX IX_ScopedThreat_SessionSubActive "
        "ON Scoped_Threat(SessionID, SubsystemID) "
        "WHERE Superseded = 0"
    )
    op.execute(
        "CREATE INDEX IX_ScenarioOutput_SessionSubActive "
        "ON Threat_Scenario_Output(SessionID, SubsystemID) "
        "WHERE Superseded = 0"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IX_SubsystemStageState_SessionSubLevel ON Subsystem_Stage_State")
    op.execute("DROP INDEX IX_Session_CompletedByAsset ON Scenario_Session")
    op.execute("DROP INDEX IX_IdentifiedThreat_SessionSubActive ON Identified_Threat")
    op.execute("DROP INDEX IX_ScopedThreat_SessionSubActive ON Scoped_Threat")
    op.execute("DROP INDEX IX_ScenarioOutput_SessionSubActive ON Threat_Scenario_Output")
