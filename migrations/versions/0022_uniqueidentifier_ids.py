"""Convert GUID-shaped id columns from nvarchar(36) to native uniqueidentifier
(2026-07-09 storage fix).

Every TSG-owned id column (session/threat/scenario/etc.) has been stored as
`nvarchar(36)` -- 36 characters of text shaped like a GUID -- instead of SQL
Server's native `uniqueidentifier`. `uniqueidentifier` uses ~4.5x less storage
(16 bytes vs. 72), compares/joins faster (native binary vs. text), and avoids a
collation footgun `nvarchar` doesn't. `app/db/models.py`'s `GUID` type is now a
dialect-aware `TypeDecorator` (real `uniqueidentifier` on MSSQL, `Unicode(36)`
on SQLite) -- this migration brings existing MSSQL databases into line with it.

`dal.guid()` only ever writes `str(uuid.uuid4())`, which converts to
`uniqueidentifier` natively -- values are unaffected, only storage. No FK
constraints exist anywhere (by design), so no cross-table drop ordering to
worry about; each table's block below is independent.

`ALTER COLUMN` on a column that's part of a `PRIMARY KEY` or an index requires
dropping that constraint/index first and recreating it after -- 8 tables'
clustered PKs, plus 2 extra indexes that also key on a converting column
(`UX_Scenario_ActiveIdentity` on `Threat_Scenario_Output.SessionID`,
`IX_PromptLog_Session` on `Prompt_Log.SessionID`). Each table gets a
`TRY_CONVERT`-based pre-flight guard first (same `THROW 50000` pattern as
migration 0003) so a malformed id fails loudly and attributably before any
constraint is touched, instead of a generic mid-alter conversion error.

**Operational note:** this drops and recreates 8 clustered indexes plus 2
more -- effectively a full rebuild of every TSG-owned table. Fine instantly on
an empty/small dev DB; on a table with real row counts this wants a
maintenance window, not a live-traffic deploy. Also note `Prompt_Log` and
`Threat_Candidate_Review` were originally created (migrations 0012/0014) with
an inline, unnamed `PRIMARY KEY` -- if a target database still carries SQL
Server's auto-generated constraint name instead of `PK_Prompt_Log` /
`PK_Threat_Candidate_Review` (the name `scripts/bootstrap_schema.sql` uses),
the `DROP CONSTRAINT` for those two tables will fail and the real name will
need to be looked up (`sys.key_constraints`) before re-running.

Revision ID: 0022
Revises: 0021
"""
from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def _guard(table: str, not_null_cols: list[str], nullable_cols: list[str] = ()) -> str:
    checks = [f"TRY_CONVERT(uniqueidentifier, {c}) IS NULL" for c in not_null_cols]
    checks += [f"({c} IS NOT NULL AND TRY_CONVERT(uniqueidentifier, {c}) IS NULL)" for c in nullable_cols]
    return (
        f"IF EXISTS (SELECT 1 FROM {table} WHERE " + " OR ".join(checks) + ") "
        f"THROW 50000, '0022: {table} has a malformed GUID id -- fix before converting to uniqueidentifier', 1;"
    )


def upgrade() -> None:
    # --- Scenario_Session ---------------------------------------------------
    op.execute(_guard("Scenario_Session", ["SessionID"], ["ActiveTaskID"]))
    op.execute("ALTER TABLE Scenario_Session DROP CONSTRAINT PK_Scenario_Session")
    op.execute("ALTER TABLE Scenario_Session ALTER COLUMN SessionID uniqueidentifier NOT NULL")
    op.execute("ALTER TABLE Scenario_Session ALTER COLUMN ActiveTaskID uniqueidentifier NULL")
    op.execute("ALTER TABLE Scenario_Session ADD CONSTRAINT PK_Scenario_Session PRIMARY KEY CLUSTERED (SessionID)")

    # --- Subsystem_Stage_State -----------------------------------------------
    op.execute(_guard("Subsystem_Stage_State", ["StateID", "SessionID"], ["ActiveTaskID"]))
    op.execute("ALTER TABLE Subsystem_Stage_State DROP CONSTRAINT PK_Subsystem_Stage_State")
    op.execute("ALTER TABLE Subsystem_Stage_State ALTER COLUMN StateID uniqueidentifier NOT NULL")
    op.execute("ALTER TABLE Subsystem_Stage_State ALTER COLUMN SessionID uniqueidentifier NOT NULL")
    op.execute("ALTER TABLE Subsystem_Stage_State ALTER COLUMN ActiveTaskID uniqueidentifier NULL")
    op.execute(
        "ALTER TABLE Subsystem_Stage_State ADD CONSTRAINT PK_Subsystem_Stage_State PRIMARY KEY CLUSTERED (StateID)"
    )

    # --- Identified_Threat ----------------------------------------------------
    op.execute(_guard("Identified_Threat", ["ThreatID", "SessionID"]))
    op.execute("ALTER TABLE Identified_Threat DROP CONSTRAINT PK_Identified_Threat")
    op.execute("ALTER TABLE Identified_Threat ALTER COLUMN ThreatID uniqueidentifier NOT NULL")
    op.execute("ALTER TABLE Identified_Threat ALTER COLUMN SessionID uniqueidentifier NOT NULL")
    op.execute("ALTER TABLE Identified_Threat ADD CONSTRAINT PK_Identified_Threat PRIMARY KEY CLUSTERED (ThreatID)")

    # --- Scoped_Threat ----------------------------------------------------------
    op.execute(_guard("Scoped_Threat", ["ScopedThreatID", "SessionID", "ThreatID"]))
    op.execute("ALTER TABLE Scoped_Threat DROP CONSTRAINT PK_Scoped_Threat")
    op.execute("ALTER TABLE Scoped_Threat ALTER COLUMN ScopedThreatID uniqueidentifier NOT NULL")
    op.execute("ALTER TABLE Scoped_Threat ALTER COLUMN SessionID uniqueidentifier NOT NULL")
    op.execute("ALTER TABLE Scoped_Threat ALTER COLUMN ThreatID uniqueidentifier NOT NULL")
    op.execute("ALTER TABLE Scoped_Threat ADD CONSTRAINT PK_Scoped_Threat PRIMARY KEY CLUSTERED (ScopedThreatID)")

    # --- Threat_Scenario_Output (+ UX_Scenario_ActiveIdentity) ------------------
    op.execute(_guard("Threat_Scenario_Output", ["OutputID", "SessionID", "ScopedThreatID"]))
    op.execute("DROP INDEX UX_Scenario_ActiveIdentity ON Threat_Scenario_Output")
    op.execute("ALTER TABLE Threat_Scenario_Output DROP CONSTRAINT PK_Threat_Scenario_Output")
    op.execute("ALTER TABLE Threat_Scenario_Output ALTER COLUMN OutputID uniqueidentifier NOT NULL")
    op.execute("ALTER TABLE Threat_Scenario_Output ALTER COLUMN SessionID uniqueidentifier NOT NULL")
    op.execute("ALTER TABLE Threat_Scenario_Output ALTER COLUMN ScopedThreatID uniqueidentifier NOT NULL")
    op.execute(
        "ALTER TABLE Threat_Scenario_Output ADD CONSTRAINT PK_Threat_Scenario_Output PRIMARY KEY CLUSTERED (OutputID)"
    )
    op.execute(
        "CREATE UNIQUE INDEX UX_Scenario_ActiveIdentity ON Threat_Scenario_Output(SessionID, IdentityHash) "
        "WHERE Superseded = 0"
    )

    # --- Scenario_Audit -----------------------------------------------------------
    op.execute(_guard("Scenario_Audit", ["AuditID", "SessionID"], ["TaskID"]))
    op.execute("ALTER TABLE Scenario_Audit DROP CONSTRAINT PK_Scenario_Audit")
    op.execute("ALTER TABLE Scenario_Audit ALTER COLUMN AuditID uniqueidentifier NOT NULL")
    op.execute("ALTER TABLE Scenario_Audit ALTER COLUMN SessionID uniqueidentifier NOT NULL")
    op.execute("ALTER TABLE Scenario_Audit ALTER COLUMN TaskID uniqueidentifier NULL")
    op.execute("ALTER TABLE Scenario_Audit ADD CONSTRAINT PK_Scenario_Audit PRIMARY KEY CLUSTERED (AuditID)")

    # --- Prompt_Log (+ IX_PromptLog_Session) --------------------------------------
    op.execute(_guard("Prompt_Log", ["LogID", "SessionID"]))
    op.execute("DROP INDEX IX_PromptLog_Session ON Prompt_Log")
    op.execute("ALTER TABLE Prompt_Log DROP CONSTRAINT PK_Prompt_Log")
    op.execute("ALTER TABLE Prompt_Log ALTER COLUMN LogID uniqueidentifier NOT NULL")
    op.execute("ALTER TABLE Prompt_Log ALTER COLUMN SessionID uniqueidentifier NOT NULL")
    op.execute("ALTER TABLE Prompt_Log ADD CONSTRAINT PK_Prompt_Log PRIMARY KEY CLUSTERED (LogID)")
    op.execute("CREATE INDEX IX_PromptLog_Session ON Prompt_Log(SessionID, SubsystemID)")

    # --- Threat_Candidate_Review ---------------------------------------------------
    op.execute(_guard("Threat_Candidate_Review", ["CandidateID", "SessionID"]))
    op.execute("ALTER TABLE Threat_Candidate_Review DROP CONSTRAINT PK_Threat_Candidate_Review")
    op.execute("ALTER TABLE Threat_Candidate_Review ALTER COLUMN CandidateID uniqueidentifier NOT NULL")
    op.execute("ALTER TABLE Threat_Candidate_Review ALTER COLUMN SessionID uniqueidentifier NOT NULL")
    op.execute(
        "ALTER TABLE Threat_Candidate_Review ADD CONSTRAINT PK_Threat_Candidate_Review PRIMARY KEY CLUSTERED (CandidateID)"
    )


def downgrade() -> None:
    # --- Scenario_Session ---------------------------------------------------
    op.execute("ALTER TABLE Scenario_Session DROP CONSTRAINT PK_Scenario_Session")
    op.execute("ALTER TABLE Scenario_Session ALTER COLUMN SessionID nvarchar(36) NOT NULL")
    op.execute("ALTER TABLE Scenario_Session ALTER COLUMN ActiveTaskID nvarchar(36) NULL")
    op.execute("ALTER TABLE Scenario_Session ADD CONSTRAINT PK_Scenario_Session PRIMARY KEY CLUSTERED (SessionID)")

    # --- Subsystem_Stage_State -----------------------------------------------
    op.execute("ALTER TABLE Subsystem_Stage_State DROP CONSTRAINT PK_Subsystem_Stage_State")
    op.execute("ALTER TABLE Subsystem_Stage_State ALTER COLUMN StateID nvarchar(36) NOT NULL")
    op.execute("ALTER TABLE Subsystem_Stage_State ALTER COLUMN SessionID nvarchar(36) NOT NULL")
    op.execute("ALTER TABLE Subsystem_Stage_State ALTER COLUMN ActiveTaskID nvarchar(36) NULL")
    op.execute(
        "ALTER TABLE Subsystem_Stage_State ADD CONSTRAINT PK_Subsystem_Stage_State PRIMARY KEY CLUSTERED (StateID)"
    )

    # --- Identified_Threat ----------------------------------------------------
    op.execute("ALTER TABLE Identified_Threat DROP CONSTRAINT PK_Identified_Threat")
    op.execute("ALTER TABLE Identified_Threat ALTER COLUMN ThreatID nvarchar(36) NOT NULL")
    op.execute("ALTER TABLE Identified_Threat ALTER COLUMN SessionID nvarchar(36) NOT NULL")
    op.execute("ALTER TABLE Identified_Threat ADD CONSTRAINT PK_Identified_Threat PRIMARY KEY CLUSTERED (ThreatID)")

    # --- Scoped_Threat ----------------------------------------------------------
    op.execute("ALTER TABLE Scoped_Threat DROP CONSTRAINT PK_Scoped_Threat")
    op.execute("ALTER TABLE Scoped_Threat ALTER COLUMN ScopedThreatID nvarchar(36) NOT NULL")
    op.execute("ALTER TABLE Scoped_Threat ALTER COLUMN SessionID nvarchar(36) NOT NULL")
    op.execute("ALTER TABLE Scoped_Threat ALTER COLUMN ThreatID nvarchar(36) NOT NULL")
    op.execute("ALTER TABLE Scoped_Threat ADD CONSTRAINT PK_Scoped_Threat PRIMARY KEY CLUSTERED (ScopedThreatID)")

    # --- Threat_Scenario_Output (+ UX_Scenario_ActiveIdentity) ------------------
    op.execute("DROP INDEX UX_Scenario_ActiveIdentity ON Threat_Scenario_Output")
    op.execute("ALTER TABLE Threat_Scenario_Output DROP CONSTRAINT PK_Threat_Scenario_Output")
    op.execute("ALTER TABLE Threat_Scenario_Output ALTER COLUMN OutputID nvarchar(36) NOT NULL")
    op.execute("ALTER TABLE Threat_Scenario_Output ALTER COLUMN SessionID nvarchar(36) NOT NULL")
    op.execute("ALTER TABLE Threat_Scenario_Output ALTER COLUMN ScopedThreatID nvarchar(36) NOT NULL")
    op.execute(
        "ALTER TABLE Threat_Scenario_Output ADD CONSTRAINT PK_Threat_Scenario_Output PRIMARY KEY CLUSTERED (OutputID)"
    )
    op.execute(
        "CREATE UNIQUE INDEX UX_Scenario_ActiveIdentity ON Threat_Scenario_Output(SessionID, IdentityHash) "
        "WHERE Superseded = 0"
    )

    # --- Scenario_Audit -----------------------------------------------------------
    op.execute("ALTER TABLE Scenario_Audit DROP CONSTRAINT PK_Scenario_Audit")
    op.execute("ALTER TABLE Scenario_Audit ALTER COLUMN AuditID nvarchar(36) NOT NULL")
    op.execute("ALTER TABLE Scenario_Audit ALTER COLUMN SessionID nvarchar(36) NOT NULL")
    op.execute("ALTER TABLE Scenario_Audit ALTER COLUMN TaskID nvarchar(36) NULL")
    op.execute("ALTER TABLE Scenario_Audit ADD CONSTRAINT PK_Scenario_Audit PRIMARY KEY CLUSTERED (AuditID)")

    # --- Prompt_Log (+ IX_PromptLog_Session) --------------------------------------
    op.execute("DROP INDEX IX_PromptLog_Session ON Prompt_Log")
    op.execute("ALTER TABLE Prompt_Log DROP CONSTRAINT PK_Prompt_Log")
    op.execute("ALTER TABLE Prompt_Log ALTER COLUMN LogID nvarchar(36) NOT NULL")
    op.execute("ALTER TABLE Prompt_Log ALTER COLUMN SessionID nvarchar(36) NOT NULL")
    op.execute("ALTER TABLE Prompt_Log ADD CONSTRAINT PK_Prompt_Log PRIMARY KEY CLUSTERED (LogID)")
    op.execute("CREATE INDEX IX_PromptLog_Session ON Prompt_Log(SessionID, SubsystemID)")

    # --- Threat_Candidate_Review ---------------------------------------------------
    op.execute("ALTER TABLE Threat_Candidate_Review DROP CONSTRAINT PK_Threat_Candidate_Review")
    op.execute("ALTER TABLE Threat_Candidate_Review ALTER COLUMN CandidateID nvarchar(36) NOT NULL")
    op.execute("ALTER TABLE Threat_Candidate_Review ALTER COLUMN SessionID nvarchar(36) NOT NULL")
    op.execute(
        "ALTER TABLE Threat_Candidate_Review ADD CONSTRAINT PK_Threat_Candidate_Review PRIMARY KEY CLUSTERED (CandidateID)"
    )
