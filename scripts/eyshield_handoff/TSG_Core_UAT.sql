-- ============================================================================
-- TSG_Core_UAT — upgrades an ALREADY-DEPLOYED UAT/PROD TSG database to the
-- current schema. The body below is the current TSG_Core.sql, verbatim: every
-- statement is guarded against the live catalog, so whatever this database is
-- missing gets applied and everything already in place no-ops. Safe to re-run
-- any time; never drops tables or columns; never touches row data beyond the
-- two guarded fixups noted below.
--
-- On a UAT database that already has the TSG tables, this run will:
--   * widen Risk_Treatment_Plan Status / TreatmentStrategy / RiskLevel /
--     ReviewStatus to nvarchar(100), and ErrorReason to nvarchar(max)
--   * create any table / column added since the last run (guarded CREATEs/ADDs)
--   * create index IX_TreatmentPlan_SessionHistory (superseded-plan history)
--   * DROP the retired index IX_Session_CompletedByAsset if present
--   * fix up data: backfill Risk_Treatment_Plan.ErrorReason on legacy ERROR
--     rows, and rename review verdict 'changes_requested' -> 'rejected'
--   * on OLDER databases also: widen Scenario_Session.StageStatus and
--     Subsystem_Stage_State.Status, rebuild UX_Scenario_ActiveIdentity to
--     include ScenarioNumber, drop the legacy non-unique
--     IX_SubsystemStageState_SessionSubLevel, and relax
--     CrmRiskIdentificationID to nullable
--
-- SECTION 0 (RCSI) no-ops when RCSI is already ON (true of any working TSG
-- database). If it is somehow OFF, enabling it forces every other session off
-- the database — run in a quiet window.
--
-- HOW TO RUN: paste this WHOLE file into an SSMS query window connected to the
-- TSG database and run (F5), then read the Messages pane top to bottom — an
-- error there means that batch did not apply. CLI alternative:
--   sqlcmd -b -I -S <server> -d <database> -E -i TSG_Core_UAT.sql
-- (-b: exit non-zero on any SQL error. -I: QUOTED_IDENTIFIER ON, required by
--  the filtered indexes. -E = Windows auth; use -U/-P where SQL logins apply.)
-- AFTERWARDS: run TSG_Verify.sql — section 2 confirms indexes, section 3 the
-- ALTER-added columns, section 4 the enum column widths.
--
-- KEEP IN LOCKSTEP with TSG_Core.sql: on the next schema change, regenerate
-- this file (this header + verbatim TSG_Core.sql body). Re-running the
-- canonical TSG_Core.sql itself is equivalent — it carries the same guards.
-- ============================================================================
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;

-- ============================================================
-- SECTION 0 — Enable RCSI (Read Committed Snapshot Isolation), once.
-- Required so reads never block behind a writer (CAS/lock design).
-- WARNING: forces every other session off the database to apply.
-- ============================================================

IF NOT EXISTS (SELECT 1 FROM sys.databases WHERE database_id = DB_ID() AND is_read_committed_snapshot_on = 1)
BEGIN
    ALTER DATABASE CURRENT SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    ALTER DATABASE CURRENT SET READ_COMMITTED_SNAPSHOT ON;
    ALTER DATABASE CURRENT SET MULTI_USER;
END

GO

-- ============================================================
-- SECTION 1 — TSG's own tables
-- ============================================================

IF OBJECT_ID('dbo.Scenario_Session', 'U') IS NULL
CREATE TABLE Scenario_Session (
    SessionID             uniqueidentifier NOT NULL CONSTRAINT PK_Scenario_Session PRIMARY KEY,
    TenantID              nvarchar(200)  NOT NULL,
    EntityID              nvarchar(200)  NOT NULL,          -- [R7] isolation key
    UserID                nvarchar(200)  NULL,
    AssetName             nvarchar(300)  NOT NULL,
    AssetID               nvarchar(200)  NOT NULL,          -- [R7] isolation key
    SessionStatus         nvarchar(100)   NOT NULL,
    CurrentStage          nvarchar(100)   NOT NULL,
    StageStatus           nvarchar(100)   NOT NULL,
    Mode                  nvarchar(100)   NOT NULL,
    CurrentSubsystemIndex int            NULL,
    SubsystemsJSON        nvarchar(max)  NOT NULL,
    IdempotencyKey        nvarchar(200)  NULL,
    SectorIDsJSON         nvarchar(max)  NULL,
    AssetContextJSON      nvarchar(max)  NULL,
    ScoringRulesSnapshotJSON    nvarchar(max)  NULL,               -- frozen tuning rulebook (core.tuning); NULL = pre-feature session
    CreatedAt             datetime2      NULL,
    UpdatedAt             datetime2      NULL,
    CompletedAt           datetime2      NULL,
    CONSTRAINT CK_Session_Status CHECK (SessionStatus IN ('active', 'completed', 'cancelled'))
);

-- ScoringRulesSnapshotJSON: frozen Config_Tuning snapshot at session creation. NULL = pre-feature session.
IF OBJECT_ID('dbo.Scenario_Session', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Session', 'ScoringRulesSnapshotJSON') IS NULL
    ALTER TABLE Scenario_Session ADD ScoringRulesSnapshotJSON nvarchar(max) NULL;

-- Library-promotion retry tracking (accept.py's isolated Phase 2). NULL PromotionFailedAt =
-- never failed, or already resolved by a successful attempt/retry.
IF OBJECT_ID('dbo.Scenario_Session', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Session', 'PromotionFailedAt') IS NULL
    ALTER TABLE Scenario_Session ADD PromotionFailedAt datetime2 NULL;

IF OBJECT_ID('dbo.Scenario_Session', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Session', 'PromotionAttempts') IS NULL
    ALTER TABLE Scenario_Session ADD PromotionAttempts int NOT NULL CONSTRAINT DF_Session_PromotionAttempts DEFAULT 0;

IF OBJECT_ID('dbo.Scenario_Session', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Session', 'PromotionError') IS NULL
    ALTER TABLE Scenario_Session ADD PromotionError nvarchar(max) NULL;

-- The accepting user when promotion first failed, so a later retry (automatic or admin-
-- triggered) attributes promoted threats to that SAME person, never a system identity.
IF OBJECT_ID('dbo.Scenario_Session', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Session', 'PromotionUserID') IS NULL
    ALTER TABLE Scenario_Session ADD PromotionUserID nvarchar(200) NULL;

GO

-- Widen StageStatus on PRE-EXISTING databases (fresh installs already get nvarchar(100) from
-- the CREATE above). Only a value that GREW after databases were provisioned can be stuck
-- narrow in a WORKING database — exactly this column: the rename to
-- 'SCENARIOS_AWAITING_DECISION' (27 chars) overflowed the original nvarchar(20), the
-- documented review-barrier freeze; TSG_Verify.sql section 4 FAILs on it. SessionStatus and
-- CurrentStage are deliberately NOT altered: their longest values ('completed' 9,
-- 'THREAT_IDENTIFICATION' 21) are original vocabulary — a database too narrow for them could
-- never have finished a single session — and SessionStatus is referenced by two FILTERED
-- index predicates (UX_Session_ActiveAsset / IX_Session_Active),
-- where an in-place ALTER COLUMN raises Msg 5074. Guard is schema-qualified (a same-named
-- table in another schema must not trigger — or worse, narrow — the dbo column) and skips
-- nvarchar(max) (-1). NOT NULL restated because ALTER COLUMN resets nullability. Widening
-- nvarchar is metadata-only but takes a brief SCH-M lock on a hot table (RCSI does not exempt
-- readers from SCH-S) — prefer a quiet window. Own GO batch: a failure here must not silently
-- skip the rest of the migration, and vice versa.
IF EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
           WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = 'Scenario_Session'
             AND COLUMN_NAME = 'StageStatus'
             AND CHARACTER_MAXIMUM_LENGTH BETWEEN 1 AND 99)
    ALTER TABLE dbo.Scenario_Session ALTER COLUMN StageStatus nvarchar(100) NOT NULL;

GO

IF OBJECT_ID('dbo.Subsystem_Stage_State', 'U') IS NULL
CREATE TABLE Subsystem_Stage_State (
    StateID          uniqueidentifier NOT NULL CONSTRAINT PK_Subsystem_Stage_State PRIMARY KEY,
    SessionID        uniqueidentifier NOT NULL,
    TenantID         nvarchar(200) NULL,
    EntityID         nvarchar(200) NULL,
    SubsystemID      int           NOT NULL,
    Level            nvarchar(100)  NOT NULL,                -- THREATS|SCENARIOS|_LOCK
    Status           nvarchar(100)  NOT NULL,
    GenerationEpoch  int           NOT NULL,
    ActiveTaskID     uniqueidentifier NULL,
    LeaseExpiresAt   datetime2     NULL,
    HeartbeatAt      datetime2     NULL,
    AttemptCount     int           NOT NULL CONSTRAINT DF_SSS_AttemptCount DEFAULT 0,
    ErrorMessage     nvarchar(max) NULL,
    UpdatedAt        datetime2     NOT NULL,
    CreatedAt datetime2 NULL CONSTRAINT DF_StageState_CreatedAt DEFAULT SYSUTCDATETIME()
);

-- Adds CreatedAt for pre-2026-07-30 databases.
IF OBJECT_ID('dbo.Subsystem_Stage_State', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Subsystem_Stage_State', 'CreatedAt') IS NULL
    ALTER TABLE Subsystem_Stage_State ADD CreatedAt datetime2 NULL CONSTRAINT DF_StageState_CreatedAt DEFAULT SYSUTCDATETIME();

GO

-- Same pre-existing-database widening for Status, which receives the same StageStatus enum
-- values (incl. the 27-char 'SCENARIOS_AWAITING_DECISION'). Level is deliberately NOT
-- altered: its longest value ('SCENARIOS', 9) is original vocabulary — nothing to fix — and
-- it is a key of UX_SubsystemStageState_SessionSubLevel, so there is no reason to touch it in
-- place. Same guard posture as the Scenario_Session block above.
IF EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
           WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = 'Subsystem_Stage_State'
             AND COLUMN_NAME = 'Status'
             AND CHARACTER_MAXIMUM_LENGTH BETWEEN 1 AND 99)
    ALTER TABLE dbo.Subsystem_Stage_State ALTER COLUMN Status nvarchar(100) NOT NULL;

GO

IF OBJECT_ID('dbo.Identified_Threat', 'U') IS NULL
CREATE TABLE Identified_Threat (
    ThreatID           uniqueidentifier NOT NULL CONSTRAINT PK_Identified_Threat PRIMARY KEY,
    SessionID          uniqueidentifier NOT NULL,
    TenantID           nvarchar(200) NULL,
    EntityID           nvarchar(200) NULL,
    UserID             nvarchar(200) NULL,
    SubsystemID        int           NOT NULL,
    ThreatCategory     nvarchar(200) NOT NULL,
    ThreatType         nvarchar(300) NOT NULL,
    ThreatName         nvarchar(500) NULL,
    GenericName        nvarchar(500) NULL,   -- library-shaped ThreatName (no asset/product names); NULL = legacy row
    ThreatActorsJSON   nvarchar(max) NULL,
    LibraryThreatType  nvarchar(300) NULL,
    LibraryThreatName  nvarchar(500) NULL,
    ThreatTypeID       int           NULL,
    ThreatCatalogueID  int           NULL,
    GroundingStatus    nvarchar(100)  NOT NULL,
    GroundingScore     float         NULL,
    Superseded         int           NOT NULL,
    CreatedAt          datetime2     NULL
);

-- Audit-only trail of AI-proposed threats DROPPED as duplicates during find_threats (identity-hash
-- exact match, or semantic near-duplicate) — never read by scoping/scenario generation/next-set;
-- Identified_Threat stays exactly as it is today, so no existing query needs to change.
-- DuplicateOfThreatID is best-effort: populated for semantic matches (score/label both known at
-- drop time); NULL for an identity-hash match against a threat from a PRIOR round, where only the
-- hash, not the original threat id, is available without a second lookup.
IF OBJECT_ID('dbo.Identified_Duplicate_Threat', 'U') IS NULL
CREATE TABLE Identified_Duplicate_Threat (
    DuplicateThreatID  uniqueidentifier NOT NULL CONSTRAINT PK_Identified_Duplicate_Threat PRIMARY KEY,
    SessionID          uniqueidentifier NOT NULL,
    TenantID           nvarchar(200) NULL,
    EntityID           nvarchar(200) NULL,
    UserID             nvarchar(200) NULL,
    SubsystemID        int           NOT NULL,
    ThreatCategory     nvarchar(200) NOT NULL,
    ThreatType         nvarchar(300) NOT NULL,
    ThreatName         nvarchar(500) NULL,
    GenericName        nvarchar(500) NULL,
    ThreatActorsJSON   nvarchar(max) NULL,
    DuplicateOfThreatID uniqueidentifier NULL,   -- Identified_Threat.ThreatID it matched, when known
    DuplicateReason    nvarchar(100)  NOT NULL,   -- DuplicateReason enum (app/core/enums.py)
    SimilarityScore    float         NULL,       -- cosine score for semantic matches; NULL for identity
    CreatedAt          datetime2     NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_IdentifiedDuplicateThreat_Session' AND object_id = OBJECT_ID('dbo.Identified_Duplicate_Threat'))
CREATE INDEX IX_IdentifiedDuplicateThreat_Session ON Identified_Duplicate_Threat(SessionID);
-- The table's whole purpose is "which threats were dropped as duplicates, in which session" —
-- without this, that lookup is a full table scan. No filter predicate: unlike Scoped_Threat's
-- Superseded-filtered indexes, every row here is permanent audit history, never superseded.

IF OBJECT_ID('dbo.Scoped_Threat', 'U') IS NULL
CREATE TABLE Scoped_Threat (
    ScopedThreatID  uniqueidentifier NOT NULL CONSTRAINT PK_Scoped_Threat PRIMARY KEY,
    SessionID       uniqueidentifier NOT NULL,
    TenantID        nvarchar(200) NULL,
    EntityID        nvarchar(200) NULL,
    UserID          nvarchar(200) NULL,
    SubsystemID     int           NOT NULL,
    ThreatID        uniqueidentifier NOT NULL,
    Score           float         NOT NULL,
    ScopeRank       int           NOT NULL,
    Selected        int           NOT NULL,
    Reason          nvarchar(500) NULL,
    RejectionKind   nvarchar(100)  NULL,
    SelectionKind   nvarchar(100)  NULL,
    FactorsJSON     nvarchar(max) NULL,
    Superseded      int           NOT NULL,
    CreatedAt       datetime2     NULL
);

-- Adds RejectionKind for pre-2026-08-03 databases. Pre-existing NULL rows: run
-- scripts/backfill_rejection_kind.sql once.
IF OBJECT_ID('dbo.Scoped_Threat', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scoped_Threat', 'RejectionKind') IS NULL
    ALTER TABLE Scoped_Threat ADD RejectionKind nvarchar(30) NULL;

-- SelectionKind: why a threat WAS selected. NULL = unknown, never re-derived from Reason text.
IF OBJECT_ID('dbo.Scoped_Threat', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scoped_Threat', 'SelectionKind') IS NULL
    ALTER TABLE Scoped_Threat ADD SelectionKind nvarchar(30) NULL;

-- GenericName: library-shaped ThreatName, used for accept-time triage. NULL = legacy row.
IF OBJECT_ID('dbo.Identified_Threat', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Identified_Threat', 'GenericName') IS NULL
    ALTER TABLE Identified_Threat ADD GenericName nvarchar(500) NULL;

-- ProposedGenericName: library-shaped proposal shown to curators.
IF OBJECT_ID('dbo.Threat_Candidate_Review', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Candidate_Review', 'ProposedGenericName') IS NULL
    ALTER TABLE Threat_Candidate_Review ADD ProposedGenericName nvarchar(500) NULL;

IF OBJECT_ID('dbo.Threat_Scenario_Output', 'U') IS NULL
CREATE TABLE Threat_Scenario_Output (
    OutputID             uniqueidentifier NOT NULL CONSTRAINT PK_Threat_Scenario_Output PRIMARY KEY,
    SessionID            uniqueidentifier NOT NULL,
    TenantID             nvarchar(200) NULL,
    EntityID             nvarchar(200) NULL,
    UserID               nvarchar(200) NULL,
    SubsystemID          int           NOT NULL,
    ScopedThreatID       uniqueidentifier NOT NULL,
    Status               nvarchar(100)  NOT NULL,
    ScenarioJSON         nvarchar(max) NULL,
    ValidationJSON       nvarchar(max) NULL,
    AcceptedSubsetJSON   nvarchar(max) NULL,
    Accepted             int           NOT NULL,
    Superseded           int           NOT NULL,
    IdentityHash         nvarchar(100)  NULL,
    ScenarioNumber       int           NOT NULL CONSTRAINT DF_ScenarioOutput_ScenarioNumber DEFAULT 1,  -- 1 = original, 2+ = "generate next set" alternates
    ReplacesOutputID     uniqueidentifier NULL,   -- OutputID this row replaced; NULL for first-run/variant rows
    GenerationEpoch      int           NOT NULL,
    ErrorMessage         nvarchar(max) NULL,
    CreatedAt            datetime2     NULL,
    ControlsMappedAt     datetime2     NULL,  -- Step-4 attempt stamp; NULL = not yet tried
    -- Per-scenario review decision. NULL/NULL = pending (nobody has decided yet), which is why
    -- these are nullable columns rather than a status value: Status is the GENERATION outcome
    -- (complete|error) and is load-bearing in the accept and promotion predicates, so a review
    -- verdict must not ride on it. Mutually exclusive with Accepted=1.
    RejectedAt           datetime2     NULL,
    RejectedBy           nvarchar(200) NULL
);

-- Adds ControlsMappedAt for pre-Step-4 databases.
IF OBJECT_ID('dbo.Threat_Scenario_Output', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario_Output', 'ControlsMappedAt') IS NULL
    ALTER TABLE Threat_Scenario_Output ADD ControlsMappedAt datetime2 NULL;

-- Adds ScenarioNumber for pre-2026-07-29 databases.
IF OBJECT_ID('dbo.Threat_Scenario_Output', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario_Output', 'ScenarioNumber') IS NULL
    ALTER TABLE Threat_Scenario_Output ADD ScenarioNumber int NOT NULL CONSTRAINT DF_ScenarioOutput_ScenarioNumber DEFAULT 1;

-- Adds ReplacesOutputID for pre-2026-07-30 databases. Legacy rows simply read as originals.
IF OBJECT_ID('dbo.Threat_Scenario_Output', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario_Output', 'ReplacesOutputID') IS NULL
    ALTER TABLE Threat_Scenario_Output ADD ReplacesOutputID uniqueidentifier NULL;

-- Adds the per-scenario review decision for pre-2026-08-23 databases. Legacy rows read as
-- pending, which is correct: nobody recorded a rejection for them.
IF OBJECT_ID('dbo.Threat_Scenario_Output', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario_Output', 'RejectedAt') IS NULL
    ALTER TABLE Threat_Scenario_Output ADD RejectedAt datetime2 NULL;

IF OBJECT_ID('dbo.Threat_Scenario_Output', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario_Output', 'RejectedBy') IS NULL
    ALTER TABLE Threat_Scenario_Output ADD RejectedBy nvarchar(200) NULL;

-- Adds ScenarioSource for pre-scenario-library databases. NULL reads as "generated for this
-- asset", which is what every legacy row is.
IF OBJECT_ID('dbo.Threat_Scenario_Output', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario_Output', 'ScenarioSource') IS NULL
    ALTER TABLE Threat_Scenario_Output ADD ScenarioSource nvarchar(100) NULL;

-- A scenario cannot be both accepted and rejected. Enforced in the DATABASE, not only in the
-- service layer: accept and reject will be independent routes reachable at any time after the
-- session completes, so the one place both orderings must meet is the row itself. Guarded so a
-- re-run is a no-op, and NOT trusted to WITH CHECK on legacy data — existing rows all read
-- pending (RejectedAt NULL), so the constraint holds for them by construction.
IF OBJECT_ID('dbo.Threat_Scenario_Output', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario_Output', 'RejectedAt') IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM sys.check_constraints
                    WHERE name = 'CK_ScenarioOutput_DecisionExclusive')
    ALTER TABLE Threat_Scenario_Output ADD CONSTRAINT CK_ScenarioOutput_DecisionExclusive
        CHECK (RejectedAt IS NULL OR Accepted = 0);

-- Per-scenario decision trail for pre-2026-08-23 databases. Legacy rows read as NULL, which is
-- correct: they were session-scoped events and belong to no single scenario.
IF OBJECT_ID('dbo.Scenario_Audit', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Audit', 'OutputID') IS NULL
    ALTER TABLE Scenario_Audit ADD OutputID uniqueidentifier NULL;

-- MANDATORY one-time backfill for the scenario-lifecycle change.
-- Generation now COMPLETES the session when it reaches its review barrier, which is what releases
-- the asset (UX_Session_ActiveAsset is filtered on SessionStatus='active'). Sessions created
-- before that change are parked at REVIEW while still 'active', and nothing will ever complete
-- them: the only writer that used to do it was accept, which no longer completes anything. Left
-- alone they hold their asset open forever and block every new session for it.
-- Idempotent: the WHERE clause matches nothing on a second run.
IF OBJECT_ID('dbo.Scenario_Session', 'U') IS NOT NULL
    UPDATE Scenario_Session
        SET SessionStatus = 'completed',
            CompletedAt   = COALESCE(CompletedAt, SYSUTCDATETIME()),
            UpdatedAt     = SYSUTCDATETIME()
    WHERE SessionStatus = 'active'
        AND CurrentStage = 'REVIEW';

-- ---------------------------------------------------------------------------
-- Widen the short enum/status columns to nvarchar(100)
-- ---------------------------------------------------------------------------
-- These hold values from closed vocabularies (app/core/enums.py) and were sized to the longest
-- member at the time. Adding a longer member later is a one-line enum change that silently
-- outgrows its column: every SHORTER value still inserts, so the application looks healthy right
-- up until the first write of the new value fails, and the workflow stalls with no obvious cause.
-- TSG_Verify.sql has a whole 'Column width' section devoted to catching exactly that.
--
-- nvarchar(100) is far past any current member, so that failure mode stops being reachable. The
-- cost is nothing: nvarchar is variable-length, so a 12-character value occupies 12 characters
-- whatever the declared maximum.
--
-- Guarded on the CURRENT width, so re-running is a no-op and a site already at 100 is skipped.

-- IX_ScenarioAudit_SessionSubEvent has EventType in its key, and SQL Server refuses ALTER COLUMN
-- while an index depends on it. Dropped here and recreated by the guarded CREATE INDEX further
-- down this same script - no duplicate definition to keep in step.
IF COL_LENGTH('dbo.Scenario_Audit', 'EventType') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Scenario_Audit'), 'EventType', 'CharMaxLen') < 100
    AND EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioAudit_SessionSubEvent'
                AND object_id = OBJECT_ID('dbo.Scenario_Audit'))
    DROP INDEX IX_ScenarioAudit_SessionSubEvent ON Scenario_Audit;

IF OBJECT_ID('dbo.Identified_Threat', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Identified_Threat', 'GroundingStatus') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Identified_Threat'), 'GroundingStatus', 'CharMaxLen') < 100
    ALTER TABLE Identified_Threat ALTER COLUMN GroundingStatus nvarchar(100) NOT NULL;
IF OBJECT_ID('dbo.Identified_Duplicate_Threat', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Identified_Duplicate_Threat', 'DuplicateReason') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Identified_Duplicate_Threat'), 'DuplicateReason', 'CharMaxLen') < 100
    ALTER TABLE Identified_Duplicate_Threat ALTER COLUMN DuplicateReason nvarchar(100) NOT NULL;
IF OBJECT_ID('dbo.Scoped_Threat', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scoped_Threat', 'RejectionKind') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Scoped_Threat'), 'RejectionKind', 'CharMaxLen') < 100
    ALTER TABLE Scoped_Threat ALTER COLUMN RejectionKind nvarchar(100) NULL;
IF OBJECT_ID('dbo.Scoped_Threat', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scoped_Threat', 'SelectionKind') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Scoped_Threat'), 'SelectionKind', 'CharMaxLen') < 100
    ALTER TABLE Scoped_Threat ALTER COLUMN SelectionKind nvarchar(100) NULL;
IF OBJECT_ID('dbo.Threat_Scenario_Output', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario_Output', 'Status') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Threat_Scenario_Output'), 'Status', 'CharMaxLen') < 100
    ALTER TABLE Threat_Scenario_Output ALTER COLUMN Status nvarchar(100) NOT NULL;
IF OBJECT_ID('dbo.Threat_Library_Import_Run', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Library_Import_Run', 'Source') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Threat_Library_Import_Run'), 'Source', 'CharMaxLen') < 100
    ALTER TABLE Threat_Library_Import_Run ALTER COLUMN Source nvarchar(100) NOT NULL;
IF OBJECT_ID('dbo.Threat_Library_Import_Run', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Library_Import_Run', 'SourceTag') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Threat_Library_Import_Run'), 'SourceTag', 'CharMaxLen') < 100
    ALTER TABLE Threat_Library_Import_Run ALTER COLUMN SourceTag nvarchar(100) NULL;
IF OBJECT_ID('dbo.Threat_Library_Import_Run', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Library_Import_Run', 'Status') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Threat_Library_Import_Run'), 'Status', 'CharMaxLen') < 100
    ALTER TABLE Threat_Library_Import_Run ALTER COLUMN Status nvarchar(100) NOT NULL;
IF OBJECT_ID('dbo.Scenario_Audit', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Audit', 'Stage') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Scenario_Audit'), 'Stage', 'CharMaxLen') < 100
    ALTER TABLE Scenario_Audit ALTER COLUMN Stage nvarchar(100) NULL;
IF OBJECT_ID('dbo.Scenario_Audit', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Audit', 'EventType') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Scenario_Audit'), 'EventType', 'CharMaxLen') < 100
    ALTER TABLE Scenario_Audit ALTER COLUMN EventType nvarchar(100) NOT NULL;
IF OBJECT_ID('dbo.Scenario_Audit', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Audit', 'Decision') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Scenario_Audit'), 'Decision', 'CharMaxLen') < 100
    ALTER TABLE Scenario_Audit ALTER COLUMN Decision nvarchar(100) NULL;
IF OBJECT_ID('dbo.Scenario_Audit', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Audit', 'Granularity') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Scenario_Audit'), 'Granularity', 'CharMaxLen') < 100
    ALTER TABLE Scenario_Audit ALTER COLUMN Granularity nvarchar(100) NULL;
IF OBJECT_ID('dbo.Scenario_Audit', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Audit', 'ActorType') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Scenario_Audit'), 'ActorType', 'CharMaxLen') < 100
    ALTER TABLE Scenario_Audit ALTER COLUMN ActorType nvarchar(100) NULL;
IF OBJECT_ID('dbo.Prompt_Log', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Prompt_Log', 'Stage') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Prompt_Log'), 'Stage', 'CharMaxLen') < 100
    ALTER TABLE Prompt_Log ALTER COLUMN Stage nvarchar(100) NOT NULL;
IF OBJECT_ID('dbo.Prompt_Log', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Prompt_Log', 'PromptVersion') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Prompt_Log'), 'PromptVersion', 'CharMaxLen') < 100
    ALTER TABLE Prompt_Log ALTER COLUMN PromptVersion nvarchar(100) NOT NULL;
IF OBJECT_ID('dbo.Threat_Candidate_Review', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Candidate_Review', 'CandidateKind') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Threat_Candidate_Review'), 'CandidateKind', 'CharMaxLen') < 100
    ALTER TABLE Threat_Candidate_Review ALTER COLUMN CandidateKind nvarchar(100) NULL;
IF OBJECT_ID('dbo.Config_Tuning', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Config_Tuning', 'ValueType') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Config_Tuning'), 'ValueType', 'CharMaxLen') < 100
    ALTER TABLE Config_Tuning ALTER COLUMN ValueType nvarchar(100) NOT NULL;

-- ---------------------------------------------------------------------------
-- Rename Scenario_Session.TuningJSON -> ScoringRulesSnapshotJSON
-- ---------------------------------------------------------------------------
-- The value is a SNAPSHOT, frozen at session creation, and that is the whole point: every later
-- stage reads it so a mid-run Config_Tuning edit cannot change how a session already in flight
-- scores. "TuningJSON" read as "the tuning config", which is exactly what it is not.
--
-- sp_rename, not add-and-copy: it preserves the data in place. Guarded both ways, so it runs once
-- and is a no-op afterwards.
IF OBJECT_ID('dbo.Scenario_Session', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Session', 'TuningJSON') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Session', 'ScoringRulesSnapshotJSON') IS NULL
    EXEC sp_rename 'dbo.Scenario_Session.TuningJSON', 'ScoringRulesSnapshotJSON', 'COLUMN';

-- Second hop, for anyone who ran this script during the brief window it used the intermediate
-- name TuningSnapshotJSON. Guarded the same way, so it is a no-op on every other database.
IF OBJECT_ID('dbo.Scenario_Session', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Session', 'TuningSnapshotJSON') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Session', 'ScoringRulesSnapshotJSON') IS NULL
    EXEC sp_rename 'dbo.Scenario_Session.TuningSnapshotJSON', 'ScoringRulesSnapshotJSON', 'COLUMN';


IF OBJECT_ID('dbo.Threat_Library_Import_Run', 'U') IS NULL
CREATE TABLE Threat_Library_Import_Run (
    RunID            uniqueidentifier NOT NULL CONSTRAINT PK_Threat_Library_Import_Run PRIMARY KEY,
    Source           nvarchar(100)  NOT NULL,   -- attack | attack_ics | capec | emb3d | pytm | threat_composer | misp_actors
    SourceTag        nvarchar(100)  NULL,       -- provenance tag stamped on imported rows (Threat_Type.Source)
    DryRun           bit           NOT NULL,
    Status           nvarchar(100)  NOT NULL,   -- running | success | failed
    JobID            nvarchar(100) NULL,       -- Celery task id
    StartedBy        nvarchar(200) NULL,
    StartedAt        datetime2     NULL,
    FinishedAt       datetime2     NULL,
    TypesImported    int           NULL,
    ThreatsImported  int           NULL,
    ActorsUpserted   int           NULL,
    OtRules          int           NULL,
    SkippedCount     int           NULL,
    ErrorMessage     nvarchar(max) NULL
);

-- Threat_Scenario_Control_Map (Step-4 mapping) lives in Control_library.sql.

IF OBJECT_ID('dbo.Scenario_Audit', 'U') IS NULL
CREATE TABLE Scenario_Audit (
    AuditID          uniqueidentifier NOT NULL CONSTRAINT PK_Scenario_Audit PRIMARY KEY,
    SessionID        uniqueidentifier NOT NULL,
    TenantID         nvarchar(200) NULL,
    EntityID         nvarchar(200) NULL,
    Stage            nvarchar(100)  NULL,
    SubsystemID      int           NULL,
    EventType        nvarchar(100)  NOT NULL,
    -- The scenario this event is ABOUT. NULL on every session- or subsystem-scoped event; set on
    -- the per-scenario decision rows (scenario_accepted / scenario_rejected). A column, not a
    -- DetailJSON key, because "the decision history of this scenario" is the question a GRC
    -- reviewer actually asks, and JSON cannot be indexed for it.
    OutputID         uniqueidentifier NULL,
    Decision         nvarchar(100)  NULL,
    Granularity      nvarchar(100)  NULL,
    ThreatTypeRefID  int           NULL,
    ActorUserID      nvarchar(200) NULL,   -- who is ACCOUNTABLE (back-filled to the session owner)
    ActorType        nvarchar(100)  NULL,   -- who PERFORMED it: 'user' | 'system'
    DetailJSON       nvarchar(max) NULL,
    CreatedAt        datetime2     NOT NULL
);

IF OBJECT_ID('dbo.Prompt_Log', 'U') IS NULL
CREATE TABLE Prompt_Log (
    LogID           uniqueidentifier NOT NULL CONSTRAINT PK_Prompt_Log PRIMARY KEY,
    SessionID       uniqueidentifier NOT NULL,
    TenantID        nvarchar(200) NULL,
    EntityID        nvarchar(200) NULL,
    UserID          nvarchar(200) NULL,
    SubsystemID     int           NOT NULL,
    Stage           nvarchar(100)  NOT NULL,
    PromptVersion   nvarchar(100)  NOT NULL,
    Messages        nvarchar(max) NOT NULL,
    Prompt          nvarchar(max) NULL,
    ResponseText    nvarchar(max) NULL,
    Model           nvarchar(200) NULL,
    ModelVersion    nvarchar(100) NULL,
    ParseSucceeded  bit           NOT NULL,
    CreatedAt       datetime2     NOT NULL,
    CorrelationID   uniqueidentifier NULL      -- per-item id of the work this call served (e.g. treatment PlanID)
);

-- Adds CorrelationID for pre-2026-08-06 databases. Legacy rows have no per-item linkage.
IF OBJECT_ID('dbo.Prompt_Log', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Prompt_Log', 'CorrelationID') IS NULL
    ALTER TABLE Prompt_Log ADD CorrelationID uniqueidentifier NULL;

-- Adds Prompt (flattened prompt text) for pre-2026-08-03 databases. Still recoverable
-- from Messages, so nothing to backfill.
IF OBJECT_ID('dbo.Prompt_Log', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Prompt_Log', 'Prompt') IS NULL
    ALTER TABLE Prompt_Log ADD Prompt nvarchar(max) NULL;

IF OBJECT_ID('dbo.Threat_Candidate_Review', 'U') IS NULL
CREATE TABLE Threat_Candidate_Review (
    CandidateID       uniqueidentifier NOT NULL CONSTRAINT PK_Threat_Candidate_Review PRIMARY KEY,
    TenantID          nvarchar(200) NOT NULL,
    EntityID          nvarchar(200) NULL,
    SessionID         uniqueidentifier NOT NULL,
    ProposedCategory  nvarchar(200) NULL,     -- NULL on actor candidates (kind='actor')
    ProposedType      nvarchar(300) NULL,     -- actor candidates: the threat type the actor was
                                              -- proposed FOR (approval's link target); NULL only on legacy rows
    ProposedName      nvarchar(500) NOT NULL, -- threat name, or the actor name for kind='actor'
    ProposedGenericName nvarchar(500) NULL,  -- library-shaped name the curator generalizes toward
    Status            nvarchar(100)  NOT NULL,
    ThreatTypeID      int NULL,
    ThreatCatalogueID int NULL,
    ReviewedBy        nvarchar(200) NULL,
    ReviewedAt        datetime2 NULL,
    CreatedAt         datetime2 NOT NULL,
    CandidateKind     nvarchar(100) NULL,      -- 'threat' | 'actor'; NULL = legacy 'threat'
    CreatedBy         nvarchar(200) NULL      -- ORIGINAL proposer (accepting user), never the admin
);

-- Admin-gated library growth (2026-08-18): the queue now also holds ACTOR candidates
-- (CandidateKind 'actor'; NULL = legacy 'threat' rows). On those, ProposedName is the actor and
-- ProposedType names the threat type it was proposed for (approval's link target) — category is
-- NULL, and both columns must become nullable (type is NULL on legacy actor rows queued before
-- the type text was stamped). CreatedBy = the ORIGINAL proposer (the user whose accept raised
-- the candidate); NULL reads honestly as "predates the column".
-- nvarchar(100), NOT 20: this ADD sits BELOW the blanket widen block, so on a database that
-- did not yet have the column the widen is a no-op (COL_LENGTH IS NULL) and this ADD is what
-- the column ends up as - permanently. At 20 an upgraded site would sit two widths below a
-- fresh install's CREATE TABLE, which is exactly the silent drift the widen block exists to
-- stop. Matches the CREATE TABLE above.
IF COL_LENGTH('dbo.Threat_Candidate_Review', 'CandidateKind') IS NULL
    ALTER TABLE dbo.Threat_Candidate_Review ADD CandidateKind nvarchar(100) NULL;
IF COL_LENGTH('dbo.Threat_Candidate_Review', 'CreatedBy') IS NULL
    ALTER TABLE dbo.Threat_Candidate_Review ADD CreatedBy nvarchar(200) NULL;
IF EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('dbo.Threat_Candidate_Review')
           AND name = 'ProposedCategory' AND is_nullable = 0)
    ALTER TABLE dbo.Threat_Candidate_Review ALTER COLUMN ProposedCategory nvarchar(200) NULL;
IF EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('dbo.Threat_Candidate_Review')
           AND name = 'ProposedType' AND is_nullable = 0)
    ALTER TABLE dbo.Threat_Candidate_Review ALTER COLUMN ProposedType nvarchar(300) NULL;

-- Speeds up the curator queue's "list pending" read. Non-unique: names can legitimately recur.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ThreatCandidateReview_Session_Status' AND object_id = OBJECT_ID('dbo.Threat_Candidate_Review'))
    CREATE INDEX IX_ThreatCandidateReview_Session_Status
        ON Threat_Candidate_Review (SessionID, Status);

-- The admin curator queue (GET /v1/tsg/threat-library/candidates) is deliberately CROSS-session
-- — Status alone, no SessionID filter, ordered oldest-first — so the index above can't serve it:
-- SessionID is its leading column, and a query with no SessionID predicate can't seek on it.
-- NOT filtered to Status='pending': SQLAlchemy sends Status as a bound parameter, not a literal,
-- and SQL Server can't match a filtered index against a parameterized predicate (same reasoning
-- IX_ScopedThreat_SessionActiveScores below documents) — Status leads as a plain key column
-- instead, with CreatedAt trailing so the ORDER BY is satisfied by the same seek, no extra sort.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ThreatCandidateReview_Status_Created' AND object_id = OBJECT_ID('dbo.Threat_Candidate_Review'))
    CREATE INDEX IX_ThreatCandidateReview_Status_Created
        ON Threat_Candidate_Review (Status, CreatedAt);

-- Risk Treatment Plan (docs/RISK_TREATMENT_PLAN_SDD.md). One row per generation attempt
-- on an accepted scenario; at most one active (Superseded=0) row per OutputID, enforced
-- by UX_TreatmentPlan_ActiveOutput below. Risk data (ratings, level, existing controls)
-- arrives in the request body — TSG reads no external risk tables.
IF OBJECT_ID('dbo.Risk_Treatment_Plan', 'U') IS NULL
CREATE TABLE Risk_Treatment_Plan (
    PlanID                  uniqueidentifier NOT NULL CONSTRAINT PK_Risk_Treatment_Plan PRIMARY KEY,
    SessionID               uniqueidentifier NOT NULL,
    OutputID                uniqueidentifier NOT NULL,  -- the accepted Threat_Scenario_Output
    TenantID                nvarchar(200) NULL,
    EntityID                nvarchar(200) NULL,         -- copied from the session (authz boundary)
    UserID                  nvarchar(200) NULL,         -- requesting principal (provenance)
    CrmRiskIdentificationID int           NULL,         -- reserved; unused (no register lookup)
    TreatmentStrategy       nvarchar(100) NOT NULL,     -- 'Mitigate' only in v1
    Status                  nvarchar(100) NOT NULL,     -- StageStatus subset: RUNNING | COMPLETE | ERROR
    ActiveTaskID            nvarchar(100) NULL,         -- Celery claim / redelivery fence
    RiskIdentificationDate  datetime2     NULL,         -- crm creation_date; never AI-generated
    InputSnapshotJSON       nvarchar(max) NULL,         -- exact redacted context sent to the LLM
    PlanJSON                nvarchar(max) NULL,         -- parsed LLM output
    ValidationJSON          nvarchar(max) NULL,         -- advisory: moderation + vocabulary warnings
    ErrorMessage            nvarchar(max) NULL,         -- client-safe only; raw text lives in Prompt_Log
    Superseded              int           NOT NULL CONSTRAINT DF_TreatmentPlan_Superseded DEFAULT 0,
    CreatedAt               datetime2     NULL,
    UpdatedAt               datetime2     NULL,         -- progress clock: claim + each LLM attempt bump it
    CompletedAt             datetime2     NULL,
    RiskLevel               nvarchar(100) NULL,         -- register risk level from the request (filterable)
    ReviewStatus            nvarchar(100) NULL,         -- TreatmentReviewStatus; NULL = not reviewed
    ReviewComment           nvarchar(max) NULL,
    ReviewedBy              nvarchar(200) NULL,         -- from the reviewer's login token
    ReviewedAt              datetime2     NULL,
    ErrorReason             nvarchar(max) NULL          -- TreatmentOutcomeReason: WHY it ended that
                                                        -- way. NULL on COMPLETE. Holds 5 of the
                                                        -- enum's 6 values — 'timed_out' is a
                                                        -- read-time projection with no writer, so
                                                        -- do NOT add a CHECK for all six.
);
GO

-- Adds review/register columns for pre-2026-08-06 databases. Guarded PER COLUMN, not on
-- RiskLevel alone: an abort between the ALTERs (lock timeout, killed session) must not let
-- the re-run see RiskLevel present and skip the rest — ReviewComment/ReviewedBy/ReviewedAt
-- are in no TSG_Verify width check, so that miss would be permanent and silent.
IF OBJECT_ID('dbo.Risk_Treatment_Plan', 'U') IS NOT NULL AND COL_LENGTH('dbo.Risk_Treatment_Plan', 'RiskLevel') IS NULL
    ALTER TABLE Risk_Treatment_Plan ADD RiskLevel nvarchar(100) NULL;
IF OBJECT_ID('dbo.Risk_Treatment_Plan', 'U') IS NOT NULL AND COL_LENGTH('dbo.Risk_Treatment_Plan', 'ReviewStatus') IS NULL
    ALTER TABLE Risk_Treatment_Plan ADD ReviewStatus nvarchar(100) NULL;
IF OBJECT_ID('dbo.Risk_Treatment_Plan', 'U') IS NOT NULL AND COL_LENGTH('dbo.Risk_Treatment_Plan', 'ReviewComment') IS NULL
    ALTER TABLE Risk_Treatment_Plan ADD ReviewComment nvarchar(max) NULL;
IF OBJECT_ID('dbo.Risk_Treatment_Plan', 'U') IS NOT NULL AND COL_LENGTH('dbo.Risk_Treatment_Plan', 'ReviewedBy') IS NULL
    ALTER TABLE Risk_Treatment_Plan ADD ReviewedBy nvarchar(200) NULL;
IF OBJECT_ID('dbo.Risk_Treatment_Plan', 'U') IS NOT NULL AND COL_LENGTH('dbo.Risk_Treatment_Plan', 'ReviewedAt') IS NULL
    ALTER TABLE Risk_Treatment_Plan ADD ReviewedAt datetime2 NULL;
GO

-- Widen ReviewStatus on PRE-EXISTING databases (fresh installs get nvarchar(100) from the
-- CREATE above, and the guarded ADD block now also creates it at 100). Headroom (v0.14) so a
-- future verdict value can never repeat the StageStatus truncation freeze documented earlier
-- in this file. Same conventions as that widen: guard schema-qualified, BETWEEN skips
-- nvarchar(max) (-1) so a max column can never be narrowed, NULL restated because ALTER COLUMN
-- resets nullability, metadata-only, own GO batch. ReviewStatus sits in no index key or
-- filtered-index predicate (both Risk_Treatment_Plan indexes filter on Superseded only), so
-- there is no Msg 5074 risk.
IF EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
           WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = 'Risk_Treatment_Plan'
             AND COLUMN_NAME = 'ReviewStatus'
             AND CHARACTER_MAXIMUM_LENGTH BETWEEN 1 AND 99)
    ALTER TABLE dbo.Risk_Treatment_Plan ALTER COLUMN ReviewStatus nvarchar(100) NULL;
GO

-- Widen Status the same way (fresh installs get nvarchar(100) from the CREATE above). Same
-- conventions as the two widens above; NOT NULL restated because ALTER COLUMN resets
-- nullability. Status is in no index key or filtered-index predicate (both indexes filter on
-- Superseded only), so there is no Msg 5074 risk.
IF EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
           WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = 'Risk_Treatment_Plan'
             AND COLUMN_NAME = 'Status'
             AND CHARACTER_MAXIMUM_LENGTH BETWEEN 1 AND 99)
    ALTER TABLE dbo.Risk_Treatment_Plan ALTER COLUMN Status nvarchar(100) NOT NULL;
GO

-- Adds the machine-readable terminal reason for pre-2026-08-11 databases.
-- DEPLOY THIS BEFORE THE CODE: unlike every earlier treatment change this one is NOT safe in the
-- other order — the worker writes ErrorReason on every failure path, so code-before-DB fails every
-- plan. Run this script, then deploy.
IF OBJECT_ID('dbo.Risk_Treatment_Plan', 'U') IS NOT NULL AND COL_LENGTH('dbo.Risk_Treatment_Plan', 'ErrorReason') IS NULL
    ALTER TABLE Risk_Treatment_Plan ADD ErrorReason nvarchar(max) NULL;
GO

-- Widen TreatmentStrategy / RiskLevel the same way as the two widens above (fresh installs
-- get nvarchar(100) from the CREATE; the guarded ADD above also creates RiskLevel at 100).
-- Same conventions: schema-qualified guard, BETWEEN skips nvarchar(max) (-1), nullability
-- restated per column, one GO batch each so a failure cannot silently skip the rest. Neither
-- is in an index key or filtered-index predicate (both indexes filter on Superseded only) —
-- no Msg 5074 risk. ErrorReason has its own to-max block below.
IF EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
           WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = 'Risk_Treatment_Plan'
             AND COLUMN_NAME = 'TreatmentStrategy'
             AND CHARACTER_MAXIMUM_LENGTH BETWEEN 1 AND 99)
    ALTER TABLE dbo.Risk_Treatment_Plan ALTER COLUMN TreatmentStrategy nvarchar(100) NOT NULL;
GO

IF EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
           WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = 'Risk_Treatment_Plan'
             AND COLUMN_NAME = 'RiskLevel'
             AND CHARACTER_MAXIMUM_LENGTH BETWEEN 1 AND 99)
    ALTER TABLE dbo.Risk_Treatment_Plan ALTER COLUMN RiskLevel nvarchar(100) NULL;
GO

-- ErrorReason goes all the way to nvarchar(max) (user request): fire on ANY bounded width
-- (-1 = already max). Values are short reason codes stored in-row, so this costs nothing at
-- rest; the column is in no index (nvarchar(max) could not be an index key anyway). The
-- Verify width row for ErrorReason stays — the width check skips max columns and re-arms if
-- the column is ever re-narrowed.
IF EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
           WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = 'Risk_Treatment_Plan'
             AND COLUMN_NAME = 'ErrorReason'
             AND CHARACTER_MAXIMUM_LENGTH <> -1)
    ALTER TABLE dbo.Risk_Treatment_Plan ALTER COLUMN ErrorReason nvarchar(max) NULL;
GO

-- One-time backfill so rows that failed before the column existed are switchable too. Idempotent
-- (the ErrorReason IS NULL predicate means a re-run touches nothing) and it is the LAST legitimate
-- read of these message literals — after this the reason code carries the meaning, not the English.
-- 'timed_out' is absent by construction: it is a read-time projection and is never stored.
-- The enqueue match is a LIKE on the ASCII prefix, NOT the full stored literal: that message
-- contains an em dash, and legacy sqlcmd reads a BOM-less UTF-8 file in the ANSI codepage,
-- mangling the dash client-side — an equality match would then silently fall to the catch-all
-- (and the ErrorReason IS NULL guard would make that misfile permanent).
IF COL_LENGTH('dbo.Risk_Treatment_Plan', 'ErrorReason') IS NOT NULL
    UPDATE Risk_Treatment_Plan
    SET    ErrorReason = CASE
               WHEN ErrorMessage = N'cancelled by user' THEN N'cancelled'
               WHEN ErrorMessage LIKE N'failed to queue generation%' THEN N'enqueue_failed'
               ELSE N'generation_failed'   -- the historical catch-all for everything else
           END
    WHERE  Status = 'ERROR' AND ErrorReason IS NULL;
GO

-- Renames the review verdict 'changes_requested' -> 'rejected'. Idempotent (a re-run matches
-- nothing). Safe in either order relative to the code deploy — stored values are read back as
-- raw text, never 500 — but run it WITH the deploy so review_status=rejected filters match
-- pre-rename rows. Audit DetailJSON history keeps the old literal: records as written.
IF COL_LENGTH('dbo.Risk_Treatment_Plan', 'ReviewStatus') IS NOT NULL
    UPDATE Risk_Treatment_Plan SET ReviewStatus = N'rejected' WHERE ReviewStatus = N'changes_requested';
GO

-- Relaxes CrmRiskIdentificationID to nullable — unused since the request-body redesign.
IF COLUMNPROPERTY(OBJECT_ID('dbo.Risk_Treatment_Plan'), 'CrmRiskIdentificationID', 'AllowsNull') = 0
    ALTER TABLE Risk_Treatment_Plan ALTER COLUMN CrmRiskIdentificationID int NULL;
GO

-- ============================================================
-- SECTION 2 — Threat-library master tables now live in Threat_library.sql.
-- ============================================================

GO

-- ============================================================
-- SECTION 3 — TSG's own guard indexes
-- ============================================================

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Session_ActiveAsset' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
CREATE UNIQUE INDEX UX_Session_ActiveAsset ON Scenario_Session(EntityID, AssetID) WHERE SessionStatus = 'active';
-- One active session per (entity, asset).

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Session_IdempotencyKey' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
CREATE UNIQUE INDEX UX_Session_IdempotencyKey ON Scenario_Session(EntityID, IdempotencyKey) WHERE IdempotencyKey IS NOT NULL;
-- Retried POST /v1/sessions with the same key returns the same session.

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Session_Active' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
CREATE NONCLUSTERED INDEX IX_Session_Active ON Scenario_Session(SessionStatus) WHERE SessionStatus = 'active';

-- One active scenario per (session, subsystem, catalogue-threat, ScenarioNumber). Coexisting
-- scenario numbers are legal; a repeat at the SAME number collides (double-click guard).
-- Drops the old 2-column index first so re-running widens it.
IF EXISTS (SELECT 1 FROM sys.indexes i
           WHERE i.name = 'UX_Scenario_ActiveIdentity' AND i.object_id = OBJECT_ID('dbo.Threat_Scenario_Output')
           AND NOT EXISTS (SELECT 1 FROM sys.index_columns ic
                           JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
                           WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id
                           AND c.name = 'ScenarioNumber'))
    DROP INDEX UX_Scenario_ActiveIdentity ON Threat_Scenario_Output;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Scenario_ActiveIdentity' AND object_id = OBJECT_ID('dbo.Threat_Scenario_Output'))
CREATE UNIQUE INDEX UX_Scenario_ActiveIdentity ON Threat_Scenario_Output(SessionID, IdentityHash, ScenarioNumber) WHERE Superseded = 0;

-- One ACCEPTED scenario per (session, threat identity, ScenarioNumber). Accepted is decoupled
-- from Superseded (a reviewer may accept an older, superseded version), so the active-identity
-- index above no longer implies this rule — the database, not app code, is the arbiter.
-- IdentityHash IS NOT NULL: a NULL hash means identity unknown (pre-IdentityHash legacy rows) —
-- unknown identities are distinct scenarios, and SQL Server's NULLs-compare-equal unique
-- semantics would falsely collide two of them; those rows are covered by accept's app guard only.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Scenario_ActiveAccepted' AND object_id = OBJECT_ID('dbo.Threat_Scenario_Output'))
CREATE UNIQUE INDEX UX_Scenario_ActiveAccepted ON Threat_Scenario_Output(SessionID, IdentityHash, ScenarioNumber) WHERE Accepted = 1 AND IdentityHash IS NOT NULL;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_PromptLog_Session' AND object_id = OBJECT_ID('dbo.Prompt_Log'))
CREATE INDEX IX_PromptLog_Session ON Prompt_Log(SessionID, SubsystemID);

-- (SessionID, SubsystemID, Level) is the row's real identity — the whole CAS/lock design
-- assumes exactly one row per triple. CREATE FIRST, DROP SECOND: a failed CREATE (duplicate
-- rows already exist) then leaves the old index in place instead of leaving none at all.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_SubsystemStageState_SessionSubLevel' AND object_id = OBJECT_ID('dbo.Subsystem_Stage_State'))
CREATE UNIQUE INDEX UX_SubsystemStageState_SessionSubLevel ON Subsystem_Stage_State(SessionID, SubsystemID, Level);
GO

IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_SubsystemStageState_SessionSubLevel' AND object_id = OBJECT_ID('dbo.Subsystem_Stage_State'))
    AND EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SubsystemStageState_SessionSubLevel' AND object_id = OBJECT_ID('dbo.Subsystem_Stage_State'))
    DROP INDEX IX_SubsystemStageState_SessionSubLevel ON Subsystem_Stage_State;

-- IX_Session_CompletedByAsset dropped: built for a GET /assets/{id}/accepted-scenarios route
-- that never shipped (accepted scenarios are served per-session); no query reads it, it only
-- taxed Scenario_Session writes. Re-add it WITH that route, and query via the literal_execute
-- pattern (see dal.session_active) or the filtered predicate cannot serve the plan.
IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Session_CompletedByAsset' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
    DROP INDEX IX_Session_CompletedByAsset ON Scenario_Session;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_IdentifiedThreat_SessionSubActive' AND object_id = OBJECT_ID('dbo.Identified_Threat'))
CREATE INDEX IX_IdentifiedThreat_SessionSubActive ON Identified_Threat(SessionID, SubsystemID) WHERE Superseded = 0;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScopedThreat_SessionSubActive' AND object_id = OBJECT_ID('dbo.Scoped_Threat'))
CREATE INDEX IX_ScopedThreat_SessionSubActive ON Scoped_Threat(SessionID, SubsystemID) WHERE Superseded = 0;

-- Unfiltered on purpose: SQL Server can't match a filtered index against a parameterized
-- predicate, so Superseded is a trailing key column instead — keeps dal.threat_scores seeking.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScopedThreat_SessionActiveScores' AND object_id = OBJECT_ID('dbo.Scoped_Threat'))
CREATE INDEX IX_ScopedThreat_SessionActiveScores ON Scoped_Threat(SessionID, Superseded)
    INCLUDE (ThreatID, Score, ScopeRank);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioOutput_SessionSubActive' AND object_id = OBJECT_ID('dbo.Threat_Scenario_Output'))
CREATE INDEX IX_ScenarioOutput_SessionSubActive ON Threat_Scenario_Output(SessionID, SubsystemID) WHERE Superseded = 0;
-- Backs dal.active_scenario_rows. Not covering ScenarioJSON on purpose — that column holds
-- the whole scenario, so including it would duplicate the table into the index.

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioAudit_SessionSubEvent' AND object_id = OBJECT_ID('dbo.Scenario_Audit'))
CREATE INDEX IX_ScenarioAudit_SessionSubEvent ON Scenario_Audit(SessionID, SubsystemID, EventType, CreatedAt DESC);

-- "Show me every decision on this scenario, newest first." Filtered so it costs nothing for the
-- session/subsystem rows that carry no OutputID, which is the overwhelming majority of the ledger.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioAudit_Output' AND object_id = OBJECT_ID('dbo.Scenario_Audit'))
    AND COL_LENGTH('dbo.Scenario_Audit', 'OutputID') IS NOT NULL
    EXEC('CREATE INDEX IX_ScenarioAudit_Output ON Scenario_Audit(OutputID, CreatedAt DESC) WHERE OutputID IS NOT NULL');
-- Speeds up dal.latest_next_set_outcome, polled on every status check. Not in
-- invariants.REQUIRED_INDEXES: that list is for correctness, not performance.

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Session_EntityUser' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
CREATE INDEX IX_Session_EntityUser ON Scenario_Session(EntityID, UserID) INCLUDE (SessionStatus);
-- GET /v1/users/{user_id}/scenarios and /v1/entities/{entity_id}/scenarios hot path.
-- Unfiltered: those routes query all three session statuses.

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Session_PromotionFailed' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
CREATE INDEX IX_Session_PromotionFailed ON Scenario_Session(PromotionFailedAt) WHERE PromotionFailedAt IS NOT NULL;
-- Backs the promotion-retry sweep and the admin GET /v1/tsg/sessions/promotions list — the
-- failed set is always a tiny fraction of all sessions, so this stays a narrow lookup, never a
-- full table scan, regardless of how large Scenario_Session grows.

-- One active treatment plan per scenario — the concurrent-POST race arbiter (the losing
-- INSERT hits this and surfaces as 409 generation_in_progress).
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_TreatmentPlan_ActiveOutput' AND object_id = OBJECT_ID('dbo.Risk_Treatment_Plan'))
CREATE UNIQUE INDEX UX_TreatmentPlan_ActiveOutput ON Risk_Treatment_Plan(OutputID) WHERE Superseded = 0;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_TreatmentPlan_SessionActive' AND object_id = OBJECT_ID('dbo.Risk_Treatment_Plan'))
CREATE INDEX IX_TreatmentPlan_SessionActive ON Risk_Treatment_Plan(SessionID) WHERE Superseded = 0;

-- Regeneration-history reads (?include_superseded=true on the single-plan GET and the session
-- board). The two indexes above are filtered Superseded = 0 and serve no Superseded = 1
-- predicate, so without this every history read scans the whole plan table — a cost that grows
-- with every plan ever generated, tenant-wide. Seeks by SessionID (board form) or
-- SessionID+OutputID (single-plan form); CreatedAt keyed for the newest-first ORDER BY.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_TreatmentPlan_SessionHistory' AND object_id = OBJECT_ID('dbo.Risk_Treatment_Plan'))
CREATE INDEX IX_TreatmentPlan_SessionHistory ON Risk_Treatment_Plan(SessionID, OutputID, CreatedAt) WHERE Superseded = 1;

-- ============================================================
-- SECTION 4 — Threat-library guard indexes now live in Threat_library.sql.
-- ============================================================

-- ============================================================
-- SECTION 5 — removed 2026-08-09. Used to ALTER platform tables
-- (ctm_scan_entity, onboarding_supporting_systems); TSG is read-only there
-- now. Missing-column checks moved to TSG_Preflight.sql.
-- ============================================================

-- ============================================================
-- Config_Tuning: runtime overrides for app/core/tuning.py::TUNABLE_KEYS.
-- Empty table = config-only behaviour (no-op rollout).
-- ============================================================
IF OBJECT_ID('dbo.Config_Tuning', 'U') IS NULL
CREATE TABLE Config_Tuning (
    TuningID        int            NOT NULL IDENTITY(1,1) CONSTRAINT PK_Config_Tuning PRIMARY KEY,
    TuningKey       nvarchar(100)  NOT NULL CONSTRAINT UQ_Config_Tuning_Key UNIQUE,
    TuningValue     nvarchar(100)  NOT NULL,
    ValueType       nvarchar(100)   NOT NULL CONSTRAINT CK_Config_Tuning_ValueType CHECK (ValueType IN ('float', 'int')),
    EmbeddingModel  nvarchar(200)  NULL,
    CreateDate      datetime2      NULL,
    CreatedBy       nvarchar(200)  NULL,
    UpdateDate      datetime2      NULL,
    UpdatedBy       nvarchar(200)  NULL,
    IsActive        bit            NOT NULL CONSTRAINT DF_Config_Tuning_IsActive DEFAULT 1,
    IsDeleted       bit            NOT NULL CONSTRAINT DF_Config_Tuning_IsDeleted DEFAULT 0
);

GO

-- ============================================================
-- API_Client — API-key authentication for the header auth model (app/api/deps.get_principal).
-- TSG-owned. One row per caller (today: the Shield backend). The secret is NEVER stored, only
-- its SHA-256 hex (KeyHash). SHA-256, not bcrypt: the secret is a 32-byte RANDOM value
-- (python -c "import secrets; print(secrets.token_hex(32))"), so there is no dictionary to
-- stretch. Several Active rows may coexist for make-before-break rotation; revoke = one UPDATE.
-- Seed a key:  compute the hash in PYTHON (UTF-8), then insert the literal. Do NOT use HASHBYTES
--              in SQL: given a parameter or an N'...' literal it hashes UTF-16 and never matches
--              the app's UTF-8 SHA-256 (silent 401s).
--                python -c "import hashlib,secrets; s=secrets.token_hex(32); print(s, hashlib.sha256(s.encode()).hexdigest())"
--              INSERT INTO API_Client (ClientID, KeyHash, Name, Module) VALUES ('shield-prod', '<keyhash>', 'Shield', 'tsg');
-- Module scopes a key to ONE module ('tsg', 'chatbot', ...): a key authenticates only for its own
-- Module, so a leaked key is contained to one module. Default 'tsg' applies if a manual INSERT
-- omits Module (the app always sets it explicitly — dal.create_api_client).
-- ============================================================
IF OBJECT_ID('dbo.API_Client', 'U') IS NULL
CREATE TABLE API_Client (
    ClientID    nvarchar(100) NOT NULL CONSTRAINT PK_API_Client PRIMARY KEY,
    KeyHash     nvarchar(100)  NOT NULL,
    Name        nvarchar(200) NOT NULL,
    Module      nvarchar(100)  NOT NULL CONSTRAINT DF_API_Client_Module   DEFAULT 'tsg',
    Active      bit           NOT NULL CONSTRAINT DF_API_Client_Active    DEFAULT 1,
    -- Audit trail (provenance only; the auth path reads none of these):
    CreatedAt   datetime2(3)  NOT NULL CONSTRAINT DF_API_Client_CreatedAt DEFAULT SYSUTCDATETIME(),
    CreatedBy   nvarchar(200) NULL,   -- who provisioned the key
    RevokedAt   datetime2(3)  NULL,   -- when it was deactivated
    RevokedBy   nvarchar(200) NULL    -- who revoked it
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_API_Client_KeyHash' AND object_id = OBJECT_ID('dbo.API_Client'))
CREATE UNIQUE INDEX UX_API_Client_KeyHash ON API_Client (KeyHash) WHERE Active = 1;

GO

-- Verify
SELECT 'RCSI' AS what, CAST(is_read_committed_snapshot_on AS int) AS ok FROM sys.databases WHERE database_id = DB_ID()
UNION ALL
SELECT TABLE_NAME, 1 FROM INFORMATION_SCHEMA.TABLES
WHERE TABLE_SCHEMA = 'dbo' AND TABLE_TYPE = 'BASE TABLE' AND TABLE_NAME IN (
    'Scenario_Session','Subsystem_Stage_State','Identified_Threat','Identified_Duplicate_Threat',
    'Scoped_Threat','Threat_Scenario_Output','Threat_Library_Import_Run','Scenario_Audit',
    'Prompt_Log','Threat_Candidate_Review','Risk_Treatment_Plan','Config_Tuning','API_Client');


-- ---------------------------------------------------------------------------
-- Scenario_Library - generated scenario text, reused across every asset of one PROFILE
-- ---------------------------------------------------------------------------
-- Control_Library already proves the model: 1,288 pre-written rows, reused by everyone, zero
-- AI. A threat scenario is content too, not a per-request computation, so generating the same
-- text again for the 400th pumping station of the same design is pure waste - and output
-- tokens, not call count, are the bill.
--
-- ProfileKey is a sha256 of CLASSIFICATION CODES ONLY (sector scope, asset type, sub-sector,
-- and each supporting system's technology/criticality in order) - never a name, an entity id
-- or free text. That is what makes a row here safe to serve across tenants while the asset
-- data it was derived from stays isolated. See app/pipeline/scenario_profile.py.
--
-- SourceNamesJSON is the ordered [asset, system 1, system 2, ...] name list that was live when
-- the text was written. Serving the row to a different asset swaps those names positionally,
-- and the swap REFUSES rather than guesses if any source name survives it - so a mismatch
-- costs a regeneration, never a register naming the wrong customer's system.
--
-- PromptVersion and ModelID are the invalidation key: a row is only served back to a session
-- running the same prompt and model that produced it.
IF OBJECT_ID('dbo.Scenario_Library', 'U') IS NULL
CREATE TABLE Scenario_Library (
    ScenarioLibraryID  uniqueidentifier NOT NULL CONSTRAINT PK_Scenario_Library PRIMARY KEY,
    ProfileKey         nvarchar(100)  NOT NULL,   -- sha256 hex; classification codes only
    ThreatCatalogueID  int            NOT NULL,   -- library threats only: a novel threat has no stable identity to key on
    ScenarioNumber     int            NOT NULL CONSTRAINT DF_ScenarioLibrary_ScenarioNumber DEFAULT 1,
    ScenarioJSON       nvarchar(max)  NOT NULL,
    SourceNamesJSON    nvarchar(max)  NOT NULL,   -- ordered [asset, system 1, ...] at write time
    PromptVersion      nvarchar(100)  NULL,
    ModelID            nvarchar(200)  NULL,
    CreatedAt          datetime2      NULL
);

-- The natural key. UNIQUE so a race between two sessions of the same profile cannot leave two
-- competing texts for one (profile, threat, scenario number) - the loser's INSERT fails and is
-- discarded, which is correct: either text was valid, and the session keeps its own copy
-- regardless.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ScenarioLibrary_Natural' AND object_id = OBJECT_ID('dbo.Scenario_Library'))
CREATE UNIQUE INDEX UX_ScenarioLibrary_Natural
    ON Scenario_Library(ProfileKey, ThreatCatalogueID, ScenarioNumber);


-- ---------------------------------------------------------------------------
-- Widen every remaining short nvarchar column to nvarchar(100)
-- ---------------------------------------------------------------------------
-- A blanket floor, not a per-column judgement. Narrow columns sized to today's longest value are
-- a standing trap: the value that outgrows one is usually a one-line enum or vocabulary change,
-- and the failure is invisible because every SHORTER value still inserts - the application looks
-- healthy until the first write of the new value fails, mid-workflow, with no obvious cause.
--
-- nvarchar is variable-length, so this costs nothing: a 12-character value occupies 12 characters
-- whatever the declared maximum. Index keys are unaffected in practice - the widest key here
-- reaches 220 bytes against a 1700-byte limit.
--
-- Each is guarded on the CURRENT width, so re-running is a no-op and a site already at 100 skips.

IF OBJECT_ID('dbo.Scenario_Session', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Session', 'Mode') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Scenario_Session'), 'Mode', 'CharMaxLen') < 100
    ALTER TABLE Scenario_Session ALTER COLUMN Mode nvarchar(100) NOT NULL;
IF OBJECT_ID('dbo.Threat_Scenario_Output', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario_Output', 'IdentityHash') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Threat_Scenario_Output'), 'IdentityHash', 'CharMaxLen') < 100
    ALTER TABLE Threat_Scenario_Output ALTER COLUMN IdentityHash nvarchar(100) NULL;
IF OBJECT_ID('dbo.Threat_Candidate_Review', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Candidate_Review', 'Status') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Threat_Candidate_Review'), 'Status', 'CharMaxLen') < 100
    ALTER TABLE Threat_Candidate_Review ALTER COLUMN Status nvarchar(100) NOT NULL;
IF OBJECT_ID('dbo.API_Client', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.API_Client', 'KeyHash') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.API_Client'), 'KeyHash', 'CharMaxLen') < 100
    ALTER TABLE API_Client ALTER COLUMN KeyHash nvarchar(100) NOT NULL;
IF OBJECT_ID('dbo.API_Client', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.API_Client', 'Module') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.API_Client'), 'Module', 'CharMaxLen') < 100
    ALTER TABLE API_Client ALTER COLUMN Module nvarchar(100) NOT NULL;
