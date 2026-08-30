-- ============================================================================
-- TSG_Core — creates/updates TSG's own tables. Safe to re-run: enables RCSI once,
-- adds any missing table/column/index, never touches row data.
--
-- Threat-library masters live in Threat_library.sql; Threat_Scenario_Control_Map
-- in Control_library.sql. Platform tables (ctm_scan_*, onboarding_*) are read-only
-- to TSG. No FOREIGN KEYs, by design (SDD §7.7). Uses GO batches.
--
-- Keep in lockstep with models.py: a new column needs a CREATE TABLE entry
-- (fresh DB) AND a guarded ALTER below it (existing DB).
--
-- RUN: paste the whole file into SSMS (F5) and read the Messages pane, or
--   sqlcmd -b -S <server> -d <database> -E -i TSG_Core.sql
-- (-b exits non-zero on any SQL error instead of burying it mid-output.)
--
-- *** HARD CUTOVER *** This run renames Threat_Scenario_Output -> Threat_Scenario
-- with its PK, CHECK, DEFAULT and three indexes. An old and a new application
-- build CANNOT both run against one database, and there is no rolling deploy.
-- STOP the API and the Celery workers, run this script, run 6. TSG_Verify.sql,
-- deploy the matching code, then start.
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

-- ---------------------------------------------------------------------------
-- Threat_Scenario_Output -> Threat_Scenario, plus the six object names reading "Output"
-- ---------------------------------------------------------------------------
-- POSITION IS LOAD-BEARING: this block MUST run before every CREATE TABLE, ADD
-- CONSTRAINT and CREATE INDEX below. Those are guarded on the NEW names, so run
-- against a pre-rename database each guard would see its object missing and
-- CREATE A SECOND ONE -- an empty Threat_Scenario beside the populated old table
-- -- after which the rename fails Msg 15335 and the app binds the empty one.
--
-- Guarded both ways per object: fires once, no-op on re-run and on fresh installs.
-- sp_rename is metadata only; its "Caution: Changing any part of an object name"
-- notice is informational, not an error. The NEW name is always BARE -- passing
-- 'dbo.X' does not fail, it creates an object literally called "dbo.X".

-- 1. The table FIRST, so every guard after it has one address to test.
IF OBJECT_ID('dbo.Threat_Scenario_Output', 'U') IS NOT NULL
    AND OBJECT_ID('dbo.Threat_Scenario', 'U') IS NULL
    EXEC sp_rename 'dbo.Threat_Scenario_Output', 'Threat_Scenario', 'OBJECT';

-- 2. Constraints. OBJECT_ID finds these -- PK, CHECK and DEFAULT are rows in
--    sys.objects. Renaming the PK constraint renames its backing index with it,
--    so there is deliberately NO separate INDEX rename for the primary key.
IF OBJECT_ID('dbo.PK_Threat_Scenario_Output', 'PK') IS NOT NULL
    AND OBJECT_ID('dbo.PK_Threat_Scenario', 'PK') IS NULL
    EXEC sp_rename 'dbo.PK_Threat_Scenario_Output', 'PK_Threat_Scenario', 'OBJECT';

IF OBJECT_ID('dbo.CK_ScenarioOutput_DecisionExclusive', 'C') IS NOT NULL
    AND OBJECT_ID('dbo.CK_Scenario_DecisionExclusive', 'C') IS NULL
    EXEC sp_rename 'dbo.CK_ScenarioOutput_DecisionExclusive', 'CK_Scenario_DecisionExclusive', 'OBJECT';

IF OBJECT_ID('dbo.DF_ScenarioOutput_ScenarioNumber', 'D') IS NOT NULL
    AND OBJECT_ID('dbo.DF_Scenario_ScenarioNumber', 'D') IS NULL
    EXEC sp_rename 'dbo.DF_ScenarioOutput_ScenarioNumber', 'DF_Scenario_ScenarioNumber', 'OBJECT';

-- 3. Indexes. OBJECT_ID CANNOT guard these: an index is not a row in sys.objects,
--    so the guard would be dead code that silently never fires. sys.indexes.name
--    is unique per TABLE, so the object_id predicate is load-bearing. @objname is
--    the three-part 'schema.table.index'; the new name stays bare.
IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioOutput_SessionSubActive'
           AND object_id = OBJECT_ID('dbo.Threat_Scenario'))
    AND NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Scenario_SessionSubActive'
                    AND object_id = OBJECT_ID('dbo.Threat_Scenario'))
    EXEC sp_rename 'dbo.Threat_Scenario.IX_ScenarioOutput_SessionSubActive',
                   'IX_Scenario_SessionSubActive', 'INDEX';

-- On Scenario_Audit, not the renamed table: "Output" here named the id it indexes.
IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioAudit_Output'
           AND object_id = OBJECT_ID('dbo.Scenario_Audit'))
    AND NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioAudit_Scenario'
                    AND object_id = OBJECT_ID('dbo.Scenario_Audit'))
    EXEC sp_rename 'dbo.Scenario_Audit.IX_ScenarioAudit_Output',
                   'IX_ScenarioAudit_Scenario', 'INDEX';

-- Also registered in invariants.REQUIRED_INDEXES and TSG_Verify.sql section 2 --
-- all three must carry the new name together, or the app refuses to boot.
IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_TreatmentPlan_ActiveOutput'
           AND object_id = OBJECT_ID('dbo.Risk_Treatment_Plan'))
    AND NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_TreatmentPlan_ActiveScenario'
                    AND object_id = OBJECT_ID('dbo.Risk_Treatment_Plan'))
    EXEC sp_rename 'dbo.Risk_Treatment_Plan.UX_TreatmentPlan_ActiveOutput',
                   'UX_TreatmentPlan_ActiveScenario', 'INDEX';

GO

-- ============================================================
-- SECTION 1 — TSG's own tables
-- ============================================================

IF OBJECT_ID('dbo.Scenario_Session', 'U') IS NULL
CREATE TABLE Scenario_Session (
    SessionID             uniqueidentifier NOT NULL CONSTRAINT PK_Scenario_Session PRIMARY KEY,
    TenantID              nvarchar(200)  NOT NULL,
    EntityID              nvarchar(200)  NOT NULL,         
    UserID                nvarchar(200)  NULL,
    AssetName             nvarchar(300)  NOT NULL,
    AssetID               nvarchar(200)  NOT NULL,          
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

-- Cancellation attribution. Independently guarded per column — see the RiskLevel
-- block below on why a shared guard can skip later columns silently.
IF OBJECT_ID('dbo.Scenario_Session', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Session', 'CancelledAt') IS NULL
    ALTER TABLE Scenario_Session ADD CancelledAt datetime2 NULL;

IF OBJECT_ID('dbo.Scenario_Session', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Session', 'CancelledBy') IS NULL
    ALTER TABLE Scenario_Session ADD CancelledBy nvarchar(200) NULL;

GO

-- Widen StageStatus on PRE-EXISTING databases; fresh installs get nvarchar(100)
-- from the CREATE above. 'SCENARIOS_AWAITING_DECISION' (27 chars) overflowed the
-- original nvarchar(20) and froze sessions at the review barrier.
-- SessionStatus and CurrentStage are deliberately NOT altered: SessionStatus is in
-- two FILTERED index predicates, where an in-place ALTER COLUMN raises Msg 5074.
-- Guard is schema-qualified and skips nvarchar(max) (-1); NOT NULL restated
-- because ALTER COLUMN resets nullability. Metadata-only, but takes a brief SCH-M
-- lock on a hot table — prefer a quiet window. Own GO batch, so a failure here
-- cannot silently skip the rest of the migration.
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

-- Same widening for Status, which takes the same StageStatus values. Level is NOT
-- altered: it is a key of UX_SubsystemStageState_SessionSubLevel and needs no fix.
-- Same guard posture as the Scenario_Session block above.
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
    Description        nvarchar(200) NULL,   -- AI description OF THE THREAT; copied to crm_threat_risk_register.threat_scenario on promotion
    ThreatCategoryID   int           NULL,   -- resolved category id (grounding already computes it); ThreatCategory text kept for display
    ThreatActorsJSON   nvarchar(max) NULL,
    LibraryThreatType  nvarchar(300) NULL,
    LibraryThreatName  nvarchar(500) NULL,
    ThreatTypeID       int           NULL,
    ThreatCatalogueID  int           NULL,   -- Threat_Catalogue.ThreatCatalogueID; set <=> GroundingStatus verified
    IsThreatAIGenerated bit          NOT NULL DEFAULT 0, -- immutable provenance: 1 = NOT in the catalogue at identification (invented by the AI); promotion never flips it
    IsThreatTypeAIGenerated bit      NOT NULL DEFAULT 0, -- same rule, type-level: 1 = ThreatTypeID was NOT a library match at identification; separate fact from IsAIGenerated, promotion never flips it either
    GroundingStatus    nvarchar(100)  NOT NULL,
    GroundingScore     float         NULL,
    Superseded         int           NOT NULL,
    CreatedAt          datetime2     NULL
);

-- Audit-only trail of AI-proposed threats DROPPED as duplicates during
-- find_threats. Never read by scoping or scenario generation.
-- DuplicateOfThreatID is best-effort: set for semantic matches, NULL for an
-- identity-hash match against a PRIOR round, where only the hash is available.
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
-- Without this, "which threats were dropped in which session" is a full scan. No
-- filter predicate: every row here is permanent audit history, never superseded.

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

-- Pre-existing NULL rows: run scripts/backfill_rejection_kind.sql once.
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

-- Description carries the AI's wording into crm_threat_risk_register.threat_scenario;
-- ThreatCategoryID stops consumers re-deriving a category id grounding already resolved.
IF OBJECT_ID('dbo.Identified_Threat', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Identified_Threat', 'Description') IS NULL
    ALTER TABLE Identified_Threat ADD Description nvarchar(200) NULL;

IF OBJECT_ID('dbo.Identified_Threat', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Identified_Threat', 'ThreatCategoryID') IS NULL
    ALTER TABLE Identified_Threat ADD ThreatCategoryID int NULL;

-- The library identity (Threat_Catalogue row matched at Stage 1).
IF OBJECT_ID('dbo.Identified_Threat', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Identified_Threat', 'ThreatCatalogueID') IS NULL
    ALTER TABLE Identified_Threat ADD ThreatCatalogueID int NULL;

-- Legacy name here on purpose: this guard is "does an ancient DB have the column AT ALL",
-- for a deployment that predates IsAIGenerated existing. The rename block further down
-- (positioned AFTER this, per this file's own POSITION IS LOAD-BEARING rule) converts
-- whatever this leaves behind -- freshly-added or already-present -- to IsThreatAIGenerated.
-- Renaming this guard's own target to the NEW name would let it fire on an existing DB that
-- already has IsAIGenerated with real data, adding a SECOND, freshly-defaulted column before
-- the rename ever runs and silently orphaning the real history in the old one.
IF OBJECT_ID('dbo.Identified_Threat', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Identified_Threat', 'IsAIGenerated') IS NULL
    AND COL_LENGTH('dbo.Identified_Threat', 'IsThreatAIGenerated') IS NULL
    ALTER TABLE Identified_Threat ADD IsAIGenerated bit NOT NULL DEFAULT 0;

IF OBJECT_ID('dbo.Identified_Threat', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Identified_Threat', 'IsThreatTypeAIGenerated') IS NULL
    ALTER TABLE Identified_Threat ADD IsThreatTypeAIGenerated bit NOT NULL DEFAULT 0;

IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NULL
CREATE TABLE Threat_Scenario (
    ScenarioID           uniqueidentifier NOT NULL CONSTRAINT PK_Threat_Scenario PRIMARY KEY,
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
    ScenarioNumber       int           NOT NULL CONSTRAINT DF_Scenario_ScenarioNumber DEFAULT 1,  -- 1 = original, 2+ = "generate next set" alternates
    ReplacesScenarioID   uniqueidentifier NULL,   -- ScenarioID this row replaced; NULL for first-run/variant rows
    GenerationEpoch      int           NOT NULL,
    ErrorMessage         nvarchar(max) NULL,
    CreatedAt            datetime2     NULL,
    ControlsMappedAt     datetime2     NULL,  -- Step-4 attempt stamp; NULL = not yet tried
    -- Per-scenario review decision; NULL/NULL = pending. Nullable columns rather
    -- than a status value because Status is the GENERATION outcome and is
    -- load-bearing in the accept predicates. Mutually exclusive with Accepted=1.
    RejectedAt           datetime2     NULL,
    RejectedBy           nvarchar(200) NULL
);

-- Adds ControlsMappedAt for pre-Step-4 databases.
IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario', 'ControlsMappedAt') IS NULL
    ALTER TABLE Threat_Scenario ADD ControlsMappedAt datetime2 NULL;

-- Adds ScenarioNumber for pre-2026-07-29 databases.
IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario', 'ScenarioNumber') IS NULL
    ALTER TABLE Threat_Scenario ADD ScenarioNumber int NOT NULL CONSTRAINT DF_Scenario_ScenarioNumber DEFAULT 1;

-- Adds ReplacesOutputID for pre-2026-07-30 databases. Legacy rows simply read as originals.
IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario', 'ReplacesOutputID') IS NULL
    ALTER TABLE Threat_Scenario ADD ReplacesOutputID uniqueidentifier NULL;

-- Adds the per-scenario review decision for pre-2026-08-23 databases. Legacy rows read as
-- pending, which is correct: nobody recorded a rejection for them.
IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario', 'RejectedAt') IS NULL
    ALTER TABLE Threat_Scenario ADD RejectedAt datetime2 NULL;

IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario', 'RejectedBy') IS NULL
    ALTER TABLE Threat_Scenario ADD RejectedBy nvarchar(200) NULL;

-- The ACCEPT half of the decision attribution. Legacy rows read NULL; no backfill.
-- Separately guarded per column: a shared guard would let a re-run see the first
-- column present and skip the second. CK_Scenario_DecisionExclusive needs no
-- change — AcceptedAt is only ever set where Accepted = 1.
IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario', 'AcceptedAt') IS NULL
    ALTER TABLE Threat_Scenario ADD AcceptedAt datetime2 NULL;

IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario', 'AcceptedBy') IS NULL
    ALTER TABLE Threat_Scenario ADD AcceptedBy nvarchar(200) NULL;

-- Adds ScenarioSource for pre-scenario-library databases. NULL reads as "generated for this
-- asset", which is what every legacy row is.
IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario', 'ScenarioSource') IS NULL
    ALTER TABLE Threat_Scenario ADD ScenarioSource nvarchar(100) NULL;

-- A scenario cannot be both accepted and rejected. Enforced in the DATABASE
-- because accept and reject are independent routes reachable at any time, so the
-- row itself is the only place both orderings meet. Legacy rows all read pending,
-- so the constraint holds for them by construction.
IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario', 'RejectedAt') IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM sys.check_constraints
                    WHERE name = 'CK_Scenario_DecisionExclusive')
    ALTER TABLE Threat_Scenario ADD CONSTRAINT CK_Scenario_DecisionExclusive
        CHECK (RejectedAt IS NULL OR Accepted = 0);

-- Per-scenario decision trail for pre-2026-08-23 databases. Legacy rows read as NULL, which is
-- correct: they were session-scoped events and belong to no single scenario.
IF OBJECT_ID('dbo.Scenario_Audit', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Audit', 'OutputID') IS NULL
    ALTER TABLE Scenario_Audit ADD OutputID uniqueidentifier NULL;

-- The PLAN a treatment event concerns. A real column, not a DetailJSON key,
-- because an indexed column can be seeked and a JSON blob cannot. Legacy rows
-- read NULL, correctly: session- and scenario-scoped events belong to no plan.
IF OBJECT_ID('dbo.Scenario_Audit', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Audit', 'PlanID') IS NULL
    ALTER TABLE Scenario_Audit ADD PlanID uniqueidentifier NULL;

-- MANDATORY one-time backfill. Generation now COMPLETES a session at its review
-- barrier, which is what releases the asset. Sessions created before that change
-- sit at active+REVIEW and nothing will ever complete them — left alone they hold
-- their asset open forever. Idempotent: the WHERE matches nothing on a re-run.
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
-- Closed vocabularies (app/core/enums.py), sized to the longest member at the
-- time. A longer member added later silently outgrows its column: every SHORTER
-- value still inserts, so the application looks healthy until the first write of
-- the new one. nvarchar(100) is far past any current member and costs nothing.
-- Guarded on the CURRENT width, so re-running is a no-op.

-- SQL Server refuses ALTER COLUMN while an index depends on the column. Dropped
-- here, recreated by the guarded CREATE INDEX further down this same script.
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
IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario', 'Status') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Threat_Scenario'), 'Status', 'CharMaxLen') < 100
    ALTER TABLE Threat_Scenario ALTER COLUMN Status nvarchar(100) NOT NULL;IF OBJECT_ID('dbo.Scenario_Audit', 'U') IS NOT NULL
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
    ALTER TABLE Prompt_Log ALTER COLUMN PromptVersion nvarchar(100) NOT NULL;IF OBJECT_ID('dbo.Config_Tuning', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Config_Tuning', 'ValueType') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Config_Tuning'), 'ValueType', 'CharMaxLen') < 100
    ALTER TABLE Config_Tuning ALTER COLUMN ValueType nvarchar(100) NOT NULL;

-- ---------------------------------------------------------------------------
-- Rename Scenario_Session.TuningJSON -> ScoringRulesSnapshotJSON
-- ---------------------------------------------------------------------------
-- The value is a SNAPSHOT frozen at session creation, so a mid-run Config_Tuning
-- edit cannot change how an in-flight session scores. "TuningJSON" read as "the
-- tuning config", which is exactly what it is not. sp_rename keeps the data in
-- place; guarded both ways, so it runs once.
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

-- ---------------------------------------------------------------------------
-- OutputID -> ScenarioID. The column identifies a SCENARIO; "output" named the
-- table it happened to live in, not the thing itself.
--
-- sp_rename keeps the data in place, and INDEXES FOLLOW AUTOMATICALLY -- SQL
-- Server stores index key references by column ID. The index NAMES are renamed by
-- the guarded block at the top of this file.
--
-- Guarded BOTH ways on every table: runs once, no-op afterwards, and on a fresh
-- install the CREATE TABLEs already declare ScenarioID. Order-independent -- each
-- guard tests its own table, so a table that does not exist yet is skipped.
IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario', 'OutputID') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario', 'ScenarioID') IS NULL
    EXEC sp_rename 'dbo.Threat_Scenario.OutputID', 'ScenarioID', 'COLUMN';

-- The self-reference: which scenario this one replaced. Renamed for the same reason, or the table
-- would carry ScenarioID beside ReplacesOutputID and reintroduce the inconsistency in one row.
IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario', 'ReplacesOutputID') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario', 'ReplacesScenarioID') IS NULL
    EXEC sp_rename 'dbo.Threat_Scenario.ReplacesOutputID', 'ReplacesScenarioID', 'COLUMN';

IF OBJECT_ID('dbo.Scenario_Audit', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Audit', 'OutputID') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Audit', 'ScenarioID') IS NULL
    EXEC sp_rename 'dbo.Scenario_Audit.OutputID', 'ScenarioID', 'COLUMN';

IF OBJECT_ID('dbo.Risk_Treatment_Plan', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Risk_Treatment_Plan', 'OutputID') IS NOT NULL
    AND COL_LENGTH('dbo.Risk_Treatment_Plan', 'ScenarioID') IS NULL
    EXEC sp_rename 'dbo.Risk_Treatment_Plan.OutputID', 'ScenarioID', 'COLUMN';

-- IsAIGenerated -> IsThreatAIGenerated: matches IsThreatTypeAIGenerated's naming (added
-- alongside it, same table) instead of leaving the older column the one inconsistent name.
IF OBJECT_ID('dbo.Identified_Threat', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Identified_Threat', 'IsAIGenerated') IS NOT NULL
    AND COL_LENGTH('dbo.Identified_Threat', 'IsThreatAIGenerated') IS NULL
    EXEC sp_rename 'dbo.Identified_Threat.IsAIGenerated', 'IsThreatAIGenerated', 'COLUMN';


-- One row per grounding-threshold calibration sweep, and the THRESHOLD STORE:
-- MatchTh on the latest Status='success' row for a model pair is what the pipeline
-- reads. Keyed by model pair because the cutoff is model-specific; a new pair has
-- no successful row and falls back to the static default.
IF OBJECT_ID('dbo.Grounding_Calibration_Run', 'U') IS NULL
CREATE TABLE Grounding_Calibration_Run (
    RunID              uniqueidentifier NOT NULL CONSTRAINT PK_Grounding_Calibration_Run PRIMARY KEY,
    JobID              nvarchar(100) NULL,        -- Celery task id
    Status             nvarchar(100) NOT NULL,    -- running | success | no_signal | failed
    StartedBy          nvarchar(200) NULL,        -- X-User-Id: CLAIMED, never verified on admin routes
    StartedByClient    nvarchar(200) NULL,        -- API_Client.ClientID: VERIFIED
    StartedAt          datetime2     NULL,
    FinishedAt         datetime2     NULL,
    EmbeddingModel     nvarchar(500) NULL,
    RerankerModel      nvarchar(500) NULL,
    Forced             bit           NOT NULL CONSTRAINT DF_GroundingCalibration_Forced DEFAULT 0,
    MatchTh            float         NULL,        -- the cutoff; NULL unless Status='success'
    Quality            float         NULL,        -- Youden's J at MatchTh, 0-1
    NegativesCount     int           NULL,
    PositivesCount     int           NULL,
    HighestNegative    float         NULL,
    LowestPositive     float         NULL,
    NearDuplicatesJSON nvarchar(max) NULL,        -- curation to-do list, not an error
    ErrorMessage       nvarchar(max) NULL
);
GO

-- WHICH cutoff judged each threat: 'calibrated' | 'static_default' | 'env_pinned'.
-- The three collide numerically, so without this the threats graded on a default
-- tuned for a DIFFERENT model pair cannot be found. Nullable so the seeds' explicit
-- column lists stay valid; never backfilled.
IF COL_LENGTH('dbo.Identified_Threat', 'GroundingThresholdOrigin') IS NULL
    ALTER TABLE Identified_Threat ADD GroundingThresholdOrigin nvarchar(100) NULL;
GO

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
    -- The scenario this event is ABOUT. NULL on session- and subsystem-scoped
    -- events. A column, not a DetailJSON key, because JSON cannot be indexed.
    ScenarioID       uniqueidentifier NULL,
    PlanID           uniqueidentifier NULL,
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

-- Risk Treatment Plan (docs/RISK_TREATMENT_PLAN_SDD.md). One row per generation attempt
-- on an accepted scenario; at most one active (Superseded=0) row per ScenarioID, enforced
-- by UX_TreatmentPlan_ActiveScenario below. Risk data (ratings, level, existing controls)
-- arrives in the request body — TSG reads no external risk tables.
IF OBJECT_ID('dbo.Risk_Treatment_Plan', 'U') IS NULL
CREATE TABLE Risk_Treatment_Plan (
    PlanID                  uniqueidentifier NOT NULL CONSTRAINT PK_Risk_Treatment_Plan PRIMARY KEY,
    SessionID               uniqueidentifier NOT NULL,
    ScenarioID              uniqueidentifier NOT NULL,  -- the accepted Threat_Scenario row
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
    ErrorReason             nvarchar(max) NULL          -- TreatmentOutcomeReason; NULL on COMPLETE.
                                                        -- Holds 5 of the enum's 6 values: 'timed_out'
                                                        -- has no writer, so do NOT CHECK for all six.
);
GO

-- Guarded PER COLUMN, not on RiskLevel alone: an abort between the ALTERs must
-- not let a re-run see RiskLevel present and skip the rest. ReviewComment /
-- ReviewedBy / ReviewedAt are in no TSG_Verify width check, so that miss would be
-- permanent and silent.
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
-- Cancellation attribution, the same gap the accept columns close on
-- Threat_Scenario. Independently guarded per column, for the reason above.
IF OBJECT_ID('dbo.Risk_Treatment_Plan', 'U') IS NOT NULL AND COL_LENGTH('dbo.Risk_Treatment_Plan', 'CancelledAt') IS NULL
    ALTER TABLE Risk_Treatment_Plan ADD CancelledAt datetime2 NULL;
IF OBJECT_ID('dbo.Risk_Treatment_Plan', 'U') IS NOT NULL AND COL_LENGTH('dbo.Risk_Treatment_Plan', 'CancelledBy') IS NULL
    ALTER TABLE Risk_Treatment_Plan ADD CancelledBy nvarchar(200) NULL;
GO

-- Widen ReviewStatus on PRE-EXISTING databases, so a future verdict value cannot
-- repeat the StageStatus truncation freeze above. Same conventions as that widen.
-- In no index key or filtered predicate, so there is no Msg 5074 risk.
IF EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
           WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = 'Risk_Treatment_Plan'
             AND COLUMN_NAME = 'ReviewStatus'
             AND CHARACTER_MAXIMUM_LENGTH BETWEEN 1 AND 99)
    ALTER TABLE dbo.Risk_Treatment_Plan ALTER COLUMN ReviewStatus nvarchar(100) NULL;
GO

-- Widen Status the same way. NOT NULL restated because ALTER COLUMN resets
-- nullability; in no index key or filtered predicate, so no Msg 5074 risk.
IF EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
           WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = 'Risk_Treatment_Plan'
             AND COLUMN_NAME = 'Status'
             AND CHARACTER_MAXIMUM_LENGTH BETWEEN 1 AND 99)
    ALTER TABLE dbo.Risk_Treatment_Plan ALTER COLUMN Status nvarchar(100) NOT NULL;
GO

-- DEPLOY THIS BEFORE THE CODE: the worker writes ErrorReason on every failure
-- path, so code-before-DB fails every plan. Run this script, then deploy.
IF OBJECT_ID('dbo.Risk_Treatment_Plan', 'U') IS NOT NULL AND COL_LENGTH('dbo.Risk_Treatment_Plan', 'ErrorReason') IS NULL
    ALTER TABLE Risk_Treatment_Plan ADD ErrorReason nvarchar(max) NULL;
GO

-- Widen TreatmentStrategy / RiskLevel the same way. One GO batch each, so a
-- failure cannot silently skip the rest. Neither is in an index key or filtered
-- predicate. ErrorReason has its own to-max block below.
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

-- ErrorReason goes to nvarchar(max): fires on ANY bounded width (-1 = already
-- max). Values are short reason codes stored in-row, so this costs nothing. The
-- Verify width row stays — that check skips max columns and re-arms if it is ever
-- re-narrowed.
IF EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
           WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = 'Risk_Treatment_Plan'
             AND COLUMN_NAME = 'ErrorReason'
             AND CHARACTER_MAXIMUM_LENGTH <> -1)
    ALTER TABLE dbo.Risk_Treatment_Plan ALTER COLUMN ErrorReason nvarchar(max) NULL;
GO

-- One-time backfill for rows that failed before the column existed. Idempotent via
-- the ErrorReason IS NULL predicate, and the LAST read of these message literals.
-- The enqueue match is a LIKE on the ASCII prefix, NOT the full literal: that
-- message contains an em dash and legacy sqlcmd mangles it in the ANSI codepage,
-- so an equality match would silently fall to the catch-all -- permanently.
IF COL_LENGTH('dbo.Risk_Treatment_Plan', 'ErrorReason') IS NOT NULL
    UPDATE Risk_Treatment_Plan
    SET    ErrorReason = CASE
               WHEN ErrorMessage = N'cancelled by user' THEN N'cancelled'
               WHEN ErrorMessage LIKE N'failed to queue generation%' THEN N'enqueue_failed'
               ELSE N'generation_failed'   -- the historical catch-all for everything else
           END
    WHERE  Status = 'ERROR' AND ErrorReason IS NULL;
GO

-- Renames the review verdict 'changes_requested' -> 'rejected'. Idempotent. Run it
-- WITH the code deploy so review_status=rejected filters match pre-rename rows.
-- Audit DetailJSON keeps the old literal: records as written.
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
           WHERE i.name = 'UX_Scenario_ActiveIdentity' AND i.object_id = OBJECT_ID('dbo.Threat_Scenario')
           AND NOT EXISTS (SELECT 1 FROM sys.index_columns ic
                           JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
                           WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id
                           AND c.name = 'ScenarioNumber'))
    DROP INDEX UX_Scenario_ActiveIdentity ON Threat_Scenario;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Scenario_ActiveIdentity' AND object_id = OBJECT_ID('dbo.Threat_Scenario'))
CREATE UNIQUE INDEX UX_Scenario_ActiveIdentity ON Threat_Scenario(SessionID, IdentityHash, ScenarioNumber) WHERE Superseded = 0;

-- One ACCEPTED scenario per (session, threat identity, ScenarioNumber). Accepted
-- is decoupled from Superseded, so the index above does not imply this rule.
-- IdentityHash IS NOT NULL because a NULL hash means identity unknown, and SQL
-- Server's NULLs-compare-equal semantics would falsely collide two of them.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Scenario_ActiveAccepted' AND object_id = OBJECT_ID('dbo.Threat_Scenario'))
CREATE UNIQUE INDEX UX_Scenario_ActiveAccepted ON Threat_Scenario(SessionID, IdentityHash, ScenarioNumber) WHERE Accepted = 1 AND IdentityHash IS NOT NULL;

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

-- Dropped: built for a route that never shipped, so it only taxed writes. Re-add
-- it WITH that route, querying via the literal_execute pattern (see
-- dal.session_active) or the filtered predicate cannot serve the plan.
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

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Scenario_SessionSubActive' AND object_id = OBJECT_ID('dbo.Threat_Scenario'))
CREATE INDEX IX_Scenario_SessionSubActive ON Threat_Scenario(SessionID, SubsystemID) WHERE Superseded = 0;
-- Backs dal.active_scenario_rows. Not covering ScenarioJSON on purpose — that column holds
-- the whole scenario, so including it would duplicate the table into the index.

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioAudit_SessionSubEvent' AND object_id = OBJECT_ID('dbo.Scenario_Audit'))
CREATE INDEX IX_ScenarioAudit_SessionSubEvent ON Scenario_Audit(SessionID, SubsystemID, EventType, CreatedAt DESC);

-- "Show me every decision on this scenario, newest first." Filtered so it costs nothing for the
-- session/subsystem rows that carry no ScenarioID, which is the overwhelming majority of the ledger.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioAudit_Scenario' AND object_id = OBJECT_ID('dbo.Scenario_Audit'))
    AND COL_LENGTH('dbo.Scenario_Audit', 'ScenarioID') IS NOT NULL
    EXEC('CREATE INDEX IX_ScenarioAudit_Scenario ON Scenario_Audit(ScenarioID, CreatedAt DESC) WHERE ScenarioID IS NOT NULL');

-- Same shape for the plan dimension, filtered for the same reason: session- and scenario-scoped
-- rows carry no PlanID and are the overwhelming majority of the ledger.
IF OBJECT_ID('dbo.Scenario_Audit', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Audit', 'PlanID') IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioAudit_Plan')
    EXEC('CREATE INDEX IX_ScenarioAudit_Plan ON Scenario_Audit(PlanID, CreatedAt DESC) WHERE PlanID IS NOT NULL');
-- Speeds up dal.latest_next_set_outcome, polled on every status check. Not in
-- invariants.REQUIRED_INDEXES: that list is for correctness, not performance.

-- ONE in-flight calibration per model pair. A CORRECTNESS index: a sweep costs
-- ~100 billed LLM calls, and two requests arriving together both read "nothing
-- running" before either writes, so the database refusing the second INSERT is the
-- only thing that closes the gap. Registered in invariants.REQUIRED_INDEXES; a DB
-- missing it fails the boot. Stale 'running' rows are settled to 'failed' by the
-- route before inserting. Filtered on the literal CalibrationStatus.running
-- carries — invariants.FILTERED_INDEX_LITERALS pins the two together.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_GroundingCalibration_Running' AND object_id = OBJECT_ID('dbo.Grounding_Calibration_Run'))
    EXEC('CREATE UNIQUE INDEX UX_GroundingCalibration_Running ON Grounding_Calibration_Run(EmbeddingModel, RerankerModel) WHERE Status = ''running''');

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Session_EntityUser' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
CREATE INDEX IX_Session_EntityUser ON Scenario_Session(EntityID, UserID) INCLUDE (SessionStatus);
-- Hot path for GET /v1/users/{user_id}/scenarios and /v1/entities/{id}/scenarios.
-- Unfiltered: those routes query all three session statuses. Also backs the
-- promotion-retry sweep and the admin GET /v1/tsg/sessions/promotions list.

-- One active treatment plan per scenario — the concurrent-POST race arbiter (the losing
-- INSERT hits this and surfaces as 409 generation_in_progress).
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_TreatmentPlan_ActiveScenario' AND object_id = OBJECT_ID('dbo.Risk_Treatment_Plan'))
CREATE UNIQUE INDEX UX_TreatmentPlan_ActiveScenario ON Risk_Treatment_Plan(ScenarioID) WHERE Superseded = 0;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_TreatmentPlan_SessionActive' AND object_id = OBJECT_ID('dbo.Risk_Treatment_Plan'))
CREATE INDEX IX_TreatmentPlan_SessionActive ON Risk_Treatment_Plan(SessionID) WHERE Superseded = 0;

-- Regeneration-history reads (?include_superseded=true). The two indexes above are
-- filtered Superseded = 0, so without this every history read scans the whole plan
-- table. CreatedAt is keyed for the newest-first ORDER BY.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_TreatmentPlan_SessionHistory' AND object_id = OBJECT_ID('dbo.Risk_Treatment_Plan'))
CREATE INDEX IX_TreatmentPlan_SessionHistory ON Risk_Treatment_Plan(SessionID, ScenarioID, CreatedAt) WHERE Superseded = 1;

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
-- API_Client — API-key auth for the header auth model (app/api/deps.get_principal).
-- The secret is NEVER stored, only its SHA-256 hex (KeyHash). Several Active rows
-- may coexist for make-before-break rotation; revoke = one UPDATE.
-- Seed a key:  compute the hash in PYTHON (UTF-8), then insert the literal. Do NOT
--              use HASHBYTES in SQL -- it hashes UTF-16 and never matches the app's
--              UTF-8 SHA-256 (silent 401s).
--                python -c "import hashlib,secrets; s=secrets.token_hex(32); print(s, hashlib.sha256(s.encode()).hexdigest())"
--              INSERT INTO API_Client (ClientID, KeyHash, Name, Module) VALUES ('shield-prod', '<keyhash>', 'Shield', 'tsg');
-- Module scopes a key to ONE module, so a leaked key is contained to that module.
-- Default 'tsg' applies if a manual INSERT omits it.
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
    'Scoped_Threat','Threat_Scenario','Scenario_Audit',
    'Prompt_Log','Risk_Treatment_Plan','Config_Tuning','API_Client');


-- ---------------------------------------------------------------------------
-- Scenario_Library - generated scenario text, reused across every asset of one PROFILE
-- ---------------------------------------------------------------------------
-- ProfileKey is a sha256 of CLASSIFICATION CODES ONLY - never a name, an entity id
-- or free text. That is what makes a row safe to serve across tenants while the
-- asset data it came from stays isolated. See app/pipeline/scenario_profile.py.
--
-- SourceNamesJSON is the ordered [asset, system 1, ...] name list live at write
-- time. Serving the row to a different asset swaps those names positionally, and
-- the swap REFUSES rather than guesses if any source name survives it - so a
-- mismatch costs a regeneration, never a register naming the wrong customer's
-- system.
--
-- PromptVersion and ModelID are the invalidation key: a row is only served back to
-- a session running the same prompt and model that produced it.
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

-- The natural key. UNIQUE so two sessions of the same profile cannot leave two
-- competing texts; the loser's INSERT fails and is discarded, which is correct -
-- either text was valid, and the session keeps its own copy regardless.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ScenarioLibrary_Natural' AND object_id = OBJECT_ID('dbo.Scenario_Library'))
CREATE UNIQUE INDEX UX_ScenarioLibrary_Natural
    ON Scenario_Library(ProfileKey, ThreatCatalogueID, ScenarioNumber);


-- ---------------------------------------------------------------------------
-- Widen every remaining short nvarchar column to nvarchar(100)
-- ---------------------------------------------------------------------------
-- A blanket floor. A value that outgrows its column fails only on that one value,
-- so the application looks healthy until the first write of it. nvarchar is
-- variable-length, so the headroom costs nothing. Each guarded on the CURRENT
-- width, so re-running is a no-op.

IF OBJECT_ID('dbo.Scenario_Session', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Session', 'Mode') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Scenario_Session'), 'Mode', 'CharMaxLen') < 100
    ALTER TABLE Scenario_Session ALTER COLUMN Mode nvarchar(100) NOT NULL;
IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario', 'IdentityHash') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Threat_Scenario'), 'IdentityHash', 'CharMaxLen') < 100
    ALTER TABLE Threat_Scenario ALTER COLUMN IdentityHash nvarchar(100) NULL;IF OBJECT_ID('dbo.API_Client', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.API_Client', 'KeyHash') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.API_Client'), 'KeyHash', 'CharMaxLen') < 100
    ALTER TABLE API_Client ALTER COLUMN KeyHash nvarchar(100) NOT NULL;
IF OBJECT_ID('dbo.API_Client', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.API_Client', 'Module') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.API_Client'), 'Module', 'CharMaxLen') < 100
    ALTER TABLE API_Client ALTER COLUMN Module nvarchar(100) NOT NULL;
