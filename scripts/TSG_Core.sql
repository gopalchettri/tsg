-- ============================================================================
-- TSG_Core — creates/updates TSG's own tables. Safe to re-run any time: enables
-- RCSI once, adds any missing table/column/index, never touches row data.
--
-- Threat-library master tables live in Threat_library.sql; Threat_Scenario_
-- Control_Map lives in Control_library.sql. Platform tables (ctm_scan_*,
-- onboarding_*) already exist elsewhere — TSG only reads them, never creates
-- or alters them (SDD §7.7). No FOREIGN KEYs, by design (SDD §7.7).
--
-- Uses GO batches: SQL Server must see a table created before a later batch
-- can reference it.
--
-- Keep in lockstep with models.py: a new column needs a CREATE TABLE entry
-- (fresh DB) AND a guarded ALTER below it (existing DB).
--
-- SSMS: run with `sqlcmd -b -S <server> -d <database> -E -i TSG_Core.sql`, not F5.
-- (-b: exit non-zero on any SQL error instead of burying it mid-output and reporting success.)
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
    Mode                  nvarchar(20)   NOT NULL,
    CurrentSubsystemIndex int            NULL,
    SubsystemsJSON        nvarchar(max)  NOT NULL,
    IdempotencyKey        nvarchar(200)  NULL,
    SectorIDsJSON         nvarchar(max)  NULL,
    AssetContextJSON      nvarchar(max)  NULL,
    TuningJSON            nvarchar(max)  NULL,               -- frozen tuning rulebook (core.tuning); NULL = pre-feature session
    CreatedAt             datetime2      NULL,
    UpdatedAt             datetime2      NULL,
    CompletedAt           datetime2      NULL,
    CONSTRAINT CK_Session_Status CHECK (SessionStatus IN ('active', 'completed', 'cancelled'))
);

-- TuningJSON: frozen Config_Tuning snapshot at session creation. NULL = pre-feature session.
IF OBJECT_ID('dbo.Scenario_Session', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Session', 'TuningJSON') IS NULL
    ALTER TABLE Scenario_Session ADD TuningJSON nvarchar(max) NULL;

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
-- never have finished a single session — and SessionStatus is referenced by three FILTERED
-- index predicates (UX_Session_ActiveAsset / IX_Session_Active / IX_Session_CompletedByAsset),
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
    GroundingStatus    nvarchar(20)  NOT NULL,
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
    DuplicateReason    nvarchar(30)  NOT NULL,   -- DuplicateReason enum (app/core/enums.py)
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
    RejectionKind   nvarchar(30)  NULL,
    SelectionKind   nvarchar(30)  NULL,
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
    Status               nvarchar(20)  NOT NULL,
    ScenarioJSON         nvarchar(max) NULL,
    ValidationJSON       nvarchar(max) NULL,
    AcceptedSubsetJSON   nvarchar(max) NULL,
    Accepted             int           NOT NULL,
    Superseded           int           NOT NULL,
    IdentityHash         nvarchar(64)  NULL,
    ScenarioNumber       int           NOT NULL CONSTRAINT DF_ScenarioOutput_ScenarioNumber DEFAULT 1,  -- 1 = original, 2+ = "generate next set" alternates
    ReplacesOutputID     uniqueidentifier NULL,   -- OutputID this row replaced; NULL for first-run/variant rows
    GenerationEpoch      int           NOT NULL,
    ErrorMessage         nvarchar(max) NULL,
    CreatedAt            datetime2     NULL,
    ControlsMappedAt     datetime2     NULL   -- Step-4 attempt stamp; NULL = not yet tried
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

IF OBJECT_ID('dbo.Threat_Library_Import_Run', 'U') IS NULL
CREATE TABLE Threat_Library_Import_Run (
    RunID            uniqueidentifier NOT NULL CONSTRAINT PK_Threat_Library_Import_Run PRIMARY KEY,
    Source           nvarchar(50)  NOT NULL,   -- attack | attack_ics | capec | emb3d | pytm | threat_composer | misp_actors
    SourceTag        nvarchar(50)  NULL,       -- provenance tag stamped on imported rows (Threat_Type.Source)
    DryRun           bit           NOT NULL,
    Status           nvarchar(20)  NOT NULL,   -- running | success | failed
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
    Stage            nvarchar(32)  NULL,
    SubsystemID      int           NULL,
    EventType        nvarchar(40)  NOT NULL,
    Decision         nvarchar(30)  NULL,
    Granularity      nvarchar(20)  NULL,
    ThreatTypeRefID  int           NULL,
    ActorUserID      nvarchar(200) NULL,   -- who is ACCOUNTABLE (back-filled to the session owner)
    ActorType        nvarchar(20)  NULL,   -- who PERFORMED it: 'user' | 'system'
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
    Stage           nvarchar(20)  NOT NULL,
    PromptVersion   nvarchar(20)  NOT NULL,
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
    ProposedCategory  nvarchar(200) NOT NULL,
    ProposedType      nvarchar(300) NOT NULL,
    ProposedName      nvarchar(500) NOT NULL,
    ProposedGenericName nvarchar(500) NULL,  -- library-shaped name the curator generalizes toward
    Status            nvarchar(20)  NOT NULL,
    ThreatTypeID      int NULL,
    ThreatCatalogueID int NULL,
    ReviewedBy        nvarchar(200) NULL,
    ReviewedAt        datetime2 NULL,
    CreatedAt         datetime2 NOT NULL
);

-- Speeds up the curator queue's "list pending" read. Non-unique: names can legitimately recur.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ThreatCandidateReview_Session_Status')
    CREATE INDEX IX_ThreatCandidateReview_Session_Status
        ON Threat_Candidate_Review (SessionID, Status);

-- The admin curator queue (GET /v1/tsg/threat-library/candidates) is deliberately CROSS-session
-- — Status alone, no SessionID filter, ordered oldest-first — so the index above can't serve it:
-- SessionID is its leading column, and a query with no SessionID predicate can't seek on it.
-- NOT filtered to Status='pending': SQLAlchemy sends Status as a bound parameter, not a literal,
-- and SQL Server can't match a filtered index against a parameterized predicate (same reasoning
-- IX_ScopedThreat_SessionActiveScores below documents) — Status leads as a plain key column
-- instead, with CreatedAt trailing so the ORDER BY is satisfied by the same seek, no extra sort.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ThreatCandidateReview_Status_Created')
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

-- Adds review/register columns for pre-2026-08-06 databases.
IF OBJECT_ID('dbo.Risk_Treatment_Plan', 'U') IS NOT NULL AND COL_LENGTH('dbo.Risk_Treatment_Plan', 'RiskLevel') IS NULL
BEGIN
    ALTER TABLE Risk_Treatment_Plan ADD RiskLevel nvarchar(100) NULL;
    ALTER TABLE Risk_Treatment_Plan ADD ReviewStatus nvarchar(100) NULL;
    ALTER TABLE Risk_Treatment_Plan ADD ReviewComment nvarchar(max) NULL;
    ALTER TABLE Risk_Treatment_Plan ADD ReviewedBy nvarchar(200) NULL;
    ALTER TABLE Risk_Treatment_Plan ADD ReviewedAt datetime2 NULL;
END
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
IF COL_LENGTH('dbo.Risk_Treatment_Plan', 'ErrorReason') IS NOT NULL
    UPDATE Risk_Treatment_Plan
    SET    ErrorReason = CASE
               WHEN ErrorMessage = N'cancelled by user' THEN N'cancelled'
               WHEN ErrorMessage = N'failed to queue generation — request it again' THEN N'enqueue_failed'
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

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Session_CompletedByAsset' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
CREATE INDEX IX_Session_CompletedByAsset ON Scenario_Session(EntityID, AssetID, CompletedAt DESC) WHERE SessionStatus = 'completed';
-- GET /assets/{id}/accepted-scenarios hot path.

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
    ValueType       nvarchar(10)   NOT NULL CONSTRAINT CK_Config_Tuning_ValueType CHECK (ValueType IN ('float', 'int')),
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
    KeyHash     nvarchar(64)  NOT NULL,
    Name        nvarchar(200) NOT NULL,
    Module      nvarchar(50)  NOT NULL CONSTRAINT DF_API_Client_Module   DEFAULT 'tsg',
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
SELECT TABLE_NAME, 1 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME IN (
    'Scenario_Session','Subsystem_Stage_State','Identified_Threat','Scoped_Threat',
    'Threat_Scenario_Output','Threat_Library_Import_Run','Scenario_Audit','Prompt_Log',
    'Threat_Candidate_Review','Risk_Treatment_Plan','API_Client');
