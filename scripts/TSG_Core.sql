-- ============================================================================
-- TSG_Core — one-stop script for BOTH production and dev. Run this alone, on
-- either database, any time you need to stand up a fresh TSG database.
-- Merges the former bootstrap_schema.sql + production_setup.sql +
-- add_ctm_scan_entity_columns.sql (2026-07-19).
--
-- Dev-phase simplification (2026-07-19): dropped the legacy-database-healing
-- sections this script used to carry (IDENTITY retrofit, column upgrades,
-- GUID-type healing, dead-column drops) — every one of them was confirmed a
-- no-op against the actual live database (IDENTITY already on, GUID columns
-- already uniqueidentifier, every healed column already present, all 3 dead
-- columns already gone). A database created by this script is never in the
-- old shape those sections existed to fix, so there was nothing left to
-- protect. If you ever restore a genuinely old/legacy database, check its
-- shape against Sections 1-2 below by hand rather than relying on inherited
-- migration logic.
--
-- >>> SSMS users: prefer `sqlcmd -S <server> -d <database> -E -i TSG_Core.sql`
-- over F5 — no IntelliSense static-analysis noise, only real execution results.
--
-- Contract (safe to re-run any time): enables RCSI once; creates any missing
-- table/column/index; never touches row data.
--
-- Creates TSG's own pipeline tables and the threat-library masters
-- (Threat_Category/Type/Catalogue/Actor + the type-actor map), schema-only —
-- see scripts/Seed_to_Threat_library.sql for real rows. Config_Threat_Rule
-- and Threat_Catalogue_Category_Map live in scripts/Threat_library.sql
-- instead. Assumes the ASSET/ONBOARDING platform tables already exist
-- (group, onboarding_*, ctm_scan_*) — a different system's schema TSG reuses
-- but does not create (SDD §7.7). No FOREIGN KEYs by design (SDD §7.7).
--
-- Uses GO batch separators: SQL Server binds object/column names for an
-- entire batch before executing any of it, so a table created earlier in the
-- same unbroken batch as a later reference to it fails to resolve.
--
-- tests/test_schema_sync.py asserts every models.py column appears in the
-- CREATE TABLE blocks below — keep both in lockstep.
-- ============================================================================

SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;

-- ============================================================
-- SECTION 0 — Enable Read Committed Snapshot Isolation (RCSI), once.
-- Required by the app's CAS/lock concurrency design (claim_stage,
-- acquire_lock — reads must not block behind a concurrent writer).
--
-- WARNING: needs the database to itself (no other connections), or it just
-- BLOCKS waiting for everyone to disconnect. SET SINGLE_USER below forces
-- every other session off (rolling back their in-flight work) so this can't
-- hang. Only safe against a database with no real traffic.
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
    SessionStatus         nvarchar(20)   NOT NULL,
    CurrentStage          nvarchar(32)   NOT NULL,
    StageStatus           nvarchar(20)   NOT NULL,
    Mode                  nvarchar(20)   NOT NULL,
    CurrentSubsystemIndex int            NULL,
    SubsystemsJSON        nvarchar(max)  NOT NULL,
    IdempotencyKey        nvarchar(200)  NULL,
    SectorIDsJSON         nvarchar(max)  NULL,
    AssetContextJSON      nvarchar(max)  NULL,
    CreatedAt             datetime2      NULL,
    UpdatedAt             datetime2      NULL,
    CompletedAt           datetime2      NULL,
    CONSTRAINT CK_Session_Status CHECK (SessionStatus IN ('active', 'completed', 'cancelled'))
);

IF OBJECT_ID('dbo.Subsystem_Stage_State', 'U') IS NULL
CREATE TABLE Subsystem_Stage_State (
    StateID          uniqueidentifier NOT NULL CONSTRAINT PK_Subsystem_Stage_State PRIMARY KEY,
    SessionID        uniqueidentifier NOT NULL,
    TenantID         nvarchar(200) NULL,
    EntityID         nvarchar(200) NULL,
    SubsystemID      int           NOT NULL,
    Level            nvarchar(20)  NOT NULL,                -- THREATS|SCENARIOS|_LOCK
    Status           nvarchar(20)  NOT NULL,
    GenerationEpoch  int           NOT NULL,
    ActiveTaskID     uniqueidentifier NULL,
    LeaseExpiresAt   datetime2     NULL,
    HeartbeatAt      datetime2     NULL,
    AttemptCount     int           NOT NULL CONSTRAINT DF_SSS_AttemptCount DEFAULT 0,
    ErrorMessage     nvarchar(max) NULL,
    UpdatedAt        datetime2     NOT NULL,
    CreatedAt datetime2 NULL CONSTRAINT DF_StageState_CreatedAt DEFAULT SYSUTCDATETIME()
);

-- Existing databases created before the CreatedAt stamp (2026-07-30): add it in place.
IF OBJECT_ID('dbo.Subsystem_Stage_State', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Subsystem_Stage_State', 'CreatedAt') IS NULL
    ALTER TABLE Subsystem_Stage_State ADD CreatedAt datetime2 NULL CONSTRAINT DF_StageState_CreatedAt DEFAULT SYSUTCDATETIME();

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
    FactorsJSON     nvarchar(max) NULL,
    Superseded      int           NOT NULL,
    CreatedAt       datetime2     NULL
);

-- Existing databases created before the typed rejection kind (2026-08-03): add it in place.
-- Nullable, so no DEFAULT and no table rewrite. Rows written before this column read NULL, which
-- next_unserved_unique_threats treats as NOT re-servable -- correct-but-lossy, so a pre-existing
-- database should run scripts/backfill_rejection_kind.sql once. TSG_Core.sql never touches row data.
IF OBJECT_ID('dbo.Scoped_Threat', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scoped_Threat', 'RejectionKind') IS NULL
    ALTER TABLE Scoped_Threat ADD RejectionKind nvarchar(30) NULL;

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
    ScenarioNumber       int           NOT NULL CONSTRAINT DF_ScenarioOutput_ScenarioNumber DEFAULT 1,  -- which of the threat's coexisting scenarios: 1 = original, 2+ = "generate next set" alternates (2026-07-29, see readme.txt)
    ReplacesOutputID     uniqueidentifier NULL,   -- the OutputID this row REPLACED (regeneration / error-card retry); NULL for first-run, next-set and variant rows. Backward-linked, so following it yields the full revision chain. Deliberately NOT indexed: nothing filters or joins on it (2026-07-30, see readme.txt)
    GenerationEpoch      int           NOT NULL,
    ErrorMessage         nvarchar(max) NULL,
    CreatedAt            datetime2     NULL,
    ControlsMappedAt     datetime2     NULL   -- Step-4 attempt stamp: NULL = not yet tried; set even when zero controls matched (control_mapping.map_controls)
);

-- Existing databases created before the Step-4 attempt stamp: add the column in place.
IF OBJECT_ID('dbo.Threat_Scenario_Output', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario_Output', 'ControlsMappedAt') IS NULL
    ALTER TABLE Threat_Scenario_Output ADD ControlsMappedAt datetime2 NULL;

-- Existing databases created before scenario variants (2026-07-29): add the column in place.
IF OBJECT_ID('dbo.Threat_Scenario_Output', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario_Output', 'ScenarioNumber') IS NULL
    ALTER TABLE Threat_Scenario_Output ADD ScenarioNumber int NOT NULL CONSTRAINT DF_ScenarioOutput_ScenarioNumber DEFAULT 1;

-- Existing databases created before regeneration lineage (2026-07-30): add the column in place.
-- Nullable, so no DEFAULT and no table rewrite. On a database that predates the column, rows
-- regenerated earlier stay NULL and read as originals. No backfill ships: the link is derivable
-- from (IdentityHash, ScenarioNumber) ordered by GenerationEpoch should a pre-2026-07-30 database
-- ever need it, but that is a one-shot script's job -- TSG_Core.sql never touches row data.
IF OBJECT_ID('dbo.Threat_Scenario_Output', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario_Output', 'ReplacesOutputID') IS NULL
    ALTER TABLE Threat_Scenario_Output ADD ReplacesOutputID uniqueidentifier NULL;

IF OBJECT_ID('dbo.Threat_Library_Import_Run', 'U') IS NULL
CREATE TABLE Threat_Library_Import_Run (
    RunID            uniqueidentifier NOT NULL CONSTRAINT PK_Threat_Library_Import_Run PRIMARY KEY,
    Source           nvarchar(50)  NOT NULL,   -- API source name: attack | attack_ics | capec | emb3d | pytm | threat_composer | misp_actors
    SourceTag        nvarchar(50)  NULL,       -- provenance tag stamped on the imported rows (Threat_Type.Source)
    DryRun           bit           NOT NULL,
    Status           nvarchar(20)  NOT NULL,   -- running | success | failed
    JobID            nvarchar(100) NULL,       -- Celery task id, for correlating with the import status route
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

IF OBJECT_ID('dbo.Threat_Scenario_Control_Map', 'U') IS NULL
CREATE TABLE Threat_Scenario_Control_Map (
    OutputID          uniqueidentifier NOT NULL,
    ControlLibraryID  int           NOT NULL,
    SessionID         uniqueidentifier NOT NULL,
    MapRank           int           NOT NULL,   -- 1 = best match for this scenario
    Score             float         NULL,       -- raw rerank 0-100
    SuggestedControl  nvarchar(500) NULL,       -- the LLM's free-text suggestion this grounded from (NULL on scenario-text fallback)
    CreatedAt         datetime2     NULL,
    CONSTRAINT PK_Threat_Scenario_Control_Map PRIMARY KEY (OutputID, ControlLibraryID)
);

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
    ActorType        nvarchar(20)  NULL,   -- who PERFORMED it: 'user' | 'system' (see enums.ActorType)
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
    CreatedAt       datetime2     NOT NULL
);

-- Existing databases created before the flattened-prompt column (2026-08-03): add it in place.
-- Nullable, so no DEFAULT and no table rewrite. Rows written before this column read NULL -- the
-- same prompt is still recoverable from Messages, so there is nothing to backfill.
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
    Status            nvarchar(20)  NOT NULL,
    ThreatTypeID      int NULL,
    ThreatCatalogueID int NULL,
    ReviewedBy        nvarchar(200) NULL,
    ReviewedAt        datetime2 NULL,
    CreatedAt         datetime2 NOT NULL
);

-- The curator queue is read by (SessionID, Status), and the table had no index beyond its PK, so
-- "list what is pending" was a full scan. Non-unique on purpose: the same proposed name may
-- legitimately recur across sessions and each occurrence is its own curation record.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ThreatCandidateReview_Session_Status')
    CREATE INDEX IX_ThreatCandidateReview_Session_Status
        ON Threat_Candidate_Review (SessionID, Status);

-- 2026-08-03: Risk Treatment Plan Generation (docs/RISK_TREATMENT_PLAN_SDD.md). One row per
-- generation attempt against an ACCEPTED scenario; at most one active (Superseded = 0) row per
-- OutputID, enforced by UX_TreatmentPlan_ActiveOutput in SECTION 3. Lives OUTSIDE the session
-- state machine (accepted scenarios sit on completed sessions, where stage locks refuse to run) —
-- the row's own Status column is the state. Reads crm_* Risk-module tables at POST time only;
-- the frozen context goes in InputSnapshotJSON so worker and reads never touch crm_*.
IF OBJECT_ID('dbo.Risk_Treatment_Plan', 'U') IS NULL
CREATE TABLE Risk_Treatment_Plan (
    PlanID                  uniqueidentifier NOT NULL CONSTRAINT PK_Risk_Treatment_Plan PRIMARY KEY,
    SessionID               uniqueidentifier NOT NULL,
    OutputID                uniqueidentifier NOT NULL,  -- the accepted Threat_Scenario_Output
    TenantID                nvarchar(200) NULL,
    EntityID                nvarchar(200) NULL,         -- copied from the session (authz boundary)
    UserID                  nvarchar(200) NULL,         -- requesting principal (provenance)
    CrmRiskIdentificationID int           NOT NULL,     -- crm_risk_identification.id from the request
    TreatmentStrategy       nvarchar(30)  NOT NULL,     -- 'Mitigate' only in v1
    Status                  nvarchar(20)  NOT NULL,     -- StageStatus subset: RUNNING | COMPLETE | ERROR
    ActiveTaskID            nvarchar(100) NULL,         -- Celery claim / redelivery fence
    RiskIdentificationDate  datetime2     NULL,         -- crm creation_date; never AI-generated
    InputSnapshotJSON       nvarchar(max) NULL,         -- exact redacted context sent to the LLM
    PlanJSON                nvarchar(max) NULL,         -- parsed LLM output
    ValidationJSON          nvarchar(max) NULL,         -- advisory: moderation + vocabulary warnings
    ErrorMessage            nvarchar(max) NULL,         -- client-safe only; raw text lives in Prompt_Log
    Superseded              int           NOT NULL CONSTRAINT DF_TreatmentPlan_Superseded DEFAULT 0,
    CreatedAt               datetime2     NULL,
    UpdatedAt               datetime2     NULL,         -- progress clock: claim + each LLM attempt bump it
    CompletedAt             datetime2     NULL
);
GO

-- ============================================================
-- SECTION 2 — Threat-library master tables. Schema only — see
-- scripts/Seed_to_Threat_library.sql for real rows. Type/Catalogue/Actor
-- PKs are IDENTITY (R10 promote-on-accept inserts new masters and reads the
-- generated key back). Threat_Category stays a plain int PK (fixed STRIDE
-- set, app never inserts it).
-- ============================================================

-- Audit quartet on all four masters (CreatedAt/CreatedBy/UpdatedAt/UpdatedBy): all NULL and
-- DEFAULT-less on purpose. Seed_to_Threat_library.sql inserts with explicit column lists, so a
-- NOT NULL column without a default would break every one of its ~120 statements; NULL also reads
-- honestly as "row predates the audit columns" rather than a fabricated timestamp. CreatedBy /
-- UpdatedBy hold the caller's user id (Principal.user_id / JWT sub) — the same identity
-- Scenario_Audit.ActorUserID records — or an 'auto:<source>' / 'cli:<user>' literal when a
-- background import had no logged-in caller. Updated* are written ONLY by the CRUD endpoints
-- (app/api/threat_library_crud.py): the importer and promote-on-accept upserts deliberately leave
-- an existing row untouched, because provenance is first-writer (dal.upsert_threat_type).
IF OBJECT_ID('dbo.Threat_Category', 'U') IS NULL
CREATE TABLE Threat_Category (
    ThreatCategoryID    int            NOT NULL CONSTRAINT PK_Threat_Category PRIMARY KEY,
    ThreatCategoryName  nvarchar(200)  NOT NULL,
    ThreatCategoryCode  nvarchar(20)   NULL,
    SecurityObjective   nvarchar(200)  NULL,
    IsActive            bit            NOT NULL,
    IsDeleted           bit            NOT NULL,
    CreatedAt           datetime2      NULL,
    CreatedBy           nvarchar(200)  NULL,
    UpdatedAt           datetime2      NULL,
    UpdatedBy           nvarchar(200)  NULL
);

IF OBJECT_ID('dbo.Threat_Type', 'U') IS NULL
CREATE TABLE Threat_Type (
    ThreatTypeID             int            IDENTITY(1,1) NOT NULL CONSTRAINT PK_Threat_Type PRIMARY KEY,
    ThreatTypeName           nvarchar(300)  NOT NULL,
    Description              nvarchar(max)  NULL,
    SectorID                 int            NULL,
    ThreatCategoryID  int            NULL,
    IsActive                 bit            NOT NULL,
    IsDeleted                bit            NOT NULL,
    CreatedAt                datetime2      NULL,
    CreatedBy                nvarchar(200)  NULL,
    UpdatedAt                datetime2      NULL,
    UpdatedBy                nvarchar(200)  NULL
);

IF OBJECT_ID('dbo.Threat_Catalogue', 'U') IS NULL
CREATE TABLE Threat_Catalogue (
    ThreatCatalogueID  int            IDENTITY(1,1) NOT NULL CONSTRAINT PK_Threat_Catalogue PRIMARY KEY,
    ThreatTypeID       int            NOT NULL,
    ThreatName         nvarchar(500)  NOT NULL,
    Description        nvarchar(max)  NULL,
    SectorID           int            NULL,
    IsActive           bit            NOT NULL,
    IsDeleted          bit            NOT NULL,
    CreatedAt          datetime2      NULL,
    CreatedBy          nvarchar(200)  NULL,
    UpdatedAt          datetime2      NULL,
    UpdatedBy          nvarchar(200)  NULL
);

-- Source mirrors Threat_Type.Source/Threat_Catalogue.Source (which Threat_library.sql bolts on) so
-- an imported actor is distinguishable from an AI-promoted or hand-curated one. Declared in this
-- CREATE block rather than as an ALTER over there because the column is new — that keeps it out of
-- test_schema_sync's _COLUMN_DEPLOYED_SEPARATELY allowlist.
IF OBJECT_ID('dbo.Threat_Actor', 'U') IS NULL
CREATE TABLE Threat_Actor (
    ThreatActorID    int            IDENTITY(1,1) NOT NULL CONSTRAINT PK_Threat_Actor PRIMARY KEY,
    ThreatActorName  nvarchar(200)  NOT NULL,
    IsCapable        int            NOT NULL,
    IsActive         bit            NOT NULL,
    IsDeleted        bit            NOT NULL,
    Source           nvarchar(50)   NULL,
    CreatedAt        datetime2      NULL,
    CreatedBy        nvarchar(200)  NULL,
    UpdatedAt        datetime2      NULL,
    UpdatedBy        nvarchar(200)  NULL
);

-- Existing databases: every CREATE above is IF OBJECT_ID(...) IS NULL guarded, so it is a no-op
-- once the table exists and the new columns would never arrive. Same in-place pattern as
-- Threat_Scenario_Output.ControlsMappedAt in Section 1. Guarded on one column per table — the four
-- are always added together, so the first one's absence proves none of them are there.
IF OBJECT_ID('dbo.Threat_Actor', 'U') IS NOT NULL AND COL_LENGTH('dbo.Threat_Actor', 'Source') IS NULL
    ALTER TABLE Threat_Actor ADD Source nvarchar(50) NULL;

IF OBJECT_ID('dbo.Threat_Category', 'U') IS NOT NULL AND COL_LENGTH('dbo.Threat_Category', 'CreatedAt') IS NULL
    ALTER TABLE Threat_Category ADD CreatedAt datetime2 NULL, CreatedBy nvarchar(200) NULL, UpdatedAt datetime2 NULL, UpdatedBy nvarchar(200) NULL;

IF OBJECT_ID('dbo.Threat_Type', 'U') IS NOT NULL AND COL_LENGTH('dbo.Threat_Type', 'CreatedAt') IS NULL
    ALTER TABLE Threat_Type ADD CreatedAt datetime2 NULL, CreatedBy nvarchar(200) NULL, UpdatedAt datetime2 NULL, UpdatedBy nvarchar(200) NULL;

IF OBJECT_ID('dbo.Threat_Catalogue', 'U') IS NOT NULL AND COL_LENGTH('dbo.Threat_Catalogue', 'CreatedAt') IS NULL
    ALTER TABLE Threat_Catalogue ADD CreatedAt datetime2 NULL, CreatedBy nvarchar(200) NULL, UpdatedAt datetime2 NULL, UpdatedBy nvarchar(200) NULL;

IF OBJECT_ID('dbo.Threat_Actor', 'U') IS NOT NULL AND COL_LENGTH('dbo.Threat_Actor', 'CreatedAt') IS NULL
    ALTER TABLE Threat_Actor ADD CreatedAt datetime2 NULL, CreatedBy nvarchar(200) NULL, UpdatedAt datetime2 NULL, UpdatedBy nvarchar(200) NULL;

IF OBJECT_ID('dbo.ThreatType_ThreatActor_Map', 'U') IS NULL
CREATE TABLE ThreatType_ThreatActor_Map (
    ThreatTypeID   int NOT NULL,
    ThreatActorID  int NOT NULL,
    CreatedAt datetime2 NULL CONSTRAINT DF_TypeActorMap_CreatedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_ThreatType_ThreatActor_Map PRIMARY KEY (ThreatTypeID, ThreatActorID)
);

-- Existing databases created before the CreatedAt stamp (2026-07-30): add it in place.
IF OBJECT_ID('dbo.ThreatType_ThreatActor_Map', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.ThreatType_ThreatActor_Map', 'CreatedAt') IS NULL
    ALTER TABLE ThreatType_ThreatActor_Map ADD CreatedAt datetime2 NULL CONSTRAINT DF_TypeActorMap_CreatedAt DEFAULT SYSUTCDATETIME();

-- Config_Threat_Rule and Threat_Catalogue_Category_Map live in
-- scripts/Threat_library.sql instead — see that file.

GO

-- ============================================================
-- SECTION 3 — TSG's own guard indexes
-- ============================================================

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Session_ActiveAsset' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
CREATE UNIQUE INDEX UX_Session_ActiveAsset ON Scenario_Session(EntityID, AssetID) WHERE SessionStatus = 'active';
-- one active session per (entity, asset).

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Session_IdempotencyKey' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
CREATE UNIQUE INDEX UX_Session_IdempotencyKey ON Scenario_Session(EntityID, IdempotencyKey) WHERE IdempotencyKey IS NOT NULL;
-- retried POST /v1/sessions with the same key returns the same session.

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Session_Active' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
CREATE NONCLUSTERED INDEX IX_Session_Active ON Scenario_Session(SessionStatus) WHERE SessionStatus = 'active';

-- IdentityHash = sha256(SessionID|SubsystemID|dedup_key), dedup_key = cat:/type:/txt: (tasks._dedup_key).
-- SubsystemID is folded into the hash (this index has no subsystem column), so this one active
-- scenario per (session, subsystem, catalogue-level threat) — sibling subsystems don't collide.
-- One active row per (identity, ScenarioNumber) — coexisting scenario numbers are legal
-- (scenario variants, 2026-07-29), a second row at the SAME number still collides
-- (double-click race guard). Drop the older two-column form first so an existing
-- database gets the widened index on re-run.
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

-- 2026-07-30: promoted from a NON-unique IX_ to a UNIQUE UX_. (SessionID, SubsystemID, Level) is
-- the row's real identity — the surrogate StateID PK is never queried by anything, while all ~25
-- access sites in dal.py / reaper.py / sessions.py key on this triple. The entire lock and
-- epoch-CAS design (claim_stage, finish_stage, renew_lease, acquire_lock/release_lock) asserts
-- exactly-one-row by testing `rowcount == 1` in Python; a duplicate row would make a CAS silently
-- match two rows and put two workers on one subsystem. Safe to enforce: the sole insert is
-- tasks.set_up_progress_tracking, called once per session from the create endpoint (itself
-- guarded by UX_Session_IdempotencyKey / UX_Session_ActiveAsset), writing exactly one row per
-- level. Idempotent: the first run drops the old IX_ and creates the UX_; later runs no-op.
-- CREATE FIRST, DROP SECOND. The CREATE UNIQUE can legitimately fail (a database holding
-- duplicate (SessionID, SubsystemID, Level) rows rejects it), and dropping first would then leave
-- the table with NEITHER index while the script still reports success — and invariants.py now
-- makes the UX_ name boot-blocking, so the API and every worker would refuse to start. In this
-- order a failed CREATE leaves the old index in place and the app boots on the previous code.
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

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioOutput_SessionSubActive' AND object_id = OBJECT_ID('dbo.Threat_Scenario_Output'))
CREATE INDEX IX_ScenarioOutput_SessionSubActive ON Threat_Scenario_Output(SessionID, SubsystemID) WHERE Superseded = 0;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Session_EntityUser' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
CREATE INDEX IX_Session_EntityUser ON Scenario_Session(EntityID, UserID) INCLUDE (SessionStatus);
-- GET /v1/users/{user_id}/scenarios and /v1/entities/{entity_id}/scenarios hot path.
-- UNfiltered on purpose: those routes query all three session statuses, so the existing
-- filtered EntityID indexes (active/completed only) can't serve them.

-- One active treatment plan per scenario — the concurrent-POST race arbiter (the losing INSERT
-- hits this index and surfaces as 409 generation_in_progress). Boot-blocking via
-- invariants.REQUIRED_INDEXES; the non-unique session index below is deliberately NOT registered
-- there (_assert_indexes rejects non-unique entries).
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_TreatmentPlan_ActiveOutput' AND object_id = OBJECT_ID('dbo.Risk_Treatment_Plan'))
CREATE UNIQUE INDEX UX_TreatmentPlan_ActiveOutput ON Risk_Treatment_Plan(OutputID) WHERE Superseded = 0;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_TreatmentPlan_SessionActive' AND object_id = OBJECT_ID('dbo.Risk_Treatment_Plan'))
CREATE INDEX IX_TreatmentPlan_SessionActive ON Risk_Treatment_Plan(SessionID) WHERE Superseded = 0;

-- ============================================================
-- SECTION 4 — Natural-key guard indexes on the threat-library masters
-- ============================================================

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatType_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Type'))
CREATE UNIQUE INDEX UX_ThreatType_NaturalKey ON Threat_Type(ThreatTypeName, ThreatCategoryID, SectorID) WHERE IsActive = 1 AND IsDeleted = 0;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatCatalogue_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Catalogue'))
CREATE UNIQUE INDEX UX_ThreatCatalogue_NaturalKey ON Threat_Catalogue(ThreatTypeID, ThreatName, SectorID) WHERE IsActive = 1 AND IsDeleted = 0;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatActor_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Actor'))
CREATE UNIQUE INDEX UX_ThreatActor_NaturalKey ON Threat_Actor(ThreatActorName) WHERE IsActive = 1 AND IsDeleted = 0;

-- Threat_Category was the ONLY CRUD-writable master without one (2026-07-30). The shared CRUD
-- create/update path turns a clash into a 409 purely by catching the IntegrityError this index
-- raises (app/api/library_crud.py) — with no index there is no error, so a duplicate name was
-- accepted silently, and the two consumers then disagreed about which id it means:
-- grounding.find_category orders by ThreatCategoryID and takes the LOWEST, while the library
-- importer builds its own name->id map. Same filtered shape as its three siblings above, so a
-- soft-deleted category frees its name for reuse.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatCategory_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Category'))
CREATE UNIQUE INDEX UX_ThreatCategory_NaturalKey ON Threat_Category(ThreatCategoryName) WHERE IsActive = 1 AND IsDeleted = 0;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ThreatType_Category_Active' AND object_id = OBJECT_ID('dbo.Threat_Type'))
CREATE INDEX IX_ThreatType_Category_Active ON Threat_Type(ThreatCategoryID, SectorID) WHERE IsActive = 1 AND IsDeleted = 0;
-- supports grounding.get_possible_types()'s category+sector filter.

-- ============================================================
-- SECTION 5 — Platform-table columns app code reads (ctm_scan_entity,
-- onboarding_supporting_systems). These are platform tables TSG reuses but
-- never creates (SDD §7.7); without these columns, real session creation
-- fails with "Invalid column name" (context.py selects them explicitly).
-- ============================================================

IF OBJECT_ID('dbo.ctm_scan_entity', 'U') IS NOT NULL
BEGIN
    IF COL_LENGTH('dbo.ctm_scan_entity', 'data_handled') IS NULL
        ALTER TABLE ctm_scan_entity ADD data_handled ntext NULL;
    IF COL_LENGTH('dbo.ctm_scan_entity', 'system_managed_by') IS NULL
        ALTER TABLE ctm_scan_entity ADD system_managed_by nvarchar(100) NULL;
    IF COL_LENGTH('dbo.ctm_scan_entity', 'operating_system') IS NULL
        ALTER TABLE ctm_scan_entity ADD operating_system nvarchar(200) NULL;
    IF COL_LENGTH('dbo.ctm_scan_entity', 'location') IS NULL
        ALTER TABLE ctm_scan_entity ADD location nvarchar(200) NULL;
    IF COL_LENGTH('dbo.ctm_scan_entity', 'target_rto_hours') IS NULL
        ALTER TABLE ctm_scan_entity ADD target_rto_hours int NULL;
    IF COL_LENGTH('dbo.ctm_scan_entity', 'target_rpo_hours') IS NULL
        ALTER TABLE ctm_scan_entity ADD target_rpo_hours int NULL;
END

IF OBJECT_ID('dbo.onboarding_supporting_systems', 'U') IS NOT NULL
BEGIN
    IF COL_LENGTH('dbo.onboarding_supporting_systems', 'technology_used') IS NULL
        ALTER TABLE onboarding_supporting_systems ADD technology_used nvarchar(max) NULL;
    IF COL_LENGTH('dbo.onboarding_supporting_systems', 'vendor_name') IS NULL
        ALTER TABLE onboarding_supporting_systems ADD vendor_name nvarchar(200) NULL;
    IF COL_LENGTH('dbo.onboarding_supporting_systems', 'database_platforms') IS NULL
        ALTER TABLE onboarding_supporting_systems ADD database_platforms nvarchar(300) NULL;
END

GO

-- Verify
SELECT 'RCSI' AS what, CAST(is_read_committed_snapshot_on AS int) AS ok FROM sys.databases WHERE database_id = DB_ID()
UNION ALL
SELECT TABLE_NAME, 1 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME IN (
    'Scenario_Session','Subsystem_Stage_State','Identified_Threat','Scoped_Threat',
    'Threat_Scenario_Output','Threat_Scenario_Control_Map','Threat_Library_Import_Run','Scenario_Audit','Prompt_Log','Threat_Candidate_Review','Risk_Treatment_Plan',
    'Threat_Category','Threat_Type','Threat_Catalogue','Threat_Actor','ThreatType_ThreatActor_Map')
UNION ALL
SELECT TABLE_NAME + '.' + COLUMN_NAME, 1 FROM INFORMATION_SCHEMA.COLUMNS
WHERE (TABLE_NAME = 'ctm_scan_entity' AND COLUMN_NAME IN
        ('data_handled', 'system_managed_by', 'operating_system', 'location', 'target_rto_hours', 'target_rpo_hours'))
   OR (TABLE_NAME = 'onboarding_supporting_systems' AND COLUMN_NAME IN
        ('technology_used', 'vendor_name', 'database_platforms'));
