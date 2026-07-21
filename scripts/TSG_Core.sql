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
    UpdatedAt        datetime2     NOT NULL
);

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
    FactorsJSON     nvarchar(max) NULL,
    Superseded      int           NOT NULL,
    CreatedAt       datetime2     NULL
);

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
    GenerationEpoch      int           NOT NULL,
    ErrorMessage         nvarchar(max) NULL,
    CreatedAt            datetime2     NULL
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
    ActorUserID      nvarchar(200) NULL,
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
    ResponseText    nvarchar(max) NULL,
    Model           nvarchar(200) NULL,
    ModelVersion    nvarchar(100) NULL,
    ParseSucceeded  bit           NOT NULL,
    CreatedAt       datetime2     NOT NULL
);

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

-- ============================================================
-- SECTION 2 — Threat-library master tables. Schema only — see
-- scripts/Seed_to_Threat_library.sql for real rows. Type/Catalogue/Actor
-- PKs are IDENTITY (R10 promote-on-accept inserts new masters and reads the
-- generated key back). Threat_Category stays a plain int PK (fixed STRIDE
-- set, app never inserts it).
-- ============================================================

IF OBJECT_ID('dbo.Threat_Category', 'U') IS NULL
CREATE TABLE Threat_Category (
    ThreatCategoryID    int            NOT NULL CONSTRAINT PK_Threat_Category PRIMARY KEY,
    ThreatCategoryName  nvarchar(200)  NOT NULL,
    ThreatCategoryCode  nvarchar(20)   NULL,
    SecurityObjective   nvarchar(200)  NULL,
    IsActive            bit            NOT NULL,
    IsDeleted           bit            NOT NULL
);

IF OBJECT_ID('dbo.Threat_Type', 'U') IS NULL
CREATE TABLE Threat_Type (
    ThreatTypeID             int            IDENTITY(1,1) NOT NULL CONSTRAINT PK_Threat_Type PRIMARY KEY,
    ThreatTypeName           nvarchar(300)  NOT NULL,
    Description              nvarchar(max)  NULL,
    SectorID                 int            NULL,
    ThreatCategoryID  int            NULL,
    IsActive                 bit            NOT NULL,
    IsDeleted                bit            NOT NULL
);

IF OBJECT_ID('dbo.Threat_Catalogue', 'U') IS NULL
CREATE TABLE Threat_Catalogue (
    ThreatCatalogueID  int            IDENTITY(1,1) NOT NULL CONSTRAINT PK_Threat_Catalogue PRIMARY KEY,
    ThreatTypeID       int            NOT NULL,
    ThreatName         nvarchar(500)  NOT NULL,
    Description        nvarchar(max)  NULL,
    SectorID           int            NULL,
    IsActive           bit            NOT NULL,
    IsDeleted          bit            NOT NULL
);

IF OBJECT_ID('dbo.Threat_Actor', 'U') IS NULL
CREATE TABLE Threat_Actor (
    ThreatActorID    int            IDENTITY(1,1) NOT NULL CONSTRAINT PK_Threat_Actor PRIMARY KEY,
    ThreatActorName  nvarchar(200)  NOT NULL,
    IsCapable        int            NOT NULL,
    IsActive         bit            NOT NULL,
    IsDeleted        bit            NOT NULL
);

IF OBJECT_ID('dbo.ThreatType_ThreatActor_Map', 'U') IS NULL
CREATE TABLE ThreatType_ThreatActor_Map (
    ThreatTypeID   int NOT NULL,
    ThreatActorID  int NOT NULL,
    CONSTRAINT PK_ThreatType_ThreatActor_Map PRIMARY KEY (ThreatTypeID, ThreatActorID)
);

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
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Scenario_ActiveIdentity' AND object_id = OBJECT_ID('dbo.Threat_Scenario_Output'))
CREATE UNIQUE INDEX UX_Scenario_ActiveIdentity ON Threat_Scenario_Output(SessionID, IdentityHash) WHERE Superseded = 0;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_PromptLog_Session' AND object_id = OBJECT_ID('dbo.Prompt_Log'))
CREATE INDEX IX_PromptLog_Session ON Prompt_Log(SessionID, SubsystemID);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SubsystemStageState_SessionSubLevel' AND object_id = OBJECT_ID('dbo.Subsystem_Stage_State'))
CREATE INDEX IX_SubsystemStageState_SessionSubLevel ON Subsystem_Stage_State(SessionID, SubsystemID, Level);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Session_CompletedByAsset' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
CREATE INDEX IX_Session_CompletedByAsset ON Scenario_Session(EntityID, AssetID, CompletedAt DESC) WHERE SessionStatus = 'completed';
-- GET /assets/{id}/accepted-scenarios hot path.

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_IdentifiedThreat_SessionSubActive' AND object_id = OBJECT_ID('dbo.Identified_Threat'))
CREATE INDEX IX_IdentifiedThreat_SessionSubActive ON Identified_Threat(SessionID, SubsystemID) WHERE Superseded = 0;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScopedThreat_SessionSubActive' AND object_id = OBJECT_ID('dbo.Scoped_Threat'))
CREATE INDEX IX_ScopedThreat_SessionSubActive ON Scoped_Threat(SessionID, SubsystemID) WHERE Superseded = 0;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioOutput_SessionSubActive' AND object_id = OBJECT_ID('dbo.Threat_Scenario_Output'))
CREATE INDEX IX_ScenarioOutput_SessionSubActive ON Threat_Scenario_Output(SessionID, SubsystemID) WHERE Superseded = 0;

-- ============================================================
-- SECTION 4 — Natural-key guard indexes on the threat-library masters
-- ============================================================

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatType_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Type'))
CREATE UNIQUE INDEX UX_ThreatType_NaturalKey ON Threat_Type(ThreatTypeName, ThreatCategoryID, SectorID) WHERE IsActive = 1 AND IsDeleted = 0;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatCatalogue_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Catalogue'))
CREATE UNIQUE INDEX UX_ThreatCatalogue_NaturalKey ON Threat_Catalogue(ThreatTypeID, ThreatName, SectorID) WHERE IsActive = 1 AND IsDeleted = 0;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatActor_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Actor'))
CREATE UNIQUE INDEX UX_ThreatActor_NaturalKey ON Threat_Actor(ThreatActorName) WHERE IsActive = 1 AND IsDeleted = 0;

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
    'Threat_Scenario_Output','Scenario_Audit','Prompt_Log','Threat_Candidate_Review',
    'Threat_Category','Threat_Type','Threat_Catalogue','Threat_Actor','ThreatType_ThreatActor_Map')
UNION ALL
SELECT TABLE_NAME + '.' + COLUMN_NAME, 1 FROM INFORMATION_SCHEMA.COLUMNS
WHERE (TABLE_NAME = 'ctm_scan_entity' AND COLUMN_NAME IN
        ('data_handled', 'system_managed_by', 'operating_system', 'location', 'target_rto_hours', 'target_rpo_hours'))
   OR (TABLE_NAME = 'onboarding_supporting_systems' AND COLUMN_NAME IN
        ('technology_used', 'vendor_name', 'database_platforms'));
