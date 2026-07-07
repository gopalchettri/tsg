-- ============================================================================
-- TSG bootstrap schema — THE one-stop production script for the TSG database.
-- Consolidates the baseline TSG tables + migrations 0002-0017 into one
-- idempotent T-SQL script. (0017 is a legacy-data vocabulary rename on
-- Scenario_Audit.EventType — no schema/DDL change, so a fresh bootstrap DB
-- has nothing to apply for it; it only matters when healing an existing DB.) Production databases are stood up AND upgraded by
-- re-running this script alone; alembic is the dev-environment mechanism.
--
-- Contract (safe to re-run any time, from any prior version of this script):
--   * creates any missing table (final, fully-migrated shape);
--   * adds any missing column to a table that already exists (Section 3 —
--     the migration chain's ALTER logic, synced in);
--   * creates any missing index;
--   * never drops anything, never modifies existing rows or data.
--
-- Creates TSG's own pipeline tables AND the threat-library master tables
-- (Threat_Category/Type/Catalogue/Actor + the type-actor map) — the latter
-- are schema-only, seeded externally, not populated here. Assumes only the
-- ASSET/ONBOARDING platform tables already exist (group, onboarding_*,
-- ctm_scan_*) — a different system's schema TSG reuses but does not create
-- (SDD §7.7). No FOREIGN KEYs by design — ids are app-enforced (SDD §7.7).
--
-- Run with SSMS or sqlcmd — the script uses GO batch separators so Section 3's
-- column additions are committed before Section 4's indexes compile.
--
-- Alembic is NOT required for a database managed by this script. Only if
-- alembic will ever manage this database (dev environments): run
-- `alembic stamp 0017` once after this script (its DDL matches migrations
-- 0002-0017 exactly). If newer migrations exist by the time you're reading
-- this (check migrations/versions/ against the range above), stamp 0017
-- first, then run `alembic upgrade head` to pick up anything added since.
--
-- tests/test_schema_sync.py asserts every models.py column appears in the
-- CREATE TABLE blocks below — keep both in lockstep.
-- ============================================================================

-- ============================================================
-- SECTION 1 — TSG's own tables, in final (fully-migrated) shape
-- ============================================================

IF OBJECT_ID('dbo.Scenario_Session', 'U') IS NULL
CREATE TABLE Scenario_Session (
    SessionID             nvarchar(36)   NOT NULL CONSTRAINT PK_Scenario_Session PRIMARY KEY,
    TenantID              nvarchar(200)  NOT NULL,
    EntityID              nvarchar(200)  NOT NULL,          -- [R7] isolation key
    UserID                nvarchar(200)  NULL,
    AssetName             nvarchar(300)  NOT NULL,
    AssetExternalID       nvarchar(200)  NOT NULL,          -- [R7] isolation key
    SessionStatus         nvarchar(20)   NOT NULL,
    CurrentStage          nvarchar(32)   NOT NULL,
    StageStatus           nvarchar(20)   NOT NULL,
    Mode                  nvarchar(20)   NOT NULL,
    CurrentSubsystemIndex int            NULL,
    SubsystemsJSON        nvarchar(max)  NOT NULL,
    ActiveTaskID          nvarchar(36)   NULL,
    ErrorMessage          nvarchar(max)  NULL,
    IdempotencyKey        nvarchar(200)  NULL,              -- M8/[R9]
    SectorIDsJSON         nvarchar(max)  NULL,              -- R6: sector_ids from gather_asset_details
    CreatedAt             datetime2      NULL,
    UpdatedAt             datetime2      NULL,
    CompletedAt           datetime2      NULL
);

IF OBJECT_ID('dbo.Subsystem_Stage_State', 'U') IS NULL
CREATE TABLE Subsystem_Stage_State (
    StateID          nvarchar(36)  NOT NULL CONSTRAINT PK_Subsystem_Stage_State PRIMARY KEY,
    SessionID        nvarchar(36)  NOT NULL,
    TenantID         nvarchar(200) NULL,
    EntityID         nvarchar(200) NULL,
    SubsystemID      int           NOT NULL,
    Level            nvarchar(20)  NOT NULL,                -- PROFILE|THREATS|SCENARIOS|_LOCK
    Status           nvarchar(20)  NOT NULL,
    GenerationEpoch  int           NOT NULL,
    ActiveTaskID     nvarchar(36)  NULL,
    LeaseExpiresAt   datetime2     NULL,                    -- M7/[R1]
    HeartbeatAt      datetime2     NULL,                    -- M7/[R1]
    AttemptCount     int           NOT NULL CONSTRAINT DF_SSS_AttemptCount DEFAULT 0,  -- M8 poison-terminal cap
    ErrorMessage     nvarchar(max) NULL,
    UpdatedAt        datetime2     NOT NULL
);

IF OBJECT_ID('dbo.Subsystem_Profile', 'U') IS NULL
CREATE TABLE Subsystem_Profile (
    ProfileID       nvarchar(36)  NOT NULL CONSTRAINT PK_Subsystem_Profile PRIMARY KEY,
    SessionID       nvarchar(36)  NOT NULL,
    TenantID        nvarchar(200) NULL,
    EntityID        nvarchar(200) NULL,
    SubsystemID     int           NOT NULL,
    ProfileJSON     nvarchar(max) NOT NULL,
    ValidationJSON  nvarchar(max) NULL,                     -- 0011/§5.2
    Accepted        int           NOT NULL,
    Superseded      int           NOT NULL,
    CreatedAt       datetime2     NULL
);

IF OBJECT_ID('dbo.Identified_Threat', 'U') IS NULL
CREATE TABLE Identified_Threat (
    ThreatID           nvarchar(36)  NOT NULL CONSTRAINT PK_Identified_Threat PRIMARY KEY,
    SessionID          nvarchar(36)  NOT NULL,
    TenantID           nvarchar(200) NULL,
    EntityID           nvarchar(200) NULL,                  -- baseline col (models.py) — missed by pre-0015 script versions
    SubsystemID        int           NOT NULL,
    ThreatCategory     nvarchar(200) NOT NULL,
    ThreatType         nvarchar(300) NOT NULL,
    ThreatName         nvarchar(500) NULL,
    ThreatActorsJSON   nvarchar(max) NULL,
    LibraryThreatType  nvarchar(300) NULL,
    LibraryThreatName  nvarchar(500) NULL,
    ThreatTypeID       int           NULL,                  -- M1 match-by-id
    ThreatCatalogueID  int           NULL,                  -- M1 match-by-id
    GroundingStatus    nvarchar(20)  NOT NULL,
    GroundingScore     float         NULL,
    Superseded         int           NOT NULL,
    CreatedAt          datetime2     NULL
);

IF OBJECT_ID('dbo.Scoped_Threat', 'U') IS NULL
CREATE TABLE Scoped_Threat (
    ScopedThreatID  nvarchar(36)  NOT NULL CONSTRAINT PK_Scoped_Threat PRIMARY KEY,
    SessionID       nvarchar(36)  NOT NULL,
    TenantID        nvarchar(200) NULL,
    SubsystemID     int           NOT NULL,
    ThreatID        nvarchar(36)  NOT NULL,
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
    OutputID             nvarchar(36)  NOT NULL CONSTRAINT PK_Threat_Scenario_Output PRIMARY KEY,
    SessionID            nvarchar(36)  NOT NULL,
    TenantID             nvarchar(200) NULL,
    EntityID             nvarchar(200) NULL,                -- baseline col (models.py) — missed by pre-0015 script versions
    SubsystemID          int           NOT NULL,
    ScopedThreatID       nvarchar(36)  NOT NULL,
    Status               nvarchar(20)  NOT NULL,
    ScenarioJSON         nvarchar(max) NULL,
    ValidationJSON       nvarchar(max) NULL,
    AcceptedSubsetJSON   nvarchar(max) NULL,
    Accepted             int           NOT NULL,
    Superseded           int           NOT NULL,
    IdentityHash         nvarchar(64)  NULL,                -- M6: sha256(SessionID|ScopedThreatID)
    GenerationEpoch      int           NOT NULL,
    ErrorMessage         nvarchar(max) NULL,
    CreatedAt            datetime2     NULL
);

IF OBJECT_ID('dbo.Scenario_Audit', 'U') IS NULL
CREATE TABLE Scenario_Audit (
    AuditID          nvarchar(36)  NOT NULL CONSTRAINT PK_Scenario_Audit PRIMARY KEY,
    SessionID        nvarchar(36)  NOT NULL,
    TenantID         nvarchar(200) NULL,
    EntityID         nvarchar(200) NULL,
    Stage            nvarchar(32)  NULL,
    SubsystemID      int           NULL,
    EventType        nvarchar(40)  NOT NULL,
    Decision         nvarchar(30)  NULL,
    Granularity      nvarchar(20)  NULL,
    ThreatTypeRefID  int           NULL,
    ActorUserID      nvarchar(200) NULL,
    TaskID           nvarchar(36)  NULL,
    DetailJSON       nvarchar(max) NULL,
    CreatedAt        datetime2     NOT NULL
);

IF OBJECT_ID('dbo.Prompt_Log', 'U') IS NULL
CREATE TABLE Prompt_Log (
    LogID           nvarchar(36)  NOT NULL CONSTRAINT PK_Prompt_Log PRIMARY KEY,
    SessionID       nvarchar(36)  NOT NULL,
    TenantID        nvarchar(200) NULL,
    EntityID        nvarchar(200) NULL,
    UserID          nvarchar(200) NULL,
    SubsystemID     int           NOT NULL,
    Stage           nvarchar(20)  NOT NULL,                 -- 'profile'|'threats'|'scenario'
    PromptVersion   nvarchar(20)  NOT NULL,
    Messages        nvarchar(max) NOT NULL,                 -- already-redacted/allowlisted prompt sent
    ResponseText    nvarchar(max) NULL,                     -- raw LLM reply, incl. malformed ones
    Model           nvarchar(200) NULL,
    ModelVersion    nvarchar(100) NULL,
    ParseSucceeded  bit           NOT NULL,
    CreatedAt       datetime2     NOT NULL
);

IF OBJECT_ID('dbo.Threat_Candidate_Review', 'U') IS NULL
CREATE TABLE Threat_Candidate_Review (   -- M9/R10: audit ledger of promotion events (0014)
    CandidateID       nvarchar(36)  NOT NULL CONSTRAINT PK_Threat_Candidate_Review PRIMARY KEY,
    TenantID          nvarchar(200) NOT NULL,
    EntityID          nvarchar(200) NULL,
    SessionID         nvarchar(36)  NOT NULL,
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
-- SECTION 2 — Threat-library master tables (models.py "Threat library
-- masters" section). Schema only — these tables are EMPTY after this
-- script; seeding real Threat_Type/Catalogue/Actor/Category rows is a
-- separate manual task. Threat_Type/Catalogue/Actor PKs are IDENTITY: the
-- R10 promote-on-accept path INSERTs new masters without ids
-- (dal.upsert_threat_* reads the generated key back) — without IDENTITY the
-- first real promotion fails with "Cannot insert NULL into ...ID". Seeding
-- reference data with explicit ids therefore needs
-- SET IDENTITY_INSERT <table> ON around the seed batch. Threat_Category
-- stays a plain int PK — the app never inserts categories (fixed STRIDE set).
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
    PrimaryThreatCategoryID  int            NULL,
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

IF OBJECT_ID('dbo.Config_Threat_Rule', 'U') IS NULL
CREATE TABLE Config_Threat_Rule (   -- R12/0016: scoping rules (SDD §5.4/Appendix A.1) — curator-seeded config, schema only here
    ThreatRuleID  int            NOT NULL CONSTRAINT PK_Config_Threat_Rule PRIMARY KEY,
    RuleType      nvarchar(50)   NOT NULL,               -- tech_gate | relevance_flag | relevance_context_value
    ThreatTypeID  int            NOT NULL,               -- app-enforced FK -> Threat_Type
    RuleKey       nvarchar(200)  NOT NULL,               -- e.g. 'internet_facing' (scoping.py allowlist)
    RuleValue     nvarchar(450)  NULL,                   -- optional expected value
    Metadata      nvarchar(max)  NULL,                   -- extra rule config (JSON), e.g. {"weight": 15}
    CreateDate    datetime2      NULL,
    CreatedBy     nvarchar(200)  NULL,
    UpdateDate    datetime2      NULL,
    UpdatedBy     nvarchar(200)  NULL,
    IsActive      bit            NOT NULL,
    IsDeleted     bit            NOT NULL
);

GO

-- ============================================================
-- SECTION 2b — Retrofit IDENTITY onto a pre-existing Threat_Type/Catalogue/
-- Actor table that predates this script's IDENTITY declaration above (the
-- CREATE TABLE guards in Section 2 only fire for a table that doesn't exist
-- yet, so an older table never picks up IDENTITY just by re-running this
-- script). Each block below is a no-op unless that exact table exists AND
-- is still missing IDENTITY — same "Cannot insert NULL into ...ID" failure
-- mode documented in Section 2's header. Rebuild-and-preserve-ids: create a
-- new table with IDENTITY, copy every row across with SET IDENTITY_INSERT
-- so no existing id changes (there are no FK constraints to this script's
-- design, so nothing else needs re-linking), drop the old table, rename the
-- new one into place. Section 5's natural-key indexes (dropped along with
-- the old table) are recreated afterward by their own IF NOT EXISTS guards.
-- ============================================================

IF OBJECT_ID('dbo.Threat_Type', 'U') IS NOT NULL
   AND COLUMNPROPERTY(OBJECT_ID('dbo.Threat_Type'), 'ThreatTypeID', 'IsIdentity') = 0
BEGIN
    CREATE TABLE Threat_Type_New (
        ThreatTypeID             int            IDENTITY(1,1) NOT NULL CONSTRAINT PK_Threat_Type_New PRIMARY KEY,
        ThreatTypeName           nvarchar(300)  NOT NULL,
        Description              nvarchar(max)  NULL,
        SectorID                 int            NULL,
        PrimaryThreatCategoryID  int            NULL,
        IsActive                 bit            NOT NULL,
        IsDeleted                bit            NOT NULL
    );
    SET IDENTITY_INSERT Threat_Type_New ON;
    INSERT INTO Threat_Type_New (ThreatTypeID, ThreatTypeName, Description, SectorID, PrimaryThreatCategoryID, IsActive, IsDeleted)
    SELECT ThreatTypeID, ThreatTypeName, Description, SectorID, PrimaryThreatCategoryID, IsActive, IsDeleted FROM Threat_Type;
    SET IDENTITY_INSERT Threat_Type_New OFF;
    DROP TABLE Threat_Type;
    EXEC sp_rename 'Threat_Type_New', 'Threat_Type';
    EXEC sp_rename 'PK_Threat_Type_New', 'PK_Threat_Type';
END

IF OBJECT_ID('dbo.Threat_Catalogue', 'U') IS NOT NULL
   AND COLUMNPROPERTY(OBJECT_ID('dbo.Threat_Catalogue'), 'ThreatCatalogueID', 'IsIdentity') = 0
BEGIN
    CREATE TABLE Threat_Catalogue_New (
        ThreatCatalogueID  int            IDENTITY(1,1) NOT NULL CONSTRAINT PK_Threat_Catalogue_New PRIMARY KEY,
        ThreatTypeID       int            NOT NULL,
        ThreatName         nvarchar(500)  NOT NULL,
        Description        nvarchar(max)  NULL,
        SectorID           int            NULL,
        IsActive           bit            NOT NULL,
        IsDeleted          bit            NOT NULL
    );
    SET IDENTITY_INSERT Threat_Catalogue_New ON;
    INSERT INTO Threat_Catalogue_New (ThreatCatalogueID, ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted)
    SELECT ThreatCatalogueID, ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted FROM Threat_Catalogue;
    SET IDENTITY_INSERT Threat_Catalogue_New OFF;
    DROP TABLE Threat_Catalogue;
    EXEC sp_rename 'Threat_Catalogue_New', 'Threat_Catalogue';
    EXEC sp_rename 'PK_Threat_Catalogue_New', 'PK_Threat_Catalogue';
END

IF OBJECT_ID('dbo.Threat_Actor', 'U') IS NOT NULL
   AND COLUMNPROPERTY(OBJECT_ID('dbo.Threat_Actor'), 'ThreatActorID', 'IsIdentity') = 0
BEGIN
    CREATE TABLE Threat_Actor_New (
        ThreatActorID    int            IDENTITY(1,1) NOT NULL CONSTRAINT PK_Threat_Actor_New PRIMARY KEY,
        ThreatActorName  nvarchar(200)  NOT NULL,
        IsCapable        int            NOT NULL,
        IsActive         bit            NOT NULL,
        IsDeleted        bit            NOT NULL
    );
    SET IDENTITY_INSERT Threat_Actor_New ON;
    INSERT INTO Threat_Actor_New (ThreatActorID, ThreatActorName, IsCapable, IsActive, IsDeleted)
    SELECT ThreatActorID, ThreatActorName, IsCapable, IsActive, IsDeleted FROM Threat_Actor;
    SET IDENTITY_INSERT Threat_Actor_New OFF;
    DROP TABLE Threat_Actor;
    EXEC sp_rename 'Threat_Actor_New', 'Threat_Actor';
    EXEC sp_rename 'PK_Threat_Actor_New', 'PK_Threat_Actor';
END

GO

-- ============================================================
-- SECTION 3 — Column upgrades for tables that already existed (the
-- migration chain's ALTER logic, synced in). Each guard is a no-op on a
-- fresh database (Section 1 created the column) and heals a database stood
-- up from an older version of this script. This is what makes re-running
-- the latest script the complete production upgrade path.
--
-- NOTE: whole NEW tables (e.g. Prompt_Log/0012, Threat_Candidate_Review/0014,
-- Config_Threat_Rule/0016) need NO entry here — their IF OBJECT_ID guards in
-- Sections 1-2 already create them on re-run against an older DB. This section
-- is only for columns added to a table whose CREATE gets skipped because the
-- table already exists.
--
-- Deliberately absent: 0003's ALTER-to-NOT-NULL (every version of this
-- script ever shipped already created those columns NOT NULL) and 0006's
-- drop-of-old-unfiltered-IdentityHash-index cleanup (only pre-0006
-- EYShield-baseline DBs had that index; this script never targets those).
-- ============================================================

IF COL_LENGTH('dbo.Scenario_Session', 'IdempotencyKey') IS NULL
    ALTER TABLE Scenario_Session ADD IdempotencyKey nvarchar(200) NULL;             -- 0009/M8
IF COL_LENGTH('dbo.Scenario_Session', 'SectorIDsJSON') IS NULL
    ALTER TABLE Scenario_Session ADD SectorIDsJSON nvarchar(max) NULL;              -- 0013/R6

IF COL_LENGTH('dbo.Subsystem_Stage_State', 'LeaseExpiresAt') IS NULL
    ALTER TABLE Subsystem_Stage_State ADD LeaseExpiresAt datetime2 NULL;            -- 0007/M7
IF COL_LENGTH('dbo.Subsystem_Stage_State', 'HeartbeatAt') IS NULL
    ALTER TABLE Subsystem_Stage_State ADD HeartbeatAt datetime2 NULL;               -- 0007/M7
IF COL_LENGTH('dbo.Subsystem_Stage_State', 'AttemptCount') IS NULL
    ALTER TABLE Subsystem_Stage_State ADD AttemptCount int NOT NULL CONSTRAINT DF_SSS_AttemptCount DEFAULT 0;  -- 0008/M8

IF COL_LENGTH('dbo.Subsystem_Profile', 'ValidationJSON') IS NULL
    ALTER TABLE Subsystem_Profile ADD ValidationJSON nvarchar(max) NULL;            -- 0011/§5.2

IF COL_LENGTH('dbo.Identified_Threat', 'ThreatTypeID') IS NULL
    ALTER TABLE Identified_Threat ADD ThreatTypeID int NULL;                        -- 0002/M1
IF COL_LENGTH('dbo.Identified_Threat', 'ThreatCatalogueID') IS NULL
    ALTER TABLE Identified_Threat ADD ThreatCatalogueID int NULL;                   -- 0002/M1
IF COL_LENGTH('dbo.Identified_Threat', 'EntityID') IS NULL
    ALTER TABLE Identified_Threat ADD EntityID nvarchar(200) NULL;                  -- 0015: baseline col missed by pre-0015 script versions

IF COL_LENGTH('dbo.Threat_Scenario_Output', 'EntityID') IS NULL
    ALTER TABLE Threat_Scenario_Output ADD EntityID nvarchar(200) NULL;             -- 0015: baseline col missed by pre-0015 script versions

GO

-- ============================================================
-- SECTION 4 — TSG's own guard indexes (0004, 0005, 0006, 0009, 0012)
-- ============================================================

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Session_ActiveAsset' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
CREATE UNIQUE INDEX UX_Session_ActiveAsset ON Scenario_Session(EntityID, AssetExternalID) WHERE SessionStatus = 'active';
-- M4: one active session per (entity, asset) — the coarse per-asset lock.

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Session_IdempotencyKey' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
CREATE UNIQUE INDEX UX_Session_IdempotencyKey ON Scenario_Session(EntityID, IdempotencyKey) WHERE IdempotencyKey IS NOT NULL;
-- M8/[R9]: retried POST /v1/sessions with the same key returns the same session.

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Session_Active' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
CREATE NONCLUSTERED INDEX IX_Session_Active ON Scenario_Session(SessionStatus) WHERE SessionStatus = 'active';
-- M8/[R9]: cheap index-only COUNT for the admission-control backpressure ceiling.

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Profile_Active' AND object_id = OBJECT_ID('dbo.Subsystem_Profile'))
CREATE UNIQUE INDEX UX_Profile_Active ON Subsystem_Profile(SessionID, SubsystemID) WHERE Superseded = 0;
-- M5/[R3]: one active profile per (session, subsystem) — idempotent Stage-1 writes.

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Scenario_ActiveIdentity' AND object_id = OBJECT_ID('dbo.Threat_Scenario_Output'))
CREATE UNIQUE INDEX UX_Scenario_ActiveIdentity ON Threat_Scenario_Output(SessionID, IdentityHash) WHERE Superseded = 0;
-- M6/[R3]: regen + multi-generation retention coexist safely.

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_PromptLog_Session' AND object_id = OBJECT_ID('dbo.Prompt_Log'))
CREATE INDEX IX_PromptLog_Session ON Prompt_Log(SessionID, SubsystemID);

-- ============================================================
-- SECTION 5 — Natural-key guard indexes on the threat-library masters
-- (M2 / migration 0010). Safe promotion — no duplicate masters.
-- ============================================================

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatType_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Type'))
CREATE UNIQUE INDEX UX_ThreatType_NaturalKey ON Threat_Type(ThreatTypeName, PrimaryThreatCategoryID, SectorID) WHERE IsActive = 1 AND IsDeleted = 0;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatCatalogue_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Catalogue'))
CREATE UNIQUE INDEX UX_ThreatCatalogue_NaturalKey ON Threat_Catalogue(ThreatTypeID, ThreatName, SectorID) WHERE IsActive = 1 AND IsDeleted = 0;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatActor_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Actor'))
CREATE UNIQUE INDEX UX_ThreatActor_NaturalKey ON Threat_Actor(ThreatActorName) WHERE IsActive = 1 AND IsDeleted = 0;
