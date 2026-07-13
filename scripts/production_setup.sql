-- ============================================================================
-- TSG production setup — THE single script to run against a production or
-- dev database. Combines, in order: (0) enable RCSI, (0b) fix a platform
-- table TSG's app code depends on, (1-5) the full TSG schema bootstrap,
-- (6) seed real Config_Threat_Rule scoping data. Idempotent throughout —
-- safe to run once on a fresh database or repeatedly on an existing one.
--
-- This file is a concatenation of 3 already-independently-reviewed scripts
-- plus one new section, kept in sync manually (same "migration triangle"
-- discipline this repo already uses for models.py <-> migrations <->
-- bootstrap_schema.sql — see tests/test_schema_sync.py):
--   - scripts/bootstrap_schema.sql        (Sections 1-5, byte-for-byte)
--   - scripts/add_ctm_scan_entity_columns.sql (Section 0b)
--   - scripts/seed_threat_rules_asset_type.sql (Section 6)
-- If you only need to re-run one piece, those individual files still work
-- standalone — this file exists so you don't have to run 3-4 files by hand.
--
-- NOT included, and must NOT be run in production:
--   scripts/backfill_null_platform_fields_for_testing.sql — explicitly
--   local-dev-only test data for one hardcoded test asset (id=7).
--
-- >>> READ THIS BEFORE YOU RUN IT <<<
-- 1. Section 0 (RCSI) needs EXCLUSIVE database access to apply. If other
--    connections are open it will WAIT, not fail (this script deliberately
--    does not use WITH ROLLBACK IMMEDIATE, which would forcibly kill other
--    users' transactions — that requires your own explicit judgment call,
--    not a default in an unattended script). Run this during a maintenance
--    window with no other active connections, or expect Section 0 to hang
--    until they clear.
--    ONGOING cost once RCSI is on (not just an enable-time concern): every
--    row UPDATE/DELETE keeps its pre-image in tempdb's version store until
--    the oldest active read transaction closes. Under sustained write load
--    (Scenario_Audit is append-only-growing; Prompt_Log.Messages/ResponseText
--    are nvarchar(max) on every LLM call) plus any long-open reader (an idle
--    SSMS session, a slow report query), tempdb can grow unbounded and, if it
--    fills, causes an instance-wide outage — not just for this database.
--    Monitor tempdb free space and watch for long-running read transactions;
--    this script only turns RCSI on, it does not monitor it afterward.
-- 2. Section 2b contains a conditional DROP TABLE + rename sequence (legacy
--    IDENTITY retrofit, a no-op on every database checked so far). SSMS's
--    IntelliSense / "Error List" panel does NOT understand the table comes
--    back under the same name a few lines later — it will show "Invalid
--    object name 'Threat_Type'" (and Catalogue/Actor) as a squiggly-
--    underline warning for the rest of the file, EVEN THOUGH THE SCRIPT
--    RUNS FINE. Real SQL Server errors always look like "Msg 208, Level 16,
--    State 1, Line 530" in the Messages tab, never plain English with no Msg
--    number in the Error List. Prefer `sqlcmd -S <server> -d <database> -E
--    -i production_setup.sql` for a completely clean run with zero
--    IntelliSense noise.
-- 3. Run connected to (or `sqlcmd -d`'d into) the actual target database,
--    not master — Section 0 uses `ALTER DATABASE CURRENT`.
--
-- Prerequisite (not created by this script): the base platform tables
-- (group, onboarding_*, ctm_scan_*) must already exist — TSG reuses another
-- system's schema and never creates it (SDD §7.7).
--
-- Alembic is NOT required for a database managed by this script. Only if
-- alembic will ever manage this database (dev environments): run
-- `alembic stamp 0024` once after this script.
-- ============================================================================

-- ODBC/OLE DB connections default these ON, but not every client does (some
-- sqlcmd builds/connection pools leave QUOTED_IDENTIFIER OFF) — Section 4/5's
-- filtered indexes (WHERE clauses) require QUOTED_IDENTIFIER ON to CREATE, and
-- fail with Msg 1934 if it's off. sqlcmd doesn't abort the script on that
-- error by default, so the index silently never gets created — caught via a
-- throwaway-DB live-execution test (documents/TSG_Gap_Analysis.md §13.14).
-- Session-scoped only; no effect on stored data.
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;

-- ============================================================
-- SECTION 0 — Enable Read Committed Snapshot Isolation (RCSI), once.
-- Required by the app's CAS/lock concurrency design (claim_stage,
-- acquire_lock, status-machine CAS updates all assume readers don't block
-- writers; under default READ COMMITTED locking, the status-board reads and
-- worker CAS updates would contend). Not checked by app/db/invariants.py —
-- this script is what actually turns it on. Guarded so a second run is a
-- fast no-op once RCSI is already on. See warning #1 above about exclusive
-- access.
-- ============================================================

IF NOT EXISTS (SELECT 1 FROM sys.databases WHERE database_id = DB_ID() AND is_read_committed_snapshot_on = 1)
    ALTER DATABASE CURRENT SET READ_COMMITTED_SNAPSHOT ON;

GO

-- ============================================================
-- SECTION 0b — Platform table fix: add asset/subsystem-level columns TSG's
-- app code depends on. ctm_scan_entity/onboarding_supporting_systems are
-- platform tables TSG reuses but never creates (SDD §7.7) —
-- app/pipeline/context.py's asset/subsystem lookups select these on every
-- POST /v1/sessions call. These were added out-of-band on specific databases
-- at different points in this engagement and never propagated to every
-- database, since no TSG migration tracks platform-table schema. Guarded —
-- a no-op if already present. Skipped entirely (not an error) if the table
-- doesn't exist yet — the platform tables are an assumed prerequisite (see
-- header), not something this script creates. Byte-for-byte the same as
-- scripts/add_ctm_scan_entity_columns.sql — see that file for the full
-- per-column rationale/type notes.
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

-- ============================================================
-- SECTION 1 — TSG's own tables, in final (fully-migrated) shape
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
    IdempotencyKey        nvarchar(200)  NULL,              -- M8/[R9]
    SectorIDsJSON         nvarchar(max)  NULL,              -- R6: sector_ids from gather_asset_details
    AssetContextJSON      nvarchar(max)  NULL,              -- 0020: UI-supplied asset-level context
    CreatedAt             datetime2      NULL,
    UpdatedAt             datetime2      NULL,
    CompletedAt           datetime2      NULL
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
    LeaseExpiresAt   datetime2     NULL,                    -- M7/[R1]
    HeartbeatAt      datetime2     NULL,                    -- M7/[R1]
    AttemptCount     int           NOT NULL CONSTRAINT DF_SSS_AttemptCount DEFAULT 0,  -- M8 poison-terminal cap
    ErrorMessage     nvarchar(max) NULL,
    UpdatedAt        datetime2     NOT NULL
);

IF OBJECT_ID('dbo.Identified_Threat', 'U') IS NULL
CREATE TABLE Identified_Threat (
    ThreatID           uniqueidentifier NOT NULL CONSTRAINT PK_Identified_Threat PRIMARY KEY,
    SessionID          uniqueidentifier NOT NULL,
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
    ScopedThreatID  uniqueidentifier NOT NULL CONSTRAINT PK_Scoped_Threat PRIMARY KEY,
    SessionID       uniqueidentifier NOT NULL,
    TenantID        nvarchar(200) NULL,
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
    EntityID             nvarchar(200) NULL,                -- baseline col (models.py) — missed by pre-0015 script versions
    SubsystemID          int           NOT NULL,
    ScopedThreatID       uniqueidentifier NOT NULL,
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
    Stage           nvarchar(20)  NOT NULL,                 -- 'threats'|'scenario'
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
-- SECTION 2 — Threat-library master tables (models.py "Threat library
-- masters" section). Schema only — these tables are EMPTY after this
-- script (except Config_Threat_Rule, seeded in Section 6 below); seeding
-- real Threat_Type/Catalogue/Actor/Category rows is a separate manual task.
-- Threat_Type/Catalogue/Actor PKs are IDENTITY: the R10 promote-on-accept
-- path INSERTs new masters without ids (dal.upsert_threat_* reads the
-- generated key back) — without IDENTITY the first real promotion fails
-- with "Cannot insert NULL into ...ID". Seeding reference data with
-- explicit ids therefore needs SET IDENTITY_INSERT <table> ON around the
-- seed batch. Threat_Category stays a plain int PK — the app never inserts
-- categories (fixed STRIDE set).
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
-- mode documented in Section 2's header. Confirmed a no-op on every real
-- database checked against this script version (Threat_Type/Catalogue/Actor
-- all already IDENTITY) — kept as a defensive path for an unknown database
-- that might still need it, not because any known one does.
--
-- Rebuild-and-preserve-ids: create a new table with IDENTITY, copy every row
-- across with SET IDENTITY_INSERT so no existing id changes (there are no FK
-- constraints to this script's design, so nothing else needs re-linking),
-- drop the old table, rename the new one into place. Section 5's natural-key
-- indexes (dropped along with the old table) are recreated afterward by
-- their own IF NOT EXISTS guards.
--
-- SSMS NOTE (see file header): this block's DROP TABLE is what triggers the
-- harmless IntelliSense "Invalid object name" false positive for every later
-- reference to these 3 tables in this file. It is a static-analysis
-- limitation, not a real error — verify against the Messages tab.
-- ============================================================

-- Each block below is wrapped in its own explicit transaction (TRY/CATCH +
-- ROLLBACK on failure) so a mid-sequence failure (e.g. a row that can't
-- survive the rebuild) leaves the original table exactly as it was instead
-- of a half-renamed/dropped state that breaks the guard's own re-entry
-- condition on the next run — see the finding this closes in
-- documents/TSG_Gap_Analysis.md §13.14.

IF OBJECT_ID('dbo.Threat_Type', 'U') IS NOT NULL
AND COLUMNPROPERTY(OBJECT_ID('dbo.Threat_Type'), 'ThreatTypeID', 'IsIdentity') = 0
BEGIN
    BEGIN TRY
        BEGIN TRAN;
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
        COMMIT TRAN;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRAN;
        THROW;
    END CATCH
END

IF OBJECT_ID('dbo.Threat_Catalogue', 'U') IS NOT NULL
AND COLUMNPROPERTY(OBJECT_ID('dbo.Threat_Catalogue'), 'ThreatCatalogueID', 'IsIdentity') = 0
BEGIN
    BEGIN TRY
        BEGIN TRAN;
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
        COMMIT TRAN;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRAN;
        THROW;
    END CATCH
END

IF OBJECT_ID('dbo.Threat_Actor', 'U') IS NOT NULL
AND COLUMNPROPERTY(OBJECT_ID('dbo.Threat_Actor'), 'ThreatActorID', 'IsIdentity') = 0
BEGIN
    BEGIN TRY
        BEGIN TRAN;
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
        COMMIT TRAN;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRAN;
        THROW;
    END CATCH
END

GO


-- 0021: rename, not add+drop — preserves the data and the UX_Session_ActiveAsset index
-- (SQL Server indexes bind to column_id, not name). Both guards matter: the first skips a
-- DB already renamed, the second refuses to fire if an AssetID column somehow exists too.
IF COL_LENGTH('dbo.Scenario_Session', 'AssetExternalID') IS NOT NULL
AND COL_LENGTH('dbo.Scenario_Session', 'AssetID') IS NULL
    EXEC sp_rename 'dbo.Scenario_Session.AssetExternalID', 'AssetID', 'COLUMN';     -- 0021

IF COL_LENGTH('dbo.Subsystem_Stage_State', 'LeaseExpiresAt') IS NULL
    ALTER TABLE Subsystem_Stage_State ADD LeaseExpiresAt datetime2 NULL;            -- 0007/M7
IF COL_LENGTH('dbo.Subsystem_Stage_State', 'HeartbeatAt') IS NULL
    ALTER TABLE Subsystem_Stage_State ADD HeartbeatAt datetime2 NULL;               -- 0007/M7
IF COL_LENGTH('dbo.Subsystem_Stage_State', 'AttemptCount') IS NULL
    ALTER TABLE Subsystem_Stage_State ADD AttemptCount int NOT NULL CONSTRAINT DF_SSS_AttemptCount DEFAULT 0;  -- 0008/M8

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
-- SECTION 3b — Heal legacy nvarchar(36) GUID columns to uniqueidentifier
-- (0022). Section 1 above already creates every id column as uniqueidentifier,
-- so each guard below is a no-op on a fresh database and a no-op once a
-- healed database has been through this block once. It only fires against a
-- database bootstrapped by an older version of this script that still has
-- nvarchar(36) ids. ALTER COLUMN fails on a column that's part of a PRIMARY
-- KEY or an index, so each block drops the table's PK (and, for
-- Threat_Scenario_Output/Prompt_Log, the extra index keyed on the converting
-- SessionID) before altering, then recreates the PK here; the two dropped
-- indexes are picked back up by Section 4's own IF NOT EXISTS guards below —
-- same "recreated afterward by their own guards" pattern Section 2b uses for
-- Threat_Type/Catalogue/Actor's natural-key indexes.
--
-- Scenario_Session.ActiveTaskID and Scenario_Audit.TaskID are deliberately
-- NOT converted here (unlike Subsystem_Stage_State.ActiveTaskID, which is
-- still live) — both are dropped outright by Section 3c below, so
-- type-converting them first would be wasted work on a column about to be
-- removed. This is why they no longer appear in the two blocks below.
-- ============================================================

-- Each block below is wrapped in its own explicit transaction (TRY/CATCH +
-- ROLLBACK on failure) — a conversion error partway through (e.g. a legacy
-- row whose nvarchar(36) value isn't a valid GUID) previously left the PK
-- dropped and never recreated, which then broke the guard's own re-entry
-- condition on the next run. See documents/TSG_Gap_Analysis.md §13.14.

IF EXISTS (SELECT 1 FROM sys.columns c JOIN sys.types t ON c.user_type_id = t.user_type_id
        WHERE c.object_id = OBJECT_ID('dbo.Scenario_Session') AND c.name = 'SessionID' AND t.name = 'nvarchar')
BEGIN
    BEGIN TRY
        BEGIN TRAN;
        ALTER TABLE Scenario_Session DROP CONSTRAINT PK_Scenario_Session;
        ALTER TABLE Scenario_Session ALTER COLUMN SessionID uniqueidentifier NOT NULL;
        ALTER TABLE Scenario_Session ADD CONSTRAINT PK_Scenario_Session PRIMARY KEY CLUSTERED (SessionID);
        COMMIT TRAN;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRAN;
        THROW;
    END CATCH
END

IF EXISTS (SELECT 1 FROM sys.columns c JOIN sys.types t ON c.user_type_id = t.user_type_id
        WHERE c.object_id = OBJECT_ID('dbo.Subsystem_Stage_State') AND c.name = 'StateID' AND t.name = 'nvarchar')
BEGIN
    BEGIN TRY
        BEGIN TRAN;
        ALTER TABLE Subsystem_Stage_State DROP CONSTRAINT PK_Subsystem_Stage_State;
        ALTER TABLE Subsystem_Stage_State ALTER COLUMN StateID uniqueidentifier NOT NULL;
        ALTER TABLE Subsystem_Stage_State ALTER COLUMN SessionID uniqueidentifier NOT NULL;
        ALTER TABLE Subsystem_Stage_State ALTER COLUMN ActiveTaskID uniqueidentifier NULL;
        ALTER TABLE Subsystem_Stage_State ADD CONSTRAINT PK_Subsystem_Stage_State PRIMARY KEY CLUSTERED (StateID);
        COMMIT TRAN;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRAN;
        THROW;
    END CATCH
END

IF EXISTS (SELECT 1 FROM sys.columns c JOIN sys.types t ON c.user_type_id = t.user_type_id
        WHERE c.object_id = OBJECT_ID('dbo.Identified_Threat') AND c.name = 'ThreatID' AND t.name = 'nvarchar')
BEGIN
    BEGIN TRY
        BEGIN TRAN;
        ALTER TABLE Identified_Threat DROP CONSTRAINT PK_Identified_Threat;
        ALTER TABLE Identified_Threat ALTER COLUMN ThreatID uniqueidentifier NOT NULL;
        ALTER TABLE Identified_Threat ALTER COLUMN SessionID uniqueidentifier NOT NULL;
        ALTER TABLE Identified_Threat ADD CONSTRAINT PK_Identified_Threat PRIMARY KEY CLUSTERED (ThreatID);
        COMMIT TRAN;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRAN;
        THROW;
    END CATCH
END

IF EXISTS (SELECT 1 FROM sys.columns c JOIN sys.types t ON c.user_type_id = t.user_type_id
        WHERE c.object_id = OBJECT_ID('dbo.Scoped_Threat') AND c.name = 'ScopedThreatID' AND t.name = 'nvarchar')
BEGIN
    BEGIN TRY
        BEGIN TRAN;
        ALTER TABLE Scoped_Threat DROP CONSTRAINT PK_Scoped_Threat;
        ALTER TABLE Scoped_Threat ALTER COLUMN ScopedThreatID uniqueidentifier NOT NULL;
        ALTER TABLE Scoped_Threat ALTER COLUMN SessionID uniqueidentifier NOT NULL;
        ALTER TABLE Scoped_Threat ALTER COLUMN ThreatID uniqueidentifier NOT NULL;
        ALTER TABLE Scoped_Threat ADD CONSTRAINT PK_Scoped_Threat PRIMARY KEY CLUSTERED (ScopedThreatID);
        COMMIT TRAN;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRAN;
        THROW;
    END CATCH
END

IF EXISTS (SELECT 1 FROM sys.columns c JOIN sys.types t ON c.user_type_id = t.user_type_id
        WHERE c.object_id = OBJECT_ID('dbo.Threat_Scenario_Output') AND c.name = 'OutputID' AND t.name = 'nvarchar')
BEGIN
    BEGIN TRY
        BEGIN TRAN;
        IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Scenario_ActiveIdentity' AND object_id = OBJECT_ID('dbo.Threat_Scenario_Output'))
            DROP INDEX UX_Scenario_ActiveIdentity ON Threat_Scenario_Output;
        ALTER TABLE Threat_Scenario_Output DROP CONSTRAINT PK_Threat_Scenario_Output;
        ALTER TABLE Threat_Scenario_Output ALTER COLUMN OutputID uniqueidentifier NOT NULL;
        ALTER TABLE Threat_Scenario_Output ALTER COLUMN SessionID uniqueidentifier NOT NULL;
        ALTER TABLE Threat_Scenario_Output ALTER COLUMN ScopedThreatID uniqueidentifier NOT NULL;
        ALTER TABLE Threat_Scenario_Output ADD CONSTRAINT PK_Threat_Scenario_Output PRIMARY KEY CLUSTERED (OutputID);
        COMMIT TRAN;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRAN;
        THROW;
    END CATCH
END

IF EXISTS (SELECT 1 FROM sys.columns c JOIN sys.types t ON c.user_type_id = t.user_type_id
        WHERE c.object_id = OBJECT_ID('dbo.Scenario_Audit') AND c.name = 'AuditID' AND t.name = 'nvarchar')
BEGIN
    BEGIN TRY
        BEGIN TRAN;
        ALTER TABLE Scenario_Audit DROP CONSTRAINT PK_Scenario_Audit;
        ALTER TABLE Scenario_Audit ALTER COLUMN AuditID uniqueidentifier NOT NULL;
        ALTER TABLE Scenario_Audit ALTER COLUMN SessionID uniqueidentifier NOT NULL;
        ALTER TABLE Scenario_Audit ADD CONSTRAINT PK_Scenario_Audit PRIMARY KEY CLUSTERED (AuditID);
        COMMIT TRAN;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRAN;
        THROW;
    END CATCH
END

IF EXISTS (SELECT 1 FROM sys.columns c JOIN sys.types t ON c.user_type_id = t.user_type_id
        WHERE c.object_id = OBJECT_ID('dbo.Prompt_Log') AND c.name = 'LogID' AND t.name = 'nvarchar')
BEGIN
    BEGIN TRY
        BEGIN TRAN;
        IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_PromptLog_Session' AND object_id = OBJECT_ID('dbo.Prompt_Log'))
            DROP INDEX IX_PromptLog_Session ON Prompt_Log;
        ALTER TABLE Prompt_Log DROP CONSTRAINT PK_Prompt_Log;
        ALTER TABLE Prompt_Log ALTER COLUMN LogID uniqueidentifier NOT NULL;
        ALTER TABLE Prompt_Log ALTER COLUMN SessionID uniqueidentifier NOT NULL;
        ALTER TABLE Prompt_Log ADD CONSTRAINT PK_Prompt_Log PRIMARY KEY CLUSTERED (LogID);
        COMMIT TRAN;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRAN;
        THROW;
    END CATCH
END

IF EXISTS (SELECT 1 FROM sys.columns c JOIN sys.types t ON c.user_type_id = t.user_type_id
        WHERE c.object_id = OBJECT_ID('dbo.Threat_Candidate_Review') AND c.name = 'CandidateID' AND t.name = 'nvarchar')
BEGIN
    BEGIN TRY
        BEGIN TRAN;
        ALTER TABLE Threat_Candidate_Review DROP CONSTRAINT PK_Threat_Candidate_Review;
        ALTER TABLE Threat_Candidate_Review ALTER COLUMN CandidateID uniqueidentifier NOT NULL;
        ALTER TABLE Threat_Candidate_Review ALTER COLUMN SessionID uniqueidentifier NOT NULL;
        ALTER TABLE Threat_Candidate_Review ADD CONSTRAINT PK_Threat_Candidate_Review PRIMARY KEY CLUSTERED (CandidateID);
        COMMIT TRAN;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRAN;
        THROW;
    END CATCH
END

GO

-- ============================================================
-- SECTION 3c — Drop 3 confirmed-dead columns (0023, 2026-07-09). Each was
-- verified by a full-repo grep (app/, tests/, migrations/, scripts/,
-- documents/) to be never written and never read anywhere — see
-- migrations/versions/0023_drop_dead_columns.py's docstring for the exact
-- evidence per column. None is part of any index or constraint, so a plain
-- DROP COLUMN needs no PK/index teardown. Guarded — a no-op if the column
-- was already dropped, or never existed (e.g. a database bootstrapped fresh
-- by THIS version of the script, whose Section 1 above never creates them).
-- ============================================================

IF COL_LENGTH('dbo.Scenario_Session', 'ActiveTaskID') IS NOT NULL
    ALTER TABLE Scenario_Session DROP COLUMN ActiveTaskID;
IF COL_LENGTH('dbo.Scenario_Session', 'ErrorMessage') IS NOT NULL
    ALTER TABLE Scenario_Session DROP COLUMN ErrorMessage;
IF COL_LENGTH('dbo.Scenario_Audit', 'TaskID') IS NOT NULL
    ALTER TABLE Scenario_Audit DROP COLUMN TaskID;

GO

-- ============================================================
-- SECTION 4 — TSG's own guard indexes (0004, 0005, 0006, 0009, 0012)
-- ============================================================

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Session_ActiveAsset' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
CREATE UNIQUE INDEX UX_Session_ActiveAsset ON Scenario_Session(EntityID, AssetID) WHERE SessionStatus = 'active';
-- M4: one active session per (entity, asset) — the coarse per-asset lock.

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Session_IdempotencyKey' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
CREATE UNIQUE INDEX UX_Session_IdempotencyKey ON Scenario_Session(EntityID, IdempotencyKey) WHERE IdempotencyKey IS NOT NULL;
-- M8/[R9]: retried POST /v1/sessions with the same key returns the same session.

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Session_Active' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
CREATE NONCLUSTERED INDEX IX_Session_Active ON Scenario_Session(SessionStatus) WHERE SessionStatus = 'active';
-- M8/[R9]: cheap index-only COUNT for the admission-control backpressure ceiling.

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Scenario_ActiveIdentity' AND object_id = OBJECT_ID('dbo.Threat_Scenario_Output'))
CREATE UNIQUE INDEX UX_Scenario_ActiveIdentity ON Threat_Scenario_Output(SessionID, IdentityHash) WHERE Superseded = 0;
-- M6/[R3]: regen + multi-generation retention coexist safely.

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_PromptLog_Session' AND object_id = OBJECT_ID('dbo.Prompt_Log'))
CREATE INDEX IX_PromptLog_Session ON Prompt_Log(SessionID, SubsystemID);

-- Migration 0024 (2026-07-12): every real call site against these 4 tables filters
-- by SessionID(+SubsystemID[+Level/Superseded]); none of them touch the clustered
-- GUID PK, so without these every stage claim/lock, supersede write, and the
-- accepted-scenarios downstream contract's session lookup table-scanned. See
-- migrations/versions/0024_supporting_indexes.py for the full per-table evidence.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SubsystemStageState_SessionSubLevel' AND object_id = OBJECT_ID('dbo.Subsystem_Stage_State'))
CREATE INDEX IX_SubsystemStageState_SessionSubLevel ON Subsystem_Stage_State(SessionID, SubsystemID, Level);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Session_CompletedByAsset' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
CREATE INDEX IX_Session_CompletedByAsset ON Scenario_Session(EntityID, AssetID, CompletedAt DESC) WHERE SessionStatus = 'completed';
-- [R13]: dal.latest_completed_session's hot path — GET /assets/{id}/accepted-scenarios.

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_IdentifiedThreat_SessionSubActive' AND object_id = OBJECT_ID('dbo.Identified_Threat'))
CREATE INDEX IX_IdentifiedThreat_SessionSubActive ON Identified_Threat(SessionID, SubsystemID) WHERE Superseded = 0;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScopedThreat_SessionSubActive' AND object_id = OBJECT_ID('dbo.Scoped_Threat'))
CREATE INDEX IX_ScopedThreat_SessionSubActive ON Scoped_Threat(SessionID, SubsystemID) WHERE Superseded = 0;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioOutput_SessionSubActive' AND object_id = OBJECT_ID('dbo.Threat_Scenario_Output'))
CREATE INDEX IX_ScenarioOutput_SessionSubActive ON Threat_Scenario_Output(SessionID, SubsystemID) WHERE Superseded = 0;

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

-- Supporting (non-unique) index for get_possible_types() in app/pipeline/grounding.py, which
-- filters active Threat_Type rows by category + sector on every grounding call (migration 0018).
-- Not a correctness guard, so verify_startup does NOT check it — a bootstrapped DB missing this
-- index boots happily and just table-scans. Hence it must be created here, not caught at startup.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ThreatType_Category_Active' AND object_id = OBJECT_ID('dbo.Threat_Type'))
CREATE INDEX IX_ThreatType_Category_Active ON Threat_Type(PrimaryThreatCategoryID, SectorID) WHERE IsActive = 1 AND IsDeleted = 0;

GO

-- ============================================================
-- SECTION 6 — Seed real Config_Threat_Rule exclusion rules keyed on
-- asset_type: 12 OT-equipment-specific tech_gate rules. Classification
-- basis: all 71 active Threat_Type rows were reviewed against one rule — a
-- threat is OT-equipment-specific ONLY when its own name hardwires OT field
-- equipment (SCADA, RTU, IED, protection relay/breaker) as the target, so it
-- cannot attach to a non-OT asset. Generic mechanisms (privilege escalation,
-- credential theft, log/audit gaps, DoS, tampering, spoofing) stay universal
-- even when their catalogue examples happen to be OT-flavored.
--
-- Effect once run: a supporting system whose asset_type resolves to
-- anything OTHER than "Operational Technology (OT)" stops getting scenarios
-- written for these 12 threat types — the tech_gate fails, Selected=0,
-- reason "tech_gate:asset_type failed", recorded in Scoped_Threat.FactorsJSON.
--
-- Idempotent — guarded IF NOT EXISTS per row, safe to re-run. Depends on
-- Threat_Type already holding real seeded rows at ids
-- 5/9/15/16/20/23/26/27/28/54/64/68 — true on this engagement's live
-- database via a separate external seed process (Section 2 above creates
-- Threat_Type schema-only, it does not populate these ids). No FK
-- constraints (by design), so these INSERTs still succeed even if that data
-- doesn't exist yet — they're just inert until it does.
--
-- ThreatRuleID is a plain int PK, NOT IDENTITY (app/db/models.py:239 —
-- same "curator-seeded, explicit id" pattern as Threat_Category; confirmed
-- via grep that app/ never INSERTs into this table, only SELECTs it in
-- dal.py:541). Every INSERT below supplies ThreatRuleID explicitly — 1-12.
-- ============================================================

-- DECLARE @RuleValue nvarchar(450) = N'Operational Technology (OT)';
-- DECLARE @CreatedBy nvarchar(200) = N'production_setup.sql';

-- ThreatRuleID 1  / ThreatTypeID 5  — Disruption of RTU availability or responsiveness
-- ThreatRuleID 2  / ThreatTypeID 9  — Exposure of sensitive RTU data
-- ThreatRuleID 3  / ThreatTypeID 15 — Identity spoofing of RTU components
-- ThreatRuleID 4  / ThreatTypeID 16 — Unauthorized modification of SCADA data or configuration
-- ThreatRuleID 5  / ThreatTypeID 20 — Unauthorized privilege escalation within RTU subsystem
-- ThreatRuleID 6  / ThreatTypeID 23 — Unauthorized access to SCADA operational or configuration information
-- ThreatRuleID 7  / ThreatTypeID 26 — Interruption or degradation of SCADA availability from internal actions or failures
-- ThreatRuleID 8  / ThreatTypeID 27 — Unauthorized privilege escalation within the internal SCADA environment
-- ThreatRuleID 9  / ThreatTypeID 28 — Unauthorized modification of RTU data or configuration
-- ThreatRuleID 10 / ThreatTypeID 54 — Device/response suppression (protection-relay/breaker communication)
-- ThreatRuleID 11 / ThreatTypeID 64 — Network-level DoS to SCADA/RTU
-- ThreatRuleID 12 / ThreatTypeID 68 — Telemetry spoofing (forged RTU/IED field telemetry)

-- IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule WHERE ThreatTypeID = 5 AND RuleKey = 'asset_type' AND RuleType = 'tech_gate')
--     INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted, CreateDate, CreatedBy)
--     VALUES (1, 'tech_gate', 5, 'asset_type', @RuleValue, 1, 0, SYSUTCDATETIME(), @CreatedBy);

-- IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule WHERE ThreatTypeID = 9 AND RuleKey = 'asset_type' AND RuleType = 'tech_gate')
--     INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted, CreateDate, CreatedBy)
--     VALUES (2, 'tech_gate', 9, 'asset_type', @RuleValue, 1, 0, SYSUTCDATETIME(), @CreatedBy);

-- IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule WHERE ThreatTypeID = 15 AND RuleKey = 'asset_type' AND RuleType = 'tech_gate')
--     INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted, CreateDate, CreatedBy)
--     VALUES (3, 'tech_gate', 15, 'asset_type', @RuleValue, 1, 0, SYSUTCDATETIME(), @CreatedBy);

-- IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule WHERE ThreatTypeID = 16 AND RuleKey = 'asset_type' AND RuleType = 'tech_gate')
--     INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted, CreateDate, CreatedBy)
--     VALUES (4, 'tech_gate', 16, 'asset_type', @RuleValue, 1, 0, SYSUTCDATETIME(), @CreatedBy);

-- IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule WHERE ThreatTypeID = 20 AND RuleKey = 'asset_type' AND RuleType = 'tech_gate')
--     INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted, CreateDate, CreatedBy)
--     VALUES (5, 'tech_gate', 20, 'asset_type', @RuleValue, 1, 0, SYSUTCDATETIME(), @CreatedBy);

-- IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule WHERE ThreatTypeID = 23 AND RuleKey = 'asset_type' AND RuleType = 'tech_gate')
--     INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted, CreateDate, CreatedBy)
--     VALUES (6, 'tech_gate', 23, 'asset_type', @RuleValue, 1, 0, SYSUTCDATETIME(), @CreatedBy);

-- IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule WHERE ThreatTypeID = 26 AND RuleKey = 'asset_type' AND RuleType = 'tech_gate')
--     INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted, CreateDate, CreatedBy)
--     VALUES (7, 'tech_gate', 26, 'asset_type', @RuleValue, 1, 0, SYSUTCDATETIME(), @CreatedBy);

-- IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule WHERE ThreatTypeID = 27 AND RuleKey = 'asset_type' AND RuleType = 'tech_gate')
--     INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted, CreateDate, CreatedBy)
--     VALUES (8, 'tech_gate', 27, 'asset_type', @RuleValue, 1, 0, SYSUTCDATETIME(), @CreatedBy);

-- IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule WHERE ThreatTypeID = 28 AND RuleKey = 'asset_type' AND RuleType = 'tech_gate')
--     INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted, CreateDate, CreatedBy)
--     VALUES (9, 'tech_gate', 28, 'asset_type', @RuleValue, 1, 0, SYSUTCDATETIME(), @CreatedBy);

-- IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule WHERE ThreatTypeID = 54 AND RuleKey = 'asset_type' AND RuleType = 'tech_gate')
--     INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted, CreateDate, CreatedBy)
--     VALUES (10, 'tech_gate', 54, 'asset_type', @RuleValue, 1, 0, SYSUTCDATETIME(), @CreatedBy);

-- IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule WHERE ThreatTypeID = 64 AND RuleKey = 'asset_type' AND RuleType = 'tech_gate')
--     INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted, CreateDate, CreatedBy)
--     VALUES (11, 'tech_gate', 64, 'asset_type', @RuleValue, 1, 0, SYSUTCDATETIME(), @CreatedBy);

-- IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule WHERE ThreatTypeID = 68 AND RuleKey = 'asset_type' AND RuleType = 'tech_gate')
--     INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted, CreateDate, CreatedBy)
--     VALUES (12, 'tech_gate', 68, 'asset_type', @RuleValue, 1, 0, SYSUTCDATETIME(), @CreatedBy);

-- -- Verify
-- SELECT ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, CreatedBy
-- FROM Config_Threat_Rule
-- WHERE RuleKey = 'asset_type'
-- ORDER BY ThreatTypeID;
