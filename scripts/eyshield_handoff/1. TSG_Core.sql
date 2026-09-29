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
-- Required so reads never block behind a writer (CAS/lock design), and NOT
-- advisory: app/db/invariants.py::_assert_rcsi_enabled raises
-- StartupInvariantError while it is off, so neither the API nor any Celery
-- worker boots. A run that leaves it off has deployed nothing.
--
-- WHY THIS IS NO LONGER `SET SINGLE_USER / SET RCSI / SET MULTI_USER`.
-- That was THREE statements, and the middle one can fail. SINGLE_USER succeeds
-- and evicts every other session; one of those sessions reconnects and takes the
-- single permitted connection; `SET READ_COMMITTED_SNAPSHOT ON` then fails with
-- "database is in use", the batch aborts, and `SET MULTI_USER` NEVER RUNS. The
-- database is left SINGLE_USER — and this database also holds the platform tables
-- TSG only reads (ctm_scan_*, onboarding_*, [user], option, option_value), so
-- every OTHER application on it is locked out until a DBA restores MULTI_USER by
-- hand. An outage caused by a schema script, announced as one aborted batch in
-- the Messages pane.
--
-- `SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE` performs the same
-- eviction in ONE statement: either the setting changes or nothing does. There is
-- no intermediate state to be stranded in, so there is nothing to restore — which
-- is why the fix is to delete the dance, not to add a rescue path to it.
--
-- READ sys.databases, NEVER DATABASEPROPERTYEX. That property returned NULL on a
-- SQL Server 2022 Express instance whose setting was demonstrably ON, and every
-- comparison against NULL is UNKNOWN, so the check silently decided nothing.
-- is_read_committed_snapshot_on is a non-nullable bit present for every database.
-- A row this script cannot READ is reported as its own case and never ALTERed
-- blind, because the command it would otherwise run disconnects people.
--
-- @disconnect_others is the ONE LINE in this file you are meant to edit. It is 1
-- because the setting is required. Set it to 0 to be told who is connected and
-- have the script stop instead of interrupting them.
--
-- KEPT IN STEP ACROSS THE DEPLOY PATHS. The same block, for the same reasons, is
-- in TSG_Core_UAT.sql, in scripts/tsg_remediation_tables.sql and in
-- scripts/tsg_script/00_validation/002_enable_isolation_level.sql.
-- tests/test_tsg_script_package.py::test_no_deploy_script_takes_the_database_single_user
-- fails the build if any deploy script goes back to the SINGLE_USER dance, and
-- ::test_the_package_sets_every_database_setting_it_validates reads all four.
-- ============================================================

DECLARE @disconnect_others bit = 1;

DECLARE @rcsi bit = (SELECT d.is_read_committed_snapshot_on
                     FROM sys.databases d WHERE d.database_id = DB_ID());

IF @rcsi = 1
    PRINT ' [EXISTS]  READ_COMMITTED_SNAPSHOT is already ON. Nothing was changed.';

ELSE IF @rcsi IS NULL
BEGIN
    PRINT ' [ERROR]   Could not read this database''s isolation setting - no visible';
    PRINT '           sys.databases row for DB_ID(). NOTHING was changed. Check the';
    PRINT '           setting by hand before deploying, and do NOT run the ALTER blind:';
    PRINT '           the form that always succeeds disconnects every open session.';
    RAISERROR('READ_COMMITTED_SNAPSHOT could not be read - stopping before any change.', 16, 1);
END

ELSE
BEGIN
    IF @disconnect_others = 1
        PRINT ' [WARNING] READ_COMMITTED_SNAPSHOT is OFF. Every OTHER session on this database is about to be disconnected and its in-flight work rolled back.';
    ELSE
        PRINT ' [INFO]    READ_COMMITTED_SNAPSHOT is OFF. Turning it on without waiting for anybody, and without disconnecting anybody.';

    -- Two literal statements rather than one built with sp_executesql: dynamic SQL
    -- would spare the IF, but it would also hide the destructive form inside a
    -- string, and a schema script has to let a reviewer SEE what it can do.
    BEGIN TRY
        IF @disconnect_others = 1
            ALTER DATABASE CURRENT SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE;
        ELSE
            ALTER DATABASE CURRENT SET READ_COMMITTED_SNAPSHOT ON WITH NO_WAIT;
        PRINT ' [FIXED]   READ_COMMITTED_SNAPSHOT is now ON.';
    END TRY
    BEGIN CATCH
        PRINT ' [FAIL]    READ_COMMITTED_SNAPSHOT could not be turned on. NOTHING was';
        PRINT '           changed, no session was disconnected, and the database is NOT';
        PRINT '           single-user.';
        PRINT '           SQL Server said (' + CAST(ERROR_NUMBER() AS varchar(10)) + '): '
              + ERROR_MESSAGE();

        -- Branch on what is OBSERVABLE, never on the error number. A live run with one
        -- other session connected raised 5069, which no plausible hand-typed list of
        -- "database in use" codes contained, so the operator was sent after a
        -- permissions problem they did not have. sys.dm_exec_sessions answers the real
        -- question and cannot go stale.
        IF EXISTS (SELECT 1 FROM sys.dm_exec_sessions s
                   WHERE s.database_id = DB_ID() AND s.session_id <> @@SPID)
        BEGIN
            -- PRINTed, not SELECTed: SSMS sends a SELECT to the Results grid and PRINT to
            -- the Messages pane, and the operator reading the failure is in Messages.
            DECLARE @others int, @who nvarchar(max) = N'';
            SELECT @others = COUNT(*) FROM sys.dm_exec_sessions s
            WHERE  s.database_id = DB_ID() AND s.session_id <> @@SPID;
            SELECT @who = @who + CHAR(13) + CHAR(10) + N'               ' +
                          RIGHT(N'      ' + CAST(s.session_id AS nvarchar(10)), 6) + N'  ' +
                          LEFT(ISNULL(s.login_name, N'?') + SPACE(30), 30) + N'  ' +
                          LEFT(ISNULL(s.host_name, N'?') + SPACE(18), 18) + N'  ' +
                          LEFT(ISNULL(s.program_name, N'?') + SPACE(30), 30)
            FROM   sys.dm_exec_sessions s
            WHERE  s.database_id = DB_ID() AND s.session_id <> @@SPID;
            PRINT '           Somebody else is connected to this database - '
                  + CAST(@others AS varchar(10)) + ' other session(s):';
            PRINT '               SPID  LOGIN                           HOST                PROGRAM';
            PRINT @who;
            -- PRINT stops at 4000 characters; the COUNT above is always exact.
            IF @others > 40
                PRINT '           (the list above is cut off by PRINT; the count is exact)';
            PRINT '           Two ways forward:';
            PRINT '             1. Ask them to disconnect, then run this script again.';
            PRINT '             2. In an agreed window set @disconnect_others to 1 at the top';
            PRINT '                of THIS script and run it again. It then disconnects the';
            PRINT '                sessions above and rolls back their in-flight work.';
        END
        ELSE
        BEGIN
            PRINT '           No other session is visible from this login, so this is most';
            PRINT '           likely a permissions problem: no ALTER permission on the';
            PRINT '           database, or no VIEW SERVER STATE - and without that second one';
            PRINT '           the sessions holding it are HIDDEN from the listing above rather';
            PRINT '           than absent. Ask a DBA to run:';
            PRINT '           ALTER DATABASE [' + DB_NAME() + '] SET READ_COMMITTED_SNAPSHOT ON;';
        END

        RAISERROR('READ_COMMITTED_SNAPSHOT is OFF and could not be turned on - stopping.', 16, 1);
    END CATCH
END

GO

-- ---------------------------------------------------------------------------
-- Threat_Scenario_Output -> Threat_Scenario, plus the five object names reading
-- "Output" that can be renamed, and the one filtered index that must be dropped
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
-- DROPPED, not renamed: this one is FILTERED (WHERE OutputID IS NOT NULL), and a
-- filtered predicate is stored as TEXT naming its column. While it exists, the
-- sp_rename of Scenario_Audit.OutputID below fails Msg 5074 / Msg 4922 no matter
-- what the index is called -- renaming it first only changes which name is stuck.
-- Section 3 recreates it on ScenarioID; same drop-then-recreate shape as the
-- IX_ScenarioAudit_SessionSubEvent block further down. Deliberately NOT in
-- invariants.REQUIRED_INDEXES, so nothing boot-asserts it mid-script.
IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioAudit_Output'
           AND object_id = OBJECT_ID('dbo.Scenario_Audit'))
    DROP INDEX IX_ScenarioAudit_Output ON Scenario_Audit;

-- Repairs a database stuck by the failure above: that run renamed the index and
-- then could not rename the column, leaving the NEW index name over the OLD column,
-- a state no guard here used to match. The COL_LENGTH test fires ONLY in that state
-- -- on a healthy database OutputID is gone, so the good index is kept. The ADD
-- OutputID guard in Section 1 is what stops a re-run re-arming this.
IF COL_LENGTH('dbo.Scenario_Audit', 'OutputID') IS NOT NULL
    AND EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioAudit_Scenario'
                AND object_id = OBJECT_ID('dbo.Scenario_Audit'))
    DROP INDEX IX_ScenarioAudit_Scenario ON Scenario_Audit;

-- The only one of the three boot-asserted: invariants.REQUIRED_INDEXES pins this name
-- (app/db/invariants.py), so a database still carrying UX_TreatmentPlan_ActiveOutput
-- refuses to start. TSG_Verify.sql checks it too. IX_Scenario_SessionSubActive above
-- is performance-only, and IX_ScenarioAudit_Scenario is now created fresh by Section 3
-- rather than renamed.
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
    SubsystemsJSON        nvarchar(max)  NOT NULL,
    IdempotencyKey        nvarchar(200)  NULL,
    AssetContextJSON      nvarchar(max)  NULL,
    ScoringRulesSnapshotJSON    nvarchar(max)  NULL,               -- frozen tuning rulebook (core.tuning); NULL = pre-feature session
    CreatedAt             datetime2      NULL,
    UpdatedAt             datetime2      NULL,
    CompletedAt           datetime2      NULL,
    ControlMapSeconds     float          NULL,               -- seconds ACTUALLY SPENT mapping, summed over every sweep pass; NOT a span (mapping resumes across ticks 300s apart, so a span would be mostly waiting)
    CONSTRAINT CK_Session_Status CHECK (SessionStatus IN ('active', 'completed', 'cancelled'))
);

-- Drops CurrentSubsystemIndex and SectorIDsJSON for databases created before 2026-09-29.
-- CurrentSubsystemIndex was written as a literal 0 at session creation and never moved; the
-- per-subsystem progress every reader actually uses lives in Subsystem_Stage_State.
-- SectorIDsJSON is the last survivor of the 2026-08 sector removal that already took
-- Threat_Type.SectorID and Threat_Catalogue.SectorID - with no sector-scoped master rows left
-- to choose between, nothing read it back. Both are NULLable, so an application that has
-- already stopped writing them keeps inserting either way; this only reclaims the bytes.
-- Guarded, so re-running against an already-dropped database is a provable no-op.
IF COL_LENGTH('dbo.Scenario_Session', 'CurrentSubsystemIndex') IS NOT NULL
    ALTER TABLE Scenario_Session DROP COLUMN CurrentSubsystemIndex;

IF COL_LENGTH('dbo.Scenario_Session', 'SectorIDsJSON') IS NOT NULL
    ALTER TABLE Scenario_Session DROP COLUMN SectorIDsJSON;

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

-- Control-mapping working time, for the per-step timings the status board reports.
-- Independently guarded per column, same reason as the cancellation pair above.
IF OBJECT_ID('dbo.Scenario_Session', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Session', 'ControlMapSeconds') IS NULL
    ALTER TABLE Scenario_Session ADD ControlMapSeconds float NULL;

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
    StartedAt        datetime2     NULL,                     -- stage span start, written by dal.claim_stage; the ONLY source of per-stage duration
    FinishedAt       datetime2     NULL                      -- stage span end, written by dal.finish_stage. UpdatedAt cannot substitute: every lease renewal overwrites it
);

-- Per-stage timing span (threat identification / scenarios). Existing rows stay NULL: there is no
-- historical start or finish to backfill, and the API reports NULL rather than inventing one.
IF OBJECT_ID('dbo.Subsystem_Stage_State', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Subsystem_Stage_State', 'StartedAt') IS NULL
    ALTER TABLE Subsystem_Stage_State ADD StartedAt datetime2 NULL;

IF OBJECT_ID('dbo.Subsystem_Stage_State', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Subsystem_Stage_State', 'FinishedAt') IS NULL
    ALTER TABLE Subsystem_Stage_State ADD FinishedAt datetime2 NULL;

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
    SubsystemID        int           NOT NULL,
    ThreatCategory     nvarchar(200) NOT NULL,
    ThreatType         nvarchar(300) NOT NULL,
    ThreatName         nvarchar(500) NULL,
    GenericName        nvarchar(500) NULL,   -- library-shaped ThreatName (no asset/product names); NULL = legacy row
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

-- RETIRED: no query reads this. Dropped rather than uncreated, or an upgraded database
-- keeps paying for it while a fresh one does not, and the deploy paths diverge in silence.
IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_IdentifiedDuplicateThreat_Session' AND object_id = OBJECT_ID('dbo.Identified_Duplicate_Threat'))
BEGIN
    PRINT ' [FIXED]   Dropping IX_IdentifiedDuplicateThreat_Session - no query reads this table.';
    DROP INDEX IX_IdentifiedDuplicateThreat_Session ON Identified_Duplicate_Threat;
END;
-- Without this, "which threats were dropped in which session" is a full scan. No
-- filter predicate: every row here is permanent audit history, never superseded.

IF OBJECT_ID('dbo.Scoped_Threat', 'U') IS NULL
CREATE TABLE Scoped_Threat (
    ScopedThreatID  uniqueidentifier NOT NULL CONSTRAINT PK_Scoped_Threat PRIMARY KEY,
    SessionID       uniqueidentifier NOT NULL,
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

-- ThreatCategoryID stops consumers re-deriving a category id grounding already resolved.
IF OBJECT_ID('dbo.Identified_Threat', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Identified_Threat', 'ThreatCategoryID') IS NULL
    ALTER TABLE Identified_Threat ADD ThreatCategoryID int NULL;

-- Description DROPPED 2026-09-05 (user instruction) - the last of the three, after Threat_Type's
-- and Threat_Catalogue's went on 2026-08-30. Nothing read it: promotion stopped copying it when
-- Threat_Catalogue.Description went, leaving the /results payload as its only consumer, and the
-- model is no longer asked to produce one (prompts.py). The comment this replaces was already
-- stale - promote.py never wrote crm_threat_risk_register.threat_scenario from this column.
-- Guarded, so re-running against an already-dropped database is a provable no-op.
IF COL_LENGTH('dbo.Identified_Threat', 'Description') IS NOT NULL
    ALTER TABLE Identified_Threat DROP COLUMN Description;

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
    ControlMapAttempts   int           NOT NULL CONSTRAINT DF_ThreatScenario_ControlMapAttempts DEFAULT 0,  -- mapping passes survived without a ControlsMappedAt stamp; >= TSG_CONTROL_MAP_MAX_ATTEMPTS permanently stops retrying (hard cutoff)
    GenStartedAt         datetime2     NULL,  -- per-scenario generation span; duration is DERIVED (finish - start), never stored
    GenFinishedAt        datetime2     NULL,  -- these OVERLAP across rows (generation fans out 5 at a time), so never sum them for a stage total
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

-- Adds the control-mapping attempt-limit column for pre-retry-limit databases. Existing rows get
-- ControlMapAttempts=0, i.e. a full fresh attempt budget - correct, since there is no reliable
-- historical attempt count to backfill.
IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario', 'ControlMapAttempts') IS NULL
    ALTER TABLE Threat_Scenario ADD ControlMapAttempts int NOT NULL
        CONSTRAINT DF_ThreatScenario_ControlMapAttempts DEFAULT 0;

-- Per-scenario generation span. Existing rows stay NULL - CreatedAt records when the row was
-- PERSISTED (sequentially, after the whole batch finished), so it cannot be used to backfill a
-- generation start. Guarded independently per column.
IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario', 'GenStartedAt') IS NULL
    ALTER TABLE Threat_Scenario ADD GenStartedAt datetime2 NULL;

IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario', 'GenFinishedAt') IS NULL
    ALTER TABLE Threat_Scenario ADD GenFinishedAt datetime2 NULL;

-- Drops ControlMapLastAttemptAt for databases that picked it up from an earlier, superseded
-- version of this fix (a backoff-lane clock that was never shipped as the final design - the
-- limit above is a hard cutoff, not a backoff, so nothing ever read this column).
IF COL_LENGTH('dbo.Threat_Scenario', 'ControlMapLastAttemptAt') IS NOT NULL
    ALTER TABLE Threat_Scenario DROP COLUMN ControlMapLastAttemptAt;

-- Adds ScenarioNumber for pre-2026-07-29 databases.
IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario', 'ScenarioNumber') IS NULL
    ALTER TABLE Threat_Scenario ADD ScenarioNumber int NOT NULL CONSTRAINT DF_Scenario_ScenarioNumber DEFAULT 1;

-- Adds ReplacesOutputID for pre-2026-07-30 databases. Legacy rows simply read as originals.
IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario', 'ReplacesOutputID') IS NULL
    AND COL_LENGTH('dbo.Threat_Scenario', 'ReplacesScenarioID') IS NULL
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
    AND COL_LENGTH('dbo.Scenario_Audit', 'ScenarioID') IS NULL
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
-- sp_rename keeps the data in place, and index KEY references follow automatically
-- -- SQL Server stores those by column ID. A FILTERED index does NOT follow: its
-- predicate is stored as text naming the column, so it blocks the rename outright
-- (Msg 5074) and has to be dropped first. The block at the top of this file renames
-- the index names that can be renamed and drops the one filtered index that cannot.
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
    -- The same measured cutoff for CONTROL MAPPING, which asks a different question: a scenario
    -- paragraph against the control library, not a short threat label against the threat library.
    -- The NON-NULL column is the discriminator - a grounding sweep leaves ControlMapTh NULL, a
    -- control-map sweep leaves MatchTh NULL - so no 'kind' column is needed and the reader's
    -- existing MatchTh IS NOT NULL filter keeps working. Nullable: every existing row predates it.
    ControlMapTh       float         NULL,        -- NULL on a grounding-only run
    Quality            float         NULL,        -- Youden's J at MatchTh, 0-1
    NegativesCount     int           NULL,
    PositivesCount     int           NULL,
    HighestNegative    float         NULL,
    LowestPositive     float         NULL,
    NearDuplicatesJSON nvarchar(max) NULL,        -- curation to-do list, not an error
    ErrorMessage       nvarchar(max) NULL
);
GO

-- The same column for a database that ALREADY has the table - UAT and Prod do, so the CREATE
-- above never runs there and this guarded ADD is the only way the column reaches them. Nullable,
-- so nothing has to be backfilled: no run before this one measured a control-mapping cutoff.
IF COL_LENGTH('dbo.Grounding_Calibration_Run', 'ControlMapTh') IS NULL
    ALTER TABLE Grounding_Calibration_Run ADD ControlMapTh float NULL;
GO

-- WHICH cutoff judged each threat: 'calibrated' | 'static_default' | 'env_pinned'.
-- The three collide numerically, so without this the threats graded on a default
-- tuned for a DIFFERENT model pair cannot be found. Nullable so the seeds' explicit
-- column lists stay valid; never backfilled.
IF COL_LENGTH('dbo.Identified_Threat', 'GroundingThresholdOrigin') IS NULL
    ALTER TABLE Identified_Threat ADD GroundingThresholdOrigin nvarchar(100) NULL;
GO

-- Threat_Scenario_Control_Map (Step-4 mapping) lives in Control_library.sql.

-- PAGE compressed like the three log tables. Its CLUSTERING is deliberately left on the
-- primary key: this is the compliance ledger, read through seven customer-facing paths
-- keyed on its own ids, and it is not where the write pressure is.
IF OBJECT_ID('dbo.Scenario_Audit', 'U') IS NULL
CREATE TABLE Scenario_Audit (
    AuditID          uniqueidentifier NOT NULL CONSTRAINT PK_Scenario_Audit PRIMARY KEY WITH (DATA_COMPRESSION = PAGE),
    SessionID        uniqueidentifier NOT NULL,
    EntityID         nvarchar(200) NULL,
    Stage            nvarchar(100)  NULL,
    SubsystemID      int           NULL,
    EventType        nvarchar(100)  NOT NULL,
    -- The scenario this event is ABOUT. NULL on session- and subsystem-scoped
    -- events. A column, not a DetailJSON key, because JSON cannot be indexed.
    ScenarioID       uniqueidentifier NULL,
    PlanID           uniqueidentifier NULL,
    Decision         nvarchar(100)  NULL,
    ActorUserID      nvarchar(200) NULL,   -- who is ACCOUNTABLE (back-filled to the session owner)
    ActorType        nvarchar(100)  NULL,   -- who PERFORMED it: 'user' | 'system'
    DetailJSON       nvarchar(max) NULL,
    CreatedAt        datetime2     NOT NULL
);

-- Application_Log: the ordinary log stream, durably. OPERATOR-ONLY, like Diagnostic_Event.
-- Every line at INFO and above, so it grows far faster and is kept for days rather than weeks.
-- Written by a background batching writer, never on a request thread.
-- PRIMARY KEY NONCLUSTERED and PAGE compressed, for the reason on Prompt_Log above.
-- This is the hottest insert path in the system, so it is the table that paid the most
-- for a random clustering key. Section 3 clusters it on (CreatedAt, LogID).
IF OBJECT_ID('dbo.Application_Log', 'U') IS NULL
CREATE TABLE Application_Log (
    LogID       uniqueidentifier NOT NULL CONSTRAINT PK_Application_Log PRIMARY KEY NONCLUSTERED WITH (DATA_COMPRESSION = PAGE),
    CreatedAt   datetime2(7) NOT NULL,
    Level       nvarchar(20) NOT NULL,
    Logger      nvarchar(200) NULL,
    Event       nvarchar(500) NULL,
    SessionID   nvarchar(100) NULL,
    RequestID   nvarchar(100) NULL,
    TaskID      nvarchar(100) NULL,
    FieldsJSON  nvarchar(max) NULL
);

-- Diagnostic_Event: OPERATOR-ONLY failure detail. The exception class, message and traceback
-- behind a failed run, plus the sanitised text the customer was shown so a report of "it said
-- stage processing failed" joins to the real cause. No tenant-facing route reads it. Written
-- best-effort, so failing to write it never turns a diagnosable error into an undiagnosable one.
-- PRIMARY KEY NONCLUSTERED and PAGE compressed, for the reason on Prompt_Log above.
-- Section 3 clusters it on (CreatedAt, DiagnosticID): both readers of this table -- "why
-- did session X fail" and the retention purge -- are bounded by time first.
IF OBJECT_ID('dbo.Diagnostic_Event', 'U') IS NULL
CREATE TABLE Diagnostic_Event (
    DiagnosticID     uniqueidentifier NOT NULL CONSTRAINT PK_Diagnostic_Event PRIMARY KEY NONCLUSTERED WITH (DATA_COMPRESSION = PAGE),
    CreatedAt        datetime2(7) NOT NULL,
    SessionID        uniqueidentifier NULL,
    EntityID         nvarchar(200) NULL,
    SubsystemID      int NULL,
    TaskID           nvarchar(100) NULL,
    RequestID        nvarchar(100) NULL,
    Kind             nvarchar(50) NOT NULL,
    ExceptionClass   nvarchar(200) NOT NULL,
    ExceptionMessage nvarchar(4000) NULL,
    Traceback        nvarchar(max) NULL,
    ClientMessage    nvarchar(1000) NULL,
    ContextJSON      nvarchar(max) NULL
);

-- PRIMARY KEY NONCLUSTERED: the table is CLUSTERED ON (CreatedAt, LogID) in Section 3,
-- because LogID is a random GUID and a clustered GUID key puts every insert in the
-- MIDDLE of the index -- a page split per write on the fastest-growing table here.
-- The key itself is unchanged; only where the rows sit is. PAGE compressed because
-- log rows repeat heavily (same stage, model, session, entity) and compress 40-60%.
IF OBJECT_ID('dbo.Prompt_Log', 'U') IS NULL
CREATE TABLE Prompt_Log (
    LogID           uniqueidentifier NOT NULL CONSTRAINT PK_Prompt_Log PRIMARY KEY NONCLUSTERED WITH (DATA_COMPRESSION = PAGE),
    SessionID       uniqueidentifier NOT NULL,
    Stage           nvarchar(100)  NOT NULL,
    PromptVersion   nvarchar(100)  NOT NULL,
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

-- Adds Prompt (flattened prompt text) for pre-2026-08-03 databases. Legacy rows have
-- it NULL and the block below is what fills them in.
IF OBJECT_ID('dbo.Prompt_Log', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Prompt_Log', 'Prompt') IS NULL
    ALTER TABLE Prompt_Log ADD Prompt nvarchar(max) NULL;

-- Drops Messages, which held the prompt a SECOND time: Messages was the wire JSON and
-- Prompt the same content flattened. Nothing in the application reads Messages; Prompt
-- is what the customer evidence endpoint returns. Two copies of one value, written on
-- every model call, on the fastest-growing table in the database.
--
-- NOT OPTIONAL, unlike the removals in tsg_remediation_tables.sql's DropRemovedColumns
-- switch: Messages is NOT NULL, so once the application stops writing it, every INSERT
-- into Prompt_Log fails while the column is still there.
--
-- THE BACKFILL RUNS FIRST. Rows written before 2026-08-03 have Prompt NULL and Messages
-- holding the ONLY copy of the prompt; dropping it without copying forward would empty
-- the evidence endpoint for every one of them. Idempotent: the WHERE matches nothing on
-- a second run, and the guard finds no column at all once the drop has happened.
--
-- BOTH GO THROUGH EXEC. SQL Server binds column names when it COMPILES a batch, so a
-- plain `WHERE Prompt IS NULL` inside an IF that is never taken still aborts the whole
-- batch with Msg 207 on a database that has not got the column yet.
IF COL_LENGTH('dbo.Prompt_Log', 'Messages') IS NOT NULL
    AND COL_LENGTH('dbo.Prompt_Log', 'Prompt') IS NOT NULL
    EXEC('UPDATE Prompt_Log SET Prompt = Messages WHERE Prompt IS NULL;');

-- Guarded on the backfill having covered every row, and LOUD when it has not: a failing
-- insert is recoverable by re-running this script, a deleted prompt is not.
IF COL_LENGTH('dbo.Prompt_Log', 'Messages') IS NOT NULL
    EXEC('IF NOT EXISTS (SELECT 1 FROM Prompt_Log WHERE Prompt IS NULL)
              ALTER TABLE Prompt_Log DROP COLUMN Messages;
          ELSE
              RAISERROR(''Prompt_Log.Messages NOT dropped: Prompt is still NULL on at least one row, so Messages holds the only copy of that prompt. Find out why the backfill above did not cover it, then re-run.'', 16, 1);');

-- Risk Treatment Plan (docs/RISK_TREATMENT_PLAN_SDD.md). One row per generation attempt
-- on an accepted scenario; at most one active (Superseded=0) row per ScenarioID, enforced
-- by UX_TreatmentPlan_ActiveScenario below. Risk data (ratings, level, existing controls)
-- arrives in the request body — TSG reads no external risk tables.
IF OBJECT_ID('dbo.Risk_Treatment_Plan', 'U') IS NULL
CREATE TABLE Risk_Treatment_Plan (
    PlanID                  uniqueidentifier NOT NULL CONSTRAINT PK_Risk_Treatment_Plan PRIMARY KEY,
    SessionID               uniqueidentifier NOT NULL,
    ScenarioID              uniqueidentifier NOT NULL,  -- the accepted Threat_Scenario row
    EntityID                nvarchar(200) NULL,         -- copied from the session (authz boundary)
    UserID                  nvarchar(200) NULL,         -- requesting principal (provenance)
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

-- One active scenario per scoped threat — the database-level twin of invariants.ACTIVE_UNIQUE.
-- Every scenario writer mints a fresh Scoped_Threat row alongside its scenario (ScopedThreatID is
-- that table's primary key), so a correct write never fires this. It exists to reject a BAD write
-- at write time: before it, the startup check was the only guard, so a duplicate landed silently
-- and the service then refused to boot at the next restart, far from the change that caused it.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Scenario_ActiveScoped' AND object_id = OBJECT_ID('dbo.Threat_Scenario'))
CREATE UNIQUE INDEX UX_Scenario_ActiveScoped ON Threat_Scenario(SessionID, ScopedThreatID) WHERE Superseded = 0;

-- One ACCEPTED scenario per (session, threat identity, ScenarioNumber). Accepted
-- is decoupled from Superseded, so the index above does not imply this rule.
-- IdentityHash IS NOT NULL because a NULL hash means identity unknown, and SQL
-- Server's NULLs-compare-equal semantics would falsely collide two of them.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Scenario_ActiveAccepted' AND object_id = OBJECT_ID('dbo.Threat_Scenario'))
CREATE UNIQUE INDEX UX_Scenario_ActiveAccepted ON Threat_Scenario(SessionID, IdentityHash, ScenarioNumber) WHERE Accepted = 1 AND IdentityHash IS NOT NULL;

-- RETIRED: no query reads this. Dropped rather than uncreated, or an upgraded database
-- keeps paying for it while a fresh one does not, and the deploy paths diverge in silence.
IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_PromptLog_Session' AND object_id = OBJECT_ID('dbo.Prompt_Log'))
BEGIN
    PRINT ' [FIXED]   Dropping IX_PromptLog_Session - the prompt log is only read by CorrelationID.';
    DROP INDEX IX_PromptLog_Session ON Prompt_Log;
END;

-- The treatment-evidence read (dal_treatment.prompt_logs_for_plan, behind
-- GET /v1/sessions/{id}/scenarios/{id}/treatment-plan/evidence) filters Prompt_Log on
-- CorrelationID alone and orders by CreatedAt. Prompt_Log has no other index on that
-- column, so without this the read SCANS a table that grows by one row per model call:
-- it never errors and never logs, it just gets slower for the life of the database.
-- Filtered because session/subsystem rows carry no CorrelationID and are the majority.
-- This index was created by scripts/tsg_remediation_tables.sql and by the generated
-- scripts/tsg_script/ package and by NEITHER of the numbered scripts, because no guard
-- compared the three paths' index inventories. One now does:
-- tests/test_schema_sync.py::test_every_deploy_path_creates_the_same_indexes.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_PromptLog_Correlation' AND object_id = OBJECT_ID('dbo.Prompt_Log'))
CREATE INDEX IX_PromptLog_Correlation ON Prompt_Log(CorrelationID, CreatedAt) WHERE CorrelationID IS NOT NULL;

-- Diagnostics reads and the retention purge. "Why did session X fail" is THE query the
-- diagnostics table exists to answer, and it is asked by a support engineer while someone
-- waits; CreatedAt is the second key because the answer is always read newest-first, so the
-- ordering comes from the index rather than from a sort over the matched rows.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_DiagnosticEvent_Session' AND object_id = OBJECT_ID('dbo.Diagnostic_Event'))
CREATE INDEX IX_DiagnosticEvent_Session ON Diagnostic_Event(SessionID, CreatedAt DESC) WHERE SessionID IS NOT NULL;

-- RETIRED, and dropped where they still exist. Both were nonclustered on (CreatedAt DESC).
-- Section 3 below now CLUSTERS these two tables on (CreatedAt, id), so the table itself is
-- held in that order -- and a clustered index is scanned backwards as cheaply as forwards,
-- carrying the whole row, so it answers every query these did without a key lookup.
-- That made them a second copy of an ordering the table already has, maintained on every
-- INSERT, on the two hottest insert paths in the system.
-- DROPPED rather than merely un-created: otherwise an upgraded database keeps paying for
-- them forever while a fresh one does not, and the two deploy paths diverge in silence.
IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_DiagnosticEvent_Created' AND object_id = OBJECT_ID('dbo.Diagnostic_Event'))
BEGIN
    PRINT ' [FIXED]   Dropping IX_DiagnosticEvent_Created - covered by the clustered index.';
    DROP INDEX IX_DiagnosticEvent_Created ON Diagnostic_Event;
END;

IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ApplicationLog_Created' AND object_id = OBJECT_ID('dbo.Application_Log'))
BEGIN
    PRINT ' [FIXED]   Dropping IX_ApplicationLog_Created - covered by the clustered index.';
    DROP INDEX IX_ApplicationLog_Created ON Application_Log;
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ApplicationLog_Session' AND object_id = OBJECT_ID('dbo.Application_Log'))
CREATE INDEX IX_ApplicationLog_Session ON Application_Log(SessionID, CreatedAt DESC) WHERE SessionID IS NOT NULL;
GO

-- ------------------------------------------------------------------------------------
-- The three log tables are CLUSTERED ON TIME, not on their primary key.
--
-- Their key is a random uniqueidentifier, so on a clustered primary key every insert
-- lands in the MIDDLE of the index: a page split on the three most append-heavy tables
-- in the system, on every write, and fragmentation that grows as fast as the table does.
-- Clustered on (CreatedAt, <id>) the inserts become pure appends, and every "last N
-- hours" read and every retention purge becomes a range seek instead of a scan.
--
-- THE PRIMARY KEY SURVIVES as a NONCLUSTERED PRIMARY KEY on the same single column, so
-- uniqueness and anything that references the key are unchanged. <id> is the second key
-- column so the clustering key stays unique -- without it SQL Server adds a hidden
-- 4-byte uniquifier to duplicate CreatedAt values and carries it in every nonclustered
-- index on the table.
--
-- Scenario_Audit is deliberately absent: the compliance ledger, seven customer-facing
-- read paths, and not where the write pressure is.
--
-- A constraint cannot be converted in place, so this is DROP-then-ADD in one transaction
-- per table -- the key is never missing outside it. Guarded on the primary key still
-- BEING clustered, so a second run finds it nonclustered and does nothing. This rebuilds
-- every nonclustered index on the table and needs log space: maintenance window only.
-- ------------------------------------------------------------------------------------
IF EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = OBJECT_ID('dbo.Prompt_Log')
           AND is_primary_key = 1 AND type_desc = 'CLUSTERED')
BEGIN
    BEGIN TRY
        BEGIN TRANSACTION;
        ALTER TABLE Prompt_Log DROP CONSTRAINT PK_Prompt_Log;
        ALTER TABLE Prompt_Log ADD CONSTRAINT PK_Prompt_Log PRIMARY KEY NONCLUSTERED (LogID) WITH (DATA_COMPRESSION = PAGE);
        COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
        IF XACT_STATE() <> 0 ROLLBACK TRANSACTION;
        THROW;   -- re-raised so sqlcmd -b stops here instead of carrying on
    END CATCH
END
GO

IF EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = OBJECT_ID('dbo.Application_Log')
           AND is_primary_key = 1 AND type_desc = 'CLUSTERED')
BEGIN
    BEGIN TRY
        BEGIN TRANSACTION;
        ALTER TABLE Application_Log DROP CONSTRAINT PK_Application_Log;
        ALTER TABLE Application_Log ADD CONSTRAINT PK_Application_Log PRIMARY KEY NONCLUSTERED (LogID) WITH (DATA_COMPRESSION = PAGE);
        COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
        IF XACT_STATE() <> 0 ROLLBACK TRANSACTION;
        THROW;   -- re-raised so sqlcmd -b stops here instead of carrying on
    END CATCH
END
GO

IF EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = OBJECT_ID('dbo.Diagnostic_Event')
           AND is_primary_key = 1 AND type_desc = 'CLUSTERED')
BEGIN
    BEGIN TRY
        BEGIN TRANSACTION;
        ALTER TABLE Diagnostic_Event DROP CONSTRAINT PK_Diagnostic_Event;
        ALTER TABLE Diagnostic_Event ADD CONSTRAINT PK_Diagnostic_Event PRIMARY KEY NONCLUSTERED (DiagnosticID) WITH (DATA_COMPRESSION = PAGE);
        COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
        IF XACT_STATE() <> 0 ROLLBACK TRANSACTION;
        THROW;   -- re-raised so sqlcmd -b stops here instead of carrying on
    END CATCH
END
GO

-- The second guard -- no clustered index of ANY name on the table -- is what keeps these
-- from ABORTING the run if the primary key above could not be moved: without it the
-- statement fails with Msg 1902 (a table may have only one clustered index) and every
-- statement after it is skipped.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'CIX_PromptLog_Created' AND object_id = OBJECT_ID('dbo.Prompt_Log'))
   AND NOT EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = OBJECT_ID('dbo.Prompt_Log') AND type_desc = 'CLUSTERED')
CREATE CLUSTERED INDEX CIX_PromptLog_Created ON Prompt_Log(CreatedAt, LogID) WITH (DATA_COMPRESSION = PAGE);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'CIX_ApplicationLog_Created' AND object_id = OBJECT_ID('dbo.Application_Log'))
   AND NOT EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = OBJECT_ID('dbo.Application_Log') AND type_desc = 'CLUSTERED')
CREATE CLUSTERED INDEX CIX_ApplicationLog_Created ON Application_Log(CreatedAt, LogID) WITH (DATA_COMPRESSION = PAGE);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'CIX_DiagnosticEvent_Created' AND object_id = OBJECT_ID('dbo.Diagnostic_Event'))
   AND NOT EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = OBJECT_ID('dbo.Diagnostic_Event') AND type_desc = 'CLUSTERED')
CREATE CLUSTERED INDEX CIX_DiagnosticEvent_Created ON Diagnostic_Event(CreatedAt, DiagnosticID) WITH (DATA_COMPRESSION = PAGE);
GO

-- The two nonclustered (CreatedAt DESC) indexes these replace are RETIRED above, and dropped
-- from databases that still carry them. The IX_*_Session indexes are KEPT on purpose: they
-- lead on SessionID, which no clustered index here covers, so "everything for session X"
-- would otherwise scan. Redundancy is decided by the LEADING column, not by whether
-- CreatedAt appears somewhere in the key.

-- PAGE compression for a database that ALREADY EXISTS. The CREATE TABLEs above declare it,
-- which only ever covers a FRESH database: compression is a property of a stored index and
-- an index that is already there is never re-created. Log rows repeat heavily -- the same
-- stage, kind, session and entity over and over -- so page compression typically recovers
-- 40-60% of the stored bytes at negligible CPU cost, and fewer pages also means fewer
-- reads. Invisible to the application: no query, no column and no type changes.
--
-- ALTER INDEX ALL, not ALTER TABLE ... REBUILD: the latter compresses only the table's own
-- data and leaves every nonclustered index on it uncompressed, and on these four tables
-- those are a large part of the bytes. index_id > 0 skips a heap, which can only exist
-- here if the clustered index above could not be created. data_compression 2 is PAGE, so
-- a second run finds nothing to do. Rewrites the whole table: maintenance window only.
IF EXISTS (SELECT 1 FROM sys.partitions WHERE object_id = OBJECT_ID('dbo.Prompt_Log')
           AND index_id > 0 AND data_compression <> 2)
    ALTER INDEX ALL ON Prompt_Log REBUILD WITH (DATA_COMPRESSION = PAGE);
GO

IF EXISTS (SELECT 1 FROM sys.partitions WHERE object_id = OBJECT_ID('dbo.Application_Log')
           AND index_id > 0 AND data_compression <> 2)
    ALTER INDEX ALL ON Application_Log REBUILD WITH (DATA_COMPRESSION = PAGE);
GO

IF EXISTS (SELECT 1 FROM sys.partitions WHERE object_id = OBJECT_ID('dbo.Diagnostic_Event')
           AND index_id > 0 AND data_compression <> 2)
    ALTER INDEX ALL ON Diagnostic_Event REBUILD WITH (DATA_COMPRESSION = PAGE);
GO

IF EXISTS (SELECT 1 FROM sys.partitions WHERE object_id = OBJECT_ID('dbo.Scenario_Audit')
           AND index_id > 0 AND data_compression <> 2)
    ALTER INDEX ALL ON Scenario_Audit REBUILD WITH (DATA_COMPRESSION = PAGE);
GO

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

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Scenario_RejectedDecision' AND object_id = OBJECT_ID('dbo.Threat_Scenario'))
CREATE INDEX IX_Scenario_RejectedDecision ON Threat_Scenario(SessionID) WHERE RejectedAt IS NOT NULL;
-- Backs the reject-side seek in GET /sessions/{id}/results, which re-adds a DECIDED scenario
-- even after a regeneration superseded it — the accepted row was always re-added, the declined
-- one was not, and that asymmetry hid what a reviewer had already turned down. Threat_Scenario
-- has no unfiltered SessionID index, so without this the seek degrades to a table scan on a
-- POLLED endpoint. Performance only: deliberately NOT in invariants.REQUIRED_INDEXES nor in
-- 6. TSG_Verify.sql, so a database that has not run it still boots and still passes verify.

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioAudit_SessionSubEvent' AND object_id = OBJECT_ID('dbo.Scenario_Audit'))
CREATE INDEX IX_ScenarioAudit_SessionSubEvent ON Scenario_Audit(SessionID, SubsystemID, EventType, CreatedAt DESC);

-- "Show me every decision on this scenario, newest first." Filtered so it costs nothing for the
-- session/subsystem rows that carry no ScenarioID, which is the overwhelming majority of the ledger.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioAudit_Scenario' AND object_id = OBJECT_ID('dbo.Scenario_Audit'))
    AND COL_LENGTH('dbo.Scenario_Audit', 'ScenarioID') IS NOT NULL
    EXEC('CREATE INDEX IX_ScenarioAudit_Scenario ON Scenario_Audit(ScenarioID, CreatedAt DESC) WHERE ScenarioID IS NOT NULL');

-- Same shape for the plan dimension, filtered for the same reason: session- and scenario-scoped
-- rows carry no PlanID and are the overwhelming majority of the ledger.
-- RETIRED: no query reads this. Dropped rather than uncreated, or an upgraded database
-- keeps paying for it while a fresh one does not, and the deploy paths diverge in silence.
IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioAudit_Plan' AND object_id = OBJECT_ID('dbo.Scenario_Audit'))
BEGIN
    PRINT ' [FIXED]   Dropping IX_ScenarioAudit_Plan - no query filters the audit table by PlanID.';
    DROP INDEX IX_ScenarioAudit_Plan ON Scenario_Audit;
END;
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
-- Scenario_Library — REMOVED 2026-08-29, along with the cross-tenant
-- scenario-reuse feature it backed.
-- ---------------------------------------------------------------------------
-- It is not in app/db/models.py, nothing under app/ reads or writes it, and
-- neither of the other two deploy paths (scripts/tsg_remediation_tables.sql and
-- the generated scripts/tsg_script/ package) creates it. This script kept
-- creating it anyway, and "6. TSG_Verify.sql" kept requiring it — so a database
-- built by either of those paths and then verified reported "Table missing:
-- Scenario_Library" as a BLOCKING failure on a correct database. The shipped
-- remedy was a paragraph telling the operator to read past one blocking failure
-- from a script whose other blocking failures are real, which is how a real one
-- gets read past too. The CREATE, its UX_ScenarioLibrary_Natural index and the
-- verify entry are all gone instead.
--
-- A database that already HAS the table keeps it: it is inert, nothing reads it,
-- and dropping a table that once held generated text is not a schema script's
-- decision to make. Drop it by hand when convenient.
--
-- tests/test_schema_sync.py::test_verify_script_table_list_matches_create_inventory
-- now derives the expected table list from the ORM, so an unmapped table cannot
-- re-enter this file's CREATE inventory or the verify list again.


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

-- ---------------------------------------------------------------------------
-- 2026-09-30: 25 columns no query reads.
--
-- Twenty of them are TenantID/EntityID/UserID copied from Scenario_Session at insert and never
-- refreshed again. SessionID is NOT NULL on every table below, so the session's own columns
-- answer the same question and cannot drift; tenancy is enforced on EntityID, and TenantID was
-- never a predicate anywhere in the application. The rest were written and never read back.
--
-- Guarded on the column still existing, so re-running against an already-dropped database is a
-- provable no-op.
--
-- WHAT DELIBERATELY STAYS, because each one IS read:
--   Subsystem_Stage_State.UpdatedAt  - the step-4 control-mapping sweep filters its queue on it
--                                      (UpdatedAt < cutoff) and orders by it, oldest first.
--   Risk_Treatment_Plan.EntityID     - the treatment audit rows are stamped from it, and the
--                                      entity-wide compliance feed filters on that stamp.
--   Scenario_Audit.EntityID          - that same feed's predicate.
--   Diagnostic_Event.EntityID        - SessionID is NULLable there, so a session-less diagnostic
--                                      has no join home and this is its only scoping id.
--   Scenario_Session's own TenantID/EntityID/UserID - the NOT NULL authz truth all the copies
--                                      above were redundant against.
--   SubsystemID everywhere except Prompt_Log - filtered in a dozen queries, keys three indexes.
--
-- NOT OPTIONAL for one of them. Prompt_Log.SubsystemID is NOT NULL, so once the application
-- stops writing it every INSERT into Prompt_Log fails while the column is still there - one row
-- per LLM call. It is dropped here for the same reason Prompt_Log.Messages was.
-- Prompt_Log.Stage is deliberately NOT dropped: the application still writes it, and the
-- smoke-testing guide tells an operator to select it by hand.
-- ---------------------------------------------------------------------------
-- Subsystem_Stage_State.CreatedAt carries DF_StageState_CreatedAt; a DEFAULT bound to a column
-- refuses the DROP outright (msg 5074), so the constraint goes first.
IF COL_LENGTH('dbo.Subsystem_Stage_State', 'CreatedAt') IS NOT NULL
   AND EXISTS (SELECT 1 FROM sys.default_constraints WHERE name = 'DF_StageState_CreatedAt')
    ALTER TABLE Subsystem_Stage_State DROP CONSTRAINT DF_StageState_CreatedAt;

IF COL_LENGTH('dbo.Subsystem_Stage_State', 'TenantID') IS NOT NULL
    ALTER TABLE Subsystem_Stage_State DROP COLUMN TenantID;

IF COL_LENGTH('dbo.Subsystem_Stage_State', 'EntityID') IS NOT NULL
    ALTER TABLE Subsystem_Stage_State DROP COLUMN EntityID;

IF COL_LENGTH('dbo.Subsystem_Stage_State', 'CreatedAt') IS NOT NULL
    ALTER TABLE Subsystem_Stage_State DROP COLUMN CreatedAt;

IF COL_LENGTH('dbo.Identified_Threat', 'TenantID') IS NOT NULL
    ALTER TABLE Identified_Threat DROP COLUMN TenantID;

IF COL_LENGTH('dbo.Identified_Threat', 'EntityID') IS NOT NULL
    ALTER TABLE Identified_Threat DROP COLUMN EntityID;

IF COL_LENGTH('dbo.Identified_Threat', 'UserID') IS NOT NULL
    ALTER TABLE Identified_Threat DROP COLUMN UserID;

IF COL_LENGTH('dbo.Identified_Duplicate_Threat', 'TenantID') IS NOT NULL
    ALTER TABLE Identified_Duplicate_Threat DROP COLUMN TenantID;

IF COL_LENGTH('dbo.Identified_Duplicate_Threat', 'EntityID') IS NOT NULL
    ALTER TABLE Identified_Duplicate_Threat DROP COLUMN EntityID;

IF COL_LENGTH('dbo.Identified_Duplicate_Threat', 'UserID') IS NOT NULL
    ALTER TABLE Identified_Duplicate_Threat DROP COLUMN UserID;

IF COL_LENGTH('dbo.Scoped_Threat', 'TenantID') IS NOT NULL
    ALTER TABLE Scoped_Threat DROP COLUMN TenantID;

IF COL_LENGTH('dbo.Scoped_Threat', 'EntityID') IS NOT NULL
    ALTER TABLE Scoped_Threat DROP COLUMN EntityID;

IF COL_LENGTH('dbo.Scoped_Threat', 'UserID') IS NOT NULL
    ALTER TABLE Scoped_Threat DROP COLUMN UserID;

IF COL_LENGTH('dbo.Threat_Scenario', 'TenantID') IS NOT NULL
    ALTER TABLE Threat_Scenario DROP COLUMN TenantID;

IF COL_LENGTH('dbo.Threat_Scenario', 'EntityID') IS NOT NULL
    ALTER TABLE Threat_Scenario DROP COLUMN EntityID;

IF COL_LENGTH('dbo.Threat_Scenario', 'UserID') IS NOT NULL
    ALTER TABLE Threat_Scenario DROP COLUMN UserID;

IF COL_LENGTH('dbo.Risk_Treatment_Plan', 'TenantID') IS NOT NULL
    ALTER TABLE Risk_Treatment_Plan DROP COLUMN TenantID;

IF COL_LENGTH('dbo.Risk_Treatment_Plan', 'CrmRiskIdentificationID') IS NOT NULL
    ALTER TABLE Risk_Treatment_Plan DROP COLUMN CrmRiskIdentificationID;

IF COL_LENGTH('dbo.Prompt_Log', 'TenantID') IS NOT NULL
    ALTER TABLE Prompt_Log DROP COLUMN TenantID;

IF COL_LENGTH('dbo.Prompt_Log', 'EntityID') IS NOT NULL
    ALTER TABLE Prompt_Log DROP COLUMN EntityID;

IF COL_LENGTH('dbo.Prompt_Log', 'UserID') IS NOT NULL
    ALTER TABLE Prompt_Log DROP COLUMN UserID;

IF COL_LENGTH('dbo.Prompt_Log', 'SubsystemID') IS NOT NULL
    ALTER TABLE Prompt_Log DROP COLUMN SubsystemID;

IF COL_LENGTH('dbo.Diagnostic_Event', 'TenantID') IS NOT NULL
    ALTER TABLE Diagnostic_Event DROP COLUMN TenantID;

IF COL_LENGTH('dbo.Scenario_Audit', 'TenantID') IS NOT NULL
    ALTER TABLE Scenario_Audit DROP COLUMN TenantID;

IF COL_LENGTH('dbo.Scenario_Audit', 'Granularity') IS NOT NULL
    ALTER TABLE Scenario_Audit DROP COLUMN Granularity;

IF COL_LENGTH('dbo.Scenario_Audit', 'ThreatTypeRefID') IS NOT NULL
    ALTER TABLE Scenario_Audit DROP COLUMN ThreatTypeRefID;

GO
