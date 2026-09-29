/*==============================================================================
  PRE-DEPLOYMENT VALIDATION  (READ ONLY)

  Script:      001_pre_deployment_validation.sql
  Order:       00_validation / 001   (run after 000_helpers.sql, before 01_tables)
  Purpose:     Report what is already here and what the deployment will change.
  Depends on:  Nothing.
  Re-runnable: YES - it reads catalog views only.
  Modifies:    NOTHING. This script never writes, alters, creates or drops.

  READ THE OUTPUT BEFORE YOU DEPLOY. It tells you whether this is an empty
  database or an upgrade, whether the platform tables TSG depends on exist, and
  what data is present that could block a change.

  A [FAIL] here does not mean the deployment will fail. It means a human should
  look before running it.

  RELATED: "0. TSG_Preflight.sql" checks the platform tables column by column
  and is worth running too. This script does not repeat that depth; it answers
  the questions this package needs - fresh or upgrade, what data is at risk,
  and which boot-critical indexes are missing.
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;
GO

PRINT '==============================================================';
PRINT ' TSG PRE-DEPLOYMENT VALIDATION';
PRINT ' Database: ' + DB_NAME() + '   Server: ' + @@SERVERNAME;
PRINT ' Run at:   ' + CONVERT(varchar(19), SYSUTCDATETIME(), 120) + ' UTC';
PRINT '==============================================================';
GO

/*--------------------------------------------------------------------------
  1. SQL Server version.
     The package uses STRING_SPLIT (2016+) and CREATE OR ALTER (2016 SP1+).
--------------------------------------------------------------------------*/
PRINT '';
PRINT '--- 1. Server ---';
GO
DECLARE @major int = TRY_CAST(SERVERPROPERTY('ProductMajorVersion') AS int);
PRINT ' [INFO]    Version: ' + CAST(SERVERPROPERTY('ProductVersion') AS varchar(50)) +
      '  (' + CAST(SERVERPROPERTY('Edition') AS varchar(60)) + ')';
IF @major >= 13
    PRINT ' [PASS]    SQL Server 2016 or later - STRING_SPLIT and CREATE OR ALTER are available.';
ELSE
    PRINT ' [FAIL]    SQL Server 2016 or later is required by this package.';
GO

/*--------------------------------------------------------------------------
  2. Read-Committed Snapshot Isolation.
     The application relies on it: without RCSI, readers block writers and the
     pipeline's concurrent stages deadlock.

     READ sys.databases, NOT DATABASEPROPERTYEX. That property returned NULL on
     a SQL Server 2022 Express instance whose RCSI was demonstrably ON, and
     `NULL = 1` is UNKNOWN, so this section printed [FAIL] and told the operator
     to run ALTER DATABASE ... WITH ROLLBACK IMMEDIATE - a statement that kills
     every open connection - against a database that was already correct.
     sys.databases.is_read_committed_snapshot_on is a non-nullable bit present
     for every database, so it cannot produce that false alarm.

     A read that returns NOTHING is reported as its own case. "I could not tell"
     must never print the ALTER, because acting on it would be destructive.
--------------------------------------------------------------------------*/
PRINT '';
PRINT '--- 2. Isolation level ---';
GO
DECLARE @rcsi bit = (SELECT d.is_read_committed_snapshot_on
                     FROM sys.databases d WHERE d.database_id = DB_ID());
IF @rcsi = 1
    PRINT ' [PASS]    READ_COMMITTED_SNAPSHOT is ON.';
ELSE IF @rcsi = 0
BEGIN
    PRINT ' [FAIL]    READ_COMMITTED_SNAPSHOT is OFF. The application needs it ON.';
    PRINT '          Fix (run when nobody else is connected):';
    PRINT '          ALTER DATABASE [' + DB_NAME() +
          '] SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE;';
END
ELSE
BEGIN
    PRINT ' [FAIL]    Could not read this database''s isolation setting - no visible';
    PRINT '          sys.databases row. Check the setting before deploying, and do';
    PRINT '          NOT run the ALTER blind: it disconnects every active session.';
END;
GO

/*--------------------------------------------------------------------------
  3. Platform tables.
     TSG READS these and must never create or alter them. If they are missing,
     the schema still deploys, but the application cannot resolve an asset, so
     POST /v1/sessions fails at run time. Ask the platform team.
--------------------------------------------------------------------------*/
PRINT '';
PRINT '--- 3. Platform tables (owned by another team - TSG only reads them) ---';
GO
DECLARE @platform TABLE (name sysname);
INSERT INTO @platform (name) VALUES
    ('ctm_scan_category'), ('ctm_scan_entity'), ('ctm_scan_entity_bu'),
    ('ctm_scan_entity_supporting_system'), ('onboarding_sectors'), ('onboarding_services'),
    ('onboarding_supporting_systems'), ('option'), ('option_value'),
    ('user'), ('user_scope_assignment');

SELECT CASE WHEN OBJECT_ID('dbo.' + QUOTENAME(p.name), 'U') IS NULL
            THEN '[WARNING] missing: ' ELSE '[PASS]    present: ' END + p.name AS PlatformTable
FROM   @platform p
ORDER  BY p.name;

DECLARE @missing_platform int =
    (SELECT COUNT(*) FROM @platform p WHERE OBJECT_ID('dbo.' + QUOTENAME(p.name), 'U') IS NULL);

IF @missing_platform > 0
BEGIN
    PRINT ' [WARNING] ' + CAST(@missing_platform AS varchar(10)) + ' platform table(s) missing.';
    PRINT '          This package will NOT create them - they belong to another team.';
    PRINT '          The schema still deploys, but the application cannot resolve an asset.';
END
ELSE
    PRINT ' [PASS]    All 11 platform tables are present.';
GO

/*--------------------------------------------------------------------------
  4. TSG tables - is this a fresh install or an upgrade?
--------------------------------------------------------------------------*/
PRINT '';
PRINT '--- 4. TSG tables ---';
GO
DECLARE @owned TABLE (name sysname);
INSERT INTO @owned (name) VALUES
    ('Threat_Category'), ('Threat_Type'), ('Threat_Catalogue'), ('Threat_Actor'),
    ('Threat_Catalogue_Category_Map'), ('ThreatType_ThreatActor_Map'),
    ('Control_Standard'), ('Control_Library'), ('Control_Library_Standard_Map'),
    ('API_Client'), ('Config_Tuning'), ('Grounding_Calibration_Run'),
    ('Scenario_Session'), ('Subsystem_Stage_State'), ('Identified_Threat'),
    ('Identified_Duplicate_Threat'), ('Scoped_Threat'), ('Threat_Scenario'),
    ('Threat_Scenario_Control_Map'), ('Risk_Treatment_Plan'),
    ('Scenario_Audit'), ('Prompt_Log'), ('Diagnostic_Event','Application_Log'), ('Application_Log');

DECLARE @total   int = (SELECT COUNT(*) FROM @owned);
DECLARE @present int = (SELECT COUNT(*) FROM @owned o
                        WHERE OBJECT_ID('dbo.' + QUOTENAME(o.name), 'U') IS NOT NULL);

PRINT ' [INFO]    ' + CAST(@present AS varchar(10)) + ' of ' + CAST(@total AS varchar(10)) +
      ' TSG tables already exist.';
IF @present = 0
    PRINT ' [INFO]    EMPTY DATABASE. The deployment will create everything.';
ELSE IF @present = @total
    PRINT ' [INFO]    UPGRADE. Every table exists; the deployment will reconcile columns only.';
ELSE
    PRINT ' [INFO]    PARTIAL INSTALL. Missing tables are created, existing ones reconciled.';

SELECT CASE WHEN OBJECT_ID('dbo.' + QUOTENAME(o.name), 'U') IS NULL
            THEN '[WILL CREATE] ' ELSE '[EXISTS]      ' END + o.name AS TsgTable
FROM   @owned o
ORDER  BY o.name;
GO

/*--------------------------------------------------------------------------
  5. Row counts - how much data is at risk.
     An empty table can be changed freely. A table with rows is where a
     narrowing change or a new NOT NULL column gets blocked or softened.
--------------------------------------------------------------------------*/
PRINT '';
PRINT '--- 5. Existing data ---';
GO
SELECT   t.name          AS TableName,
         SUM(p.rows)     AS ApproxRows
FROM     sys.tables t
JOIN     sys.partitions p ON p.object_id = t.object_id AND p.index_id IN (0, 1)
WHERE    t.name IN ('Threat_Category','Threat_Type','Threat_Catalogue','Threat_Actor',
                    'Threat_Catalogue_Category_Map','ThreatType_ThreatActor_Map',
                    'Control_Standard','Control_Library','Control_Library_Standard_Map',
                    'API_Client','Config_Tuning','Grounding_Calibration_Run',
                    'Scenario_Session','Subsystem_Stage_State','Identified_Threat',
                    'Identified_Duplicate_Threat','Scoped_Threat','Threat_Scenario',
                    'Threat_Scenario_Control_Map','Risk_Treatment_Plan',
                    'Scenario_Audit','Prompt_Log','Diagnostic_Event')
GROUP BY t.name
HAVING   SUM(p.rows) > 0
ORDER BY SUM(p.rows) DESC;
GO
PRINT ' [INFO]    Any table listed above holds data. Narrowing a column there, or adding a';
PRINT '          NOT NULL column, will be BLOCKED or added as NULL. That is deliberate.';
GO

/*--------------------------------------------------------------------------
  6. The 15 indexes the application refuses to boot without.
     Sources: app/db/invariants.py::REQUIRED_INDEXES (14) AND
              app/db/invariants.py::FILTERED_INDEX_LITERALS, whose second entry
              IX_Session_Active is NOT in REQUIRED_INDEXES. verify_startup runs
              BOTH lists, so a script checking only the first reported a clean
              [PASS] for a database the API would refuse to start against.
     If one is missing after deployment, the API and the workers will not start.
--------------------------------------------------------------------------*/
PRINT '';
PRINT '--- 6. Boot-critical indexes ---';
GO
DECLARE @req TABLE (ix sysname, tbl sysname);
INSERT INTO @req (ix, tbl) VALUES
    ('UX_Session_ActiveAsset','Scenario_Session'),
    ('IX_Session_Active','Scenario_Session'),
    ('UX_Session_IdempotencyKey','Scenario_Session'),
    ('UX_Scenario_ActiveIdentity','Threat_Scenario'),
    ('UX_Scenario_ActiveScoped','Threat_Scenario'),
    ('UX_Scenario_ActiveAccepted','Threat_Scenario'),
    ('UX_ThreatType_NaturalKey','Threat_Type'),
    ('UX_ThreatCatalogue_NaturalKey','Threat_Catalogue'),
    ('UX_ThreatActor_NaturalKey','Threat_Actor'),
    ('UX_ThreatCategory_NaturalKey','Threat_Category'),
    ('UX_SubsystemStageState_SessionSubLevel','Subsystem_Stage_State'),
    ('UX_TreatmentPlan_ActiveScenario','Risk_Treatment_Plan'),
    ('UX_GroundingCalibration_Running','Grounding_Calibration_Run'),
    ('UX_Control_Standard_Name','Control_Standard'),
    ('UX_Control_Library_Code','Control_Library');

SELECT CASE WHEN EXISTS (SELECT 1 FROM sys.indexes i
                         WHERE i.name = r.ix
                           AND i.object_id = OBJECT_ID('dbo.' + QUOTENAME(r.tbl)))
            THEN '[PASS]        ' ELSE '[WILL CREATE] ' END + r.ix + '  on ' + r.tbl
       AS RequiredIndex
FROM   @req r
ORDER  BY r.ix;
GO

PRINT '';
PRINT '==============================================================';
PRINT ' PRE-DEPLOYMENT VALIDATION COMPLETE - nothing was changed.';
PRINT ' Read any [FAIL] or [WARNING] above before continuing.';
PRINT ' Next: 01_tables, then 02_constraints, then 03_indexes.';
PRINT '==============================================================';
GO
