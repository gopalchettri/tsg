/*==============================================================================
  POST-DEPLOYMENT VALIDATION  (READ ONLY)

  Script:      001_post_deployment_validation.sql
  Order:       99_validation / 001   (run LAST)
  Purpose:     Prove the database now matches what the application needs.
  Depends on:  Every script in 01_tables, 02_constraints and 03_indexes.
  Re-runnable: YES - it reads catalog views only.
  Modifies:    NOTHING.

  This is the sign-off. If the last line says PASS, the application can start.
  If it says FAILED, the rows above name exactly what is missing.

  WHAT IT CANNOT TELL YOU: whether the threat and control LIBRARIES hold data.
  An empty library is a working schema that returns empty results forever, so
  check the seed scripts separately (see the README, step 8).
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;
GO

PRINT '==============================================================';
PRINT ' TSG POST-DEPLOYMENT VALIDATION';
PRINT ' Database: ' + DB_NAME();
PRINT ' Run at:   ' + CONVERT(varchar(19), SYSUTCDATETIME(), 120) + ' UTC';
PRINT '==============================================================';
GO

DECLARE @fail_tables      int = 0,
        @fail_pk          int = 0,
        @fail_indexes     int = 0,
        @fail_constraints int = 0,
        @fail_rcsi        int = 0;

DECLARE @owned TABLE (name sysname);
INSERT INTO @owned (name) VALUES
    ('Threat_Category'), ('Threat_Type'), ('Threat_Catalogue'), ('Threat_Actor'),
    ('Threat_Catalogue_Category_Map'), ('ThreatType_ThreatActor_Map'),
    ('Control_Standard'), ('Control_Library'), ('Control_Library_Standard_Map'),
    ('API_Client'), ('Config_Tuning'), ('Grounding_Calibration_Run'),
    ('Scenario_Session'), ('Subsystem_Stage_State'), ('Identified_Threat'),
    ('Identified_Duplicate_Threat'), ('Scoped_Threat'), ('Threat_Scenario'),
    ('Threat_Scenario_Control_Map'), ('Risk_Treatment_Plan'),
    ('Scenario_Audit'), ('Prompt_Log');

/* 15, not 14. app/db/invariants.py::verify_startup runs REQUIRED_INDEXES (14 names) AND
   FILTERED_INDEX_LITERALS, whose second entry IX_Session_Active appears in neither the
   REQUIRED_INDEXES list nor, previously, this one. Checking only REQUIRED_INDEXES signed off
   "Overall: PASS" on a database the API would then refuse to boot against - the precise failure
   this script exists to prevent. */
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

DECLARE @checks TABLE (name sysname);
INSERT INTO @checks (name) VALUES
    ('CK_Config_Tuning_ValueType'), ('CK_Session_Status'), ('CK_Scenario_DecisionExclusive');

/*-------------------------- tables --------------------------*/
SELECT @fail_tables = COUNT(*)
FROM   @owned o WHERE OBJECT_ID('dbo.' + QUOTENAME(o.name), 'U') IS NULL;

IF @fail_tables > 0
    SELECT '[FAIL] missing table: ' + o.name AS Problem
    FROM   @owned o WHERE OBJECT_ID('dbo.' + QUOTENAME(o.name), 'U') IS NULL;

/*-------------------------- primary keys --------------------------*/
SELECT @fail_pk = COUNT(*)
FROM   @owned o
WHERE  OBJECT_ID('dbo.' + QUOTENAME(o.name), 'U') IS NOT NULL
  AND  NOT EXISTS (SELECT 1 FROM sys.key_constraints k
                   WHERE k.parent_object_id = OBJECT_ID('dbo.' + QUOTENAME(o.name))
                     AND k.type = 'PK');

IF @fail_pk > 0
    SELECT '[FAIL] no primary key on: ' + o.name AS Problem
    FROM   @owned o
    WHERE  OBJECT_ID('dbo.' + QUOTENAME(o.name), 'U') IS NOT NULL
      AND  NOT EXISTS (SELECT 1 FROM sys.key_constraints k
                       WHERE k.parent_object_id = OBJECT_ID('dbo.' + QUOTENAME(o.name))
                         AND k.type = 'PK');

/*-------------------------- boot-critical indexes --------------------------
  `is_disabled = 0` is part of the match, not an afterthought. A DISABLED index still has its
  row in sys.indexes, so matching on name + table alone reported [PASS] for an index SQL Server
  will not use and that enforces nothing - and every one of these is a UNIQUE constraint the
  application leans on for a race it cannot otherwise win (one active session per asset, one
  accepted version per scenario, one running calibration). Signing off on a disabled uniqueness
  guard is worse than reporting it missing, because nothing else will ever mention it again.

  WHAT THIS STILL DOES NOT CHECK, stated rather than implied: the index's COLUMN LIST and its
  filter predicate. An index carrying the right name over the wrong columns passes here. Column
  and filter verification would need the expected definitions generated from the DDL; until that
  exists, do not read a PASS on this line as "the indexes are correct", only as "they are present
  and enabled".
--------------------------------------------------------------------*/
SELECT @fail_indexes = COUNT(*)
FROM   @req r
WHERE  NOT EXISTS (SELECT 1 FROM sys.indexes i
                   WHERE i.name = r.ix
                     AND i.object_id = OBJECT_ID('dbo.' + QUOTENAME(r.tbl))
                     AND i.is_disabled = 0);

IF @fail_indexes > 0
    SELECT '[FAIL] ' +
           CASE WHEN EXISTS (SELECT 1 FROM sys.indexes i
                             WHERE i.name = r.ix
                               AND i.object_id = OBJECT_ID('dbo.' + QUOTENAME(r.tbl)))
                THEN 'DISABLED index: ' ELSE 'missing index: ' END
           + r.ix + ' on ' + r.tbl +
           '  -> the API and workers will NOT start' AS Problem
    FROM   @req r
    WHERE  NOT EXISTS (SELECT 1 FROM sys.indexes i
                       WHERE i.name = r.ix
                         AND i.object_id = OBJECT_ID('dbo.' + QUOTENAME(r.tbl))
                         AND i.is_disabled = 0);

/*-------------------------- check constraints --------------------------*/
SELECT @fail_constraints = COUNT(*)
FROM   @checks c
WHERE  NOT EXISTS (SELECT 1 FROM sys.check_constraints k WHERE k.name = c.name);

IF @fail_constraints > 0
    SELECT '[FAIL] missing check constraint: ' + c.name AS Problem
    FROM   @checks c
    WHERE  NOT EXISTS (SELECT 1 FROM sys.check_constraints k WHERE k.name = c.name);

/*-------------------------- isolation level --------------------------
  FAIL-OPEN BUG THIS REPLACES, because it is the exact failure a sign-off script
  must not have: DATABASEPROPERTYEX returned NULL on a SQL Server 2022 Express
  instance, and `NULL <> 1` is UNKNOWN - so the SET never ran, @fail_rcsi stayed
  0, and this script printed "Isolation: PASS" and "Overall: PASS" having checked
  nothing at all. A verdict that cannot tell ON from unreadable is not a verdict.

  sys.databases.is_read_committed_snapshot_on is a non-nullable bit for every
  database. NULL here means the row was not visible, which is a FAILURE, not a
  pass - this script's whole job is to say whether the application may start.
--------------------------------------------------------------------*/
DECLARE @rcsi bit = (SELECT d.is_read_committed_snapshot_on
                     FROM sys.databases d WHERE d.database_id = DB_ID());
IF @rcsi IS NULL OR @rcsi = 0
    SET @fail_rcsi = 1;

/*-------------------------- counts, for the record --------------------------*/
PRINT '';
PRINT '--- counted in this database ---';
DECLARE @t int = (SELECT COUNT(*) FROM @owned o
                  WHERE OBJECT_ID('dbo.' + QUOTENAME(o.name), 'U') IS NOT NULL);
DECLARE @i int = (SELECT COUNT(*) FROM sys.indexes i
                  JOIN sys.tables tb ON tb.object_id = i.object_id
                  WHERE tb.name IN (SELECT name FROM @owned)
                    AND i.name IS NOT NULL AND i.is_primary_key = 0);
DECLARE @d int = (SELECT COUNT(*) FROM sys.default_constraints dc
                  JOIN sys.tables tb ON tb.object_id = dc.parent_object_id
                  WHERE tb.name IN (SELECT name FROM @owned));
PRINT ' [INFO]    Tables:              ' + CAST(@t AS varchar(10)) + ' of 22';
PRINT ' [INFO]    Non-PK indexes:      ' + CAST(@i AS varchar(10)) +
      '  (32 expected: 31 from 03_indexes + UQ_Config_Tuning_Key)';
PRINT ' [INFO]    Default constraints: ' + CAST(@d AS varchar(10)) + '  (22 expected)';

/*-------------------------- the verdict --------------------------*/
PRINT '';
PRINT 'DATABASE VALIDATION RESULT';
PRINT '--------------------------';
PRINT 'Tables:        ' + CASE WHEN @fail_tables      = 0 THEN 'PASS' ELSE 'FAILED' END;
PRINT '  (columns are NOT checked here - see 002_schema_verdict.sql)';
PRINT 'Primary keys:  ' + CASE WHEN @fail_pk          = 0 THEN 'PASS' ELSE 'FAILED' END;
PRINT 'Indexes:       ' + CASE WHEN @fail_indexes     = 0 THEN 'PASS' ELSE 'FAILED' END;
PRINT 'Constraints:   ' + CASE WHEN @fail_constraints = 0 THEN 'PASS' ELSE 'FAILED' END;
PRINT 'Isolation:     ' + CASE WHEN @fail_rcsi        = 0 THEN 'PASS' ELSE 'FAILED' END;
PRINT '';

IF (@fail_tables + @fail_pk + @fail_indexes + @fail_constraints + @fail_rcsi) = 0
BEGIN
    PRINT 'Objects: PASS';
    PRINT '';
    PRINT 'NOT YET A SIGN-OFF. The five verdicts above cover OBJECTS only - tables, primary';
    PRINT 'keys, indexes, check constraints, isolation. Not one of them reads a COLUMN, so a';
    PRINT 'deployment that printed [BLOCKED] on a narrowing change, or added a NOT NULL column';
    PRINT 'as NULL because the table had rows, reaches this line looking clean.';
    PRINT '';
    PRINT 'Run 99_validation/002_schema_verdict.sql now. It checks all 319 columns, all 32';
    PRINT 'index shapes, 21 defaults, 6 identity columns and the collation, then prints the';
    PRINT 'FINAL SIGN-OFF. Then confirm the threat and control libraries hold data';
    PRINT '(README step 11) before starting the application.';
END
ELSE
BEGIN
    PRINT 'Objects: FAILED';
    PRINT '';
    PRINT 'Fix the rows listed above and re-run the matching script. Every script in';
    PRINT 'this package is safe to run again.';
    IF @fail_rcsi = 1
    BEGIN
        PRINT '';
        PRINT 'ISOLATION prints no row to fix, so here is its one: run';
        PRINT '00_validation/002_enable_isolation_level.sql. It turns the setting on without';
        PRINT 'waiting for, or disconnecting, anybody, and reports who is holding it if it';
        PRINT 'cannot. The application does not start until this says PASS.';
    END;
END;
GO
