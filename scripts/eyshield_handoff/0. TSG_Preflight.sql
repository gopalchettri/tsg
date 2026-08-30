-- ============================================================================
-- TSG_Preflight — RUN FIRST, before any other script. READ-ONLY: creates
-- nothing, changes nothing, writes no row.
--
-- Every row is one check. Send the whole result set to the application team
-- before running anything else. FAIL must be resolved first; WARN rows are
-- judgement calls, explained in the Detail column.
--
-- Table and column lists are generated from app/db/models.py.
-- ============================================================================

SET NOCOUNT ON;

IF OBJECT_ID('tempdb..#tsg_preflight') IS NOT NULL DROP TABLE #tsg_preflight;
CREATE TABLE #tsg_preflight (
    Seq      int IDENTITY(1,1),
    Category nvarchar(40),
    Status   nvarchar(8),
    Check_   nvarchar(200),
    Detail   nvarchar(1000)
);

-- ---------------------------------------------------------------------------
-- 1. CLIENT SESSION — the most common cause of a failed install.
-- ---------------------------------------------------------------------------
-- Filtered indexes, and inserts against them, need QUOTED_IDENTIFIER ON (SSMS
-- defaults ON, sqlcmd OFF). The scripts set it themselves; this warns if your
-- tooling forces it back OFF.
INSERT INTO #tsg_preflight (Category, Status, Check_, Detail)
SELECT 'Session',
       CASE WHEN SESSIONPROPERTY('QUOTED_IDENTIFIER') = 1 THEN 'PASS' ELSE 'WARN' END,
       'QUOTED_IDENTIFIER is ON for this session',
       CASE WHEN SESSIONPROPERTY('QUOTED_IDENTIFIER') = 1
            THEN N'ON — filtered indexes and their inserts will succeed.'
            ELSE N'OFF. The install scripts set it themselves, so this is usually fine. '
               + N'If any script still fails with Msg 1934, re-run sqlcmd with the -I flag.'
       END;

-- ---------------------------------------------------------------------------
-- 2. DATABASE CONFIGURATION
-- ---------------------------------------------------------------------------
-- RCSI: the API and every worker REFUSE TO START without it. TSG_Core.sql
-- enables it, but that forces every other session off the database — if this
-- says OFF, schedule a maintenance window.
INSERT INTO #tsg_preflight (Category, Status, Check_, Detail)
SELECT 'Database',
       CASE WHEN d.is_read_committed_snapshot_on = 1 THEN 'PASS' ELSE 'WARN' END,
       'Read Committed Snapshot Isolation (RCSI) enabled',
       CASE WHEN d.is_read_committed_snapshot_on = 1
            THEN N'Already ON — TSG_Core.sql will skip the change entirely.'
            ELSE N'OFF. TSG_Core.sql will run ALTER DATABASE SET SINGLE_USER WITH ROLLBACK '
               + N'IMMEDIATE to enable it, which DISCONNECTS every other session and rolls '
               + N'back in-flight work. MAINTENANCE WINDOW REQUIRED.'
       END
FROM sys.databases d WHERE d.database_id = DB_ID();

INSERT INTO #tsg_preflight (Category, Status, Check_, Detail)
SELECT 'Database', 'INFO', 'Target database / server',
       N'Database: ' + DB_NAME() + N'  |  Server: ' + CAST(SERVERPROPERTY('ServerName') AS nvarchar(200))
     + N'  |  Version: ' + CAST(SERVERPROPERTY('ProductMajorVersion') AS nvarchar(10))
     + N'  |  Collation: ' + CAST(DATABASEPROPERTYEX(DB_NAME(), 'Collation') AS nvarchar(200));

-- ---------------------------------------------------------------------------
-- 3. PLATFORM DEPENDENCIES — tables TSG READS but never creates.
-- ---------------------------------------------------------------------------
-- Owned by the onboarding/CTM platform; TSG only reads them. A missing table,
-- or one missing a column, stops the API at boot. Resolve with the platform
-- team, not by editing TSG.
DECLARE @platform_cols TABLE (TableName sysname, ColumnName sysname);
INSERT INTO @platform_cols (TableName, ColumnName) VALUES
    (N'ctm_scan_category', N'id'),
    (N'ctm_scan_category', N'parent_id'),
    (N'ctm_scan_category', N'code'),
    (N'ctm_scan_category', N'name'),
    (N'ctm_scan_entity', N'id'),
    (N'ctm_scan_entity', N'type'),
    (N'ctm_scan_entity', N'name'),
    (N'ctm_scan_entity', N'description'),
    (N'ctm_scan_entity', N'criticality'),
    (N'ctm_scan_entity', N'operating_system'),
    (N'ctm_scan_entity', N'location'),
    (N'ctm_scan_entity', N'owner_custodian'),
    (N'ctm_scan_entity', N'target_rto_hours'),
    (N'ctm_scan_entity', N'target_rpo_hours'),
    (N'ctm_scan_entity', N'tier1_critical_service_id'),
    (N'ctm_scan_entity', N'data_handled'),
    (N'ctm_scan_entity', N'ctm_category_id'),
    (N'ctm_scan_entity_bu', N'id'),
    (N'ctm_scan_entity_bu', N'ctm_scan_entity_id'),
    (N'ctm_scan_entity_bu', N'group_id'),
    (N'ctm_scan_entity_bu', N'service_id'),
    (N'ctm_scan_entity_supporting_system', N'ctm_scan_entity_id'),
    (N'ctm_scan_entity_supporting_system', N'onboarding_supporting_system_id'),
    (N'onboarding_sectors', N'id'),
    (N'onboarding_sectors', N'name'),
    (N'onboarding_sectors', N'parent_id'),
    (N'onboarding_sectors', N'definition'),
    (N'onboarding_services', N'id'),
    (N'onboarding_services', N'name'),
    (N'onboarding_services', N'description'),
    (N'onboarding_services', N'sector_id'),
    (N'onboarding_supporting_systems', N'id'),
    (N'onboarding_supporting_systems', N'name'),
    (N'onboarding_supporting_systems', N'asset_type'),
    (N'onboarding_supporting_systems', N'min_no_of_transactions'),
    (N'onboarding_supporting_systems', N'max_no_of_transactions'),
    (N'onboarding_supporting_systems', N'url'),
    (N'onboarding_supporting_systems', N'accessability_channel'),
    (N'onboarding_supporting_systems', N'technology_used'),
    (N'onboarding_supporting_systems', N'user_base_count'),
    (N'onboarding_supporting_systems', N'targeted_users'),
    (N'onboarding_supporting_systems', N'managed_by'),
    (N'onboarding_supporting_systems', N'vendor_name'),
    (N'onboarding_supporting_systems', N'maintenance_contract_exists'),
    (N'onboarding_supporting_systems', N'hosting_location'),
    (N'onboarding_supporting_systems', N'dr_location'),
    (N'onboarding_supporting_systems', N'network_connectivity_primary_dr'),
    (N'onboarding_supporting_systems', N'last_dr_test_date'),
    (N'onboarding_supporting_systems', N'backup_multi_site'),
    (N'onboarding_supporting_systems', N'backup_retention_period_days'),
    (N'onboarding_supporting_systems', N'backup_tested'),
    (N'onboarding_supporting_systems', N'offsite_air_gapped_backup'),
    (N'onboarding_supporting_systems', N'data_residency_restrictions'),
    (N'onboarding_supporting_systems', N'data_residency_restriction_justification'),
    (N'onboarding_supporting_systems', N'document_drp_exists'),
    (N'onboarding_supporting_systems', N'dr_drill_frequency'),
    (N'onboarding_supporting_systems', N'database_platforms'),
    (N'onboarding_supporting_systems', N'saas_backup_required'),
    (N'onboarding_supporting_systems', N'saas_platform_list'),
    (N'onboarding_supporting_systems', N'public_cloud_platforms'),
    (N'onboarding_supporting_systems', N'rto_target_mins'),
    (N'onboarding_supporting_systems', N'rpo_target_mins'),
    (N'onboarding_supporting_systems', N'data_loss_incident_last_3_years'),
    (N'onboarding_supporting_systems', N'incident_description'),
    (N'onboarding_supporting_systems', N'is_deleted'),
    (N'onboarding_supporting_systems', N'delete_reason'),
    (N'onboarding_supporting_systems', N'creation_date'),
    (N'onboarding_supporting_systems', N'date_updated'),
    (N'onboarding_supporting_systems', N'created_by'),
    (N'onboarding_supporting_systems', N'updated_by'),
    (N'option', N'id'),
    (N'option', N'option'),
    (N'option', N'code'),
    (N'option_value', N'id'),
    (N'option_value', N'name'),
    (N'option_value', N'value'),
    (N'option_value', N'option_id'),
    (N'option_value', N'description'),
    (N'user', N'id'),
    (N'user', N'username'),
    (N'user', N'email');

-- 3a. Missing platform TABLES.
INSERT INTO #tsg_preflight (Category, Status, Check_, Detail)
SELECT 'Platform dependency', 'FAIL',
       N'Platform table missing: ' + t.TableName,
       N'TSG reads this table but never creates it. The API will not start until the platform '
     + N'team provides it. Do NOT attempt to create it from the TSG scripts.'
FROM (SELECT DISTINCT TableName FROM @platform_cols) t
WHERE NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.TABLES i
                  WHERE i.TABLE_NAME = t.TableName);

-- 3b. Missing COLUMNS on tables that DO exist — one missing column stops the
--     application dead at boot.
INSERT INTO #tsg_preflight (Category, Status, Check_, Detail)
SELECT 'Platform dependency', 'FAIL',
       N'Platform column missing: ' + p.TableName + N'.' + p.ColumnName,
       N'The table exists but this column does not. The application asserts every mapped column '
     + N'at boot and will refuse to start. Raise with the platform team.'
FROM @platform_cols p
WHERE EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.TABLES i WHERE i.TABLE_NAME = p.TableName)
  AND NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS c
                  WHERE c.TABLE_NAME = p.TableName AND c.COLUMN_NAME = p.ColumnName);

-- 3c. All-clear line, so a clean run still produces visible evidence.
INSERT INTO #tsg_preflight (Category, Status, Check_, Detail)
SELECT 'Platform dependency', 'PASS',
       N'All 10 platform tables present with all 81 required columns',
       N'Verified against the application''s own boot-time assertion list.'
WHERE NOT EXISTS (SELECT 1 FROM #tsg_preflight WHERE Category = 'Platform dependency');

-- ---------------------------------------------------------------------------
-- 4. FRESH INSTALL OR UPGRADE?
-- ---------------------------------------------------------------------------
DECLARE @tsg_existing int = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES
    WHERE TABLE_NAME IN (
        N'Config_Tuning', N'Control_Library',
        N'Control_Library_Standard_Map', N'Control_Standard', N'Identified_Threat',
        N'Prompt_Log', N'Risk_Treatment_Plan', N'Scenario_Audit', N'Scenario_Session',
        N'Scenario_Library', N'Grounding_Calibration_Run',
        N'Scoped_Threat', N'Subsystem_Stage_State',
        N'Threat_Actor', N'Threat_Catalogue', N'Threat_Catalogue_Category_Map',
        N'Threat_Category', N'ThreatType_ThreatActor_Map',
        N'Threat_Scenario_Control_Map', N'Threat_Scenario', N'Threat_Scenario_Output',
        N'Threat_Type'));
-- 22 names, at most 21 present at once: a database carries EITHER
-- Threat_Scenario_Output OR the renamed Threat_Scenario, never both. This runs
-- before TSG_Core.sql renames it, so 21 is the correct expected count.

INSERT INTO #tsg_preflight (Category, Status, Check_, Detail)
SELECT 'Install type', 'INFO',
       CASE WHEN @tsg_existing = 0 THEN N'FRESH INSTALL — no TSG tables present'
            WHEN @tsg_existing = 21 THEN N'UPGRADE — all 21 TSG tables already present'
            ELSE N'PARTIAL — some TSG tables present' END,
       N'Found ' + CAST(@tsg_existing AS nvarchar(10)) + N' of 21 TSG tables. '
     + CASE WHEN @tsg_existing = 0
            THEN N'Run all five install scripts in order.'
            WHEN @tsg_existing = 21
            THEN N'Every CREATE is guarded by IF OBJECT_ID(...) IS NULL, so re-running is safe '
               + N'and applies any new columns via the guarded ALTERs.'
            ELSE N'A previous install may have stopped part-way. Re-running the scripts in order '
               + N'is safe and will complete it — but review the earlier run''s output first.'
       END;


-- ---------------------------------------------------------------------------
-- RESULT
-- ---------------------------------------------------------------------------
SELECT Category, Status, Check_ AS [Check], Detail
FROM #tsg_preflight
ORDER BY CASE Status WHEN 'FAIL' THEN 1 WHEN 'WARN' THEN 2 WHEN 'INFO' THEN 3 ELSE 4 END, Seq;

DECLARE @fails int = (SELECT COUNT(*) FROM #tsg_preflight WHERE Status = 'FAIL');
SELECT CASE WHEN @fails = 0
            THEN N'PREFLIGHT PASSED — safe to run the install scripts in order.'
            ELSE N'PREFLIGHT FAILED — ' + CAST(@fails AS nvarchar(10))
               + N' blocking issue(s) above. Resolve them before running any install script.'
       END AS [Preflight result];

DROP TABLE #tsg_preflight;
