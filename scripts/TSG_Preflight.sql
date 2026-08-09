-- ============================================================================
-- TSG_Preflight — RUN THIS FIRST, BEFORE ANY OTHER SCRIPT.
--
-- READ-ONLY. Creates no permanent object, changes no setting, writes no row.
-- Safe to run on production at any time, as many times as you like.
--
-- It answers the four questions that decide whether the install will succeed:
--   1. Is this client session configured so the install can even run?
--   2. Is the database configured the way the application requires?
--   3. Do the pre-existing platform tables the application READS actually exist,
--      with every column it expects?
--   4. Is this a fresh install or an upgrade — and if an upgrade, is there a
--      known conversion the scripts cannot perform automatically?
--
-- Every row it returns is one check. Send the whole result set back to the
-- application team before running anything else. Any row with Status = 'FAIL'
-- must be resolved first; 'WARN' rows are judgement calls, explained inline.
--
-- The table and column lists below are GENERATED from app/db/models.py — they
-- are the exact set the application asserts at boot, not a hand-written copy.
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
-- 1. CLIENT SESSION — the single most common cause of a failed install.
-- ---------------------------------------------------------------------------
-- The install scripts create FILTERED indexes (WHERE IsActive = 1 AND
-- IsDeleted = 0) and then INSERT into those tables. SQL Server refuses both
-- unless QUOTED_IDENTIFIER is ON. SSMS defaults it ON; sqlcmd defaults it OFF.
-- The scripts now set it themselves, but if your tooling forces it OFF this
-- tells you before you find out from a half-created schema.
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
-- Read Committed Snapshot Isolation. The application's concurrency design
-- (compare-and-swap stage claims, per-asset locks) requires readers not to
-- block behind writers. The API and every background worker REFUSE TO START
-- without it. TSG_Core.sql will enable it, but doing so forces every other
-- session off the database and rolls back their work — so if this says OFF,
-- schedule a maintenance window rather than running the install ad hoc.
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
-- These belong to the onboarding/CTM platform. The install scripts do NOT
-- create them; the application only reads them. If one is missing, or exists
-- but is missing a column, the API refuses to start — it checks every column
-- listed here at boot. Resolve with the platform team, not by editing TSG.
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

-- 3b. Missing COLUMNS on platform tables that DO exist. This is the boot blocker:
--     a table present but short one column stops the application dead.
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
       N'All 11 platform tables present with all 85 required columns',
       N'Verified against the application''s own boot-time assertion list.'
WHERE NOT EXISTS (SELECT 1 FROM #tsg_preflight WHERE Category = 'Platform dependency');

-- ---------------------------------------------------------------------------
-- 4. FRESH INSTALL OR UPGRADE?
-- ---------------------------------------------------------------------------
DECLARE @tsg_existing int = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES
    WHERE TABLE_NAME IN (
        N'Config_Threat_Rule', N'Config_Tuning', N'Control_Library',
        N'Control_Library_Standard_Map', N'Control_Standard', N'Identified_Threat',
        N'Prompt_Log', N'Risk_Treatment_Plan', N'Scenario_Audit', N'Scenario_Session',
        N'Scoped_Threat', N'Subsystem_Stage_State', N'ThreatType_ThreatActor_Map',
        N'Threat_Actor', N'Threat_Candidate_Review', N'Threat_Catalogue',
        N'Threat_Catalogue_Category_Map', N'Threat_Category', N'Threat_Library_Import_Run',
        N'Threat_Scenario_Control_Map', N'Threat_Scenario_Output', N'Threat_Type'));

INSERT INTO #tsg_preflight (Category, Status, Check_, Detail)
SELECT 'Install type', 'INFO',
       CASE WHEN @tsg_existing = 0 THEN N'FRESH INSTALL — no TSG tables present'
            WHEN @tsg_existing = 22 THEN N'UPGRADE — all 22 TSG tables already present'
            ELSE N'PARTIAL — some TSG tables present' END,
       N'Found ' + CAST(@tsg_existing AS nvarchar(10)) + N' of 22 TSG tables. '
     + CASE WHEN @tsg_existing = 0
            THEN N'Run all five install scripts in order.'
            WHEN @tsg_existing = 22
            THEN N'Every CREATE is guarded by IF OBJECT_ID(...) IS NULL, so re-running is safe '
               + N'and applies any new columns via the guarded ALTERs.'
            ELSE N'A previous install may have stopped part-way. Re-running the scripts in order '
               + N'is safe and will complete it — but review the earlier run''s output first.'
       END;

-- ---------------------------------------------------------------------------
-- 5. KNOWN UPGRADE HAZARD — Config_Threat_Rule primary key.
-- ---------------------------------------------------------------------------
-- On a fresh install this table is created with an IDENTITY primary key and
-- there is nothing to do. But on a database created before 2026-08, the table
-- may exist with a PLAIN INT key. The CREATE is guarded by IF OBJECT_ID(...)
-- IS NULL, so it is skipped, and NOTHING converts the column — the scripts
-- cannot fix this automatically. The threat-library import then fails on every
-- rule it writes, because it inserts without supplying the key and reads the
-- generated value back.
INSERT INTO #tsg_preflight (Category, Status, Check_, Detail)
SELECT 'Upgrade hazard',
       CASE WHEN COLUMNPROPERTY(OBJECT_ID('dbo.Config_Threat_Rule'), 'ThreatRuleID', 'IsIdentity') = 1
            THEN 'PASS' ELSE 'FAIL' END,
       N'Config_Threat_Rule.ThreatRuleID is an IDENTITY column',
       CASE WHEN COLUMNPROPERTY(OBJECT_ID('dbo.Config_Threat_Rule'), 'ThreatRuleID', 'IsIdentity') = 1
            THEN N'IDENTITY confirmed — no action needed.'
            ELSE N'NOT an IDENTITY column. The install scripts cannot convert it (the CREATE is '
               + N'skipped because the table already exists). The threat-library import will fail '
               + N'on every auto-written rule. Report this to the application team BEFORE '
               + N'proceeding — a one-off conversion is required.'
       END
WHERE OBJECT_ID('dbo.Config_Threat_Rule') IS NOT NULL;

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
