-- ============================================================================
-- TSG_Verify — RUN THIS LAST, AFTER ALL FIVE INSTALL SCRIPTS.
--
-- READ-ONLY. Creates no permanent object, changes no setting, writes no row.
-- Safe to run on production at any time, as many times as you like.
--
-- This is the sign-off. It proves the install actually worked, rather than
-- assuming it did because no error scrolled past. Every row is one check.
-- Send the whole result set back to the application team.
--
-- WHY THIS EXISTS: two of the ways this install can fail are SILENT. A script
-- that aborts half way still leaves a database that looks populated, and a
-- seed script that inserts nothing leaves an application that starts normally
-- and then produces empty results forever. Neither shows up as an error at
-- deploy time. This script catches both.
--
-- The expected tables and indexes below are GENERATED from app/db/models.py
-- and the application's own boot-time assertion list — not a hand-written copy.
-- ============================================================================

-- QI ON is required by the FOR XML column-list checks below (XML data type methods err
-- Msg 1934 under QI OFF) — set here so the script runs identically from SSMS (QI defaults
-- ON) and from `sqlcmd` (defaults OFF unless -I), same posture as TSG_Core.sql.
SET QUOTED_IDENTIFIER ON;
SET NOCOUNT ON;

IF OBJECT_ID('tempdb..#tsg_verify') IS NOT NULL DROP TABLE #tsg_verify;
CREATE TABLE #tsg_verify (
    Seq      int IDENTITY(1,1),
    Category nvarchar(40),
    Status   nvarchar(8),
    Check_   nvarchar(200),
    Detail   nvarchar(1000)
);

-- ---------------------------------------------------------------------------
-- 1. ALL 23 TSG TABLES EXIST
-- ---------------------------------------------------------------------------
DECLARE @tsg_tables TABLE (TableName sysname);
INSERT INTO @tsg_tables (TableName) VALUES
    (N'API_Client'),
    (N'Config_Threat_Rule'),
    (N'Config_Tuning'),
    (N'Control_Library'),
    (N'Control_Library_Standard_Map'),
    (N'Control_Standard'),
    (N'Identified_Threat'),
    (N'Prompt_Log'),
    (N'Risk_Treatment_Plan'),
    (N'Scenario_Audit'),
    (N'Scenario_Session'),
    (N'Scoped_Threat'),
    (N'Subsystem_Stage_State'),
    (N'ThreatType_ThreatActor_Map'),
    (N'Threat_Actor'),
    (N'Threat_Candidate_Review'),
    (N'Threat_Catalogue'),
    (N'Threat_Catalogue_Category_Map'),
    (N'Threat_Category'),
    (N'Threat_Library_Import_Run'),
    (N'Threat_Scenario_Control_Map'),
    (N'Threat_Scenario_Output'),
    (N'Threat_Type');

INSERT INTO #tsg_verify (Category, Status, Check_, Detail)
SELECT 'Tables', 'FAIL', N'Table missing: ' + t.TableName,
       N'Expected by the application but not present. The script that creates it did not '
     + N'complete — re-run the install scripts in order and review the output.'
FROM @tsg_tables t
WHERE NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.TABLES i WHERE i.TABLE_NAME = t.TableName);

INSERT INTO #tsg_verify (Category, Status, Check_, Detail)
SELECT 'Tables', 'PASS', N'All 23 TSG tables present', N'Nothing missing.'
WHERE NOT EXISTS (SELECT 1 FROM #tsg_verify WHERE Category = 'Tables');

-- ---------------------------------------------------------------------------
-- 2. THE 12 INDEXES THE APPLICATION ASSERTS AT BOOT
-- ---------------------------------------------------------------------------
-- These are not performance indexes. Each one enforces a correctness rule the
-- code relies on — one active session per asset, one active scenario per
-- identity, unique library natural keys, and so on. The application checks all
-- twelve at every start and REFUSES TO BOOT if one is missing, on the wrong
-- table, or missing a column.
DECLARE @req_indexes TABLE (IndexName sysname, TableName sysname, Cols nvarchar(400));
INSERT INTO @req_indexes (IndexName, TableName, Cols) VALUES
    (N'UX_Session_ActiveAsset', N'Scenario_Session', N'EntityID,AssetID'),
    (N'UX_Scenario_ActiveIdentity', N'Threat_Scenario_Output', N'SessionID,IdentityHash,ScenarioNumber'),
    (N'UX_ThreatType_NaturalKey', N'Threat_Type', N'ThreatTypeName,ThreatCategoryID,SectorID'),
    (N'UX_ThreatCatalogue_NaturalKey', N'Threat_Catalogue', N'ThreatTypeID,ThreatName,SectorID'),
    (N'UX_ThreatActor_NaturalKey', N'Threat_Actor', N'ThreatActorName'),
    (N'UX_ThreatCategory_NaturalKey', N'Threat_Category', N'ThreatCategoryName'),
    (N'UX_SubsystemStageState_SessionSubLevel', N'Subsystem_Stage_State', N'SessionID,SubsystemID,Level'),
    (N'UX_TreatmentPlan_ActiveOutput', N'Risk_Treatment_Plan', N'OutputID'),
    (N'UX_ConfigThreatRule_NaturalKey', N'Config_Threat_Rule', N'ThreatTypeID,RuleType,RuleKey,RuleValue'),
    (N'UX_Session_IdempotencyKey', N'Scenario_Session', N'EntityID,IdempotencyKey'),
    (N'UX_Control_Standard_Name', N'Control_Standard', N'StandardName'),
    (N'UX_Control_Library_Code', N'Control_Library', N'ControlCode');

-- Missing entirely, or on the wrong table.
INSERT INTO #tsg_verify (Category, Status, Check_, Detail)
SELECT 'Indexes', 'FAIL', N'Index missing: ' + r.IndexName + N' on ' + r.TableName,
       N'The application asserts this index at boot and will NOT START without it. Expected '
     + N'columns: ' + r.Cols + N'. If Threat_library.sql or Control_library.sql reported '
     + N'Msg 1934, that is the cause — re-run it with QUOTED_IDENTIFIER ON (sqlcmd -I).'
FROM @req_indexes r
WHERE NOT EXISTS (
    SELECT 1 FROM sys.indexes i
    JOIN sys.tables t ON t.object_id = i.object_id
    WHERE i.name = r.IndexName AND t.name = r.TableName);

-- Present but not UNIQUE, or disabled — both defeat the guarantee.
INSERT INTO #tsg_verify (Category, Status, Check_, Detail)
SELECT 'Indexes', 'FAIL', N'Index not usable: ' + r.IndexName,
       N'Exists on ' + r.TableName + N' but is_unique=' + CAST(i.is_unique AS nvarchar(2))
     + N', is_disabled=' + CAST(i.is_disabled AS nvarchar(2))
     + N'. It must be UNIQUE and enabled, or duplicate rows will be silently accepted.'
FROM @req_indexes r
JOIN sys.tables t ON t.name = r.TableName
JOIN sys.indexes i ON i.object_id = t.object_id AND i.name = r.IndexName
WHERE i.is_unique = 0 OR i.is_disabled = 1;

-- Present and unique, but built on the wrong columns.
INSERT INTO #tsg_verify (Category, Status, Check_, Detail)
SELECT 'Indexes', 'FAIL', N'Index has wrong columns: ' + r.IndexName,
       N'Expected (' + r.Cols + N') but found (' + actual.ColList + N') on ' + r.TableName
     + N'. Drop it and re-run the script that creates it.'
FROM @req_indexes r
JOIN sys.tables t ON t.name = r.TableName
JOIN sys.indexes i ON i.object_id = t.object_id AND i.name = r.IndexName
CROSS APPLY (
    SELECT STUFF((SELECT N',' + c.name
                  FROM sys.index_columns ic
                  JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
                  WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id
                    AND ic.is_included_column = 0
                  ORDER BY ic.key_ordinal
                  FOR XML PATH(''), TYPE).value('.', 'nvarchar(400)'), 1, 1, '') AS ColList
) actual
WHERE actual.ColList <> r.Cols;

INSERT INTO #tsg_verify (Category, Status, Check_, Detail)
SELECT 'Indexes', 'PASS', N'All 12 boot-asserted indexes present, unique and correct',
       N'The application''s startup index check will pass.'
WHERE NOT EXISTS (SELECT 1 FROM #tsg_verify WHERE Category = 'Indexes');

-- ---------------------------------------------------------------------------
-- 3. COLUMNS ADDED BY ALTER — the silent casualty of a part-way abort
-- ---------------------------------------------------------------------------
-- Threat_Type.Source and Threat_Catalogue.Source are added by ALTER statements
-- near the END of Threat_library.sql. If that script aborted at its first
-- filtered index, the tables exist but these two columns do not — and the seed
-- script then fails on every row, because it names Source explicitly.
INSERT INTO #tsg_verify (Category, Status, Check_, Detail)
SELECT 'Columns', 'FAIL', N'Column missing: ' + x.T + N'.Source',
       N'Added by an ALTER near the end of Threat_library.sql. Its absence means that script '
     + N'did not run to completion. Re-run it, then re-run Seed_to_Threat_library.sql.'
FROM (VALUES (N'Threat_Type'), (N'Threat_Catalogue')) AS x(T)
WHERE OBJECT_ID(N'dbo.' + x.T) IS NOT NULL
  AND COL_LENGTH(N'dbo.' + x.T, N'Source') IS NULL;

INSERT INTO #tsg_verify (Category, Status, Check_, Detail)
SELECT 'Columns', 'PASS', N'Late-ALTER columns present (Threat_Type.Source, Threat_Catalogue.Source)',
       N'Confirms Threat_library.sql ran to completion.'
WHERE NOT EXISTS (SELECT 1 FROM #tsg_verify WHERE Category = 'Columns');

-- ---------------------------------------------------------------------------
-- 4. ENUM COLUMNS ARE WIDE ENOUGH FOR THE VALUES THE APPLICATION WRITES
-- ---------------------------------------------------------------------------
-- The third silent failure mode. A column narrower than the longest value its
-- enum can hold breaks ONLY when that one value is first written — every other
-- value inserts fine, so the install looks clean, the application starts, and
-- sessions run normally until they reach that one state.
--
-- This has shipped: Scenario_Session.StageStatus was nvarchar(20) and could not
-- hold 'SCENARIOS_AWAITING_DECISION' (27 chars), the value that marks the review
-- barrier. Threat and scenario generation completed correctly, then the session
-- froze forever at the hand-off to review, and the truncation error was swallowed
-- by the reaper's own per-session error handling. Nothing in this script would
-- have caught it — tables and indexes were all present and correct.
--
-- NeedChars is the longest member of each enum in app/core/enums.py.
-- CHARACTER_MAXIMUM_LENGTH is in CHARACTERS; COL_LENGTH would report bytes
-- (2x for nvarchar) and is deliberately not used here.
DECLARE @enum_cols TABLE (
    TableName sysname, ColumnName sysname, NeedChars int,
    EnumName nvarchar(40), LongestValue nvarchar(100));
INSERT INTO @enum_cols (TableName, ColumnName, NeedChars, EnumName, LongestValue) VALUES
    (N'Scenario_Session',            N'SessionStatus',      9, N'SessionStatus',          N'completed'),
    (N'Scenario_Session',            N'CurrentStage',      21, N'WorkflowStage',          N'THREAT_IDENTIFICATION'),
    (N'Scenario_Session',            N'StageStatus',       27, N'StageStatus',            N'SCENARIOS_AWAITING_DECISION'),
    (N'Scenario_Session',            N'Mode',               4, N'SessionMode',            N'AUTO'),
    (N'Subsystem_Stage_State',       N'Level',              9, N'SubsystemLevel',         N'SCENARIOS'),
    (N'Subsystem_Stage_State',       N'Status',            27, N'StageStatus',            N'SCENARIOS_AWAITING_DECISION'),
    (N'Identified_Threat',           N'GroundingStatus',   10, N'GroundingStatus',        N'unverified'),
    (N'Identified_Duplicate_Threat', N'DuplicateReason',   23, N'DuplicateReason',        N'semantic_cross_category'),
    (N'Threat_Scenario_Output',      N'Status',             8, N'ScenarioStatus',         N'complete'),
    (N'Threat_Candidate_Review',     N'Status',             8, N'CandidateStatus',        N'accepted'),
    (N'Threat_Library_Import_Run',   N'Status',             7, N'import run status',      N'running'),
    (N'Config_Threat_Rule',          N'RuleType',          23, N'ThreatRuleType',         N'relevance_context_value'),
    (N'Risk_Treatment_Plan',         N'Status',             8, N'StageStatus subset',     N'COMPLETE'),
    (N'Risk_Treatment_Plan',         N'TreatmentStrategy',  8, N'TreatmentStrategy',      N'Mitigate'),
    (N'Risk_Treatment_Plan',         N'RiskLevel',          8, N'RiskLevel',              N'Critical'),
    (N'Risk_Treatment_Plan',         N'ReviewStatus',       8, N'TreatmentReviewStatus',  N'approved'),
    (N'Risk_Treatment_Plan',         N'ErrorReason',       17, N'TreatmentOutcomeReason', N'generation_failed'),
    (N'Scenario_Audit',              N'Stage',             21, N'WorkflowStage',          N'THREAT_IDENTIFICATION'),
    (N'Scenario_Audit',              N'EventType',         24, N'AuditEventType',         N'treatment_plan_requested'),
    (N'Scenario_Audit',              N'Decision',          10, N'AuditDecision',          N'regenerate'),
    (N'Scenario_Audit',              N'Granularity',        8, N'RegenGranularity',       N'scenario'),
    (N'Scenario_Audit',              N'ActorType',          6, N'ActorType',              N'system');

-- Too narrow: the application will fail on ONE value and work for all the others.
INSERT INTO #tsg_verify (Category, Status, Check_, Detail)
SELECT 'Column width', 'FAIL', N'Too narrow: ' + e.TableName + N'.' + e.ColumnName,
       N'Declared nvarchar(' + CAST(c.CHARACTER_MAXIMUM_LENGTH AS nvarchar(10)) + N') but '
     + e.EnumName + N' can write ''' + e.LongestValue + N''' ('
     + CAST(e.NeedChars AS nvarchar(10)) + N' chars). Every shorter value inserts normally, so the '
     + N'application appears healthy until it first reaches that state — then that write fails and '
     + N'the workflow stalls with no obvious cause. Widen to at least nvarchar('
     + CAST(e.NeedChars AS nvarchar(10)) + N').'
FROM @enum_cols e
JOIN INFORMATION_SCHEMA.COLUMNS c
  ON c.TABLE_NAME = e.TableName AND c.COLUMN_NAME = e.ColumnName
WHERE c.CHARACTER_MAXIMUM_LENGTH <> -1          -- -1 = nvarchar(max): always sufficient
  AND c.CHARACTER_MAXIMUM_LENGTH < e.NeedChars;

-- Absent altogether — without this the JOIN above drops the row and passes silently.
-- Guarded on the table existing, so a missing TABLE is still reported once, by section 1.
INSERT INTO #tsg_verify (Category, Status, Check_, Detail)
SELECT 'Column width', 'FAIL', N'Column missing: ' + e.TableName + N'.' + e.ColumnName,
       N'The application writes ' + e.EnumName + N' values here but the column does not exist. '
     + N'The script that creates or alters ' + e.TableName + N' did not complete — re-run the '
     + N'install scripts in order and review the output.'
FROM @enum_cols e
WHERE OBJECT_ID(N'dbo.' + e.TableName) IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS c
                  WHERE c.TABLE_NAME = e.TableName AND c.COLUMN_NAME = e.ColumnName);

INSERT INTO #tsg_verify (Category, Status, Check_, Detail)
SELECT 'Column width', 'PASS', N'All enum columns can hold their longest value',
       N'No status, stage or reason column can silently truncate.'
WHERE NOT EXISTS (SELECT 1 FROM #tsg_verify WHERE Category = 'Column width');

-- ---------------------------------------------------------------------------
-- 5. SEED DATA ACTUALLY LANDED
-- ---------------------------------------------------------------------------
-- The failure this catches is entirely silent: if a seed script aborted, the
-- application still starts normally and simply produces empty results forever.
-- No error, no warning — scenarios generate with zero controls attached and
-- nobody can tell why.
DECLARE @expected TABLE (TableName sysname, Expected int, Meaning nvarchar(200));
INSERT INTO @expected VALUES
    (N'Threat_Category',    6,    N'STRIDE categories'),
    (N'Threat_Type',        27,   N'threat families'),
    (N'Threat_Catalogue',   75,   N'curated named threats'),
    (N'Config_Threat_Rule', 21,   N'scoping rules'),
    (N'Control_Standard',   30,   N'control standards'),
    (N'Control_Library',    1288, N'controls');

DECLARE @t sysname, @exp int, @mean nvarchar(200), @actual int, @sql nvarchar(400);
DECLARE seed_cur CURSOR LOCAL FAST_FORWARD FOR SELECT TableName, Expected, Meaning FROM @expected;
OPEN seed_cur;
FETCH NEXT FROM seed_cur INTO @t, @exp, @mean;
WHILE @@FETCH_STATUS = 0
BEGIN
    SET @actual = -1;
    IF OBJECT_ID(N'dbo.' + @t) IS NOT NULL
    BEGIN
        SET @sql = N'SELECT @c = COUNT(*) FROM ' + QUOTENAME(@t);
        EXEC sp_executesql @sql, N'@c int OUTPUT', @c = @actual OUTPUT;
    END
    INSERT INTO #tsg_verify (Category, Status, Check_, Detail)
    SELECT 'Seed data',
           CASE WHEN @actual < 0 THEN 'FAIL'
                WHEN @actual = 0 THEN 'FAIL'
                WHEN @actual < @exp THEN 'WARN'
                ELSE 'PASS' END,
           @t + N': ' + CAST(CASE WHEN @actual < 0 THEN 0 ELSE @actual END AS nvarchar(10))
             + N' rows (expected ' + CAST(@exp AS nvarchar(10)) + N' ' + @mean + N')',
           CASE WHEN @actual < 0 THEN N'Table does not exist.'
                WHEN @actual = 0 THEN N'EMPTY. The seed script did not insert. This fails SILENTLY '
                                    + N'at runtime — the application starts fine and produces '
                                    + N'nothing. Re-run the matching Seed_to_*.sql with '
                                    + N'QUOTED_IDENTIFIER ON (sqlcmd -I).'
                WHEN @actual < @exp THEN N'Fewer rows than the shipped seed. Acceptable only if '
                                    + N'rows were deliberately removed by a curator.'
                ELSE N'At or above the shipped seed count.' END;
    FETCH NEXT FROM seed_cur INTO @t, @exp, @mean;
END
CLOSE seed_cur; DEALLOCATE seed_cur;

-- Control-to-standard links: the join table Step-8 control mapping reads.
INSERT INTO #tsg_verify (Category, Status, Check_, Detail)
SELECT 'Seed data',
       CASE WHEN c.n = 0 THEN 'FAIL' WHEN c.n < 6105 THEN 'WARN' ELSE 'PASS' END,
       N'Control_Library_Standard_Map: ' + CAST(c.n AS nvarchar(10)) + N' rows (expected 6105 links)',
       CASE WHEN c.n = 0 THEN N'EMPTY — controls will resolve to no standard.'
            ELSE N'Links present.' END
FROM (SELECT COUNT(*) AS n FROM Control_Library_Standard_Map) c
WHERE OBJECT_ID('dbo.Control_Library_Standard_Map') IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 6. DATABASE CONFIGURATION AND KNOWN HAZARD (re-checked after install)
-- ---------------------------------------------------------------------------
INSERT INTO #tsg_verify (Category, Status, Check_, Detail)
SELECT 'Database',
       CASE WHEN d.is_read_committed_snapshot_on = 1 THEN 'PASS' ELSE 'FAIL' END,
       'Read Committed Snapshot Isolation (RCSI) enabled',
       CASE WHEN d.is_read_committed_snapshot_on = 1
            THEN N'ON.'
            ELSE N'STILL OFF after install. The API and every worker will refuse to start. '
               + N'TSG_Core.sql should have enabled it — check its output for a blocked '
               + N'ALTER DATABASE.' END
FROM sys.databases d WHERE d.database_id = DB_ID();

INSERT INTO #tsg_verify (Category, Status, Check_, Detail)
SELECT 'Database',
       CASE WHEN COLUMNPROPERTY(OBJECT_ID('dbo.Config_Threat_Rule'), 'ThreatRuleID', 'IsIdentity') = 1
            THEN 'PASS' ELSE 'FAIL' END,
       N'Config_Threat_Rule.ThreatRuleID is an IDENTITY column',
       CASE WHEN COLUMNPROPERTY(OBJECT_ID('dbo.Config_Threat_Rule'), 'ThreatRuleID', 'IsIdentity') = 1
            THEN N'IDENTITY confirmed.'
            ELSE N'NOT an IDENTITY column — pre-existing table the scripts cannot convert. The '
               + N'threat-library import will fail on every auto-written rule. Report to the '
               + N'application team; a one-off conversion is required.' END
WHERE OBJECT_ID('dbo.Config_Threat_Rule') IS NOT NULL;

-- ---------------------------------------------------------------------------
-- RESULT
-- ---------------------------------------------------------------------------
SELECT Category, Status, Check_ AS [Check], Detail
FROM #tsg_verify
ORDER BY CASE Status WHEN 'FAIL' THEN 1 WHEN 'WARN' THEN 2 WHEN 'INFO' THEN 3 ELSE 4 END, Seq;

DECLARE @f int = (SELECT COUNT(*) FROM #tsg_verify WHERE Status = 'FAIL');
DECLARE @w int = (SELECT COUNT(*) FROM #tsg_verify WHERE Status = 'WARN');
SELECT CASE WHEN @f = 0 AND @w = 0
            THEN N'VERIFY PASSED — the database is ready. Start the application.'
            WHEN @f = 0
            THEN N'VERIFY PASSED WITH ' + CAST(@w AS nvarchar(10)) + N' WARNING(S) — review above, '
               + N'then start the application.'
            ELSE N'VERIFY FAILED — ' + CAST(@f AS nvarchar(10)) + N' blocking issue(s) above. '
               + N'The application will not work correctly. Do not sign off.'
       END AS [Verify result];

DROP TABLE #tsg_verify;
