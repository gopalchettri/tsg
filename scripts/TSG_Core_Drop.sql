/* ===========================================================================================
   TSG — DROP the core tables so TSG_Core.sql can recreate them from scratch
   ===========================================================================================

   *** THIS DELETES DATA. IT CANNOT BE UNDONE. ***

   Every threat assessment, generated scenario, accept/reject decision, audit record, treatment
   plan and API client in this database is destroyed. Intended for DEVELOPMENT, where recreating
   from a clean schema is faster than migrating.

   DO NOT RUN THIS AGAINST UAT OR PRODUCTION. For those, run scripts/TSG_Core.sql (or
   scripts/TSG_Migration_ScenarioLifecycle.sql) instead — both are additive and preserve data.

   -------------------------------------------------------------------------------------------
   HOW TO USE
     1. Change @I_UNDERSTAND below from 'NO' to 'YES'. Nothing happens until you do.
     2. Run this file.
     3. Run scripts/TSG_Core.sql  -> recreates all 13 tables at the current schema, with the
        scenario-lifecycle columns already present. Nothing left to migrate.
     4. Re-insert an API_Client row, then restart the application.

   WHAT IT DOES NOT TOUCH
     The threat library and control library tables, and their seed data (~1.4 MB across
     Seed_to_Threat_library.sql and Seed_to_Control_library.sql). Those survive, so the slow seed
     scripts do not need re-running. Drop order is irrelevant: TSG_Core.sql declares no FOREIGN
     KEYs by design (SDD 7.7), so nothing can block a drop.
   =========================================================================================== */

SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;
GO

DECLARE @I_UNDERSTAND nvarchar(10) = 'NO';   /* <=== change to 'YES' to actually drop */

IF @I_UNDERSTAND <> 'YES'
BEGIN
    PRINT '';
    PRINT '  NOTHING WAS DROPPED.';
    PRINT '  This script destroys every session, scenario, decision and audit record.';
    PRINT '  If that is what you want, set @I_UNDERSTAND = ''YES'' at the top and run again.';
    PRINT '';
END
ELSE
BEGIN
    /* No FOREIGN KEYs exist between these tables, so any order works. */
    IF OBJECT_ID('dbo.Scenario_Audit', 'U')              IS NOT NULL DROP TABLE dbo.Scenario_Audit;
    IF OBJECT_ID('dbo.Risk_Treatment_Plan', 'U')         IS NOT NULL DROP TABLE dbo.Risk_Treatment_Plan;
    IF OBJECT_ID('dbo.Threat_Scenario_Output', 'U')      IS NOT NULL DROP TABLE dbo.Threat_Scenario_Output;
    IF OBJECT_ID('dbo.Scoped_Threat', 'U')               IS NOT NULL DROP TABLE dbo.Scoped_Threat;
    IF OBJECT_ID('dbo.Identified_Duplicate_Threat', 'U') IS NOT NULL DROP TABLE dbo.Identified_Duplicate_Threat;
    IF OBJECT_ID('dbo.Identified_Threat', 'U')           IS NOT NULL DROP TABLE dbo.Identified_Threat;
    IF OBJECT_ID('dbo.Threat_Candidate_Review', 'U')     IS NOT NULL DROP TABLE dbo.Threat_Candidate_Review;
    IF OBJECT_ID('dbo.Subsystem_Stage_State', 'U')       IS NOT NULL DROP TABLE dbo.Subsystem_Stage_State;
    IF OBJECT_ID('dbo.Scenario_Session', 'U')            IS NOT NULL DROP TABLE dbo.Scenario_Session;
    IF OBJECT_ID('dbo.Threat_Library_Import_Run', 'U')   IS NOT NULL DROP TABLE dbo.Threat_Library_Import_Run;
    IF OBJECT_ID('dbo.Prompt_Log', 'U')                  IS NOT NULL DROP TABLE dbo.Prompt_Log;
    IF OBJECT_ID('dbo.Config_Tuning', 'U')               IS NOT NULL DROP TABLE dbo.Config_Tuning;
    IF OBJECT_ID('dbo.API_Client', 'U')                  IS NOT NULL DROP TABLE dbo.API_Client;

    /* Threat_Scenario_Control_Map is per-SCENARIO data but is created by Control_library.sql,
       not TSG_Core.sql — so dropping the tables above leaves it holding rows keyed to OutputIDs
       that no longer exist. Emptied rather than dropped: the table would then need
       Control_library.sql re-run to come back, and its rows are session data, not library data. */
    IF OBJECT_ID('dbo.Threat_Scenario_Control_Map', 'U') IS NOT NULL
        DELETE FROM dbo.Threat_Scenario_Control_Map;

    PRINT '';
    PRINT '  Dropped. Now run scripts/TSG_Core.sql to recreate all 13 tables.';
    PRINT '  (Every index on those tables went with them — DROP TABLE removes its own indexes,';
    PRINT '   so the recreate leaves exactly the 22 indexes TSG_Core.sql defines and no strays.)';
    PRINT '';
    PRINT '  REMEMBER: API_Client was dropped too, so TSG_Core.sql recreates it EMPTY. The app';
    PRINT '  refuses to boot with no active API client (db/invariants.py), so re-insert your';
    PRINT '  development key afterwards or startup will fail on that check.';
    PRINT '';
END
GO

/* -- What survived ------------------------------------------------------------------------- */
SELECT name AS RemainingTable
FROM sys.tables
WHERE name IN ('Scenario_Session','Subsystem_Stage_State','Identified_Threat',
               'Identified_Duplicate_Threat','Scoped_Threat','Threat_Scenario_Output',
               'Threat_Library_Import_Run','Scenario_Audit','Prompt_Log',
               'Threat_Candidate_Review','Risk_Treatment_Plan','Config_Tuning','API_Client')
ORDER BY name;
GO
/* An EMPTY result set means the drop is complete — run scripts/TSG_Core.sql next.
   Rows still listed mean @I_UNDERSTAND was left at 'NO' and nothing was dropped. */

/* -- Stale indexes on the tables that SURVIVED ----------------------------------------------
   The 13 dropped tables need no index cleanup: DROP TABLE takes its indexes with it, so the
   recreate leaves exactly what TSG_Core.sql defines.

   The library and control tables are NOT recreated, so an index left behind by an older version
   of Threat_library.sql / Control_library.sql would persist unnoticed. This lists any index on
   them that the current scripts do not define.

   REPORT ONLY — it deliberately does not drop anything. An unrecognised index may be one a DBA
   added on purpose for a slow query, and silently dropping it would be a performance regression
   nobody could trace back to here. Review the list, then drop what you recognise as dead. */
SELECT  t.name  AS TableName,
        i.name  AS UnexpectedIndex,
        i.type_desc AS IndexType,
        i.is_unique AS IsUnique
FROM    sys.indexes i
JOIN    sys.tables  t ON t.object_id = i.object_id
WHERE   t.name IN ('Threat_Category','Threat_Type','Threat_Catalogue','Threat_Actor',
                   'ThreatType_ThreatActor_Map','Threat_Catalogue_Category_Map',
                   'Config_Threat_Rule','Control_Standard','Control_Library',
                   'Control_Library_Standard_Map','Threat_Scenario_Control_Map')
    AND i.name IS NOT NULL                 -- skip heaps
    AND i.is_primary_key = 0               -- PKs are structure, not tuning
    AND i.is_unique_constraint = 0
    AND i.name NOT IN (                    -- everything the current scripts create
            'IX_ThreatType_Category_Active','UX_ConfigThreatRule_NaturalKey',
            'UX_ThreatActor_NaturalKey','UX_ThreatCatalogue_NaturalKey',
            'UX_ThreatCategory_NaturalKey','UX_ThreatType_NaturalKey',
            'UX_Control_Library_Code','UX_Control_Standard_Name')
ORDER BY t.name, i.name;
GO
/* An EMPTY result set here means there are no stray indexes — nothing to clean up. */
