/*==============================================================================
  INDEXES: Risk_Treatment_Plan

  Script:      015_Risk_Treatment_Plan_indexes.sql
  Order:       03_indexes / 015
  Purpose:     3 index(es) on Risk_Treatment_Plan.
  Depends on:  01_tables/ *_Risk_Treatment_Plan.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Risk_Treatment_Plan

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- indexes: Risk_Treatment_Plan ---';
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_TreatmentPlan_ActiveScenario' AND i.object_id = OBJECT_ID(N'dbo.Risk_Treatment_Plan')
          AND (i.is_unique <> 1 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 1
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'ScenarioID')))
BEGIN
    PRINT ' [REBUILD] Risk_Treatment_Plan.UX_TreatmentPlan_ActiveScenario exists with the wrong shape - recreating it on (ScenarioID).';
    DROP INDEX [UX_TreatmentPlan_ActiveScenario] ON [dbo].[Risk_Treatment_Plan];
END;
/* One active remediation plan per scenario. This index is what arbitrates two
   simultaneous plan requests. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_TreatmentPlan_ActiveScenario' AND object_id = OBJECT_ID('dbo.Risk_Treatment_Plan'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_TreatmentPlan_ActiveScenario] ON [dbo].[Risk_Treatment_Plan] ([ScenarioID])
        WHERE [Superseded] = 0;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Risk_Treatment_Plan.UX_TreatmentPlan_ActiveScenario on (ScenarioID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_TreatmentPlan_ActiveScenario could not be created - deployment stopped.', 16, 1);
END CATCH;
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_TreatmentPlan_SessionActive' AND i.object_id = OBJECT_ID(N'dbo.Risk_Treatment_Plan')
          AND (i.is_unique <> 0 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 1
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')))
BEGIN
    PRINT ' [REBUILD] Risk_Treatment_Plan.IX_TreatmentPlan_SessionActive exists with the wrong shape - recreating it on (SessionID).';
    DROP INDEX [IX_TreatmentPlan_SessionActive] ON [dbo].[Risk_Treatment_Plan];
END;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_TreatmentPlan_SessionActive' AND object_id = OBJECT_ID('dbo.Risk_Treatment_Plan'))
    CREATE NONCLUSTERED INDEX [IX_TreatmentPlan_SessionActive] ON [dbo].[Risk_Treatment_Plan] ([SessionID])
        WHERE [Superseded] = 0;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Risk_Treatment_Plan.IX_TreatmentPlan_SessionActive on (SessionID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_TreatmentPlan_SessionActive could not be created - deployment stopped.', 16, 1);
END CATCH;
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_TreatmentPlan_SessionHistory' AND i.object_id = OBJECT_ID(N'dbo.Risk_Treatment_Plan')
          AND (i.is_unique <> 0 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 3
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'ScenarioID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 3 AND c.name = N'CreatedAt')))
BEGIN
    PRINT ' [REBUILD] Risk_Treatment_Plan.IX_TreatmentPlan_SessionHistory exists with the wrong shape - recreating it on (SessionID, ScenarioID, CreatedAt).';
    DROP INDEX [IX_TreatmentPlan_SessionHistory] ON [dbo].[Risk_Treatment_Plan];
END;
/* Backs the plan version history, which reads only retired rows. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_TreatmentPlan_SessionHistory' AND object_id = OBJECT_ID('dbo.Risk_Treatment_Plan'))
    CREATE NONCLUSTERED INDEX [IX_TreatmentPlan_SessionHistory] ON [dbo].[Risk_Treatment_Plan] ([SessionID], [ScenarioID], [CreatedAt])
        WHERE [Superseded] = 1;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Risk_Treatment_Plan.IX_TreatmentPlan_SessionHistory on (SessionID, ScenarioID, CreatedAt).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_TreatmentPlan_SessionHistory could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
