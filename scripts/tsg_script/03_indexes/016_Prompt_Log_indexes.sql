/*==============================================================================
  INDEXES: Prompt_Log

  Script:      016_Prompt_Log_indexes.sql
  Order:       03_indexes / 016
  Purpose:     2 index(es) on Prompt_Log.
  Depends on:  01_tables/ *_Prompt_Log.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Prompt_Log

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- indexes: Prompt_Log ---';
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_PromptLog_Correlation' AND i.object_id = OBJECT_ID(N'dbo.Prompt_Log')
          AND (i.is_unique <> 0 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'CorrelationID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'CreatedAt')))
BEGIN
    PRINT ' [REBUILD] Prompt_Log.IX_PromptLog_Correlation exists with the wrong shape - recreating it on (CorrelationID, CreatedAt).';
    DROP INDEX [IX_PromptLog_Correlation] ON [dbo].[Prompt_Log];
END;
/* The evidence endpoint reads the prompt log by correlation id and nothing
   else. Without this index that read scans the whole table, which grows by one
   row per model call. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_PromptLog_Correlation' AND object_id = OBJECT_ID('dbo.Prompt_Log'))
    CREATE NONCLUSTERED INDEX [IX_PromptLog_Correlation] ON [dbo].[Prompt_Log] ([CorrelationID], [CreatedAt])
        WHERE [CorrelationID] IS NOT NULL;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Prompt_Log.IX_PromptLog_Correlation on (CorrelationID, CreatedAt).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_PromptLog_Correlation could not be created - deployment stopped.', 16, 1);
END CATCH;
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'CIX_PromptLog_Created' AND i.object_id = OBJECT_ID(N'dbo.Prompt_Log')
          AND (i.is_unique <> 0 OR i.has_filter <> 0
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'CreatedAt')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'LogID')))
BEGIN
    PRINT ' [REBUILD] Prompt_Log.CIX_PromptLog_Created exists with the wrong shape - recreating it on (CreatedAt, LogID).';
    DROP INDEX [CIX_PromptLog_Created] ON [dbo].[Prompt_Log];
END;
/*------------------------------------------------------------------------------
  Then the clustered indexes themselves.

  The second guard - no clustered index of ANY name on the table - is what keeps
  this statement from ABORTING the run on a database whose primary key could not
  be moved above. Without it the statement fails with Msg 1902 (a table may have
  only one clustered index), the batch stops, and every section after this one is
  skipped over a table that was already reported as a finding. With it the index
  is simply not created, and Section 7 reports it as MISSING INDEX.
------------------------------------------------------------------------------*/
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'CIX_PromptLog_Created' AND object_id = OBJECT_ID('dbo.Prompt_Log'))
   AND NOT EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = OBJECT_ID('dbo.Prompt_Log') AND type_desc = 'CLUSTERED')
    CREATE CLUSTERED INDEX [CIX_PromptLog_Created] ON [dbo].[Prompt_Log] ([CreatedAt], [LogID])
        WITH (DATA_COMPRESSION = PAGE);
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Prompt_Log.CIX_PromptLog_Created on (CreatedAt, LogID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index CIX_PromptLog_Created could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
