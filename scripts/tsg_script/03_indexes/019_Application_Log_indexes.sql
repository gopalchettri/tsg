/*==============================================================================
  INDEXES: Application_Log

  Script:      019_Application_Log_indexes.sql
  Order:       03_indexes / 019
  Purpose:     2 index(es) on Application_Log.
  Depends on:  01_tables/ *_Application_Log.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Application_Log

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- indexes: Application_Log ---';
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_ApplicationLog_Session' AND i.object_id = OBJECT_ID(N'dbo.Application_Log')
          AND (i.is_unique <> 0 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'CreatedAt')))
BEGIN
    PRINT ' [REBUILD] Application_Log.IX_ApplicationLog_Session exists with the wrong shape - recreating it on (SessionID, CreatedAt).';
    DROP INDEX [IX_ApplicationLog_Session] ON [dbo].[Application_Log];
END;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ApplicationLog_Session' AND object_id = OBJECT_ID('dbo.Application_Log'))
    CREATE NONCLUSTERED INDEX [IX_ApplicationLog_Session] ON [dbo].[Application_Log] ([SessionID], [CreatedAt] DESC)
        WHERE [SessionID] IS NOT NULL;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Application_Log.IX_ApplicationLog_Session on (SessionID, CreatedAt).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_ApplicationLog_Session could not be created - deployment stopped.', 16, 1);
END CATCH;
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'CIX_ApplicationLog_Created' AND i.object_id = OBJECT_ID(N'dbo.Application_Log')
          AND (i.is_unique <> 0 OR i.has_filter <> 0
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'CreatedAt')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'LogID')))
BEGIN
    PRINT ' [REBUILD] Application_Log.CIX_ApplicationLog_Created exists with the wrong shape - recreating it on (CreatedAt, LogID).';
    DROP INDEX [CIX_ApplicationLog_Created] ON [dbo].[Application_Log];
END;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'CIX_ApplicationLog_Created' AND object_id = OBJECT_ID('dbo.Application_Log'))
   AND NOT EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = OBJECT_ID('dbo.Application_Log') AND type_desc = 'CLUSTERED')
    CREATE CLUSTERED INDEX [CIX_ApplicationLog_Created] ON [dbo].[Application_Log] ([CreatedAt], [LogID])
        WITH (DATA_COMPRESSION = PAGE);
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Application_Log.CIX_ApplicationLog_Created on (CreatedAt, LogID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index CIX_ApplicationLog_Created could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
