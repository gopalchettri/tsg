/*==============================================================================
  INDEXES: Diagnostic_Event

  Script:      018_Diagnostic_Event_indexes.sql
  Order:       03_indexes / 018
  Purpose:     2 index(es) on Diagnostic_Event.
  Depends on:  01_tables/ *_Diagnostic_Event.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Diagnostic_Event

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- indexes: Diagnostic_Event ---';
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_DiagnosticEvent_Session' AND i.object_id = OBJECT_ID(N'dbo.Diagnostic_Event')
          AND (i.is_unique <> 0 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'CreatedAt')))
BEGIN
    PRINT ' [REBUILD] Diagnostic_Event.IX_DiagnosticEvent_Session exists with the wrong shape - recreating it on (SessionID, CreatedAt).';
    DROP INDEX [IX_DiagnosticEvent_Session] ON [dbo].[Diagnostic_Event];
END;
/* "Why did session X fail" is THE query the diagnostics table exists to answer,
   and it is asked by a support engineer while someone waits. Without this index
   it scans every row ever recorded. CreatedAt is the second key because the
   answer is always read newest-first, so the ordering comes from the index
   rather than from a sort over the matched rows. Filtered, because a failure
   that happened before any session was resolved has none. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_DiagnosticEvent_Session' AND object_id = OBJECT_ID('dbo.Diagnostic_Event'))
    CREATE NONCLUSTERED INDEX [IX_DiagnosticEvent_Session] ON [dbo].[Diagnostic_Event] ([SessionID], [CreatedAt] DESC)
        WHERE [SessionID] IS NOT NULL;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Diagnostic_Event.IX_DiagnosticEvent_Session on (SessionID, CreatedAt).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_DiagnosticEvent_Session could not be created - deployment stopped.', 16, 1);
END CATCH;
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_DiagnosticEvent_Created' AND i.object_id = OBJECT_ID(N'dbo.Diagnostic_Event')
          AND (i.is_unique <> 0 OR i.has_filter <> 0
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 1
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'CreatedAt')))
BEGIN
    PRINT ' [REBUILD] Diagnostic_Event.IX_DiagnosticEvent_Created exists with the wrong shape - recreating it on (CreatedAt).';
    DROP INDEX [IX_DiagnosticEvent_Created] ON [dbo].[Diagnostic_Event];
END;
/* Two readers, not one: "what has been failing lately" with no session filter,
   AND the retention purge, which deletes by age. The purge is why this is not
   optional - without it the scheduled DELETE scans the whole table to find the
   old rows, on a table whose entire purpose is to keep growing. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_DiagnosticEvent_Created' AND object_id = OBJECT_ID('dbo.Diagnostic_Event'))
    CREATE NONCLUSTERED INDEX [IX_DiagnosticEvent_Created] ON [dbo].[Diagnostic_Event] ([CreatedAt] DESC);
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Diagnostic_Event.IX_DiagnosticEvent_Created on (CreatedAt).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_DiagnosticEvent_Created could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
