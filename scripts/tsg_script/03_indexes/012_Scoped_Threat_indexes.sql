/*==============================================================================
  INDEXES: Scoped_Threat

  Script:      012_Scoped_Threat_indexes.sql
  Order:       03_indexes / 012
  Purpose:     2 index(es) on Scoped_Threat.
  Depends on:  01_tables/ *_Scoped_Threat.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Scoped_Threat

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- indexes: Scoped_Threat ---';
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_ScopedThreat_SessionSubActive' AND i.object_id = OBJECT_ID(N'dbo.Scoped_Threat')
          AND (i.is_unique <> 0 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'SubsystemID')))
BEGIN
    PRINT ' [REBUILD] Scoped_Threat.IX_ScopedThreat_SessionSubActive exists with the wrong shape - recreating it on (SessionID, SubsystemID).';
    DROP INDEX [IX_ScopedThreat_SessionSubActive] ON [dbo].[Scoped_Threat];
END;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScopedThreat_SessionSubActive' AND object_id = OBJECT_ID('dbo.Scoped_Threat'))
    CREATE NONCLUSTERED INDEX [IX_ScopedThreat_SessionSubActive] ON [dbo].[Scoped_Threat] ([SessionID], [SubsystemID])
        WHERE [Superseded] = 0;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Scoped_Threat.IX_ScopedThreat_SessionSubActive on (SessionID, SubsystemID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_ScopedThreat_SessionSubActive could not be created - deployment stopped.', 16, 1);
END CATCH;
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_ScopedThreat_SessionActiveScores' AND i.object_id = OBJECT_ID(N'dbo.Scoped_Threat')
          AND (i.is_unique <> 0 OR i.has_filter <> 0
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'Superseded')))
BEGIN
    PRINT ' [REBUILD] Scoped_Threat.IX_ScopedThreat_SessionActiveScores exists with the wrong shape - recreating it on (SessionID, Superseded).';
    DROP INDEX [IX_ScopedThreat_SessionActiveScores] ON [dbo].[Scoped_Threat];
END;
/* Deliberately NOT filtered, even though Superseded appears in it. SQL Server
   cannot match a filtered index against a parameterised predicate, so the
   column sits in the key instead of a WHERE clause. Backs the scoring read. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScopedThreat_SessionActiveScores' AND object_id = OBJECT_ID('dbo.Scoped_Threat'))
    CREATE NONCLUSTERED INDEX [IX_ScopedThreat_SessionActiveScores] ON [dbo].[Scoped_Threat] ([SessionID], [Superseded])
        INCLUDE ([ThreatID], [Score], [ScopeRank]);
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Scoped_Threat.IX_ScopedThreat_SessionActiveScores on (SessionID, Superseded).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_ScopedThreat_SessionActiveScores could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
