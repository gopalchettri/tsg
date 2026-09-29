/*==============================================================================
  INDEXES: Identified_Threat

  Script:      011_Identified_Threat_indexes.sql
  Order:       03_indexes / 011
  Purpose:     1 index(es) on Identified_Threat.
  Depends on:  01_tables/ *_Identified_Threat.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Identified_Threat

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- indexes: Identified_Threat ---';
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_IdentifiedThreat_SessionSubActive' AND i.object_id = OBJECT_ID(N'dbo.Identified_Threat')
          AND (i.is_unique <> 0 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'SubsystemID')))
BEGIN
    PRINT ' [REBUILD] Identified_Threat.IX_IdentifiedThreat_SessionSubActive exists with the wrong shape - recreating it on (SessionID, SubsystemID).';
    DROP INDEX [IX_IdentifiedThreat_SessionSubActive] ON [dbo].[Identified_Threat];
END;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_IdentifiedThreat_SessionSubActive' AND object_id = OBJECT_ID('dbo.Identified_Threat'))
    CREATE NONCLUSTERED INDEX [IX_IdentifiedThreat_SessionSubActive] ON [dbo].[Identified_Threat] ([SessionID], [SubsystemID])
        WHERE [Superseded] = 0;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Identified_Threat.IX_IdentifiedThreat_SessionSubActive on (SessionID, SubsystemID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_IdentifiedThreat_SessionSubActive could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
