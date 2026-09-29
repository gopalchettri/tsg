/*==============================================================================
  INDEXES: API_Client

  Script:      007_API_Client_indexes.sql
  Order:       03_indexes / 007
  Purpose:     1 index(es) on API_Client.
  Depends on:  01_tables/ *_API_Client.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.API_Client

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- indexes: API_Client ---';
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_API_Client_KeyHash' AND i.object_id = OBJECT_ID(N'dbo.API_Client')
          AND (i.is_unique <> 1 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 1
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'KeyHash')))
BEGIN
    PRINT ' [REBUILD] API_Client.UX_API_Client_KeyHash exists with the wrong shape - recreating it on (KeyHash).';
    DROP INDEX [UX_API_Client_KeyHash] ON [dbo].[API_Client];
END;
/* Stops two active clients sharing one key hash, and turns every
   authentication from a table scan into a seek. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_API_Client_KeyHash' AND object_id = OBJECT_ID('dbo.API_Client'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_API_Client_KeyHash] ON [dbo].[API_Client] ([KeyHash])
        WHERE [Active] = 1;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild API_Client.UX_API_Client_KeyHash on (KeyHash).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_API_Client_KeyHash could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
