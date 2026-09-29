/*==============================================================================
  INDEXES: Control_Library

  Script:      006_Control_Library_indexes.sql
  Order:       03_indexes / 006
  Purpose:     1 index(es) on Control_Library.
  Depends on:  01_tables/ *_Control_Library.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Control_Library

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- indexes: Control_Library ---';
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_Control_Library_Code' AND i.object_id = OBJECT_ID(N'dbo.Control_Library')
          AND (i.is_unique <> 1 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 1
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'ControlCode')))
BEGIN
    PRINT ' [REBUILD] Control_Library.UX_Control_Library_Code exists with the wrong shape - recreating it on (ControlCode).';
    DROP INDEX [UX_Control_Library_Code] ON [dbo].[Control_Library];
END;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Control_Library_Code' AND object_id = OBJECT_ID('dbo.Control_Library'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_Control_Library_Code] ON [dbo].[Control_Library] ([ControlCode])
        WHERE [IsActive] = 1 AND [IsDeleted] = 0;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Control_Library.UX_Control_Library_Code on (ControlCode).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_Control_Library_Code could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
