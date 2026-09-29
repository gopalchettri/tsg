/*==============================================================================
  INDEXES: Subsystem_Stage_State

  Script:      010_Subsystem_Stage_State_indexes.sql
  Order:       03_indexes / 010
  Purpose:     1 index(es) on Subsystem_Stage_State.
  Depends on:  01_tables/ *_Subsystem_Stage_State.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Subsystem_Stage_State

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- indexes: Subsystem_Stage_State ---';
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_SubsystemStageState_SessionSubLevel' AND i.object_id = OBJECT_ID(N'dbo.Subsystem_Stage_State')
          AND (i.is_unique <> 1 OR i.has_filter <> 0
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 3
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'SubsystemID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 3 AND c.name = N'Level')))
BEGIN
    PRINT ' [REBUILD] Subsystem_Stage_State.UX_SubsystemStageState_SessionSubLevel exists with the wrong shape - recreating it on (SessionID, SubsystemID, Level).';
    DROP INDEX [UX_SubsystemStageState_SessionSubLevel] ON [dbo].[Subsystem_Stage_State];
END;
/* The row identity the whole locking design depends on. A duplicate would let
   one claim match two rows and put two workers on the same unit of work. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_SubsystemStageState_SessionSubLevel' AND object_id = OBJECT_ID('dbo.Subsystem_Stage_State'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_SubsystemStageState_SessionSubLevel] ON [dbo].[Subsystem_Stage_State] ([SessionID], [SubsystemID], [Level]);
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Subsystem_Stage_State.UX_SubsystemStageState_SessionSubLevel on (SessionID, SubsystemID, Level).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_SubsystemStageState_SessionSubLevel could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
