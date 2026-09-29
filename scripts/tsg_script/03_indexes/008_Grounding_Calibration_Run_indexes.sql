/*==============================================================================
  INDEXES: Grounding_Calibration_Run

  Script:      008_Grounding_Calibration_Run_indexes.sql
  Order:       03_indexes / 008
  Purpose:     1 index(es) on Grounding_Calibration_Run.
  Depends on:  01_tables/ *_Grounding_Calibration_Run.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Grounding_Calibration_Run

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- indexes: Grounding_Calibration_Run ---';
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_GroundingCalibration_Running' AND i.object_id = OBJECT_ID(N'dbo.Grounding_Calibration_Run')
          AND (i.is_unique <> 1 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'EmbeddingModel')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'RerankerModel')))
BEGIN
    PRINT ' [REBUILD] Grounding_Calibration_Run.UX_GroundingCalibration_Running exists with the wrong shape - recreating it on (EmbeddingModel, RerankerModel).';
    DROP INDEX [UX_GroundingCalibration_Running] ON [dbo].[Grounding_Calibration_Run];
END;
/* One calibration sweep at a time per model pair. The route cannot prevent a
   double start on its own: two requests arriving together both read "nothing
   running" before either writes. Only this index closes that window, and a
   sweep costs 10 to 15 minutes of billed model calls. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_GroundingCalibration_Running' AND object_id = OBJECT_ID('dbo.Grounding_Calibration_Run'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_GroundingCalibration_Running] ON [dbo].[Grounding_Calibration_Run] ([EmbeddingModel], [RerankerModel])
        WHERE [Status] = 'running';
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Grounding_Calibration_Run.UX_GroundingCalibration_Running on (EmbeddingModel, RerankerModel).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_GroundingCalibration_Running could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
