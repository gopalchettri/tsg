/*==============================================================================
  INDEXES: Threat_Actor

  Script:      004_Threat_Actor_indexes.sql
  Order:       03_indexes / 004
  Purpose:     1 index(es) on Threat_Actor.
  Depends on:  01_tables/ *_Threat_Actor.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Threat_Actor

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- indexes: Threat_Actor ---';
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_ThreatActor_NaturalKey' AND i.object_id = OBJECT_ID(N'dbo.Threat_Actor')
          AND (i.is_unique <> 1 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 1
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'ThreatActorName')))
BEGIN
    PRINT ' [REBUILD] Threat_Actor.UX_ThreatActor_NaturalKey exists with the wrong shape - recreating it on (ThreatActorName).';
    DROP INDEX [UX_ThreatActor_NaturalKey] ON [dbo].[Threat_Actor];
END;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatActor_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Actor'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_ThreatActor_NaturalKey] ON [dbo].[Threat_Actor] ([ThreatActorName])
        WHERE [IsActive] = 1 AND [IsDeleted] = 0;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Threat_Actor.UX_ThreatActor_NaturalKey on (ThreatActorName).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_ThreatActor_NaturalKey could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
