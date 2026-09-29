/*==============================================================================
  INDEXES: Threat_Catalogue

  Script:      003_Threat_Catalogue_indexes.sql
  Order:       03_indexes / 003
  Purpose:     1 index(es) on Threat_Catalogue.
  Depends on:  01_tables/ *_Threat_Catalogue.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Threat_Catalogue

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- indexes: Threat_Catalogue ---';
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_ThreatCatalogue_NaturalKey' AND i.object_id = OBJECT_ID(N'dbo.Threat_Catalogue')
          AND (i.is_unique <> 1 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 1
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'ThreatName')))
BEGIN
    PRINT ' [REBUILD] Threat_Catalogue.UX_ThreatCatalogue_NaturalKey exists with the wrong shape - recreating it on (ThreatName).';
    DROP INDEX [UX_ThreatCatalogue_NaturalKey] ON [dbo].[Threat_Catalogue];
END;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatCatalogue_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Catalogue'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_ThreatCatalogue_NaturalKey] ON [dbo].[Threat_Catalogue] ([ThreatName])
        WHERE [IsDeleted] = 0;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Threat_Catalogue.UX_ThreatCatalogue_NaturalKey on (ThreatName).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_ThreatCatalogue_NaturalKey could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
