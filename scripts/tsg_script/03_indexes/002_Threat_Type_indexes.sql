/*==============================================================================
  INDEXES: Threat_Type

  Script:      002_Threat_Type_indexes.sql
  Order:       03_indexes / 002
  Purpose:     2 index(es) on Threat_Type.
  Depends on:  01_tables/ *_Threat_Type.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Threat_Type

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- indexes: Threat_Type ---';
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_ThreatType_NaturalKey' AND i.object_id = OBJECT_ID(N'dbo.Threat_Type')
          AND (i.is_unique <> 1 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 1
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'ThreatTypeName')))
BEGIN
    PRINT ' [REBUILD] Threat_Type.UX_ThreatType_NaturalKey exists with the wrong shape - recreating it on (ThreatTypeName).';
    DROP INDEX [UX_ThreatType_NaturalKey] ON [dbo].[Threat_Type];
END;
/* Library natural keys. Two sessions promoting the same new name at once must
   not both create it. Filtered so a soft-deleted row releases its name.

   THE PREDICATE IS `WHERE [IsDeleted] = 0`, NOT the older
   `WHERE [IsActive] = 1 AND [IsDeleted] = 0`. Widened 2026-09-04: promote-to-library
   inserts AI-authored rows as IsActive = 0 (pending curator review -
   dal.upsert_threat_type / upsert_threat_catalogue), and a FILTERED index only
   constrains rows that satisfy its own predicate, so under the old filter an
   IsActive = 0 insert was NEVER covered. That is not a narrow race: it was ZERO
   duplicate-name protection for every promoted row, and the library quietly
   accumulated same-name twins that normalize_name() in Python already treats as one.

   The widening reached "2. Threat_library.sql" for BOTH keys and
   scripts/tsg_remediation_tables.sql for Threat_Catalogue ONLY - Threat_Type was
   left at the old predicate there, and the generated scripts/tsg_script/ package
   inherited it from that file. So a database built by the numbered scripts enforced
   one rule and a database built by the consolidated script or the package enforced
   another, on a boot-asserted UNIQUE index, with nothing comparing the two.
   tests/test_schema_sync.py::test_every_deploy_path_creates_the_same_indexes now
   compares each index's filter predicate across all three paths - it is the check
   that found this. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatType_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Type'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_ThreatType_NaturalKey] ON [dbo].[Threat_Type] ([ThreatTypeName])
        WHERE [IsDeleted] = 0;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Threat_Type.UX_ThreatType_NaturalKey on (ThreatTypeName).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_ThreatType_NaturalKey could not be created - deployment stopped.', 16, 1);
END CATCH;
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_ThreatType_Category_Active' AND i.object_id = OBJECT_ID(N'dbo.Threat_Type')
          AND (i.is_unique <> 0 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 1
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'ThreatCategoryID')))
BEGIN
    PRINT ' [REBUILD] Threat_Type.IX_ThreatType_Category_Active exists with the wrong shape - recreating it on (ThreatCategoryID).';
    DROP INDEX [IX_ThreatType_Category_Active] ON [dbo].[Threat_Type];
END;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ThreatType_Category_Active' AND object_id = OBJECT_ID('dbo.Threat_Type'))
    CREATE NONCLUSTERED INDEX [IX_ThreatType_Category_Active] ON [dbo].[Threat_Type] ([ThreatCategoryID])
        WHERE [IsActive] = 1 AND [IsDeleted] = 0;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Threat_Type.IX_ThreatType_Category_Active on (ThreatCategoryID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_ThreatType_Category_Active could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
