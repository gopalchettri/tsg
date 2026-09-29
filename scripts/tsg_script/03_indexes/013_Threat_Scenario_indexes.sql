/*==============================================================================
  INDEXES: Threat_Scenario

  Script:      013_Threat_Scenario_indexes.sql
  Order:       03_indexes / 013
  Purpose:     5 index(es) on Threat_Scenario.
  Depends on:  01_tables/ *_Threat_Scenario.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Threat_Scenario

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- indexes: Threat_Scenario ---';
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_Scenario_ActiveIdentity' AND i.object_id = OBJECT_ID(N'dbo.Threat_Scenario')
          AND (i.is_unique <> 1 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 3
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'IdentityHash')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 3 AND c.name = N'ScenarioNumber')))
BEGIN
    PRINT ' [REBUILD] Threat_Scenario.UX_Scenario_ActiveIdentity exists with the wrong shape - recreating it on (SessionID, IdentityHash, ScenarioNumber).';
    DROP INDEX [UX_Scenario_ActiveIdentity] ON [dbo].[Threat_Scenario];
END;
/* One current version per scenario identity. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Scenario_ActiveIdentity' AND object_id = OBJECT_ID('dbo.Threat_Scenario'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_Scenario_ActiveIdentity] ON [dbo].[Threat_Scenario] ([SessionID], [IdentityHash], [ScenarioNumber])
        WHERE [Superseded] = 0;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Threat_Scenario.UX_Scenario_ActiveIdentity on (SessionID, IdentityHash, ScenarioNumber).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_Scenario_ActiveIdentity could not be created - deployment stopped.', 16, 1);
END CATCH;
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_Scenario_ActiveScoped' AND i.object_id = OBJECT_ID(N'dbo.Threat_Scenario')
          AND (i.is_unique <> 1 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'ScopedThreatID')))
BEGIN
    PRINT ' [REBUILD] Threat_Scenario.UX_Scenario_ActiveScoped exists with the wrong shape - recreating it on (SessionID, ScopedThreatID).';
    DROP INDEX [UX_Scenario_ActiveScoped] ON [dbo].[Threat_Scenario];
END;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Scenario_ActiveScoped' AND object_id = OBJECT_ID('dbo.Threat_Scenario'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_Scenario_ActiveScoped] ON [dbo].[Threat_Scenario] ([SessionID], [ScopedThreatID])
        WHERE [Superseded] = 0;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Threat_Scenario.UX_Scenario_ActiveScoped on (SessionID, ScopedThreatID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_Scenario_ActiveScoped could not be created - deployment stopped.', 16, 1);
END CATCH;
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_Scenario_ActiveAccepted' AND i.object_id = OBJECT_ID(N'dbo.Threat_Scenario')
          AND (i.is_unique <> 1 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 3
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'IdentityHash')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 3 AND c.name = N'ScenarioNumber')))
BEGIN
    PRINT ' [REBUILD] Threat_Scenario.UX_Scenario_ActiveAccepted exists with the wrong shape - recreating it on (SessionID, IdentityHash, ScenarioNumber).';
    DROP INDEX [UX_Scenario_ActiveAccepted] ON [dbo].[Threat_Scenario];
END;
/* One ACCEPTED version per identity. Separate from the index above: a reviewer
   may accept an older version, so "current" and "accepted" are not the same row. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Scenario_ActiveAccepted' AND object_id = OBJECT_ID('dbo.Threat_Scenario'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_Scenario_ActiveAccepted] ON [dbo].[Threat_Scenario] ([SessionID], [IdentityHash], [ScenarioNumber])
        WHERE [Accepted] = 1 AND [IdentityHash] IS NOT NULL;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Threat_Scenario.UX_Scenario_ActiveAccepted on (SessionID, IdentityHash, ScenarioNumber).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_Scenario_ActiveAccepted could not be created - deployment stopped.', 16, 1);
END CATCH;
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_Scenario_SessionSubActive' AND i.object_id = OBJECT_ID(N'dbo.Threat_Scenario')
          AND (i.is_unique <> 0 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'SubsystemID')))
BEGIN
    PRINT ' [REBUILD] Threat_Scenario.IX_Scenario_SessionSubActive exists with the wrong shape - recreating it on (SessionID, SubsystemID).';
    DROP INDEX [IX_Scenario_SessionSubActive] ON [dbo].[Threat_Scenario];
END;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Scenario_SessionSubActive' AND object_id = OBJECT_ID('dbo.Threat_Scenario'))
    CREATE NONCLUSTERED INDEX [IX_Scenario_SessionSubActive] ON [dbo].[Threat_Scenario] ([SessionID], [SubsystemID])
        WHERE [Superseded] = 0;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Threat_Scenario.IX_Scenario_SessionSubActive on (SessionID, SubsystemID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_Scenario_SessionSubActive could not be created - deployment stopped.', 16, 1);
END CATCH;
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_Scenario_RejectedDecision' AND i.object_id = OBJECT_ID(N'dbo.Threat_Scenario')
          AND (i.is_unique <> 0 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 1
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')))
BEGIN
    PRINT ' [REBUILD] Threat_Scenario.IX_Scenario_RejectedDecision exists with the wrong shape - recreating it on (SessionID).';
    DROP INDEX [IX_Scenario_RejectedDecision] ON [dbo].[Threat_Scenario];
END;
/* The reject side of GET /v1/sessions/{id}/results, which re-adds a DECIDED scenario
   even after a regeneration superseded it. Threat_Scenario has NO unfiltered SessionID
   index - its key is the GUID id, and every SessionID-leading index above is filtered
   on Superseded or Accepted - so /results issues one seek per filtered index rather
   than a single OR. Without this index the reject-side seek degrades into a full table
   scan on an endpoint clients POLL: correct, and merely slow, which is how a table scan
   reaches production unnoticed. Filtered over the rejected rows only, so it costs almost
   nothing. The same statement is in "1. TSG_Core.sql" (canonical) and in
   scripts/TSG_Migration_RejectedDecisionIndex.sql (for a database already up); it was
   missing HERE, and from the generated package this file is the source for, because no
   guard compared the three deploy paths' index inventories. One now does:
   tests/test_schema_sync.py::test_every_deploy_path_creates_the_same_indexes. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Scenario_RejectedDecision' AND object_id = OBJECT_ID('dbo.Threat_Scenario'))
    CREATE NONCLUSTERED INDEX [IX_Scenario_RejectedDecision] ON [dbo].[Threat_Scenario] ([SessionID])
        WHERE [RejectedAt] IS NOT NULL;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Threat_Scenario.IX_Scenario_RejectedDecision on (SessionID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_Scenario_RejectedDecision could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
