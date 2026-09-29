/*==============================================================================
  INDEXES: Scenario_Session

  Script:      009_Scenario_Session_indexes.sql
  Order:       03_indexes / 009
  Purpose:     4 index(es) on Scenario_Session.
  Depends on:  01_tables/ *_Scenario_Session.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Scenario_Session

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- indexes: Scenario_Session ---';
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_Session_ActiveAsset' AND i.object_id = OBJECT_ID(N'dbo.Scenario_Session')
          AND (i.is_unique <> 1 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'EntityID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'AssetID')))
BEGIN
    PRINT ' [REBUILD] Scenario_Session.UX_Session_ActiveAsset exists with the wrong shape - recreating it on (EntityID, AssetID).';
    DROP INDEX [UX_Session_ActiveAsset] ON [dbo].[Scenario_Session];
END;
/* One active session per asset. Without it a retried request creates a second
   session for the same asset instead of returning the first. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Session_ActiveAsset' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_Session_ActiveAsset] ON [dbo].[Scenario_Session] ([EntityID], [AssetID])
        WHERE [SessionStatus] = 'active';
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Scenario_Session.UX_Session_ActiveAsset on (EntityID, AssetID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_Session_ActiveAsset could not be created - deployment stopped.', 16, 1);
END CATCH;
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_Session_IdempotencyKey' AND i.object_id = OBJECT_ID(N'dbo.Scenario_Session')
          AND (i.is_unique <> 1 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'EntityID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'IdempotencyKey')))
BEGIN
    PRINT ' [REBUILD] Scenario_Session.UX_Session_IdempotencyKey exists with the wrong shape - recreating it on (EntityID, IdempotencyKey).';
    DROP INDEX [UX_Session_IdempotencyKey] ON [dbo].[Scenario_Session];
END;
/* Idempotency: a repeated request carrying the same key returns the original
   session rather than creating another. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Session_IdempotencyKey' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_Session_IdempotencyKey] ON [dbo].[Scenario_Session] ([EntityID], [IdempotencyKey])
        WHERE [IdempotencyKey] IS NOT NULL;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Scenario_Session.UX_Session_IdempotencyKey on (EntityID, IdempotencyKey).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_Session_IdempotencyKey could not be created - deployment stopped.', 16, 1);
END CATCH;
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_Session_Active' AND i.object_id = OBJECT_ID(N'dbo.Scenario_Session')
          AND (i.is_unique <> 0 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 1
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionStatus')))
BEGIN
    PRINT ' [REBUILD] Scenario_Session.IX_Session_Active exists with the wrong shape - recreating it on (SessionStatus).';
    DROP INDEX [IX_Session_Active] ON [dbo].[Scenario_Session];
END;
/* Not unique, but also verified at start-up: the application reads this index's
   WHERE clause to confirm the stored status wording still matches its own. It
   also makes the capacity count and the recovery sweep proportional to the
   number of ACTIVE sessions rather than to the whole table. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Session_Active' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
    CREATE NONCLUSTERED INDEX [IX_Session_Active] ON [dbo].[Scenario_Session] ([SessionStatus])
        WHERE [SessionStatus] = 'active';
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Scenario_Session.IX_Session_Active on (SessionStatus).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_Session_Active could not be created - deployment stopped.', 16, 1);
END CATCH;
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_Session_EntityUser' AND i.object_id = OBJECT_ID(N'dbo.Scenario_Session')
          AND (i.is_unique <> 0 OR i.has_filter <> 0
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'EntityID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'UserID')))
BEGIN
    PRINT ' [REBUILD] Scenario_Session.IX_Session_EntityUser exists with the wrong shape - recreating it on (EntityID, UserID).';
    DROP INDEX [IX_Session_EntityUser] ON [dbo].[Scenario_Session];
END;
/* Backs the cross-session scenario browse feed, which filters entity, then
   optionally user and session status. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Session_EntityUser' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
    CREATE NONCLUSTERED INDEX [IX_Session_EntityUser] ON [dbo].[Scenario_Session] ([EntityID], [UserID])
        INCLUDE ([SessionStatus]);
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Scenario_Session.IX_Session_EntityUser on (EntityID, UserID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_Session_EntityUser could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
