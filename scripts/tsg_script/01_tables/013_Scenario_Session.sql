/*==============================================================================
  TABLE: Scenario_Session

  Script:      013_Scenario_Session.sql
  Order:       01_tables / 013
  Purpose:     Create Scenario_Session, or bring an existing copy up to 22 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Scenario_Session

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- Scenario_Session ---';
GO

IF OBJECT_ID('dbo.Scenario_Session', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Scenario_Session] (
        [SessionID] UNIQUEIDENTIFIER NOT NULL,
        [TenantID] NVARCHAR(200) NOT NULL,
        [EntityID] NVARCHAR(200) NOT NULL,
        [UserID] NVARCHAR(200) NULL,
        [AssetName] NVARCHAR(300) NOT NULL,
        [AssetID] NVARCHAR(200) NOT NULL,
        [SessionStatus] NVARCHAR(100) NOT NULL,
        [CurrentStage] NVARCHAR(100) NOT NULL,
        [StageStatus] NVARCHAR(100) NOT NULL,
        [Mode] NVARCHAR(100) NOT NULL,
        [CurrentSubsystemIndex] INT NULL,
        [SubsystemsJSON] NVARCHAR(max) NOT NULL,
        [IdempotencyKey] NVARCHAR(200) NULL,
        [SectorIDsJSON] NVARCHAR(max) NULL,
        [AssetContextJSON] NVARCHAR(max) NULL,
        [ScoringRulesSnapshotJSON] NVARCHAR(max) NULL,
        [CreatedAt] DATETIME2(7) NULL,
        [UpdatedAt] DATETIME2(7) NULL,
        [CompletedAt] DATETIME2(7) NULL,
        [CancelledAt] DATETIME2(7) NULL,
        [CancelledBy] NVARCHAR(200) NULL,
        [ControlMapSeconds] FLOAT NULL,
        CONSTRAINT [PK_Scenario_Session] PRIMARY KEY CLUSTERED ([SessionID])
    );
    PRINT ' [CREATED] Table: Scenario_Session (22 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Scenario_Session';
GO

/* Legacy column names: renamed in place so their data is kept. */
EXEC dbo.tsg_rename_column @table = N'Scenario_Session', @old = N'TuningJSON', @new = N'ScoringRulesSnapshotJSON';
EXEC dbo.tsg_rename_column @table = N'Scenario_Session', @old = N'TuningSnapshotJSON', @new = N'ScoringRulesSnapshotJSON';
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'SessionID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'TenantID',
     @expected = N'NVARCHAR(200)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'EntityID',
     @expected = N'NVARCHAR(200)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'UserID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'AssetName',
     @expected = N'NVARCHAR(300)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'AssetID',
     @expected = N'NVARCHAR(200)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'SessionStatus',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'CurrentStage',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'StageStatus',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'Mode',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'CurrentSubsystemIndex',
     @expected = N'INT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'SubsystemsJSON',
     @expected = N'NVARCHAR(max)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'IdempotencyKey',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'SectorIDsJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'AssetContextJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'ScoringRulesSnapshotJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'UpdatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'CompletedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'CancelledAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'CancelledBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'ControlMapSeconds',
     @expected = N'FLOAT', @nullable = 1;
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Scenario_Session', @columns = N'SessionID';
GO

/* Legacy column TuningJSON, replaced by ScoringRulesSnapshotJSON. Normally already RENAMED away above; it is still here
   only if ScoringRulesSnapshotJSON existed too, in which case its values were copied across. Dropped only when
   EVERY value it holds is already in ScoringRulesSnapshotJSON - nothing is lost. */
IF COL_LENGTH('dbo.Scenario_Session', 'TuningJSON') IS NOT NULL
BEGIN
    DECLARE @n bigint;
    BEGIN TRY
        EXEC sp_executesql N'SELECT @n = COUNT_BIG(*) FROM dbo.[Scenario_Session]
                             WHERE [TuningJSON] IS NOT NULL
                               AND ([ScoringRulesSnapshotJSON] IS NULL OR [ScoringRulesSnapshotJSON] <> [TuningJSON]);',
             N'@n bigint OUTPUT', @n = @n OUTPUT;
        IF @n > 0
        BEGIN
            PRINT ' [BLOCKED] Scenario_Session.TuningJSON holds ' + CAST(@n AS varchar(20)) +
                  ' value(s) that differ from ScoringRulesSnapshotJSON - NOT dropped.';
            PRINT '          Decide which value is right, update ScoringRulesSnapshotJSON, then re-run.';
        END
        ELSE
        BEGIN
            /* Old indexes built on the column go with it, in the same transaction. */
            DECLARE @ix sysname, @ixs nvarchar(max) = N'', @drop nvarchar(max);
            BEGIN TRANSACTION;
            DECLARE legacy_ix CURSOR LOCAL STATIC READ_ONLY FOR
                SELECT i.name
                FROM   sys.indexes i
                WHERE  i.object_id = OBJECT_ID(N'dbo.Scenario_Session') AND i.type IN (1, 2)
                  AND  i.is_primary_key = 0 AND i.is_unique_constraint = 0
                  AND  (EXISTS (SELECT 1 FROM sys.index_columns ic
                                WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id
                                  AND ic.column_id = COLUMNPROPERTY(i.object_id, N'TuningJSON', 'ColumnId'))
                        OR CHARINDEX(N'[TuningJSON]', ISNULL(i.filter_definition, N'')) > 0);
            OPEN legacy_ix; FETCH NEXT FROM legacy_ix INTO @ix;
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @drop = N'DROP INDEX ' + QUOTENAME(@ix) + N' ON dbo.[Scenario_Session];';
                EXEC sp_executesql @drop;
                SET @ixs = @ixs + CASE WHEN @ixs = N'' THEN N'' ELSE N', ' END + @ix;
                FETCH NEXT FROM legacy_ix INTO @ix;
            END;
            CLOSE legacy_ix; DEALLOCATE legacy_ix;
            EXEC sp_executesql N'ALTER TABLE dbo.[Scenario_Session] DROP COLUMN [TuningJSON];';
            COMMIT;
            PRINT ' [DROPPED] Scenario_Session.TuningJSON - legacy column; all of its data is in ScoringRulesSnapshotJSON.';
            IF @ixs <> N''
                PRINT '          Old index(es) on it dropped too: ' + @ixs +
                      ' (the current ones are created by 03_indexes).';
        END
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK;
        PRINT ' [ERROR]   Could not drop Scenario_Session.TuningJSON.';
        PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
        EXEC sp_set_session_context N'tsg_deploy_failed', 1;
        RAISERROR('Legacy column Scenario_Session.TuningJSON could not be dropped - deployment stopped.', 16, 1);
    END CATCH
END
GO

/* Legacy column TuningSnapshotJSON, replaced by ScoringRulesSnapshotJSON. Normally already RENAMED away above; it is still here
   only if ScoringRulesSnapshotJSON existed too, in which case its values were copied across. Dropped only when
   EVERY value it holds is already in ScoringRulesSnapshotJSON - nothing is lost. */
IF COL_LENGTH('dbo.Scenario_Session', 'TuningSnapshotJSON') IS NOT NULL
BEGIN
    DECLARE @n bigint;
    BEGIN TRY
        EXEC sp_executesql N'SELECT @n = COUNT_BIG(*) FROM dbo.[Scenario_Session]
                             WHERE [TuningSnapshotJSON] IS NOT NULL
                               AND ([ScoringRulesSnapshotJSON] IS NULL OR [ScoringRulesSnapshotJSON] <> [TuningSnapshotJSON]);',
             N'@n bigint OUTPUT', @n = @n OUTPUT;
        IF @n > 0
        BEGIN
            PRINT ' [BLOCKED] Scenario_Session.TuningSnapshotJSON holds ' + CAST(@n AS varchar(20)) +
                  ' value(s) that differ from ScoringRulesSnapshotJSON - NOT dropped.';
            PRINT '          Decide which value is right, update ScoringRulesSnapshotJSON, then re-run.';
        END
        ELSE
        BEGIN
            /* Old indexes built on the column go with it, in the same transaction. */
            DECLARE @ix sysname, @ixs nvarchar(max) = N'', @drop nvarchar(max);
            BEGIN TRANSACTION;
            DECLARE legacy_ix CURSOR LOCAL STATIC READ_ONLY FOR
                SELECT i.name
                FROM   sys.indexes i
                WHERE  i.object_id = OBJECT_ID(N'dbo.Scenario_Session') AND i.type IN (1, 2)
                  AND  i.is_primary_key = 0 AND i.is_unique_constraint = 0
                  AND  (EXISTS (SELECT 1 FROM sys.index_columns ic
                                WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id
                                  AND ic.column_id = COLUMNPROPERTY(i.object_id, N'TuningSnapshotJSON', 'ColumnId'))
                        OR CHARINDEX(N'[TuningSnapshotJSON]', ISNULL(i.filter_definition, N'')) > 0);
            OPEN legacy_ix; FETCH NEXT FROM legacy_ix INTO @ix;
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @drop = N'DROP INDEX ' + QUOTENAME(@ix) + N' ON dbo.[Scenario_Session];';
                EXEC sp_executesql @drop;
                SET @ixs = @ixs + CASE WHEN @ixs = N'' THEN N'' ELSE N', ' END + @ix;
                FETCH NEXT FROM legacy_ix INTO @ix;
            END;
            CLOSE legacy_ix; DEALLOCATE legacy_ix;
            EXEC sp_executesql N'ALTER TABLE dbo.[Scenario_Session] DROP COLUMN [TuningSnapshotJSON];';
            COMMIT;
            PRINT ' [DROPPED] Scenario_Session.TuningSnapshotJSON - legacy column; all of its data is in ScoringRulesSnapshotJSON.';
            IF @ixs <> N''
                PRINT '          Old index(es) on it dropped too: ' + @ixs +
                      ' (the current ones are created by 03_indexes).';
        END
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK;
        PRINT ' [ERROR]   Could not drop Scenario_Session.TuningSnapshotJSON.';
        PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
        EXEC sp_set_session_context N'tsg_deploy_failed', 1;
        RAISERROR('Legacy column Scenario_Session.TuningSnapshotJSON could not be dropped - deployment stopped.', 16, 1);
    END CATCH
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Scenario_Session', @known = N'SessionID,TenantID,EntityID,UserID,AssetName,AssetID,SessionStatus,CurrentStage,StageStatus,Mode,CurrentSubsystemIndex,SubsystemsJSON,IdempotencyKey,SectorIDsJSON,AssetContextJSON,ScoringRulesSnapshotJSON,CreatedAt,UpdatedAt,CompletedAt,CancelledAt,CancelledBy,ControlMapSeconds';
GO
