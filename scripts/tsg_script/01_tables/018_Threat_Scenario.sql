/*==============================================================================
  TABLE: Threat_Scenario

  Script:      018_Threat_Scenario.sql
  Order:       01_tables / 018
  Purpose:     Create Threat_Scenario, or bring an existing copy up to 25 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Threat_Scenario

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- Threat_Scenario ---';
GO

/* Legacy table name Threat_Scenario_Output. Renamed in place - data kept - BEFORE the CREATE below, which
   would otherwise build an empty Threat_Scenario beside it. An empty Threat_Scenario left by an earlier partial run is
   dropped first (it holds nothing); both holding rows is refused rather than guessed at. */
IF OBJECT_ID('dbo.Threat_Scenario_Output', 'U') IS NOT NULL
BEGIN
    DECLARE @old_rows bigint, @new_rows bigint = 0;
    BEGIN TRY
        EXEC sp_executesql N'SELECT @r = COUNT_BIG(*) FROM dbo.[Threat_Scenario_Output];', N'@r bigint OUTPUT', @r = @old_rows OUTPUT;
        IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL
            EXEC sp_executesql N'SELECT @r = COUNT_BIG(*) FROM dbo.[Threat_Scenario];', N'@r bigint OUTPUT', @r = @new_rows OUTPUT;
        IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL AND @new_rows > 0 AND @old_rows > 0
        BEGIN
            PRINT ' [ERROR]   Both Threat_Scenario_Output (' + CAST(@old_rows AS varchar(20)) + ' rows) and Threat_Scenario (' +
                  CAST(@new_rows AS varchar(20)) + ' rows) hold data. Merge them by hand, then re-run.';
            EXEC sp_set_session_context N'tsg_deploy_failed', 1;
            RAISERROR('Legacy table Threat_Scenario_Output and Threat_Scenario both hold data - deployment stopped.', 16, 1);
        END
        ELSE IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL AND @new_rows > 0
            PRINT ' [INFO]    Threat_Scenario_Output is empty and Threat_Scenario holds the data. Threat_Scenario_Output was left alone.';
        ELSE
        BEGIN
            BEGIN TRANSACTION;
            IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL
                EXEC sp_executesql N'DROP TABLE dbo.[Threat_Scenario];';   -- empty: nothing is lost
            EXEC sp_rename 'dbo.Threat_Scenario_Output', 'Threat_Scenario', 'OBJECT';
            COMMIT;
            PRINT ' [RENAMED] Table Threat_Scenario_Output -> Threat_Scenario  (' + CAST(@old_rows AS varchar(20)) + ' row(s), data kept)';
        END
    END TRY
    BEGIN CATCH
        DECLARE @e nvarchar(4000) = ERROR_MESSAGE();
        IF @@TRANCOUNT > 0 ROLLBACK;
        PRINT ' [ERROR]   Could not rename table Threat_Scenario_Output to Threat_Scenario: ' + @e;
        EXEC sp_set_session_context N'tsg_deploy_failed', 1;
        RAISERROR('Legacy table Threat_Scenario_Output could not be renamed - deployment stopped.', 16, 1);
    END CATCH
END
GO

IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Threat_Scenario] (
        [ScenarioID] UNIQUEIDENTIFIER NOT NULL,
        [SessionID] UNIQUEIDENTIFIER NOT NULL,
        [SubsystemID] INT NOT NULL,
        [ScopedThreatID] UNIQUEIDENTIFIER NOT NULL,
        [Status] NVARCHAR(100) NOT NULL,
        [ScenarioJSON] NVARCHAR(max) NULL,
        [ValidationJSON] NVARCHAR(max) NULL,
        [AcceptedSubsetJSON] NVARCHAR(max) NULL,
        [Accepted] INT NOT NULL,
        [Superseded] INT NOT NULL,
        [IdentityHash] NVARCHAR(100) NULL,
        [ScenarioNumber] INT NOT NULL,
        [ReplacesScenarioID] UNIQUEIDENTIFIER NULL,
        [GenerationEpoch] INT NOT NULL,
        [ErrorMessage] NVARCHAR(max) NULL,
        [CreatedAt] DATETIME2(7) NULL,
        [ControlsMappedAt] DATETIME2(7) NULL,
        [ControlMapAttempts] INT NOT NULL,
        [GenStartedAt] DATETIME2(7) NULL,
        [GenFinishedAt] DATETIME2(7) NULL,
        [ScenarioSource] NVARCHAR(100) NULL,
        [RejectedAt] DATETIME2(7) NULL,
        [RejectedBy] NVARCHAR(200) NULL,
        [AcceptedAt] DATETIME2(7) NULL,
        [AcceptedBy] NVARCHAR(200) NULL,
        CONSTRAINT [PK_Threat_Scenario] PRIMARY KEY CLUSTERED ([ScenarioID])
    );
    PRINT ' [CREATED] Table: Threat_Scenario (25 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Threat_Scenario';
GO

/* Legacy column names: renamed in place so their data is kept. */
EXEC dbo.tsg_rename_column @table = N'Threat_Scenario', @old = N'OutputID', @new = N'ScenarioID';
EXEC dbo.tsg_rename_column @table = N'Threat_Scenario', @old = N'ReplacesOutputID', @new = N'ReplacesScenarioID';
GO

/* Constraint and index names from before the rename, brought to the current names so the
   constraint and index scripts find them instead of creating a second copy. */
IF OBJECT_ID('dbo.PK_Threat_Scenario_Output') IS NOT NULL AND NOT OBJECT_ID('dbo.PK_Threat_Scenario') IS NOT NULL
BEGIN
    EXEC sp_rename 'dbo.PK_Threat_Scenario_Output', 'PK_Threat_Scenario', 'OBJECT';
    PRINT ' [RENAMED] PK_Threat_Scenario_Output -> PK_Threat_Scenario';
END;
IF OBJECT_ID('dbo.CK_ScenarioOutput_DecisionExclusive') IS NOT NULL AND NOT OBJECT_ID('dbo.CK_Scenario_DecisionExclusive') IS NOT NULL
BEGIN
    EXEC sp_rename 'dbo.CK_ScenarioOutput_DecisionExclusive', 'CK_Scenario_DecisionExclusive', 'OBJECT';
    PRINT ' [RENAMED] CK_ScenarioOutput_DecisionExclusive -> CK_Scenario_DecisionExclusive';
END;
IF OBJECT_ID('dbo.DF_ScenarioOutput_ScenarioNumber') IS NOT NULL AND NOT OBJECT_ID('dbo.DF_Scenario_ScenarioNumber') IS NOT NULL
BEGIN
    EXEC sp_rename 'dbo.DF_ScenarioOutput_ScenarioNumber', 'DF_Scenario_ScenarioNumber', 'OBJECT';
    PRINT ' [RENAMED] DF_ScenarioOutput_ScenarioNumber -> DF_Scenario_ScenarioNumber';
END;
IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioOutput_SessionSubActive' AND object_id = OBJECT_ID('dbo.Threat_Scenario')) AND NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Scenario_SessionSubActive' AND object_id = OBJECT_ID('dbo.Threat_Scenario'))
BEGIN
    EXEC sp_rename 'dbo.Threat_Scenario.IX_ScenarioOutput_SessionSubActive', 'IX_Scenario_SessionSubActive', 'INDEX';
    PRINT ' [RENAMED] IX_ScenarioOutput_SessionSubActive -> IX_Scenario_SessionSubActive';
END;
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'ScenarioID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'SessionID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'SubsystemID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'ScopedThreatID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'Status',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'ScenarioJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'ValidationJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'AcceptedSubsetJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'Accepted',
     @expected = N'INT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'Superseded',
     @expected = N'INT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'IdentityHash',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'ScenarioNumber',
     @expected = N'INT', @nullable = 0, @fill = N'1';
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'ReplacesScenarioID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'GenerationEpoch',
     @expected = N'INT', @nullable = 0, @fill = N'1';
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'ErrorMessage',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'ControlsMappedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'ControlMapAttempts',
     @expected = N'INT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'GenStartedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'GenFinishedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'ScenarioSource',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'RejectedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'RejectedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'AcceptedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'AcceptedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Threat_Scenario', @columns = N'ScenarioID';
GO

/* Legacy column OutputID, replaced by ScenarioID. Normally already RENAMED away above; it is still here
   only if ScenarioID existed too, in which case its values were copied across. Dropped only when
   EVERY value it holds is already in ScenarioID - nothing is lost. */
IF COL_LENGTH('dbo.Threat_Scenario', 'OutputID') IS NOT NULL
BEGIN
    DECLARE @n bigint;
    BEGIN TRY
        EXEC sp_executesql N'SELECT @n = COUNT_BIG(*) FROM dbo.[Threat_Scenario]
                             WHERE [OutputID] IS NOT NULL
                               AND ([ScenarioID] IS NULL OR [ScenarioID] <> [OutputID]);',
             N'@n bigint OUTPUT', @n = @n OUTPUT;
        IF @n > 0
        BEGIN
            PRINT ' [BLOCKED] Threat_Scenario.OutputID holds ' + CAST(@n AS varchar(20)) +
                  ' value(s) that differ from ScenarioID - NOT dropped.';
            PRINT '          Decide which value is right, update ScenarioID, then re-run.';
        END
        ELSE
        BEGIN
            /* Old indexes built on the column go with it, in the same transaction. */
            DECLARE @ix sysname, @ixs nvarchar(max) = N'', @drop nvarchar(max);
            BEGIN TRANSACTION;
            DECLARE legacy_ix CURSOR LOCAL STATIC READ_ONLY FOR
                SELECT i.name
                FROM   sys.indexes i
                WHERE  i.object_id = OBJECT_ID(N'dbo.Threat_Scenario') AND i.type IN (1, 2)
                  AND  i.is_primary_key = 0 AND i.is_unique_constraint = 0
                  AND  (EXISTS (SELECT 1 FROM sys.index_columns ic
                                WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id
                                  AND ic.column_id = COLUMNPROPERTY(i.object_id, N'OutputID', 'ColumnId'))
                        OR CHARINDEX(N'[OutputID]', ISNULL(i.filter_definition, N'')) > 0);
            OPEN legacy_ix; FETCH NEXT FROM legacy_ix INTO @ix;
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @drop = N'DROP INDEX ' + QUOTENAME(@ix) + N' ON dbo.[Threat_Scenario];';
                EXEC sp_executesql @drop;
                SET @ixs = @ixs + CASE WHEN @ixs = N'' THEN N'' ELSE N', ' END + @ix;
                FETCH NEXT FROM legacy_ix INTO @ix;
            END;
            CLOSE legacy_ix; DEALLOCATE legacy_ix;
            EXEC sp_executesql N'ALTER TABLE dbo.[Threat_Scenario] DROP COLUMN [OutputID];';
            COMMIT;
            PRINT ' [DROPPED] Threat_Scenario.OutputID - legacy column; all of its data is in ScenarioID.';
            IF @ixs <> N''
                PRINT '          Old index(es) on it dropped too: ' + @ixs +
                      ' (the current ones are created by 03_indexes).';
        END
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK;
        PRINT ' [ERROR]   Could not drop Threat_Scenario.OutputID.';
        PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
        EXEC sp_set_session_context N'tsg_deploy_failed', 1;
        RAISERROR('Legacy column Threat_Scenario.OutputID could not be dropped - deployment stopped.', 16, 1);
    END CATCH
END
GO

/* Legacy column ReplacesOutputID, replaced by ReplacesScenarioID. Normally already RENAMED away above; it is still here
   only if ReplacesScenarioID existed too, in which case its values were copied across. Dropped only when
   EVERY value it holds is already in ReplacesScenarioID - nothing is lost. */
IF COL_LENGTH('dbo.Threat_Scenario', 'ReplacesOutputID') IS NOT NULL
BEGIN
    DECLARE @n bigint;
    BEGIN TRY
        EXEC sp_executesql N'SELECT @n = COUNT_BIG(*) FROM dbo.[Threat_Scenario]
                             WHERE [ReplacesOutputID] IS NOT NULL
                               AND ([ReplacesScenarioID] IS NULL OR [ReplacesScenarioID] <> [ReplacesOutputID]);',
             N'@n bigint OUTPUT', @n = @n OUTPUT;
        IF @n > 0
        BEGIN
            PRINT ' [BLOCKED] Threat_Scenario.ReplacesOutputID holds ' + CAST(@n AS varchar(20)) +
                  ' value(s) that differ from ReplacesScenarioID - NOT dropped.';
            PRINT '          Decide which value is right, update ReplacesScenarioID, then re-run.';
        END
        ELSE
        BEGIN
            /* Old indexes built on the column go with it, in the same transaction. */
            DECLARE @ix sysname, @ixs nvarchar(max) = N'', @drop nvarchar(max);
            BEGIN TRANSACTION;
            DECLARE legacy_ix CURSOR LOCAL STATIC READ_ONLY FOR
                SELECT i.name
                FROM   sys.indexes i
                WHERE  i.object_id = OBJECT_ID(N'dbo.Threat_Scenario') AND i.type IN (1, 2)
                  AND  i.is_primary_key = 0 AND i.is_unique_constraint = 0
                  AND  (EXISTS (SELECT 1 FROM sys.index_columns ic
                                WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id
                                  AND ic.column_id = COLUMNPROPERTY(i.object_id, N'ReplacesOutputID', 'ColumnId'))
                        OR CHARINDEX(N'[ReplacesOutputID]', ISNULL(i.filter_definition, N'')) > 0);
            OPEN legacy_ix; FETCH NEXT FROM legacy_ix INTO @ix;
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @drop = N'DROP INDEX ' + QUOTENAME(@ix) + N' ON dbo.[Threat_Scenario];';
                EXEC sp_executesql @drop;
                SET @ixs = @ixs + CASE WHEN @ixs = N'' THEN N'' ELSE N', ' END + @ix;
                FETCH NEXT FROM legacy_ix INTO @ix;
            END;
            CLOSE legacy_ix; DEALLOCATE legacy_ix;
            EXEC sp_executesql N'ALTER TABLE dbo.[Threat_Scenario] DROP COLUMN [ReplacesOutputID];';
            COMMIT;
            PRINT ' [DROPPED] Threat_Scenario.ReplacesOutputID - legacy column; all of its data is in ReplacesScenarioID.';
            IF @ixs <> N''
                PRINT '          Old index(es) on it dropped too: ' + @ixs +
                      ' (the current ones are created by 03_indexes).';
        END
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK;
        PRINT ' [ERROR]   Could not drop Threat_Scenario.ReplacesOutputID.';
        PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
        EXEC sp_set_session_context N'tsg_deploy_failed', 1;
        RAISERROR('Legacy column Threat_Scenario.ReplacesOutputID could not be dropped - deployment stopped.', 16, 1);
    END CATCH
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Threat_Scenario', @known = N'ScenarioID,SessionID,SubsystemID,ScopedThreatID,Status,ScenarioJSON,ValidationJSON,AcceptedSubsetJSON,Accepted,Superseded,IdentityHash,ScenarioNumber,ReplacesScenarioID,GenerationEpoch,ErrorMessage,CreatedAt,ControlsMappedAt,ControlMapAttempts,GenStartedAt,GenFinishedAt,ScenarioSource,RejectedAt,RejectedBy,AcceptedAt,AcceptedBy';
GO
