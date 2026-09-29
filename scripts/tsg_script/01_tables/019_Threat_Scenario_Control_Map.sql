/*==============================================================================
  TABLE: Threat_Scenario_Control_Map

  Script:      019_Threat_Scenario_Control_Map.sql
  Order:       01_tables / 019
  Purpose:     Create Threat_Scenario_Control_Map, or bring an existing copy up to 7 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Threat_Scenario_Control_Map

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- Threat_Scenario_Control_Map ---';
GO

IF OBJECT_ID('dbo.Threat_Scenario_Control_Map', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Threat_Scenario_Control_Map] (
        [ScenarioID] UNIQUEIDENTIFIER NOT NULL,
        [ControlLibraryID] INT NOT NULL,
        [SessionID] UNIQUEIDENTIFIER NOT NULL,
        [MapRank] INT NOT NULL,
        [Score] FLOAT NULL,
        [SuggestedControl] NVARCHAR(500) NULL,
        [CreatedAt] DATETIME2(7) NULL,
        CONSTRAINT [PK_Threat_Scenario_Control_Map] PRIMARY KEY CLUSTERED ([ScenarioID], [ControlLibraryID])
    );
    PRINT ' [CREATED] Table: Threat_Scenario_Control_Map (7 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Threat_Scenario_Control_Map';
GO

/* Legacy column names: renamed in place so their data is kept. */
EXEC dbo.tsg_rename_column @table = N'Threat_Scenario_Control_Map', @old = N'OutputID', @new = N'ScenarioID';
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario_Control_Map', @column = N'ScenarioID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario_Control_Map', @column = N'ControlLibraryID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario_Control_Map', @column = N'SessionID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario_Control_Map', @column = N'MapRank',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario_Control_Map', @column = N'Score',
     @expected = N'FLOAT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario_Control_Map', @column = N'SuggestedControl',
     @expected = N'NVARCHAR(500)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario_Control_Map', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Threat_Scenario_Control_Map', @columns = N'ScenarioID,ControlLibraryID';
GO

/* Legacy column OutputID, replaced by ScenarioID. Normally already RENAMED away above; it is still here
   only if ScenarioID existed too, in which case its values were copied across. Dropped only when
   EVERY value it holds is already in ScenarioID - nothing is lost. */
IF COL_LENGTH('dbo.Threat_Scenario_Control_Map', 'OutputID') IS NOT NULL
BEGIN
    DECLARE @n bigint;
    BEGIN TRY
        EXEC sp_executesql N'SELECT @n = COUNT_BIG(*) FROM dbo.[Threat_Scenario_Control_Map]
                             WHERE [OutputID] IS NOT NULL
                               AND ([ScenarioID] IS NULL OR [ScenarioID] <> [OutputID]);',
             N'@n bigint OUTPUT', @n = @n OUTPUT;
        IF @n > 0
        BEGIN
            PRINT ' [BLOCKED] Threat_Scenario_Control_Map.OutputID holds ' + CAST(@n AS varchar(20)) +
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
                WHERE  i.object_id = OBJECT_ID(N'dbo.Threat_Scenario_Control_Map') AND i.type IN (1, 2)
                  AND  i.is_primary_key = 0 AND i.is_unique_constraint = 0
                  AND  (EXISTS (SELECT 1 FROM sys.index_columns ic
                                WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id
                                  AND ic.column_id = COLUMNPROPERTY(i.object_id, N'OutputID', 'ColumnId'))
                        OR CHARINDEX(N'[OutputID]', ISNULL(i.filter_definition, N'')) > 0);
            OPEN legacy_ix; FETCH NEXT FROM legacy_ix INTO @ix;
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @drop = N'DROP INDEX ' + QUOTENAME(@ix) + N' ON dbo.[Threat_Scenario_Control_Map];';
                EXEC sp_executesql @drop;
                SET @ixs = @ixs + CASE WHEN @ixs = N'' THEN N'' ELSE N', ' END + @ix;
                FETCH NEXT FROM legacy_ix INTO @ix;
            END;
            CLOSE legacy_ix; DEALLOCATE legacy_ix;
            EXEC sp_executesql N'ALTER TABLE dbo.[Threat_Scenario_Control_Map] DROP COLUMN [OutputID];';
            COMMIT;
            PRINT ' [DROPPED] Threat_Scenario_Control_Map.OutputID - legacy column; all of its data is in ScenarioID.';
            IF @ixs <> N''
                PRINT '          Old index(es) on it dropped too: ' + @ixs +
                      ' (the current ones are created by 03_indexes).';
        END
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK;
        PRINT ' [ERROR]   Could not drop Threat_Scenario_Control_Map.OutputID.';
        PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
        EXEC sp_set_session_context N'tsg_deploy_failed', 1;
        RAISERROR('Legacy column Threat_Scenario_Control_Map.OutputID could not be dropped - deployment stopped.', 16, 1);
    END CATCH
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Threat_Scenario_Control_Map', @known = N'ScenarioID,ControlLibraryID,SessionID,MapRank,Score,SuggestedControl,CreatedAt';
GO
