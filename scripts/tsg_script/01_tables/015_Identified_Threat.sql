/*==============================================================================
  TABLE: Identified_Threat

  Script:      015_Identified_Threat.sql
  Order:       01_tables / 015
  Purpose:     Create Identified_Threat, or bring an existing copy up to 20 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Identified_Threat

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- Identified_Threat ---';
GO

IF OBJECT_ID('dbo.Identified_Threat', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Identified_Threat] (
        [ThreatID] UNIQUEIDENTIFIER NOT NULL,
        [SessionID] UNIQUEIDENTIFIER NOT NULL,
        [SubsystemID] INT NOT NULL,
        [ThreatCategory] NVARCHAR(200) NOT NULL,
        [ThreatType] NVARCHAR(300) NOT NULL,
        [ThreatName] NVARCHAR(500) NULL,
        [GenericName] NVARCHAR(500) NULL,
        [ThreatCategoryID] INT NULL,
        [ThreatActorsJSON] NVARCHAR(max) NULL,
        [LibraryThreatType] NVARCHAR(300) NULL,
        [LibraryThreatName] NVARCHAR(500) NULL,
        [ThreatTypeID] INT NULL,
        [ThreatCatalogueID] INT NULL,
        [IsThreatAIGenerated] BIT NOT NULL,
        [IsThreatTypeAIGenerated] BIT NOT NULL,
        [GroundingStatus] NVARCHAR(100) NOT NULL,
        [GroundingScore] FLOAT NULL,
        [GroundingThresholdOrigin] NVARCHAR(100) NULL,
        [Superseded] INT NOT NULL,
        [CreatedAt] DATETIME2(7) NULL,
        CONSTRAINT [PK_Identified_Threat] PRIMARY KEY CLUSTERED ([ThreatID])
    );
    PRINT ' [CREATED] Table: Identified_Threat (20 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Identified_Threat';
GO

/* Legacy column names: renamed in place so their data is kept. */
EXEC dbo.tsg_rename_column @table = N'Identified_Threat', @old = N'IsAIGenerated', @new = N'IsThreatAIGenerated';
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'ThreatID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'SessionID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'SubsystemID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'ThreatCategory',
     @expected = N'NVARCHAR(200)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'ThreatType',
     @expected = N'NVARCHAR(300)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'ThreatName',
     @expected = N'NVARCHAR(500)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'GenericName',
     @expected = N'NVARCHAR(500)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'ThreatCategoryID',
     @expected = N'INT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'ThreatActorsJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'LibraryThreatType',
     @expected = N'NVARCHAR(300)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'LibraryThreatName',
     @expected = N'NVARCHAR(500)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'ThreatTypeID',
     @expected = N'INT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'ThreatCatalogueID',
     @expected = N'INT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'IsThreatAIGenerated',
     @expected = N'BIT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'IsThreatTypeAIGenerated',
     @expected = N'BIT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'GroundingStatus',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'GroundingScore',
     @expected = N'FLOAT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'GroundingThresholdOrigin',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'Superseded',
     @expected = N'INT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Identified_Threat', @columns = N'ThreatID';
GO

/* Legacy column IsAIGenerated, replaced by IsThreatAIGenerated. Normally already RENAMED away above; it is still here
   only if IsThreatAIGenerated existed too, in which case its values were copied across. Dropped only when
   EVERY value it holds is already in IsThreatAIGenerated - nothing is lost. */
IF COL_LENGTH('dbo.Identified_Threat', 'IsAIGenerated') IS NOT NULL
BEGIN
    DECLARE @n bigint;
    BEGIN TRY
        EXEC sp_executesql N'SELECT @n = COUNT_BIG(*) FROM dbo.[Identified_Threat]
                             WHERE [IsAIGenerated] IS NOT NULL
                               AND ([IsThreatAIGenerated] IS NULL OR [IsThreatAIGenerated] <> [IsAIGenerated]);',
             N'@n bigint OUTPUT', @n = @n OUTPUT;
        IF @n > 0
        BEGIN
            PRINT ' [BLOCKED] Identified_Threat.IsAIGenerated holds ' + CAST(@n AS varchar(20)) +
                  ' value(s) that differ from IsThreatAIGenerated - NOT dropped.';
            PRINT '          Decide which value is right, update IsThreatAIGenerated, then re-run.';
        END
        ELSE
        BEGIN
            /* Old indexes built on the column go with it, in the same transaction. */
            DECLARE @ix sysname, @ixs nvarchar(max) = N'', @drop nvarchar(max);
            BEGIN TRANSACTION;
            DECLARE legacy_ix CURSOR LOCAL STATIC READ_ONLY FOR
                SELECT i.name
                FROM   sys.indexes i
                WHERE  i.object_id = OBJECT_ID(N'dbo.Identified_Threat') AND i.type IN (1, 2)
                  AND  i.is_primary_key = 0 AND i.is_unique_constraint = 0
                  AND  (EXISTS (SELECT 1 FROM sys.index_columns ic
                                WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id
                                  AND ic.column_id = COLUMNPROPERTY(i.object_id, N'IsAIGenerated', 'ColumnId'))
                        OR CHARINDEX(N'[IsAIGenerated]', ISNULL(i.filter_definition, N'')) > 0);
            OPEN legacy_ix; FETCH NEXT FROM legacy_ix INTO @ix;
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @drop = N'DROP INDEX ' + QUOTENAME(@ix) + N' ON dbo.[Identified_Threat];';
                EXEC sp_executesql @drop;
                SET @ixs = @ixs + CASE WHEN @ixs = N'' THEN N'' ELSE N', ' END + @ix;
                FETCH NEXT FROM legacy_ix INTO @ix;
            END;
            CLOSE legacy_ix; DEALLOCATE legacy_ix;
            EXEC sp_executesql N'ALTER TABLE dbo.[Identified_Threat] DROP COLUMN [IsAIGenerated];';
            COMMIT;
            PRINT ' [DROPPED] Identified_Threat.IsAIGenerated - legacy column; all of its data is in IsThreatAIGenerated.';
            IF @ixs <> N''
                PRINT '          Old index(es) on it dropped too: ' + @ixs +
                      ' (the current ones are created by 03_indexes).';
        END
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK;
        PRINT ' [ERROR]   Could not drop Identified_Threat.IsAIGenerated.';
        PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
        EXEC sp_set_session_context N'tsg_deploy_failed', 1;
        RAISERROR('Legacy column Identified_Threat.IsAIGenerated could not be dropped - deployment stopped.', 16, 1);
    END CATCH
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Identified_Threat', @known = N'ThreatID,SessionID,SubsystemID,ThreatCategory,ThreatType,ThreatName,GenericName,ThreatCategoryID,ThreatActorsJSON,LibraryThreatType,LibraryThreatName,ThreatTypeID,ThreatCatalogueID,IsThreatAIGenerated,IsThreatTypeAIGenerated,GroundingStatus,GroundingScore,GroundingThresholdOrigin,Superseded,CreatedAt';
GO
