/*==============================================================================
  TABLE: Grounding_Calibration_Run

  Script:      012_Grounding_Calibration_Run.sql
  Order:       01_tables / 012
  Purpose:     Create Grounding_Calibration_Run, or bring an existing copy up to 19 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Grounding_Calibration_Run

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- Grounding_Calibration_Run ---';
GO

IF OBJECT_ID('dbo.Grounding_Calibration_Run', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Grounding_Calibration_Run] (
        [RunID] UNIQUEIDENTIFIER NOT NULL,
        [JobID] NVARCHAR(100) NULL,
        [Status] NVARCHAR(100) NOT NULL,
        [StartedBy] NVARCHAR(200) NULL,
        [StartedByClient] NVARCHAR(200) NULL,
        [StartedAt] DATETIME2(7) NULL,
        [FinishedAt] DATETIME2(7) NULL,
        [EmbeddingModel] NVARCHAR(500) NULL,
        [RerankerModel] NVARCHAR(500) NULL,
        [Forced] BIT NOT NULL,
        [MatchTh] FLOAT NULL,
        [ControlMapTh] FLOAT NULL,
        [Quality] FLOAT NULL,
        [NegativesCount] INT NULL,
        [PositivesCount] INT NULL,
        [HighestNegative] FLOAT NULL,
        [LowestPositive] FLOAT NULL,
        [NearDuplicatesJSON] NVARCHAR(max) NULL,
        [ErrorMessage] NVARCHAR(max) NULL,
        CONSTRAINT [PK_Grounding_Calibration_Run] PRIMARY KEY CLUSTERED ([RunID])
    );
    PRINT ' [CREATED] Table: Grounding_Calibration_Run (19 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Grounding_Calibration_Run';
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'RunID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'JobID',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'Status',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'StartedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'StartedByClient',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'StartedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'FinishedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'EmbeddingModel',
     @expected = N'NVARCHAR(500)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'RerankerModel',
     @expected = N'NVARCHAR(500)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'Forced',
     @expected = N'BIT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'MatchTh',
     @expected = N'FLOAT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'ControlMapTh',
     @expected = N'FLOAT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'Quality',
     @expected = N'FLOAT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'NegativesCount',
     @expected = N'INT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'PositivesCount',
     @expected = N'INT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'HighestNegative',
     @expected = N'FLOAT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'LowestPositive',
     @expected = N'FLOAT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'NearDuplicatesJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'ErrorMessage',
     @expected = N'NVARCHAR(max)', @nullable = 1;
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Grounding_Calibration_Run', @columns = N'RunID';
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Grounding_Calibration_Run', @known = N'RunID,JobID,Status,StartedBy,StartedByClient,StartedAt,FinishedAt,EmbeddingModel,RerankerModel,Forced,MatchTh,ControlMapTh,Quality,NegativesCount,PositivesCount,HighestNegative,LowestPositive,NearDuplicatesJSON,ErrorMessage';
GO
