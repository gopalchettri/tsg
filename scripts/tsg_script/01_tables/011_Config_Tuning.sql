/*==============================================================================
  TABLE: Config_Tuning

  Script:      011_Config_Tuning.sql
  Order:       01_tables / 011
  Purpose:     Create Config_Tuning, or bring an existing copy up to 11 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Config_Tuning

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- Config_Tuning ---';
GO

IF OBJECT_ID('dbo.Config_Tuning', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Config_Tuning] (
        [TuningID] INT IDENTITY(1,1) NOT NULL,
        [TuningKey] NVARCHAR(100) NOT NULL,
        [TuningValue] NVARCHAR(100) NOT NULL,
        [ValueType] NVARCHAR(100) NOT NULL,
        [EmbeddingModel] NVARCHAR(200) NULL,
        [CreateDate] DATETIME2(7) NULL,
        [CreatedBy] NVARCHAR(200) NULL,
        [UpdateDate] DATETIME2(7) NULL,
        [UpdatedBy] NVARCHAR(200) NULL,
        [IsActive] BIT NOT NULL,
        [IsDeleted] BIT NOT NULL,
        CONSTRAINT [PK_Config_Tuning] PRIMARY KEY CLUSTERED ([TuningID])
    );
    PRINT ' [CREATED] Table: Config_Tuning (11 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Config_Tuning';
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Config_Tuning', @column = N'TuningID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Config_Tuning', @column = N'TuningKey',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Config_Tuning', @column = N'TuningValue',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Config_Tuning', @column = N'ValueType',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Config_Tuning', @column = N'EmbeddingModel',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Config_Tuning', @column = N'CreateDate',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Config_Tuning', @column = N'CreatedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Config_Tuning', @column = N'UpdateDate',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Config_Tuning', @column = N'UpdatedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Config_Tuning', @column = N'IsActive',
     @expected = N'BIT', @nullable = 0, @fill = N'1';
EXEC dbo.tsg_reconcile_column @table = N'Config_Tuning', @column = N'IsDeleted',
     @expected = N'BIT', @nullable = 0, @fill = N'0';
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Config_Tuning', @columns = N'TuningID';
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Config_Tuning', @known = N'TuningID,TuningKey,TuningValue,ValueType,EmbeddingModel,CreateDate,CreatedBy,UpdateDate,UpdatedBy,IsActive,IsDeleted';
GO
