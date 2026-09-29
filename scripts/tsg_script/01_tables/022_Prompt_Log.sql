/*==============================================================================
  TABLE: Prompt_Log

  Script:      022_Prompt_Log.sql
  Order:       01_tables / 022
  Purpose:     Create Prompt_Log, or bring an existing copy up to 15 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Prompt_Log

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- Prompt_Log ---';
GO

IF OBJECT_ID('dbo.Prompt_Log', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Prompt_Log] (
        [LogID] UNIQUEIDENTIFIER NOT NULL,
        [SessionID] UNIQUEIDENTIFIER NOT NULL,
        [TenantID] NVARCHAR(200) NULL,
        [EntityID] NVARCHAR(200) NULL,
        [UserID] NVARCHAR(200) NULL,
        [SubsystemID] INT NOT NULL,
        [Stage] NVARCHAR(100) NOT NULL,
        [PromptVersion] NVARCHAR(100) NOT NULL,
        [Prompt] NVARCHAR(max) NULL,
        [ResponseText] NVARCHAR(max) NULL,
        [Model] NVARCHAR(200) NULL,
        [ModelVersion] NVARCHAR(100) NULL,
        [ParseSucceeded] BIT NOT NULL,
        [CreatedAt] DATETIME2(7) NOT NULL,
        [CorrelationID] UNIQUEIDENTIFIER NULL,
        CONSTRAINT [PK_Prompt_Log] PRIMARY KEY CLUSTERED ([LogID])
    );
    PRINT ' [CREATED] Table: Prompt_Log (15 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Prompt_Log';
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'LogID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'SessionID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'TenantID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'EntityID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'UserID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'SubsystemID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'Stage',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'PromptVersion',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'Prompt',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'ResponseText',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'Model',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'ModelVersion',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'ParseSucceeded',
     @expected = N'BIT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'CorrelationID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 1;
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Prompt_Log', @columns = N'LogID';
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Prompt_Log', @known = N'LogID,SessionID,TenantID,EntityID,UserID,SubsystemID,Stage,PromptVersion,Prompt,ResponseText,Model,ModelVersion,ParseSucceeded,CreatedAt,CorrelationID';
GO
