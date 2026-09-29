/*==============================================================================
  TABLE: Application_Log

  Script:      024_Application_Log.sql
  Order:       01_tables / 024
  Purpose:     Create Application_Log, or bring an existing copy up to 9 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Application_Log

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- Application_Log ---';
GO

IF OBJECT_ID('dbo.Application_Log', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Application_Log] (
        [LogID] UNIQUEIDENTIFIER NOT NULL,
        [CreatedAt] DATETIME2(7) NOT NULL,
        [Level] NVARCHAR(20) NOT NULL,
        [Logger] NVARCHAR(200) NULL,
        [Event] NVARCHAR(500) NULL,
        [SessionID] NVARCHAR(100) NULL,
        [RequestID] NVARCHAR(100) NULL,
        [TaskID] NVARCHAR(100) NULL,
        [FieldsJSON] NVARCHAR(max) NULL,
        CONSTRAINT [PK_Application_Log] PRIMARY KEY CLUSTERED ([LogID])
    );
    PRINT ' [CREATED] Table: Application_Log (9 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Application_Log';
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Application_Log', @column = N'LogID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Application_Log', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Application_Log', @column = N'Level',
     @expected = N'NVARCHAR(20)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Application_Log', @column = N'Logger',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Application_Log', @column = N'Event',
     @expected = N'NVARCHAR(500)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Application_Log', @column = N'SessionID',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Application_Log', @column = N'RequestID',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Application_Log', @column = N'TaskID',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Application_Log', @column = N'FieldsJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Application_Log', @columns = N'LogID';
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Application_Log', @known = N'LogID,CreatedAt,Level,Logger,Event,SessionID,RequestID,TaskID,FieldsJSON';
GO
