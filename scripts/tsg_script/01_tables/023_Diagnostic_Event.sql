/*==============================================================================
  TABLE: Diagnostic_Event

  Script:      023_Diagnostic_Event.sql
  Order:       01_tables / 023
  Purpose:     Create Diagnostic_Event, or bring an existing copy up to 13 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Diagnostic_Event

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- Diagnostic_Event ---';
GO

IF OBJECT_ID('dbo.Diagnostic_Event', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Diagnostic_Event] (
        [DiagnosticID] UNIQUEIDENTIFIER NOT NULL,
        [CreatedAt] DATETIME2(7) NOT NULL,
        [SessionID] UNIQUEIDENTIFIER NULL,
        [EntityID] NVARCHAR(200) NULL,
        [SubsystemID] INT NULL,
        [TaskID] NVARCHAR(100) NULL,
        [RequestID] NVARCHAR(100) NULL,
        [Kind] NVARCHAR(50) NOT NULL,
        [ExceptionClass] NVARCHAR(200) NOT NULL,
        [ExceptionMessage] NVARCHAR(4000) NULL,
        [Traceback] NVARCHAR(max) NULL,
        [ClientMessage] NVARCHAR(1000) NULL,
        [ContextJSON] NVARCHAR(max) NULL,
        CONSTRAINT [PK_Diagnostic_Event] PRIMARY KEY CLUSTERED ([DiagnosticID])
    );
    PRINT ' [CREATED] Table: Diagnostic_Event (13 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Diagnostic_Event';
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'DiagnosticID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'SessionID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'EntityID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'SubsystemID',
     @expected = N'INT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'TaskID',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'RequestID',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'Kind',
     @expected = N'NVARCHAR(50)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'ExceptionClass',
     @expected = N'NVARCHAR(200)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'ExceptionMessage',
     @expected = N'NVARCHAR(4000)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'Traceback',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'ClientMessage',
     @expected = N'NVARCHAR(1000)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'ContextJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Diagnostic_Event', @columns = N'DiagnosticID';
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Diagnostic_Event', @known = N'DiagnosticID,CreatedAt,SessionID,EntityID,SubsystemID,TaskID,RequestID,Kind,ExceptionClass,ExceptionMessage,Traceback,ClientMessage,ContextJSON';
GO
