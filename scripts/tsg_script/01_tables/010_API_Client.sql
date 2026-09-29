/*==============================================================================
  TABLE: API_Client

  Script:      010_API_Client.sql
  Order:       01_tables / 010
  Purpose:     Create API_Client, or bring an existing copy up to 9 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.API_Client

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- API_Client ---';
GO

IF OBJECT_ID('dbo.API_Client', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[API_Client] (
        [ClientID] NVARCHAR(100) NOT NULL,
        [KeyHash] NVARCHAR(100) NOT NULL,
        [Name] NVARCHAR(200) NOT NULL,
        [Module] NVARCHAR(100) NOT NULL,
        [Active] BIT NOT NULL,
        [CreatedAt] DATETIME2(3) NOT NULL,
        [CreatedBy] NVARCHAR(200) NULL,
        [RevokedAt] DATETIME2(3) NULL,
        [RevokedBy] NVARCHAR(200) NULL,
        CONSTRAINT [PK_API_Client] PRIMARY KEY CLUSTERED ([ClientID])
    );
    PRINT ' [CREATED] Table: API_Client (9 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: API_Client';
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'API_Client', @column = N'ClientID',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'API_Client', @column = N'KeyHash',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'API_Client', @column = N'Name',
     @expected = N'NVARCHAR(200)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'API_Client', @column = N'Module',
     @expected = N'NVARCHAR(100)', @nullable = 0, @fill = N'N''tsg''';
EXEC dbo.tsg_reconcile_column @table = N'API_Client', @column = N'Active',
     @expected = N'BIT', @nullable = 0, @fill = N'1';
EXEC dbo.tsg_reconcile_column @table = N'API_Client', @column = N'CreatedAt',
     @expected = N'DATETIME2(3)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'API_Client', @column = N'CreatedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'API_Client', @column = N'RevokedAt',
     @expected = N'DATETIME2(3)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'API_Client', @column = N'RevokedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'API_Client', @columns = N'ClientID';
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'API_Client', @known = N'ClientID,KeyHash,Name,Module,Active,CreatedAt,CreatedBy,RevokedAt,RevokedBy';
GO
