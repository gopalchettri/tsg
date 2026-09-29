/*==============================================================================
  TABLE: Control_Standard

  Script:      007_Control_Standard.sql
  Order:       01_tables / 007
  Purpose:     Create Control_Standard, or bring an existing copy up to 9 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Control_Standard

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- Control_Standard ---';
GO

IF OBJECT_ID('dbo.Control_Standard', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Control_Standard] (
        [StandardID] INT IDENTITY(1,1) NOT NULL,
        [StandardName] NVARCHAR(200) NOT NULL,
        [Source] NVARCHAR(100) NULL,
        [CreatedAt] DATETIME NULL,
        [CreatedBy] NVARCHAR(200) NULL,
        [UpdatedAt] DATETIME NULL,
        [UpdatedBy] NVARCHAR(200) NULL,
        [IsActive] BIT NOT NULL,
        [IsDeleted] BIT NOT NULL,
        CONSTRAINT [PK_Control_Standard] PRIMARY KEY CLUSTERED ([StandardID])
    );
    PRINT ' [CREATED] Table: Control_Standard (9 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Control_Standard';
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Control_Standard', @column = N'StandardID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Control_Standard', @column = N'StandardName',
     @expected = N'NVARCHAR(200)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Control_Standard', @column = N'Source',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Control_Standard', @column = N'CreatedAt',
     @expected = N'DATETIME', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Control_Standard', @column = N'CreatedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Control_Standard', @column = N'UpdatedAt',
     @expected = N'DATETIME', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Control_Standard', @column = N'UpdatedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Control_Standard', @column = N'IsActive',
     @expected = N'BIT', @nullable = 0, @fill = N'1';
EXEC dbo.tsg_reconcile_column @table = N'Control_Standard', @column = N'IsDeleted',
     @expected = N'BIT', @nullable = 0, @fill = N'0';
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Control_Standard', @columns = N'StandardID';
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Control_Standard', @known = N'StandardID,StandardName,Source,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy,IsActive,IsDeleted';
GO
