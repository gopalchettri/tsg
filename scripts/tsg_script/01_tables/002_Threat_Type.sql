/*==============================================================================
  TABLE: Threat_Type

  Script:      002_Threat_Type.sql
  Order:       01_tables / 002
  Purpose:     Create Threat_Type, or bring an existing copy up to 10 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Threat_Type

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- Threat_Type ---';
GO

IF OBJECT_ID('dbo.Threat_Type', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Threat_Type] (
        [ThreatTypeID] INT IDENTITY(1,1) NOT NULL,
        [ThreatTypeName] NVARCHAR(300) NOT NULL,
        [ThreatCategoryID] INT NULL,
        [IsActive] BIT NOT NULL,
        [IsDeleted] BIT NOT NULL,
        [Source] NVARCHAR(50) NULL,
        [CreatedAt] DATETIME2(7) NULL,
        [CreatedBy] NVARCHAR(200) NULL,
        [UpdatedAt] DATETIME2(7) NULL,
        [UpdatedBy] NVARCHAR(200) NULL,
        CONSTRAINT [PK_Threat_Type] PRIMARY KEY CLUSTERED ([ThreatTypeID])
    );
    PRINT ' [CREATED] Table: Threat_Type (10 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Threat_Type';
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Threat_Type', @column = N'ThreatTypeID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Type', @column = N'ThreatTypeName',
     @expected = N'NVARCHAR(300)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Type', @column = N'ThreatCategoryID',
     @expected = N'INT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Type', @column = N'IsActive',
     @expected = N'BIT', @nullable = 0, @fill = N'1';
EXEC dbo.tsg_reconcile_column @table = N'Threat_Type', @column = N'IsDeleted',
     @expected = N'BIT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Threat_Type', @column = N'Source',
     @expected = N'NVARCHAR(50)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Type', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Type', @column = N'CreatedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Type', @column = N'UpdatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Type', @column = N'UpdatedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Threat_Type', @columns = N'ThreatTypeID';
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Threat_Type', @known = N'ThreatTypeID,ThreatTypeName,ThreatCategoryID,IsActive,IsDeleted,Source,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy';
GO
