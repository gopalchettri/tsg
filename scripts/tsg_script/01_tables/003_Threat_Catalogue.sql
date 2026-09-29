/*==============================================================================
  TABLE: Threat_Catalogue

  Script:      003_Threat_Catalogue.sql
  Order:       01_tables / 003
  Purpose:     Create Threat_Catalogue, or bring an existing copy up to 10 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Threat_Catalogue

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- Threat_Catalogue ---';
GO

IF OBJECT_ID('dbo.Threat_Catalogue', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Threat_Catalogue] (
        [ThreatCatalogueID] INT IDENTITY(1,1) NOT NULL,
        [ThreatTypeID] INT NOT NULL,
        [ThreatName] NVARCHAR(500) NOT NULL,
        [IsActive] BIT NOT NULL,
        [IsDeleted] BIT NOT NULL,
        [Source] NVARCHAR(100) NULL,
        [CreatedAt] DATETIME2(7) NULL,
        [CreatedBy] NVARCHAR(200) NULL,
        [UpdatedAt] DATETIME2(7) NULL,
        [UpdatedBy] NVARCHAR(200) NULL,
        CONSTRAINT [PK_Threat_Catalogue] PRIMARY KEY CLUSTERED ([ThreatCatalogueID])
    );
    PRINT ' [CREATED] Table: Threat_Catalogue (10 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Threat_Catalogue';
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Threat_Catalogue', @column = N'ThreatCatalogueID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Catalogue', @column = N'ThreatTypeID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Catalogue', @column = N'ThreatName',
     @expected = N'NVARCHAR(500)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Catalogue', @column = N'IsActive',
     @expected = N'BIT', @nullable = 0, @fill = N'1';
EXEC dbo.tsg_reconcile_column @table = N'Threat_Catalogue', @column = N'IsDeleted',
     @expected = N'BIT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Threat_Catalogue', @column = N'Source',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Catalogue', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Catalogue', @column = N'CreatedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Catalogue', @column = N'UpdatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Catalogue', @column = N'UpdatedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Threat_Catalogue', @columns = N'ThreatCatalogueID';
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Threat_Catalogue', @known = N'ThreatCatalogueID,ThreatTypeID,ThreatName,IsActive,IsDeleted,Source,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy';
GO
