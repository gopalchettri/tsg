/*==============================================================================
  TABLE: Threat_Catalogue_Category_Map

  Script:      005_Threat_Catalogue_Category_Map.sql
  Order:       01_tables / 005
  Purpose:     Create Threat_Catalogue_Category_Map, or bring an existing copy up to 3 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Threat_Catalogue_Category_Map

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- Threat_Catalogue_Category_Map ---';
GO

IF OBJECT_ID('dbo.Threat_Catalogue_Category_Map', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Threat_Catalogue_Category_Map] (
        [ThreatCategoryID] INT NOT NULL,
        [ThreatCatalogueID] INT NOT NULL,
        [CreatedAt] DATETIME2(7) NULL,
        CONSTRAINT [PK_Threat_Catalogue_Category_Map] PRIMARY KEY CLUSTERED ([ThreatCategoryID], [ThreatCatalogueID])
    );
    PRINT ' [CREATED] Table: Threat_Catalogue_Category_Map (3 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Threat_Catalogue_Category_Map';
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Threat_Catalogue_Category_Map', @column = N'ThreatCategoryID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Catalogue_Category_Map', @column = N'ThreatCatalogueID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Catalogue_Category_Map', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Threat_Catalogue_Category_Map', @columns = N'ThreatCategoryID,ThreatCatalogueID';
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Threat_Catalogue_Category_Map', @known = N'ThreatCategoryID,ThreatCatalogueID,CreatedAt';
GO
