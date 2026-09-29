/*==============================================================================
  TABLE: Identified_Duplicate_Threat

  Script:      016_Identified_Duplicate_Threat.sql
  Order:       01_tables / 016
  Purpose:     Create Identified_Duplicate_Threat, or bring an existing copy up to 15 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Identified_Duplicate_Threat

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- Identified_Duplicate_Threat ---';
GO

IF OBJECT_ID('dbo.Identified_Duplicate_Threat', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Identified_Duplicate_Threat] (
        [DuplicateThreatID] UNIQUEIDENTIFIER NOT NULL,
        [SessionID] UNIQUEIDENTIFIER NOT NULL,
        [TenantID] NVARCHAR(200) NULL,
        [EntityID] NVARCHAR(200) NULL,
        [UserID] NVARCHAR(200) NULL,
        [SubsystemID] INT NOT NULL,
        [ThreatCategory] NVARCHAR(200) NOT NULL,
        [ThreatType] NVARCHAR(300) NOT NULL,
        [ThreatName] NVARCHAR(500) NULL,
        [GenericName] NVARCHAR(500) NULL,
        [ThreatActorsJSON] NVARCHAR(max) NULL,
        [DuplicateOfThreatID] UNIQUEIDENTIFIER NULL,
        [DuplicateReason] NVARCHAR(100) NOT NULL,
        [SimilarityScore] FLOAT NULL,
        [CreatedAt] DATETIME2(7) NULL,
        CONSTRAINT [PK_Identified_Duplicate_Threat] PRIMARY KEY CLUSTERED ([DuplicateThreatID])
    );
    PRINT ' [CREATED] Table: Identified_Duplicate_Threat (15 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Identified_Duplicate_Threat';
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'DuplicateThreatID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'SessionID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'TenantID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'EntityID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'UserID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'SubsystemID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'ThreatCategory',
     @expected = N'NVARCHAR(200)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'ThreatType',
     @expected = N'NVARCHAR(300)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'ThreatName',
     @expected = N'NVARCHAR(500)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'GenericName',
     @expected = N'NVARCHAR(500)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'ThreatActorsJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'DuplicateOfThreatID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'DuplicateReason',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'SimilarityScore',
     @expected = N'FLOAT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Identified_Duplicate_Threat', @columns = N'DuplicateThreatID';
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Identified_Duplicate_Threat', @known = N'DuplicateThreatID,SessionID,TenantID,EntityID,UserID,SubsystemID,ThreatCategory,ThreatType,ThreatName,GenericName,ThreatActorsJSON,DuplicateOfThreatID,DuplicateReason,SimilarityScore,CreatedAt';
GO
