/*==============================================================================
  TABLE: Scoped_Threat

  Script:      017_Scoped_Threat.sql
  Order:       01_tables / 017
  Purpose:     Create Scoped_Threat, or bring an existing copy up to 13 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Scoped_Threat

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- Scoped_Threat ---';
GO

IF OBJECT_ID('dbo.Scoped_Threat', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Scoped_Threat] (
        [ScopedThreatID] UNIQUEIDENTIFIER NOT NULL,
        [SessionID] UNIQUEIDENTIFIER NOT NULL,
        [SubsystemID] INT NOT NULL,
        [ThreatID] UNIQUEIDENTIFIER NOT NULL,
        [Score] FLOAT NOT NULL,
        [ScopeRank] INT NOT NULL,
        [Selected] INT NOT NULL,
        [Reason] NVARCHAR(500) NULL,
        [RejectionKind] NVARCHAR(100) NULL,
        [SelectionKind] NVARCHAR(100) NULL,
        [FactorsJSON] NVARCHAR(max) NULL,
        [Superseded] INT NOT NULL,
        [CreatedAt] DATETIME2(7) NULL,
        CONSTRAINT [PK_Scoped_Threat] PRIMARY KEY CLUSTERED ([ScopedThreatID])
    );
    PRINT ' [CREATED] Table: Scoped_Threat (13 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Scoped_Threat';
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'ScopedThreatID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'SessionID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'SubsystemID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'ThreatID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'Score',
     @expected = N'FLOAT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'ScopeRank',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'Selected',
     @expected = N'INT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'Reason',
     @expected = N'NVARCHAR(500)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'RejectionKind',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'SelectionKind',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'FactorsJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'Superseded',
     @expected = N'INT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Scoped_Threat', @columns = N'ScopedThreatID';
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Scoped_Threat', @known = N'ScopedThreatID,SessionID,SubsystemID,ThreatID,Score,ScopeRank,Selected,Reason,RejectionKind,SelectionKind,FactorsJSON,Superseded,CreatedAt';
GO
