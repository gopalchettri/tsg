/*==============================================================================
  TABLE: Control_Library

  Script:      008_Control_Library.sql
  Order:       01_tables / 008
  Purpose:     Create Control_Library, or bring an existing copy up to 14 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Control_Library

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- Control_Library ---';
GO

IF OBJECT_ID('dbo.Control_Library', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Control_Library] (
        [ControlLibraryID] INT IDENTITY(1,1) NOT NULL,
        [ControlCode] NVARCHAR(100) NOT NULL,
        [ITOT] NVARCHAR(100) NOT NULL,
        [Domain] NVARCHAR(200) NOT NULL,
        [ControlName] NVARCHAR(500) NOT NULL,
        [ControlDescription] NVARCHAR(max) NOT NULL,
        [SampleEvidence] NVARCHAR(max) NULL,
        [Source] NVARCHAR(100) NULL,
        [CreatedAt] DATETIME NULL,
        [CreatedBy] NVARCHAR(200) NULL,
        [UpdatedAt] DATETIME NULL,
        [UpdatedBy] NVARCHAR(200) NULL,
        [IsActive] BIT NOT NULL,
        [IsDeleted] BIT NOT NULL,
        CONSTRAINT [PK_Control_Library] PRIMARY KEY CLUSTERED ([ControlLibraryID])
    );
    PRINT ' [CREATED] Table: Control_Library (14 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Control_Library';
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'ControlLibraryID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'ControlCode',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'ITOT',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'Domain',
     @expected = N'NVARCHAR(200)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'ControlName',
     @expected = N'NVARCHAR(500)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'ControlDescription',
     @expected = N'NVARCHAR(max)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'SampleEvidence',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'Source',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'CreatedAt',
     @expected = N'DATETIME', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'CreatedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'UpdatedAt',
     @expected = N'DATETIME', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'UpdatedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'IsActive',
     @expected = N'BIT', @nullable = 0, @fill = N'1';
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'IsDeleted',
     @expected = N'BIT', @nullable = 0, @fill = N'0';
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Control_Library', @columns = N'ControlLibraryID';
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Control_Library', @known = N'ControlLibraryID,ControlCode,ITOT,Domain,ControlName,ControlDescription,SampleEvidence,Source,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy,IsActive,IsDeleted';
GO
