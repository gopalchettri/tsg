/*==============================================================================
  TABLE: Subsystem_Stage_State

  Script:      014_Subsystem_Stage_State.sql
  Order:       01_tables / 014
  Purpose:     Create Subsystem_Stage_State, or bring an existing copy up to 17 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Subsystem_Stage_State

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- Subsystem_Stage_State ---';
GO

IF OBJECT_ID('dbo.Subsystem_Stage_State', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Subsystem_Stage_State] (
        [StateID] UNIQUEIDENTIFIER NOT NULL,
        [SessionID] UNIQUEIDENTIFIER NOT NULL,
        [TenantID] NVARCHAR(200) NULL,
        [EntityID] NVARCHAR(200) NULL,
        [SubsystemID] INT NOT NULL,
        [Level] NVARCHAR(100) NOT NULL,
        [Status] NVARCHAR(100) NOT NULL,
        [GenerationEpoch] INT NOT NULL,
        [ActiveTaskID] UNIQUEIDENTIFIER NULL,
        [LeaseExpiresAt] DATETIME2(7) NULL,
        [HeartbeatAt] DATETIME2(7) NULL,
        [AttemptCount] INT NOT NULL,
        [ErrorMessage] NVARCHAR(max) NULL,
        [UpdatedAt] DATETIME2(7) NOT NULL,
        [CreatedAt] DATETIME2(7) NULL,
        [StartedAt] DATETIME2(7) NULL,
        [FinishedAt] DATETIME2(7) NULL,
        CONSTRAINT [PK_Subsystem_Stage_State] PRIMARY KEY CLUSTERED ([StateID])
    );
    PRINT ' [CREATED] Table: Subsystem_Stage_State (17 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Subsystem_Stage_State';
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'StateID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'SessionID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'TenantID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'EntityID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'SubsystemID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'Level',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'Status',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'GenerationEpoch',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'ActiveTaskID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'LeaseExpiresAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'HeartbeatAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'AttemptCount',
     @expected = N'INT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'ErrorMessage',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'UpdatedAt',
     @expected = N'DATETIME2(7)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'StartedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'FinishedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Subsystem_Stage_State', @columns = N'StateID';
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Subsystem_Stage_State', @known = N'StateID,SessionID,TenantID,EntityID,SubsystemID,Level,Status,GenerationEpoch,ActiveTaskID,LeaseExpiresAt,HeartbeatAt,AttemptCount,ErrorMessage,UpdatedAt,CreatedAt,StartedAt,FinishedAt';
GO
