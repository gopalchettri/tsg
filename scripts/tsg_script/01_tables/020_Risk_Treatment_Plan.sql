/*==============================================================================
  TABLE: Risk_Treatment_Plan

  Script:      020_Risk_Treatment_Plan.sql
  Order:       01_tables / 020
  Purpose:     Create Risk_Treatment_Plan, or bring an existing copy up to 25 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Risk_Treatment_Plan

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- Risk_Treatment_Plan ---';
GO

IF OBJECT_ID('dbo.Risk_Treatment_Plan', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Risk_Treatment_Plan] (
        [PlanID] UNIQUEIDENTIFIER NOT NULL,
        [SessionID] UNIQUEIDENTIFIER NOT NULL,
        [ScenarioID] UNIQUEIDENTIFIER NOT NULL,
        [EntityID] NVARCHAR(200) NULL,
        [UserID] NVARCHAR(200) NULL,
        [TreatmentStrategy] NVARCHAR(100) NOT NULL,
        [Status] NVARCHAR(100) NOT NULL,
        [ActiveTaskID] NVARCHAR(100) NULL,
        [RiskIdentificationDate] DATETIME2(7) NULL,
        [InputSnapshotJSON] NVARCHAR(max) NULL,
        [PlanJSON] NVARCHAR(max) NULL,
        [ValidationJSON] NVARCHAR(max) NULL,
        [ErrorMessage] NVARCHAR(max) NULL,
        [Superseded] INT NOT NULL,
        [CreatedAt] DATETIME2(7) NULL,
        [UpdatedAt] DATETIME2(7) NULL,
        [CompletedAt] DATETIME2(7) NULL,
        [RiskLevel] NVARCHAR(100) NULL,
        [ReviewStatus] NVARCHAR(100) NULL,
        [ReviewComment] NVARCHAR(max) NULL,
        [ReviewedBy] NVARCHAR(200) NULL,
        [ReviewedAt] DATETIME2(7) NULL,
        [CancelledAt] DATETIME2(7) NULL,
        [CancelledBy] NVARCHAR(200) NULL,
        [ErrorReason] NVARCHAR(max) NULL,
        CONSTRAINT [PK_Risk_Treatment_Plan] PRIMARY KEY CLUSTERED ([PlanID])
    );
    PRINT ' [CREATED] Table: Risk_Treatment_Plan (25 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Risk_Treatment_Plan';
GO

/* Legacy column names: renamed in place so their data is kept. */
EXEC dbo.tsg_rename_column @table = N'Risk_Treatment_Plan', @old = N'OutputID', @new = N'ScenarioID';
GO

/* Constraint and index names from before the rename, brought to the current names so the
   constraint and index scripts find them instead of creating a second copy. */
IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_TreatmentPlan_ActiveOutput' AND object_id = OBJECT_ID('dbo.Risk_Treatment_Plan')) AND NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_TreatmentPlan_ActiveScenario' AND object_id = OBJECT_ID('dbo.Risk_Treatment_Plan'))
BEGIN
    EXEC sp_rename 'dbo.Risk_Treatment_Plan.UX_TreatmentPlan_ActiveOutput', 'UX_TreatmentPlan_ActiveScenario', 'INDEX';
    PRINT ' [RENAMED] UX_TreatmentPlan_ActiveOutput -> UX_TreatmentPlan_ActiveScenario';
END;
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'PlanID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'SessionID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'ScenarioID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'EntityID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'UserID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'TreatmentStrategy',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'Status',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'ActiveTaskID',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'RiskIdentificationDate',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'InputSnapshotJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'PlanJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'ValidationJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'ErrorMessage',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'Superseded',
     @expected = N'INT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'UpdatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'CompletedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'RiskLevel',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'ReviewStatus',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'ReviewComment',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'ReviewedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'ReviewedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'CancelledAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'CancelledBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'ErrorReason',
     @expected = N'NVARCHAR(max)', @nullable = 1;
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Risk_Treatment_Plan', @columns = N'PlanID';
GO

/* Legacy column OutputID, replaced by ScenarioID. Normally already RENAMED away above; it is still here
   only if ScenarioID existed too, in which case its values were copied across. Dropped only when
   EVERY value it holds is already in ScenarioID - nothing is lost. */
IF COL_LENGTH('dbo.Risk_Treatment_Plan', 'OutputID') IS NOT NULL
BEGIN
    DECLARE @n bigint;
    BEGIN TRY
        EXEC sp_executesql N'SELECT @n = COUNT_BIG(*) FROM dbo.[Risk_Treatment_Plan]
                             WHERE [OutputID] IS NOT NULL
                               AND ([ScenarioID] IS NULL OR [ScenarioID] <> [OutputID]);',
             N'@n bigint OUTPUT', @n = @n OUTPUT;
        IF @n > 0
        BEGIN
            PRINT ' [BLOCKED] Risk_Treatment_Plan.OutputID holds ' + CAST(@n AS varchar(20)) +
                  ' value(s) that differ from ScenarioID - NOT dropped.';
            PRINT '          Decide which value is right, update ScenarioID, then re-run.';
        END
        ELSE
        BEGIN
            /* Old indexes built on the column go with it, in the same transaction. */
            DECLARE @ix sysname, @ixs nvarchar(max) = N'', @drop nvarchar(max);
            BEGIN TRANSACTION;
            DECLARE legacy_ix CURSOR LOCAL STATIC READ_ONLY FOR
                SELECT i.name
                FROM   sys.indexes i
                WHERE  i.object_id = OBJECT_ID(N'dbo.Risk_Treatment_Plan') AND i.type IN (1, 2)
                  AND  i.is_primary_key = 0 AND i.is_unique_constraint = 0
                  AND  (EXISTS (SELECT 1 FROM sys.index_columns ic
                                WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id
                                  AND ic.column_id = COLUMNPROPERTY(i.object_id, N'OutputID', 'ColumnId'))
                        OR CHARINDEX(N'[OutputID]', ISNULL(i.filter_definition, N'')) > 0);
            OPEN legacy_ix; FETCH NEXT FROM legacy_ix INTO @ix;
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @drop = N'DROP INDEX ' + QUOTENAME(@ix) + N' ON dbo.[Risk_Treatment_Plan];';
                EXEC sp_executesql @drop;
                SET @ixs = @ixs + CASE WHEN @ixs = N'' THEN N'' ELSE N', ' END + @ix;
                FETCH NEXT FROM legacy_ix INTO @ix;
            END;
            CLOSE legacy_ix; DEALLOCATE legacy_ix;
            EXEC sp_executesql N'ALTER TABLE dbo.[Risk_Treatment_Plan] DROP COLUMN [OutputID];';
            COMMIT;
            PRINT ' [DROPPED] Risk_Treatment_Plan.OutputID - legacy column; all of its data is in ScenarioID.';
            IF @ixs <> N''
                PRINT '          Old index(es) on it dropped too: ' + @ixs +
                      ' (the current ones are created by 03_indexes).';
        END
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK;
        PRINT ' [ERROR]   Could not drop Risk_Treatment_Plan.OutputID.';
        PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
        EXEC sp_set_session_context N'tsg_deploy_failed', 1;
        RAISERROR('Legacy column Risk_Treatment_Plan.OutputID could not be dropped - deployment stopped.', 16, 1);
    END CATCH
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Risk_Treatment_Plan', @known = N'PlanID,SessionID,ScenarioID,EntityID,UserID,TreatmentStrategy,Status,ActiveTaskID,RiskIdentificationDate,InputSnapshotJSON,PlanJSON,ValidationJSON,ErrorMessage,Superseded,CreatedAt,UpdatedAt,CompletedAt,RiskLevel,ReviewStatus,ReviewComment,ReviewedBy,ReviewedAt,CancelledAt,CancelledBy,ErrorReason';
GO
