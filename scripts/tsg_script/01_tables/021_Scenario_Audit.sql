/*==============================================================================
  TABLE: Scenario_Audit

  Script:      021_Scenario_Audit.sql
  Order:       01_tables / 021
  Purpose:     Create Scenario_Audit, or bring an existing copy up to 16 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Scenario_Audit

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- Scenario_Audit ---';
GO

IF OBJECT_ID('dbo.Scenario_Audit', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Scenario_Audit] (
        [AuditID] UNIQUEIDENTIFIER NOT NULL,
        [SessionID] UNIQUEIDENTIFIER NOT NULL,
        [TenantID] NVARCHAR(200) NULL,
        [EntityID] NVARCHAR(200) NULL,
        [Stage] NVARCHAR(100) NULL,
        [SubsystemID] INT NULL,
        [EventType] NVARCHAR(100) NOT NULL,
        [ScenarioID] UNIQUEIDENTIFIER NULL,
        [PlanID] UNIQUEIDENTIFIER NULL,
        [Decision] NVARCHAR(100) NULL,
        [Granularity] NVARCHAR(100) NULL,
        [ThreatTypeRefID] INT NULL,
        [ActorUserID] NVARCHAR(200) NULL,
        [ActorType] NVARCHAR(100) NULL,
        [DetailJSON] NVARCHAR(max) NULL,
        [CreatedAt] DATETIME2(7) NOT NULL,
        CONSTRAINT [PK_Scenario_Audit] PRIMARY KEY CLUSTERED ([AuditID])
    );
    PRINT ' [CREATED] Table: Scenario_Audit (16 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Scenario_Audit';
GO

/* Legacy column names: renamed in place so their data is kept. */
EXEC dbo.tsg_rename_column @table = N'Scenario_Audit', @old = N'OutputID', @new = N'ScenarioID';
GO

/* Constraint and index names from before the rename, brought to the current names so the
   constraint and index scripts find them instead of creating a second copy. */
IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioAudit_Output' AND object_id = OBJECT_ID('dbo.Scenario_Audit')) AND NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioAudit_Scenario' AND object_id = OBJECT_ID('dbo.Scenario_Audit'))
BEGIN
    EXEC sp_rename 'dbo.Scenario_Audit.IX_ScenarioAudit_Output', 'IX_ScenarioAudit_Scenario', 'INDEX';
    PRINT ' [RENAMED] IX_ScenarioAudit_Output -> IX_ScenarioAudit_Scenario';
END;
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'AuditID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'SessionID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'TenantID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'EntityID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'Stage',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'SubsystemID',
     @expected = N'INT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'EventType',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'ScenarioID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'PlanID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'Decision',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'Granularity',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'ThreatTypeRefID',
     @expected = N'INT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'ActorUserID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'ActorType',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'DetailJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 0;
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Scenario_Audit', @columns = N'AuditID';
GO

/* Legacy column OutputID, replaced by ScenarioID. Normally already RENAMED away above; it is still here
   only if ScenarioID existed too, in which case its values were copied across. Dropped only when
   EVERY value it holds is already in ScenarioID - nothing is lost. */
IF COL_LENGTH('dbo.Scenario_Audit', 'OutputID') IS NOT NULL
BEGIN
    DECLARE @n bigint;
    BEGIN TRY
        EXEC sp_executesql N'SELECT @n = COUNT_BIG(*) FROM dbo.[Scenario_Audit]
                             WHERE [OutputID] IS NOT NULL
                               AND ([ScenarioID] IS NULL OR [ScenarioID] <> [OutputID]);',
             N'@n bigint OUTPUT', @n = @n OUTPUT;
        IF @n > 0
        BEGIN
            PRINT ' [BLOCKED] Scenario_Audit.OutputID holds ' + CAST(@n AS varchar(20)) +
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
                WHERE  i.object_id = OBJECT_ID(N'dbo.Scenario_Audit') AND i.type IN (1, 2)
                  AND  i.is_primary_key = 0 AND i.is_unique_constraint = 0
                  AND  (EXISTS (SELECT 1 FROM sys.index_columns ic
                                WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id
                                  AND ic.column_id = COLUMNPROPERTY(i.object_id, N'OutputID', 'ColumnId'))
                        OR CHARINDEX(N'[OutputID]', ISNULL(i.filter_definition, N'')) > 0);
            OPEN legacy_ix; FETCH NEXT FROM legacy_ix INTO @ix;
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @drop = N'DROP INDEX ' + QUOTENAME(@ix) + N' ON dbo.[Scenario_Audit];';
                EXEC sp_executesql @drop;
                SET @ixs = @ixs + CASE WHEN @ixs = N'' THEN N'' ELSE N', ' END + @ix;
                FETCH NEXT FROM legacy_ix INTO @ix;
            END;
            CLOSE legacy_ix; DEALLOCATE legacy_ix;
            EXEC sp_executesql N'ALTER TABLE dbo.[Scenario_Audit] DROP COLUMN [OutputID];';
            COMMIT;
            PRINT ' [DROPPED] Scenario_Audit.OutputID - legacy column; all of its data is in ScenarioID.';
            IF @ixs <> N''
                PRINT '          Old index(es) on it dropped too: ' + @ixs +
                      ' (the current ones are created by 03_indexes).';
        END
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK;
        PRINT ' [ERROR]   Could not drop Scenario_Audit.OutputID.';
        PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
        EXEC sp_set_session_context N'tsg_deploy_failed', 1;
        RAISERROR('Legacy column Scenario_Audit.OutputID could not be dropped - deployment stopped.', 16, 1);
    END CATCH
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Scenario_Audit', @known = N'AuditID,SessionID,TenantID,EntityID,Stage,SubsystemID,EventType,ScenarioID,PlanID,Decision,Granularity,ThreatTypeRefID,ActorUserID,ActorType,DetailJSON,CreatedAt';
GO
