/*==============================================================================
  UNIQUE CONSTRAINTS

  Script:      003_unique_constraints.sql
  Order:       02_constraints / 003
  Purpose:     1 unique constraint(s) the CREATE TABLE step omits.
  Depends on:  01_tables/ *
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    unique constraints

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- unique constraints ---';
GO

/* UQ_Config_Tuning_Key - Config_Tuning (TuningKey).
   Declared unique=True in app/db/models.py and as a table constraint in the reviewed DDL, but
   emitted by NEITHER table_script() (columns + PK only) nor index_blocks() (CREATE INDEX only),
   so the package used to skip it entirely. ALTER, not CREATE TABLE, so an existing database
   gains it too.
   Duplicates are reported instead of letting ALTER fail with a bare constraint error: the rows
   have to be reconciled by a human, and the message needs to say which ones. */
IF NOT EXISTS (SELECT 1 FROM sys.key_constraints
               WHERE name = 'UQ_Config_Tuning_Key'
                 AND parent_object_id = OBJECT_ID('dbo.Config_Tuning'))
BEGIN
    IF EXISTS (SELECT 1 FROM dbo.[Config_Tuning] GROUP BY [TuningKey] HAVING COUNT(*) > 1)
    BEGIN
        PRINT ' [BLOCKED] Config_Tuning.TuningKey has duplicate values, so';
        PRINT '          UQ_Config_Tuning_Key cannot be created. The rows below must be';
        PRINT '          reconciled first - keep one, retire the rest.';
        SELECT [TuningKey], COUNT(*) AS Copies
        FROM   dbo.[Config_Tuning] GROUP BY [TuningKey] HAVING COUNT(*) > 1;
    END
    ELSE
    BEGIN
        ALTER TABLE dbo.[Config_Tuning] ADD CONSTRAINT [UQ_Config_Tuning_Key] UNIQUE ([TuningKey]);
        PRINT ' [ADDED]   UQ_Config_Tuning_Key on Config_Tuning (TuningKey)';
    END
END
ELSE
    PRINT ' [EXISTS]  UQ_Config_Tuning_Key';
GO
