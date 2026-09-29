/*==============================================================================
  CHECK CONSTRAINTS

  Script:      002_check_constraints.sql
  Order:       02_constraints / 002
  Purpose:     3 check constraints.
  Depends on:  01_tables/ *
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    check constraints

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- check constraints ---';
GO

/*==============================================================================
  SECTION 5 — Check constraints
==============================================================================*/
IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_Config_Tuning_ValueType')
    ALTER TABLE [dbo].[Config_Tuning] WITH CHECK ADD CONSTRAINT [CK_Config_Tuning_ValueType]
        CHECK (([ValueType] = 'int' OR [ValueType] = 'float'));
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_Session_Status')
    ALTER TABLE [dbo].[Scenario_Session] WITH CHECK ADD CONSTRAINT [CK_Session_Status]
        CHECK (([SessionStatus] = 'cancelled' OR [SessionStatus] = 'completed' OR [SessionStatus] = 'active'));
GO

/* A scenario cannot be accepted and rejected at once. Accept and reject are
   separate routes reachable in either order, so the row is the only place both
   orderings meet. */
IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_Scenario_DecisionExclusive')
    ALTER TABLE [dbo].[Threat_Scenario] WITH CHECK ADD CONSTRAINT [CK_Scenario_DecisionExclusive]
        CHECK (([RejectedAt] IS NULL OR [Accepted] = (0)));
GO
