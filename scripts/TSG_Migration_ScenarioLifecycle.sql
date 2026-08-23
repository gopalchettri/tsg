/* ===========================================================================================
   TSG — scenario-lifecycle release: copy-paste migration
   ===========================================================================================
   Paste this whole file into SSMS / Azure Data Studio against the TSG database and run it.

   scripts/TSG_Core.sql REMAINS CANONICAL and already contains every statement below. This file
   exists only so you do not have to run the full ~800-line schema script to apply one release.
   Running either, or both, in any order, is safe.

   Every statement is guarded and idempotent: re-running changes nothing.

   WHAT IT DOES
     1. Threat_Scenario_Output.RejectedAt / RejectedBy  — records who declined a scenario, and when
     2. CK_ScenarioOutput_DecisionExclusive             — a scenario cannot be accepted AND rejected
     3. Scenario_Audit.OutputID                         — which scenario a decision event is about
     4. IX_ScenarioAudit_Output                         — makes "this scenario's decision history"
                                                          a seek instead of a table scan
     5. One-time backfill of sessions stranded at REVIEW (see the note at step 5)

   ORDER: run this BEFORE deploying the new application code. The app asserts its indexes at
   startup and will refuse to boot against an un-migrated database — by design, so the failure
   lands at deploy time rather than at runtime.
   =========================================================================================== */

SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;
GO

/* -- 1. Per-scenario reject ---------------------------------------------------------------- */
IF OBJECT_ID('dbo.Threat_Scenario_Output', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario_Output', 'RejectedAt') IS NULL
    ALTER TABLE Threat_Scenario_Output ADD RejectedAt datetime2 NULL;
GO

IF OBJECT_ID('dbo.Threat_Scenario_Output', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario_Output', 'RejectedBy') IS NULL
    ALTER TABLE Threat_Scenario_Output ADD RejectedBy nvarchar(200) NULL;
GO

/* -- 2. Accept and reject are mutually exclusive -------------------------------------------
   Enforced in the DATABASE, not only in the service layer: accept and reject are independent
   routes reachable at any time after the session completes, so the one place both orderings
   must meet is the row itself. Existing rows all read as pending (RejectedAt NULL), so the
   constraint holds for them by construction.                                                 */
IF OBJECT_ID('dbo.Threat_Scenario_Output', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario_Output', 'RejectedAt') IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM sys.check_constraints
                    WHERE name = 'CK_ScenarioOutput_DecisionExclusive')
    ALTER TABLE Threat_Scenario_Output ADD CONSTRAINT CK_ScenarioOutput_DecisionExclusive
        CHECK (RejectedAt IS NULL OR Accepted = 0);
GO

/* -- 3. Per-scenario decision trail --------------------------------------------------------
   NULL on every session- or subsystem-scoped event; set on the scenario_accepted /
   scenario_rejected rows. A column rather than a DetailJSON key because "the decision history
   of this scenario" is the question a reviewer actually asks, and JSON cannot be indexed for it. */
IF OBJECT_ID('dbo.Scenario_Audit', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Audit', 'OutputID') IS NULL
    ALTER TABLE Scenario_Audit ADD OutputID uniqueidentifier NULL;
GO

/* -- 4. ...and the index that makes it a seek ----------------------------------------------
   Filtered, so it costs nothing for the session/subsystem rows that carry no OutputID — which
   is the overwhelming majority of the ledger.                                                */
IF NOT EXISTS (SELECT 1 FROM sys.indexes
               WHERE name = 'IX_ScenarioAudit_Output' AND object_id = OBJECT_ID('dbo.Scenario_Audit'))
    AND COL_LENGTH('dbo.Scenario_Audit', 'OutputID') IS NOT NULL
    EXEC('CREATE INDEX IX_ScenarioAudit_Output ON Scenario_Audit(OutputID, CreatedAt DESC) WHERE OutputID IS NOT NULL');
GO

/* -- 5. One-time backfill ------------------------------------------------------------------
   DEVELOPMENT / FRESH DATABASE: ignore this — it matches zero rows and is a no-op.

   UAT / PRODUCTION: it is not optional. Generation now COMPLETES a session when it reaches its
   review barrier, which is what releases the asset (UX_Session_ActiveAsset is filtered on
   SessionStatus='active'). Sessions created before this release are parked at REVIEW while still
   'active', and nothing will ever complete them: the only writer that used to do it was accept,
   which no longer completes anything. Left alone they hold their asset open forever and block
   every new session for that asset.

   Idempotent: the WHERE clause matches nothing on a second run.                              */
IF OBJECT_ID('dbo.Scenario_Session', 'U') IS NOT NULL
    UPDATE Scenario_Session
        SET SessionStatus = 'completed',
            CompletedAt   = COALESCE(CompletedAt, SYSUTCDATETIME()),
            UpdatedAt     = SYSUTCDATETIME()
    WHERE SessionStatus = 'active'
        AND CurrentStage = 'REVIEW';
GO

/* -- Verify -------------------------------------------------------------------------------- */
SELECT
    CASE WHEN COL_LENGTH('dbo.Threat_Scenario_Output', 'RejectedAt') IS NOT NULL
         THEN 'OK' ELSE 'MISSING' END AS RejectedAt,
    CASE WHEN COL_LENGTH('dbo.Threat_Scenario_Output', 'RejectedBy') IS NOT NULL
         THEN 'OK' ELSE 'MISSING' END AS RejectedBy,
    CASE WHEN EXISTS (SELECT 1 FROM sys.check_constraints
                      WHERE name = 'CK_ScenarioOutput_DecisionExclusive')
         THEN 'OK' ELSE 'MISSING' END AS DecisionExclusive,
    CASE WHEN COL_LENGTH('dbo.Scenario_Audit', 'OutputID') IS NOT NULL
         THEN 'OK' ELSE 'MISSING' END AS AuditOutputID,
    CASE WHEN EXISTS (SELECT 1 FROM sys.indexes
                      WHERE name = 'IX_ScenarioAudit_Output'
                        AND object_id = OBJECT_ID('dbo.Scenario_Audit'))
         THEN 'OK' ELSE 'MISSING' END AS AuditOutputIndex,
    (SELECT COUNT(*) FROM Scenario_Session
     WHERE SessionStatus = 'active' AND CurrentStage = 'REVIEW') AS StillStranded;
GO
/* All five columns must read OK, and StillStranded must be 0, before deploying the code. */
