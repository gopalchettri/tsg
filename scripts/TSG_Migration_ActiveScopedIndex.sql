/* ===========================================================================================
   TSG — one active scenario per scoped threat: copy-paste migration
   ===========================================================================================
   Paste this whole file into SSMS / Azure Data Studio against the TSG database and run it.

   scripts/eyshield_handoff/"1. TSG_Core.sql" REMAINS CANONICAL and already contains the statement
   below (as does TSG_Core_UAT.sql). This file exists only so you do not have to run the full schema
   script to apply one release to a database that is already up.

   Every statement is guarded and idempotent: re-running changes nothing.

   WHAT IT DOES
     Creates UX_Scenario_ActiveScoped: a filtered unique index on
     Threat_Scenario(SessionID, ScopedThreatID) WHERE Superseded = 0.

   WHY (the short version)
     The rule "a scoped threat has at most one active scenario" was enforced ONLY by a startup check
     (app/db/invariants.py, ACTIVE_UNIQUE). Nothing stopped a duplicate being written, so a bad row
     committed silently and the service refused to boot — API and every worker — at the next
     restart or deploy, far from the change that caused it. This index rejects the duplicate at the
     moment it is written, as an ordinary error on the request that caused it.

     A correct write never fires it: every scenario writer mints a fresh Scoped_Threat row alongside
     its scenario, and ScopedThreatID is that table's primary key.

   SAFETY CHECK
     If duplicates already exist the index cannot be built. This script then stops with a clear
     message instead of a cryptic index error. A deployment that boots today cannot have any: the
     startup check already refuses to boot on one.

   ORDER: run this BEFORE deploying the new application code. The app asserts its indexes at
   startup and will refuse to boot against an un-migrated database — by design, so the failure
   lands at deploy time rather than at runtime.
   =========================================================================================== */

SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;
GO

IF EXISTS (SELECT 1 FROM Threat_Scenario
           WHERE Superseded = 0
           GROUP BY SessionID, ScopedThreatID
           HAVING COUNT(*) > 1)
BEGIN
    ;THROW 50001, 'Cannot create UX_Scenario_ActiveScoped: at least one (SessionID, ScopedThreatID) has more than one active Threat_Scenario row. Resolve the duplicates first - the application would also refuse to boot against this data.', 1;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Scenario_ActiveScoped' AND object_id = OBJECT_ID('dbo.Threat_Scenario'))
CREATE UNIQUE INDEX UX_Scenario_ActiveScoped ON Threat_Scenario(SessionID, ScopedThreatID) WHERE Superseded = 0;
GO

PRINT 'UX_Scenario_ActiveScoped present.';
GO
