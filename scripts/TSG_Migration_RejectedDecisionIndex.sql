/* ===========================================================================================
   TSG — rejected-decision index: copy-paste migration
   ===========================================================================================
   Paste this whole file into SSMS / Azure Data Studio against the TSG database and run it.

   scripts/eyshield_handoff/"1. TSG_Core.sql" REMAINS CANONICAL and should carry the same
   statement (as should TSG_Core_UAT.sql). This file exists only so you do not have to run the
   full schema script to apply one release to a database that is already up.

   Every statement is guarded and idempotent: re-running changes nothing.

   WHAT IT DOES
     Adds the filtered index IX_Scenario_RejectedDecision on Threat_Scenario(SessionID)
     WHERE RejectedAt IS NOT NULL.

   WHY (the short version)
     GET /v1/sessions/{session_id}/results now returns a REJECTED scenario even after a later
     regeneration superseded it, exactly as it already does for an ACCEPTED one. Both are human
     decisions on the record, and neither should disappear from the default view because somebody
     regenerated afterwards. Before this change a reviewer could not see what had already been
     turned down, which is the asymmetry being closed.

   WHY AN INDEX IS NOT OPTIONAL
     Threat_Scenario has NO unfiltered SessionID index — its primary key is the GUID id column,
     and every SessionID-leading index is filtered:

       UX_Scenario_ActiveIdentity     WHERE Superseded = 0
       IX_Scenario_SessionSubActive   WHERE Superseded = 0
       UX_Scenario_ActiveAccepted     WHERE Accepted = 1 AND IdentityHash IS NOT NULL

     /results issues one seek per filtered index rather than a single OR, precisely so each half
     stays index-eligible. The new reject-side seek has no index to land on until this migration
     runs, so it degrades into a full table scan on an endpoint clients POLL. Apply this BEFORE
     or WITH the application release; the feature is correct without it and merely slow, but
     "merely slow" on a polled endpoint is how a table scan reaches production unnoticed.

   COST
     A filtered index over the rejected rows only. Rejections are a small fraction of
     Threat_Scenario, so both the index and its maintenance overhead stay proportionally tiny —
     the same shape as UX_Scenario_ActiveAccepted, which filters the accepted rows.

   ROLLBACK
     DROP INDEX IX_Scenario_RejectedDecision ON dbo.Threat_Scenario;
     Safe at any time: dropping it changes no results, only the plan (back to a scan).
   =========================================================================================== */

SET NOCOUNT ON;
GO

IF NOT EXISTS (
        SELECT 1 FROM sys.indexes
        WHERE name = N'IX_Scenario_RejectedDecision'
          AND object_id = OBJECT_ID(N'dbo.Threat_Scenario'))
BEGIN
    CREATE NONCLUSTERED INDEX IX_Scenario_RejectedDecision
        ON dbo.Threat_Scenario (SessionID)
        WHERE RejectedAt IS NOT NULL;
    PRINT 'created IX_Scenario_RejectedDecision';
END
ELSE
    PRINT 'IX_Scenario_RejectedDecision already present — nothing to do';
GO

/* ---- verification: run this and confirm one row comes back ---- */
SELECT i.name                AS index_name,
       i.type_desc,
       i.has_filter,
       i.filter_definition
FROM sys.indexes i
WHERE i.object_id = OBJECT_ID(N'dbo.Threat_Scenario')
  AND i.name = N'IX_Scenario_RejectedDecision';
GO
