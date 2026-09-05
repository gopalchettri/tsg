/* ===========================================================================================
   TSG - drop Identified_Threat.Description: copy-paste migration
   ===========================================================================================
   Paste this whole file into SSMS / Azure Data Studio against the TSG database and run it.

   scripts/eyshield_handoff/"1. TSG_Core.sql" REMAINS CANONICAL and already contains the
   statement below (as does TSG_Core_UAT.sql). This file exists only so you do not have to run
   the full schema script to apply one release to a database that is already up.

   The statement is guarded and idempotent: re-running changes nothing.

   *** THIS ONE IS DESTRUCTIVE AND IRREVERSIBLE ***
   DROP COLUMN deletes the stored AI description on EVERY existing Identified_Threat row. There
   is no undo short of a database restore. If you want that text kept, take a copy first:

       SELECT ThreatID, SessionID, Description
       INTO   dbo.Identified_Threat_Description_Backup_20260905
       FROM   dbo.Identified_Threat
       WHERE  Description IS NOT NULL;

   WHAT IT DOES
     Drops Identified_Threat.Description. This is the LAST of the three threat descriptions:
     Threat_Type.Description and Threat_Catalogue.Description were dropped on 2026-08-30.

   WHY IT IS SAFE TO DROP (as opposed to safe to lose - see the warning above)
     Nothing consumed it. Promotion stopped copying it the moment Threat_Catalogue.Description
     was removed, which left the /results payload as its only reader. The DDL comment claiming it
     fed crm_threat_risk_register.threat_scenario was already stale - promote.py never read this
     column. The model is no longer asked to produce one either (app/pipeline/prompts.py).

   API IMPACT - THIS IS A BREAKING CHANGE
     `threat.description` disappears from GET /sessions/{id}/results and every other response
     built from _threat_block. A typed client with a required `description` will fail to parse.
     Unlike the per-step timings release, this one is NOT additive.

   ORDER: deploy the new application code FIRST, then run this. The app no longer selects the
   column, so it is happy either way; running this against OLD code would break /results, which
   still selects it.
   =========================================================================================== */

SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;
GO

IF COL_LENGTH('dbo.Identified_Threat', 'Description') IS NOT NULL
    ALTER TABLE Identified_Threat DROP COLUMN Description;
GO

PRINT 'Identified_Threat.Description dropped (or already absent).';
PRINT 'threat.description is gone from /results and from the Stage-1 prompt.';
PRINT 'Threat_Type.Description and Threat_Catalogue.Description were already dropped 2026-08-30.';
GO
