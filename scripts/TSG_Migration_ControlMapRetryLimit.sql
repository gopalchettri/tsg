/* ===========================================================================================
   TSG — control-mapping attempt limit: copy-paste migration
   ===========================================================================================
   Paste this whole file into SSMS / Azure Data Studio against the TSG database and run it.

   scripts/eyshield_handoff/"1. TSG_Core.sql" REMAINS CANONICAL and already contains every
   statement below (as does TSG_Core_UAT.sql). This file exists only so you do not have to run the
   full schema script to apply one release to a database that is already up.

   Every statement is guarded and idempotent: re-running changes nothing.

   WHAT IT DOES
     Adds Threat_Scenario.ControlMapAttempts. Also drops Threat_Scenario.ControlMapLastAttemptAt
     if present (added by an earlier, superseded version of this fix — see below).

   WHY (the short version)
     Before this, a scenario whose control mapping failed for a STRUCTURAL reason (e.g. the
     control library has nothing for its category yet) retried forever, every sweep tick, with no
     limit and no signal to anyone — and because the sweep is ordered oldest-first with only 5
     slots per tick, enough permanently-stuck rows could starve genuinely fixable ones behind
     them. ControlMapAttempts backs a HARD CUTOFF (TSG_CONTROL_MAP_MAX_ATTEMPTS, by explicit owner
     instruction): once a row reaches that many attempts without a ControlsMappedAt stamp, it is
     permanently excluded from every future mapping pass and the failure is logged
     (controls.mapping_exhausted) — recovering it needs a regenerate, not an automatic retry.

   ControlMapLastAttemptAt was added by an earlier draft of this fix (a backoff lane that would
   have retried an exhausted row on a slow cadence instead of stopping for good). That design was
   superseded by the hard cutoff above, and confirmed unused — nothing reads it — so it is dropped
   here rather than left as dead weight.

   Existing rows get ControlMapAttempts=0 — a full fresh attempt budget, which is the correct,
   safe reading: there is no reliable historical attempt count to backfill, and inventing one
   would misstate rows that were genuinely never retried before this fix existed.

   ORDER: run this BEFORE deploying the new application code. The app asserts its indexes at
   startup and will refuse to boot against an un-migrated database — by design, so the failure
   lands at deploy time rather than at runtime.

   AFTER: set TSG_CONTROL_MAP_MAX_ATTEMPTS in .env if the default (5 attempts) doesn't fit this
   deployment's traffic.
   =========================================================================================== */

SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;
GO

/* -- 1. The attempt counter -------------------------------------------------------------------- */
IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario', 'ControlMapAttempts') IS NULL
    ALTER TABLE Threat_Scenario ADD ControlMapAttempts int NOT NULL
        CONSTRAINT DF_ThreatScenario_ControlMapAttempts DEFAULT 0;
GO

/* -- 2. Cleanup: drop the superseded backoff-lane clock, if this database ever got it ----------- */
IF COL_LENGTH('dbo.Threat_Scenario', 'ControlMapLastAttemptAt') IS NOT NULL
    ALTER TABLE Threat_Scenario DROP COLUMN ControlMapLastAttemptAt;
GO

PRINT 'TSG control-map attempt-limit migration applied.';
PRINT 'Every Threat_Scenario row now has a hard attempt limit (default 5) instead of retrying';
PRINT 'control mapping forever - once reached, it is permanently excluded and logged.';
GO
