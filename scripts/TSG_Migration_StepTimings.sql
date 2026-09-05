/* ===========================================================================================
   TSG — per-step timings: copy-paste migration
   ===========================================================================================
   Paste this whole file into SSMS / Azure Data Studio against the TSG database and run it.

   scripts/eyshield_handoff/"1. TSG_Core.sql" REMAINS CANONICAL and already contains every
   statement below (as does TSG_Core_UAT.sql). This file exists only so you do not have to run the
   full schema script to apply one release to a database that is already up.

   Every statement is guarded and idempotent: re-running changes nothing.

   WHAT IT DOES
     Adds five nullable columns so the API can report how long each step of a session took:
       Subsystem_Stage_State.StartedAt / .FinishedAt   -> threat identification, scenarios
       Threat_Scenario.GenStartedAt / .GenFinishedAt   -> each individual scenario
       Scenario_Session.ControlMapSeconds               -> control mapping

   WHY TIMESTAMPS AND NOT DURATIONS
     Durations are DERIVED (finish - start) and never stored. Storing a duration next to the
     timestamps that produced it creates two numbers that must agree, and eventually they don't.
     One clock, one source of truth, subtraction at read time.

     Subsystem_Stage_State needed real columns because nothing existing could stand in:
     UpdatedAt is overwritten by claim_stage, renew_lease, renew_lock_lease, release_lock AND
     finish_stage, and CreatedAt is stamped for every level at once when the session is created.

   THE ONE EXCEPTION
     ControlMapSeconds is a SUM, not a span. Control mapping resumes across several
     tsg.map_controls_sweep ticks 300s apart, so a StartedAt/FinishedAt pair would report mostly
     WAITING. It accumulates (+=) the seconds actually spent mapping, once per pass.

   BACKFILL: none, deliberately. Existing rows stay NULL and the API reports NULL rather than
   inventing a number. Threat_Scenario.CreatedAt records when a row was PERSISTED (sequentially,
   after the whole batch finished generating), so it cannot stand in for a generation start.

   ORDER: run this BEFORE deploying the new application code — the app selects these columns, and
   a missing one fails at runtime with "Invalid column name".
   =========================================================================================== */

SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;
GO

/* -- 1. Stage span: threat identification and scenario generation ------------------------------ */
IF OBJECT_ID('dbo.Subsystem_Stage_State', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Subsystem_Stage_State', 'StartedAt') IS NULL
    ALTER TABLE Subsystem_Stage_State ADD StartedAt datetime2 NULL;
GO

IF OBJECT_ID('dbo.Subsystem_Stage_State', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Subsystem_Stage_State', 'FinishedAt') IS NULL
    ALTER TABLE Subsystem_Stage_State ADD FinishedAt datetime2 NULL;
GO

/* -- 2. Per-scenario generation span ------------------------------------------------------------
   These OVERLAP across rows: generation fans out TSG_SCENARIO_GENERATION_CONCURRENCY (default 5)
   at a time, so several rows share a GenStartedAt. Never sum them for a stage total — use the
   SCENARIOS row of Subsystem_Stage_State for that. */
IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario', 'GenStartedAt') IS NULL
    ALTER TABLE Threat_Scenario ADD GenStartedAt datetime2 NULL;
GO

IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario', 'GenFinishedAt') IS NULL
    ALTER TABLE Threat_Scenario ADD GenFinishedAt datetime2 NULL;
GO

/* -- 3. Control-mapping working time ------------------------------------------------------------ */
IF OBJECT_ID('dbo.Scenario_Session', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Scenario_Session', 'ControlMapSeconds') IS NULL
    ALTER TABLE Scenario_Session ADD ControlMapSeconds float NULL;
GO

PRINT 'TSG per-step timings migration applied.';
PRINT 'GET /sessions/{id} now reports progress.timings for threats, scenarios and controls,';
PRINT 'and /results reports gen_started_at / gen_finished_at / gen_seconds per scenario.';
PRINT 'Sessions that ran before this migration report NULL - nothing is backfilled.';
GO
