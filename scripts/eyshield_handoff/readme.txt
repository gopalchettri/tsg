============================================================================
DBA RUNBOOK — hand this section to whoever runs the deployment
============================================================================

Run these SEVEN files, in this order, against the target database. The first
and last are READ-ONLY checks; the middle five do the work. All are idempotent
and safe to re-run.

  0. TSG_Preflight.sql            -- READ-ONLY. Run FIRST. Confirms the database and the
                                     platform tables are ready, and detects the one upgrade
                                     hazard the scripts cannot fix themselves. Send the result
                                     set back before continuing. Any FAIL row is a stop.
  1. TSG_Core.sql                 -- baseline tables (TSG's own session/pipeline tables)
  2. Threat_library.sql           -- threat-library master tables + extras (maps, rules, context config)
  3. Seed_to_Threat_library.sql   -- curated threat library data
  4. Control_library.sql          -- control library tables + Threat_Scenario_Control_Map (Step-4 control mapping)
  5. Seed_to_Control_library.sql  -- 30 standards, 1288 controls, 6105 control-standard links
  6. TSG_Verify.sql               -- READ-ONLY. Run LAST. Proves the install worked. Send the
                                     result set back. Do not sign off on a FAIL.

THREE THINGS TO KNOW BEFORE YOU START

  * MAINTENANCE WINDOW. TSG_Core.sql enables Read Committed Snapshot Isolation,
    which the application requires to start. If RCSI is not already on, the script
    runs ALTER DATABASE SET SINGLE_USER WITH ROLLBACK IMMEDIATE — this DISCONNECTS
    every other session and rolls back their in-flight work. TSG_Preflight.sql tells
    you in advance whether this will happen.

  * RUN WITH QUOTED_IDENTIFIER ON. Every script sets it itself, so this is normally
    automatic. But if your tooling forces it OFF and you see "Msg 1934", re-run with
    sqlcmd -I. Two failures look different: a schema script stops with an error, but a
    SEED script failing this way is SILENT — the application starts normally and then
    produces empty results forever. TSG_Verify.sql catches that case.

  * SOME TABLES ARE NOT OURS TO CREATE. TSG READS 11 pre-existing platform tables
    (ctm_scan_entity, onboarding_supporting_systems, option, option_value and others)
    and never creates or modifies them. None of these seven files contain any CREATE,
    ALTER, INSERT, UPDATE or DELETE against a platform table — they are strictly
    read-only towards the platform database. If TSG_Preflight.sql reports one missing,
    or missing a column, that is a conversation with the platform team — do not try to
    create them from these scripts.

NOT PART OF THE INSTALL — do not run:
  * TSG_Core_Drop.sql -- *** DESTRUCTIVE. NEVER RUN THIS AGAINST UAT OR PRODUCTION. ***
    A DEVELOPMENT-ONLY helper that DROPS the 13 tables script 1 creates, so a developer can
    recreate them clean. Every assessment, scenario, decision, audit record and API client is
    destroyed and cannot be recovered. It self-guards (nothing happens until a variable inside
    it is changed to 'YES'), but it should not be in this package at all — it is named here so
    that if a copy ever travels with these files, you know to delete it.
  * TSG_Migration_ScenarioLifecycle.sql -- a convenience extract of the scenario-lifecycle
    changes, for sites applying just that release without re-running the full script 1.
    Redundant here: script 1 already contains every statement in it. Harmless if run (guarded
    and idempotent), but unnecessary.
  * backfill_null_platform_fields_for_testing.sql -- developer fixture. Writes FABRICATED
    values into PLATFORM tables. It now refuses to run unless the database name looks like
    dev/test, but do not run it regardless.
  * backfill_rejection_kind.sql -- one-off repair for databases created before 2026-08-03.
    Not needed for a fresh install; it self-guards and reports if it is not applicable.

UPGRADING AN EXISTING TSG DATABASE (not a fresh install)

  Script 1 is additive and guarded, so the same seven files upgrade in place. One thing to
  know: the scenario-lifecycle release changed when a session ends. Generation now completes a
  session at its review barrier, and the accept path that used to close pre-release sessions no
  longer completes anything — so script 1 carries a one-time UPDATE that closes any session
  left at active+REVIEW. Without it those sessions never complete and hold their asset open
  permanently, blocking every new assessment for it. Script 6 checks this and FAILs if any
  remain, so run it and read the 'Scenario lifecycle' rows before signing off.

This package was generated fresh from the TSG repo's scripts/ folder on 2026-08-23.
Regenerate it from source rather than reusing an old copy — do not keep a standing
duplicate of these files anywhere else.
