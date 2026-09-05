============================================================================
TSG SCHEMA SCRIPT — RUNBOOK
tsg_remediation_tables.sql
============================================================================

WHAT THIS SCRIPT IS

One file that brings a TSG database to the current schema. It creates what is
missing, upgrades what is out of date, and reports anything it will not change
on its own.

It replaces the four schema scripts in the parent folder (0, 1, 2 and 4). It
does NOT replace the two seed scripts (3 and 5), which load reference data.

Safe to re-run. Every statement checks the live database first, so a second run
does nothing and a run that stops halfway can simply be run again.


WHAT IT CONTAINS

  Section 0   Snapshot isolation, and the two switches for the run
  Section 1   Legacy names: repairs, renames, and the five removed columns
  Section 2   Tables (22)
  Section 3   Columns (291), then three one-time data fixes
  Section 4   Default constraints (21)
  Section 5   Check constraints (3)
  Section 6   Indexes (29)
  Section 7   Verification


----------------------------------------------------------------------------
THE TWO SWITCHES — HOW TO FIND AND CHANGE THEM
----------------------------------------------------------------------------

THE FILE TO EDIT is the SQL script sitting in this same folder, next to this
readme:

    tsg_remediation_tables.sql

Full path from the repository root:

    tsg\scripts\eyshield_handoff\scripts\tsg_remediation_tables.sql

It is the ONLY file you edit. Never edit the numbered scripts in the folder
above this one.

HOW TO FIND THE LINE
  1. Open that file in SSMS, Notepad++, VS Code, or any editor.
  2. Press Ctrl+F.
  3. Search for:   EDIT THIS LINE
  4. There is exactly one match. It looks like this:

       INSERT INTO #opt (PreviewOnly, DropRemovedColumns) VALUES (0, 1);  -- <<< EDIT THIS LINE

  A large banner reading "CHANGE THESE TWO NUMBERS" sits just above it.

WHAT TO CHANGE
  Only the two digits inside the brackets. Nothing else on the line.

       VALUES ( A , B )
                A = PreviewOnly         1 = dry run, 0 = do the work
                B = DropRemovedColumns  1 = delete the five columns for good
                                        0 = keep them, only list them

  Save the file after each change.

THE FOUR COMBINATIONS
       VALUES (1, 0)   dry run, changes nothing            used in step 4
       VALUES (0, 0)   do the work, keep the five columns  used in step 5
       VALUES (0, 1)   do the work and delete them         used in step 8
       VALUES (1, 1)   dry run that also shows deletions   optional


----------------------------------------------------------------------------
THE STEPS
----------------------------------------------------------------------------
Every command below is one line. Replace <server> and <database> with your own.
Run them from this folder, so the relative filenames resolve.

Example values used in the samples:
  <server>    DCSAZ1SQLDBP01\INST01
  <database>  EYShieldDB_Copy

The -b flag makes sqlcmd exit non-zero on error. The -I flag turns on
QUOTED_IDENTIFIER, which the filtered indexes require. Do not omit either.


============================ STEP 1 — BACK UP ==============================

RUN
  sqlcmd -b -S <server> -d master -E -Q "BACKUP DATABASE [<database>] TO DISK='D:\Backup\<database>_preTSG.bak' WITH INIT, COMPRESSION, STATS=10;"

EXPECT
  "BACKUP DATABASE successfully processed ... pages"

STOP IF
  Any error. Do not continue without a backup. Step 6 cannot be undone.


======================= STEP 2 — STOP THE SERVICES =========================

DO
  Stop the TSG API and the Celery workers. Both, not just the API.

CHECK
  sqlcmd -b -S <server> -d <database> -E -Q "SELECT COUNT(*) AS OpenSessions FROM sys.dm_exec_sessions WHERE database_id = DB_ID() AND session_id <> @@SPID;"

EXPECT
  OpenSessions = 0, or only your own tools.

WHY
  This script renames tables and columns. The running application cannot see
  the renamed schema, and there is no rolling deploy.


========================== STEP 3 — PREFLIGHT ==============================

RUN
  sqlcmd -b -I -S <server> -d <database> -E -i "..\0. TSG_Preflight.sql" -o step3_preflight.txt

READ
  step3_preflight.txt, the Status column.

EXPECT
  Last line: "PREFLIGHT PASSED — safe to run the install scripts in order."

STOP IF
  Any row says FAIL. Send the file to whoever owns the change.

IGNORE
  "PARTIAL — some TSG tables present" is INFO, not a failure.
  Two tables may be absent and both are correct:
    Threat_Scenario_Output   the old name, gone once the rename has run
    Scenario_Library         a removed feature, nothing reads it


=========================== STEP 4 — DRY RUN ===============================

EDIT the switch line. Open tsg_remediation_tables.sql, press Ctrl+F, search
for  EDIT THIS LINE  and change the two digits to (1, 0):

  BEFORE   ... VALUES (0, 1);  -- <<< EDIT THIS LINE
  AFTER    ... VALUES (1, 0);  -- <<< EDIT THIS LINE

Save the file. The 1 means dry run. The 0 means do not delete anything.

RUN
  sqlcmd -b -I -S <server> -d <database> -E -i tsg_remediation_tables.sql -o step4_dryrun.txt

READ
  step4_dryrun.txt.

EXPECT
  Near the top: "Section 1: checking for legacy names...  [PREVIEW - nothing
  will be changed]"
  Then a list of lines beginning "would". That list is the plan for step 5.

STOP IF
  Any line begins "applied:", "renamed:", "repaired:" or "removed column".
  That means the edit above was not saved, and the run was NOT a dry run.

CONFIRM NOTHING CHANGED
  sqlcmd -b -S <server> -d <database> -E -Q "SELECT COUNT(*) AS Cols FROM sys.columns c JOIN sys.tables t ON t.object_id=c.object_id;"
  Note the number. It must be the same after step 5 minus any columns the
  dry run said it would add.


===================== STEP 5 — APPLY, NO DELETIONS =========================

EDIT the switch line again. Same search:  EDIT THIS LINE

  BEFORE   ... VALUES (1, 0);  -- <<< EDIT THIS LINE
  AFTER    ... VALUES (0, 0);  -- <<< EDIT THIS LINE

Save the file. Both zeros: do the work, delete nothing.

RUN
  sqlcmd -b -I -S <server> -d <database> -E -i tsg_remediation_tables.sql -o step5_apply.txt

READ
  step5_apply.txt.

EXPECT
  Lines beginning "renamed:", "repaired:", "applied:" that match what step 4
  said it would do.
  "DropRemovedColumns = 0: the five removed columns are left in place."
  Two result sets at the end. Both should be empty.

STOP IF
  sqlcmd returns a non-zero exit code, or the first result set has rows.
  Read the Detail column, fix the cause, then run this step again.


=========================== STEP 6 — VERIFY ================================

RUN
  sqlcmd -b -I -S <server> -d <database> -E -i "..\6. TSG_Verify.sql" -o step6_verify.txt

READ
  step6_verify.txt.

EXPECT
  PASS on: "All 13 boot-asserted indexes present, unique and correct"
  PASS on: the column, scenario-lifecycle and RCSI rows.

IGNORE THIS ONE FAILURE
  "Table missing: Scenario_Library" — that check is out of date. The table is
  deliberately not created and nothing reads it.

ALSO IGNORE, ONLY IF THE LIBRARIES ARE MEANT TO BE EMPTY
  Seed-data FAIL rows. If they are not meant to be empty, run
  "3. Seed_to_Threat_library.sql" and "5. Seed_to_Control_library.sql" now.

STOP IF
  Any index row fails. The application checks fourteen indexes at start-up and
  will not run if one is missing, on the wrong columns, or not unique.


==================== STEP 7 — RESTART AND SMOKE TEST =======================

DO
  1. Deploy the application build that matches this schema.
  2. Start the API, then the Celery workers.
  3. Confirm the API is up:       GET  /health   expect 200
  4. Confirm dependencies are up: GET  /ready    expect 200
  5. Create a session:            POST /v1/sessions              expect 202
  6. Poll it to review:           GET  /v1/sessions/{id}
  7. Read the results:            GET  /v1/sessions/{id}/results

  Steps 5 to 7 need all four headers, or they return 401:
      X-API-Key: <the client secret, not its hash>
      X-User-Id: <a user id>
      X-Entity-Id: <the entity that owns the asset>
      X-Tenant-Id: <the tenant id>

EXPECT
  Step 5 returns a session id. Step 6 reaches stage REVIEW.
  Step 7 returns scenarios, each with a non-empty controls list.

STOP IF
  The API will not start. Read its log: a failed start-up check names the
  exact index or column it wants.

  Every call returns 401. Outside local development the application needs at
  least one active row in API_Client whose KeyHash is the SHA-256 of the
  secret you are sending. Generate it outside SQL, never with HASHBYTES.

  Controls are empty on every scenario. That points at the control mapping,
  not the schema. Check that Control_Library has rows.


=================== STEP 8 — THE DELETIONS (LATER) =========================

Do this only after step 7 has passed, and only when you are ready to accept
that five columns are gone for good.

EDIT the switch line one last time. Same search:  EDIT THIS LINE

  BEFORE   ... VALUES (0, 0);  -- <<< EDIT THIS LINE
  AFTER    ... VALUES (0, 1);  -- <<< EDIT THIS LINE

Save the file. The second 1 is what deletes the six columns.

RUN
  sqlcmd -b -I -S <server> -d <database> -E -i tsg_remediation_tables.sql -o step8_drop.txt

EXPECT
  Six lines: "removed column <table>.<column> (no longer part of the product)."
      Threat_Category.SecurityObjective
      Threat_Type.Description
      Threat_Type.SectorID
      Threat_Catalogue.Description
      Threat_Catalogue.SectorID
      Identified_Threat.Description
  And one line in capitals telling you to re-run grounding calibration.

STOP IF
  Any "DROP FAILED" row appears in the first result set. It names the object
  that blocked the drop.


==================== STEP 9 — RE-RUN CALIBRATION ===========================

Required after step 8, and only after step 8.

RUN
  POST /v1/tsg/grounding/calibrate
  Header: X-Admin-Key: <the admin key>

EXPECT
  202 with a job id. Poll GET /v1/tsg/grounding/calibrate/status/{job_id}
  until it reports success. It takes 10 to 15 minutes.

WHY
  Removing Threat_Catalogue.Description changes threat matching from name and
  description to name alone. The stored accuracy threshold was measured against
  text that no longer exists, so it has to be measured again.

STOP IF
  It returns 409. Another calibration is already running; wait for it.


----------------------------------------------------------------------------
READING THE OUTPUT
----------------------------------------------------------------------------

The Messages pane shows each action as it happens. Two result sets follow.

FIRST RESULT SET — findings the script would not act on by itself.
An empty result set is a clean run.

  TWO COLUMNS FOR ONE VALUE
      An old and a new column both exist and the new one holds data. The
      script will not guess which is authoritative. Decide, then drop the
      other and rename by hand.

  TWO TABLES FOR ONE THING
      Same situation one level up, and both tables hold rows. Nothing was
      changed.

  DATATYPE DIFFERS
      Converting rewrites stored data, so the script reports instead.

  SHOULD BE NOT NULL
      The change fails if any row holds a null. Populate the column first,
      then alter it by hand.

  ADDED AS NULL, WANTS NOT NULL
      The column was added, but with no default there is nothing to backfill
      existing rows with. Populate it, then tighten it.

  CHANGE FAILED
      The real SQL Server message, plus the name of whatever object depends
      on the column. Drop that object, re-run, and Section 6 rebuilds it.

  UNEXPECTED COLUMN
      Present in the database, unknown to the application. Never dropped.

SECOND RESULT SET — anything still missing after the run: tables, indexes,
columns, or snapshot isolation. An empty result set means the schema is
complete.

ONE WARNING IS EXPECTED AND HARMLESS:
  "The maximum key length for a nonclustered index is 1700 bytes. The index
   'UX_GroundingCalibration_Running' has maximum length of 2000 bytes."
  Its two key columns are model names. An insert would only fail if two names
  together exceeded about 850 characters; real ones run 30 to 60. The index is
  created and works.


----------------------------------------------------------------------------
WHAT THIS SCRIPT DOES NOT DO
----------------------------------------------------------------------------

  * No seed data. If the threat or control libraries are empty, run
    "3. Seed_to_Threat_library.sql" and "5. Seed_to_Control_library.sql".

  * No API client row. Outside local development the application refuses to
    start without at least one active row in API_Client. The key hash must be
    generated outside SQL, never with HASHBYTES.

  * No column is ever narrowed, and no column holding data is ever dropped.


----------------------------------------------------------------------------
TWO THINGS THAT LOOK LIKE MISTAKES AND ARE NOT
----------------------------------------------------------------------------

1. THERE ARE NO FOREIGN KEYS, deliberately. Rows are retired rather than
   deleted, some columns point at a schema TSG does not own, and one column
   uses 0 and null as meaningful values rather than references. Integrity is
   enforced in the application. Please do not add foreign key constraints.

2. Config_Tuning uses CreateDate and UpdateDate where every other table uses
   CreatedAt and UpdatedAt. The application depends on this. Please do not
   rename them for consistency.


----------------------------------------------------------------------------
IF SOMETHING GOES WRONG
----------------------------------------------------------------------------

The script is additive and guarded, so the usual answer is to fix the cause
and run it again.

  Stopped partway
      Re-run it. Completed work is skipped.

  A rename failed
      Read the first result set. It names the object that blocked the change.

  Wrong outcome, and you need to go back
      Restore the backup taken before step 3. Renames could in principle be
      reversed by hand, but the step 6 deletions cannot.

  Application will not start after the run
      Run "6. TSG_Verify.sql" and read the index rows. The application checks
      fourteen indexes at start-up and refuses to run if any is missing, on
      the wrong columns, or not unique.
