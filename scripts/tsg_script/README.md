# TSG database deployment package

Creates the TSG schema on an empty database, **and** brings an existing database up to date —
using the same scripts, safely, as many times as you like.

Written against the application itself: `app/db/models.py` for tables and columns,
`app/db/invariants.py` for the indexes the app refuses to start without, and the reviewed
`tsg_remediation_tables.sql` for index and constraint DDL. Nothing here was invented.

---

## 1. What it covers

| Object | Count |
|---|---:|
| Tables TSG owns | 24 |
| Columns | 316 |
| Primary keys | 24 |
| Non-PK indexes | 33 |
| Default constraints | 22 |
| Check constraints | 3 |
| **Foreign keys** | **0 — deliberate, see section 6** |

**11 further tables are read but never created by TSG.** `ctm_scan_entity`, `ctm_scan_entity_bu`,
`ctm_scan_entity_supporting_system`, `onboarding_supporting_systems`, `onboarding_sectors`,
`onboarding_services`, `ctm_scan_category`, `option`, `option_value`, `user`,
`user_scope_assignment` belong to the platform team. This package **checks** them and reports what
is missing; it never creates or alters them.

---

## 2. Execution sequence

Run in this order. Each step is safe to re-run.

| Step | Script | Purpose | Depends on |
|---:|---|---|---|
| 1 | `00_validation/000_helpers.sql` | Install the two reconcile procedures | nothing |
| 2 | `00_validation/001_pre_deployment_validation.sql` | Read-only report: fresh or upgrade, data at risk | nothing |
| 3 | `00_validation/002_enable_isolation_level.sql` | Turn `READ_COMMITTED_SNAPSHOT` **on** — the application does not boot without it | nothing |
| 4 | `01_tables/001…024_*.sql` | Create or reconcile each table, in order | step 1 |
| 5 | `02_constraints/001_default_constraints.sql` | 22 default constraints | step 4 |
| 6 | `02_constraints/002_check_constraints.sql` | 3 check constraints | step 4 |
| 7 | `02_constraints/003_unique_constraints.sql` | 1 unique constraint — `UQ_Config_Tuning_Key` | step 4 |
| 8 | `03_indexes/001…018_*_indexes.sql` | 33 indexes | steps 4-7 |
| 9 | `99_validation/001_post_deployment_validation.sql` | Objects: tables, PKs, indexes, constraints, isolation | steps 4-8 |
| 10 | `99_validation/002_schema_verdict.sql` | **The final sign-off** — 316 columns, 33 index shapes, 22 defaults, 6 identity columns, collation | step 9 |
| 11 | *(separate)* seed the libraries | Threat and control master data | step 10 |

> **Step 3 has the only line in this package you are meant to edit.** By default
> (`@disconnect_others = 0`) it turns the setting on when the database is idle, and when it
> is not it changes nothing, lists who is connected and stops the run. Setting it to `1`
> makes the same script run `WITH ROLLBACK IMMEDIATE`, which rolls back every other
> session's in-flight work on this database — including the other applications that read the
> platform tables. Use `1` only in an agreed maintenance window, and put it back to `0`.

> **Step 9 is not the sign-off on its own.** Its five verdicts read objects, never a column, so a
> deployment that printed `[BLOCKED]` on a narrowing change — or added a `NOT NULL` column as
> `NULL` because the table already had rows — reaches the end of step 9 looking clean. It also
> matches indexes by **name and table only**, so one carrying the right name over the wrong
> columns, or with its `WHERE` filter dropped, passes there too. Step 10 checks both and prints
> `FINAL SIGN-OFF`.

**Step 11 is not in this package.** The schema is empty until the curated library data is loaded by
`scripts/eyshield_handoff/3. Seed_to_Threat_library.sql` and `5. Seed_to_Control_library.sql`.
A correct but empty database returns empty results forever, which looks like a bug and is not one.

### Deploy as ONE file — `TSG_Deploy_All.sql`

For UAT and Prod, where the deliverable is a single artefact on a change ticket rather than a
folder. It contains all 11 steps above, in order, in one ~230 KB file.

```bash
sqlcmd -b -S <server> -d <database> -i TSG_Deploy_All.sql
```

Or open it in SSMS and press **F5**. No SQLCMD Mode, no folder, nothing else to copy. Each embedded
script announces itself as `>>> [n/47] <path>`, so the log says where the run got to.

> **It stops at the first error, in SSMS too.** SSMS alone would run on past a failed batch, so
> a check follows every batch: on an error it prints `!!! DEPLOYMENT STOPPED` and turns execution
> off (`SET NOEXEC ON`). The real error is the red message just above those lines; the last
> `>>> [n/47]` line names the script. Fix it and run the whole file again — it is re-runnable.
> A clean run ends with `Objects: PASS` and then `FINAL SIGN-OFF`.

> **It is generated — never edit it.** Change the script it came from and re-run
> `python scripts/tsg_script/_generate.py`.
> `test_the_single_file_deployment_matches_the_package` fails the build if the two disagree, so
> the file handed to a DBA cannot quietly be a month behind the package.

### Run it script by script

```bash
sqlcmd -b -S <server> -d <database> -i 00_validation/000_helpers.sql
sqlcmd -b -S <server> -d <database> -i 00_validation/001_pre_deployment_validation.sql
sqlcmd -b -S <server> -d <database> -i 00_validation/002_enable_isolation_level.sql
# then every file in 01_tables, 02_constraints, 03_indexes, in name order
sqlcmd -b -S <server> -d <database> -i 99_validation/001_post_deployment_validation.sql
sqlcmd -b -S <server> -d <database> -i 99_validation/002_schema_verdict.sql
```

> **`-b` is not optional.** Without it `sqlcmd` prints an error and runs the next script
> anyway, so step 3 refusing to continue is ignored and the deployment carries on against a
> database the application cannot start on. `-b` makes it exit on the first error.

> **`SET QUOTED_IDENTIFIER ON` is required** and every script sets it. Several indexes are
> filtered, and SQL Server refuses to create a filtered index without it. SSMS defaults it on;
> `sqlcmd` defaults it **off**, which is why the scripts set it themselves.

---

## 3. Dependency map

There are no foreign keys, so nothing *forces* an order. This order is still the right one: a
reader meets a table before the tables that reference it by value, and the validation report reads
top to bottom.

```
Reference data     Threat_Category -> Threat_Type -> Threat_Catalogue -> Threat_Actor
                   + the two junction maps
                   Control_Standard -> Control_Library -> Control_Library_Standard_Map
                              |
Configuration      API_Client . Config_Tuning . Grounding_Calibration_Run
                              |
The run            Scenario_Session
                        -> Subsystem_Stage_State
                        -> Identified_Threat -> Identified_Duplicate_Threat
                        -> Scoped_Threat
                        -> Threat_Scenario -> Threat_Scenario_Control_Map
                        -> Risk_Treatment_Plan
                              |
Trails             Scenario_Audit . Prompt_Log . Diagnostic_Event . Application_Log
```

---

## 4. What each run prints

| Status | Meaning |
|---|---|
| `[CREATED]` | A table was created |
| `[EXISTS]` | Already correct — nothing done |
| `[ADDED]` | A missing column was added |
| `[UPDATED]` | A safe change was applied; the before and after are printed |
| `[INFO]` | Something you should know; no change made |
| `[WARNING]` | Applied, but a human still has work to do |
| `[BLOCKED]` | A change is needed but would risk data — **nothing was changed** |
| `[REBUILD]` | An index existed with the wrong shape and was recreated |
| `[RENAMED]` | An old table/column/constraint/index name was renamed to the current one; data kept |
| `[DROPPED]` | A legacy column whose data is all in its replacement was removed |
| `[ERROR]` | The statement failed; the real database error is printed, and `TSG_Deploy_All.sql` stops |
| `[PASS]` / `[FAIL]` | Validation verdicts |

A second run of the whole package prints `[EXISTS]` throughout and changes nothing.

---

## 5. How column changes are decided

The rule: **widen freely, narrow only after proving the data fits, never drop anything.**

| Situation | What happens |
|---|---|
| Column missing, table empty | Added exactly as the application expects |
| Column missing, table has rows, app wants NOT NULL | Added as **NULL**, with `[WARNING]` and the exact statement to run after backfilling |
| Type is wider than needed | `[UPDATED]` — safe |
| Type is narrower than needed | Counts the rows that would truncate. None → `[UPDATED]`. Any → `[BLOCKED]` with the count |
| Different type family | `[BLOCKED]` — conversion could fail or change values |
| NULL → NOT NULL | Counts NULLs. None → applied. Any → `[BLOCKED]` with the count |
| Column exists, app does not use it | `[INFO]` only. **Never dropped** — it may belong to another release |
| Old table/column names from before the rename release (`Threat_Scenario_Output`, `OutputID`, `ReplacesOutputID`, `TuningSnapshotJSON`, `IsAIGenerated`, and "Output" constraint/index names) | **`[RENAMED]` in place — data kept**, before anything is created. If both old and new columns exist, old values are copied across, and the old column is `[DROPPED]` only when every value is already in the new one; otherwise `[BLOCKED]` and kept |
| Column missing, table has rows, app wants NOT NULL **and has a default** | Added NOT NULL; existing rows get the application's own default (e.g. `ControlMapAttempts = 0`) |
| Column change blocked by a CHECK constraint or index (e.g. widening `Scenario_Session.SessionStatus`) | Those objects are dropped, the column changed, and they are recreated unchanged — **one transaction** |
| …and it is NOT NULL with no default | Made **NULL-able** (`[UPDATED]`, same type, no data changed) — the app never writes it, so every insert would fail. If it is part of an index: `[ERROR]` and the run stops |

Nothing destructive happens without a human deciding.

### Primary keys and indexes on an existing database

The `CREATE` sets the key and indexes only for a **new** table. An older copy can carry different
ones, so every run also compares them with the application:

| Situation | What happens |
|---|---|
| Primary key on different columns (e.g. an old `Threat_Scenario_Control_Map` keyed on `OutputID`) | Old key dropped and the correct one added **in one transaction** → `[UPDATED]` with was/now |
| Index with the wrong columns, uniqueness or filter (e.g. an old natural key that still includes `SectorID`) | Dropped and recreated **in one transaction** → `[REBUILD]` |
| The new key/index cannot be built (NULLs or duplicates in its columns) | Rolled back — **the old one stays** — `[ERROR]` with the database's reason, and the run stops |

The final sign-off (`002_schema_verdict.sql`) checks key columns too: `Keys: PASS/FAILED`.

---

## 6. Why there are no foreign keys

The schema has none, on purpose. Three reasons, all from the implementation:

1. **Rows are retired, not deleted.** `Superseded = 1` marks a row as history. A foreign key would
   keep pointing at it and block nothing useful.
2. **Some columns reference a schema TSG does not own.** A constraint cannot span that boundary.
3. **`Scenario_Audit.SubsystemID` uses `0` and `NULL` as meaningful values**, not as references.

Referential integrity is enforced in the application. **Please do not add FK constraints** — the
existing schema script says the same, and several would fail to create against real data.

The relationships still exist; they are simply not declared. Section 3 is the list.

---

## 7. Gap analysis

| Area | Result | Note |
|---|---|---|
| Tables | PASS | 22 owned tables, generated from `models.py` |
| Columns | PASS | 296 columns, types compiled by SQLAlchemy, not hand-typed |
| Datatypes | PASS | `INTEGER` normalised to `INT` so the check matches `sys.columns` |
| Primary keys | PASS | 22, key columns reconciled on every run and verified in the sign-off |
| Foreign keys | N/A | None by design — section 6 |
| Constraints | PASS | 22 defaults, 3 checks, 1 unique, all existence-guarded |
| Indexes | PASS | 32 (31 + `UQ_Config_Tuning_Key`), including all 15 the application needs to boot |
| API queries | PASS | Every table the ORM maps has a script; the ORM is what the API reads through |
| Dependencies | PASS | Reference data before the pipeline; no script needs a later one |
| Script sequence | PASS | Folder order is execution order |
| Idempotency | PASS | Every statement checks first; a second run reports `[EXISTS]` |
| Empty database | PASS | `CREATE TABLE` path, then constraints, then indexes |
| Existing database | PASS | `CREATE` skipped, columns reconciled one at a time |
| Error handling | PASS | The real `ERROR_NUMBER()` and `ERROR_MESSAGE()` are printed, never swallowed |
| Partial failure | PASS | Each column is independent; re-running continues from where it stopped |
| Data safety | PASS | Narrowing and NOT NULL are proven against the data first |
| End-to-end workflow | PASS | The save path (`Scenario_Session` → `Identified_Threat` → `Scoped_Threat` → `Threat_Scenario` → `Threat_Scenario_Control_Map` → `Risk_Treatment_Plan` → `Scenario_Audit`) has all seven tables, their columns and their indexes |

### Known limitations, stated rather than hidden

| Limitation | Why |
|---|---|
| No transaction wraps a whole table script | SQL Server cannot roll back a `GO`-separated batch as one unit. Each column is applied independently, so a failure stops that column, not the file. Re-running resumes |
| Seed data is not included | Master data is large and separately reviewed; see step 11 |
| Platform tables are not created | They belong to another team — section 1 |
| A missing IDENTITY cannot be repaired in place | SQL Server cannot `ALTER` a column into an identity — it needs a table rebuild. The `CREATE` path emits all 6 correctly and step 10 **fails** if one is absent, rather than implying a re-run can fix it |

---

## 8. Regenerating

The `.sql` files under `01_tables/`, `02_constraints/` and `03_indexes/` are **generated**. Do not
edit them by hand — the next regeneration overwrites your change.

```bash
python scripts/tsg_script/_generate.py
```

Change `app/db/models.py`, re-run that, and the package follows. `tests/test_tsg_script_package.py`
fails the build if the checked-in files no longer match the ORM, so they cannot drift quietly.

Hand-written and safe to edit: `00_validation/*`, `99_validation/*`, this README.

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Msg 1934` on an index | `QUOTED_IDENTIFIER` is off | Run the script as provided; it sets it |
| `[BLOCKED]` on a narrowing change | Real rows are too long | Shorten or archive them, re-run |
| `[WARNING]` about NOT NULL | The table already had rows | Backfill, then run the printed `ALTER` |
| `[ERROR]` mentioning an index | An index depends on the column | Drop the index, re-run the table script, re-run the index script |
| Post-validation `FAILED` on an index | An index script did not run | Re-run `03_indexes/`; the app will not start without all 15 |
| Application starts but returns nothing | Schema deployed, libraries empty | Run the seed scripts — step 11 |
