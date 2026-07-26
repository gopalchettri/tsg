1. once the database is created. run the following command-
ALTER DATABASE <database_name> SET READ_COMMITTED_SNAPSHOT ON;

(If you forget this step, the app will refuse to start and tell you to run it —
app/db/invariants.py checks RCSI is on every time the API or a Celery worker boots.)

2. that's it -- there is no migration step. This project is database-first: these
.sql scripts are the ONE source of truth for the schema.

TSG_Core.sql creates every baseline table (all CREATE TABLEs are guarded with
IF OBJECT_ID(...) IS NULL, so re-running it is safe). app/db/engine.py never calls
metadata.create_all() -- the app only ever reads a schema these scripts built.

Full install order (all idempotent, all required for a working environment):
  1. TSG_Core.sql                 -- baseline tables (incl. Threat_Scenario_Control_Map)
  2. Threat_library.sql           -- threat-library extras (maps, rules, context config)
  3. Seed_to_Threat_library.sql   -- curated threat library data
  4. Control_library.sql          -- control library tables (Step-4 control mapping)
  5. Seed_to_Control_library.sql  -- 30 standards, 1288 controls, 6105 control-standard links

Alembic was removed (2026-07-25). It was a second, parallel owner of the same
schema, and on a hand-scripted database it could only ever be wrong: the .sql
scripts build the tables but not alembic's own version-tracking table, so alembic
reported "nothing has ever been applied" against a complete schema and start.ps1
warned on every startup.

WHEN YOU CHANGE THE SCHEMA: edit TSG_Core.sql and models.py together, in the same
change. tests/test_schema_sync.py fails if a column exists in models.py but not in
the script -- that test is now the only guard against a production DB being born
missing a column the app selects, so do not skip it.

To apply a schema change to a database that already exists, write the ALTER by hand
and run it in SSMS. Nothing tracks which ALTERs a given database has received --
that is the tradeoff of dropping the migration tool.