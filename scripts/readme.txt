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
  1. TSG_Core.sql                 -- baseline tables (TSG's own session/pipeline tables)
  2. Threat_library.sql           -- threat-library master tables + extras (maps, rules, context config)
  3. Seed_to_Threat_library.sql   -- curated threat library data
  4. Control_library.sql          -- control library tables + Threat_Scenario_Control_Map (Step-4 control mapping)
  5. Seed_to_Control_library.sql  -- 30 standards, 1288 controls, 6105 control-standard links


WHEN YOU CHANGE THE SCHEMA: edit TSG_Core.sql and models.py together, in the same
change. THERE IS NO LONGER AN AUTOMATED GUARD FOR THIS. tests/test_schema_sync.py used
to fail when a column existed in models.py but not in the script; the tests/ directory
was removed, so nothing catches that drift now -- a column added to models.py and
missed in TSG_Core.sql will not surface until a production query fails at runtime with
"Invalid column name". Re-read both files side by side before committing.
(app/db/invariants.py still asserts the UNIQUE indexes at boot; that check is alive and
unrelated -- it does not look at columns.)

2026-07-25: Alembic was REMOVED. It was a second, parallel owner of the same schema, and on a
hand-scripted database it could only ever be wrong. These .sql scripts are the ONE source of
truth; there is no migration step. Re-running TSG_Core.sql IS the migration. (The app's
boot-time index check says exactly that if an index is missing.)

2026-07-27: Threat_Category / Threat_Type / Threat_Catalogue / Threat_Actor gained CreatedAt /
CreatedBy / UpdatedAt / UpdatedBy, and Threat_Actor gained Source. All nullable with no DEFAULT --
Seed_to_Threat_library.sql inserts with explicit column lists, so a NOT NULL column without a
default would break every one of its statements, and NULL reads honestly as "row predates the
audit columns". Existing rows are NOT backfilled. Created* is stamped by all three write paths
(import, promote-on-accept, and the CRUD API); Updated* only by the CRUD API -- a re-import
re-asserts rows rather than editing them, and provenance is first-writer.

2026-07-29: Threat_Scenario_Output gained ScenarioNumber (int NOT NULL DEFAULT 1) -- which of a
threat's coexisting scenarios this row is: 1 = the original, 2+ = alternate takes added by
"generate next set" when no brand-new threat could be found. (2026-08-05: the
max_scenarios_per_threat cap named here was REMOVED -- how many scenarios a threat accumulates is
now derived from its own plausible entry points, so the number varies per threat and per asset.
The column and the index below are unchanged.) UX_Scenario_ActiveIdentity was widened from
(SessionID, IdentityHash) to
(SessionID, IdentityHash, ScenarioNumber) so those alternates can coexist while a second row at
the SAME number still collides -- the double-click race guard is intact. TSG_Core.sql upgrades an
existing database in place: a guarded ALTER adds the column (DEFAULT 1 -- every pre-existing row
is, by definition, its threat's scenario #1) and the old two-column index is dropped and
recreated in the widened form.

2026-07-30: schema-audit fixes, all in the install scripts (no data migration needed if the
database is recreated).
  * Threat_Category: added UX_ThreatCategory_NaturalKey (filtered on IsActive/IsDeleted, same
    shape as the Type/Catalogue/Actor siblings). It was the ONLY CRUD-writable master without
    one, and the shared CRUD 409 fires purely on the IntegrityError such an index raises -- so a
    duplicate category NAME was silently accepted, after which grounding.find_category (lowest
    id wins) and the library importer disagreed about which id that name meant.
  * Threat_Category PK is a plain caller-supplied int, NOT IDENTITY. models.py now says
    autoincrement=False. Without it SQLAlchemy infers the lone int PK as autoincrement and the
    MSSQL dialect emits SET IDENTITY_INSERT before the insert, which SQL Server rejects (Msg
    8106) -- a guaranteed 500 on POST /threat-library/threat-categories, invisible to CI because
    SQLite has no IDENTITY_INSERT logic. tests/test_schema_sync.py now asserts model-inferred
    autoincrement matches an actual IDENTITY in the DDL.
  * Subsystem_Stage_State: IX_SubsystemStageState_SessionSubLevel promoted to UNIQUE and renamed
    UX_. (SessionID, SubsystemID, Level) is the row's real identity -- the StateID PK is never
    queried -- and the whole lock/epoch-CAS design asserts exactly-one-row with a Python
    rowcount == 1. Now boot-asserted in invariants.REQUIRED_INDEXES.
  * Threat_Catalogue_Category_Map: composite PK reordered to (ThreatCategoryID,
    ThreatCatalogueID) so grounding's filter on the category can seek the clustered index.
  * Config_Threat_Rule rows are now also gated on their PARENT Threat_Type being live
    (dal.active_threat_rules). No FKs exist, so soft-deleting a type previously left its scoping
    rules steering real generations.

2026-07-30: CreatedAt datetime2 added to Subsystem_Stage_State, ThreatType_ThreatActor_Map,
Threat_Catalogue_Category_Map, Context_Field_Config and Control_Library_Standard_Map -- the five
tables that had no creation stamp at all. Nullable WITH a DEFAULT SYSUTCDATETIME(): nullable so
the seeds' explicit column lists keep working, defaulted so seeded rows still get a real UTC
value rather than NULL. Every app write site stamps dal.now() explicitly, so the DB default only
ever fires for SQL-seeded rows. NOT added to Threat_Library_Import_Run (StartedAt already IS its
creation time) or Config_Threat_Rule (has CreateDate/UpdateDate -- the last holdout of the older
naming; renaming it is a separate decision, not a second column meaning the same thing).

2026-07-30: dal.guid() now mints SEQUENTIAL (COMB) GUIDs instead of uuid4. Nine tables have a
uniqueidentifier PRIMARY KEY, which SQL Server makes CLUSTERED by default, so a random key means
a page split per insert forever on append-heavy tables (Prompt_Log and Scenario_Audit take a row
per LLM call / pipeline event). The 48-bit ms timestamp goes in the LAST 6 bytes deliberately:
SQL Server does NOT order uniqueidentifier by byte order -- it compares bytes 10-15 first, then
8-9, 6-7, 4-5, 0-3 -- so a UUIDv7 (timestamp in the FIRST bytes) is sequential on PostgreSQL and
useless here. Still a valid RFC 9562 UUID (version 8, RFC variant); ~74 bits of randomness remain
per millisecond. Generated app-side rather than via NEWSEQUENTIALID() because the app needs ids
before the insert (it threads OutputID/ScopedThreatID between rows in one transaction).
tests/test_comb_guid.py pins the ordering, and includes a uuid4 baseline so the guard cannot go
vacuous.

2026-07-30: regeneration lineage. Threat_Scenario_Output gained ReplacesOutputID (see the entry
above); GET /results exposes it as replaced_output_ids plus an opt-in ?include_replaced=true that
returns the retired versions themselves. (The response SHAPE described here was superseded on
2026-07-31 -- see the last entry. The column and the tenant boundary below are unchanged.) TENANT BOUNDARY: the ancestry walk re-asserts SessionID.
ReplacesOutputID is unvalidated data in a multi-tenant table with no foreign keys, so following it
unscoped returned another entity's scenario text and its control mappings to a caller authorized
only for this session (reproduced, then fixed and pinned by
test_include_replaced_never_crosses_the_session_boundary).

2026-07-30: Control_Standard / Control_Library CreatedAt now DEFAULT SYSUTCDATETIME(), not
getdate(). getdate() is server LOCAL time while every app writer stamps dal.now() (UTC), so one
column held two clocks and rows were not comparable across a seed/CRUD boundary. Existing rows are
NOT rewritten -- a local-time row is indistinguishable from a UTC one after the fact, so treat
pre-migration Control_* timestamps as approximate. CreatedBy/UpdatedBy widened nvarchar(55) -> 200
to match every other identity column: they hold the JWT `sub`, which is unbounded, and at 55 a
long subject truncated silently on MSSQL. Both migrated in place by the guarded block at the end
of Control_library.sql.

2026-07-30: the UX_SubsystemStageState_SessionSubLevel swap CREATEs before it DROPs. A
CREATE UNIQUE legitimately fails on a database holding duplicate (SessionID, SubsystemID, Level)
rows; dropping first would leave the table with NEITHER index while the script still reported
success -- and invariants.py makes that index boot-blocking, so the API and every worker would
refuse to start. In this order a failed CREATE leaves the old index in place.

2026-07-30: tests/test_schema_sync.py gained two guards CI could not previously provide --
every model-inferred autoincrement column must have a real IDENTITY in the DDL (the SQLite
dialect cannot see SET IDENTITY_INSERT failures), and every name in
invariants.REQUIRED_INDEXES must have a CREATE UNIQUE INDEX in the install scripts (a
boot-blocking index with no creating script is a production-only failure).

2026-07-31: GET /results reshaped -- retired versions are now NESTED inside the scenario that
replaced them, in ScenarioResult.replaced_scenarios (newest first, and FLAT: v3 holds [v2, v1]
as siblings, whose own lists are always empty, so no consumer recurses). The top-level
replaced_scenarios array and the parallel replaced_output_ids id list are BOTH gone -- pairing an
old version to its current card no longer needs a client-side join. No schema change: same
ReplacesOutputID column, same walk, same tenant boundary.
  Two consequences worth knowing. (1) The default read path no longer walks ancestry AT ALL --
replaced_output_ids was the only thing that had to be populated unconditionally, so a polled
/results now costs zero ancestry queries however deep the history runs
(test_default_results_never_walks_ancestry_even_after_regeneration, which carries a negative
control so it cannot pass vacuously). (2) A card with no history is now indistinguishable from a
never-regenerated one on the default path; if a "version 3 of 3" badge is ever wanted there, add
a replaced_count int rather than reinstating the id list.
  The walk's cycle guard now seeds itself with the OWNER id, so a scenario can never appear in
its own history. Naming itself was survivable while this was an id list; nesting would have
embedded a full duplicate of the card inside itself
(test_results_survives_a_self_referential_replaces_pointer).

2026-07-31: the partial-accept 404 names WHICH subset ids failed and WHY. It used to report only
a count ("1 of 3 ... did not match"), which cost three hand-written SQL queries to diagnose on a
real call; the offender turned out to be a superseded id whose replacement was in the same
request. dal.unacceptable_subset_reasons classifies each id as superseded / failure_card /
subsystem_not_awaiting_decision / unknown, and NotFoundError gained an optional `details` dict
that _handle_not_found now emits (same shape as AcceptConflict.reason).
  Two properties to preserve. (1) It is a FAILURE-PATH read: the classifier runs only once the
counts already disagree, so a clean accept pays nothing -- pinned by
test_full_subset_accept_runs_no_diagnostic_query. (2) The query is scoped to SessionID, so an id
from another session classifies as `unknown`, NEVER "exists, wrong session" -- otherwise the
endpoint becomes an existence oracle for other tenants' OutputIDs
(test_partial_accept_404_does_not_confirm_another_sessions_row_exists).
  Deliberately NOT naming the replacement id for a superseded one: the immediate successor can
itself be superseded (v2 -> v3 -> v4), so it would sometimes hand back another dead id. The
message points at ?include_replaced=true instead, which nests the retired version inside its
current card and is always right. mark_scenarios_accepted's signature and return are unchanged.

2026-08-05: Scenario_Audit gained IX_ScenarioAudit_SessionSubEvent (SessionID, SubsystemID,
EventType, CreatedAt DESC). dal.latest_next_set_outcome reads the newest next_set_outcome row on
every status poll, and Scenario_Audit grows with every event in a session's life, so unindexed
that read was a scan whose cost climbed as the session was worked. Guarded IF NOT EXISTS, so
re-running TSG_Core.sql is the upgrade. Deliberately NOT added to invariants.REQUIRED_INDEXES:
that list is for UNIQUE indexes whose absence is a correctness bug, and a missing performance
index must never fail boot.
  Same date, no schema change but worth knowing when reading Threat_Scenario_Output rows:
ScenarioJSON now carries entry_point (label), entry_point_id (the supporting system's own id) and
plausible_entry_point_ids (that threat's coverage target, declared by its FIRST scenario and
inherited by every later one). They are additive JSON keys inside the existing nvarchar(max)
column -- no DDL, and rows written before this simply lack them, which every reader treats as
"no coverage signal". IX_ScenarioOutput_SessionSubActive is what serves the single
dal.active_scenario_rows read that folds those out.
