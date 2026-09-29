"""Generate the TSG database deployment package from the application itself.

WHY A GENERATOR AND NOT 40 HAND-WRITTEN FILES. The package describes 22 tables and 296 columns.
Hand-copying that once is error-prone; keeping it correct after the next model change is worse —
and a deployment script that disagrees with the ORM is not a document that is slightly wrong, it
is a database that does not work. So the column facts come from `app/db/models.py` (the ORM the
application actually reads and writes through) and the index/constraint DDL comes from the
reviewed script the repository already ships. Nothing here is typed by hand twice.

Run it from the repository root:

    python scripts/tsg_script/_generate.py

It rewrites the .sql files under scripts/tsg_script/. It never touches a database.

SOURCES OF TRUTH
  app/db/models.py                                             tables, columns, types, nullability, PKs
  scripts/eyshield_handoff/scripts/tsg_remediation_tables.sql  indexes, defaults, check constraints
  app/db/invariants.py::REQUIRED_INDEXES                       indexes the app refuses to boot without

WHAT IT DELIBERATELY DOES NOT DO
  * No foreign keys. The schema has none on purpose: rows are retired with Superseded = 1 rather
    than deleted, some columns point at a schema TSG does not own, and Scenario_Audit.SubsystemID
    uses 0 and NULL as meaningful values. Adding FKs would break the running application.
  * No CREATE for the 11 platform tables. TSG reads them and must never create or alter them.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
SOURCE_SQL = ROOT / "scripts" / "eyshield_handoff" / "scripts" / "tsg_remediation_tables.sql"

sys.path.insert(0, str(ROOT))

# Read-only platform tables. TSG SELECTs from these; another team owns and creates them.
PLATFORM_TABLES = {
    "ctm_scan_category", "ctm_scan_entity", "ctm_scan_entity_bu",
    "ctm_scan_entity_supporting_system", "onboarding_sectors", "onboarding_services",
    "onboarding_supporting_systems", "option", "option_value", "user", "user_scope_assignment",
}

# Creation order. Reference data first, then the session pipeline, then what hangs off it. There
# are no foreign keys, so this order is for human readability and for the validation report - not
# a database requirement. It still matters: a reviewer reading the package top to bottom should
# meet a table before the tables that reference it by value.
TABLE_ORDER = [
    # reference / master data
    "Threat_Category", "Threat_Type", "Threat_Catalogue", "Threat_Actor",
    "Threat_Catalogue_Category_Map", "ThreatType_ThreatActor_Map",
    "Control_Standard", "Control_Library", "Control_Library_Standard_Map",
    # platform configuration
    "API_Client", "Config_Tuning", "Grounding_Calibration_Run",
    # the session pipeline, in the order a run fills them
    "Scenario_Session", "Subsystem_Stage_State", "Identified_Threat",
    "Identified_Duplicate_Threat", "Scoped_Threat", "Threat_Scenario",
    "Threat_Scenario_Control_Map", "Risk_Treatment_Plan",
    # trails
    "Scenario_Audit", "Prompt_Log",
]


# SQLAlchemy emits ANSI synonyms for a few types. SQL Server accepts them in DDL but reports the
# canonical name in sys.columns — so INTEGER would be compared against 'int' and every one of the
# 82 integer columns would be reported [BLOCKED] as a type-family change, on a database that is
# perfectly correct. Normalise here, at the single producer, rather than teaching the comparison
# about synonyms.
#: SQLAlchemy's MSSQL spelling -> what this schema actually uses, applied ONLY to columns the
#: reviewed script does not declare (everything else keeps its exact source spelling).
#:   INTEGER  -> INT        sys.columns reports 'int'; the ANSI synonym never matched.
#:   DATETIME -> DATETIME2  `DateTime()` carries no precision, and every datetime column added to
#:                          this schema since the handoff script is datetime2 in the deployed
#:                          database. Defaulting to DATETIME made the reconcile check report a
#:                          type-family change on four correct columns.
#:   NTEXT    -> NVARCHAR(MAX)  `Text()` compiles to the type Microsoft deprecated; the deployed
#:                          schema uses nvarchar(max), which is also what sys.columns reports.
_CANONICAL = {"INTEGER": "INT", "DATETIME": "DATETIME2", "NTEXT": "NVARCHAR(MAX)"}

#: {table: {column: "TYPE(...)"}} lifted from the reviewed CREATE TABLE blocks — see
#: source_column_types(). Filled once by load_metadata().
_SOURCE_TYPES: dict[str, dict[str, str]] = {}


def source_column_types() -> dict[str, dict[str, str]]:
    """The column types the REVIEWED script declares, which is what real databases were built
    from — the same sourcing rule the indexes and constraints already follow.

    WHY THE ORM IS NOT THE TRUTH HERE. SQLAlchemy's MSSQL dialect compiles `DateTime()` to
    `DATETIME` and `Text()` to `NTEXT`, but the deployed schema uses `datetime2(3)`, `datetime2(7)`
    and `nvarchar(max)`. `DateTime()` carries no precision at all, so the ORM CANNOT express the
    difference between the 84 datetime2 columns and the 8 genuine datetime ones.

    Emitting the ORM spelling made `tsg_reconcile_column` compare `DATETIME` against `datetime2`
    and `NTEXT` against `nvarchar`, hit its `@want_base <> @base` branch, and print
    `[BLOCKED] different type family` for 71 columns of a database the application runs against
    today — telling an operator to hand-convert a schema that was already correct. Same failure
    as the INTEGER/int mismatch fixed earlier, and the reason that one is no longer enough on its
    own.

    A column the reviewed script does not declare falls back to the ORM, so a NEW column added to
    models.py still generates before anyone edits the handoff script."""
    src = SOURCE_SQL.read_text(encoding="utf-8", errors="replace")
    out: dict[str, dict[str, str]] = {}
    for block in re.finditer(
            r"CREATE TABLE \[dbo\]\.\[(?P<table>\w+)\]\s*\((?P<body>.*?)\n\)", src, re.S):
        cols: dict[str, str] = {}
        for line in block.group("body").splitlines():
            mt = re.match(r"\s*\[(?P<col>\w+)\]\s+\[(?P<type>\w+)\]\s*(?P<args>\([^)]*\))?", line)
            if mt:
                cols[mt.group("col")] = (mt.group("type").upper()
                                         + (mt.group("args") or "").replace(" ", ""))
        if cols:
            out[block.group("table")] = cols
    return out


def tsql_type(col) -> str:
    """The column's SQL Server type: the reviewed script's own spelling when it declares the
    column, else SQLAlchemy's compiled one, normalised to the name sys.columns reports so the
    reconcile check compares like with like."""
    if not _SOURCE_TYPES:            # lazy, so no caller has to prime it first — table_script()
        _SOURCE_TYPES.update(source_column_types())   # and column_verdict_script() are called
    table = getattr(col.table, "name", None)          # directly by the drift tests
    declared = _SOURCE_TYPES.get(table, {}).get(col.name)
    if declared:
        return declared
    from sqlalchemy.dialects import mssql
    compiled = col.type.compile(dialect=mssql.dialect())
    base, sep, rest = compiled.partition("(")
    return _CANONICAL.get(base.strip().upper(), base.strip()) + sep + rest


def load_metadata():
    from app.db import models as m
    md = m.Base.metadata
    _SOURCE_TYPES.clear()
    _SOURCE_TYPES.update(source_column_types())
    if not _SOURCE_TYPES:
        raise SystemExit(
            "could not parse any CREATE TABLE block from the reviewed script - it may have been "
            "reformatted. Without it every datetime2/nvarchar(max) column would regress to the "
            "ORM's DATETIME/NTEXT spelling and the reconcile check would report [BLOCKED].")
    missing = [t for t in TABLE_ORDER if t not in md.tables]
    if missing:
        raise SystemExit(f"TABLE_ORDER names tables the ORM does not have: {missing}")
    unordered = (set(md.tables) - PLATFORM_TABLES) - set(TABLE_ORDER)
    if unordered:
        raise SystemExit(
            "the ORM has TSG-owned tables this generator does not order - add them to "
            f"TABLE_ORDER so they get a script: {sorted(unordered)}")
    return md


def index_blocks() -> dict[str, list[tuple[str, str]]]:
    """{table: [(index_name, guarded DDL block)]} lifted from the reviewed source script.

    Taken verbatim, including each block's own comment: those comments explain WHY an index
    exists (which query it serves, which race it arbitrates), and that reasoning cannot be
    reconstructed from a column list."""
    src = SOURCE_SQL.read_text(encoding="utf-8", errors="replace")
    out: dict[str, list[tuple[str, str]]] = {}
    pattern = re.compile(
        r"(?:(/\*(?:(?!\*/).)*?\*/)\s*)?"
        r"(IF NOT EXISTS \(SELECT 1 FROM sys\.indexes.*?"
        r"CREATE\s+(?:UNIQUE\s+)?(?:NONCLUSTERED\s+|CLUSTERED\s+)?INDEX\s+"
        r"\[(?P<name>\w+)\]\s+ON\s+\[dbo\]\.\[(?P<table>\w+)\].*?;)",
        re.S)
    for match in pattern.finditer(src):
        comment, block = match.group(1), match.group(2)
        text = (comment + "\n" if comment else "") + block
        out.setdefault(match.group("table"), []).append((match.group("name"), text))
    return out


def index_definitions() -> list[dict]:
    """Each index's NAME, TABLE, uniqueness, KEY COLUMNS and whether it is filtered, from the
    reviewed DDL.

    WHY THE COLUMNS MATTER. The post-deployment sign-off matched indexes on name + table alone,
    so an index carrying the right name over the WRONG columns — or with its filter predicate
    dropped — passed. Every one of these is a uniqueness guard the application leans on for a race
    it cannot otherwise win (one active session per asset, one accepted version per scenario, one
    running calibration). A filtered unique index whose WHERE clause went missing enforces
    something quite different from what the code assumes, and does it silently.
    """
    src = SOURCE_SQL.read_text(encoding="utf-8", errors="replace")
    out: list[dict] = []
    pattern = re.compile(
        r"CREATE\s+(?P<unique>UNIQUE\s+)?(?:NONCLUSTERED\s+|CLUSTERED\s+)?INDEX\s+"
        r"\[(?P<name>\w+)\]\s+ON\s+\[dbo\]\.\[(?P<table>\w+)\]\s*"
        r"\((?P<cols>[^)]*)\)"
        r"(?:\s*INCLUDE\s*\([^)]*\))?\s*(?:WHERE(?P<filter>[^;]*))?",
        re.S | re.I)
    for m in pattern.finditer(src):
        # Strip ASC/DESC: sys.index_columns reports direction separately and every index here is
        # ascending, so keeping it would make the comparison depend on optional DDL noise.
        cols = [re.sub(r"\s+(ASC|DESC)\s*$", "", c.strip(), flags=re.I).strip().strip("[]")
                for c in m.group("cols").split(",") if c.strip()]
        out.append({
            "name": m.group("name"),
            "table": m.group("table"),
            "unique": bool(m.group("unique")),
            "columns": cols,
            "filtered": bool(m.group("filter")),
        })
    return out


def _rebuild_if_wrong_shape(block: str, ix: dict) -> str:
    """Wrap one guarded CREATE so an index that EXISTS with the wrong shape is rebuilt.

    `IF NOT EXISTS ... CREATE` alone skips an index whose name matches, so a database carrying an
    older definition (e.g. a natural key that still includes a dropped SectorID) kept it forever
    and the sign-off refused every run. Shape = the checks the schema verdict makes: key columns
    in order, uniqueness, filtered or not.

    DROP and CREATE share one transaction: if the CREATE fails — a new unique key that existing
    duplicates violate — the DROP rolls back, the old index stays, and the run stops with the
    reason. Deliberately no STRING_AGG: the package supports SQL Server 2016."""
    name, table, cols = ix["name"], ix["table"], ix["columns"]
    where = ("i.object_id = ic.object_id AND i.index_id = ic.index_id "
             "AND c.object_id = ic.object_id AND c.column_id = ic.column_id")
    col_checks = "".join(
        f"\n          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE {where}"
        f" AND ic.key_ordinal = {k} AND c.name = N'{col}')"
        for k, col in enumerate(cols, start=1))
    wrong = (
        f"EXISTS (SELECT 1 FROM sys.indexes i\n"
        f"        WHERE i.name = N'{name}' AND i.object_id = OBJECT_ID(N'dbo.{table}')\n"
        f"          AND (i.is_unique <> {int(ix['unique'])} OR i.has_filter <> {int(ix['filtered'])}\n"
        f"          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id"
        f" AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> {len(cols)}"
        f"{col_checks}))"
    )
    expected = ", ".join(cols)
    return f"""BEGIN TRY
BEGIN TRANSACTION;
IF {wrong}
BEGIN
    PRINT ' [REBUILD] {table}.{name} exists with the wrong shape - recreating it on ({expected}).';
    DROP INDEX [{name}] ON [dbo].[{table}];
END;
{block}
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild {table}.{name} on ({expected}).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'{STOP_FLAG}', 1;
    RAISERROR('Index {name} could not be created - deployment stopped.', 16, 1);
END CATCH;"""


def unique_constraints(md) -> list[dict]:
    """Table-level UNIQUE constraints, from the reviewed DDL, cross-checked against the ORM.

    WHY THIS EXISTS. `table_script()` emits columns and the PRIMARY KEY and nothing else, and
    `index_blocks()` matches `CREATE ... INDEX`. A UNIQUE constraint declared INSIDE a CREATE
    TABLE is neither, so it fell through both and the package simply did not create it —
    `Config_Tuning.TuningKey`, which `models.py` declares `unique=True` and the reviewed DDL
    declares as `CONSTRAINT [UQ_Config_Tuning_Key]`. A database built from this package was
    therefore missing the rule that stops two ACTIVE rows sharing one tuning key, and
    `dal.active_tuning_overrides` reads those rows into a dict with NO `ORDER BY` — so the
    duplicate that wins is whichever the server happens to return last. Two rows saying
    `max_threats_per_asset` = 20 and = 5 would silently produce different runs.

    Emitted as an ALTER, not inside CREATE TABLE, so it repairs an EXISTING database too — a
    CREATE-only fix would help fresh deployments and leave every current one exposed.

    The ORM is the completeness check: a column marked `unique=True` with no constraint in the
    DDL is a hard failure here rather than a silent omission, which is exactly how this one hid.
    """
    src = SOURCE_SQL.read_text(encoding="utf-8", errors="replace")
    found: dict[tuple[str, str], dict] = {}
    for block in re.finditer(
            r"CREATE TABLE \[dbo\]\.\[(?P<table>\w+)\]\((?P<body>.*?)\n\) ON \[PRIMARY\]",
            src, re.S):
        for mt in re.finditer(
                r"CONSTRAINT \[(?P<name>\w+)\] UNIQUE(?: NONCLUSTERED| CLUSTERED)?\s*\((?P<cols>[^)]*)\)",
                block.group("body"), re.S):
            cols = [re.sub(r"\s+(ASC|DESC)\s*$", "", c.strip(), flags=re.I).strip().strip("[]")
                    for c in mt.group("cols").split(",") if c.strip()]
            for col in cols:
                found[(block.group("table"), col)] = {
                    "name": mt.group("name"), "table": block.group("table"), "columns": cols}

    declared = {(t, c.name) for t in TABLE_ORDER for c in md.tables[t].columns if c.unique}
    missing = sorted(declared - set(found))
    if missing:
        raise SystemExit(
            "models.py marks these columns unique=True but the reviewed DDL declares no UNIQUE "
            f"constraint for them, so the package would not create one: {missing}. Add the "
            "constraint to tsg_remediation_tables.sql, or drop unique=True from the model.")
    # De-duplicate: a multi-column constraint is registered once per column above.
    return sorted({c["name"]: c for c in found.values()}.values(), key=lambda c: c["name"])


def constraint_blocks(kind: str) -> list[str]:
    """Guarded DEFAULT or CHECK constraint statements, from the source script.

    DEFAULTS ARE RE-GUARDED ON THE COLUMN, NOT THE NAME. The source asks
    `WHERE name = 'DF_x'`, but SQL Server's rule is ONE DEFAULT PER COLUMN — so on a database
    where the column already carries an auto-named default (`DF__Identifie__IsAIG__7954A4F6`,
    which is what SQL Server generates when DDL omits the name), the guard finds no matching
    NAME, runs the ALTER anyway, and the batch dies with
    `Msg 1781: Column already has a DEFAULT bound to it`.

    Measured against the live database: 2 of the 21 defaults hit this
    (`Identified_Threat.IsThreatAIGenerated` and `.IsThreatTypeAIGenerated`), which made
    `001_default_constraints.sql` un-runnable there. Asking about the COLUMN is both correct and
    strictly safer: a column that already has a default keeps it, whatever it is called. Renaming
    someone else's constraint is not this script's job, and dropping one to re-add it under our
    name would be a destructive change for a cosmetic gain.
    """
    src = SOURCE_SQL.read_text(encoding="utf-8", errors="replace")
    prefix = {"default": "DF_", "check": "CK_"}[kind]
    # ONE STATEMENT PER BLOCK, and the guard's constraint name must carry the same prefix as the
    # ALTER. The previous `.*?` had neither constraint, so for kind="check" the match opened at
    # the FIRST `sys.default_constraints` guard and ran to the first `CK_` ADD — swallowing all
    # 21 default statements into the check file. That file then shipped a duplicate, un-rewritten
    # copy of every default and died on the live database with Msg 1781. `[^;]*?` cannot cross a
    # statement terminator, so a block can no longer span its neighbours.
    table = {"default": "default_constraints", "check": "check_constraints"}[kind]
    pattern = re.compile(
        r"(?:(/\*(?:(?!\*/).)*?\*/)\s*)?"
        r"(IF NOT EXISTS \(SELECT 1 FROM sys\." + table + r"\s+WHERE name = '" + prefix +
        r"\w+'\)\s*ALTER TABLE [^;]*?ADD\s+CONSTRAINT\s+\[?" + prefix + r"\w+\]?[^;]*?;)",
        re.S)
    out = []
    for m in pattern.finditer(src):
        block = ((m.group(1) + "\n") if m.group(1) else "") + m.group(2)
        if kind == "default":
            block = _guard_default_on_its_column(block)
        out.append(block)
    return out


#: The collation family the schema requires. CI = case-insensitive.
#: `UX_ThreatCatalogue_NaturalKey` and the other natural-key unique indexes are the database
#: half of the library's dedup guarantee. Under a case-SENSITIVE collation 'Ransomware' and
#: 'ransomware' are two different keys, so both insert, both are "verified", and the library
#: quietly grows duplicates that `normalize_name` in Python already considers the same row.
REQUIRED_COLLATION_FAMILY = "_CI_"


def identity_columns() -> dict[tuple[str, str], tuple[int, int]]:
    """{(table, column): (seed, increment)} for every IDENTITY column in the reviewed DDL.

    WHY THIS IS NOT COSMETIC. `table_script()` emitted the column type and nullability and
    nothing else, so a database built from this package had `Threat_Type.ThreatTypeID INT NOT
    NULL` with no identity. The application never supplies that id — `dal.upsert_threat_type`
    runs `insert(m.Threat_Type).values(...)` with no ThreatTypeID and reads the generated key
    back — so the very first attempt to mint a library row would fail with "Cannot insert the
    value NULL". A fresh deployment would pass every validation in this package and then break
    on first use.

    An EXISTING column cannot be given identity by ALTER; SQL Server requires a table rebuild.
    So the CREATE path emits it and the verdict REPORTS a missing one rather than pretending a
    re-run can repair it.
    """
    src = SOURCE_SQL.read_text(encoding="utf-8", errors="replace")
    out: dict[tuple[str, str], tuple[int, int]] = {}
    for block in re.finditer(
            r"CREATE TABLE \[dbo\]\.\[(?P<table>\w+)\]\((?P<body>.*?)\n\) ON \[PRIMARY\]",
            src, re.S):
        for mt in re.finditer(
                r"\[(?P<col>\w+)\] \[\w+\](?:\([^)]*\))? IDENTITY\((?P<seed>\d+),(?P<incr>\d+)\)",
                block.group("body")):
            out[(block.group("table"), mt.group("col"))] = (int(mt.group("seed")),
                                                            int(mt.group("incr")))
    return out


def default_definitions() -> list[dict]:
    """{name, table, column} for every DEFAULT the package creates.

    The sign-off verified tables, primary keys, indexes, check constraints, isolation and — since
    the column verdict — columns. It never verified a DEFAULT: 001 only PRINTS a count as [INFO]
    and 002 did not look at them at all, so a missing default passed with a clean FINAL SIGN-OFF.
    That is the same blind spot that hid the missing IX_PromptLog_Correlation and the missing
    UQ_Config_Tuning_Key, and it matters more here: a column that loses its default does not
    error, it silently stores whatever the insert omitted.
    """
    out = []
    for block in constraint_blocks("default"):
        mt = re.search(
            r"ALTER TABLE \[dbo\]\.\[(?P<table>\w+)\] ADD CONSTRAINT \[(?P<name>\w+)\] "
            r"DEFAULT .*? FOR \[(?P<col>\w+)\]", block, re.S)
        if mt:
            out.append({"name": mt.group("name"), "table": mt.group("table"),
                        "column": mt.group("col")})
    return out


def _guard_default_on_its_column(block: str) -> str:
    """Rewrite a default's `WHERE name = 'DF_x'` guard into a check on the target COLUMN."""
    target = re.search(
        r"ALTER TABLE \[dbo\]\.\[(?P<table>\w+)\] ADD CONSTRAINT \[(?P<name>\w+)\] "
        r"DEFAULT .*? FOR \[(?P<col>\w+)\]", block, re.S)
    if not target:
        return block
    guard = (
        "IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc\n"
        "               JOIN sys.columns c ON c.object_id = dc.parent_object_id\n"
        "                                 AND c.column_id = dc.parent_column_id\n"
        f"               WHERE dc.parent_object_id = OBJECT_ID('dbo.{target.group('table')}')\n"
        f"                 AND c.name = '{target.group('col')}')")
    return re.sub(r"IF NOT EXISTS \(SELECT 1 FROM sys\.default_constraints[^)]*\)",
                  lambda _: guard, block, count=1)


def header(**fields) -> str:
    """HEADER with every substituted value made safe to sit inside a block comment.

    T-SQL block comments NEST. `Depends on: 01_tables/*` therefore opened a SECOND comment that
    was never closed, and SQL Server rejected the whole first batch with
    `Msg 113: Missing end comment mark '*/'`. That batch is the one carrying
    `SET QUOTED_IDENTIFIER ON` — required for the filtered indexes — so the scripts were running
    WITHOUT their own safety settings.

    It went unnoticed because sqlcmd fails only that batch and carries on with the rest: the
    index still appeared, the output still looked plausible, and the error scrolled past above
    it. 20 of the package's scripts were affected (all 17 index files, all 3 constraint files).

    Sanitising here, at the single producer, rather than hand-editing each `depends` string,
    because the next person to write `foo/*` into a header should not be able to break 20 files.
    """
    safe = {k: str(v).replace("/*", "/ *").replace("*/", "* /") for k, v in fields.items()}
    return HEADER.format(**safe)


HEADER = """/*==============================================================================
  {title}

  Script:      {name}
  Order:       {order}
  Purpose:     {purpose}
  Depends on:  {depends}
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    {modifies}

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
"""


# LEGACY NAMES. A database that never ran the renames in eyshield_handoff/"1. TSG_Core.sql"
# (UAT) still carries the old names. Creating the new table / adding the new column beside them
# would strand every existing value under the old name, so these are RENAMED in place first - data
# kept - by the table script, before anything is created or reconciled. Lifted from that script;
# nothing here is guessed.
LEGACY_TABLE_RENAMES = {"Threat_Scenario": "Threat_Scenario_Output"}          # new: old
LEGACY_COLUMN_RENAMES = {                                                     # table: [(old, new)]
    "Scenario_Session": [("TuningJSON", "ScoringRulesSnapshotJSON"),
                         ("TuningSnapshotJSON", "ScoringRulesSnapshotJSON")],
    "Identified_Threat": [("IsAIGenerated", "IsThreatAIGenerated")],
    "Threat_Scenario": [("OutputID", "ScenarioID"), ("ReplacesOutputID", "ReplacesScenarioID")],
    "Threat_Scenario_Control_Map": [("OutputID", "ScenarioID")],
    "Risk_Treatment_Plan": [("OutputID", "ScenarioID")],
    "Scenario_Audit": [("OutputID", "ScenarioID")],
}
# Constraint and index names that still read "Output". Renamed so the constraint/index scripts find
# them under the current name instead of creating a second copy beside them. (table, old, new, type)
LEGACY_OBJECT_RENAMES = {
    "Threat_Scenario": [
        ("PK_Threat_Scenario_Output", "PK_Threat_Scenario", "OBJECT"),
        ("CK_ScenarioOutput_DecisionExclusive", "CK_Scenario_DecisionExclusive", "OBJECT"),
        ("DF_ScenarioOutput_ScenarioNumber", "DF_Scenario_ScenarioNumber", "OBJECT"),
        ("IX_ScenarioOutput_SessionSubActive", "IX_Scenario_SessionSubActive", "INDEX")],
    "Scenario_Audit": [("IX_ScenarioAudit_Output", "IX_ScenarioAudit_Scenario", "INDEX")],
    "Risk_Treatment_Plan": [("UX_TreatmentPlan_ActiveOutput", "UX_TreatmentPlan_ActiveScenario", "INDEX")],
}


def _legacy_table_rename(new: str, old: str) -> str:
    return f"""/* Legacy table name {old}. Renamed in place - data kept - BEFORE the CREATE below, which
   would otherwise build an empty {new} beside it. An empty {new} left by an earlier partial run is
   dropped first (it holds nothing); both holding rows is refused rather than guessed at. */
IF OBJECT_ID('dbo.{old}', 'U') IS NOT NULL
BEGIN
    DECLARE @old_rows bigint, @new_rows bigint = 0;
    BEGIN TRY
        EXEC sp_executesql N'SELECT @r = COUNT_BIG(*) FROM dbo.[{old}];', N'@r bigint OUTPUT', @r = @old_rows OUTPUT;
        IF OBJECT_ID('dbo.{new}', 'U') IS NOT NULL
            EXEC sp_executesql N'SELECT @r = COUNT_BIG(*) FROM dbo.[{new}];', N'@r bigint OUTPUT', @r = @new_rows OUTPUT;
        IF OBJECT_ID('dbo.{new}', 'U') IS NOT NULL AND @new_rows > 0 AND @old_rows > 0
        BEGIN
            PRINT ' [ERROR]   Both {old} (' + CAST(@old_rows AS varchar(20)) + ' rows) and {new} (' +
                  CAST(@new_rows AS varchar(20)) + ' rows) hold data. Merge them by hand, then re-run.';
            EXEC sp_set_session_context N'{STOP_FLAG}', 1;
            RAISERROR('Legacy table {old} and {new} both hold data - deployment stopped.', 16, 1);
        END
        ELSE IF OBJECT_ID('dbo.{new}', 'U') IS NOT NULL AND @new_rows > 0
            PRINT ' [INFO]    {old} is empty and {new} holds the data. {old} was left alone.';
        ELSE
        BEGIN
            BEGIN TRANSACTION;
            IF OBJECT_ID('dbo.{new}', 'U') IS NOT NULL
                EXEC sp_executesql N'DROP TABLE dbo.[{new}];';   -- empty: nothing is lost
            EXEC sp_rename 'dbo.{old}', '{new}', 'OBJECT';
            COMMIT;
            PRINT ' [RENAMED] Table {old} -> {new}  (' + CAST(@old_rows AS varchar(20)) + ' row(s), data kept)';
        END
    END TRY
    BEGIN CATCH
        DECLARE @e nvarchar(4000) = ERROR_MESSAGE();
        IF @@TRANCOUNT > 0 ROLLBACK;
        PRINT ' [ERROR]   Could not rename table {old} to {new}: ' + @e;
        EXEC sp_set_session_context N'{STOP_FLAG}', 1;
        RAISERROR('Legacy table {old} could not be renamed - deployment stopped.', 16, 1);
    END CATCH
END
GO

"""


def _legacy_object_renames(table: str) -> str:
    out = []
    for old, new, kind in LEGACY_OBJECT_RENAMES.get(table, []):
        if kind == "INDEX":
            exists = f"EXISTS (SELECT 1 FROM sys.indexes WHERE name = '{{0}}' AND object_id = OBJECT_ID('dbo.{table}'))"
            src = f"dbo.{table}.{old}"
        else:
            exists = "OBJECT_ID('dbo.{0}') IS NOT NULL"
            src = f"dbo.{old}"
        out.append(f"IF {exists.format(old)} AND NOT {exists.format(new)}\nBEGIN\n"
                   f"    EXEC sp_rename '{src}', '{new}', '{kind}';\n"
                   f"    PRINT ' [RENAMED] {old} -> {new}';\nEND;\n")
    if not out:
        return ""
    return ("/* Constraint and index names from before the rename, brought to the current names so the\n"
            "   constraint and index scripts find them instead of creating a second copy. */\n"
            + "".join(out) + "GO\n\n")


def _legacy_drop(table: str, column: str, replaced_by: str) -> str:
    # Dynamic SQL throughout: once the column is gone, a batch that names it fails to COMPILE, so
    # every re-run would error before the COL_LENGTH guard could skip it.
    return f"""/* Legacy column {column}, replaced by {replaced_by}. Normally already RENAMED away above; it is still here
   only if {replaced_by} existed too, in which case its values were copied across. Dropped only when
   EVERY value it holds is already in {replaced_by} - nothing is lost. */
IF COL_LENGTH('dbo.{table}', '{column}') IS NOT NULL
BEGIN
    DECLARE @n bigint;
    BEGIN TRY
        EXEC sp_executesql N'SELECT @n = COUNT_BIG(*) FROM dbo.[{table}]
                             WHERE [{column}] IS NOT NULL
                               AND ([{replaced_by}] IS NULL OR [{replaced_by}] <> [{column}]);',
             N'@n bigint OUTPUT', @n = @n OUTPUT;
        IF @n > 0
        BEGIN
            PRINT ' [BLOCKED] {table}.{column} holds ' + CAST(@n AS varchar(20)) +
                  ' value(s) that differ from {replaced_by} - NOT dropped.';
            PRINT '          Decide which value is right, update {replaced_by}, then re-run.';
        END
        ELSE
        BEGIN
            /* Old indexes built on the column go with it, in the same transaction. */
            DECLARE @ix sysname, @ixs nvarchar(max) = N'', @drop nvarchar(max);
            BEGIN TRANSACTION;
            DECLARE legacy_ix CURSOR LOCAL STATIC READ_ONLY FOR
                SELECT i.name
                FROM   sys.indexes i
                WHERE  i.object_id = OBJECT_ID(N'dbo.{table}') AND i.type IN (1, 2)
                  AND  i.is_primary_key = 0 AND i.is_unique_constraint = 0
                  AND  (EXISTS (SELECT 1 FROM sys.index_columns ic
                                WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id
                                  AND ic.column_id = COLUMNPROPERTY(i.object_id, N'{column}', 'ColumnId'))
                        OR CHARINDEX(N'[{column}]', ISNULL(i.filter_definition, N'')) > 0);
            OPEN legacy_ix; FETCH NEXT FROM legacy_ix INTO @ix;
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @drop = N'DROP INDEX ' + QUOTENAME(@ix) + N' ON dbo.[{table}];';
                EXEC sp_executesql @drop;
                SET @ixs = @ixs + CASE WHEN @ixs = N'' THEN N'' ELSE N', ' END + @ix;
                FETCH NEXT FROM legacy_ix INTO @ix;
            END;
            CLOSE legacy_ix; DEALLOCATE legacy_ix;
            EXEC sp_executesql N'ALTER TABLE dbo.[{table}] DROP COLUMN [{column}];';
            COMMIT;
            PRINT ' [DROPPED] {table}.{column} - legacy column; all of its data is in {replaced_by}.';
            IF @ixs <> N''
                PRINT '          Old index(es) on it dropped too: ' + @ixs +
                      ' (the current ones are created by 03_indexes).';
        END
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK;
        PRINT ' [ERROR]   Could not drop {table}.{column}.';
        PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
        EXEC sp_set_session_context N'{STOP_FLAG}', 1;
        RAISERROR('Legacy column {table}.{column} could not be dropped - deployment stopped.', 16, 1);
    END CATCH
END
GO

"""


def _fill_literal(c) -> str | None:
    """SQL literal of the value the application writes for a NEW row of a NOT NULL column (its
    scalar ORM default), or None. tsg_reconcile_column gives it to EXISTING rows when it has to add
    or tighten the column on a populated table - instead of leaving them NULL and failing sign-off
    (UAT: Threat_Scenario.ControlMapAttempts, default 0)."""
    if c.nullable or c.default is None or not c.default.is_scalar:
        return None
    v = c.default.arg
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, str):
        return "N'" + v.replace("'", "''") + "'"
    return None


def table_script(table, order: int) -> str:
    """Create the table, or reconcile an existing one column by column.

    The reconcile half is the point of this package. On an empty database the CREATE runs and
    nothing else does. On a database that already has the table, the CREATE is skipped and each
    column is checked: missing ones are added, and a type difference is reported rather than
    silently applied, because a narrowing change can truncate data."""
    cols = list(table.columns)
    pk = [c.name for c in table.primary_key.columns]

    # IDENTITY rides the CREATE, and only the CREATE: SQL Server cannot ALTER a column into an
    # identity, so an existing table keeps whatever it has and the verdict reports a mismatch.
    # Without this the app's first library insert fails — it never supplies these ids.
    idents = identity_columns()
    create_cols = ",\n".join(
        f"        [{c.name}] {tsql_type(c)}"
        + (f" IDENTITY({idents[(table.name, c.name)][0]},{idents[(table.name, c.name)][1]})"
           if (table.name, c.name) in idents else "")
        + f" {'NOT NULL' if not c.nullable else 'NULL'}"
        for c in cols)
    pk_clause = (f",\n        CONSTRAINT [PK_{table.name}] PRIMARY KEY CLUSTERED "
                 f"({', '.join('[' + c + ']' for c in pk)})") if pk else ""

    checks = "\n".join(
        f"EXEC dbo.tsg_reconcile_column @table = N'{table.name}', @column = N'{c.name}',"
        f"\n     @expected = N'{tsql_type(c)}', @nullable = {'1' if c.nullable else '0'}"
        + (f", @fill = N'{_fill_literal(c).replace(chr(39), chr(39) * 2)}'" if _fill_literal(c) else "")
        + ";"
        for c in cols)

    known = ",".join(c.name for c in cols)
    # The CREATE sets the key only for a NEW table; an older copy can carry a different one
    # (Threat_Scenario_Control_Map was keyed on OutputID). Before the extra-columns report,
    # because an old key column cannot be made NULL-able while it is still in the key.
    pk_check = (f"/* The primary key the application expects - an older table may carry another. */\n"
                f"EXEC dbo.tsg_reconcile_primary_key @table = N'{table.name}', "
                f"@columns = N'{','.join(pk)}';\nGO\n\n") if pk else ""
    # After the key repair (which moves the key OFF the legacy column), before the extra-columns
    # report (which would otherwise just relax it).
    pk_check += "".join(_legacy_drop(table.name, old, new)
                        for old, new in LEGACY_COLUMN_RENAMES.get(table.name, []))
    # Before the CREATE: a legacy-named table is renamed, never duplicated.
    table_rename = (_legacy_table_rename(table.name, LEGACY_TABLE_RENAMES[table.name])
                    if table.name in LEGACY_TABLE_RENAMES else "")
    # After the CREATE, before the column reconcile - which would otherwise ADD the new name empty.
    renames = "".join(
        f"EXEC dbo.tsg_rename_column @table = N'{table.name}', @old = N'{old}', @new = N'{new}';\n"
        for old, new in LEGACY_COLUMN_RENAMES.get(table.name, []))
    if renames:
        renames = ("/* Legacy column names: renamed in place so their data is kept. */\n"
                   + renames + "GO\n\n")
    renames += _legacy_object_renames(table.name)
    return header(
        title=f"TABLE: {table.name}",
        name=f"{order:03d}_{table.name}.sql",
        order=f"01_tables / {order:03d}",
        purpose=f"Create {table.name}, or bring an existing copy up to {len(cols)} columns.",
        depends="00_validation/001_pre_deployment_validation.sql",
        modifies=f"dbo.{table.name}",
    ) + f"""
PRINT '';
PRINT '--- {table.name} ---';
GO

{table_rename}IF OBJECT_ID('dbo.{table.name}', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[{table.name}] (
{create_cols}{pk_clause}
    );
    PRINT ' [CREATED] Table: {table.name} ({len(cols)} columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: {table.name}';
GO

{renames}/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
{checks}
GO

{pk_check}/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'{table.name}', @known = N'{known}';
GO
"""


def column_verdict_script(md) -> str:
    """A READ-ONLY sign-off over every column the application reads or writes.

    WHY THIS FILE EXISTS. 001_post_deployment_validation.sql declares five failure counters —
    tables, primary keys, indexes, check constraints, isolation — and not one of them looks at a
    COLUMN. So a deployment where tsg_reconcile_column printed [BLOCKED] on a narrowing change,
    or added a column as NULL because the table had rows, still ended with "Overall: PASS". The
    one signal that a human had unfinished work was invisible to the verdict that says the
    application may start.

    GENERATED, never hand-listed: 296 columns across 22 tables is exactly the list that rots.
    It comes from the same models.py the table scripts come from.

    A missing column and a wrong nullability are FAILURES, because the application breaks on
    them. Length differences are deliberately not failed here — the database may legitimately be
    WIDER than the ORM asks for, and widening is the one change this package applies freely
    (README section 5)."""
    rows = []
    for name in TABLE_ORDER:
        for c in md.tables[name].columns:
            compiled = tsql_type(c)
            base = compiled.partition("(")[0].strip().lower()
            rows.append(f"    (N'{name}', N'{c.name}', N'{base}', "
                        f"N'{compiled}', {1 if c.nullable else 0})")
    values = ",\n".join(rows)
    # Unique CONSTRAINTS are verified alongside the indexes: SQL Server implements one with a
    # unique index, so sys.indexes sees it and the same shape comparison applies. Leaving them
    # out is how UQ_Config_Tuning_Key stayed missing from a database the verdict called clean.
    idx = index_definitions() + [
        {"name": u["name"], "table": u["table"], "unique": True,
         "columns": u["columns"], "filtered": False} for u in unique_constraints(md)]
    idx_rows = ",\n".join(
        f"    (N'{i['name']}', N'{i['table']}', {1 if i['unique'] else 0}, "
        f"{1 if i['filtered'] else 0}, N'{','.join(i['columns'])}')" for i in idx)
    dfs = default_definitions()
    df_rows = ",\n".join(
        f"    (N'{d['name']}', N'{d['table']}', N'{d['column']}')" for d in dfs)
    idents = identity_columns()
    ident_rows = ",\n".join(
        f"    (N'{t}', N'{c}')" for (t, c) in sorted(idents))
    pks = {name: [c.name for c in md.tables[name].primary_key.columns] for name in TABLE_ORDER}
    pk_rows = ",\n".join(f"    (N'{t}', N'{','.join(cols)}')" for t, cols in pks.items() if cols)
    collation_family = REQUIRED_COLLATION_FAMILY
    return header(
        title="SCHEMA VERDICT  (READ ONLY)",
        name="002_schema_verdict.sql",
        order="99_validation / 002   (run LAST, after 001)",
        purpose=(f"Verify all {len(rows)} columns and all {len(idx)} indexes, "
                 "down to index key columns and filters."),
        depends="99_validation/001_post_deployment_validation.sql",
        modifies="NOTHING. Catalog views only.",
    ) + f"""
PRINT '';
PRINT '==============================================================';
PRINT ' TSG COLUMN VERDICT   ({len(rows)} columns across {len(TABLE_ORDER)} tables)';
PRINT ' Database: ' + DB_NAME();
PRINT '==============================================================';
GO

DECLARE @expected TABLE (
    tbl sysname, col sysname, base_type sysname, full_type nvarchar(100), is_nullable bit);
INSERT INTO @expected (tbl, col, base_type, full_type, is_nullable) VALUES
{values};

DECLARE @missing int = 0, @wrong_type int = 0, @wrong_null int = 0;

/* A column the application reads that the database does not have. The app breaks on first use. */
SELECT @missing = COUNT(*)
FROM   @expected e
WHERE  OBJECT_ID('dbo.' + QUOTENAME(e.tbl), 'U') IS NOT NULL
  AND  NOT EXISTS (SELECT 1 FROM sys.columns c
                   WHERE c.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                     AND c.name = e.col);

IF @missing > 0
    SELECT '[FAIL] missing column: ' + e.tbl + '.' + e.col +
           '  (expected ' + e.full_type + ')' AS Problem
    FROM   @expected e
    WHERE  OBJECT_ID('dbo.' + QUOTENAME(e.tbl), 'U') IS NOT NULL
      AND  NOT EXISTS (SELECT 1 FROM sys.columns c
                       WHERE c.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                         AND c.name = e.col);

/* A different type FAMILY. Not a widening, not recoverable by re-running the deployment. */
SELECT @wrong_type = COUNT(*)
FROM   @expected e
JOIN   sys.columns c ON c.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl)) AND c.name = e.col
WHERE  TYPE_NAME(c.user_type_id) <> e.base_type;

IF @wrong_type > 0
    SELECT '[FAIL] wrong type: ' + e.tbl + '.' + e.col +
           '  is ' + TYPE_NAME(c.user_type_id) + ', expected ' + e.base_type AS Problem
    FROM   @expected e
    JOIN   sys.columns c ON c.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl)) AND c.name = e.col
    WHERE  TYPE_NAME(c.user_type_id) <> e.base_type;

/* NULLABILITY, and only the DANGEROUS direction fails.

   A column the application requires that the database lets be NULL is a real failure: it is
   exactly what the deployment DELIBERATELY creates when it adds a NOT NULL column to a table
   that already has rows, printing a [WARNING] and the ALTER to run after backfilling. That
   warning scrolls past; this does not.

   The OPPOSITE - database NOT NULL where the ORM says nullable - is reported but not failed.
   It is the safe direction (the database is stricter), it is what the reviewed script already
   declares for the library tables' CreatedAt columns, and those carry a DEFAULT so an insert
   that omits the value still succeeds. Failing it would refuse sign-off on the schema this
   package itself deploys. */
SELECT @wrong_null = COUNT(*)
FROM   @expected e
JOIN   sys.columns c ON c.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl)) AND c.name = e.col
WHERE  c.is_nullable = 1 AND e.is_nullable = 0;

IF @wrong_null > 0
    SELECT '[FAIL] nullability: ' + e.tbl + '.' + e.col +
           '  allows NULL but the application requires NOT NULL'
           + '  -> backfill, then: ALTER TABLE dbo.' + QUOTENAME(e.tbl)
           + ' ALTER COLUMN ' + QUOTENAME(e.col) + ' ' + e.full_type + ' NOT NULL;' AS Problem
    FROM   @expected e
    JOIN   sys.columns c ON c.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl)) AND c.name = e.col
    WHERE  c.is_nullable = 1 AND e.is_nullable = 0;

IF EXISTS (SELECT 1 FROM @expected e
           JOIN sys.columns c ON c.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                             AND c.name = e.col
           WHERE c.is_nullable = 0 AND e.is_nullable = 1)
    SELECT '[INFO] stricter than the application: ' + e.tbl + '.' + e.col +
           ' is NOT NULL where the model allows NULL (safe; inserts rely on its DEFAULT)'
           AS Note
    FROM   @expected e
    JOIN   sys.columns c ON c.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl)) AND c.name = e.col
    WHERE  c.is_nullable = 0 AND e.is_nullable = 1;

/*============================ INDEXES ============================
  001 matches indexes by NAME and TABLE only, so an index carrying the right name over the WRONG
  COLUMNS, or with its WHERE filter dropped, signs off clean. Every one of these is a uniqueness
  guard the application leans on for a race it cannot otherwise win - one active session per
  asset, one accepted version per scenario, one running calibration. A filtered unique index
  whose predicate went missing enforces something quite different from what the code assumes.

  Key columns are compared BY NAME AND ORDER (key_ordinal), which is what decides whether the
  index can serve the query and what the uniqueness actually spans. Included columns are not
  compared: they change only cost, never correctness.
==================================================================*/
DECLARE @ix TABLE (name sysname, tbl sysname, is_unique bit, is_filtered bit, cols nvarchar(900));
INSERT INTO @ix (name, tbl, is_unique, is_filtered, cols) VALUES
{idx_rows};

DECLARE @ix_missing int = 0, @ix_shape int = 0;

SELECT @ix_missing = COUNT(*)
FROM   @ix e
WHERE  NOT EXISTS (SELECT 1 FROM sys.indexes i
                   WHERE i.name = e.name
                     AND i.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                     AND i.is_disabled = 0);

IF @ix_missing > 0
    SELECT '[FAIL] index missing or disabled: ' + e.name + ' on ' + e.tbl AS Problem
    FROM   @ix e
    WHERE  NOT EXISTS (SELECT 1 FROM sys.indexes i
                       WHERE i.name = e.name
                         AND i.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                         AND i.is_disabled = 0);

/* Shape: uniqueness, filtered-ness, and the key column list in order. */
DECLARE @actual TABLE (name sysname, tbl sysname, is_unique bit, is_filtered bit,
                       cols nvarchar(900));
INSERT INTO @actual (name, tbl, is_unique, is_filtered, cols)
SELECT i.name, t.name, i.is_unique, i.has_filter,
       STUFF((SELECT ',' + c.name
              FROM   sys.index_columns ic
              JOIN   sys.columns c ON c.object_id = ic.object_id
                                  AND c.column_id = ic.column_id
              WHERE  ic.object_id = i.object_id AND ic.index_id = i.index_id
                AND  ic.is_included_column = 0
              ORDER BY ic.key_ordinal
              FOR XML PATH('')), 1, 1, '')
FROM   sys.indexes i
JOIN   sys.tables  t ON t.object_id = i.object_id
WHERE  i.name IN (SELECT name FROM @ix);

SELECT @ix_shape = COUNT(*)
FROM   @ix e JOIN @actual a ON a.name = e.name AND a.tbl = e.tbl
WHERE  a.is_unique <> e.is_unique OR a.is_filtered <> e.is_filtered
   OR  ISNULL(a.cols, '') <> e.cols;

IF @ix_shape > 0
    SELECT '[FAIL] index shape: ' + e.name + ' on ' + e.tbl +
           CASE WHEN a.is_unique   <> e.is_unique   THEN '  UNIQUE differs;' ELSE '' END +
           CASE WHEN a.is_filtered <> e.is_filtered THEN '  filter differs;' ELSE '' END +
           CASE WHEN ISNULL(a.cols, '') <> e.cols
                THEN '  keys are (' + ISNULL(a.cols, '<none>') + '), expected (' + e.cols + ')'
                ELSE '' END AS Problem
    FROM   @ix e JOIN @actual a ON a.name = e.name AND a.tbl = e.tbl
    WHERE  a.is_unique <> e.is_unique OR a.is_filtered <> e.is_filtered
       OR  ISNULL(a.cols, '') <> e.cols;

/*========================== PRIMARY KEYS ==========================
  The key COLUMNS, in order. 001 only asks whether a table HAS a primary key, so an older
  Threat_Scenario_Control_Map keyed on (OutputID, ControlLibraryID) passed it - and every insert
  failed, because the application writes ScenarioID and never supplies OutputID.
==================================================================*/
DECLARE @pk TABLE (tbl sysname, cols nvarchar(900));
INSERT INTO @pk (tbl, cols) VALUES
{pk_rows};

DECLARE @pk_wrong int = 0;
DECLARE @pk_actual TABLE (tbl sysname, cols nvarchar(900));
INSERT INTO @pk_actual (tbl, cols)
SELECT e.tbl,
       STUFF((SELECT ',' + c.name
              FROM   sys.indexes i
              JOIN   sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
              JOIN   sys.columns c        ON c.object_id = ic.object_id AND c.column_id = ic.column_id
              WHERE  i.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                AND  i.is_primary_key = 1 AND ic.key_ordinal > 0
              ORDER BY ic.key_ordinal
              FOR XML PATH('')), 1, 1, '')
FROM   @pk e
WHERE  OBJECT_ID('dbo.' + QUOTENAME(e.tbl), 'U') IS NOT NULL;

SELECT @pk_wrong = COUNT(*)
FROM   @pk e JOIN @pk_actual a ON a.tbl = e.tbl
WHERE  ISNULL(a.cols, '') <> e.cols;

IF @pk_wrong > 0
    SELECT '[FAIL] primary key: ' + e.tbl + '  keys are (' + ISNULL(a.cols, '<none>') +
           '), expected (' + e.cols + ')' AS Problem
    FROM   @pk e JOIN @pk_actual a ON a.tbl = e.tbl
    WHERE  ISNULL(a.cols, '') <> e.cols;

/*============================ DEFAULTS ============================
  Checked BY COLUMN, not by constraint name. SQL Server permits one default per column, and a
  database may legitimately carry it under an auto-generated name
  (DF__Identifie__IsAIG__7954A4F6) — the column still has its default, which is what the
  application depends on. Demanding our name would fail a correct database and tempt someone to
  drop and recreate a constraint for cosmetics.

  Nothing verified these before: 001 prints a count as [INFO] and never fails on it. A column
  that loses its default does not error — it silently stores whatever the insert left out.
==================================================================*/
DECLARE @df TABLE (name sysname, tbl sysname, col sysname);
INSERT INTO @df (name, tbl, col) VALUES
{df_rows};

DECLARE @df_missing int = 0;
SELECT @df_missing = COUNT(*)
FROM   @df e
WHERE  OBJECT_ID('dbo.' + QUOTENAME(e.tbl), 'U') IS NOT NULL
  AND  NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
                   JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                     AND c.column_id = dc.parent_column_id
                   WHERE dc.parent_object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                     AND c.name = e.col);

IF @df_missing > 0
    SELECT '[FAIL] no DEFAULT on ' + e.tbl + '.' + e.col +
           '  (expected ' + e.name + ') -> inserts omitting it store no value' AS Problem
    FROM   @df e
    WHERE  OBJECT_ID('dbo.' + QUOTENAME(e.tbl), 'U') IS NOT NULL
      AND  NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
                       JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                         AND c.column_id = dc.parent_column_id
                       WHERE dc.parent_object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                         AND c.name = e.col);

/*=================== IDENTITY and COLLATION ===================
  IDENTITY: the application NEVER supplies these ids — dal.upsert_threat_type and its siblings
  insert without the key and read the generated value back. A table created without identity
  therefore passes every other check here and then fails on the first library insert with
  "Cannot insert the value NULL". It cannot be repaired by ALTER (SQL Server needs a table
  rebuild), so this reports it rather than pretending a re-run fixes it.

  COLLATION: the natural-key unique indexes are the database half of the library's dedup
  guarantee. Under a case-SENSITIVE collation 'Ransomware' and 'ransomware' are different keys,
  so both insert and the library quietly accumulates duplicates that normalize_name() in Python
  already treats as one row. Checked as a FAMILY (_CI_), not an exact string, because the
  accent and locale parts are a deployment choice and only case-insensitivity is relied upon.
==============================================================*/
DECLARE @ident TABLE (tbl sysname, col sysname);
INSERT INTO @ident (tbl, col) VALUES
{ident_rows};

DECLARE @id_missing int = 0, @fail_collation int = 0;

SELECT @id_missing = COUNT(*)
FROM   @ident e
WHERE  OBJECT_ID('dbo.' + QUOTENAME(e.tbl), 'U') IS NOT NULL
  AND  NOT EXISTS (SELECT 1 FROM sys.identity_columns ic
                   JOIN sys.columns c ON c.object_id = ic.object_id
                                     AND c.column_id = ic.column_id
                   WHERE ic.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                     AND c.name = e.col);

IF @id_missing > 0
    SELECT '[FAIL] ' + e.tbl + '.' + e.col + ' is not an IDENTITY column. The application '
           + 'inserts without this id, so the first write to ' + e.tbl + ' will fail. '
           + 'IDENTITY cannot be added by ALTER - the table must be rebuilt.' AS Problem
    FROM   @ident e
    WHERE  OBJECT_ID('dbo.' + QUOTENAME(e.tbl), 'U') IS NOT NULL
      AND  NOT EXISTS (SELECT 1 FROM sys.identity_columns ic
                       JOIN sys.columns c ON c.object_id = ic.object_id
                                         AND c.column_id = ic.column_id
                       WHERE ic.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                         AND c.name = e.col);

DECLARE @collation nvarchar(128) = CAST(DATABASEPROPERTYEX(DB_NAME(), 'Collation') AS nvarchar(128));
IF @collation IS NULL OR @collation NOT LIKE '%{collation_family}%'
BEGIN
    SET @fail_collation = 1;
    PRINT ' [FAIL] Database collation is ' + ISNULL(@collation, '<unreadable>') + '.';
    PRINT '       A case-INSENSITIVE collation is required: the natural-key unique indexes';
    PRINT '       are what stop the threat library holding ''Ransomware'' and ''ransomware''';
    PRINT '       as two rows, and normalize_name() in the application already treats them';
    PRINT '       as one. Case-sensitive here means silent duplicate library entries.';
END;

PRINT '';
PRINT 'SCHEMA VERDICT';
PRINT '--------------';
PRINT ' [INFO]    Columns expected:   {len(rows)}';
PRINT ' [INFO]    Missing:            ' + CAST(@missing    AS varchar(10));
PRINT ' [INFO]    Wrong type:         ' + CAST(@wrong_type AS varchar(10));
PRINT ' [INFO]    Wrong nullability:  ' + CAST(@wrong_null AS varchar(10));
PRINT ' [INFO]    Indexes expected:   {len(idx)}';
PRINT ' [INFO]    Missing/disabled:   ' + CAST(@ix_missing AS varchar(10));
PRINT ' [INFO]    Wrong shape:        ' + CAST(@ix_shape   AS varchar(10));
PRINT ' [INFO]    Primary keys wrong: ' + CAST(@pk_wrong   AS varchar(10));
PRINT ' [INFO]    Defaults expected:  {len(dfs)}';
PRINT ' [INFO]    Missing defaults:   ' + CAST(@df_missing AS varchar(10));
PRINT ' [INFO]    Identity expected:  {len(idents)}';
PRINT ' [INFO]    Missing identity:   ' + CAST(@id_missing AS varchar(10));
PRINT ' [INFO]    Collation:          ' + ISNULL(@collation, '<unreadable>');
PRINT '';
PRINT 'Columns:   ' + CASE WHEN (@missing + @wrong_type + @wrong_null) = 0
                           THEN 'PASS' ELSE 'FAILED' END;
PRINT 'Indexes:   ' + CASE WHEN (@ix_missing + @ix_shape) = 0 THEN 'PASS' ELSE 'FAILED' END;
PRINT 'Keys:      ' + CASE WHEN @pk_wrong = 0 THEN 'PASS' ELSE 'FAILED' END;
PRINT 'Defaults:  ' + CASE WHEN @df_missing = 0 THEN 'PASS' ELSE 'FAILED' END;
PRINT 'Identity:  ' + CASE WHEN @id_missing = 0 THEN 'PASS' ELSE 'FAILED' END;
PRINT 'Collation: ' + CASE WHEN @fail_collation = 0 THEN 'PASS' ELSE 'FAILED' END;
PRINT '';

IF (@missing + @wrong_type + @wrong_null + @ix_missing + @ix_shape + @pk_wrong + @df_missing
    + @id_missing + @fail_collation) = 0
BEGIN
    PRINT 'FINAL SIGN-OFF: this script and 001 have both passed. The application may start.';
END
ELSE
BEGIN
    PRINT 'FINAL SIGN-OFF: REFUSED. The failing rows are in the RESULTS tab in SSMS (listed';
    PRINT 'above in sqlcmd). A column [FAIL] usually means the deployment left work for a human -';
    PRINT 'a NOT NULL column added as NULL because the table already had rows - and re-running';
    PRINT 'will NOT clear it. An index [FAIL] should not survive a run: 03_indexes rebuilds a';
    PRINT 'wrong-shaped index, so check the output for an [ERROR] on that index.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('FINAL SIGN-OFF REFUSED - see the rows in the Results tab.', 16, 1);
END;
GO
"""


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\r\n")   # sqlcmd and SSMS prefer CRLF


COMBINED_NAME = "TSG_Deploy_All.sql"

COMBINED_NOTES = """/*------------------------------------------------------------------------------
  HOW TO RUN IT

    sqlcmd -b -S <server> -d <database> -i TSG_Deploy_All.sql

  or open it in SSMS and press F5. No SQLCMD Mode, no folder, no other file.

  IT STOPS AT THE FIRST ERROR, in SSMS too. SSMS on its own does NOT stop at a
  failed batch, so a check follows every batch in this file: after an error it
  prints "!!! DEPLOYMENT STOPPED" and switches execution off (SET NOEXEC ON).
  The real error is the red message just above the !!! lines, and the last
  ">>> [n/total]" line above that names the script. Fix it, then run this WHOLE
  file again - it is re-runnable.

  READ THE END BEFORE YOU BELIEVE IT. A clean run ends with "Objects: PASS" and
  then "FINAL SIGN-OFF"; a stopped one ends with "DEPLOYMENT STOPPED".

  WHAT IT CHANGES BESIDES TABLES. It turns READ_COMMITTED_SNAPSHOT on, because
  the application does not start without it. On a database somebody else is
  using, that disconnects those sessions and rolls back their in-flight work.
  Deploy in a window if that matters.

  WHAT IT DOES NOT DO. It does not load the threat and control libraries. The
  schema is correct but empty until those are seeded, and an empty library
  returns empty results forever, which looks like a bug and is not one.
------------------------------------------------------------------------------*/
GO
"""


# THE SSMS STOP. SSMS runs every batch even after one fails, so a pasted deployment could finish
# half-applied and look done. A guard follows every GO: `@@ERROR` survives into the next batch,
# so a failed batch is seen by the guard after it and `SET NOEXEC ON` turns the rest into
# compile-only. Measured on SQL Server, @@ERROR alone MISSES two cases, hence the other two parts:
#   * an error mid-batch with statements after it  -> XACT_ABORT ON ends the batch AT the error;
#   * a RAISERROR inside CATCH (END CATCH resets @@ERROR) -> the CATCH sets this session flag.
# The guard is constant text so the package test can strip it and still find every script verbatim.
STOP_FLAG = "tsg_deploy_failed"
STOP_GUARD = f"""IF @@ERROR <> 0 OR SESSION_CONTEXT(N'{STOP_FLAG}') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'{STOP_FLAG}', 1;
    SET NOEXEC ON;
END
GO
"""
# NOEXEC OFF in a batch of its own: a stopped run earlier in the same SSMS window left it ON, and
# only a lone SET NOEXEC OFF is honoured while it is. Then clear the flag that run left behind.
STOP_PROLOGUE = f"""SET NOEXEC OFF;
GO
SET XACT_ABORT ON;
EXEC sp_set_session_context N'{STOP_FLAG}', 0;
GO
"""


def _with_stop_guards(sql: str) -> str:
    return re.sub(r"(?im)^GO[ \t]*\n", lambda _m: "GO\n" + STOP_GUARD, sql)


def combined_script() -> str:
    """Every script in the package, in execution order, as ONE self-contained file.

    WHY. The package is 47 files across five folders, and a UAT or Prod handover is normally ONE
    artefact: something that attaches to a change ticket, reviews as a single diff, and runs
    without the DBA rebuilding a folder layout. A `:r` loader would be a fraction of the size and
    could never go stale, but it needs the whole folder beside it AND SSMS switched to SQLCMD
    Mode first, so it cannot be handed over on its own.

    NOTHING HERE IS HAND-LISTED. Name order already IS execution order (00_validation <
    01_tables < 02_constraints < 03_indexes < 99_validation), so a script added to the package
    joins the deployment by existing. A hand-kept list is precisely what went wrong in the README,
    where 003_unique_constraints.sql was missing from the step table and a reader following it
    row by row never created UQ_Config_Tuning_Key.

    Generated LAST in main(), after every other write(), so it concatenates the text just
    produced rather than the previous run's.
    """
    sources = sorted((p for p in OUT.rglob("*.sql") if p.name != COMBINED_NAME),
                     key=lambda p: p.relative_to(OUT).as_posix())
    total = len(sources)

    parts = [
        header(
            title=f"TSG SCHEMA - COMPLETE DEPLOYMENT IN ONE FILE ({total} scripts)",
            name=COMBINED_NAME,
            order=f"all {total} scripts of this package, in execution order",
            purpose="Deploy or reconcile the entire TSG schema, then prove it.",
            depends="Nothing. It contains every script it needs.",
            modifies="Every TSG table, constraint and index, and the isolation level.",
        ),
        COMBINED_NOTES,
        STOP_PROLOGUE,
    ]

    for n, path in enumerate(sources, start=1):
        rel = path.relative_to(OUT).as_posix()
        # The locator, so a 200 KB file stays navigable and the run log says where it got to.
        # It opens with '>' and never '[': sqlcmd DELETES a bracketed marker that starts a
        # message line, which is what test_every_status_marker_survives_the_client_that_prints_it
        # pins for every other script in this package.
        parts.append(_with_stop_guards(
            "/*" + "=" * 76 + "\n"
            f"  >>> {n} of {total}   {rel}\n"
            + "=" * 76 + "*/\n"
            "PRINT '';\n"
            f"PRINT '>>> [{n}/{total}] {rel}';\n"
            "GO\n\n"
            # Every file here already ends with GO, so two scripts cannot land in one batch, and
            # each sets its own NOCOUNT and QUOTED_IDENTIFIER.
            + path.read_text(encoding="utf-8").replace("\r\n", "\n").rstrip("\n") + "\n"
        ))

    # No guard after these: the first one is what switches execution back on.
    parts.append(
        "SET NOEXEC OFF;\n"
        "GO\n"
        "SET XACT_ABORT OFF;\n"
        f"IF SESSION_CONTEXT(N'{STOP_FLAG}') = 1\n"
        "BEGIN\n"
        "    PRINT '';\n"
        "    PRINT '!!! DEPLOYMENT STOPPED - it is NOT complete. The error is just above the';\n"
        "    PRINT '!!! first \"!!! DEPLOYMENT STOPPED\" lines. Fix it, then run this whole file again.';\n"
        "END\n"
        "ELSE\n"
        "BEGIN\n"
        "    PRINT '';\n"
        f"    PRINT '>>> all {total} scripts have run. Read the two verdicts above:';\n"
        "    PRINT '>>>   Objects: PASS   then   FINAL SIGN-OFF';\n"
        "    PRINT '>>> Anything else means the deployment is NOT complete.';\n"
        "END\n"
        "GO\n"
    )
    return "\n".join(parts)


def main() -> None:
    md = load_metadata()
    indexes = index_blocks()
    defaults, checks = constraint_blocks("default"), constraint_blocks("check")
    if not indexes or not defaults or not checks:
        raise SystemExit(
            "could not extract DDL from the source script - it may have been reformatted. "
            f"indexes={len(indexes)} defaults={len(defaults)} checks={len(checks)}")

    for n, name in enumerate(TABLE_ORDER, start=1):
        write(OUT / "01_tables" / f"{n:03d}_{name}.sql", table_script(md.tables[name], n))

    shapes = {d["name"]: d for d in index_definitions()}
    n = 0
    for name in TABLE_ORDER:
        if name not in indexes:
            continue
        n += 1
        body = "\nGO\n\n".join(_rebuild_if_wrong_shape(block, shapes[ix])
                                for ix, block in indexes[name])
        write(OUT / "03_indexes" / f"{n:03d}_{name}_indexes.sql",
              header(
                  title=f"INDEXES: {name}",
                  name=f"{n:03d}_{name}_indexes.sql",
                  order=f"03_indexes / {n:03d}",
                  purpose=f"{len(indexes[name])} index(es) on {name}.",
                  depends=f"01_tables/*_{name}.sql",
                  modifies=f"indexes on dbo.{name}",
              ) + f"\nPRINT '';\nPRINT '--- indexes: {name} ---';\nGO\n\n{body}\nGO\n")

    write(OUT / "02_constraints" / "001_default_constraints.sql",
          header(title="DEFAULT CONSTRAINTS", name="001_default_constraints.sql",
                        order="02_constraints / 001",
                        purpose=f"{len(defaults)} default constraints.",
                        depends="01_tables/*", modifies="default constraints")
          + "\nPRINT '';\nPRINT '--- default constraints ---';\nGO\n\n"
          + "\nGO\n\n".join(defaults) + "\nGO\n")

    uniques = unique_constraints(md)
    uq_blocks = []
    for u in uniques:
        cols = ", ".join(f"[{c}]" for c in u["columns"])
        group = ", ".join(f"[{c}]" for c in u["columns"])
        uq_blocks.append(f"""/* {u['name']} - {u['table']} ({', '.join(u['columns'])}).
   Declared unique=True in app/db/models.py and as a table constraint in the reviewed DDL, but
   emitted by NEITHER table_script() (columns + PK only) nor index_blocks() (CREATE INDEX only),
   so the package used to skip it entirely. ALTER, not CREATE TABLE, so an existing database
   gains it too.
   Duplicates are reported instead of letting ALTER fail with a bare constraint error: the rows
   have to be reconciled by a human, and the message needs to say which ones. */
IF NOT EXISTS (SELECT 1 FROM sys.key_constraints
               WHERE name = '{u['name']}'
                 AND parent_object_id = OBJECT_ID('dbo.{u['table']}'))
BEGIN
    IF EXISTS (SELECT 1 FROM dbo.[{u['table']}] GROUP BY {group} HAVING COUNT(*) > 1)
    BEGIN
        PRINT ' [BLOCKED] {u['table']}.{'/'.join(u["columns"])} has duplicate values, so';
        PRINT '          {u['name']} cannot be created. The rows below must be';
        PRINT '          reconciled first - keep one, retire the rest.';
        SELECT {cols}, COUNT(*) AS Copies
        FROM   dbo.[{u['table']}] GROUP BY {group} HAVING COUNT(*) > 1;
    END
    ELSE
    BEGIN
        ALTER TABLE dbo.[{u['table']}] ADD CONSTRAINT [{u['name']}] UNIQUE ({cols});
        PRINT ' [ADDED]   {u['name']} on {u['table']} ({', '.join(u['columns'])})';
    END
END
ELSE
    PRINT ' [EXISTS]  {u['name']}';""")

    write(OUT / "02_constraints" / "003_unique_constraints.sql",
          header(title="UNIQUE CONSTRAINTS", name="003_unique_constraints.sql",
                        order="02_constraints / 003",
                        purpose=f"{len(uniques)} unique constraint(s) the CREATE TABLE step omits.",
                        depends="01_tables/*", modifies="unique constraints")
          + "\nPRINT '';\nPRINT '--- unique constraints ---';\nGO\n\n"
          + "\nGO\n\n".join(uq_blocks) + "\nGO\n")

    write(OUT / "02_constraints" / "002_check_constraints.sql",
          header(title="CHECK CONSTRAINTS", name="002_check_constraints.sql",
                        order="02_constraints / 002",
                        purpose=f"{len(checks)} check constraints.",
                        depends="01_tables/*", modifies="check constraints")
          + "\nPRINT '';\nPRINT '--- check constraints ---';\nGO\n\n"
          + "\nGO\n\n".join(checks) + "\nGO\n")

    write(OUT / "99_validation" / "002_schema_verdict.sql", column_verdict_script(md))
    # The verdict used to cover columns only and was named for it. Leaving the old file behind
    # would leave a script that still prints "FINAL SIGN-OFF" after checking no index at all.
    (OUT / "99_validation" / "002_column_verdict.sql").unlink(missing_ok=True)

    # LAST, so it concatenates what the writes above just produced. Anything added to main()
    # after this point would be missing from the single-file deployment and nothing would say so.
    write(OUT / COMBINED_NAME, combined_script())

    print(f"tables   : {len(TABLE_ORDER)}")
    print(f"columns  : {sum(len(md.tables[t].columns) for t in TABLE_ORDER)} (schema verdict)")
    print(f"ix checks: {len(index_definitions())} index shapes verified")
    print(f"indexes  : {sum(len(v) for v in indexes.values())} across {len(indexes)} tables")
    print(f"defaults : {len(defaults)}")
    print(f"checks   : {len(checks)}")
    print(f"written  : {OUT}")


if __name__ == "__main__":
    main()
