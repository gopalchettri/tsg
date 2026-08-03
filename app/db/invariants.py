"""Startup invariants: checks the live database against what the application code assumes,
at boot (and in CI), so a schema/deployment gap crashes the process immediately instead of
surfacing days later as a raw SQL error mid-request.

The MSSQL-only checks need `sys.indexes`/`INFORMATION_SCHEMA` and are skipped on the
SQLite-based unit suite; checklist 3 is plain SQL and always runs.
"""
from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.engine import Engine

from app.core.config import get_settings
from app.core.enums import SessionStatus
from app.db import models as m

# CHECKLIST 1 — UNIQUE indexes the code relies on the DB to enforce. Created by the schema
# scripts, only verified here.
#
# Each entry is (index name, table, ordered columns) — not a bare name: `sys.indexes.name` is
# unique PER TABLE only, so a name-only check would pass on an index that ended up on the wrong
# table or lost a column.
REQUIRED_INDEXES = [
    # One active session per asset / one active scenario per scoped threat. Stops
    # duplicate "current" rows from a retried or racing request.
    ("UX_Session_ActiveAsset", "Scenario_Session", ("EntityID", "AssetID")),
    ("UX_Scenario_ActiveIdentity", "Threat_Scenario_Output", ("SessionID", "IdentityHash", "ScenarioNumber")),
    # Master-library natural keys — makes concurrent promote-on-accept safe: two sessions
    # accepting at once can't both create the same library master.
    ("UX_ThreatType_NaturalKey", "Threat_Type", ("ThreatTypeName", "ThreatCategoryID", "SectorID")),
    ("UX_ThreatCatalogue_NaturalKey", "Threat_Catalogue", ("ThreatTypeID", "ThreatName", "SectorID")),
    ("UX_ThreatActor_NaturalKey", "Threat_Actor", ("ThreatActorName",)),
    ("UX_ThreatCategory_NaturalKey", "Threat_Category", ("ThreatCategoryName",)),
    # The row identity the whole lock/epoch-CAS design asserts in Python (rowcount == 1);
    # a duplicate would let one CAS match two rows and put two workers on one subsystem.
    ("UX_SubsystemStageState_SessionSubLevel", "Subsystem_Stage_State",
     ("SessionID", "SubsystemID", "Level")),
    # One active treatment plan per accepted scenario — the concurrent-POST race arbiter
    # (docs/RISK_TREATMENT_PLAN_SDD.md §4.1). The companion IX_TreatmentPlan_SessionActive is
    # a plain performance index and deliberately NOT listed: this check rejects non-unique
    # entries, and registering it would make every boot fail with the DDL correctly applied.
    ("UX_TreatmentPlan_ActiveOutput", "Risk_Treatment_Plan", ("OutputID",)),
]

# CHECKLIST 6 — CRM Risk-module tables the treatment-plan feature reads (read-only). Verified
# ONLY when risk_module_enabled: the flag arms both the routes and this check together, so a
# request can never reach a missing table (models are a DB-first mirror — absence would surface
# as a raw ProgrammingError mid-request without this). crm_assessment_asset and crm_risk_level
# are optional consumers (SDD §14.3) and deliberately absent.
REQUIRED_CRM_TABLES = (
    "crm_risk_identification",
    "crm_risk_identification_option_value",
    "crm_assessment",
    "crm_risk_identification_treatment_plan",
    "crm_risk_identification_treatment_strategy",
    "crm_risk_rating",
    "crm_risk_rating_category",
    "crm_risk_control_details",
    "crm_risk_control_status",
    "group",
)

# CHECKLIST 2 — columns the code assumes can never be NULL. A NULL EntityID would silently
# bypass the entity-isolation filters that keep one customer's data away from another's.
REQUIRED_NOT_NULL = [
    ("Scenario_Session", "EntityID"), ("Scenario_Session", "AssetID"),
    ("Threat_Candidate_Review", "TenantID"),
]

# CHECKLIST 3 — a LIVE data scan, not a schema check: supersede-instead-of-delete tables must
# never hold two non-superseded rows for one group, or nothing downstream knows which row is
# current. Catches a bug that already happened (partial write, bad backfill), not a missing
# setup step.
#
# Each entry is (table, [columns defining one group]). Identified_Threat / Scoped_Threat are
# deliberately absent — they are MEANT to hold many active rows per subsystem; their guard
# against duplicate/retried writes is the epoch CAS, not uniqueness.
ACTIVE_UNIQUE = [
    (m.Threat_Scenario_Output, ["SessionID", "ScopedThreatID"]),
]


# CHECKLIST 4 (no list — see _assert_rcsi_enabled) — RCSI must be ON. Every CAS/lock-fencing
# pattern in dal.py assumes a plain read never blocks behind a concurrent writer. Without it
# nothing crashes; readers and writers just start blocking each other under load, which is
# near-undiagnosable after the fact.

# CHECKLIST 5 — these filtered indexes bake a raw 'active'/'completed' literal into their
# WHERE clause against Scenario_Session.SessionStatus, and nothing in the DB ties that text to
# the SessionStatus enum. Rename the enum without updating the DDL and the index silently stops
# matching any row the app writes — the one-active-session lock degrades with no error anywhere.
#
# Each entry is (index name, the SessionStatus member its filter must mention).
FILTERED_INDEX_LITERALS = [
    ("UX_Session_ActiveAsset", SessionStatus.active),
    ("IX_Session_Active", SessionStatus.active),
    ("IX_Session_CompletedByAsset", SessionStatus.completed),
]


class StartupInvariantError(RuntimeError):
    """Raised when any check below fails. Callers must let it propagate and kill the boot —
    refusing to start IS the point."""


def verify_startup(engine: Engine) -> None:
    """Entry point: call once at boot (and in CI). MSSQL-only checks need system tables and
    are skipped on SQLite; checklist 3 is plain SQL and always runs."""
    if engine.dialect.name == "mssql":
        _assert_indexes(engine)
        _assert_filtered_index_literals(engine)
        _assert_not_null(engine)
        _assert_rcsi_enabled(engine)
        if get_settings().risk_module_enabled:
            _assert_crm_tables(engine)
    _assert_no_duplicate_active(engine)


def _assert_indexes(engine: Engine) -> None:
    """Runs CHECKLIST 1: ONE `sys.indexes` query covering every required index at once (filtered
    to those names server-side, never a full-catalog scan), checking each one's real table,
    columns, `is_disabled` and `is_unique`. Missing, on the wrong table/columns, or present but
    not enforcing (disabled/non-unique) all refuse the boot.
    """
    by_name = {name: (table, cols) for name, table, cols in REQUIRED_INDEXES}
    params = {f"ix{i}": name for i, name in enumerate(by_name)}
    placeholders = ", ".join(f":ix{i}" for i in range(len(by_name)))
    with engine.connect() as c:
        rows = c.execute(
            text(
                "SELECT i.name, OBJECT_NAME(i.object_id), i.is_disabled, i.is_unique, "
                "STRING_AGG(c.name, ',') WITHIN GROUP (ORDER BY ic.key_ordinal) "
                "FROM sys.indexes i "
                "JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id "
                "JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id "
                f"WHERE i.name IN ({placeholders}) "
                "GROUP BY i.name, i.object_id, i.is_disabled, i.is_unique"
            ),
            params,
        ).all()
    present = {r[0]: {"table": r[1], "disabled": bool(r[2]), "unique": bool(r[3]), "columns": tuple(r[4].split(","))}
               for r in rows}
    missing = [ix for ix in by_name if ix not in present]
    if missing:
        raise StartupInvariantError(f"missing required indexes (re-run scripts/TSG_Core.sql): {missing}")
    mismatched = [ix for ix, (table, cols) in by_name.items()
                if present[ix]["table"] != table or present[ix]["columns"] != cols]
    if mismatched:
        raise StartupInvariantError(
            f"required indexes exist under the right name but on the wrong table/columns: "
            f"{[(ix, present[ix]['table'], present[ix]['columns']) for ix in mismatched]}"
        )
    unhealthy = [ix for ix in by_name if present[ix]["disabled"] or not present[ix]["unique"]]
    if unhealthy:
        raise StartupInvariantError(
            f"required indexes exist but are not enforcing (disabled and/or non-unique): {unhealthy}"
        )


def _assert_filtered_index_literals(engine: Engine) -> None:
    """Runs CHECKLIST 5: reads each index's stored `filter_definition` (the verbatim WHERE
    clause from CREATE INDEX) and confirms it still contains the current enum member's quoted
    literal. A substring check, not a SQL parse."""
    names = [name for name, _ in FILTERED_INDEX_LITERALS]
    params = {f"ix{i}": name for i, name in enumerate(names)}
    placeholders = ", ".join(f":ix{i}" for i in range(len(names)))
    with engine.connect() as c:
        rows = c.execute(
            text(f"SELECT name, filter_definition FROM sys.indexes WHERE name IN ({placeholders})"),
            params,
        ).all()
    present = {r[0]: (r[1] or "") for r in rows}
    missing = [name for name in names if name not in present]
    if missing:
        raise StartupInvariantError(f"missing filtered indexes (re-run scripts/TSG_Core.sql): {missing}")
    stale = [name for name, status in FILTERED_INDEX_LITERALS if f"'{status.value}'" not in present[name]]
    if stale:
        raise StartupInvariantError(
            f"filtered index WHERE clause no longer matches the live SessionStatus enum value "
            f"(enum renamed without updating the migration?): {stale}"
        )


def _assert_crm_tables(engine: Engine) -> None:
    """Runs CHECKLIST 6 (risk_module_enabled only): one INFORMATION_SCHEMA.TABLES query with an
    IN-list. Missing tables mean the CRM Risk module is not deployed to this database — refuse
    the boot with the exact names, rather than 500ing the first treatment-plan request."""
    params = {f"t{i}": name for i, name in enumerate(REQUIRED_CRM_TABLES)}
    placeholders = ", ".join(f":t{i}" for i in range(len(REQUIRED_CRM_TABLES)))
    with engine.connect() as c:
        rows = c.execute(
            text(f"SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME IN ({placeholders})"),
            params,
        ).all()
    present = {r[0] for r in rows}
    missing = [t for t in REQUIRED_CRM_TABLES if t not in present]
    if missing:
        raise StartupInvariantError(
            f"risk_module_enabled=true but the CRM Risk-module tables are absent: {missing}. "
            "Deploy the Risk module to this database, or set RISK_MODULE_ENABLED=false."
        )


def _assert_rcsi_enabled(engine: Engine) -> None:
    """Runs CHECKLIST 4: asks `sys.databases` whether RCSI is on for the database this
    connection is actually using (`DB_ID()`, never a hardcoded name). The error carries the
    exact ALTER DATABASE needed to fix it."""
    with engine.connect() as c:
        row = c.execute(
            text("SELECT DB_NAME(), is_read_committed_snapshot_on FROM sys.databases WHERE database_id = DB_ID()")
        ).one()
    db_name, rcsi_on = row[0], bool(row[1])
    if not rcsi_on:
        raise StartupInvariantError(
            f"Read-Committed Snapshot Isolation is OFF on database '{db_name}', but this app's "
            "concurrency model (CAS writes, stage locking) assumes it's on. Fix with: "
            f"ALTER DATABASE [{db_name}] SET READ_COMMITTED_SNAPSHOT ON;"
        )


def _assert_not_null(engine: Engine) -> None:
    """Runs CHECKLIST 2: one `INFORMATION_SCHEMA.COLUMNS` query for every pair at once. A pair
    fails either because the column (or whole table) is absent, or because it exists but is
    still nullable."""
    params: dict[str, str] = {}
    clauses = []
    for i, (table, col) in enumerate(REQUIRED_NOT_NULL):
        params[f"t{i}"] = table
        params[f"c{i}"] = col
        clauses.append(f"(TABLE_NAME = :t{i} AND COLUMN_NAME = :c{i})")
    with engine.connect() as c:
        rows = c.execute(
            text(
                "SELECT TABLE_NAME, COLUMN_NAME, IS_NULLABLE FROM INFORMATION_SCHEMA.COLUMNS "
                "WHERE " + " OR ".join(clauses)
            ),
            params,
        ).all()
    found = {(r[0], r[1]): r[2] for r in rows}
    for table, col in REQUIRED_NOT_NULL:
        nullable = found.get((table, col))
        if nullable is None:
            raise StartupInvariantError(f"missing column {table}.{col}")
        # Drivers return nullability as "YES", "1" or "TRUE" — accept all three.
        if str(nullable).upper() in ("YES", "1", "TRUE"):
            raise StartupInvariantError(f"{table}.{col} must be NOT NULL (M3/[R7])")


def _assert_no_duplicate_active(engine: Engine) -> None:
    """Runs CHECKLIST 3 (the only check the SQLite suite exercises): groups non-superseded rows
    by the ACTIVE_UNIQUE key and fails if any group holds more than one — two rows both claiming
    to be the current scenario."""
    with engine.connect() as c:
        for table, cols in ACTIVE_UNIQUE:
            grp = ", ".join(cols)
            # f-string SQL is safe here: table/column names come from the hardcoded
            # ACTIVE_UNIQUE list, never from user input.
            dupes = c.execute(
                text(
                    f"SELECT COUNT(*) FROM (SELECT {grp} FROM {table.__tablename__} "
                    f"WHERE Superseded = 0 GROUP BY {grp} HAVING COUNT(*) > 1) d"
                )
            ).scalar()
            if dupes:
                raise StartupInvariantError(
                    f"{table.__tablename__}: {dupes} ({grp}) groups have >1 active row (INV-2)"
                )
