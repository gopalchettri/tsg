"""Startup invariants (mandated assertion module; remediation INV-1..5).

WHAT THIS FILE IS, IN ONE SENTENCE: a bouncer that stands at the front door of
the app. Before the API (or a worker) starts serving real traffic, it checks
the actual database against a checklist of things the application code
*assumes* are true. If anything on the checklist is missing, the app refuses
to start at all — loudly, immediately, at boot — instead of starting up fine
and then crashing later, mid-request, in front of a real user.

WHY THIS MATTERS (concrete example): say someone deploys new application code
that depends on a new database table or index, but forgets to run the
migration that actually creates it in the database. Without this file, the
app would start up looking perfectly healthy — and only crash the first time
someone hits the code path that touches the missing table/index, potentially
hours or days later, with a confusing raw SQL error. WITH this file, the app
never starts in that broken state — you find out about the missing migration
in the first couple of seconds after deployment, not after a real user hits
the bug.

WHEN THIS RUNS: called once at boot (see `verify_startup` below) and also in
CI, so a bad deploy is caught before it ever reaches production traffic.

WHY SOME CHECKS SKIP ON SQLite: the unit test suite runs against SQLite (fast,
no real database needed), and its schema is a hand-built fixture
(tests/conftest.py), not the real production schema. Asserting the production
schema's guards against that fixture would only ever be testing the fixture, so
`verify_startup` runs checklists 1 and 2 exclusively against real MSSQL.
Checklist 1's machinery is nevertheless dialect-portable (it reads SQLite's
`pragma_index_list` where it reads SQL Server's `sys.indexes`) so that
tests/test_invariants.py can drive the real comparison end to end against a
real database instead of leaving it untested — an untested boot check is how a
wrong-shaped index reached a deployed database in the first place.
"""
from __future__ import annotations

from typing import NamedTuple

from sqlalchemy import text
from sqlalchemy.engine import Engine

from app.db import models as m

# ============================================================================
# CHECKLIST 1 — "did the database actually get its safety locks installed?"
#
# Each entry below is a UNIQUE INDEX: a rule you tell the database to enforce
# FOR you, so the database itself refuses bad data, instead of trusting the
# application code to always remember to check. These indexes are created by
# separate migration scripts (not by this file) — this file only checks that
# they exist, on the right table, over the right columns, before the app is
# allowed to start.
#
# CONCRETE EXAMPLE of what one of these prevents: `UX_Session_ActiveAsset`
# stops two people from clicking "start a new session" on the exact same
# asset at the exact same moment and ending up with two active sessions
# running simultaneously, stepping on each other's data. Without the index,
# the database would happily accept both inserts.
#
# WHY EACH ENTRY IS A FULL SHAPE AND NOT JUST A NAME: an index name is only a
# label — on its own it says nothing about what the index actually enforces.
# A hand-made index called `UX_ThreatType_NaturalKey` sitting on the WRONG
# column (a legacy `ThreatCategoryID` instead of `PrimaryThreatCategoryID`,
# say) sails straight past a name-only check while enforcing a rule the code
# never asked for — and the duplicate-master race that index exists to lose
# safely (R10, `dal.upsert_threat_type`) is then completely unguarded, with
# nothing anywhere reporting a problem. That is not hypothetical: it is what
# a UAT database was found doing. So each entry carries the table, the key
# columns IN ORDER, and whether the index must be UNIQUE, and
# `_assert_indexes` below compares every part of it.
#
# `filter_sql` is the index's WHERE clause. It is deliberately NOT part of the
# boot comparison: SQL Server rewrites a filter into its own normalized form
# (`IsActive = 1` comes back as `([IsActive]=(1))`), so comparing the text is
# a false-alarm generator. It lives here so that ONE definition of each guard
# index exists in ONE place — migration 0019 rebuilds a drifted index straight
# from `IndexSpec.ddl()`, and tests/test_schema_sync.py asserts the CREATE
# statements in scripts/bootstrap_schema.sql and in the SQLite test harness
# still agree with these specs.
#
# This list grows by one entry every time a new milestone adds a new index the
# code now depends on.
# ============================================================================
class IndexSpec(NamedTuple):
    """One required index, described completely enough to both CHECK it and
    REBUILD it. `columns` is ordered — a unique index on (A, B) and one on
    (B, A) enforce the same rule, but only the first is usable as a seek for
    the queries written against it, so order is part of the contract."""

    name: str
    table: str
    columns: tuple[str, ...]
    filter_sql: str | None = None
    unique: bool = True

    def ddl(self) -> str:
        """The exact CREATE statement that brings this index into existence —
        the single source of truth migration 0019 rebuilds a drifted index
        from, so a repair can never disagree with what boot demands."""
        unique = "UNIQUE " if self.unique else ""
        where = f" WHERE {self.filter_sql}" if self.filter_sql else ""
        return f"CREATE {unique}INDEX {self.name} ON {self.table}({', '.join(self.columns)}){where}"

    def describe(self) -> str:
        """`Threat_Type(ThreatTypeName, PrimaryThreatCategoryID, SectorID)` — the
        shape, for error messages an operator has to act on at 2am."""
        return f"{self.table}({', '.join(self.columns)})"


REQUIRED_INDEXES = [
    # One active session per asset / one active profile per subsystem / one
    # active scenario per scoped threat. Stops duplicate "current" rows from
    # a retried or racing request.
    IndexSpec("UX_Session_ActiveAsset", "Scenario_Session",
              ("EntityID", "AssetExternalID"), "SessionStatus = 'active'"),
    IndexSpec("UX_Profile_Active", "Subsystem_Profile",
              ("SessionID", "SubsystemID"), "Superseded = 0"),
    IndexSpec("UX_Scenario_ActiveIdentity", "Threat_Scenario_Output",
              ("SessionID", "IdentityHash"), "Superseded = 0"),
    # Master-library natural-key UNIQUE. Stops two people accepting sessions at
    # the same moment from both creating a DUPLICATE "Ransomware via USB"
    # threat type in the shared library (safe concurrent promotion, R10).
    # Filtered on IsActive/IsDeleted so a soft-deleted master's name is reusable.
    IndexSpec("UX_ThreatType_NaturalKey", "Threat_Type",
              ("ThreatTypeName", "PrimaryThreatCategoryID", "SectorID"),
              "IsActive = 1 AND IsDeleted = 0"),
    IndexSpec("UX_ThreatCatalogue_NaturalKey", "Threat_Catalogue",
              ("ThreatTypeID", "ThreatName", "SectorID"),
              "IsActive = 1 AND IsDeleted = 0"),
    IndexSpec("UX_ThreatActor_NaturalKey", "Threat_Actor",
              ("ThreatActorName",), "IsActive = 1 AND IsDeleted = 0"),
]


# ============================================================================
# CHECKLIST 2 — "are these specific columns actually locked down the way the
# code assumes?"
#
# A NOT NULL column is one the database refuses to ever leave empty. This list
# checks that specific columns are REALLY set up that way in the real schema
# — not just assumed to be by the Python code.
#
# CONCRETE EXAMPLE: `Scenario_Session.EntityID` tells the app which
# customer/organization a session belongs to. If this column could somehow be
# left blank for one row, the app's entity-isolation checks (which stop
# Customer A from ever seeing Customer B's data) could be silently bypassed
# for that one broken row. So the app insists on proof this can never happen
# before it will even start.
#
# `Threat_Candidate_Review.TenantID` is the newest entry here: the accept flow
# now writes a row to this table every time it promotes a newly-discovered
# threat into the shared library (R10). If the migration that creates this
# table was never run, this check makes the app refuse to boot — instead of
# the app starting fine and then crashing on the very first "Accept" click.
# ============================================================================
REQUIRED_NOT_NULL = [
    ("Scenario_Session", "EntityID"), ("Scenario_Session", "AssetExternalID"),
    ("Threat_Candidate_Review", "TenantID"),
]

# ============================================================================
# CHECKLIST 3 — "right now, is there ever more than one 'currently active' row
# where the app assumes there's exactly one?"
#
# This one is different from the two lists above: it's not "does a DB rule
# exist" (checklists 1 and 2), it's a LIVE SCAN of the actual data, run every
# time the app boots. Some tables in this system never delete old rows when
# something is regenerated — they just mark the old row "superseded" and add
# a fresh "active" one, so history is preserved. The rule this enforces:
# for a given group of rows (e.g. one session + one subsystem), there must
# NEVER be more than one row simultaneously marked "still active" — if there
# were, nothing downstream would know which one is really "the" current
# profile or scenario.
#
# This catches a live BUG (a partial write, a bad backfill script, a
# regression) that already happened and slipped past every other safeguard —
# not a missing setup step like checklists 1 and 2.
#
# Each entry is (table, [columns that define "one group"]):
#   - Subsystem_Profile: one active profile per (session, subsystem)
#   - Threat_Scenario_Output: one active scenario per (session, scoped threat)
# Identified_Threat / Scoped_Threat are deliberately NOT here — those tables
# are meant to hold MANY active rows per subsystem (a whole set of threats),
# so "only one active row" would be the wrong rule for them. Their own safety
# net against a duplicate/retried write is a different mechanism (an epoch
# compare-and-swap), not this uniqueness check.
# ============================================================================
ACTIVE_UNIQUE = [
    (m.Subsystem_Profile, ["SessionID", "SubsystemID"]),
    (m.Threat_Scenario_Output, ["SessionID", "ScopedThreatID"]),
]


class StartupInvariantError(RuntimeError):
    """Raised when any check above fails. The app is expected to let this
    exception propagate all the way up and crash the boot process — that's
    the whole point: refuse to start rather than start broken."""


def verify_startup(engine: Engine) -> None:
    """THE ENTRY POINT — this is the one function everything else in this file
    exists to support. Call it once, at boot (and in CI).

    Step by step:
      1. If we're talking to real MSSQL, run checklist 1 (does every required
         index exist, on the right table, over the right columns, UNIQUE?) and
         checklist 2 (NOT-NULL columns really are NOT NULL?). Both are gated on
         MSSQL because they assert the PRODUCTION schema, and the SQLite test
         database is a hand-built fixture — asserting the fixture against
         itself would prove nothing (see the module docstring).
      2. ALWAYS run checklist 3 (no duplicate "active" rows) — this one works
         identically on SQLite and MSSQL since it's just a plain COUNT/GROUP BY
         query, no dialect-specific system tables involved. This is why it's
         the only check exercised by the SQLite-based automated test suite.

    If any single check fails, a StartupInvariantError is raised and the caller
    (the FastAPI app's startup hook, or the Celery worker's boot hook) is
    expected to let the whole process die rather than catch it and continue.
    """
    if engine.dialect.name == "mssql":
        _assert_indexes(engine)
        _assert_not_null(engine)
    _assert_no_duplicate_active(engine)


class LiveIndex(NamedTuple):
    """One index as it ACTUALLY exists in the database right now, read back
    from the server's own catalog — the thing an `IndexSpec` is compared to."""

    table: str
    columns: tuple[str, ...]
    unique: bool


class IndexDrift(NamedTuple):
    """Everything wrong with the live indexes, sorted into the three kinds of
    wrong, because each one means a different thing went wrong and needs a
    different fix:

      * `missing`     — the name isn't in the database at all. A migration
                        never ran. Fix: run migrations / bootstrap_schema.sql.
      * `wrong_shape` — the name IS there, but on another table or over other
                        columns. Somebody built it by hand, or it predates a
                        column rename. Fix: rebuild it (migration 0019).
      * `not_unique`  — right name, right columns, but created without UNIQUE,
                        so it enforces NOTHING and every insert the app expects
                        the database to reject is silently accepted. Fix:
                        rebuild it (migration 0019).
    """

    missing: list[IndexSpec]
    wrong_shape: list[tuple[IndexSpec, tuple[LiveIndex, ...]]]
    not_unique: list[IndexSpec]

    def __bool__(self) -> bool:
        return bool(self.missing or self.wrong_shape or self.not_unique)


# Every named index in the database, with the table it sits on, its key columns
# in declared order, and whether it is UNIQUE.
#
# `is_included_column = 0 AND key_ordinal > 0` is what makes this the KEY of the
# index and nothing else. Two different things hide in sys.index_columns that are
# not part of the rule the index enforces: INCLUDE columns (payload carried for
# covering reads), and — the subtle one — the clustering-key columns SQL Server
# silently appends to a UNIQUE nonclustered index, which come back with
# is_included_column = 0 and key_ordinal = 0. Without the key_ordinal filter,
# every unique index on a table with a clustered primary key reads back with
# extra trailing columns and is declared drifted: a boot failure on a database
# that is perfectly correct.
_MSSQL_INDEX_CATALOG = text(
    "SELECT i.name AS index_name, t.name AS table_name, i.is_unique AS is_unique, "
    "       c.name AS column_name, ic.key_ordinal AS key_ordinal "
    "FROM sys.indexes i "
    "JOIN sys.tables t ON t.object_id = i.object_id "
    "JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id "
    "JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id "
    "WHERE i.name IS NOT NULL AND ic.is_included_column = 0 AND ic.key_ordinal > 0 "
    "ORDER BY i.name, ic.key_ordinal"
)

# The same read for SQLite. Production is always MSSQL, but the whole automated
# test suite runs on SQLite — without this, CHECKLIST 1 would have no test
# coverage at all, which is precisely how a wrong-shaped index reached a
# deployed database unnoticed in the first place.
_SQLITE_INDEX_CATALOG = text(
    "SELECT il.name AS index_name, m.name AS table_name, il.[unique] AS is_unique, "
    "       ii.name AS column_name, ii.seqno AS key_ordinal "
    "FROM sqlite_master m "
    "JOIN pragma_index_list(m.name) il "
    "JOIN pragma_index_info(il.name) ii "
    "WHERE m.type = 'table' AND il.origin = 'c' AND ii.name IS NOT NULL "
    "ORDER BY il.name, ii.seqno"
)


def read_index_catalog(conn) -> dict[str, list[LiveIndex]]:
    """Ask the database itself what indexes it really has.

    Keyed by index NAME, and the value is a LIST because an index name is only
    unique per-table in SQL Server — the same name can legitimately sit on two
    different tables, and "the right name, but on the wrong table" is one of
    the exact failures this file exists to catch, so we have to see all of them.

    Public (not `_`-prefixed) on purpose: migration 0019 reads the live catalog
    through this same function, so a repair decides "has this drifted?" using
    the identical query the boot check uses to decide "is this broken?".
    """
    dialect = conn.engine.dialect.name
    sql = _SQLITE_INDEX_CATALOG if dialect == "sqlite" else _MSSQL_INDEX_CATALOG
    ordered: dict[tuple[str, str], list[tuple[int, str]]] = {}
    unique: dict[tuple[str, str], bool] = {}
    for row in conn.execute(sql).mappings():
        key = (row["index_name"], row["table_name"])
        ordered.setdefault(key, []).append((row["key_ordinal"], row["column_name"]))
        unique[key] = bool(row["is_unique"])
    catalog: dict[str, list[LiveIndex]] = {}
    for (index_name, table_name), cols in ordered.items():
        catalog.setdefault(index_name, []).append(
            LiveIndex(table_name, tuple(col for _, col in sorted(cols)), unique[(index_name, table_name)])
        )
    return catalog


def diff_index_catalog(catalog: dict[str, list[LiveIndex]],
                       specs: list[IndexSpec] | None = None) -> IndexDrift:
    """Compare what the database HAS against what the code NEEDS — a pure
    function over the catalog dict, so the comparison itself is unit-testable
    without a database of any flavour.

    Identifier comparison is case-insensitive because SQL Server's default
    collation treats `SectorID` and `sectorid` as the same column; raising a
    boot failure over letter case would be a false alarm that teaches operators
    to ignore this check.
    """
    specs = REQUIRED_INDEXES if specs is None else specs
    lowered = {name.casefold(): placements for name, placements in catalog.items()}
    missing: list[IndexSpec] = []
    wrong_shape: list[tuple[IndexSpec, tuple[LiveIndex, ...]]] = []
    not_unique: list[IndexSpec] = []
    for spec in specs:
        placements = lowered.get(spec.name.casefold())
        if not placements:
            missing.append(spec)
            continue
        matched = [p for p in placements
                   if p.table.casefold() == spec.table.casefold()
                   and tuple(c.casefold() for c in p.columns) == tuple(c.casefold() for c in spec.columns)]
        if not matched:
            wrong_shape.append((spec, tuple(placements)))
        elif spec.unique and not any(p.unique for p in matched):
            not_unique.append(spec)
    return IndexDrift(missing, wrong_shape, not_unique)


def _assert_indexes(engine: Engine) -> None:
    """Runs CHECKLIST 1. How it works: ask the database's own catalog for every
    index that currently exists — its name, the table it sits on, its key
    columns in order, and whether it is UNIQUE — then compare that against
    `REQUIRED_INDEXES` above. Anything that doesn't line up stops the boot with
    a message naming the index, what the code needs, and what is actually there,
    so whoever reads it knows both what is wrong and which fix to run.

    Every failing index is reported at once, not just the first one: an operator
    fixing a broken deployment should get the whole list in one restart, not
    discover the next problem only after fixing this one.
    """
    with engine.connect() as c:
        drift = diff_index_catalog(read_index_catalog(c))
    if not drift:
        return
    problems: list[str] = []
    if drift.missing:
        problems.append(
            "missing required indexes (run migrations): "
            f"{[s.name for s in drift.missing]}"
        )
    if drift.wrong_shape:
        problems.append(
            "required indexes exist under the right name but on the wrong table/columns: "
            + "; ".join(
                f"{spec.name} needs {spec.describe()} but found "
                + " and ".join(f"{p.table}({', '.join(p.columns)})" for p in found)
                for spec, found in drift.wrong_shape
            )
        )
    if drift.not_unique:
        problems.append(
            "required indexes exist but are NOT UNIQUE, so they enforce nothing: "
            f"{[s.name for s in drift.not_unique]}"
        )
    raise StartupInvariantError(
        " | ".join(problems)
        + " — run `alembic upgrade head` (migration 0019 rebuilds a drifted guard index)"
        " or re-run scripts/bootstrap_schema.sql"
    )


def _assert_not_null(engine: Engine) -> None:
    """Runs CHECKLIST 2. How it works: for every (table, column) pair in
    `REQUIRED_NOT_NULL` above, ask SQL Server's own metadata
    (`INFORMATION_SCHEMA.COLUMNS`) whether that column is nullable. Two ways
    this can fail:
      - the column doesn't exist at all (e.g. the whole table is missing,
        like `Threat_Candidate_Review` would be if its migration never ran)
        → `nullable` comes back as `None`, and we raise "missing column".
      - the column DOES exist, but it's still marked nullable in the real
        schema (e.g. someone forgot to add the `NOT NULL` constraint when
        writing the migration) → we raise "must be NOT NULL".
    Either way, the app won't start until the real database schema actually
    matches what the code assumes.
    """
    with engine.connect() as c:
        for table, col in REQUIRED_NOT_NULL:
            nullable = c.execute(
                text(
                    "SELECT is_nullable FROM INFORMATION_SCHEMA.COLUMNS "
                    "WHERE TABLE_NAME = :t AND COLUMN_NAME = :col"
                ),
                {"t": table, "col": col},
            ).scalar()
            if nullable is None:
                raise StartupInvariantError(f"missing column {table}.{col}")
            if str(nullable).upper() in ("YES", "1", "TRUE"):
                raise StartupInvariantError(f"{table}.{col} must be NOT NULL (M3/[R7])")


def _assert_no_duplicate_active(engine: Engine) -> None:
    """Runs CHECKLIST 3 (the only one of the three that ALSO runs during the
    SQLite-based test suite — see `verify_startup` above). How it works: for
    each (table, grouping columns) pair in `ACTIVE_UNIQUE` above, run a query
    that groups all "still active" rows (`Superseded = 0`) by that grouping
    key and counts how many rows land in each group. If any group has MORE
    THAN ONE row in it, that's a live bug — two rows are simultaneously
    claiming to be "the current" profile/scenario for the same
    session+subsystem, which is a state nothing else in the app expects to
    ever see. The app refuses to start (or the CI check fails) with a message
    naming exactly which table and how many offending groups were found.
    """
    with engine.connect() as c:
        for table, cols in ACTIVE_UNIQUE:
            grp = ", ".join(cols)
            dupes = c.execute(
                text(
                    f"SELECT COUNT(*) FROM (SELECT {grp} FROM {table.name} "
                    f"WHERE Superseded = 0 GROUP BY {grp} HAVING COUNT(*) > 1) d"
                )
            ).scalar()
            if dupes:
                raise StartupInvariantError(
                    f"{table.name}: {dupes} ({grp}) groups have >1 active row (INV-2)"
                )
