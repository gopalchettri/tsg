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
no real database needed), but SQLite doesn't have the same system tables
(`sys.indexes`, `INFORMATION_SCHEMA`) that real SQL Server has. So the
index/NOT-NULL checks below only run when the app is actually talking to
MSSQL; they're skipped during SQLite-based tests, where they wouldn't make
sense anyway.
"""
from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.engine import Engine

from app.db import models as m

# ============================================================================
# CHECKLIST 1 — "did the database actually get its safety locks installed?"
#
# Each name below is a UNIQUE INDEX: a rule you tell the database to enforce
# FOR you, so the database itself refuses bad data, instead of trusting the
# application code to always remember to check. These indexes are created by
# separate migration scripts (not by this file) — this file only checks that
# they actually exist before the app is allowed to start.
#
# CONCRETE EXAMPLE of what one of these prevents: `UX_Session_ActiveAsset`
# stops two people from clicking "start a new session" on the exact same
# asset at the exact same moment and ending up with two active sessions
# running simultaneously, stepping on each other's data. Without the index,
# the database would happily accept both inserts.
#
# This list grows by one line every time a new milestone adds a new index the
# code now depends on.
# ============================================================================
REQUIRED_INDEXES = [
    # One active session per asset / one active scenario per scoped threat. Stops
    # duplicate "current" rows from a retried or racing request.
    "UX_Session_ActiveAsset", "UX_Scenario_ActiveIdentity",
    # Master-library natural-key UNIQUE. Stops two people accepting sessions at
    # the same moment from both creating a DUPLICATE "Ransomware via USB"
    # threat type in the shared library (safe concurrent promotion, R10).
    "UX_ThreatType_NaturalKey", "UX_ThreatCatalogue_NaturalKey", "UX_ThreatActor_NaturalKey",
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
#   - Threat_Scenario_Output: one active scenario per (session, scoped threat)
# Identified_Threat / Scoped_Threat are deliberately NOT here — those tables
# are meant to hold MANY active rows per subsystem (a whole set of threats),
# so "only one active row" would be the wrong rule for them. Their own safety
# net against a duplicate/retried write is a different mechanism (an epoch
# compare-and-swap), not this uniqueness check.
# ============================================================================
ACTIVE_UNIQUE = [
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
      1. If we're talking to real MSSQL, run checklist 1 (indexes exist?) and
         checklist 2 (NOT-NULL columns really are NOT NULL?). These need
         MSSQL's system tables, so they're skipped entirely on SQLite (where
         those system tables don't exist in the same form — running the tests
         there would either error out or trivially always pass, neither of
         which tells us anything useful).
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


def _assert_indexes(engine: Engine) -> None:
    """Runs CHECKLIST 1. How it works: ask SQL Server's own system catalog
    (`sys.indexes`) for the names of every index that currently exists in the
    database, then compare that list against `REQUIRED_INDEXES` above. Any
    name in `REQUIRED_INDEXES` that ISN'T in the real database gets collected
    into `missing`, and if that list is non-empty, the app refuses to boot
    with a clear error message naming exactly which index(es) are missing —
    so whoever sees the error knows precisely which migration didn't run.
    """
    with engine.connect() as c:
        present = {
            r[0] for r in c.execute(text("SELECT name FROM sys.indexes WHERE name IS NOT NULL"))
        }
    missing = [ix for ix in REQUIRED_INDEXES if ix not in present]
    if missing:
        raise StartupInvariantError(f"missing required indexes (run migrations): {missing}")


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
