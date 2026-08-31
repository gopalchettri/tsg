"""bootstrap_schema.sql <-> models.py <-> invariants.py sync guard.

bootstrap_schema.sql is the one-stop production script — the ONLY thing that
creates the baseline TSG tables (alembic 0001 is an empty stamp; the chain only
alters forward). So every column models.py declares on a TSG-owned table must
appear in the script's CREATE TABLE block, or a production DB is born missing a
column the app selects (`select(m.Identified_Threat)` names every declared
column). Third recurrence of this gap class caught in this repo — AttemptCount
(SDD), SectorIDsJSON (docs), EntityID (bootstrap) — this test ends the pattern.

The same gap class then recurred one level down, on INDEXES rather than columns:
a database can hold an index with a required name built over the wrong columns,
which is worse than not having it at all — it looks present to every name-only
check while enforcing a rule no code asked for. `invariants.REQUIRED_INDEXES` is
now the single definition of each guard index's full shape, so the second half
of this file asserts that every other place those indexes are written out —
the production script and the SQLite test harness — still says the same thing.
"""
import re
from pathlib import Path

from app.db import models as m
from app.db.invariants import REQUIRED_INDEXES

_ROOT = Path(__file__).resolve().parents[1]
_SQL = (_ROOT / "scripts" / "bootstrap_schema.sql").read_text(encoding="utf-8")
_CONFTEST = (_ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")

# Platform-owned tables the script deliberately does not create (SDD §7.7).
_PLATFORM = {"group", "onboarding_sectors", "ctm_scan_entity", "onboarding_service_entity",
             "ctm_scan_entity_supporting_system", "onboarding_supporting_systems"}


def _create_block(table_name: str) -> str:
    match = re.search(rf"CREATE TABLE {table_name} \((.*?)^\);", _SQL, re.S | re.M)
    assert match, f"bootstrap_schema.sql has no CREATE TABLE for {table_name}"
    return match.group(1)


def test_bootstrap_schema_covers_every_model_column():
    for table in m.metadata.tables.values():
        if table.name in _PLATFORM:
            continue
        block = _create_block(table.name)
        missing = [col.name for col in table.columns
                   if not re.search(rf"^\s*{col.name}\s", block, re.M)]
        assert not missing, f"bootstrap_schema.sql CREATE TABLE {table.name} is missing columns: {missing}"


# --- guard-index sync: invariants.py <-> bootstrap_schema.sql <-> conftest.py ---
def _normalize(sql: str) -> str:
    """One comparable form for the same CREATE statement written three ways:
    bare in T-SQL, with quoted identifiers in the SQLite harness, and inside a
    Python string literal (where the harness's `'active'` carries backslashes)."""
    return re.sub(r"\s+", " ", sql.replace('"', "").replace("\\", "")).strip().rstrip(";")


def test_bootstrap_creates_every_required_index_with_the_required_shape():
    # A guard index the boot check demands but the production script never
    # creates = a database that can never be brought up by the documented path.
    missing = [spec.name for spec in REQUIRED_INDEXES
               if _normalize(spec.ddl()) not in _normalize(_SQL)]
    assert not missing, (
        f"bootstrap_schema.sql does not create these exactly as REQUIRED_INDEXES declares "
        f"them (name, table, columns in order, UNIQUE, filter): {missing}"
    )


def test_sqlite_harness_builds_every_required_index_with_the_required_shape():
    # If the harness and the specs disagree, every SQLite test is asserting
    # against a schema production will never have — the drift becomes invisible.
    missing = [spec.name for spec in REQUIRED_INDEXES
               if _normalize(spec.ddl()) not in _normalize(_CONFTEST)]
    assert not missing, (
        f"tests/conftest.py does not build these exactly as REQUIRED_INDEXES declares them: {missing}"
    )


def test_bootstrap_shape_repair_table_matches_required_indexes():
    """Section 3b drops any guard index whose live shape has drifted, driven by a
    #GuardIndex spec table written out in T-SQL. It can only repair what it knows
    about, so it has to name exactly the same set REQUIRED_INDEXES does."""
    block = re.search(r"INSERT INTO #GuardIndex .*?VALUES(.*?);", _SQL, re.S)
    assert block, "bootstrap_schema.sql Section 3b has no #GuardIndex spec table"
    rows = {name: (table, cols) for name, table, cols in
            re.findall(r"\('(\w+)',\s*'(\w+)',\s*'([\w,]+)'\)", block.group(1))}
    expected = {spec.name: (spec.table, ",".join(spec.columns)) for spec in REQUIRED_INDEXES}
    assert rows == expected, (
        "bootstrap_schema.sql Section 3b's #GuardIndex table has drifted from "
        "invariants.REQUIRED_INDEXES — the repair would silently skip an index"
    )
