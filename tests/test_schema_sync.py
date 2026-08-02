"""TSG_Core.sql <-> models.py sync guard.

TSG_Core.sql is the one-stop production script — the ONLY thing that
creates the baseline TSG tables. (Alembic was removed 2026-07-25; this project is
database-first, so THIS test is now the only automated guard that a hand-built
production DB isn't born missing a column.) So every column models.py declares on a TSG-owned table must
appear in the script's CREATE TABLE block, or a production DB is born missing a
column the app selects (`select(m.Identified_Threat)` names every declared
column). Third recurrence of this gap class caught in this repo — AttemptCount
(SDD), SectorIDsJSON (docs), EntityID (bootstrap) — this test ends the pattern.

Formerly two separately-maintained files (bootstrap_schema.sql +
production_setup.sql, merged 2026-07-19): production_setup.sql's own header
said its Section 1 was "byte-for-byte" the same as bootstrap_schema.sql's
CREATE TABLE blocks, kept in sync manually — and documents/TSG_Gap_Analysis.md
§13.14 records that manual-sync discipline had already drifted silently once
(a prior audit found this test only ever checked bootstrap_schema.sql). One
file removes that drift risk structurally instead of re-documenting it.
"""
import re
from pathlib import Path

import pytest

from app.db import models as m

_SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
_SQL_FILES = ["TSG_Core.sql"]

# Platform-owned tables the script deliberately does not create (SDD §7.7).
_PLATFORM = {"group", "user", "onboarding_sectors", "ctm_scan_entity", "onboarding_service_entity",
             "ctm_scan_entity_supporting_system", "onboarding_supporting_systems",
             "onboarding_services", "option", "option_value", "ctm_scan_category",
             "ctm_scan_entity_bu"}

# TSG-owned tables deliberately created OUTSIDE TSG_Core.sql — their own standalone,
# independently-run administrative script instead (never a platform table, just not bundled
# into schema stand-up). Both are schema-only here; their real seed data (Config_Threat_Rule's
# 21 asset_type rules, Threat_Catalogue_Category_Map's 346 links) lives in
# scripts/Seed_to_Threat_library.sql instead.
_DEPLOYED_SEPARATELY = {
    "Config_Threat_Rule": "Threat_library.sql",
    "Threat_Catalogue_Category_Map": "Threat_library.sql",
    "Context_Field_Config": "Threat_library.sql",
    "Control_Standard": "Control_library.sql",
    "Control_Library": "Control_library.sql",
    "Control_Library_Standard_Map": "Control_library.sql",
}

# TSG-owned COLUMNS retrofitted onto a table that otherwise IS created here — narrower than
# _DEPLOYED_SEPARATELY above, which skips a whole table. Threat_Type/Threat_Catalogue's own
# CREATE TABLE lives in TSG_Core.sql as normal; only their Source column is added later, by
# Threat_library.sql's ALTER TABLE.
_COLUMN_DEPLOYED_SEPARATELY = {
    ("Threat_Type", "Source"): "Threat_library.sql",
    ("Threat_Catalogue", "Source"): "Threat_library.sql",
}


def _create_block(sql: str, sql_filename: str, table_name: str) -> str:
    match = re.search(rf"CREATE TABLE {table_name} \((.*?)^\);", sql, re.S | re.M)
    assert match, f"{sql_filename} has no CREATE TABLE for {table_name}"
    return match.group(1)


@pytest.mark.parametrize("sql_filename", _SQL_FILES)
def test_sql_script_covers_every_model_column(sql_filename):
    sql = (_SCRIPTS_DIR / sql_filename).read_text(encoding="utf-8")
    for table in m.metadata.tables.values():
        if table.name in _PLATFORM or table.name in _DEPLOYED_SEPARATELY:
            continue
        block = _create_block(sql, sql_filename, table.name)
        missing = [col.name for col in table.columns
                   if (table.name, col.name) not in _COLUMN_DEPLOYED_SEPARATELY
                   and not re.search(rf"^\s*{col.name}\s", block, re.M)]
        assert not missing, f"{sql_filename} CREATE TABLE {table.name} is missing columns: {missing}"


def test_separately_deployed_tables_covered_in_their_own_script():
    """Same column-coverage guarantee as above, for the table(s) intentionally excluded
    from TSG_Core.sql — a production DB should never end up missing a column here just
    because it's created in a different file."""
    for table_name, sql_filename in _DEPLOYED_SEPARATELY.items():
        sql = (_SCRIPTS_DIR / sql_filename).read_text(encoding="utf-8")
        table = m.metadata.tables[table_name]
        block = _create_block(sql, sql_filename, table_name)
        missing = [col.name for col in table.columns
                   if not re.search(rf"^\s*{col.name}\s", block, re.M)]
        assert not missing, f"{sql_filename} CREATE TABLE {table_name} is missing columns: {missing}"


def test_separately_deployed_columns_covered_in_their_own_script():
    """Same guarantee as above, one level narrower — for individual columns retrofitted
    onto an otherwise-here-created table by ALTER TABLE in a separate script (Source on
    Threat_Type/Threat_Catalogue today) — a production DB should never end up missing one
    of these just because it's added outside the table's own CREATE TABLE."""
    for (table_name, col_name), sql_filename in _COLUMN_DEPLOYED_SEPARATELY.items():
        sql = (_SCRIPTS_DIR / sql_filename).read_text(encoding="utf-8")
        assert re.search(rf"ALTER TABLE {table_name} ADD {col_name}\b", sql), \
            f"{sql_filename} does not add {table_name}.{col_name}"


def test_autoincrement_inference_matches_the_ddl():
    """SQLAlchemy's inferred autoincrement column must match an actual IDENTITY in the DDL.

    SQLAlchemy treats a lone integer PK as the autoincrement column unless told otherwise. On
    MSSQL that inference is not cosmetic: an INSERT that supplies the column makes the dialect
    emit `SET IDENTITY_INSERT <table> ON`, which SQL Server rejects with Msg 8106 on a table that
    has no identity column — surfacing as a raw 500 (a ProgrammingError, so not even the
    IntegrityError the CRUD layer converts to a 409).

    Nothing else can catch this: the whole suite runs on SQLite, whose dialect has no
    IDENTITY_INSERT logic at all, so the endpoint returns 201 in CI and 500 in production. That is
    exactly how Threat_Category shipped broken (its PK is a plain caller-supplied int, and the
    DDL comment "app never inserts it" stopped being true when the CRUD create endpoint landed).
    Assert the model and the DDL agree instead of trusting a comment.
    """
    sql = "\n".join((_SCRIPTS_DIR / f).read_text(encoding="utf-8")
                    for f in [*_SQL_FILES, *sorted(set(_DEPLOYED_SEPARATELY.values()))])
    mismatched = []
    for table in m.metadata.tables.values():
        if table.name in _PLATFORM:
            continue
        col = table._autoincrement_column
        if col is None:
            continue                      # explicit autoincrement=False, or a non-int/composite PK
        block = re.search(rf"CREATE TABLE {table.name} \((.*?)^\);", sql, re.S | re.M)
        if block is None:
            continue                      # covered by the table-coverage tests above
        declared = re.search(rf"^\s*{col.name}\s+.*IDENTITY", block.group(1), re.M | re.I)
        if not declared:
            mismatched.append(f"{table.name}.{col.name}")
    assert not mismatched, (
        "models.py infers these as autoincrement but the DDL has no IDENTITY — they will emit "
        f"SET IDENTITY_INSERT and fail on MSSQL. Add autoincrement=False: {mismatched}")


def test_every_boot_required_index_has_a_create_statement():
    """invariants.REQUIRED_INDEXES is boot-BLOCKING: a name listed there but never created by the
    install scripts means the API and every Celery worker refuse to start, in production only.

    Nothing else catches that. The index checks in invariants.py run on the mssql dialect alone,
    so the SQLite suite skips them entirely, and tests/test_invariants.py builds its fixtures FROM
    REQUIRED_INDEXES — it can only prove the comparison logic works, never that the DDL agrees.
    This is the index-side twin of the column coverage test above.
    """
    from app.db.invariants import REQUIRED_INDEXES

    sql = "\n".join((_SCRIPTS_DIR / f).read_text(encoding="utf-8")
                    for f in ["TSG_Core.sql", "Threat_library.sql", "Control_library.sql"])
    missing = [name for name, _table, _cols in REQUIRED_INDEXES
            if not re.search(rf"CREATE\s+UNIQUE\s+INDEX\s+{name}\b", sql, re.I)]
    assert not missing, (
        "boot-required indexes with no CREATE in the install scripts — the app would refuse to "
        f"start against a freshly built database: {missing}")
