"""TSG_Core.sql <-> models.py sync guard.

TSG_Core.sql is the one-stop production script — the ONLY thing that
creates the baseline TSG tables (alembic 0001 is an empty stamp; the chain only
alters forward). So every column models.py declares on a TSG-owned table must
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
