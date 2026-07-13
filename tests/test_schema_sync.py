"""bootstrap_schema.sql / production_setup.sql <-> models.py sync guard.

bootstrap_schema.sql is the one-stop production script — the ONLY thing that
creates the baseline TSG tables (alembic 0001 is an empty stamp; the chain only
alters forward). So every column models.py declares on a TSG-owned table must
appear in the script's CREATE TABLE block, or a production DB is born missing a
column the app selects (`select(m.Identified_Threat)` names every declared
column). Third recurrence of this gap class caught in this repo — AttemptCount
(SDD), SectorIDsJSON (docs), EntityID (bootstrap) — this test ends the pattern.

production_setup.sql's own header says its Section 1 is "byte-for-byte" the
same as bootstrap_schema.sql's CREATE TABLE blocks, kept in sync manually — so
this test runs the identical check against both files (documents/
TSG_Gap_Analysis.md §13.14: a prior audit found this test only ever checked
bootstrap_schema.sql, leaving production_setup.sql free to drift silently).
"""
import re
from pathlib import Path

import pytest

from app.db import models as m

_SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
_SQL_FILES = ["bootstrap_schema.sql", "production_setup.sql"]

# Platform-owned tables the script deliberately does not create (SDD §7.7).
_PLATFORM = {"group", "user", "onboarding_sectors", "ctm_scan_entity", "onboarding_service_entity",
             "ctm_scan_entity_supporting_system", "onboarding_supporting_systems",
             "onboarding_services", "option", "option_value", "ctm_scan_category"}


def _create_block(sql: str, sql_filename: str, table_name: str) -> str:
    match = re.search(rf"CREATE TABLE {table_name} \((.*?)^\);", sql, re.S | re.M)
    assert match, f"{sql_filename} has no CREATE TABLE for {table_name}"
    return match.group(1)


@pytest.mark.parametrize("sql_filename", _SQL_FILES)
def test_sql_script_covers_every_model_column(sql_filename):
    sql = (_SCRIPTS_DIR / sql_filename).read_text(encoding="utf-8")
    for table in m.metadata.tables.values():
        if table.name in _PLATFORM:
            continue
        block = _create_block(sql, sql_filename, table.name)
        missing = [col.name for col in table.columns
                   if not re.search(rf"^\s*{col.name}\s", block, re.M)]
        assert not missing, f"{sql_filename} CREATE TABLE {table.name} is missing columns: {missing}"
