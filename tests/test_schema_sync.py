"""bootstrap_schema.sql <-> models.py sync guard.

bootstrap_schema.sql is the one-stop production script — the ONLY thing that
creates the baseline TSG tables (alembic 0001 is an empty stamp; the chain only
alters forward). So every column models.py declares on a TSG-owned table must
appear in the script's CREATE TABLE block, or a production DB is born missing a
column the app selects (`select(m.Identified_Threat)` names every declared
column). Third recurrence of this gap class caught in this repo — AttemptCount
(SDD), SectorIDsJSON (docs), EntityID (bootstrap) — this test ends the pattern.
"""
import re
from pathlib import Path

from app.db import models as m

_SQL = (Path(__file__).resolve().parents[1] / "scripts" / "bootstrap_schema.sql").read_text(encoding="utf-8")

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
