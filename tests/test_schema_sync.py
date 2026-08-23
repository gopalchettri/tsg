"""The guard `app/db/models.py` has always named but which never existed.

models.py cites `test_schema_sync` and its `_DEPLOYED_SEPARATELY` / `_COLUMN_DEPLOYED_SEPARATELY`
allowlists in three places (around the Threat_Scenario_Control_Map, Control_Library and
Threat_Type definitions). A whole-tree search found only those three prose references: the file
was never written, or was deleted without updating them.

What it protects, in scripts/TSG_Core.sql's own words:

    "Keep in lockstep with models.py: a new column needs a CREATE TABLE entry (fresh DB) AND a
     guarded ALTER below it (existing DB)."

Nothing enforced that. Adding a column to models.py and forgetting the DDL produces an app that
imports cleanly, passes every other test (the suite runs on SQLite, which is built from the
models themselves), and then fails against SQL Server at runtime with "Invalid column name".

This is a STATIC check — it reads the .sql files, so CI can run it with no database.
`db.invariants._assert_mapped_columns_exist` covers the same ground at boot, but only once a
live SQL Server is reachable, which is far too late to be a development guard.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.db import models as m

_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"

#: Tables the PLATFORM owns and deploys — TSG maps them read-only for context (see the
#: "Context (platform-owned, read-only)" banner in models.py) and its scripts must never
#: create or alter them. Their DDL lives in the host product, not this repo.
_DEPLOYED_SEPARATELY = frozenset({
    "user", "user_scope_assignment",
    "onboarding_sectors", "onboarding_services", "onboarding_supporting_systems",
    "ctm_scan_entity", "ctm_scan_entity_bu", "ctm_scan_entity_supporting_system",
    "ctm_scan_category",
    "option", "option_value",
})

#: Individual columns deployed outside this repo's scripts, as "Table.Column". Empty today.
#: Prefer adding the DDL over adding an entry here — every entry is a hole in the guard.
_COLUMN_DEPLOYED_SEPARATELY: frozenset[str] = frozenset()

#: SQL Server type names that can open a column definition. Used to tell a column line apart
#: from a CONSTRAINT/INDEX line inside a CREATE TABLE body.
_TYPES = (r"n?varchar|n?char|int|bigint|bit|datetime2?|float|real|decimal|numeric"
        r"|uniqueidentifier|tinyint|smallint|date|time|money|n?text|varbinary")


def _sql_text() -> str:
    """Every script concatenated, with `--` line comments stripped so a commented-out ALTER
    cannot masquerade as deployed DDL."""
    joined = "\n".join(p.read_text(encoding="utf-8", errors="replace")
                    for p in sorted(_SCRIPTS.glob("*.sql")))
    return re.sub(r"--[^\n]*", "", joined)


def _ddl_columns() -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """(columns from CREATE TABLE, columns from guarded ALTER ... ADD), keyed by table."""
    sql = _sql_text()
    created: dict[str, set[str]] = {}
    for mt in re.finditer(r"CREATE\s+TABLE\s+(?:dbo\.)?\[?(\w+)\]?\s*\((.*?)\n\s*\)\s*;",
                        sql, re.S | re.I):
        cols = set()
        for line in mt.group(2).splitlines():
            hit = re.match(rf"\[?(\w+)\]?\s+\[?(?:{_TYPES})\b", line.strip(), re.I)
            if hit and hit.group(1).upper() not in (
                    "CONSTRAINT", "PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "INDEX"):
                cols.add(hit.group(1))
        created.setdefault(mt.group(1), set()).update(cols)

    altered: dict[str, set[str]] = {}
    for at in re.finditer(r"ALTER\s+TABLE\s+(?:dbo\.)?\[?(\w+)\]?\s+ADD\s+\[?(\w+)\]?", sql, re.I):
        altered.setdefault(at.group(1), set()).add(at.group(2))
    return created, altered


def _tsg_owned() -> list[type]:
    return [mp.class_ for mp in m.Base.registry.mappers
            if mp.class_.__tablename__ not in _DEPLOYED_SEPARATELY]


# --- the guard must not be able to pass VACUOUSLY ---------------------------------------------------
# A parser that silently stops matching would make every assertion below trivially true, which is
# strictly worse than having no guard at all. These pin the parser itself.
def test_parser_finds_the_ddl() -> None:
    created, altered = _ddl_columns()
    assert len(created) >= 20, f"only parsed {len(created)} CREATE TABLEs — the regex has drifted"
    assert sum(len(v) for v in altered.values()) >= 20, "ALTER ... ADD parsing has drifted"


def test_parser_finds_known_landmark_columns() -> None:
    """Specific columns whose presence proves both halves of the parser still work: one declared
    in a CREATE TABLE body, one added only by a guarded ALTER."""
    created, altered = _ddl_columns()
    assert "SessionID" in created.get("Scenario_Session", set())
    assert "PromotionFailedAt" in altered.get("Scenario_Session", set()), (
        "guarded-ALTER parsing broke: PromotionFailedAt is added by ALTER, not CREATE TABLE")


def test_allowlist_has_no_stale_entries() -> None:
    """An allowlisted table that no longer exists in models.py is a hole nobody is watching."""
    mapped = {mp.class_.__tablename__ for mp in m.Base.registry.mappers}
    stale = _DEPLOYED_SEPARATELY - mapped
    assert not stale, f"_DEPLOYED_SEPARATELY names tables that are no longer mapped: {sorted(stale)}"


# --- the actual invariant -----------------------------------------------------------------------------
@pytest.mark.parametrize("cls", _tsg_owned(), ids=lambda c: c.__tablename__)
def test_every_mapped_column_exists_in_the_sql(cls: type) -> None:
    """A column in models.py with no DDL passes the whole SQLite suite and then fails on SQL
    Server with "Invalid column name" — at runtime, in production."""
    created, altered = _ddl_columns()
    table = cls.__tablename__
    deployed = created.get(table, set()) | altered.get(table, set())
    assert deployed, (
        f"{table} is mapped in models.py but no scripts/*.sql CREATE TABLE or ALTER mentions it. "
        f"Add the DDL, or add it to _DEPLOYED_SEPARATELY if the platform owns it.")

    mapped = {c.name for c in cls.__table__.columns}
    gap = {c for c in mapped - deployed if f"{table}.{c}" not in _COLUMN_DEPLOYED_SEPARATELY}
    assert not gap, (
        f"{table}: mapped in models.py but absent from scripts/*.sql: {sorted(gap)}. "
        f"Per scripts/TSG_Core.sql, a new column needs a CREATE TABLE entry (fresh DB) and a "
        f"guarded ALTER (existing DB).")


def test_alter_statements_target_tables_this_repo_creates() -> None:
    """The reverse direction: an ALTER against an unknown table is a typo that silently no-ops —
    the IF OBJECT_ID(...) guard swallows it — so the column never appears and nothing complains."""
    created, altered = _ddl_columns()
    orphans = {t for t in altered if t not in created and t not in _DEPLOYED_SEPARATELY}
    assert not orphans, (
        f"ALTER ... ADD targets tables with no CREATE TABLE in scripts/: {sorted(orphans)}. "
        f"The IF OBJECT_ID(...) guard makes a misspelled table name a silent no-op.")
