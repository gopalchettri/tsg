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

# The DEPLOYED scripts are the single source of truth since the 2026-08 dedup of
# scripts/ vs scripts/eyshield_handoff/ — the numbered handoff copies are what a DBA
# actually runs, so they are what the code must stay in lockstep with.
_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts" / "eyshield_handoff"

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


def _sql_text(paths=None) -> str:
    """Every script concatenated, with `--` line comments stripped so a commented-out ALTER
    cannot masquerade as deployed DDL. Default corpus: the numbered handoff scripts."""
    joined = "\n".join(p.read_text(encoding="utf-8", errors="replace")
                    for p in (sorted(_SCRIPTS.glob("*.sql")) if paths is None else paths))
    return re.sub(r"--[^\n]*", "", joined)


def _ddl_columns(paths=None) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """(columns from CREATE TABLE, columns from guarded ALTER ... ADD), keyed by table."""
    sql = _sql_text(paths)
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
    assert "ThreatCatalogueID" in altered.get("Identified_Threat", set()), (
        "guarded-ALTER parsing broke: ThreatCatalogueID is added by ALTER too, not only "
        "CREATE TABLE")


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


# ---------------------------------------------------------------------------
# INDEX DEFINITIONS — the same lockstep guard, for indexes rather than columns.
#
# Written after a real incident: the natural-key indexes were narrowed to name-only in the DDL
# while invariants.REQUIRED_INDEXES still declared the old three-column form. Nothing compared
# them, so the first symptom would have been the APPLICATION REFUSING TO BOOT against a correctly
# migrated database — invariants asserts ordered columns and fails startup on a mismatch.
#
# The same column list is declared in three places, and all three must agree:
#   1. scripts/*.sql            CREATE UNIQUE INDEX ... (what actually gets built)
#   2. app/db/invariants.py     REQUIRED_INDEXES       (asserted at boot; wrong => no boot)
#   3. scripts/TSG_Verify.sql   @req_indexes           (wrong => a false PASS at sign-off)
#
# The FOURTH site — the IntegrityError recovery predicates in dal.upsert_threat_type /
# upsert_threat_catalogue, which must select on exactly the index's columns or a duplicate
# becomes a 500 — is covered behaviourally by
# test_dal_upsert_threat_type_collision.test_integrity_error_recovery_returns_the_existing_winner
# and test_promote_scenario_library.test_cross_type_name_collision_recovers_to_existing_row.
# ---------------------------------------------------------------------------
_CREATE_INDEX_RE = re.compile(
    r"CREATE\s+UNIQUE\s+INDEX\s+(\w+)\s+ON\s+(\w+)\s*\(([^)]*)\)", re.IGNORECASE)
_VERIFY_ROW_RE = re.compile(r"\(N'(UX_\w+)',\s*N'(\w+)',\s*N'([^']*)'\)")


def _ddl_indexes() -> dict[str, tuple[str, tuple[str, ...]]]:
    """{index name: (table, ordered columns)} from every CREATE UNIQUE INDEX in the scripts."""
    found: dict[str, tuple[str, tuple[str, ...]]] = {}
    for sql in _SCRIPTS.glob("*.sql"):
        for name, table, cols in _CREATE_INDEX_RE.findall(sql.read_text(encoding="utf-8", errors="replace")):
            found[name] = (table, tuple(c.strip() for c in cols.split(",") if c.strip()))
    return found


def test_required_indexes_match_the_ddl_that_creates_them() -> None:
    """Every index the app asserts at boot must exist in the DDL with the SAME ordered columns."""
    from app.db import invariants

    ddl = _ddl_indexes()
    mismatched, missing = [], []
    for name, table, cols in invariants.REQUIRED_INDEXES:
        if name not in ddl:
            # Some indexes are created by scripts deployed separately; only flag ones the
            # repo's own scripts are supposed to build.
            missing.append(name)
            continue
        if ddl[name] != (table, tuple(cols)):
            mismatched.append(f"{name}: invariants={table}{tuple(cols)} ddl={ddl[name][0]}{ddl[name][1]}")
    assert not mismatched, (
        "REQUIRED_INDEXES disagrees with the CREATE INDEX statements — the app will refuse to "
        "boot against a database built from these scripts:\n  " + "\n  ".join(mismatched))
    assert not missing, (
        "REQUIRED_INDEXES names indexes no script creates (a fresh install would never boot): "
        + ", ".join(sorted(missing)))


def test_verify_script_expects_the_same_index_columns() -> None:
    """TSG_Verify.sql's expected column lists must match the DDL too, or it signs off an install
    the application then rejects — the one failure mode its own section-3 comment calls
    unacceptable."""
    ddl = _ddl_indexes()
    verify = (_SCRIPTS / "6. TSG_Verify.sql").read_text(encoding="utf-8", errors="replace")
    wrong = []
    for name, table, cols in _VERIFY_ROW_RE.findall(verify):
        expected = tuple(c.strip() for c in cols.split(",") if c.strip())
        if name in ddl and ddl[name] != (table, expected):
            wrong.append(f"{name}: verify={table}{expected} ddl={ddl[name][0]}{ddl[name][1]}")
    assert not wrong, "TSG_Verify.sql disagrees with the DDL:\n  " + "\n  ".join(wrong)


# ---------------------------------------------------------------------------
# FROZEN MASTER TABLES -- the operational constraint, enforced instead of remembered.
#
# The six curated master tables hold data that must survive every deployment and may not be
# altered: the business said so, and until this test the rule lived only in conversation --
# which is exactly how a future edit (or a merge from an older branch) ships an unguarded
# ALTER and mutates a table nobody may touch. Every statement against a frozen table must be
# IDEMPOTENT-GUARDED (IF OBJECT_ID / COL_LENGTH / COLUMNPROPERTY / sys.indexes), so on a
# database that already has the schema it is a provable NO-OP; destructive statements are
# forbidden outright.
# ---------------------------------------------------------------------------
_FROZEN_TABLES = ("Threat_Category", "Threat_Type", "Threat_Catalogue", "Threat_Actor",
                "Control_Library", "Control_Standard")
_GUARD_MARKERS = ("COL_LENGTH", "COLUMNPROPERTY", "OBJECT_ID", "sys.indexes", "IF NOT EXISTS",
                "IF EXISTS")

# The ONLY sanctioned DROP COLUMNs against a frozen table. Keyed per (table, column) rather than
# per table on purpose: approving one removal must not silently authorise the next one on the same
# table. Anything not listed still fails outright -- a future edit that drops a column has to come
# through this list, in review, with a date and a reason.
_APPROVED_COLUMN_DROPS = {
    # 2026-08-30, user instruction ("they are not required"); dev data already deleted.
    ("Threat_Category", "SecurityObjective"),  # no code path ever read it
    ("Threat_Type", "Description"),            # never embedded, never displayed
    # This one DID carry curated data: it was the second half of the embedded passage
    # (embeddings.catalogue_passage_text) and was shown to the validator LLM, and dropping it
    # deletes the 75 seeded scenario descriptions. Catalogue matching is name-only from here, so
    # the stored grounding calibration has to be re-run.
    ("Threat_Catalogue", "Description"),
    # Already unmapped (deliberately, since sector logic was removed 2026-08) before this drop —
    # unlike Description above, dropping it has no functional impact; nothing ever read it.
    ("Threat_Type", "SectorID"),
    ("Threat_Catalogue", "SectorID"),
}


def test_no_destructive_statement_against_a_frozen_table() -> None:
    """Row-destroying statements are forbidden outright; column drops only by explicit approval."""
    seen: set[tuple[str, str]] = set()
    for sql in sorted(_SCRIPTS.glob("*.sql")):
        text = re.sub(r"--[^\n]*", "", sql.read_text(encoding="utf-8", errors="replace"))
        for tbl in _FROZEN_TABLES:
            for verb in (rf"DROP\s+TABLE\s+(?:dbo\.)?{tbl}\b",
                        rf"TRUNCATE\s+TABLE\s+(?:dbo\.)?{tbl}\b",
                        rf"DELETE\s+FROM\s+(?:dbo\.)?{tbl}\b"):
                assert not re.search(verb, text, re.IGNORECASE), (
                    f"{sql.name}: destructive statement against frozen table {tbl} "
                    f"(pattern {verb}) -- the six master tables hold curated data that must "
                    "survive every deployment")
            for col in re.findall(
                    rf"ALTER\s+TABLE\s+(?:dbo\.)?{tbl}\s+DROP\s+COLUMN\s+(\w+)", text, re.IGNORECASE):
                seen.add((tbl, col))
                assert (tbl, col) in _APPROVED_COLUMN_DROPS, (
                    f"{sql.name}: unapproved DROP COLUMN {tbl}.{col} on a frozen master table. "
                    "It destroys curated data and cannot be undone without a restore. If it is "
                    "genuinely intended, add it to _APPROVED_COLUMN_DROPS with the date and the "
                    "reason, so the decision is reviewable instead of incidental.")

    # The list must not outlive the change it authorised: a stale entry stands as pre-approval for
    # a removal nobody discussed.
    stale = _APPROVED_COLUMN_DROPS - seen
    assert not stale, (
        f"_APPROVED_COLUMN_DROPS lists drops no script performs: {sorted(stale)} -- remove them.")

def test_every_alter_against_a_frozen_table_is_guarded() -> None:
    """Every ALTER TABLE <frozen> must be the body of an IF existence/width guard -- either
    the single guarded statement (`IF COL_LENGTH(...) IS NULL` / `ALTER ...`) or inside a
    guarded `IF ... BEGIN ... END` block -- so re-running the script against the live frozen
    schema is a provable no-op, never a mutation.

    Implemented as a tiny FORWARD parser tracking guard state and BEGIN/END nesting, because
    both simpler heuristics failed their own bite-test: a lines-window check was satisfied by
    an unrelated COL_LENGTH nearby (passed on a truly unguarded ALTER), and a backward walk
    could not see that the second statement of a guarded BEGIN block is guarded too."""
    offenders = []
    for sql in sorted(_SCRIPTS.glob("*.sql")):
        guard_pending = False   # an IF <marker> has been seen; its body statement is next
        stack: list[bool] = []  # BEGIN/END nesting; True = block opened under a guarded IF
        for i, raw in enumerate(sql.read_text(encoding="utf-8", errors="replace").splitlines()):
            line = re.sub(r"--.*", "", raw).strip()
            if not line:
                continue
            upper = line.upper()
            if upper == "GO":
                guard_pending, stack = False, []
                continue
            if upper == "BEGIN" or upper.endswith(" BEGIN"):
                stack.append(guard_pending)
                guard_pending = False
                continue
            if upper == "END" or upper.startswith("END;"):
                if stack:
                    stack.pop()
                continue
            if re.match(r"IF\b", line, re.IGNORECASE):
                guard_pending = any(g in line for g in _GUARD_MARKERS)
                continue
            match = re.search(r"ALTER\s+TABLE\s+(?:dbo\.)?(\w+)", line, re.IGNORECASE)
            if match and match.group(1) in _FROZEN_TABLES:
                if not (guard_pending or True in stack):
                    offenders.append(f"{sql.name}:{i + 1}: {line}")
            # a completed statement consumes the pending single-statement guard
            if line.rstrip().endswith(";"):
                guard_pending = False
    assert not offenders, (
        "unguarded ALTER against a frozen master table -- make the ALTER the body of an "
        "IF COL_LENGTH/COLUMNPROPERTY/OBJECT_ID guard so re-running is a no-op:\n  "
        + "\n  ".join(offenders))

REQ_IDX_RE = 'INSERT INTO @req_indexes \\(IndexName, TableName, Cols\\) VALUES\\n(.*?);'
TRIPLE_RE = "\\(N'([^']+)', N'([^']+)', N'([^']+)'\\)"
GUARDED_CREATE_RE = "IF OBJECT_ID\\('dbo\\.(\\w+)', 'U'\\) IS NULL\\s*\\nCREATE TABLE"
TSG_TABLES_RE = 'INSERT INTO @tsg_tables \\(TableName\\) VALUES\\n(.*?);'
SINGLE_RE = "\\(N'(\\w+)'\\)"


def _verify_sql() -> str:
    return (_SCRIPTS / "6. TSG_Verify.sql").read_text(encoding="utf-8", errors="replace")


def test_verify_script_boot_index_list_matches_invariants_exactly() -> None:
    """6. TSG_Verify.sql's @req_indexes must EQUAL db.invariants.REQUIRED_INDEXES — both
    directions. The one-way column check below let the script verify only 12 of 13 boot
    indexes for weeks: a database missing UX_Scenario_ActiveAccepted passed verification and
    then refused to boot. Set equality makes that drift impossible."""
    from app.db.invariants import REQUIRED_INDEXES
    sql = _verify_sql()
    # findall over the WHOLE file: the (N'..', N'..', N'..') triple shape exists only in the
    # @req_indexes block, and slicing the block by regex was defeated by a semicolon inside one
    # of its comments.
    listed = set(re.findall(TRIPLE_RE, sql))
    expected = {(name, table, ",".join(cols)) for name, table, cols in REQUIRED_INDEXES}
    assert listed == expected, (
        "verify script's boot-index list drifted from invariants.REQUIRED_INDEXES: "
        f"only in script: {sorted(listed - expected)}; "
        f"only in invariants: {sorted(expected - listed)}")
    assert f"THE {len(expected)} INDEXES" in sql
    assert f"All {len(expected)} boot-asserted indexes present" in sql


def test_verify_script_table_list_matches_create_inventory() -> None:
    """@tsg_tables must equal the CREATE TABLE inventory of the handoff DDL scripts — the list
    claimed 24 while holding 23 names and missing two real tables (Scenario_Library,
    Grounding_Calibration_Run): a database missing either passed verification and failed boot."""
    created: set[str] = set()
    for f in ("1. TSG_Core.sql", "2. Threat_library.sql", "4. Control_library.sql"):
        text = (_SCRIPTS / f).read_text(encoding="utf-8", errors="replace")
        # only REAL creates — the guarded form. Bare "CREATE TABLE" also appears in prose
        # ("a new column needs a CREATE TABLE entry").
        created |= set(re.findall(GUARDED_CREATE_RE, text))
    sql = _verify_sql()
    block = re.search(TSG_TABLES_RE, sql, re.DOTALL)
    assert block, "@tsg_tables VALUES block not found"
    listed = set(re.findall(SINGLE_RE, block.group(1)))
    assert listed == created, (
        "verify script's table list drifted from the CREATE TABLE inventory: "
        f"only in script: {sorted(listed - created)}; "
        f"only in DDL: {sorted(created - listed)}")
    assert f"ALL {len(created)} TSG TABLES EXIST" in sql
    assert f"All {len(created)} TSG tables present" in sql


def test_every_sp_rename_actually_renames_something() -> None:
    """A rename block must stay ASYMMETRIC, or it silently stops renaming anything.

    The object rename of 2026-08-30 was applied by a bulk find-and-replace over the tree. That
    script's glob EXCLUDES the handoff SQL for exactly one reason: `1. TSG_Core.sql` is the one
    file that must KEEP the old names, because they are the sources of its sp_rename statements
    and the left half of every guard.

    Re-run that sweep over this file and nothing errors. Every statement becomes
    `sp_rename 'dbo.X', 'X'` and every guard becomes `X IS NOT NULL AND X IS NULL` -- permanently
    false. The rename never runs on any database again, the script still reports success, and the
    whole suite still passes, because nothing else here compares the two halves.

    This is that comparison. It is deliberately structural rather than a list of the seven current
    names, so a future rename block inherits the guard without anyone remembering to extend it."""
    for script in sorted(_SCRIPTS.glob("*.sql")):
        text = script.read_text(encoding="utf-8-sig", errors="replace")
        for src, dst in re.findall(
                r"sp_rename\s+'([^']+)'\s*,\s*'([^']+)'", text, re.I | re.S):
            leaf = src.split(".")[-1]
            assert leaf.lower() != dst.lower(), (
                f"{script.name}: sp_rename '{src}' -> '{dst}' renames a name to ITSELF. "
                f"A find-and-replace has almost certainly been run over this file; the rename "
                f"is now a permanent no-op that fails silently on every database.")
            assert not dst.startswith("dbo."), (
                f"{script.name}: sp_rename target '{dst}' is schema-qualified. SQL Server does "
                f"NOT reject this -- it creates an object literally named '{dst}', reachable "
                f"only as [dbo].[{dst}]. The new name must be bare.")



# ---------------------------------------------------------------------------
# DROPPED COLUMNS NEVER RETURN. The one-directional guard above (models -> SQL) cannot see a
# script that re-ADDS a column the model no longer maps, and the corpus above is deliberately
# the numbered scripts only. Real incident: after Identified_Threat.Description was dropped, the
# operator-run consolidated script eyshield_handoff/scripts/tsg_remediation_tables.sql still
# CREATEd it and its #want reconciler re-ADDed it - run it and the column came straight back.
# This scans every script an operator actually runs (the " copy" duplicates are kept on purpose
# and never run, so they are excluded) for the three ways a column can come back.
# ---------------------------------------------------------------------------
_DROPPED_COLUMNS = {
    ("Threat_Category", "SecurityObjective"),
    ("Threat_Type", "Description"), ("Threat_Type", "SectorID"),
    ("Threat_Catalogue", "Description"), ("Threat_Catalogue", "SectorID"),
    ("Identified_Threat", "Description"),          # 2026-09-05
}
_CREATE_HEAD_RE = re.compile(r"CREATE\s+TABLE\s+(?:\[?dbo\]?\.)?\[?(\w+)\]?", re.I)
_COLUMN_LINE_RE = re.compile(rf"^\s*\[?(\w+)\]?\s+\[?(?:{_TYPES})\b", re.I)
_WANT_ROW_RE = re.compile(r"\(\s*'(\w+)'\s*,\s*'(\w+)'\s*,")


def _run_scripts() -> list[Path]:
    """What a DBA actually executes: the handoff package, its consolidated scripts/ folder, and
    the standalone TSG_Migration_*.sql deltas."""
    found = [*_SCRIPTS.glob("*.sql"), *(_SCRIPTS / "scripts").glob("*.sql"), *_SCRIPTS.parent.glob("*.sql")]
    return sorted(p for p in found if " copy" not in p.name)


def _created_columns_loose(sql: str) -> set[tuple[str, str]]:
    """(table, column) for every column line inside any CREATE TABLE body, tolerant of the
    [dbo].[Table] spelling and of bodies that end in ') ON [PRIMARY]' rather than ');'."""
    out, table = set(), None
    for line in sql.splitlines():
        head = _CREATE_HEAD_RE.search(line)
        if head:
            table = head.group(1)
            continue
        if table is None:
            continue
        if line.strip().upper() == "GO" or line.lstrip().startswith(")"):
            table = None
            continue
        col = _COLUMN_LINE_RE.match(line)
        if col and col.group(1).upper() not in ("CONSTRAINT", "PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "INDEX"):
            out.add((table, col.group(1)))
    return out


def _want_rows(sql: str) -> set[tuple[str, str]]:
    """Rows of EVERY `INSERT INTO #want ... ;` block (the remediation script declares #want
    twice). Anchoring on that header keeps the two-column @dead drop list and the guarded
    DROP COLUMN statements from false-positiving."""
    rows: set[tuple[str, str]] = set()
    for block in re.findall(r"INSERT\s+INTO\s+#want\b(.*?);", sql, re.S | re.I):
        rows |= set(_WANT_ROW_RE.findall(block))
    return rows


def test_dropped_columns_never_return() -> None:
    paths = _run_scripts()
    assert len(paths) >= 8, f"run-script corpus shrank to {len(paths)} - the globs have drifted"
    sql = _sql_text(paths)
    _, altered = _ddl_columns(paths)
    created, want = _created_columns_loose(sql), _want_rows(sql)
    assert ("Identified_Threat", "ThreatCategoryID") in want, "the #want parser found nothing - it has drifted"
    back = sorted(f"{t}.{c}" for t, c in _DROPPED_COLUMNS
                  if (t, c) in created or c in altered.get(t, set()) or (t, c) in want)
    assert not back, (
        "columns dropped from the product are re-created or re-added by a script an operator "
        f"runs: {back}. Remove them from the CREATE body, the guarded ALTER and the #want list; "
        "a drop must be a drop in every script.")
