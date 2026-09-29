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

#: The operator-run single-file deploy script. A SEPARATE deploy path from the numbered scripts,
#: and it sits in a SUBDIRECTORY, so `_SCRIPTS.glob("*.sql")` — non-recursive — never sees it.
#: Passed explicitly through the `paths` parameter below.
_CONSOLIDATED = _SCRIPTS / "scripts" / "tsg_remediation_tables.sql"

#: DEPLOY PATH 3: the generated operator package. Its indexes, defaults and check constraints are
#: lifted from _CONSOLIDATED by scripts/tsg_script/_generate.py and its columns from models.py, so
#: it is the third place a database can be built from and the third place that can disagree.
_PACKAGE = Path(__file__).resolve().parents[1] / "scripts" / "tsg_script"

#: A schema-qualified table name, in EITHER spelling this repo's scripts use: the hand-written
#: `dbo.Threat_Scenario` and the SSMS-scripted `[dbo].[Threat_Scenario]`. Matching only the first
#: made the parser skip an entire deploy script in total silence — see `_ddl_columns`.
#:
#: ONE definition, in two shapes. `{g}` is where a pattern needing a NAMED group puts its prefix;
#: the alternative — a second literal spelling of the same thing for the patterns that want
#: `(?P<table>...)` — is exactly how the frozen-table guards ended up with a narrow
#: `(?:dbo\.)?(\w+)` of their own that could not match `[dbo].[Threat_Catalogue]` at all, so every
#: statement in the SSMS-scripted deploy path was invisible to them.
_TABLE_NAME_PATTERN = r"(?:\[?dbo\]?\s*\.\s*)?\[?({g}\w+)\]?"
_TABLE_NAME = _TABLE_NAME_PATTERN.format(g="")
_TABLE_NAME_NAMED = _TABLE_NAME_PATTERN.format(g="?P<table>")


def _table_literal(table: str) -> str:
    """Both spellings of ONE named table, for a pattern that looks for a specific table rather
    than capturing whichever one is there. Same reason as `_TABLE_NAME`: the frozen-table guards
    hard-coded `(?:dbo\\.)?Threat_Type`, which cannot match `[dbo].[Threat_Type]`."""
    return rf"(?:\[?dbo\]?\s*\.\s*)?\[?{table}\]?\b"

#: SQL Server type names that can open a column definition. Used to tell a column line apart
#: from a CONSTRAINT/INDEX line inside a CREATE TABLE body.
_TYPES = (r"n?varchar|n?char|int|bigint|bit|datetime2?|float|real|decimal|numeric"
        r"|uniqueidentifier|tinyint|smallint|date|time|money|n?text|varbinary")


def _numbered_scripts() -> list[Path]:
    """DEPLOY PATH 1: the numbered handoff scripts a DBA runs, plus TSG_Core_UAT.sql.

    The `" copy"` duplicates are excluded. They are kept on purpose and never run (see
    `test_dropped_columns_never_return`), and counting them would let an object that exists ONLY
    in a copy read as deployed by this path. Verified before excluding them: both copies declare
    the identical set of tables, columns, ALTERs and indexes — only their prose differs."""
    return sorted(p for p in _SCRIPTS.glob("*.sql") if " copy" not in p.name)


def _sql_text(paths=None) -> str:
    """Every script concatenated, with `--` line comments stripped so a commented-out ALTER
    cannot masquerade as deployed DDL. Default corpus: the numbered handoff scripts."""
    joined = "\n".join(p.read_text(encoding="utf-8", errors="replace")
                    for p in (_numbered_scripts() if paths is None else paths))
    return re.sub(r"--[^\n]*", "", joined)


def _ddl_columns(paths=None) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """(columns from CREATE TABLE, columns from guarded ALTER ... ADD), keyed by table."""
    sql = _sql_text(paths)
    created: dict[str, set[str]] = {}
    # The terminator has to accept BOTH hand-written and SSMS-scripted table bodies:
    #   the numbered scripts close with `);` at column 0;
    #   the consolidated script is SSMS output — `) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]` then `GO`,
    #   with no semicolon anywhere. Matching only `);` silently parsed ZERO tables out of that
    #   file, which is why it could never have been guarded by widening the corpus alone.
    # Non-greedy, so it stops at the FIRST closer that ends a statement and cannot run on into the
    # next table's body (which would attribute one table's columns to another and pass falsely).
    for mt in re.finditer(
            rf"CREATE\s+TABLE\s+{_TABLE_NAME}\s*\((.*?)\n\s*\)[^\n]*(?:;|\n\s*GO\b)",
            sql, re.S | re.I):
        cols = set()
        for line in mt.group(2).splitlines():
            hit = re.match(rf"\[?(\w+)\]?\s+\[?(?:{_TYPES})\b", line.strip(), re.I)
            if hit and hit.group(1).upper() not in (
                    "CONSTRAINT", "PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "INDEX"):
                cols.add(hit.group(1))
        created.setdefault(mt.group(1), set()).update(cols)

    altered: dict[str, set[str]] = {}
    for at in re.finditer(rf"ALTER\s+TABLE\s+{_TABLE_NAME}\s+ADD\s+\[?(\w+)\]?", sql, re.I):
        altered.setdefault(at.group(1), set()).add(at.group(2))
    return created, altered


def _tsg_owned() -> list[type]:
    """Every table models.py maps and this repo's scripts must deploy, in a STABLE order.

    `registry.mappers` is a SET, so its iteration order varies with the process's hash seed. Two
    parametrized tests below are built from this list, which made the suite collect the SAME tests
    in a DIFFERENT ORDER on every run. Consequences, none of them cosmetic:

      * `pytest -n` (xdist) refuses to run at all — each worker collects independently and aborts
        with "Different tests were collected between gw0 and gw1", so the whole 1381-test suite
        could only ever run serially, at ~8 minutes a pass;
      * `--last-failed` and any index- or order-based selection point at a different test than the
        one that failed;
      * a bisect over test order cannot reproduce itself.

    Sorting by table name costs nothing and is the only thing that makes the collection a function
    of the code rather than of the interpreter's hash seed."""
    return sorted((mp.class_ for mp in m.Base.registry.mappers
                if mp.class_.__tablename__ not in _DEPLOYED_SEPARATELY),
                key=lambda cls: cls.__tablename__)


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


def test_no_model_comment_claims_an_empty_allowlist_exempts_it() -> None:
    """While `_COLUMN_DEPLOYED_SEPARATELY` is EMPTY, no comment in models.py may send a reader to
    it — because there is nothing there to find and the trip has a cost.

    models.py told the reader, in three places, that Threat_Type.Source and
    Threat_Catalogue.Source were exempted through this frozenset. They never were: both are added
    by a guarded ALTER that `_ddl_columns()` already unions in, so the guard passed on its own
    merits. A developer whose newly-added column failed `test_every_mapped_column_exists_in_the_sql`
    followed those comments to an allowlist whose own note says every entry in it is a hole in the
    guard, and added an entry instead of writing the DDL — the precise outcome the empty frozenset
    exists to discourage. A third comment compounded it ("unlike the other two it needs no
    _COLUMN_DEPLOYED_SEPARATELY entry"), which reads as true only if the other two have one.

    Pinned as a PAIR rather than as a wording check: the day someone genuinely needs an entry,
    they add it and the comments may name it again. It is the combination — an empty allowlist and
    prose claiming it exempts something — that is the lie."""
    if _COLUMN_DEPLOYED_SEPARATELY:
        return   # entries exist; a comment naming them is accurate

    # Grouped into comment BLOCKS, not judged line by line: these comments run to a paragraph and
    # the sentence that negates the claim is rarely on the same line as the name.
    blocks, current = [], []
    for line in Path(m.__file__).read_text(encoding="utf-8").splitlines():
        if line.strip().startswith("#"):
            current.append(line.strip())
        else:
            if current:
                blocks.append("\n".join(current))
            current = []
    if current:
        blocks.append("\n".join(current))
    # The required word is "empty", not a bag of negations: the original wording was "Added by a
    # separate ALTER ... NOT this table's own CREATE block — see test_schema_sync's
    # _COLUMN_DEPLOYED_SEPARATELY", which any loose not/never check would have accepted. A block
    # that names this allowlist has to say what it actually contains.
    offenders = [b for b in blocks
                 if "_COLUMN_DEPLOYED_SEPARATELY" in b and not re.search(r"empty", b, re.I)]
    assert not offenders, (
        "_COLUMN_DEPLOYED_SEPARATELY is empty, so no column is exempt through it, but "
        f"{Path(m.__file__).name} still points a reader at it as though one were:\n  "
        + "\n  ".join(offenders)
        + "\n\nState the real mechanism instead (the column is added by a guarded ALTER, which "
          "_ddl_columns() unions with the CREATE bodies), or add the entry if one is genuinely "
          "needed. Sending a developer to an empty allowlist teaches them to punch a hole in the "
          "guard rather than write the DDL.")


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


# ---------------------------------------------------------------------------
# THE SAME COLUMN GUARD, FOR THE OPERATOR-RUN CONSOLIDATED SCRIPT.
#
# `_SCRIPTS.glob("*.sql")` is NON-RECURSIVE, so every column test above reads only the numbered
# handoff scripts and eyshield_handoff/scripts/tsg_remediation_tables.sql is outside their corpus.
# That is the same hole the index guard below already documents as a REAL INCIDENT — an object added
# to the numbered scripts and the verify script but not to the consolidated one, giving a database
# that could not boot the new code while every test stayed green. The incident note was written for
# indexes; the identical hole was still open for COLUMNS, and a column added to models.py and to the
# numbered scripts but missed here would have reproduced it exactly. Found when
# Grounding_Calibration_Run.ControlMapTh had to be added to this file BY HAND with nothing to say so.
#
# Parametrised per table so a failure names the table, and using the `paths=` extension point the
# helpers were already built with rather than widening the default corpus (which would change what
# every other test in this module means).
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("cls", _tsg_owned(), ids=lambda c: c.__tablename__)
def test_the_consolidated_script_has_every_mapped_column(cls: type) -> None:
    created, altered = _ddl_columns([_CONSOLIDATED])
    table = cls.__tablename__
    deployed = created.get(table, set()) | altered.get(table, set())
    assert deployed, (
        f"{table} is mapped in models.py but the operator-run "
        f"{_CONSOLIDATED.name} neither creates nor alters it. A database built from that script "
        f"could not boot this code, and only this test would say so.")
    mapped = {c.name for c in cls.__table__.columns}
    gap = {c for c in mapped - deployed if f"{table}.{c}" not in _COLUMN_DEPLOYED_SEPARATELY}
    assert not gap, (
        f"{table}: mapped in models.py but absent from {_CONSOLIDATED.name}: {sorted(gap)}. "
        f"That script is a SEPARATE deploy path from the numbered ones, so a column added only "
        f"there stays invisible to every other test in this module.")


def test_the_consolidated_manifest_matches_its_own_create_table_statements() -> None:
    """The consolidated script reconciles an EXISTING database against a `#want` manifest of
    literal rows, separately from the CREATE TABLE statements that build a FRESH one. Its own
    comment claims the manifest is "checked against them, so the two cannot drift apart" —
    nothing checked it. Drift means the two deploy shapes disagree: a column in CREATE TABLE
    but not the manifest is never added to an existing database, and one in the manifest but
    not CREATE TABLE is added by an ALTER that a fresh install then runs for nothing. This is
    also what lets the test above read only the CREATE TABLE bodies and still be complete."""
    sql = _sql_text([_CONSOLIDATED])
    manifest: dict[str, set[str]] = {}
    for table, column in re.findall(r"^\s*\('(\w+)','(\w+)','", sql, re.M):
        manifest.setdefault(table, set()).add(column)
    assert len(manifest) >= 20, f"only parsed {len(manifest)} manifest tables — the format moved"

    created, _ = _ddl_columns([_CONSOLIDATED])
    for table, wanted in sorted(manifest.items()):
        declared = created.get(table, set())
        assert declared, f"{table} is in the #want manifest but no CREATE TABLE builds it"
        # Identity/computed columns are declared but need no reconciliation row, so the manifest
        # is allowed to be a SUBSET. What it may not do is want a column nothing creates.
        assert not wanted - declared, (
            f"{table}: the #want manifest reconciles {sorted(wanted - declared)}, which no "
            f"CREATE TABLE in the same file declares. A fresh install would not have the column "
            f"and an existing one would, so the two deploy paths produce different databases.")


# ---------------------------------------------------------------------------
# THE THREE DEPLOY PATHS MUST DECLARE THE SAME COLUMN SHAPES.
#
# Every column guard above compares NAMES only. So did the manifest check, even though the #want
# manifest carries TypeName, MaxLen, Scale, IsNullable and IsIdentity for all 297 columns. Nothing
# in the repository compared a column's TYPE or LENGTH between the deploy paths or against the ORM,
# and the drift that produced was live: Threat_Catalogue.Source was nvarchar(50) in the numbered
# handoff scripts and nvarchar(100) in models.py, in the consolidated script and in the generated
# package. SQLAlchemy enforces no length client-side, so the SAME write would have succeeded
# against a database built by two of the three paths and failed with SQL Server 8152 against the
# third — and the file carrying the short column described itself, two paragraphs below, as
# applying "a blanket floor" of nvarchar(100).
#
# The consolidated script's #want manifest is the reference: it is the machine-readable one, it is
# what scripts/tsg_script/_generate.py reads column types out of, and it is what the consolidated
# script itself reconciles an existing database against.
# ---------------------------------------------------------------------------
#: A column's shape as any of the three paths can state it: base type as sys.columns reports it,
#: declared LENGTH in characters (-1 for MAX, None for a type that has none), SCALE/precision, and
#: nullability. Deliberately NOT the raw type string: `nvarchar(100)`, `[nvarchar](100)` and
#: `NVARCHAR(100)` are the same column declared by three different tools.
_ColumnShape = tuple[str, int | None, int | None, bool]

_WANT_SHAPE_RE = re.compile(
    r"^\s*\('(\w+)','(\w+)','(\w+)',(NULL|-?\d+),(NULL|-?\d+),([01])", re.M)
_COLUMN_DECL_RE = re.compile(
    rf"^\[?(\w+)\]?\s+\[?({_TYPES})\]?\s*(\([^)]*\))?(.*)$", re.I)


#: What SQL Server stores, and what sys.columns then reports, when the DDL gives a type NO
#: argument. Normalising here is what makes the comparison about the DATABASE rather than about
#: the typing: the numbered scripts write `datetime2` and the #want manifest carries the 7 the
#: server actually used, and 84 columns differ between the paths on nothing but that.
_TYPE_DEFAULT_ARGS: dict[str, tuple[int | None, int | None]] = {
    "datetime2": (None, 7), "datetimeoffset": (None, 7), "time": (None, 7),
    "decimal": (18, 0), "numeric": (18, 0),
    "nvarchar": (1, None), "varchar": (1, None), "nchar": (1, None), "char": (1, None),
    "varbinary": (1, None),
    # `float` is deliberately ABSENT. Its one argument is a PRECISION that sys.columns keeps in
    # `precision`, not `scale`, and the #want manifest carries NULL for it — so the reference has
    # no number to compare against and inventing the 53 the server defaults to would make every
    # float column read as a mismatch against a manifest that simply does not record it.
}


def _split_type(type_name: str, args: str | None) -> tuple[str, int | None, int | None]:
    """('nvarchar', 100, None), ('datetime2', None, 7), ('nvarchar', -1, None) for MAX.

    The single-argument case is split by TYPE FAMILY on purpose: one number after nvarchar is a
    LENGTH and one after datetime2 is a PRECISION, sys.columns and the #want manifest keep them in
    different columns, and conflating them would compare a length against a precision and call two
    identical columns different."""
    base = type_name.strip().strip("[]").lower()
    inner = (args or "").strip().strip("()").replace(" ", "")
    if not inner:
        return (base, *_TYPE_DEFAULT_ARGS.get(base, (None, None)))
    if inner.upper() == "MAX":
        return base, -1, None
    first, _, second = inner.partition(",")
    if second:
        return base, int(first), int(second)
    if base.endswith("char") or base.endswith("binary"):
        return base, int(first), None
    return base, None, int(first)


def _create_table_shapes(sql: str) -> dict[tuple[str, str], _ColumnShape]:
    """Every column declared inside a CREATE TABLE body, in either spelling."""
    out: dict[tuple[str, str], _ColumnShape] = {}
    for mt in re.finditer(
            rf"CREATE\s+TABLE\s+{_TABLE_NAME}\s*\((.*?)\n\s*\)[^\n]*(?:;|\n\s*GO\b)",
            sql, re.S | re.I):
        for line in mt.group(2).splitlines():
            hit = _COLUMN_DECL_RE.match(line.strip())
            if not hit or hit.group(1).upper() in (
                    "CONSTRAINT", "PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "INDEX"):
                continue
            base, length, scale = _split_type(hit.group(2), hit.group(3))
            out[(mt.group(1), hit.group(1))] = (
                base, length, scale, "NOT NULL" not in hit.group(4).upper())
    return out


def _numbered_column_shapes() -> dict[tuple[str, str], _ColumnShape]:
    """DEPLOY PATH 1's final shape for every column: the CREATE TABLE declaration, then any
    guarded `ALTER ... ADD` for a column an older database lacks, then any `ALTER COLUMN` widening
    — in that order, LAST ONE WINS, because that is the order the script executes in and the
    widening section at the end of each script is deliberately the final word."""
    sql = _sql_text()
    shapes = _create_table_shapes(sql)
    for at in re.finditer(
            rf"ALTER\s+TABLE\s+{_TABLE_NAME}\s+ADD\s+\[?(\w+)\]?\s+\[?({_TYPES})\]?\s*"
            r"(\([^)]*\))?([^;]*)", sql, re.I):
        base, length, scale = _split_type(at.group(3), at.group(4))
        shapes.setdefault((at.group(1), at.group(2)),
                          (base, length, scale, "NOT NULL" not in at.group(5).upper()))
    for at in re.finditer(
            rf"ALTER\s+TABLE\s+{_TABLE_NAME}\s+ALTER\s+COLUMN\s+\[?(\w+)\]?\s+\[?({_TYPES})\]?\s*"
            r"(\([^)]*\))?([^;]*)", sql, re.I):
        base, length, scale = _split_type(at.group(3), at.group(4))
        shapes[(at.group(1), at.group(2))] = (
            base, length, scale, "NOT NULL" not in at.group(5).upper())
    return shapes


def _manifest_column_shapes() -> dict[tuple[str, str], _ColumnShape]:
    """DEPLOY PATH 2's `#want` manifest, the rows it reconciles an EXISTING database against."""
    sql = _CONSOLIDATED.read_text(encoding="utf-8", errors="replace")
    out: dict[tuple[str, str], _ColumnShape] = {}
    for table, column, type_name, max_len, scale, nullable in _WANT_SHAPE_RE.findall(sql):
        out[(table, column)] = (
            type_name.lower(),
            None if max_len == "NULL" else int(max_len),
            None if scale == "NULL" else int(scale),
            nullable == "1")
    return out


def _package_column_shapes() -> dict[tuple[str, str], _ColumnShape]:
    """DEPLOY PATH 3's CREATE TABLE declarations. Read off the generated .sql rather than by
    calling the generator, so what is compared is the artefact an operator runs. The package's own
    tests already pin those CREATE bodies to models.py and to its reconcile calls, so agreeing
    with this is agreeing with the ORM."""
    return _create_table_shapes(
        "\n".join(p.read_text(encoding="utf-8", errors="replace")
                  for p in sorted((_PACKAGE / "01_tables").glob("*.sql"))))


def test_every_deploy_path_declares_the_same_column_shapes() -> None:
    reference = _manifest_column_shapes()
    numbered = _numbered_column_shapes()
    package = _package_column_shapes()
    for label, found in (("the #want manifest", reference),
                         ("the numbered handoff scripts", numbered),
                         ("the generated tsg_script package", package)):
        assert len(found) >= 280, (
            f"only {len(found)} column shapes parsed out of {label} — the parser has drifted, and "
            "an empty side makes every comparison below vacuous rather than clean")

    problems = []
    for label, found, orm_derived in (("the numbered handoff scripts", numbered, False),
                                      ("the generated tsg_script package", package, True)):
        for key in sorted(set(found) & set(reference)):
            table, column = key
            got, want = found[key], reference[key]
            if got[:3] != want[:3]:
                problems.append(
                    f"{table}.{column}: {label} declares {got[:3]}, the #want manifest wants "
                    f"{want[:3]} (base type, length in characters, scale)")
            elif got[3] != want[3]:
                # ONE direction is allowed, and only against the ORM-derived path: a database
                # STRICTER than the object model is safe, it is what the reviewed DDL already
                # declares for the library tables' CreatedAt columns (they carry a DEFAULT, so an
                # insert that omits the value still succeeds), and 002_schema_verdict.sql reports
                # it as [INFO] rather than failing it for exactly that reason. The opposite —
                # a column the application requires that the database lets be NULL — is the one
                # the verdict fails, so it fails here too.
                if orm_derived and want[3] is False and got[3] is True:
                    continue
                problems.append(
                    f"{table}.{column}: {label} says nullable={got[3]}, the #want manifest says "
                    f"nullable={want[3]}")
    assert not problems, (
        "the deploy paths declare the SAME column with DIFFERENT shapes, so the same write "
        "succeeds on a database built by one path and fails on another:\n  "
        + "\n  ".join(problems))


# ---------------------------------------------------------------------------
# THE THREE DEPLOY PATHS MUST DECLARE THE SAME DEFAULTS, CHECKS AND UNIQUE CONSTRAINTS.
#
# The remaining two object classes. Paths 2 and 3 were already tied together — the generator LIFTS
# the default and check DDL out of the consolidated script, and refuses to run if it parses none —
# but nothing compared either against DEPLOY PATH 1, so the same hole that let an index diverge was
# open for a default constraint too. A default matters differently from an index: a column that
# loses its default does not error, it silently stores whatever the insert omitted.
#
# DEFAULTS ARE COMPARED BY COLUMN, NEVER BY CONSTRAINT NAME. SQL Server permits one default per
# column and invents a name (DF__Identifie__IsAIG__7954A4F6) when the DDL omits one — which is
# exactly what the numbered scripts do for Identified_Threat.IsThreatAIGenerated and
# .IsThreatTypeAIGenerated, while the consolidated script names them. The column carrying a default
# is the fact the application depends on; the name is not, which is why the package guards and
# verifies defaults by column too.
# ---------------------------------------------------------------------------
def _normalise_expression(expression: str | None) -> str:
    """One SQL expression in a form the three paths can be compared in: brackets, parentheses,
    case and whitespace normalised away. `DEFAULT 0`, `DEFAULT ((0))` and `DEFAULT (0)` are the
    same default; `SYSUTCDATETIME()` and `(sysutcdatetime())` are the same function."""
    text = (expression or "").strip()
    text = text.replace("[", "").replace("]", "").replace("(", " ").replace(")", " ")
    return re.sub(r"\s+", " ", text).strip().lower()


def _default_values(sql: str) -> dict[tuple[str, str], str]:
    """{(table, column): normalised default expression} for every column a script gives a DEFAULT,
    in all three forms these scripts use: inline in a CREATE TABLE body,
    `ALTER ... ADD CONSTRAINT [DF_x] DEFAULT ... FOR [col]`, and
    `ALTER ... ADD [col] <type> ... DEFAULT ...` for an existing table.

    The VALUE is carried, not just the fact that one exists, because a default is the one object
    class whose divergence is completely silent at run time: a column whose default is 1 on one
    path and 0 on another accepts the same insert on both and stores different data."""
    out: dict[tuple[str, str], str] = {}
    for mt in re.finditer(
            rf"CREATE\s+TABLE\s+{_TABLE_NAME}\s*\((.*?)\n\s*\)[^\n]*(?:;|\n\s*GO\b)",
            sql, re.S | re.I):
        for line in mt.group(2).splitlines():
            hit = re.match(r"\[?(\w+)\]?\s+\[?\w+\]?", line.strip())
            value = re.search(r"\bDEFAULT\s+(.*?)(?:,\s*$|$)", line.strip(), re.I)
            if (hit and value and hit.group(1).upper() not in (
                    "CONSTRAINT", "PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "INDEX")):
                out[(mt.group(1), hit.group(1))] = _normalise_expression(value.group(1))
    for mt in re.finditer(
            rf"ALTER\s+TABLE\s+{_TABLE_NAME}\s+ADD\s+CONSTRAINT\s+\[?DF_\w+\]?\s+DEFAULT\s+"
            r"(.*?)\s+FOR\s+\[?(\w+)\]?", sql, re.S | re.I):
        out[(mt.group(1), mt.group(3))] = _normalise_expression(mt.group(2))
    for mt in re.finditer(
            rf"ALTER\s+TABLE\s+{_TABLE_NAME}\s+ADD\s+(?!CONSTRAINT\b)\[?(\w+)\]?\s+"
            rf"\[?(?:{_TYPES})\]?[^;]*?\bDEFAULT\s+([^;]*?)\s*;", sql, re.I):
        out.setdefault((mt.group(1), mt.group(2)), _normalise_expression(mt.group(3)))
    return out


def _named_constraints(sql: str, prefix: str) -> set[str]:
    """Every CK_/UQ_ constraint name a script declares, inline or by ALTER. These DO compare by
    name: unlike a default, the application's own verify and sign-off scripts look them up by name,
    so a rename is a real divergence."""
    return set(re.findall(rf"CONSTRAINT\s+\[?({prefix}\w+)\]?", sql, re.I))


def _path_sql() -> dict[str, str]:
    """The three deploy paths as text, `--` comments stripped. Path 3 is its own files rather than
    TSG_Deploy_All.sql, which is a concatenation of them and would double every count."""
    return {
        "the numbered handoff scripts": _sql_text(),
        _CONSOLIDATED.name: _sql_text([_CONSOLIDATED]),
        "the generated tsg_script package": _sql_text(
            [p for p in sorted(_PACKAGE.rglob("*.sql")) if p.name != "TSG_Deploy_All.sql"]),
    }


def test_every_deploy_path_declares_the_same_defaults_and_constraints() -> None:
    texts = _path_sql()
    # Restricted to the columns the paths have in COMMON, so the pre-rename legacy names a single
    # path carries on purpose (Identified_Threat.IsAIGenerated, whose whole job is to be renamed
    # away by that same script) are not mistaken for a missing default. Which columns each path
    # declares is a separate invariant, already enforced above.
    shapes = {"the numbered handoff scripts": _numbered_column_shapes(),
              _CONSOLIDATED.name: _manifest_column_shapes(),
              "the generated tsg_script package": _package_column_shapes()}
    common = set.intersection(*(set(s) for s in shapes.values()))
    assert len(common) >= 280, f"only {len(common)} columns common to all three paths"

    defaults = {label: {k: v for k, v in _default_values(sql).items() if k in common}
                for label, sql in texts.items()}
    found = {label: {
        "DEFAULT on a column": set(defaults[label]),
        "CHECK constraint": _named_constraints(sql, "CK_"),
        "UNIQUE constraint": _named_constraints(sql, "UQ_"),
    } for label, sql in texts.items()}

    # Anti-vacuity, per class and per path: an empty side would make every difference below
    # disappear instead of showing up. The floors are the counts the scripts and the generator
    # already agree on today (22 defaults, 3 checks, 1 unique), minus nothing.
    floors = {"DEFAULT on a column": 20, "CHECK constraint": 3, "UNIQUE constraint": 1}
    for label, classes in found.items():
        for kind, objects in classes.items():
            assert len(objects) >= floors[kind], (
                f"only {len(objects)} of class '{kind}' parsed out of {label} — the parser or the "
                "path has drifted, and an empty side reports agreement it never checked")

    reference = found[_CONSOLIDATED.name]
    problems = []
    for label, classes in found.items():
        if label == _CONSOLIDATED.name:
            continue
        for kind, objects in classes.items():
            for extra in sorted(reference[kind] - objects):
                problems.append(f"{kind} {extra}: in {_CONSOLIDATED.name} but NOT in {label}")
            for extra in sorted(objects - reference[kind]):
                problems.append(f"{kind} {extra}: in {label} but NOT in {_CONSOLIDATED.name}")
        # And the default's VALUE, for the columns both paths give one. Presence alone would let
        # `DEFAULT 1` on one path face `DEFAULT 0` on another: same insert, different row, no error
        # on either. (CHECK expressions are deliberately NOT compared as text — the consolidated
        # script was SSMS-scripted FROM a live database, so SQL Server had already rewritten
        # `IN ('a','b')` into `= 'a' OR = 'b'`. The two paths state the same predicate in two
        # forms, and telling those apart from a genuine change needs boolean equivalence, not
        # normalisation. What is compared is that the named constraint exists on every path.)
        for key in sorted(set(defaults[label]) & set(defaults[_CONSOLIDATED.name])):
            mine, theirs = defaults[label][key], defaults[_CONSOLIDATED.name][key]
            if mine != theirs:
                problems.append(
                    f"DEFAULT on a column {key[0]}.{key[1]}: {label} defaults it to {mine!r}, "
                    f"{_CONSOLIDATED.name} defaults it to {theirs!r}")
    assert not problems, (
        "the deploy paths declare different defaults or constraints, so which rules a database "
        "carries depends on which script the operator ran. A missing or different default is the "
        "quiet one: the insert succeeds either way and stores something else.\n  "
        + "\n  ".join(problems))


# ---------------------------------------------------------------------------
# THE CONSOLIDATED SCRIPT'S OWN NUMBERS.
#
# The header advertises what the file contains and Section 6 repeats the index count in its
# heading. All of them were hand-typed and nothing checked them: the edit that added seven columns
# and one default updated 291 -> 297 and 21 -> 22 and left the index count at 29 while Section 6
# built 30 and Section 7 verified 30. A reviewer reconciling this script against a live database
# then counts 29 from the header, finds 30 in sys.indexes, and has to decide whether the database
# carries a rogue index or the file is wrong — which is the same class of defect that made a
# CORRECT database read as wrong when the package's post-deployment script said "(30 expected)"
# against 31 built. That one is closed for the package; this closes it for this file.
# ---------------------------------------------------------------------------
def test_the_consolidated_header_counts_match_the_script() -> None:
    sql = _CONSOLIDATED.read_text(encoding="utf-8", errors="replace")
    body = _sql_text([_CONSOLIDATED])          # comments stripped: count STATEMENTS, not prose

    actual = {
        "tables": len(re.findall(rf"CREATE\s+TABLE\s+{_TABLE_NAME}\s*\(", body, re.I)),
        "reconciled columns": len(_WANT_SHAPE_RE.findall(sql)),
        "default constraints": len(re.findall(r"ADD\s+CONSTRAINT\s+\[?DF_\w+\]?", body, re.I)),
        "check constraints": len(re.findall(r"ADD\s+CONSTRAINT\s+\[?CK_\w+\]?", body, re.I)),
        "indexes": len(_index_definitions([_CONSOLIDATED])),
    }
    for kind, count in actual.items():
        assert count > 0, (
            f"counted ZERO {kind} in {_CONSOLIDATED.name} — the parser has drifted, and a count "
            "of zero would agree with any header that happened to say zero")

    # Scoped to the "Contents:" sentence rather than the whole file: searching everywhere would
    # sooner or later find some other paragraph's number and pin the wrong one.
    contents = re.search(r"Contents:(.*?)\.\n", sql, re.S)
    assert contents, "the header no longer opens with a 'Contents:' sentence"
    for kind, count in actual.items():
        claimed = re.search(rf"(\d+) {kind}", contents.group(1))
        assert claimed, f"the header's Contents line no longer states a {kind} count at all"
        assert int(claimed.group(1)) == count, (
            f"{_CONSOLIDATED.name}'s header advertises {claimed.group(1)} {kind} but the script "
            f"contains {count}. Correct the header; a reviewer reconciling this file against "
            "sys.indexes or sys.columns has nothing else to go on.")

    assert f"SECTION 6 — Indexes ({actual['indexes']})" in sql, (
        f"Section 6's heading disagrees with the {actual['indexes']} CREATE INDEX statements "
        "under it")

    # Section 6 is divided into 6a..6d, each announcing its own count. Those subdivide the same
    # total, so a heading left behind is the same reading error one level down: 6a said (14) while
    # holding 15.
    section6 = sql[sql.index("SECTION 6 — Indexes"):sql.index("SECTION 7 —")]
    subsections = re.findall(r"^-- (6[a-z])\..*?\((\d+)", section6, re.M | re.S)
    assert len(subsections) >= 4, (
        f"only found {len(subsections)} counted subsections in Section 6 — their heading shape "
        "moved, so nothing below is being checked")
    counted, current = {}, None
    for line in section6.splitlines():
        head = re.match(r"-- (6[a-z])\.", line.strip())
        if head:
            current = head.group(1)
            counted.setdefault(current, 0)
        elif current and re.search(r"CREATE\s+(UNIQUE\s+)?((NON)?CLUSTERED\s+)?INDEX", line, re.I):
            counted[current] += 1
    wrong = [f"{name} says ({claimed}) but holds {counted.get(name)}"
             for name, claimed in subsections if counted.get(name) != int(claimed)]
    assert not wrong, ("Section 6's subsection counts disagree with their contents: "
                       + "; ".join(wrong))
    assert sum(counted.values()) == actual["indexes"], (
        f"the 6a-6d subsections hold {sum(counted.values())} indexes but the section builds "
        f"{actual['indexes']} — one is outside every subsection, so no heading accounts for it")

    # The operator's readme sitting beside the script repeats all four counts in its own
    # "WHAT IT CONTAINS" section, and three of them had been left behind by the same hand edits.
    # It is the file the operator reads FIRST, so a stale number there is read before the header's.
    readme = (_CONSOLIDATED.parent / "README.txt").read_text(encoding="utf-8", errors="replace")
    for section, kind, count in (("2   Tables", "tables", actual["tables"]),
                                 ("3   Columns", "columns", actual["reconciled columns"]),
                                 ("4   Default constraints", "defaults",
                                  actual["default constraints"]),
                                 ("5   Check constraints", "checks", actual["check constraints"]),
                                 ("6   Indexes", "indexes", actual["indexes"])):
        assert f"Section {section} ({count})" in readme, (
            f"{_CONSOLIDATED.parent.name}/README.txt does not say 'Section {section} ({count})', "
            f"but the script contains {count} {kind}. The readme is what the operator reads first.")


# ---------------------------------------------------------------------------
# THE TWO CORE SCRIPTS ARE ONE SCRIPT.
#
# DEPLOY PATH 1 is a UNION of "1. TSG_Core.sql" and TSG_Core_UAT.sql, and the UAT file's own header
# states why: "The body below is `1. TSG_Core.sql` verbatim ... KEEP IN LOCKSTEP with
# 1. TSG_Core.sql: on the next schema change, regenerate this file as this header plus that file's
# body, verbatim." Nothing checked it, and the consequence is worse than an ordinary stale copy:
# because every cross-path comparison in this module reads the two files as ONE inventory, an object
# added to only one of them still shows up in path 1's totals. So a change applied to one file looks
# applied — while the site that actually runs TSG_Core_UAT.sql (customer and UAT databases, per
# docs/DEPLOY_SCENARIO_LIFECYCLE.md) gets the other file's schema.
#
# Compared as OBJECT INVENTORIES rather than byte for byte: the two files differ in their headers on
# purpose, and a test that demanded identical bytes would be satisfied only by deleting the UAT
# file's explanation of what it is for.
# ---------------------------------------------------------------------------
def test_the_two_core_scripts_declare_the_same_schema() -> None:
    core, uat = _SCRIPTS / "1. TSG_Core.sql", _SCRIPTS / "TSG_Core_UAT.sql"
    inventories = {}
    for path in (core, uat):
        sql = _sql_text([path])
        inventories[path.name] = {
            "column": {f"{t}.{c}={v}" for (t, c), v in _create_table_shapes(sql).items()},
            "index": {f"{n}={v}" for n, v in _index_definitions([path]).items()},
            "default on": {f"{t}.{c}={v}" for (t, c), v in _default_values(sql).items()},
            "check constraint": _named_constraints(sql, "CK_"),
            "unique constraint": _named_constraints(sql, "UQ_"),
        }
    for name, classes in inventories.items():
        for kind, objects in classes.items():
            assert objects, f"parsed no {kind} out of {name} — the parser or the file has moved"

    problems = []
    for kind in inventories[core.name]:
        left, right = inventories[core.name][kind], inventories[uat.name][kind]
        problems += [f"{kind} {o}: in {core.name} but not in {uat.name}" for o in sorted(left - right)]
        problems += [f"{kind} {o}: in {uat.name} but not in {core.name}" for o in sorted(right - left)]
    assert not problems, (
        f"{uat.name} has drifted from {core.name}, which its own header says it is a verbatim copy "
        "of. Regenerate it as its header plus that file's body:\n  " + "\n  ".join(problems))


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
# THE ONE INDEX PATTERN IN THIS MODULE, and it captures UNIQUENESS.
#
# There used to be two, both bound to this same module-level name: a strict
# `CREATE\s+UNIQUE\s+INDEX` here and, 300 lines further down, a permissive
# `CREATE\s+(?:UNIQUE\s+)?...` that did not capture UNIQUE at all. Python keeps the LAST binding,
# so `_ddl_indexes()` ran the permissive one, its docstring's promise ("from every CREATE UNIQUE
# INDEX") was false, and uniqueness became invisible to every static check in the file: deleting
# the word UNIQUE from a boot-required `CREATE UNIQUE INDEX` left the name, table and columns
# matching, so CI stayed green and the first symptom would have been a database that builds
# cleanly and then refuses to boot at invariants._assert_indexes ("required indexes exist but are
# not enforcing"). Two patterns for one concept is the defect; one pattern is the fix, so this
# module has exactly one, it is permissive about the KEYWORDS and strict about REPORTING them, and
# every index guard below reads its output.
_CREATE_INDEX_RE = re.compile(
    r"CREATE\s+(?P<unique>UNIQUE\s+)?(?:(?:NON)?CLUSTERED\s+)?INDEX\s+\[?(?P<name>\w+)\]?\s+ON\s+"
    + _TABLE_NAME_NAMED
    + r"\s*\((?P<cols>[^)]*)\)"
    # INCLUDE columns change cost, never correctness, and sys.index_columns reports them
    # separately — skipped so the filter after them is still seen.
    r"(?:\s*INCLUDE\s*\([^)]*\))?\s*(?:WHERE(?P<filter>[^;]*))?", re.I | re.S)
_VERIFY_ROW_RE = re.compile(r"\(N'(UX_\w+)',\s*N'(\w+)',\s*N'([^']*)'\)")

#: One index as the four things a database can get wrong about it and the application can notice:
#: which table it is on, the KEY COLUMNS IN ORDER, whether it is UNIQUE, and its FILTER PREDICATE
#: (empty string when unfiltered). Included columns are deliberately absent (cost, not correctness).
_IndexShape = tuple[str, tuple[str, ...], bool, str]


def _normalise_predicate(predicate: str | None) -> str:
    """One filter predicate in a form the three paths can be compared in.

    The same rule is written three ways: `WHERE Superseded = 0` by hand, `WHERE [Superseded] = 0`
    by SSMS, and `WHERE Status = ''running''` inside an EXEC('...') string because a filtered index
    needs QUOTED_IDENTIFIER ON and the numbered scripts build those two through dynamic SQL. Only
    the RULE is the fact about the database, so brackets, case, doubled quotes, whitespace and the
    dynamic-SQL closer are normalised away and everything else must match exactly.

    Boolean "is it filtered" is not enough, and that is not hypothetical: UX_ThreatType_NaturalKey
    was filtered on both paths and filtered DIFFERENTLY — `IsDeleted = 0` in the numbered scripts
    against the pre-2026-09-04 `IsActive = 1 AND IsDeleted = 0` in the other two, which gives a
    UNIQUE index that does not constrain promoted rows at all."""
    if not predicate:
        return ""
    text = predicate.strip()
    # The dynamic-SQL form ends `... WHERE Status = ''running''')` — drop the EXEC( closer, then
    # collapse the doubled quotes back to the literal they stand for.
    text = re.sub(r"'\s*\)\s*$", "", text).replace("''", "'")
    text = text.replace("[", "").replace("]", "")
    return re.sub(r"\s+", " ", text).strip().rstrip(";").strip().lower()


def _index_definitions(paths) -> dict[str, _IndexShape]:
    """{index name: (table, ordered key columns, is_unique, normalised filter)} for every
    CREATE [UNIQUE] INDEX in `paths`, with `--` comments stripped first so a commented-out or
    merely DESCRIBED index cannot read as created.

    Keyed by NAME and last-one-wins, which is what a script that DROPs a stale index and lets the
    guarded CREATE rebuild it should produce: one entry, at the current shape."""
    found: dict[str, _IndexShape] = {}
    for path in paths:
        sql = re.sub(r"--[^\n]*", "", path.read_text(encoding="utf-8", errors="replace"))
        for mt in _CREATE_INDEX_RE.finditer(sql):
            # ASC/DESC stripped: sys.index_columns reports direction separately and every index
            # here is ascending, so keeping it would make the comparison depend on DDL noise.
            cols = tuple(re.sub(r"\s+(ASC|DESC)\s*$", "", c.strip(), flags=re.I).strip().strip("[]")
                         for c in mt.group("cols").split(",") if c.strip())
            found[mt.group("name")] = (mt.group("table"), cols, bool(mt.group("unique")),
                                       _normalise_predicate(mt.group("filter")))
    return found


def _ddl_indexes() -> dict[str, _IndexShape]:
    """The index inventory of DEPLOY PATH 1, the numbered handoff scripts."""
    return _index_definitions(_numbered_scripts())


def test_the_index_parser_finds_the_ddl() -> None:
    """The anti-vacuity pin for every index guard below. A pattern that stopped matching would
    make all of them trivially true, and `_ddl_indexes()` feeds four separate comparisons."""
    ddl = _ddl_indexes()
    assert len(ddl) >= 25, f"only parsed {len(ddl)} CREATE INDEXes — the regex has drifted"
    # One UNIQUE and filtered, one plain, one carrying INCLUDE columns, and one whose CREATE is
    # inside an EXEC('...') string with doubled quotes: between them they prove every branch of the
    # pattern and of _normalise_predicate still fires, which a bare count cannot.
    assert ddl.get("UX_Session_ActiveAsset") == (
        "Scenario_Session", ("EntityID", "AssetID"), True, "sessionstatus = 'active'")
    # Plain: not unique, not filtered, no INCLUDE — and its trailing `CreatedAt DESC` proves the
    # sort-direction suffix is stripped from the key list rather than carried into a column name.
    # (This probe was IX_PromptLog_Session until that index was retired for having no reader.)
    assert ddl.get("IX_ScenarioAudit_SessionSubEvent") == (
        "Scenario_Audit", ("SessionID", "SubsystemID", "EventType", "CreatedAt"), False, "")
    assert ddl.get("IX_ScopedThreat_SessionActiveScores") == (
        "Scoped_Threat", ("SessionID", "Superseded"), False, ""), (
        "the INCLUDE branch stopped matching, so an index's filter is read off its INCLUDE list")
    assert ddl.get("UX_GroundingCalibration_Running") == (
        "Grounding_Calibration_Run", ("EmbeddingModel", "RerankerModel"), True,
        "status = 'running'"), (
        "the EXEC('...') form's predicate no longer normalises to the literal it stands for, so "
        "this index's filter would compare unequal against the same rule written plainly")


def test_required_indexes_match_the_ddl_that_creates_them() -> None:
    """Every index the app asserts at boot must exist in the DDL with the SAME ordered columns
    AND be declared UNIQUE.

    The uniqueness half is not decoration: invariants._assert_indexes refuses the boot on a
    required index whose is_unique is 0, so a DDL that creates one non-unique builds a database
    the API and every Celery worker reject — and for weeks nothing static could see it, because
    the pattern that read these statements did not capture the keyword."""
    from app.db import invariants

    ddl = _ddl_indexes()
    mismatched, missing, not_unique = [], [], []
    for name, table, cols in invariants.REQUIRED_INDEXES:
        if name not in ddl:
            # Some indexes are created by scripts deployed separately; only flag ones the
            # repo's own scripts are supposed to build.
            missing.append(name)
            continue
        ddl_table, ddl_cols, ddl_unique, _filtered = ddl[name]
        if (ddl_table, ddl_cols) != (table, tuple(cols)):
            mismatched.append(f"{name}: invariants={table}{tuple(cols)} ddl={ddl_table}{ddl_cols}")
        if not ddl_unique:
            not_unique.append(name)
    assert not mismatched, (
        "REQUIRED_INDEXES disagrees with the CREATE INDEX statements — the app will refuse to "
        "boot against a database built from these scripts:\n  " + "\n  ".join(mismatched))
    assert not missing, (
        "REQUIRED_INDEXES names indexes no script creates (a fresh install would never boot): "
        + ", ".join(sorted(missing)))
    assert not not_unique, (
        "these indexes are created WITHOUT the UNIQUE keyword but invariants asserts uniqueness "
        "at boot, so a database built from these scripts would be refused with 'required indexes "
        "exist but are not enforcing': " + ", ".join(sorted(not_unique)))


def test_verify_script_expects_the_same_index_columns() -> None:
    """TSG_Verify.sql's expected column lists must match the DDL too, or it signs off an install
    the application then rejects — the one failure mode its own section-3 comment calls
    unacceptable."""
    ddl = _ddl_indexes()
    verify = (_SCRIPTS / "6. TSG_Verify.sql").read_text(encoding="utf-8", errors="replace")
    wrong = []
    rows = _VERIFY_ROW_RE.findall(verify)
    assert len(rows) >= 13, f"only parsed {len(rows)} verify index rows — the row shape moved"
    for name, table, cols in rows:
        expected = tuple(c.strip() for c in cols.split(",") if c.strip())
        if name in ddl and ddl[name][:2] != (table, expected):
            wrong.append(f"{name}: verify={table}{expected} ddl={ddl[name][0]}{ddl[name][1]}")
    assert not wrong, "TSG_Verify.sql disagrees with the DDL:\n  " + "\n  ".join(wrong)


# ---------------------------------------------------------------------------
# THE THREE DEPLOY PATHS MUST BUILD THE SAME INDEXES.
#
# Until this test, the ONLY cross-path index comparison keyed on invariants.REQUIRED_INDEXES
# (14 names) plus FILTERED_INDEX_LITERALS (3, one of them already in the first list) — so 15 of
# the 31 indexes were compared and the other 16 were compared against nothing at all. Measured
# the day this was written, the paths had drifted in three names and nobody could have known:
#
#   IX_PromptLog_Correlation       only in paths 2 and 3. A database built by the DOCUMENTED DBA
#                                  package therefore scanned Prompt_Log — one row per model call
#                                  — on every treatment-evidence read. No error, no log entry.
#   IX_Scenario_RejectedDecision   only in path 1, whose own standalone migration calls it "not
#                                  optional" because /results polls it.
#   UX_ScenarioLibrary_Natural     only in path 1, on a table removed from the product.
#
# Names ALONE would not have been enough: an index carrying the right name over the wrong columns,
# or with its WHERE filter dropped, enforces something different and silently. So the comparison
# is on the full shape, and it is EQUALITY with no exception list — an exception list here is just
# the old blind spot with a nicer name, and every deliberate difference between these paths turned
# out on inspection to be an oversight in one of them.
# ---------------------------------------------------------------------------
def test_every_deploy_path_creates_the_same_indexes() -> None:
    paths = {
        "the numbered handoff scripts": _ddl_indexes(),
        _CONSOLIDATED.name: _index_definitions([_CONSOLIDATED]),
        "the generated tsg_script package": _index_definitions(
            sorted((_PACKAGE / "03_indexes").glob("*.sql"))),
    }
    for label, found in paths.items():
        assert len(found) >= 25, (
            f"only {len(found)} indexes parsed out of {label} — either that deploy path has lost "
            "most of its indexes or the parser no longer reads its spelling. Both make every "
            "comparison below vacuous.")

    reference = paths[_CONSOLIDATED.name]
    problems = []
    for label, found in paths.items():
        if label == _CONSOLIDATED.name:
            continue
        for name in sorted(set(reference) - set(found)):
            problems.append(f"{name}: in {_CONSOLIDATED.name} but NOT in {label}")
        for name in sorted(set(found) - set(reference)):
            problems.append(f"{name}: in {label} but NOT in {_CONSOLIDATED.name}")
        for name in sorted(set(found) & set(reference)):
            if found[name] != reference[name]:
                problems.append(f"{name}: {label} builds {found[name]}, "
                                f"{_CONSOLIDATED.name} builds {reference[name]} "
                                "(table, key columns in order, unique, filtered)")
    assert not problems, (
        "the deploy paths build DIFFERENT indexes, so which database you get depends on which "
        "script the operator ran:\n  " + "\n  ".join(problems)
        + "\n\nAdd the index to the path that lacks it. The consolidated script is the reference "
          "because scripts/tsg_script/_generate.py reads its index DDL, so an index added only "
          "to the numbered scripts reaches one path out of three.")


def test_no_other_script_creates_a_deploy_path_index_differently() -> None:
    """The standalone migration and repair scripts under scripts/ create SOME of these indexes, and
    where they do, the shape must be the deploy paths' shape.

    The three-path test above cannot see them, because they each build one index rather than a full
    schema — so set equality is the wrong question for them and per-name agreement is the right one.
    It matters: scripts/TSG_Fix_NaturalKeys.sql DROPped UX_ThreatType_NaturalKey and rebuilt it on
    the PRE-2026-09-04 filter (`IsActive = 1 AND IsDeleted = 0`) while rebuilding its Threat_Catalogue
    twin on the widened one. Running that repair therefore UNDID the widening on Threat_Type, and
    announced the old rule as the fix in its own FIXED message. A fourth place to write a predicate
    is a fourth place for one to be left behind, so this reads every one of them."""
    reference = _index_definitions([_CONSOLIDATED])
    assert len(reference) >= 25, "the reference inventory parsed almost empty"

    others = sorted(_SCRIPTS.parent.glob("*.sql"))
    assert len(others) >= 8, (
        f"only {len(others)} standalone scripts found under scripts/ — the glob has drifted and "
        "this check would pass by reading nothing")

    problems, checked = [], 0
    for path in others:
        for name, shape in sorted(_index_definitions([path]).items()):
            if name not in reference:
                # An index no deploy path builds is out of scope here (a one-off diagnostic index,
                # or one being retired) — what must not happen is a DIFFERENT shape under a name
                # the application and the deploy paths share.
                continue
            checked += 1
            if shape != reference[name]:
                problems.append(
                    f"{path.name} creates {name} as {shape}, the deploy paths create it as "
                    f"{reference[name]} (table, key columns in order, unique, filter)")
    assert checked >= 5, (
        f"only {checked} index definitions in scripts/*.sql were compared. These scripts exist to "
        "apply one index each to a database that is already up, so a number this low means the "
        "parser stopped reading them and a divergent rebuild would be invisible.")
    assert not problems, (
        "a standalone script rebuilds a deploy-path index with a different shape, so running it "
        "changes what the database enforces:\n  " + "\n  ".join(problems))


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


def _frozen_table_corpus() -> list[Path]:
    """EVERY .sql an operator can run against a live database, across all three deploy paths.

    Both guards below used to iterate `_SCRIPTS.glob("*.sql")`, which is NON-RECURSIVE: the
    operator-run consolidated script sits in a subdirectory and the whole generated package sits in
    another, so neither was ever read. `DELETE FROM dbo.Threat_Type` added to the script an
    operator actually runs passed the entire suite. The narrow `(?:dbo\\.)?(\\w+)` these guards also
    used made widening the corpus pointless on its own — it cannot match `[dbo].[Threat_Type]`,
    the only spelling the consolidated script uses — so both halves are fixed together here and in
    `_TABLE_NAME`."""
    return sorted([*_run_scripts(), *_PACKAGE.rglob("*.sql")])


def test_no_destructive_statement_against_a_frozen_table() -> None:
    """Row-destroying statements are forbidden outright; column drops only by explicit approval."""
    seen: set[tuple[str, str]] = set()
    corpus = _frozen_table_corpus()
    assert len(corpus) >= 55, (
        f"the frozen-table corpus shrank to {len(corpus)} files — the globs have drifted, and a "
        "shrinking corpus makes this guard pass by reading less rather than by finding less")
    mentions = 0
    for sql in corpus:
        text = re.sub(r"--[^\n]*", "", sql.read_text(encoding="utf-8", errors="replace"))
        for tbl in _FROZEN_TABLES:
            mentions += len(re.findall(rf"\[?{tbl}\]?\b", text))
            for verb in (rf"DROP\s+TABLE\s+{_table_literal(tbl)}",
                        rf"TRUNCATE\s+TABLE\s+{_table_literal(tbl)}",
                        rf"DELETE\s+FROM\s+{_table_literal(tbl)}"):
                assert not re.search(verb, text, re.IGNORECASE), (
                    f"{sql.name}: destructive statement against frozen table {tbl} "
                    f"(pattern {verb}) -- the six master tables hold curated data that must "
                    "survive every deployment")
            for col in re.findall(
                    rf"ALTER\s+TABLE\s+{_table_literal(tbl)}\s+DROP\s+COLUMN\s+\[?(\w+)\]?",
                    text, re.IGNORECASE):
                seen.add((tbl, col))
                assert (tbl, col) in _APPROVED_COLUMN_DROPS, (
                    f"{sql.name}: unapproved DROP COLUMN {tbl}.{col} on a frozen master table. "
                    "It destroys curated data and cannot be undone without a restore. If it is "
                    "genuinely intended, add it to _APPROVED_COLUMN_DROPS with the date and the "
                    "reason, so the decision is reviewable instead of incidental.")
    # The positive pin. Every assertion above is an absence, so a parser that matched nothing —
    # or a corpus of files that no longer name these tables — would report perfect safety.
    assert mentions >= 100, (
        f"the six frozen tables are named only {mentions} times across {len(corpus)} scripts. "
        "They are the curated masters; the deploy scripts create, alter and seed them constantly, "
        "so a number this low means the corpus or the name pattern stopped seeing them and every "
        "'no destructive statement' assertion above is vacuous.")

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
    could not see that the second statement of a guarded BEGIN block is guarded too.

    A MULTI-LINE guard condition is the norm in these scripts (`IF OBJECT_ID(...) IS NOT NULL` /
    `AND COL_LENGTH(...) IS NOT NULL` / `AND COLUMNPROPERTY(...) < 100` / the ALTER), so the
    marker search continues across the continuation lines rather than being decided by the first
    line alone."""
    offenders, guarded = [], 0
    for sql in _frozen_table_corpus():
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
            if upper.startswith("AND ") or upper.startswith("OR "):
                # A continuation of the IF condition above. It can only ADD a marker, never
                # remove one, so a guard already found stays found.
                guard_pending = guard_pending or any(g in line for g in _GUARD_MARKERS)
                continue
            match = re.search(rf"ALTER\s+TABLE\s+{_TABLE_NAME}", line, re.IGNORECASE)
            if match and match.group(1) in _FROZEN_TABLES:
                if guard_pending or True in stack:
                    guarded += 1
                else:
                    offenders.append(f"{sql.name}:{i + 1}: {line}")
            # a completed statement consumes the pending single-statement guard
            if line.rstrip().endswith(";"):
                guard_pending = False
    assert not offenders, (
        "unguarded ALTER against a frozen master table -- make the ALTER the body of an "
        "IF COL_LENGTH/COLUMNPROPERTY/OBJECT_ID guard so re-running is a no-op:\n  "
        + "\n  ".join(offenders))
    # The positive pin: `not offenders` is also what an ALTER pattern that matches nothing
    # reports, and that is precisely how this guard spent its life passing on a deploy path it
    # could not read a single statement of.
    assert guarded >= 15, (
        f"only {guarded} guarded ALTERs against a frozen table were found. These scripts widen "
        "and extend the master tables in dozens of places, so a number this low means the "
        "corpus, the table pattern or the guard parser stopped matching -- and an unguarded ALTER "
        "would now be invisible rather than absent.")

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
    """@tsg_tables must equal the OBJECT MODEL's TSG-owned tables, and so must the CREATE TABLE
    inventory of the handoff DDL scripts. A three-way equality, on purpose.

    This test used to derive its expectation from path 1's own guarded CREATEs and assert set
    equality against the verify list — which made it a consistency check between two files that
    could BOTH be wrong, and they were. Scenario_Library was dropped from the product in August
    2026; "1. TSG_Core.sql" kept creating it and the verify script kept requiring it, so the two
    agreed, this test passed, and a database built by EITHER of the other two deploy paths
    (neither of which creates it) failed sign-off with a blocking "Table missing:
    Scenario_Library" on a correct schema. The shipped remedy was a paragraph in the consolidated
    script telling the operator to read past one blocking failure from a script whose other
    blocking failures are real. Worse, the guard PINNED the staleness in place: removing the name
    from the verify script alone failed the suite.

    Anchoring on the ORM removes the cause. An unmapped table cannot enter either list, because
    the only thing both are compared against is the set of tables the application actually maps."""
    mapped = {cls.__tablename__ for cls in _tsg_owned()}
    assert len(mapped) >= 20, f"only {len(mapped)} mapped TSG tables — models.py did not load"

    created: set[str] = set()
    for f in ("1. TSG_Core.sql", "2. Threat_library.sql", "4. Control_library.sql"):
        text = (_SCRIPTS / f).read_text(encoding="utf-8", errors="replace")
        # only REAL creates — the guarded form. Bare "CREATE TABLE" also appears in prose
        # ("a new column needs a CREATE TABLE entry").
        created |= set(re.findall(GUARDED_CREATE_RE, text))
    assert created == mapped, (
        "the handoff CREATE TABLE inventory drifted from app/db/models.py: "
        f"created but not mapped: {sorted(created - mapped)}; "
        f"mapped but not created: {sorted(mapped - created)}. A table the object model does not "
        "map is a table nothing reads or writes, so creating it makes every other deploy path "
        "look incomplete by comparison.")

    sql = _verify_sql()
    block = re.search(TSG_TABLES_RE, sql, re.DOTALL)
    assert block, "@tsg_tables VALUES block not found"
    listed = set(re.findall(SINGLE_RE, block.group(1)))
    assert listed == mapped, (
        "verify script's table list drifted from app/db/models.py: "
        f"only in script: {sorted(listed - mapped)}; "
        f"only in models.py: {sorted(mapped - listed)}")
    assert f"ALL {len(mapped)} TSG TABLES EXIST" in sql
    assert f"All {len(mapped)} TSG tables present" in sql


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


# ---------------------------------------------------------------------------
# THE CONSOLIDATED SCRIPT BUILDS AND VERIFIES EVERY BOOT INDEX. Real incident: UX_Scenario_ActiveScoped
# was added to the numbered scripts, the verify script and REQUIRED_INDEXES, but not to the operator-run
# scripts/tsg_remediation_tables.sql. A database built from it could not boot the new code, and nothing
# noticed, because the index checks above read only the numbered scripts.
# ---------------------------------------------------------------------------
def test_consolidated_script_builds_and_verifies_every_boot_index() -> None:
    """Reads the ONE `_CREATE_INDEX_RE` defined above, which is the point: this test used to
    carry a SECOND definition of that module-level name, and because Python keeps the last
    binding, the permissive copy declared here silently replaced the strict one for the whole
    module — see the comment on the surviving pattern."""
    from app.db.invariants import REQUIRED_INDEXES
    sql = _CONSOLIDATED.read_text(encoding="utf-8")
    created = _index_definitions([_CONSOLIDATED])
    assert len(created) >= 25, f"only parsed {len(created)} indexes out of {_CONSOLIDATED.name}"
    start = sql.index("required_index(idx, tbl) AS (")
    verified = {name for name, _ in re.findall(r"\(\s*'(\w+)'\s*,\s*'(\w+)'\s*\)",
                                               sql[start:sql.index(") v(", start)])}
    assert len(verified) >= 25, "the required_index block parsed almost empty — its shape moved"
    problems = []
    for name, table, cols in REQUIRED_INDEXES:
        if created.get(name, (None, None))[:2] != (table, tuple(cols)):
            problems.append(f"{name}: not created as {table}{tuple(cols)} (found {created.get(name)})")
        elif not created[name][2]:
            problems.append(f"{name}: created WITHOUT the UNIQUE keyword, and invariants asserts "
                            "uniqueness at boot")
        if name not in verified:
            problems.append(f"{name}: missing from the script's required_index check")
    assert not problems, ("a database built from tsg_remediation_tables.sql would not boot:\n  "
                          + "\n  ".join(problems))


def test_every_boot_checked_index_names_a_script_that_creates_it() -> None:
    """The boot refusal names the script for each missing index from invariants.INDEX_SCRIPTS. The
    hand-written sentence it replaced fell behind a migration without anyone noticing; this pins
    the data instead: every index the boot checks has an entry, no entry is stale, and every
    named script exists and really creates that index."""
    from app.db.invariants import FILTERED_INDEX_LITERALS, INDEX_SCRIPTS, REQUIRED_INDEXES

    repo = Path(__file__).resolve().parents[1]
    checked = {n for n, _, _ in REQUIRED_INDEXES} | {n for n, _ in FILTERED_INDEX_LITERALS}
    problems = [f"{n}: no INDEX_SCRIPTS entry" for n in sorted(checked - INDEX_SCRIPTS.keys())]
    problems += [f"{n}: INDEX_SCRIPTS entry for an index the boot never checks"
                 for n in sorted(INDEX_SCRIPTS.keys() - checked)]
    for name, scripts in INDEX_SCRIPTS.items():
        for rel in scripts:
            path = repo / rel
            if not path.exists():
                problems.append(f"{name}: {rel} does not exist")
            elif not re.search(rf"CREATE\s+(UNIQUE\s+)?(NONCLUSTERED\s+)?INDEX\s+{name}\b",
                               path.read_text(encoding="utf-8", errors="replace"), re.I):
                problems.append(f"{name}: {rel} does not create it")
    assert not problems, "\n".join(problems)


class _FakeIndexEngine:
    """Stands in for SQL Server's sys.indexes: _assert_indexes reads (name, table, is_disabled,
    is_unique, 'col,col') rows, which is all this returns."""

    def __init__(self, rows):
        self.rows = rows

    def connect(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def execute(self, *_a, **_k):
        return self

    def all(self):
        return self.rows


def _healthy_index_rows():
    from app.db.invariants import REQUIRED_INDEXES
    return [(n, t, False, True, ",".join(c)) for n, t, c in REQUIRED_INDEXES]


def test_boot_passes_when_every_required_index_is_healthy() -> None:
    """The fake is faithful: the unmodified rows must boot, or every refusal below is vacuous."""
    from app.db.invariants import _assert_indexes
    _assert_indexes(_FakeIndexEngine(_healthy_index_rows()))


@pytest.mark.parametrize(("breakage", "expect"), [
    # Missing — the refusal names BOTH ways to create it, including the new standalone migration.
    ("missing", "UX_Scenario_ActiveScoped: scripts/eyshield_handoff/1. TSG_Core.sql "
                "(or, on a database already up, scripts/TSG_Migration_ActiveScopedIndex.sql)"),
    ("wrong_columns", "wrong table/columns"),
    ("non_unique", "not enforcing"),
    ("disabled", "not enforcing"),
])
def test_boot_refuses_a_broken_scoped_threat_index(breakage, expect) -> None:
    """A1's guard is only a guard if a database without it cannot start. Never exercised before:
    the live runs only proved the index refuses a duplicate once it exists."""
    from app.db.invariants import StartupInvariantError, _assert_indexes

    rows = []
    for name, table, disabled, unique, cols in _healthy_index_rows():
        if name != "UX_Scenario_ActiveScoped":
            rows.append((name, table, disabled, unique, cols))
        elif breakage != "missing":
            rows.append({"wrong_columns": (name, table, disabled, unique, "SessionID,IdentityHash"),
                         "non_unique": (name, table, disabled, False, cols),
                         "disabled": (name, table, True, unique, cols)}[breakage])
    with pytest.raises(StartupInvariantError, match=re.escape(expect)):
        _assert_indexes(_FakeIndexEngine(rows))
