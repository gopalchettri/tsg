"""The deployment package cannot drift away from the ORM.

WHY THIS FILE EXISTS. scripts/tsg_script/ is generated from app/db/models.py. Generated files rot
the moment someone adds a column and forgets to regenerate — and a deployment script that is one
column behind does not fail loudly: it creates a database the application then crashes against at
run time, in whichever environment was deployed last.

So this regenerates the package in memory and compares. Same idea as
`apply_env_comments.py --check`: the tool already knew how to detect drift, it just had no caller.
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_PKG = _ROOT / "scripts" / "tsg_script"
_GENERATOR = _PKG / "_generate.py"

# Tables TSG reads but must never create. Creating one would have TSG claim ownership of another
# team's table, and an ALTER against it could break their application.
_PLATFORM = {
    "ctm_scan_category", "ctm_scan_entity", "ctm_scan_entity_bu",
    "ctm_scan_entity_supporting_system", "onboarding_sectors", "onboarding_services",
    "onboarding_supporting_systems", "option", "option_value", "user", "user_scope_assignment",
}


def _generator():
    spec = importlib.util.spec_from_file_location("tsg_generate", _GENERATOR)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _table_sql() -> dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8") for p in (_PKG / "01_tables").glob("*.sql")}


def test_the_package_is_present_in_the_checkout_at_all() -> None:
    """Nearly every test below walks `_PKG.rglob("*.sql")`. With the directory ABSENT those loops
    iterate nothing and PASS — so a checkout carrying no deployment package at all reads as a
    clean one. That is not hypothetical: `scripts/tsg_script/` is generated, and generated output
    is exactly the kind of thing that never gets committed. A fresh clone would then ship no
    operator deploy artifact, and this module would say everything matched.

    Fails loudly instead, and names the command that produces it."""
    assert _PKG.is_dir() and _GENERATOR.is_file(), (
        f"{_PKG.name}/ is missing from this checkout. If it was never committed, commit it — it "
        "is the artifact an operator runs. To rebuild it: python scripts/tsg_script/_generate.py")
    found = {p.relative_to(_PKG).as_posix() for p in _PKG.rglob("*.sql")}
    for required in ("TSG_Deploy_All.sql", "02_constraints/001_default_constraints.sql",
                    "02_constraints/002_check_constraints.sql",
                    "02_constraints/003_unique_constraints.sql",
                    "99_validation/001_post_deployment_validation.sql",
                    "99_validation/002_schema_verdict.sql"):
        assert required in found, (
            f"{required} is absent, so every assertion in this module that reads it is skipped "
            "rather than checking. Run: python scripts/tsg_script/_generate.py")
    assert len(found) >= 40, (
        f"only {len(found)} .sql files in the package — one per owned table plus one index script "
        "per indexed table is over 40. A partial package makes the drift comparisons partial too.")


def test_every_orm_table_tsg_owns_has_a_script() -> None:
    """The completeness claim. A table the application maps but the package never creates is a
    database that deploys clean and then fails on first use."""
    from app.db import models as m

    owned = set(m.Base.metadata.tables) - _PLATFORM
    scripted = {re.sub(r"^\d+_|\.sql$", "", name) for name in _table_sql()}
    missing = sorted(owned - scripted)
    assert not missing, f"ORM tables with no deployment script: {missing}"


def test_no_script_creates_a_platform_table() -> None:
    """The opposite mistake, and the more dangerous one: TSG must never CREATE a table another
    team owns."""
    offenders = []
    for name, text in _table_sql().items():
        for platform in _PLATFORM:
            if re.search(rf"CREATE TABLE dbo\.\[{re.escape(platform)}\]", text, re.I):
                offenders.append(f"{name} creates {platform}")
    assert not offenders, "scripts create platform-owned tables: " + "; ".join(offenders)


def test_the_package_matches_the_orm_today() -> None:
    """Regenerate and compare. A difference means someone changed the models and did not run
    `python scripts/tsg_script/_generate.py`."""
    gen = _generator()
    from app.db import models as m

    for order, name in enumerate(gen.TABLE_ORDER, start=1):
        expected = gen.table_script(m.Base.metadata.tables[name], order)
        actual = (_PKG / "01_tables" / f"{order:03d}_{name}.sql").read_text(encoding="utf-8")
        assert actual.replace("\r\n", "\n") == expected.replace("\r\n", "\n"), (
            f"{order:03d}_{name}.sql is out of date with app/db/models.py. "
            "Run: python scripts/tsg_script/_generate.py")


def _validation_sql() -> dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8")
            for f in ("00_validation", "99_validation") for p in (_PKG / f).glob("*.sql")}


def test_types_use_names_sql_server_reports() -> None:
    """A type spelling the database never reports makes tsg_reconcile_column take its
    `@want_base <> @base` branch and print [BLOCKED] — "different type family, convert by hand" —
    for a column that is already correct. Three spellings have done this:

      INTEGER   sys.columns says 'int'            (82 columns)
      NTEXT     Text() compiles to the type Microsoft deprecated; the schema uses nvarchar(max)
      DATETIME  DateTime() carries no precision; 84 of this schema's datetime columns are
                datetime2, and emitting DATETIME reported a type-family change on all of them

    Verified live: before the fix the column verdict reported 71 false failures against a
    database the application runs against today."""
    # \b, not `in`: a bare substring test flags `AssetContextJSON`, because CONTEXT contains
    # NTEXT. A column name is not a type.
    bad = {"INTEGER": "int", "NTEXT": "nvarchar(max)"}
    for name, text in {**_table_sql(), **_validation_sql()}.items():
        upper = text.upper()
        for spelling, real in bad.items():
            assert not re.search(rf"\b{spelling}\b", upper), (
                f"{name} emits {spelling}; sys.columns reports '{real}', so the comparison would "
                "never match. Normalise it in _generate.py::_CANONICAL.")

    # DATETIME is NOT banned outright — the reviewed script declares 8 genuinely `datetime`
    # columns and sys.columns reports them as such. What was wrong was emitting it for columns
    # the deployed schema stores as datetime2. These four fell through to the ORM's precisionless
    # DateTime() spelling before source_column_types() existed; they are the canaries.
    gen = _generator()
    from app.db import models as m

    for table, column in (("Subsystem_Stage_State", "StartedAt"),
                          ("Subsystem_Stage_State", "FinishedAt"),
                          ("Threat_Scenario", "GenStartedAt"),
                          ("Threat_Scenario", "GenFinishedAt")):
        got = gen.tsql_type(m.Base.metadata.tables[table].columns[column])
        assert got.upper().startswith("DATETIME2"), (
            f"{table}.{column} generates {got}, but the database stores datetime2 — the "
            "reconcile check would report a type-family change on a correct column.")


def test_the_sign_off_verifies_every_column_and_index_shape() -> None:
    """001_post_deployment_validation.sql declares five failure counters — tables, primary keys,
    indexes, check constraints, isolation — and not one reads a COLUMN. So a deployment where
    tsg_reconcile_column printed [BLOCKED] on a narrowing change, or added a NOT NULL column as
    NULL because the table had rows, still ended with a clean verdict.

    Its index check was no better: it matched on NAME and TABLE, so an index carrying the right
    name over the WRONG COLUMNS, or with its WHERE filter dropped, signed off clean — and every
    one of them is a uniqueness guard the application leans on for a race it cannot otherwise
    win. The generated schema verdict closes both, so it must exist, match the ORM and the
    reviewed DDL, and print the final word."""
    gen = _generator()
    from app.db import models as m

    path = _PKG / "99_validation" / "002_schema_verdict.sql"
    assert path.exists(), "the schema verdict is missing; run scripts/tsg_script/_generate.py"
    assert not (_PKG / "99_validation" / "002_column_verdict.sql").exists(), (
        "the columns-only predecessor is still here; it prints FINAL SIGN-OFF after checking no "
        "index at all. _generate.py removes it — re-run the generator.")

    actual = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    assert actual == gen.column_verdict_script(m.Base.metadata).replace("\r\n", "\n"), (
        "002_schema_verdict.sql is out of date with app/db/models.py. "
        "Run: python scripts/tsg_script/_generate.py")

    every = sum(len(m.Base.metadata.tables[t].columns) for t in gen.TABLE_ORDER)
    assert f"Columns expected:   {every}" in actual, "the verdict miscounts the columns it checks"

    # Index SHAPE, not just presence: key columns in order, uniqueness and filtered-ness.
    idx = gen.index_definitions()
    # DERIVED from the DDL, not hardcoded. The failure this guards is "the regex stopped matching"
    # — a parser that silently drops indexes, so the verdict checks fewer shapes than the package
    # builds. A literal count ALSO fails every time an index is legitimately added, which teaches
    # whoever hits it that the number is noise to bump rather than a signal to read; it said 31
    # until the diagnostics indexes landed. Counting CREATE statements in the same file the parser
    # reads keeps the tripwire and drops the false alarm.
    declared = len(re.findall(
        r"^\s*CREATE\s+(?:UNIQUE\s+)?(?:NON)?CLUSTERED?\s*INDEX|^\s*CREATE\s+(?:UNIQUE\s+)?INDEX",
        gen.SOURCE_SQL.read_text(encoding="utf-8"), re.M | re.I))
    assert len(idx) == declared, (
        f"the reviewed DDL declares {declared} indexes but the parser found {len(idx)} — the DDL "
        "regex has stopped matching, and every shape comparison it feeds is now silently checking "
        "fewer indexes than the package actually creates")
    assert all(i["columns"] for i in idx), (
        "an index parsed with no key columns — the DDL regex stopped matching, and every shape "
        "comparison it feeds would silently compare against an empty column list")
    # The verdict checks unique CONSTRAINTS alongside the indexes — SQL Server implements one
    # with a unique index, so the same shape comparison covers it. Leaving them out is how
    # UQ_Config_Tuning_Key stayed missing from a database the verdict called clean.
    uniques = gen.unique_constraints(m.Base.metadata)
    assert f"Indexes expected:   {len(idx) + len(uniques)}" in actual, (
        "the verdict's index count does not cover the indexes PLUS the unique constraints")
    for name in ("UX_Session_ActiveAsset", "UX_Scenario_ActiveAccepted",
                 *(u["name"] for u in uniques)):
        assert name in actual, f"{name} is not in the index verdict"

    # DEFAULTS. 001 only PRINTS a count as [INFO] and never fails on it, so before this the
    # package could create 21 defaults and verify none. A column that loses its default does not
    # error — it silently stores whatever the insert omitted. Checked BY COLUMN, because a
    # correct database may carry the default under an auto-generated name.
    dfs = gen.default_definitions()
    assert len(dfs) == 21, f"expected 21 defaults parsed from the reviewed DDL, got {len(dfs)}"
    assert f"Defaults expected:  {len(dfs)}" in actual, "the verdict does not count the defaults"
    assert "@df_missing" in actual and "no DEFAULT on" in actual, (
        "the verdict no longer FAILS on a missing default")
    for d in dfs:
        assert f"N'{d['column']}'" in actual, f"{d['table']}.{d['column']} is not verified"

    # IDENTITY. The application never supplies these ids — dal.upsert_threat_type inserts
    # without the key and reads the generated value back — so a table created without identity
    # passes every other check and then fails on the first library write with "Cannot insert
    # the value NULL". The package emitted IDENTITY nowhere until this was fixed.
    idents = gen.identity_columns()
    assert len(idents) == 6, f"expected 6 IDENTITY columns, got {sorted(idents)}"
    for (tbl, col) in idents:
        create = (_PKG / "01_tables").glob(f"*_{tbl}.sql")
        body = next(create).read_text(encoding="utf-8")
        assert f"[{col}] INT IDENTITY(1,1) NOT NULL" in body, (
            f"{tbl}.{col} is created without IDENTITY; the first insert into {tbl} will fail")
    assert f"Identity expected:  {len(idents)}" in actual, "the verdict does not check identity"

    # COLLATION. The natural-key unique indexes are the database half of the library's dedup
    # guarantee; under a case-SENSITIVE collation 'Ransomware' and 'ransomware' both insert.
    assert gen.REQUIRED_COLLATION_FAMILY == "_CI_"
    assert "NOT LIKE '%_CI_%'" in actual, "the verdict no longer requires a case-insensitive collation"
    assert "@fail_collation" in actual, "the collation result does not reach the verdict"

    objects = (_PKG / "99_validation" / "001_post_deployment_validation.sql").read_text(
        encoding="utf-8")
    # Comments stripped: the file explains the old "Overall: PASS" bug in prose, and a test that
    # cannot tell an explanation from a PRINT would force the next author to delete the reasoning.
    printed = re.sub(r"--[^\n]*", "", re.sub(r"/\*.*?\*/", "", objects, flags=re.S))
    assert "Objects: PASS" in printed and "Overall: PASS" not in printed, (
        "001 must not announce an overall PASS: it verifies no column, so that verdict was a "
        "claim it never checked. The final sign-off belongs to 002.")


#: The two hand-maintained validation scripts that carry a boot-critical index list: the PRE one
#: that tells the operator what is missing before they start, and the POST one that fails the
#: object verdict over it. Named BY PATH, because selecting them by a prose substring is what made
#: the test below check nothing at all.
_BOOT_INDEX_SCRIPTS = ("001_pre_deployment_validation.sql", "001_post_deployment_validation.sql")


def test_both_validation_scripts_check_every_boot_critical_index() -> None:
    """verify_startup runs REQUIRED_INDEXES *and* FILTERED_INDEX_LITERALS, and IX_Session_Active
    lives only in the second. Both scripts listed 14 names and so signed off on a database the
    API would refuse to boot against. Derived from the invariants here, never hand-counted, so a
    16th index fails this test rather than shipping a scripted blind spot.

    HOW THIS TEST ITSELF FAILED. It used to pick its files with
    `if "oot-critical indexes" not in text: continue` and assert nothing about how many matched. So
    the whole check hung on one PROSE SUBSTRING inside the scripts it polices: rename that heading
    in both files — "Startup-critical indexes" would do it — and the loop examined zero files,
    asserted zero things and passed. A test that reports safety it never checked is worse than no
    test, and the module already had the shape for this (see
    test_the_package_is_present_in_the_checkout_at_all). Files are now selected BY PATH and the set
    that matched is asserted, so a rename fails the test instead of emptying it; the marker is kept
    only as a second, redundant signal."""
    from app.db.invariants import FILTERED_INDEX_LITERALS, REQUIRED_INDEXES

    needed = {n for n, _t, _c in REQUIRED_INDEXES} | {n for n, _lit in FILTERED_INDEX_LITERALS}
    assert len(needed) >= 14, "the boot-critical index list came back almost empty"

    scripts = {name: text for name, text in _validation_sql().items()
               if name in _BOOT_INDEX_SCRIPTS}
    assert set(scripts) == set(_BOOT_INDEX_SCRIPTS), (
        "the boot-critical index check reads exactly these two scripts, and one of them is no "
        f"longer in the package: expected {sorted(_BOOT_INDEX_SCRIPTS)}, found {sorted(scripts)}. "
        "Renaming or removing one used to make this test silently check nothing.")

    for name, text in sorted(scripts.items()):
        assert "oot-critical indexes" in text, (
            f"{name} no longer has a boot-critical index section. If the heading was simply "
            "reworded, reword this marker with it — but the per-index assertions below still run, "
            "which is the whole point of selecting the file by path.")
        missing = sorted(n for n in needed if n not in text)
        assert not missing, f"{name} never checks: {', '.join(missing)}"


def test_every_boot_critical_index_is_in_the_package() -> None:
    """app/db/invariants.py::REQUIRED_INDEXES is what the application verifies at start-up. An
    index missing from the package is an API and a worker that will not boot."""
    from app.db.invariants import REQUIRED_INDEXES

    shipped = "\n".join(p.read_text(encoding="utf-8")
                        for p in (_PKG / "03_indexes").glob("*.sql"))
    missing = sorted({name for name, _t, _c in REQUIRED_INDEXES if name not in shipped})
    assert not missing, (
        "indexes the app refuses to start without, absent from 03_indexes/: " + ", ".join(missing))


@pytest.mark.parametrize("folder,marker", [
    ("01_tables", "tsg_reconcile_column"),
    ("02_constraints", "IF NOT EXISTS"),
    ("03_indexes", "IF NOT EXISTS"),
])
def test_every_script_is_guarded(folder: str, marker: str) -> None:
    """Re-runnability is the package's core promise. An unguarded statement breaks it on the
    second run, which is exactly when a deployment is most likely to be repeated."""
    for path in sorted((_PKG / folder).glob("*.sql")):
        text = path.read_text(encoding="utf-8")
        assert marker in text, f"{path.name} has no existence guard ({marker} not found)"


def test_the_isolation_check_cannot_pass_a_database_it_could_not_read() -> None:
    """The RCSI check decided the verdict from DATABASEPROPERTYEX, which returns NULL on some
    servers (seen on SQL Server 2022 Express with RCSI demonstrably ON). NULL poisoned both
    comparisons in opposite directions: `NULL = 1` made the PRE script print [FAIL] and hand the
    operator an `ALTER DATABASE ... WITH ROLLBACK IMMEDIATE` that disconnects every session, on a
    correct database; `NULL <> 1` made the POST script leave its failure counter at 0 and sign off
    "Overall: PASS" having verified nothing.

    sys.databases.is_read_committed_snapshot_on is a non-nullable bit for every database, and an
    unreadable row must count as a FAILURE — a sign-off that cannot distinguish "ON" from "I could
    not tell" is not a sign-off."""
    for folder in ("00_validation", "99_validation"):
        for path in sorted((_PKG / folder).glob("*.sql")):
            text = path.read_text(encoding="utf-8")
            if "READ_COMMITTED_SNAPSHOT" not in text.upper():
                continue
            # Assert on CODE, not prose: both files name DATABASEPROPERTYEX in the comment that
            # explains why they stopped using it, and a test that cannot tell an explanation from
            # a call would force the next author to delete the reasoning to get green.
            code = _sql_code(text)
            assert "DATABASEPROPERTYEX" not in code.upper(), (
                f"{path.name} decides the isolation verdict from DATABASEPROPERTYEX, which can "
                "return NULL. Read sys.databases.is_read_committed_snapshot_on instead.")
            assert "is_read_committed_snapshot_on" in code, (
                f"{path.name} checks isolation without reading the catalog view that always "
                "answers: sys.databases.is_read_committed_snapshot_on.")

    post = (_PKG / "99_validation" / "001_post_deployment_validation.sql").read_text(
        encoding="utf-8")
    assert "@rcsi IS NULL OR" in post, (
        "the post-deployment isolation check must be fail-CLOSED: an unreadable setting has to "
        "fail the sign-off, not fall through to PASS.")


def test_every_script_is_valid_t_sql_the_server_will_accept() -> None:
    """Three bugs made 20 of the 46 scripts un-runnable, and none was visible from reading them.

    1. T-SQL block comments NEST. `Depends on: 01_tables/*` in the generated header opened a
       second comment that was never closed, so SQL Server rejected the FIRST BATCH of all 17
       index files and all 3 constraint files with `Msg 113: Missing end comment mark`. That
       batch is the one carrying `SET QUOTED_IDENTIFIER ON`, required by the filtered indexes —
       so the scripts ran without their own safety settings. sqlcmd fails only that batch and
       continues, which is why it looked like they worked.
    2. The check-constraint regex could span statements, so `002_check_constraints.sql` shipped a
       duplicate, un-rewritten copy of all 22 DEFAULT statements.
    3. Defaults were guarded by constraint NAME, but SQL Server allows one default per COLUMN —
       so a column already carrying an auto-named default (`DF__Identifie__IsAIG__7954A4F6`)
       made the ALTER fail with `Msg 1781`.

    Verified live after the fix: all 46 scripts run with zero errors.
    """
    for path in sorted(_PKG.rglob("*.sql")):
        text = path.read_text(encoding="utf-8")
        assert text.count("/*") == text.count("*/"), (
            f"{path.name} has unbalanced block-comment markers "
            f"({text.count('/*')} open, {text.count('*/')} close). T-SQL comments NEST, so a "
            "stray `/*` — e.g. a path like `01_tables/*` inside the header — swallows the rest "
            "of the batch. Route header values through _generate.py::header(), which escapes it.")

    checks = (_PKG / "02_constraints" / "002_check_constraints.sql").read_text(encoding="utf-8")
    assert "DF_" not in checks, (
        "002_check_constraints.sql contains DEFAULT constraints. The extraction regex is "
        "spanning statements again — it must not cross a `;`.")

    defaults = (_PKG / "02_constraints" / "001_default_constraints.sql").read_text(encoding="utf-8")
    assert "WHERE name = 'DF_" not in defaults, (
        "a default is guarded by constraint NAME. SQL Server permits one default per COLUMN, so "
        "a column already holding an auto-named default fails with Msg 1781. Guard on the column.")
    assert defaults.count("dc.parent_object_id = OBJECT_ID") == 21, (
        "expected all 21 defaults to be guarded on their column")


def test_every_unique_column_in_the_orm_is_created_by_the_package() -> None:
    """`Config_Tuning.TuningKey` is declared `unique=True` in models.py and as a table constraint
    in the reviewed DDL, but table_script() emits only columns + PK and index_blocks() matches
    only `CREATE INDEX` — so the constraint fell through both and a database built from this
    package simply had no uniqueness rule on it.

    That matters: `dal.active_tuning_overrides` loads active rows into a dict with NO `ORDER BY`,
    so two rows sharing a key would silently resolve to whichever the server returned last —
    `max_threats_per_asset` = 20 on one run and 5 on the next, with no error anywhere."""
    gen = _generator()
    from app.db import models as m

    uniques = gen.unique_constraints(m.Base.metadata)
    assert uniques, "no unique constraints found; the DDL parser stopped matching"

    emitted = (_PKG / "02_constraints" / "003_unique_constraints.sql").read_text(encoding="utf-8")
    for u in uniques:
        assert f"ADD CONSTRAINT [{u['name']}]" in emitted, f"{u['name']} is not created"

    covered = {(u["table"], c) for u in uniques for c in u["columns"]}
    declared = {(t, c.name) for t in gen.TABLE_ORDER
                for c in m.Base.metadata.tables[t].columns if c.unique}
    assert not (declared - covered), (
        f"columns marked unique=True with no constraint in the package: {declared - covered}")


def test_every_status_marker_survives_the_client_that_prints_it() -> None:
    """`sqlcmd` DELETES a `[MARKER]` that opens a message line, and the whole package speaks in
    those markers.

    The ODBC driver prefixes every message with `[Microsoft][ODBC Driver 17 for SQL Server]
    [SQL Server]`, and sqlcmd strips leading bracket groups to remove it — one group too many
    when the message itself begins with `[`. Measured against SQL Server 2022 / sqlcmd 16:

        PRINT '[FAIL] missing index'   ->  " missing index"      the marker is GONE
        PRINT ' [FAIL] missing index'  ->  " [FAIL] missing index"
        SELECT '[FAIL] ...' AS Problem ->  "[FAIL] ..."          result sets are untouched

    So under the very command the README prescribes, a `[FAIL]` line and an `[INFO]` line read
    identically — 94 of them across 28 scripts, including every `[FAIL]`, `[ERROR]`, `[BLOCKED]`
    and `[WARNING]` the package can emit. It went unseen because the markers display correctly in
    SSMS, which is what a person reads the output in; sqlcmd is what a pipeline runs.

    One leading space fixes it, and this is what keeps it fixed — including through a regenerate,
    hence the generator is checked too."""
    opener = re.compile(r"\bPRINT\s+N?'\[")
    offenders = [
        f"{path.relative_to(_PKG).as_posix()}:{n}"
        for path in sorted(_PKG.rglob("*.sql"))
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if opener.search(line)
    ]
    assert not offenders, (
        "these PRINT statements open with a status marker, which sqlcmd deletes — a failure "
        "then reads exactly like an informational line: " + ", ".join(offenders[:10]))

    assert not opener.search(_GENERATOR.read_text(encoding="utf-8")), (
        "_generate.py emits a PRINT opening with a status marker, so the next regenerate puts "
        "the stripped markers back into every generated script. Emit `PRINT ' [MARKER]` — the "
        "leading space is what survives sqlcmd.")


def test_the_single_file_deployment_matches_the_package() -> None:
    """`TSG_Deploy_All.sql` is what a UAT or Prod DBA is handed, so it is the copy that matters.

    A concatenation is the classic thing that rots: the 47 files get a fix, the combined file does
    not, and the environment nobody develops on quietly deploys last month's schema — with no
    error anywhere, because the stale file is perfectly valid T-SQL.

    Two independent checks, because the obvious one is not enough on its own. Comparing the file
    to `combined_script()` proves it was regenerated, but would still pass if that function were
    broken and emitted nothing but headers. So every source script's text is also required to be
    present verbatim."""
    gen = _generator()

    path = _PKG / gen.COMBINED_NAME
    assert path.exists(), (
        f"{gen.COMBINED_NAME} is missing; run scripts/tsg_script/_generate.py")

    actual = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    assert actual == gen.combined_script().replace("\r\n", "\n"), (
        f"{gen.COMBINED_NAME} is out of date with the scripts it contains — a fix landed in the "
        "package and the file handed to UAT still has the old text. "
        "Run: python scripts/tsg_script/_generate.py")

    sources = sorted((p for p in _PKG.rglob("*.sql") if p.name != gen.COMBINED_NAME),
                     key=lambda p: p.relative_to(_PKG).as_posix())
    assert len(sources) > 40, f"only {len(sources)} scripts found; the package layout moved"

    unguarded = actual.replace(gen.STOP_GUARD, "")   # the SSMS stop-check follows every GO
    for n, src in enumerate(sources, start=1):
        rel = src.relative_to(_PKG).as_posix()
        assert f">>> [{n}/{len(sources)}] {rel}" in actual, (
            f"{rel} has no locator in {gen.COMBINED_NAME}, or is at the wrong position. The "
            "order is the deployment order — tables before constraints before indexes.")
        body = src.read_text(encoding="utf-8").replace("\r\n", "\n").rstrip("\n")
        assert body in unguarded, (
            f"{rel} is named in {gen.COMBINED_NAME} but its statements are not there in full. "
            "A locator without its script deploys nothing and reports nothing.")


def test_the_single_file_stops_at_the_first_error_in_ssms() -> None:
    """SSMS runs every batch even after one fails, and the DBA pastes this file into SSMS — so
    without a stop-check after EVERY batch a failed step is followed by 40 more that report
    [EXISTS] and a deployment that looks finished. One missing guard is one batch whose failure
    is silently run past."""
    gen = _generator()
    actual = (_PKG / gen.COMBINED_NAME).read_text(encoding="utf-8").replace("\r\n", "\n")

    assert gen.STOP_PROLOGUE in actual, "the run never resets NOEXEC / the stop flag first"
    _head, _, rest = actual.partition(gen.STOP_PROLOGUE)
    body, sep, _tail = rest.rpartition("SET NOEXEC OFF;\nGO\n")
    assert sep, "the file never switches execution back on, so the final verdict never prints"

    go_lines = len(re.findall(r"(?m)^GO[ \t]*$", body))
    guards = body.count(gen.STOP_GUARD)
    assert guards and go_lines == 2 * guards, (
        f"{go_lines - 2 * guards} batch(es) in {gen.COMBINED_NAME} have no stop-check after "
        "them; an error there is run past in SSMS. Every GO must be followed by STOP_GUARD.")

    # END CATCH resets @@ERROR, so every CATCH that reports a failure must also set the flag.
    for name in ("000_helpers.sql", "002_enable_isolation_level.sql"):
        text = (_PKG / "00_validation" / name).read_text(encoding="utf-8")
        assert text.count("BEGIN CATCH") <= text.count(f"N'{gen.STOP_FLAG}', 1"), (
            f"{name} has a CATCH that does not set {gen.STOP_FLAG}; its failure would not stop "
            "the combined deployment.")


def test_every_table_script_reconciles_its_primary_key() -> None:
    """The CREATE sets a key only for a NEW table. DevTest5 carried an older
    Threat_Scenario_Control_Map keyed on (OutputID, ControlLibraryID); the app writes ScenarioID
    and never supplies OutputID, so every insert failed while the sign-off said PASS."""
    gen = _generator()
    from app.db import models as m
    tables = _table_sql()
    for t in gen.TABLE_ORDER:
        pk = ",".join(c.name for c in m.Base.metadata.tables[t].primary_key.columns)
        if not pk:
            continue
        script = next(text for name, text in tables.items() if name.endswith(f"_{t}.sql"))
        call = f"EXEC dbo.tsg_reconcile_primary_key @table = N'{t}', @columns = N'{pk}';"
        assert call in script, f"{t}'s table script does not reconcile its primary key ({pk})"
        assert script.index(call) < script.index("tsg_report_extra_columns"), (
            f"{t}: the key must be fixed BEFORE extra columns - an old key column cannot be made "
            "NULL-able while it is still in the key")


def test_a_fresh_database_and_an_existing_one_reach_the_same_columns() -> None:
    """Each table script has two mutually exclusive halves and both must describe the same table.

    An EMPTY database takes the CREATE and the reconcile calls then all print [EXISTS]. A database
    that ALREADY has the table - UAT does - skips the CREATE entirely, so the reconcile calls are
    the only thing that can add a new column to it. A column in one list and not the other
    therefore deploys two different schemas from one script, and the package's no-op-on-re-run
    promise only holds for whichever half was complete: reconcile prints [EXISTS] and changes
    nothing only when it finds the column at exactly the type and nullability it asks for.

    Both lists are derived from the ORM rather than read off each other, so a column added to
    models.py (Grounding_Calibration_Run.ControlMapTh is the one this was written for) is covered
    by existing and cannot be exempt by omission."""
    gen = _generator()
    from app.db import models as m

    tables = _table_sql()
    idents = gen.identity_columns()
    for t in gen.TABLE_ORDER:
        script = next(text for name, text in tables.items() if name.endswith(f"_{t}.sql"))
        cols = list(m.Base.metadata.tables[t].columns)
        for c in cols:
            ident = idents.get((t, c.name))
            created = (f"        [{c.name}] {gen.tsql_type(c)}"
                       + (f" IDENTITY({ident[0]},{ident[1]})" if ident else "")
                       + f" {'NULL' if c.nullable else 'NOT NULL'}")
            assert created in script, (
                f"{t}.{c.name} is not in the CREATE, so a fresh database never gets it: "
                f"expected {created.strip()}")
            reconciled = (f"EXEC dbo.tsg_reconcile_column @table = N'{t}', @column = N'{c.name}',"
                          f"\n     @expected = N'{gen.tsql_type(c)}', "
                          f"@nullable = {'1' if c.nullable else '0'}")
            assert reconciled in script, (
                f"{t}.{c.name} is not reconciled at {gen.tsql_type(c)} "
                f"{'NULL' if c.nullable else 'NOT NULL'}, so a database that already has "
                f"{t} never receives it - and a re-run would keep trying to change it")

        # No column in the script the ORM does not know about, in EITHER half. A stale entry is
        # the same bug from the other side: the reconcile would try to add or alter it forever.
        assert script.count("EXEC dbo.tsg_reconcile_column") == len(cols), (
            f"{t} reconciles {script.count('EXEC dbo.tsg_reconcile_column')} columns but the ORM "
            f"maps {len(cols)}. Run: python scripts/tsg_script/_generate.py")

        # The reconcile calls must sit OUTSIDE the create-or-skip branch. Inside it, an existing
        # table would take the ELSE and no new column would ever be added to UAT or Prod.
        assert script.index("EXEC dbo.tsg_reconcile_column") > script.index(
            "PRINT ' [EXISTS]  Table:"), (
            f"{t}: the column reconcile sits inside the CREATE branch, so a database that already "
            "has the table would never receive a column added later")


def test_legacy_names_are_renamed_first_and_only_dropped_when_lossless() -> None:
    """UAT still carried pre-rename names (Threat_Scenario_Output, OutputID, ...). Adding the new
    name beside the old one strands every existing value under the old name, so each listed legacy
    column is RENAMED before the column reconcile runs, and the old one is dropped only when every
    value it holds is already in the new column. The package never drops an UNKNOWN column."""
    gen = _generator()
    for name, text in _table_sql().items():
        table = name.split("_", 1)[1].removesuffix(".sql")
        renames = gen.LEGACY_COLUMN_RENAMES.get(table, [])
        assert text.count("DROP COLUMN") == len(renames), f"{name} drops a column it does not list"
        for old, new in renames:
            call = f"EXEC dbo.tsg_rename_column @table = N'{table}', @old = N'{old}', @new = N'{new}';"
            assert call in text, f"{name}: {old} -> {new} is not renamed"
            assert text.index(call) < text.index("EXEC dbo.tsg_reconcile_column"), (
                f"{name}: {old} must be renamed BEFORE the reconcile adds an empty {new}")
            at = text.index(f"DROP COLUMN [{old}]")
            assert text.index("tsg_reconcile_primary_key") < at < text.index("tsg_report_extra_columns")
            assert f"[{new}] <> [{old}]" in text, f"{name}: {old} dropped without proving it is copied"
    for new, old in gen.LEGACY_TABLE_RENAMES.items():
        text = next(t for n, t in _table_sql().items() if n.endswith(f"_{new}.sql"))
        assert text.index(f"sp_rename 'dbo.{old}', '{new}'") < text.index("CREATE TABLE"), (
            f"{old} must be renamed before the CREATE builds an empty {new} beside it")


def test_the_package_declares_no_foreign_keys() -> None:
    """The schema has none on purpose: rows are retired with Superseded = 1 rather than deleted,
    some columns point at a schema TSG does not own, and Scenario_Audit.SubsystemID uses 0 and
    NULL as meaningful values. A well-meaning FK here would fail to create, or block writes the
    application makes today."""
    for path in sorted(_PKG.rglob("*.sql")):
        text = path.read_text(encoding="utf-8")
        assert "FOREIGN KEY" not in text.upper(), (
            f"{path.name} declares a FOREIGN KEY. See README section 6 before adding one.")


def _sql_code(text: str) -> str:
    """The statements SQL Server will execute: block comments, line comments and the CONTENTS of
    every string literal removed.

    Blanking the literals is the part that matters. Every script that so much as MENTIONS the
    isolation level prints the ALTER inside a `PRINT`, so a test reading raw text cannot tell the
    script that RUNS it from the two that merely offer it to the operator — and asserting on raw
    text would force the next author to delete the operator's instructions to get green.

    Scanned in ONE pass rather than three `re.sub` calls, because the passes interfere and the
    first draft of this helper proved it: stripping `--` comments first ate the closing quote of
    `PRINT '--- isolation level ---'`, so every quote after it paired up shifted by one and half
    the file's real statements were blanked as though they were strings. A single scanner also
    gets the two things a regex cannot — T-SQL block comments NEST, and `''` inside a literal is
    an escaped quote rather than the end of it."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        pair = text[i:i + 2]
        if pair == "/*":
            depth, i = 1, i + 2
            while i < n and depth:
                if text[i:i + 2] == "/*":
                    depth, i = depth + 1, i + 2
                elif text[i:i + 2] == "*/":
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
        elif pair == "--":
            while i < n and text[i] != "\n":
                i += 1
        elif text[i] == "'":
            i += 1
            while i < n:
                if text[i] != "'":
                    i += 1
                elif text[i + 1:i + 2] == "'":
                    i += 2
                else:
                    i += 1
                    break
            out.append("''")
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


#: Every .sql in the repository an operator can run against a database, across all three deploy
#: paths. The two isolation-level guards below read this, not one folder.
_DEPLOY_SCRIPTS = sorted([
    *(_ROOT / "scripts").glob("*.sql"),
    *(p for p in (_ROOT / "scripts" / "eyshield_handoff").glob("*.sql") if " copy" not in p.name),
    *(_ROOT / "scripts" / "eyshield_handoff" / "scripts").glob("*.sql"),
    *_PKG.rglob("*.sql"),
])


def test_no_deploy_script_takes_the_database_single_user() -> None:
    """`ALTER DATABASE ... SET SINGLE_USER` is forbidden in every deploy script, on every path.

    THE INCIDENT SHAPE. Paths 1 and 2 enabled Read-Committed Snapshot Isolation with a
    three-statement dance: SET SINGLE_USER WITH ROLLBACK IMMEDIATE, SET READ_COMMITTED_SNAPSHOT ON,
    SET MULTI_USER, inside one IF block with no TRY/CATCH. The middle statement can fail:
    SINGLE_USER succeeds and evicts every other session, one of them reconnects and takes the
    single permitted connection, the ALTER fails "database is in use", the batch aborts, and
    SET MULTI_USER never runs. The database is left SINGLE_USER — and it also holds the platform
    tables TSG only reads (ctm_scan_*, onboarding_*, [user], option), so every other application on
    it is locked out until a DBA restores MULTI_USER by hand.

    `SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE` evicts exactly the same sessions in ONE
    statement: either the setting changes or nothing does, so there is no intermediate state to be
    stranded in and nothing to restore. That is why this is a ban rather than a rule about adding a
    rescue path — the rescue path is what you need only if the dance exists.

    Read from CODE, not raw text: `0. TSG_Preflight.sql` tells the operator in a string literal
    what the install is about to run, and a test that cannot tell an explanation from a statement
    would force the next author to delete the operator's warning to get green."""
    assert len(_DEPLOY_SCRIPTS) >= 55, (
        f"the deploy-script corpus shrank to {len(_DEPLOY_SCRIPTS)} files — the globs have "
        "drifted, and a shrinking corpus makes this ban pass by reading less")
    offenders = [p.name for p in _DEPLOY_SCRIPTS
                 if "SINGLE_USER" in _sql_code(p.read_text(encoding="utf-8",
                                                           errors="replace")).upper()]
    assert not offenders, (
        "these deploy scripts take the database SINGLE_USER: " + ", ".join(offenders)
        + ". Use ALTER DATABASE CURRENT SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE "
          "(or WITH NO_WAIT) instead — one atomic statement, nothing to restore if it fails.")
    # The positive pin: a ban is also satisfied by a corpus in which nothing sets the isolation
    # level at all, which is the state the package was in before 002_enable_isolation_level.sql
    # existed. Something must still be turning RCSI on.
    setters = [p.name for p in _DEPLOY_SCRIPTS
               if "SET READ_COMMITTED_SNAPSHOT ON"
               in _sql_code(p.read_text(encoding="utf-8", errors="replace")).upper()]
    assert len(setters) >= 3, (
        f"only {setters} turn READ_COMMITTED_SNAPSHOT on. All three deploy paths must: the API "
        "and every Celery worker refuse to boot without it, so a path that does not set it can "
        "only end by reporting its own omission.")


def test_the_package_sets_every_database_setting_it_validates() -> None:
    """The package CHECKED the isolation level in two places and SET it in none.

    That is not a missing nicety. `app/db/invariants.py::_assert_rcsi_enabled` raises
    StartupInvariantError when READ_COMMITTED_SNAPSHOT is off, so neither the API nor the workers
    boot. Yet 00_validation/001 only REPORTED it off and 99_validation/001 only FAILED over it,
    and nothing in 01_tables, 02_constraints or 03_indexes turned it on. A UAT deployment
    therefore ran all 46 scripts correctly and ended on `Isolation: FAILED`, having built every
    table, index and constraint asked of it and the one thing that was not.

    The package this replaced DID set it (`eyshield_handoff/1. TSG_Core.sql`), so a check
    outliving its fix is a regression. Delete the ALTER and this test fails.

    THE CORPUS IS NOW EVERY DEPLOY SCRIPT THAT WRITES THE SETTING, not `_PKG / "00_validation"`.
    Reading one folder is how the hardened form this test mandates — a single declared switch, one
    gated ROLLBACK IMMEDIATE, NO_WAIT, and blockers named from sys.dm_exec_sessions — applied to
    path 3 alone, while the two older paths named in its own docstring kept the unprotected
    SINGLE_USER dance. A guard whose corpus is narrower than the rule it states is how that
    survived."""
    # The single-file concatenation is excluded, and only here: it bundles 47 unrelated scripts,
    # so the per-script rules below ("exactly one ROLLBACK IMMEDIATE", "no hand-typed error-number
    # list") would be judging statements that belong to 000_helpers.sql's column-alter recovery.
    # Nothing is lost — test_the_single_file_deployment_matches_the_package pins it byte-for-byte
    # to the sources this test does read, and test_no_deploy_script_takes_the_database_single_user
    # above reads it directly.
    setters = [p for p in _DEPLOY_SCRIPTS
               if p.name != "TSG_Deploy_All.sql"
               and "SET READ_COMMITTED_SNAPSHOT ON"
               in _sql_code(p.read_text(encoding="utf-8", errors="replace")).upper()]
    assert setters, (
        "no script in the repository turns READ_COMMITTED_SNAPSHOT on, but "
        "99_validation/001_post_deployment_validation.sql fails its sign-off without it and "
        "app/db/invariants.py refuses to boot. A package that validates a setting it never "
        "creates can only ever end by reporting its own omission.")
    # Named, so a path that quietly stops setting it is a failure rather than a smaller corpus.
    for required in ("002_enable_isolation_level.sql", "1. TSG_Core.sql", "TSG_Core_UAT.sql",
                     "tsg_remediation_tables.sql"):
        assert required in {p.name for p in setters}, (
            f"{required} no longer turns READ_COMMITTED_SNAPSHOT on. Every deploy path has to: "
            "the application does not boot without it, and a path that only CHECKS the setting "
            "ends by reporting its own omission.")

    for path in setters:
        text = path.read_text(encoding="utf-8")
        statements = _sql_code(text).upper()
        # Literals KEPT here on purpose — [EXISTS] is something the script PRINTS. Only the
        # header comment is removed, so the promise cannot be satisfied by prose describing it.
        prose = re.sub(r"/\*.*?\*/", "", text, flags=re.S)

        assert "IS_READ_COMMITTED_SNAPSHOT_ON" in statements, (
            f"{path.name} changes the setting without reading the catalog view that always "
            "answers whether it needs changing. DATABASEPROPERTYEX returns NULL on some servers, "
            "and a script that cannot tell ON from unreadable must not run an ALTER.")
        assert "[EXISTS]" in prose, (
            f"{path.name} is not re-runnable: every script in this package reports [EXISTS] and "
            "changes nothing when the work is already done.")

        # WITH ROLLBACK IMMEDIATE disconnects every session on a database that also holds the
        # platform tables other applications read. It IS in the script — nobody should hand-type
        # a destructive ALTER with their own database name in it, which is how the wrong database
        # gets hit. What must hold is that it cannot fire unless a person deliberately switched
        # it on: exactly one flag, declared OFF, and nothing else gating that statement.
        flat = re.sub(r"\s+", " ", statements)
        flag = re.search(r"DECLARE @(\w+) BIT = (\d);", flat)
        assert flag, (
            f"{path.name} has no single declared switch for the destructive path. Without one "
            "there is nothing to read, nothing to default to off, and nothing for this test to "
            "check.")
        # Which value it DEFAULTS to is the operator's call, not this test's. It is 1 today by
        # explicit decision: the setting is required, the API does not start without it, so a run
        # that leaves it off has not deployed anything. What this test protects is that the switch
        # still exists and still gates the statement — so a site that would rather pick its own
        # moment can set it to 0 and get the refusal instead.
        assert flag.group(2) in {"0", "1"}, (
            f"{path.name} declares @{flag.group(1)} = {flag.group(2)}, which is neither on nor "
            "off. A switch with a third state is a switch nobody can reason about.")
        assert flat.count("ROLLBACK IMMEDIATE") == 1, (
            f"{path.name} executes ROLLBACK IMMEDIATE {flat.count('ROLLBACK IMMEDIATE')} times. "
            "There must be exactly one, so there is exactly one thing to gate.")
        assert re.search(rf"IF @{flag.group(1)} = 1 ALTER DATABASE CURRENT SET "
                         r"READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE;", flat), (
            f"{path.name} runs ROLLBACK IMMEDIATE outside `IF @{flag.group(1)} = 1`, so the "
            "destructive path is reachable without anyone having chosen it.")
        assert "NO_WAIT" in statements, (
            f"{path.name} runs the ALTER with no termination clause, so it waits FOREVER for "
            "other sessions to disconnect — a silent hang in the middle of the sequence. "
            "`WITH NO_WAIT` fails fast instead, which is what lets the script report who is "
            "holding it.")

        # Failing fast is only half of it: the operator has to be told WHO is holding the
        # database. The first draft gated that on `ERROR_NUMBER() IN (5061, 5030, 1205, 1222)`
        # — every "in use" code that looked plausible — and a live run with one other session
        # connected raised 5069, so the branch was skipped and the operator was sent after a
        # permissions problem they did not have. Decide from observable state instead.
        assert "DM_EXEC_SESSIONS" in statements, (
            f"{path.name} refuses without naming who is holding the database, so the operator "
            "has nobody to ask and no way to tell 'in use' from 'no permission'.")
        # And the ALTER has to be INSIDE a TRY, or none of the reporting above can run: an
        # uncaught error ends the batch at the failing statement, so the operator gets SQL
        # Server's bare message and nothing about who is connected or what to do next. This is
        # also what kept the two older paths' three-statement dance from ever restoring
        # MULTI_USER — there was no CATCH for the restore to live in.
        assert "BEGIN TRY" in statements and "BEGIN CATCH" in statements, (
            f"{path.name} runs the isolation-level ALTER without TRY/CATCH. The batch then ends "
            "at the failure, so nothing reports who is holding the database and nothing can undo "
            "a partial change.")
        assert not re.search(r"IN\s*\(\s*\d{3,}", statements), (
            f"{path.name} decides its remedy from a hand-typed list of SQL Server error "
            "numbers. That list was already wrong once (it missed 5069, the code a real busy "
            "database raises). Ask sys.dm_exec_sessions whether anyone is connected — that "
            "cannot go stale.")


def test_the_hand_written_scripts_and_the_readme_cannot_drift_from_the_package() -> None:
    """`_generate.py::main()` writes 01_tables, 02_constraints and 002_schema_verdict.sql — but
    both validation scripts and the README are hand-maintained, and nothing compared their
    filenames or their numbers against what the package actually builds. All three had drifted:

      * 001_post_deployment_validation.sql told the operator to run `002_column_verdict.sql` —
        a name the generator DELETES (`_generate.py:889`). Following it gives file-not-found.
      * It reported `(30 expected)` non-PK indexes against a package that builds 31, so a
        CORRECT database read as though it carried a rogue index.
      * The README's step table never listed `02_constraints/003_unique_constraints.sql`, so a
        reader following it row by row never created `UQ_Config_Tuning_Key` — the uniqueness
        rule `dal.active_tuning_overrides` silently depends on.

    Correcting those three strings fixes today. This test is what stops the fourth."""
    gen = _generator()
    from app.db import models as m

    present = {p.name for p in _PKG.rglob("*.sql")}
    readme = _PKG / "README.md"

    for path in [*sorted(_PKG.rglob("*.sql")), readme]:
        text = path.read_text(encoding="utf-8")
        for ref in sorted(set(re.findall(r"\b\d{3}_[A-Za-z0-9_]+\.sql", text))):
            assert ref in present, (
                f"{path.name} tells the operator to run {ref}, which is not in the package. "
                "A renamed script leaves this instruction behind and the run stops at "
                "file-not-found.")

    post = (_PKG / "99_validation" / "001_post_deployment_validation.sql").read_text(
        encoding="utf-8")

    # SQL Server implements a unique CONSTRAINT with a unique index, so both land in the count
    # this script reads out of sys.indexes. Leaving the constraint out is what made 31 look wrong.
    built = len(gen.index_definitions()) + len(gen.unique_constraints(m.Base.metadata))
    assert f"({built} expected" in post, (
        f"the post-deployment script does not expect the {built} non-PK indexes this package "
        "creates, so a correct database reads as wrong (or a wrong one as correct)")
    assert f"({len(gen.default_definitions())} expected)" in post, (
        "the post-deployment script's default-constraint count no longer matches the package")

    every = sum(len(m.Base.metadata.tables[t].columns) for t in gen.TABLE_ORDER)
    assert f"all {every} columns" in post, (
        "the post-deployment script quotes a column count the schema verdict does not check")

    readme_text = readme.read_text(encoding="utf-8")

    # THE README'S OWN NUMBERS. Its inventory table and its step table both quote counts, and both
    # had fallen behind: "Non-PK indexes | 30" and "| 30 indexes |" against a package that builds
    # 31, and "Default constraints | 21" against 22. A reader reconciling a live database against
    # the README then finds one object it cannot account for — the same reading error the
    # "(30 expected)" line above was fixed for, one file over. Pinned to what the package builds.
    for label, count in (("Non-PK indexes", len(gen.index_definitions())),
                         ("Default constraints", len(gen.default_definitions()))):
        assert f"| {label} | {count} |" in readme_text, (
            f"the README's inventory table does not say '| {label} | {count} |'. The package "
            f"builds {count}; a stale count here makes a correct database read as wrong.")
    assert f"| {len(gen.index_definitions())} indexes |" in readme_text, (
        "the README's 03_indexes step row quotes a stale index count")
    assert f"| {len(gen.default_definitions())} default constraints |" in readme_text, (
        "the README's 001_default_constraints step row quotes a stale default count")

    # 01_tables and 03_indexes are listed as ranges, one row for all 22 or all 17. Every script an
    # operator runs individually needs its own row, or it is simply never run.
    for path in sorted(_PKG.rglob("*.sql")):
        if path.parent.name in {"01_tables", "03_indexes"}:
            continue
        assert path.name in readme_text, (
            f"{path.name} is in the package but not in the README's execution sequence, so an "
            "operator following it step by step never runs it.")
