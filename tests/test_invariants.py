"""CHECKLIST 1 (`invariants._assert_indexes`) — the boot guard on index SHAPE.

This check used to compare index NAMES only, and a UAT database duly booted the
API for months carrying `UX_ThreatType_NaturalKey` built over a legacy
`ThreatCategoryID` column instead of `PrimaryThreatCategoryID`: the right name,
the wrong rule, no complaint from anywhere, and the duplicate-master race
`dal.upsert_threat_type` deliberately loses (R10) silently unguarded the whole
time. The comparison is now a full shape — table, key columns in order, UNIQUE —
and these tests hold it there.

Two layers, because the check has two halves:
  * `diff_index_catalog` is pure (a dict in, three buckets out), so the cases a
    single SQLite file cannot physically express — the same index name sitting
    on two different tables, which SQL Server allows and SQLite does not — are
    driven directly through it;
  * everything else runs `_assert_indexes` against a real database built from
    `IndexSpec.ddl()`, which also proves the DDL the repair path (migration
    0019) emits is exactly the DDL this check accepts.
"""
import pytest
from sqlalchemy import create_engine, text

from app.db import models as m
from app.db.invariants import (
    REQUIRED_INDEXES,
    IndexSpec,
    LiveIndex,
    StartupInvariantError,
    _assert_indexes,
    diff_index_catalog,
    read_index_catalog,
)

_THREAT_TYPE_KEY = next(s for s in REQUIRED_INDEXES if s.name == "UX_ThreatType_NaturalKey")


def _build(tmp_path, name, *, skip=(), extra_ddl=()):
    """A SQLite database carrying every required index except those in `skip`,
    plus whatever `extra_ddl` puts there instead — i.e. a deployment, correct or
    drifted, that `_assert_indexes` can be pointed at."""
    engine = create_engine(f"sqlite:///{tmp_path / name}")
    m.metadata.create_all(engine)
    with engine.begin() as c:
        for spec in REQUIRED_INDEXES:
            if spec.name not in skip:
                c.execute(text(spec.ddl()))
        for ddl in extra_ddl:
            c.execute(text(ddl))
    return engine


def test_correctly_built_schema_passes(tmp_path):
    # Every index created straight from IndexSpec.ddl() — the same statement
    # migration 0019 rebuilds a drifted index with — satisfies the boot check.
    _assert_indexes(_build(tmp_path, "clean.db"))


def test_catalog_reads_back_the_shape_that_was_created(tmp_path):
    with _build(tmp_path, "readback.db").connect() as c:
        catalog = read_index_catalog(c)
    assert catalog["UX_ThreatType_NaturalKey"] == [
        LiveIndex("Threat_Type", ("ThreatTypeName", "PrimaryThreatCategoryID", "SectorID"), True)
    ]
    assert not diff_index_catalog(catalog)


def test_right_name_wrong_column_is_rejected(tmp_path):
    # The exact UAT failure: the natural key keyed on a legacy category column.
    engine = _build(
        tmp_path, "wrongcol.db",
        skip={"UX_ThreatType_NaturalKey"},
        extra_ddl=[
            "ALTER TABLE Threat_Type ADD COLUMN ThreatCategoryID INTEGER",
            "CREATE UNIQUE INDEX UX_ThreatType_NaturalKey ON Threat_Type"
            "(ThreatTypeName, ThreatCategoryID, SectorID) WHERE IsActive = 1 AND IsDeleted = 0",
        ],
    )
    with pytest.raises(StartupInvariantError) as err:
        _assert_indexes(engine)
    message = str(err.value)
    assert "wrong table/columns" in message
    # Both halves must be in the message: what the code needs AND what is really
    # there — an operator cannot act on only one of them.
    assert "needs Threat_Type(ThreatTypeName, PrimaryThreatCategoryID, SectorID)" in message
    assert "found Threat_Type(ThreatTypeName, ThreatCategoryID, SectorID)" in message


def test_wrong_column_order_is_rejected(tmp_path):
    engine = _build(
        tmp_path, "wrongorder.db",
        skip={"UX_ThreatCatalogue_NaturalKey"},
        extra_ddl=["CREATE UNIQUE INDEX UX_ThreatCatalogue_NaturalKey ON Threat_Catalogue"
                   "(ThreatName, ThreatTypeID, SectorID) WHERE IsActive = 1 AND IsDeleted = 0"],
    )
    with pytest.raises(StartupInvariantError, match="wrong table/columns"):
        _assert_indexes(engine)


def test_index_without_unique_is_rejected(tmp_path):
    # The nastiest shape of all: right name, right table, right columns — and it
    # enforces nothing, so every insert the app expects the DB to reject succeeds.
    engine = _build(
        tmp_path, "notunique.db",
        skip={"UX_ThreatActor_NaturalKey"},
        extra_ddl=["CREATE INDEX UX_ThreatActor_NaturalKey ON Threat_Actor"
                   "(ThreatActorName) WHERE IsActive = 1 AND IsDeleted = 0"],
    )
    with pytest.raises(StartupInvariantError, match="NOT UNIQUE"):
        _assert_indexes(engine)


def test_missing_index_still_reports_the_original_message(tmp_path):
    engine = _build(tmp_path, "missing.db", skip={"UX_Profile_Active"})
    with pytest.raises(StartupInvariantError) as err:
        _assert_indexes(engine)
    assert "missing required indexes (run migrations)" in str(err.value)
    assert "UX_Profile_Active" in str(err.value)


def test_every_failure_is_reported_in_one_pass(tmp_path):
    # An operator fixing a broken deployment gets the whole list in one restart,
    # instead of discovering the next problem only after fixing this one.
    engine = _build(
        tmp_path, "multi.db",
        skip={"UX_Profile_Active", "UX_ThreatActor_NaturalKey", "UX_Scenario_ActiveIdentity"},
        extra_ddl=["CREATE INDEX UX_ThreatActor_NaturalKey ON Threat_Actor(ThreatActorName)",
                   "CREATE UNIQUE INDEX UX_Scenario_ActiveIdentity ON Threat_Scenario_Output"
                   "(SessionID, ScopedThreatID) WHERE Superseded = 0"],
    )
    with pytest.raises(StartupInvariantError) as err:
        _assert_indexes(engine)
    message = str(err.value)
    assert "UX_Profile_Active" in message          # missing
    assert "UX_Scenario_ActiveIdentity" in message  # wrong columns
    assert "UX_ThreatActor_NaturalKey" in message   # not unique


def test_remediation_names_a_command_to_run(tmp_path):
    engine = _build(tmp_path, "remediation.db", skip={"UX_Profile_Active"})
    with pytest.raises(StartupInvariantError) as err:
        _assert_indexes(engine)
    assert "alembic upgrade head" in str(err.value)
    assert "bootstrap_schema.sql" in str(err.value)


# --- diff_index_catalog: the cases a single SQLite file cannot express --------
def test_right_name_on_the_wrong_table_is_rejected():
    # SQL Server scopes index names per-table, so a required name can legitimately
    # exist while sitting on something else entirely; SQLite's names are global,
    # so this one can only be driven through the pure comparison.
    catalog = {s.name: [LiveIndex(s.table, s.columns, True)] for s in REQUIRED_INDEXES}
    catalog["UX_ThreatType_NaturalKey"] = [
        LiveIndex("Threat_Catalogue", ("ThreatTypeName", "PrimaryThreatCategoryID", "SectorID"), True)
    ]
    drift = diff_index_catalog(catalog)
    assert not drift.missing and not drift.not_unique
    assert [spec.name for spec, _ in drift.wrong_shape] == ["UX_ThreatType_NaturalKey"]


def test_correct_index_is_accepted_even_when_the_name_is_duplicated_elsewhere():
    catalog = {s.name: [LiveIndex(s.table, s.columns, True)] for s in REQUIRED_INDEXES}
    catalog["UX_ThreatActor_NaturalKey"].append(LiveIndex("Some_Other_Table", ("Whatever",), True))
    assert not diff_index_catalog(catalog)


def test_identifier_comparison_is_case_insensitive():
    # SQL Server's default collation treats SectorID and sectorid as one column;
    # failing a boot over letter case would be a false alarm.
    catalog = {s.name.upper(): [LiveIndex(s.table.lower(), tuple(c.upper() for c in s.columns), True)]
               for s in REQUIRED_INDEXES}
    assert not diff_index_catalog(catalog)


def test_specs_are_checked_not_just_counted():
    # Guards the guard: a spec list nothing in the DB satisfies must fail, so a
    # future edit that quietly stops comparing anything is caught here.
    drift = diff_index_catalog({}, [IndexSpec("UX_Nothing", "Nowhere", ("Nope",))])
    assert [s.name for s in drift.missing] == ["UX_Nothing"]


def test_ddl_matches_the_shape_it_declares():
    assert _THREAT_TYPE_KEY.ddl() == (
        "CREATE UNIQUE INDEX UX_ThreatType_NaturalKey ON "
        "Threat_Type(ThreatTypeName, PrimaryThreatCategoryID, SectorID) "
        "WHERE IsActive = 1 AND IsDeleted = 0"
    )
    assert _THREAT_TYPE_KEY.describe() == (
        "Threat_Type(ThreatTypeName, PrimaryThreatCategoryID, SectorID)"
    )


# --- migration 0019: the repair, planned from the same specs and catalogue ----
def _load_migration_0019():
    """Load the migration by path — `0019_...` is not an importable module name."""
    import importlib.util
    from pathlib import Path

    file = Path(__file__).resolve().parents[1] / "migrations" / "versions" / "0019_repair_guard_index_shape.py"
    spec = importlib.util.spec_from_file_location("migration_0019", file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_repair_plan_is_empty_when_nothing_has_drifted(tmp_path):
    # The migration must be a no-op on a healthy database — no DDL, no downtime,
    # no risk from re-running it.
    with _build(tmp_path, "healthy.db").connect() as c:
        assert _load_migration_0019().plan_repair(c) == []


def test_repair_plan_rebuilds_a_drifted_index(tmp_path):
    engine = _build(
        tmp_path, "drifted.db",
        skip={"UX_ThreatType_NaturalKey"},
        extra_ddl=[
            "ALTER TABLE Threat_Type ADD COLUMN ThreatCategoryID INTEGER",
            "CREATE UNIQUE INDEX UX_ThreatType_NaturalKey ON Threat_Type"
            "(ThreatTypeName, ThreatCategoryID, SectorID) WHERE IsActive = 1 AND IsDeleted = 0",
        ],
    )
    with engine.connect() as c:
        plan = _load_migration_0019().plan_repair(c)
    assert len(plan) == 1
    spec, statements = plan[0]
    assert spec.name == "UX_ThreatType_NaturalKey"
    # Drop the wrong one first, then build the right one from the very spec the
    # boot check is about to test against — the repair cannot disagree with it.
    assert statements == ["DROP INDEX UX_ThreatType_NaturalKey ON Threat_Type", _THREAT_TYPE_KEY.ddl()]


def test_repaired_database_passes_the_boot_check(tmp_path):
    """End to end: a database in the exact UAT state is rejected at boot, the
    migration's own plan is applied, and the same check then passes."""
    engine = _build(
        tmp_path, "roundtrip.db",
        skip={"UX_ThreatType_NaturalKey", "UX_ThreatActor_NaturalKey"},
        extra_ddl=[
            "ALTER TABLE Threat_Type ADD COLUMN ThreatCategoryID INTEGER",
            "CREATE UNIQUE INDEX UX_ThreatType_NaturalKey ON Threat_Type"
            "(ThreatTypeName, ThreatCategoryID, SectorID) WHERE IsActive = 1 AND IsDeleted = 0",
            "CREATE INDEX UX_ThreatActor_NaturalKey ON Threat_Actor(ThreatActorName)",
        ],
    )
    with pytest.raises(StartupInvariantError):
        _assert_indexes(engine)

    with engine.connect() as c:
        plan = _load_migration_0019().plan_repair(c)
    with engine.begin() as c:
        for _spec, statements in plan:
            for statement in statements:
                # The plan is T-SQL, where DROP INDEX names its table; SQLite's
                # index names are database-global and take no ON clause. Only the
                # DROP differs — every CREATE runs here exactly as production gets it.
                c.execute(text(statement.split(" ON ")[0] if statement.startswith("DROP INDEX") else statement))

    _assert_indexes(engine)  # the same check that refused to boot a moment ago
