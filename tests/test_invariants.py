"""Unit tests for the MSSQL-only checks in app/db/invariants.py (_assert_indexes,
_assert_filtered_index_literals). These can't run against the SQLite test DB (no
sys.indexes/INFORMATION_SCHEMA there in the same shape), so they mock the engine/
connection instead of hitting a real MSSQL instance — the thing worth verifying here
is the Python-side comparison logic, not the SQL round trip itself.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.db import invariants
from app.db.invariants import FILTERED_INDEX_LITERALS, REQUIRED_INDEXES, StartupInvariantError

_GOOD_ROWS = [
    (name, table, False, True, ",".join(cols))
    for name, table, cols in REQUIRED_INDEXES
]


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows

    def one(self):
        return self._rows[0]

    def scalar(self):
        return self._rows[0][0] if self._rows else None


class _FakeConn:
    def __init__(self, rows):
        self._rows = rows

    def execute(self, stmt, params=None):
        return _FakeResult(self._rows)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeEngine:
    def __init__(self, rows):
        self._rows = rows
        self.dialect = SimpleNamespace(name="mssql")

    def connect(self):
        return _FakeConn(self._rows)


def test_assert_indexes_passes_when_every_index_matches():
    invariants._assert_indexes(_FakeEngine(_GOOD_ROWS))  # must not raise


def test_assert_indexes_rejects_missing_index():
    rows = _GOOD_ROWS[1:]  # drop the first required index entirely
    with pytest.raises(StartupInvariantError, match="missing required indexes"):
        invariants._assert_indexes(_FakeEngine(rows))


def test_assert_indexes_rejects_name_match_on_wrong_table():
    # The exact bug this check exists to catch: right name, wrong table — a
    # name-only check (the old behavior) would have passed this silently.
    rows = list(_GOOD_ROWS)
    name, _table, cols = REQUIRED_INDEXES[0][0], REQUIRED_INDEXES[0][1], REQUIRED_INDEXES[0][2]
    rows[0] = (name, "Some_Unrelated_Table", False, True, ",".join(cols))
    with pytest.raises(StartupInvariantError, match="wrong table/columns"):
        invariants._assert_indexes(_FakeEngine(rows))


def test_assert_indexes_rejects_disabled_index():
    rows = list(_GOOD_ROWS)
    name, table, cols = REQUIRED_INDEXES[0]
    rows[0] = (name, table, True, True, ",".join(cols))  # is_disabled=True
    with pytest.raises(StartupInvariantError, match="not enforcing"):
        invariants._assert_indexes(_FakeEngine(rows))


def test_assert_filtered_index_literals_passes_when_current():
    rows = [(name, f"WHERE SessionStatus = '{status.value}'") for name, status in FILTERED_INDEX_LITERALS]
    invariants._assert_filtered_index_literals(_FakeEngine(rows))  # must not raise


def test_assert_filtered_index_literals_rejects_stale_literal():
    # Simulates the exact drift this check exists to catch: SessionStatus.active was
    # renamed (e.g. to "in_progress") but this index's filter text was never updated.
    rows = [(name, f"WHERE SessionStatus = '{status.value}'") for name, status in FILTERED_INDEX_LITERALS]
    rows[0] = (rows[0][0], "WHERE SessionStatus = 'in_progress'")
    with pytest.raises(StartupInvariantError, match="no longer matches"):
        invariants._assert_filtered_index_literals(_FakeEngine(rows))
