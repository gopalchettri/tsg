"""Threat-library inventory + import run history.

What these pin down is the question the API exists to answer: "which sources are imported,
which are still pending, and did any attempt fail?" Before the inventory endpoint that was
unanswerable — the import returned a Celery job id that expired and took the evidence with
it, so a source never attempted looked exactly like one whose import blew up.
"""
from __future__ import annotations

import pytest
from sqlalchemy import insert, select

from app.core.config import get_settings
from app.db import models as m
from app.pipeline import threat_library_import as tli

_KEY = "test-admin-key"


@pytest.fixture()
def admin_client(engine, monkeypatch):
    from tests.conftest import make_client

    monkeypatch.setenv("TSG_ADMIN_API_KEY", _KEY)
    get_settings.cache_clear()
    yield make_client({"5"})
    get_settings.cache_clear()


def _sources(client):
    r = client.get("/v1/tsg/threat-library/sources", headers={"X-Admin-Key": _KEY})
    assert r.status_code == 200
    return {s["source"]: s for s in r.json()["sources"]}


def test_inventory_lists_every_source_including_never_imported(admin_client):
    """A pending source must be VISIBLE as loaded=false, not merely absent — an absent row
    is indistinguishable from a source the system doesn't know about."""
    rows = _sources(admin_client)
    assert set(rows) == set(tli.URLS)                    # all 7, not just the imported ones
    assert all(r["loaded"] is False for r in rows.values())
    assert all(r["last_run"] is None for r in rows.values())
    assert rows["attack_ics"]["source_tag"] == tli.SOURCE_TAGS["attack_ics"]


def test_inventory_counts_reflect_imported_rows(admin_client, db):
    """Counts come from the Source column stamped on each imported row."""
    tag = tli.SOURCE_TAGS["capec"]
    db.execute(insert(m.Threat_Type), [
        {"ThreatTypeID": 900, "ThreatTypeName": "CAPEC - Injection", "IsActive": True,
         "IsDeleted": False, "Source": tag}])
    db.execute(insert(m.Threat_Catalogue), [
        {"ThreatCatalogueID": 900, "ThreatTypeID": 900, "ThreatName": "CAPEC-66 SQL Injection",
         "IsActive": True, "IsDeleted": False, "Source": tag},
        {"ThreatCatalogueID": 901, "ThreatTypeID": 900, "ThreatName": "CAPEC-63 XSS",
         "IsActive": True, "IsDeleted": False, "Source": tag}])
    db.commit()

    rows = _sources(admin_client)
    assert rows["capec"]["loaded"] is True
    assert rows["capec"]["type_count"] == 1 and rows["capec"]["threat_count"] == 2
    assert rows["pytm"]["loaded"] is False          # untouched sources stay pending


def test_run_history_records_success_and_failure(admin_client, db):
    """The point of the history table: a FAILED import must leave a record. Without one,
    'never attempted' and 'attempted and crashed' look identical to an operator."""
    ok = tli.record_import_started("emb3d", dry_run=False, job_id="job-1")
    tli.record_import_finished(ok, stats={"types": 3, "threats": 40, "skipped_count": 1,
                                          "ot_rules": [{"a": 1}, {"b": 2}]})
    bad = tli.record_import_started("pytm", dry_run=False, job_id="job-2")
    tli.record_import_finished(bad, error="RuntimeError: download timed out")

    rows = _sources(admin_client)
    good_run = rows["emb3d"]["last_run"]
    assert good_run["status"] == "success" and good_run["threats_imported"] == 40
    assert good_run["finished_at"] is not None

    failed_run = rows["pytm"]["last_run"]
    assert failed_run["status"] == "failed"
    assert "timed out" in failed_run["error"]
    # a failed import contributed no rows, so the source is still pending — but now with a
    # visible reason, which is exactly the distinction that was missing.
    assert rows["pytm"]["loaded"] is False


def test_latest_run_wins_per_source(db):
    """Only the most recent attempt per source is reported, in one query for all sources."""
    first = tli.record_import_started("capec", dry_run=True, job_id="j1")
    tli.record_import_finished(first, error="boom")
    second = tli.record_import_started("capec", dry_run=False, job_id="j2")
    tli.record_import_finished(second, stats={"types": 1, "threats": 5})

    runs = tli.latest_runs_by_source(db)
    assert runs["capec"]["status"] == "success"     # the retry, not the earlier failure
    assert runs["capec"]["dry_run"] is False
    assert len(db.execute(select(m.Threat_Library_Import_Run)).scalars().all()) == 2  # both kept


def test_dry_run_is_flagged_and_does_not_mark_loaded(admin_client):
    """A preview must not read as a completed import."""
    run = tli.record_import_started("attack", dry_run=True, job_id="j3")
    tli.record_import_finished(run, stats={"types": 0, "threats": 0})

    row = _sources(admin_client)["attack"]
    assert row["last_run"]["dry_run"] is True
    assert row["loaded"] is False


def test_inventory_requires_admin_key(admin_client):
    assert admin_client.get("/v1/tsg/threat-library/sources").status_code == 401
