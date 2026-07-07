"""Tests for app.pipeline.context.validate_ui_supplied_context — every UI-supplied
session-creation field (13-field mapping) is checked against the platform's own DB
records; any mismatch rejects the whole request with 422 (collecting ALL mismatches
in one pass, not just the first).
"""
from __future__ import annotations

from sqlalchemy import event, insert, select

from app.db import models as m
from tests.conftest import DEFAULT_ASSET_CONTEXT, DEFAULT_SUPPORTING_SYSTEMS, make_client, session_body


def _no_pipeline(monkeypatch):
    monkeypatch.setattr("app.api.sessions.enqueue_pipeline", lambda sid: None)


def _mismatch_fields(resp) -> set[str]:
    return {m_["field"] for m_ in resp.json()["details"]["mismatches"]}


# --- positive: everything matches the seeded DB rows ---
def test_matching_context_creates_session(engine, monkeypatch):
    _no_pipeline(monkeypatch)
    r = make_client({"5"}).post("/v1/sessions", json=session_body(100))
    assert r.status_code == 202


# --- negative: one mismatched field per family ---
def test_asset_description_mismatch_rejected(engine, monkeypatch):
    _no_pipeline(monkeypatch)
    r = make_client({"5"}).post("/v1/sessions", json=session_body(100, cii_asset_description="Wrong description"))
    assert r.status_code == 422
    assert r.json()["error_code"] == "context_mismatch"
    assert "cii_asset_description" in _mismatch_fields(r)


def test_data_handled_mismatch_rejected(engine, monkeypatch):
    _no_pipeline(monkeypatch)
    r = make_client({"5"}).post("/v1/sessions", json=session_body(100, data_handled="Wrong data"))
    assert r.status_code == 422
    assert "data_handled" in _mismatch_fields(r)


def test_critical_service_mismatch_rejected(engine, monkeypatch):
    _no_pipeline(monkeypatch)
    r = make_client({"5"}).post("/v1/sessions", json=session_body(100, critical_service="Wrong Service"))
    assert r.status_code == 422
    assert "critical_service" in _mismatch_fields(r)


def test_sector_and_sub_sector_swap_is_caught(engine, monkeypatch, db):
    # sector_id=51 is the leaf/sub-sector; its parent (50) is the broader sector.
    db.execute(insert(m.onboarding_sectors).values(id=50, name="Parent Sector", parent_id=None))
    db.execute(insert(m.onboarding_sectors).values(id=51, name="Sub Sector", parent_id=50))
    db.commit()
    _no_pipeline(monkeypatch)
    # swapped: sector <-> sub_sector text reversed — the easiest way to invert the
    # parent/leaf direction, so this is the concrete regression test for getting it backwards.
    r = make_client({"5"}).post("/v1/sessions", json=session_body(
        100, sector_id=51, sector="Sub Sector", sub_sector="Parent Sector"))
    assert r.status_code == 422
    assert {"sector", "sub_sector"} <= _mismatch_fields(r)


def test_sector_matching_passes(engine, monkeypatch, db):
    db.execute(insert(m.onboarding_sectors).values(id=50, name="Parent Sector", parent_id=None))
    db.execute(insert(m.onboarding_sectors).values(id=51, name="Sub Sector", parent_id=50))
    db.commit()
    _no_pipeline(monkeypatch)
    r = make_client({"5"}).post("/v1/sessions", json=session_body(
        100, sector_id=51, sector="Parent Sector", sub_sector="Sub Sector"))
    assert r.status_code == 202


def test_supporting_system_field_mismatch_rejected(engine, monkeypatch):
    _no_pipeline(monkeypatch)
    bad_sub = {**DEFAULT_SUPPORTING_SYSTEMS[0], "hosting_environment": "Not A Real Hosting Label"}
    r = make_client({"5"}).post("/v1/sessions", json=session_body(100, supporting_systems=[bad_sub]))
    assert r.status_code == 422
    assert "supporting_systems[1019].hosting_environment" in _mismatch_fields(r)


def test_system_managed_by_nonexistent_user_rejected(engine, monkeypatch):
    _no_pipeline(monkeypatch)
    bad_sub = {**DEFAULT_SUPPORTING_SYSTEMS[0], "system_managed_by": "NoSuchUser"}
    r = make_client({"5"}).post("/v1/sessions", json=session_body(100, supporting_systems=[bad_sub]))
    assert r.status_code == 422
    assert "supporting_systems[1019].system_managed_by" in _mismatch_fields(r)


# --- sector edge case: a top-level sector with no parent has no leaf to compare
# sub_sector against — sector compares directly against sector_id's own name, and
# sub_sector must be absent, not a mismatch ---
def test_top_level_sector_with_no_sub_sector_passes(engine, monkeypatch, db):
    db.execute(insert(m.onboarding_sectors).values(id=60, name="Utilities", parent_id=None))
    db.commit()
    _no_pipeline(monkeypatch)
    r = make_client({"5"}).post("/v1/sessions", json=session_body(100, sector_id=60, sector="Utilities"))
    assert r.status_code == 202


# --- null rule: DB NULL + UI field absent → OK, not a mismatch ---
def test_both_null_passes(engine, monkeypatch, db):
    db.execute(insert(m.ctm_scan_entity).values(
        id=400, name="Null Context Asset", type="app", criticality=1, group_id=5,
        tier1_critical_service_id=500))  # description/data_handled left NULL
    db.execute(insert(m.onboarding_supporting_systems).values(id=1020, name="Minimal System"))  # every optional col NULL
    db.execute(insert(m.ctm_scan_entity_supporting_system).values(ctm_scan_entity_id=400, onboarding_supporting_system_id=1020))
    db.commit()
    _no_pipeline(monkeypatch)
    r = make_client({"5"}).post("/v1/sessions", json=session_body(
        400, critical_service="Design Service", cii_asset_description=None, data_handled=None,
        supporting_systems=[{"id": 1020, "name": "Minimal System"}]))
    assert r.status_code == 202


# --- [decision 4] collect every mismatch in one pass, not just the first ---
def test_two_mismatched_fields_both_reported(engine, monkeypatch):
    _no_pipeline(monkeypatch)
    r = make_client({"5"}).post("/v1/sessions", json=session_body(
        100, cii_asset_description="Wrong description", critical_service="Wrong Service"))
    assert r.status_code == 422
    fields = _mismatch_fields(r)
    assert {"cii_asset_description", "critical_service"} <= fields


# --- IO shape: a small FIXED number of queries, independent of how many supporting
# systems are in the request (not N+1) ---
def test_validate_context_query_count_is_fixed(engine, db):
    from app.api.schemas import CreateSessionBody, SupportingSystemInput
    from app.pipeline.context import validate_ui_supplied_context

    asset_row = dict(db.execute(select(m.ctm_scan_entity).where(m.ctm_scan_entity.c.id == 100)).mappings().first())

    def _run(n: int) -> None:
        subs = [SupportingSystemInput(**DEFAULT_SUPPORTING_SYSTEMS[0]) for _ in range(n)]
        body = CreateSessionBody(asset_id=100, entity_id="5", supporting_systems=subs, **DEFAULT_ASSET_CONTEXT)
        validate_ui_supplied_context(
            db, asset_row=asset_row, sector_row=None, parent_sector_row=None,
            supporting_systems=[s.model_dump() for s in subs], body=body)

    def _count(n: int) -> int:
        counter = {"n": 0}

        def _before(conn, cursor, statement, parameters, context, executemany):
            counter["n"] += 1

        eng = db.get_bind()
        event.listen(eng, "before_cursor_execute", _before)
        try:
            _run(n)
        finally:
            event.remove(eng, "before_cursor_execute", _before)
        return counter["n"]

    n1 = _count(1)
    n5 = _count(5)
    assert n1 == n5
    assert n1 <= 4  # per the plan's IO-shape requirement: ~4 queries total, never O(supporting_systems)
