"""Tests for app.pipeline.context.gather_asset_details — the client sends only ids
(asset_id, entity_id, sector_id, user_id, supporting_system_id), and every descriptive
field (asset text, sector names, per-supporting-system fields) is resolved server-side,
authoritatively, from the platform's own DB records. There's no client-supplied text in
this path anymore for a "does it match" comparison to even apply to.
"""
from __future__ import annotations

import json

from sqlalchemy import event, func, insert, select

from app.db import models as m
from tests.conftest import make_client, session_body


def _no_pipeline(monkeypatch):
    monkeypatch.setattr("app.api.sessions.enqueue_pipeline", lambda sid: None)


def _session_row(db, session_id):
    return db.execute(select(m.Scenario_Session.__table__).where(m.Scenario_Session.SessionID == session_id)).mappings().first()


# --- positive: ids-only body creates a session, every field resolved from the DB ---
def test_ids_only_body_creates_session_with_db_resolved_context(engine, monkeypatch, db):
    _no_pipeline(monkeypatch)
    r = make_client({"5"}).post("/v1/sessions", json=session_body(100))
    assert r.status_code == 202

    row = _session_row(db, r.json()["session_id"])
    ctx = json.loads(row["AssetContextJSON"])
    assert ctx["cii_asset_description"] == "CAD design and drafting platform"
    assert ctx["critical_service"] == ["Design Service"]
    assert ctx["data_handled"] == "Engineering drawings and specs"

    subs = json.loads(row["SubsystemsJSON"])
    assert len(subs) == 1
    sub = subs[0]
    assert sub["id"] == 1019
    assert sub["name"] == "CAD System"
    assert sub["asset_type"] == "Physical infrastructure"  # resolved via ctm_scan_category
    assert sub["past_incidents"] == "None"


# --- authorization: a supporting_system_id not linked to THIS asset -> 403, never a
# 422 mismatch. This is the exact cross-tenant/IDOR shape the scoping join defends
# against: a real row that exists, but belongs to a different asset. ---
def test_supporting_system_id_linked_to_another_asset_rejected(engine, monkeypatch, db):
    db.execute(insert(m.onboarding_supporting_systems).values(id=1021, name="Other Asset's System"))
    db.execute(insert(m.ctm_scan_entity_supporting_system).values(ctm_scan_entity_id=200, onboarding_supporting_system_id=1021))
    db.commit()
    _no_pipeline(monkeypatch)
    r = make_client({"5"}).post("/v1/sessions", json=session_body(100, supporting_system_id=[1021]))
    assert r.status_code == 403


def test_nonexistent_supporting_system_id_rejected(engine, monkeypatch):
    _no_pipeline(monkeypatch)
    r = make_client({"5"}).post("/v1/sessions", json=session_body(100, supporting_system_id=[999999]))
    assert r.status_code == 403


# --- duplicate ids: rejected at the Pydantic request boundary, before any DB work at
# all — a repeated id would otherwise seed two identical (SessionID, SubsystemID,
# Level) CAS rows and corrupt claim_stage/acquire_lock's rowcount==1 win signal ---
def test_duplicate_supporting_system_ids_rejected(engine, monkeypatch, db):
    _no_pipeline(monkeypatch)
    r = make_client({"5"}).post("/v1/sessions", json=session_body(100, supporting_system_id=[1019, 1019]))
    assert r.status_code == 422
    assert r.json()["error_code"] == "validation_error"
    assert db.execute(select(func.count()).select_from(m.Subsystem_Stage_State)).scalar() == 0
    assert db.execute(select(func.count()).select_from(m.Scenario_Session)).scalar() == 0


# --- sector resolution: leaf-with-parent -> sector=parent name, sub_sector=leaf name ---
def test_sector_and_sub_sector_resolved_from_db(engine, monkeypatch, db):
    db.execute(insert(m.onboarding_sectors).values(id=50, name="Parent Sector", parent_id=None))
    db.execute(insert(m.onboarding_sectors).values(id=51, name="Sub Sector", parent_id=50))
    db.commit()
    _no_pipeline(monkeypatch)
    r = make_client({"5"}).post("/v1/sessions", json=session_body(100, sector_id=51))
    assert r.status_code == 202

    row = _session_row(db, r.json()["session_id"])
    ctx = json.loads(row["AssetContextJSON"])
    assert ctx["sector"] == "Parent Sector"
    assert ctx["sub_sector"] == "Sub Sector"
    assert json.loads(row["SectorIDsJSON"]) == [51, 50]  # sub-sector first, then parent


# --- top-level sector, no parent: sub_sector has nothing to resolve to, stays None ---
def test_top_level_sector_with_no_parent_has_no_sub_sector(engine, monkeypatch, db):
    db.execute(insert(m.onboarding_sectors).values(id=60, name="Utilities", parent_id=None))
    db.commit()
    _no_pipeline(monkeypatch)
    r = make_client({"5"}).post("/v1/sessions", json=session_body(100, sector_id=60))
    assert r.status_code == 202

    row = _session_row(db, r.json()["session_id"])
    ctx = json.loads(row["AssetContextJSON"])
    assert ctx["sector"] == "Utilities"
    assert ctx["sub_sector"] is None


# --- a sector_id that doesn't resolve to a real row -> 404. Previously silently
# accepted as sector=None; a bad reference is now a real error, not a data gap. ---
def test_bad_sector_id_returns_404(engine, monkeypatch):
    _no_pipeline(monkeypatch)
    r = make_client({"5"}).post("/v1/sessions", json=session_body(100, sector_id=999999))
    assert r.status_code == 404


# --- null passthrough: a NULL DB field resolves to null in AssetContextJSON/
# SubsystemsJSON, not an error — there's nothing to compare it against anymore ---
def test_null_asset_and_subsystem_fields_pass_through_as_null(engine, monkeypatch, db):
    db.execute(insert(m.ctm_scan_entity).values(
        id=400, name="Null Context Asset", type="app", criticality=1,
        tier1_critical_service_id=500))  # description/data_handled left NULL
    db.execute(insert(m.ctm_scan_entity_bu).values(id=400, ctm_scan_entity_id=400, group_id=5, service_id=500))
    db.execute(insert(m.onboarding_supporting_systems).values(id=1020, name="Minimal System"))  # every optional col NULL
    db.execute(insert(m.ctm_scan_entity_supporting_system).values(ctm_scan_entity_id=400, onboarding_supporting_system_id=1020))
    db.commit()
    _no_pipeline(monkeypatch)
    r = make_client({"5"}).post("/v1/sessions", json=session_body(400, supporting_system_id=[1020]))
    assert r.status_code == 202

    row = _session_row(db, r.json()["session_id"])
    ctx = json.loads(row["AssetContextJSON"])
    assert ctx["cii_asset_description"] is None
    assert ctx["data_handled"] is None
    sub = json.loads(row["SubsystemsJSON"])[0]
    assert sub["asset_type"] is None
    assert sub["past_incidents"] is None


# --- IO shape: a small FIXED number of queries, independent of how many supporting
# systems are in the request (not N+1) ---
def test_gather_asset_details_query_count_is_fixed(engine, db):
    from app.pipeline.context import gather_asset_details

    for i, sid in enumerate((1020, 1021, 1022, 1023)):
        db.execute(insert(m.onboarding_supporting_systems).values(id=sid, name=f"Extra System {i}"))
        db.execute(insert(m.ctm_scan_entity_supporting_system).values(ctm_scan_entity_id=100, onboarding_supporting_system_id=sid))
    db.commit()

    def _count(ids: list[int]) -> int:
        counter = {"n": 0}

        def _before(conn, cursor, statement, parameters, context, executemany):
            counter["n"] += 1

        eng = db.get_bind()
        event.listen(eng, "before_cursor_execute", _before)
        try:
            gather_asset_details(db, asset_id=100, entity_id="5", sector_id=None, user_id=None,
                                supporting_system_ids=ids)
        finally:
            event.remove(eng, "before_cursor_execute", _before)
        return counter["n"]

    n1 = _count([1019])
    n5 = _count([1019, 1020, 1021, 1022, 1023])
    assert n1 == n5  # the property that actually matters: not O(subsystem count)
