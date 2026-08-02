"""Cross-session scenario reads — GET /v1/users/{user_id}/scenarios,
GET /v1/entities/{entity_id}/scenarios, GET /v1/sessions/{session_id}/scenarios/{output_id}.

Rows are seeded directly (no pipeline run): these routes are read-only, so the DB state is
the whole contract. Client auth via make_client's Principal override (entities set, sub=u1).
"""
from __future__ import annotations

import json
from datetime import timedelta

from sqlalchemy import insert, select

from app.core.enums import ScenarioStatus, SessionMode, SessionStatus, StageStatus, WorkflowStage
from app.db import models as m
from app.db.dal import guid, now
from app.pipeline.tasks import ASSET_UNIT_ID
from tests.conftest import make_client

_SCN = {"scenario_title": "Bootloader implant on CAD", "scenario_statement": "S", "risk_statement": "R",
        "controls": [{"name": "Multi-Factor Authentication", "why": "stops credential replay"},
                    {"name": "Quantum Blockchain Firewall", "why": "no library counterpart"}]}


def _seed_session(db, *, entity="5", user="qa-user", status="completed", asset_id="100"):
    sid = guid()
    db.execute(insert(m.Scenario_Session).values(
        SessionID=sid, TenantID="t", EntityID=entity, UserID=user,
        AssetName="CAD", AssetID=asset_id, SessionStatus=status,
        CurrentStage=WorkflowStage.APPROVED, StageStatus=StageStatus.IDLE,
        Mode=SessionMode.AUTO, CurrentSubsystemIndex=0, SubsystemsJSON="[]",
        CreatedAt=now(), UpdatedAt=now(),
        CompletedAt=now() if status == str(SessionStatus.completed) else None))
    db.commit()
    return sid


def _seed_output(db, sid, *, accepted=0, superseded=0, status=str(ScenarioStatus.complete),
                scenario=_SCN, created_at=None, mapped=True):
    oid = guid()
    db.execute(insert(m.Threat_Scenario_Output).values(
        OutputID=oid, SessionID=sid, TenantID="t", SubsystemID=ASSET_UNIT_ID,
        ScopedThreatID=guid(), Status=status,
        ScenarioJSON=json.dumps(scenario) if scenario is not None else None,
        Accepted=accepted, Superseded=superseded, IdentityHash=guid(), ScenarioNumber=1,
        GenerationEpoch=1, CreatedAt=created_at or now(),
        ControlsMappedAt=now() if mapped else None))
    db.commit()
    return oid


def _seed_control_map(db, oid, sid):
    """One grounded Control_Library match for `oid` — proves the read-time controls merge ran."""
    if not db.execute(select(m.Control_Library).filter_by(ControlLibraryID=1)).first():
        db.execute(insert(m.Control_Library).values(
            ControlLibraryID=1, ControlCode="CII-CID-001", ITOT="IT",
            Domain="Identification & Authentication", ControlName="Multi-Factor Authentication",
            ControlDescription="MFA for privileged accounts", IsActive=True, IsDeleted=False))
    db.execute(insert(m.Threat_Scenario_Control_Map).values(
        OutputID=oid, ControlLibraryID=1, SessionID=sid, MapRank=1, Score=90.0,
        SuggestedControl="Multi-Factor Authentication", CreatedAt=now()))
    db.commit()


# --- list by user -----------------------------------------------------------

def test_user_list_full_payload_and_controls_merge(db):
    sid = _seed_session(db)
    oid = _seed_output(db, sid, accepted=1)
    _seed_control_map(db, oid, sid)

    rows = make_client({"5"}).get("/v1/users/qa-user/scenarios").json()
    assert [r["output_id"] for r in rows] == [oid]
    r = rows[0]
    assert (r["session_id"], r["entity_id"], r["user_id"]) == (sid, "5", "qa-user")
    assert r["session_status"] == "completed" and r["accepted"] is True and r["superseded"] is False
    assert r["scenario_number"] == 1 and r["created_at"] is not None
    scn = r["scenario"]
    assert scn["scenario_title"] == _SCN["scenario_title"]
    # merge: controls grounded from the map row, raw suggestions preserved, gap computed
    assert [c["control_code"] for c in scn["controls"]] == ["CII-CID-001"]
    assert {c["name"] for c in scn["suggested_controls"]} == {
        "Multi-Factor Authentication", "Quantum Blockchain Firewall"}
    assert [u["name"] for u in scn["unmatched_suggestions"]] == ["Quantum Blockchain Firewall"]


def test_user_list_restricted_to_caller_entities(db):
    _seed_output(db, _seed_session(db, entity="5"))
    _seed_output(db, _seed_session(db, entity="6", asset_id="300"))
    rows = make_client({"5"}).get("/v1/users/qa-user/scenarios").json()
    assert {r["entity_id"] for r in rows} == {"5"}  # entity-6 work invisible without the entitlement


def test_user_list_filters_by_user(db):
    _seed_output(db, _seed_session(db, user="qa-user"))
    _seed_output(db, _seed_session(db, user="someone-else", asset_id="200"))
    rows = make_client({"5"}).get("/v1/users/qa-user/scenarios").json()
    assert {r["user_id"] for r in rows} == {"qa-user"}


def test_user_list_empty_is_200(db):
    assert make_client({"5"}).get("/v1/users/nobody/scenarios").json() == []


def test_path_params_length_validated(db):
    # DB columns are nvarchar(200) — an over-long id must 422 at the boundary, not scan the DB
    client = make_client({"5"})
    assert client.get(f"/v1/users/{'x' * 201}/scenarios").status_code == 422
    assert client.get(f"/v1/entities/{'x' * 201}/scenarios").status_code == 422


# --- list by entity ---------------------------------------------------------

def test_entity_list_all_users_and_403_outside_scope(db):
    _seed_output(db, _seed_session(db, user="qa-user"))
    _seed_output(db, _seed_session(db, user="someone-else", asset_id="200"))
    client = make_client({"5"})
    rows = client.get("/v1/entities/5/scenarios").json()
    assert {r["user_id"] for r in rows} == {"qa-user", "someone-else"}  # entity view spans users
    assert client.get("/v1/entities/6/scenarios").status_code == 403


# --- status / superseded filters --------------------------------------------

def test_status_filters(db):
    client = make_client({"5"})
    by_status = {}
    for st, asset in (("active", "100"), ("completed", "200"), ("cancelled", "300")):
        by_status[st] = _seed_output(db, _seed_session(db, status=st, asset_id=asset))
    accepted_oid = _seed_output(db, _seed_session(db, asset_id="400"), accepted=1)

    for st, oid in by_status.items():
        got = {r["output_id"] for r in client.get(f"/v1/entities/5/scenarios?status={st}").json()}
        expected = {oid, accepted_oid} if st == "completed" else {oid}  # accepted row's session is completed
        assert got == expected, st
    got = {r["output_id"] for r in client.get("/v1/entities/5/scenarios?status=accepted").json()}
    assert got == {accepted_oid}
    assert client.get("/v1/entities/5/scenarios?status=bogus").status_code == 422


def test_default_hides_superseded_and_error_cards(db):
    sid = _seed_session(db)
    live = _seed_output(db, sid)
    old = _seed_output(db, sid, superseded=1)
    _seed_output(db, sid, status=str(ScenarioStatus.error), scenario=None)  # failure card
    client = make_client({"5"})

    assert {r["output_id"] for r in client.get("/v1/users/qa-user/scenarios").json()} == {live}
    widened = client.get("/v1/users/qa-user/scenarios?include_superseded=true").json()
    assert {r["output_id"] for r in widened} == {live, old}  # error card still never listed
    assert next(r for r in widened if r["output_id"] == old)["superseded"] is True


# --- pagination --------------------------------------------------------------

def test_pagination_stable_newest_first(db):
    sid = _seed_session(db)
    t0 = now()
    oids = [_seed_output(db, sid, created_at=t0 + timedelta(minutes=i)) for i in range(3)]
    client = make_client({"5"})

    page1 = client.get("/v1/users/qa-user/scenarios?limit=2").json()
    page2 = client.get("/v1/users/qa-user/scenarios?limit=2&offset=2").json()
    assert [r["output_id"] for r in page1] == [oids[2], oids[1]]  # newest first
    assert [r["output_id"] for r in page2] == [oids[0]]
    assert client.get("/v1/users/qa-user/scenarios?limit=501").status_code == 422
    assert client.get("/v1/users/qa-user/scenarios?offset=-1").status_code == 422


# --- item GET -----------------------------------------------------------------

def test_get_scenario_happy_path(db):
    sid = _seed_session(db)
    oid = _seed_output(db, sid, accepted=1)
    _seed_control_map(db, oid, sid)
    r = make_client({"5"}).get(f"/v1/sessions/{sid}/scenarios/{oid}?user_id=qa-user")
    assert r.status_code == 200
    body = r.json()
    assert body["output_id"] == oid and body["session_id"] == sid
    assert [c["control_code"] for c in body["scenario"]["controls"]] == ["CII-CID-001"]


def test_get_scenario_returns_superseded_row(db):
    sid = _seed_session(db)
    oid = _seed_output(db, sid, superseded=1)
    body = make_client({"5"}).get(f"/v1/sessions/{sid}/scenarios/{oid}?user_id=qa-user").json()
    assert body["superseded"] is True  # direct id fetch is how history is inspected


def test_get_scenario_authz_and_not_found(db):
    sid = _seed_session(db)
    oid = _seed_output(db, sid)
    other_sid = _seed_session(db, asset_id="200")
    other_oid = _seed_output(db, other_sid)
    url = f"/v1/sessions/{sid}/scenarios/{oid}?user_id=qa-user"

    assert make_client({"9"}).get(url).status_code == 403                     # session outside entity scope
    client = make_client({"5"})
    assert client.get(f"/v1/sessions/{guid()}/scenarios/{oid}?user_id=qa-user").status_code == 404
    assert client.get(f"/v1/sessions/{sid}/scenarios/{other_oid}?user_id=qa-user").status_code == 404
    assert client.get(f"/v1/sessions/{sid}/scenarios/not-a-guid?user_id=qa-user").status_code == 404
    assert client.get(f"/v1/sessions/{sid}/scenarios/{oid}?user_id=someone-else").status_code == 404
    assert client.get(f"/v1/sessions/{sid}/scenarios/{oid}").status_code == 422  # user_id required
