"""Remediation for BOTH kinds of scenario — POST /v1/remediation-plans with `is_manual`.

Real HTTP through the real app (TestClient), a file-backed SQLite database behind the production
db_session() seam, and the treatment enqueue stubbed out (its documented test seam) — the same
posture as test_e2e_full_flow.py. Each test pins one gap the design closes at its root:

  G1  a retried/double-clicked manual request never saves a second copy (Idempotency-Key)
  G2  the save is all-or-nothing: never a saved-but-unaccepted scenario
  G3  the control mapper can never select, re-map or replace a person's controls
  G4  a person's controls are never reported stale
  G5  the AI never regenerates or adds to a manual scenario (route AND worker)
  G6  provenance reads `manual` everywhere, never "AI generated"
  G7  a type/threat missing from the library is proposed PENDING, stamped manual, with its author
  G8  no blank library value is accepted anywhere
  G9  a curator-rejected threat is never proposed again
  G11 a request mixing the two kinds is refused
  G12 a key used for another asset or an AI session is a 409, never a wrong replay
"""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import pytest
from conftest import register_sqlite_json_value
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, func, select, update

from app.core.enums import SessionStatus, StageStatus, SubsystemLevel, WorkflowStage
from app.db import models as m

TENANT, ENTITY, USER = "t", "86", "u1"
ASSET, SUPPORT = 103, 321
CATEGORY_ID, TYPE_ID, CATALOGUE_ID = 6, 82, 297
CONTROLS = {213: "CII-CID-213", 242: "CII-CID-242", 17: "CII-CID-017"}
RETIRED_CONTROL = (999, "CII-CID-999")

_RISK = {
    "existing_controls": ["Perimeter firewall between the corporate IT network and the OT network"],
    "likelihood_rating": 4, "impact_rating": 5, "final_risk_rating": 20, "risk_level": "Critical",
    "risk_identification_date": "2026-09-15T09:30:00Z", "risk_owner": "Head of OT Operations",
    "impacted_business_division": "Water Treatment Operations",
    "existing_controls_all_subsystems": "No",
    "existing_controls_all_subsystems_justification": "Corporate IT only.",
    "mitigation_start_date": "2026-10-01", "mitigation_end_date": "2026-12-31",
}


def _now():
    return datetime.now(UTC)


def _manual(**overrides) -> dict:
    # The threat triple is sent BY NAME here, which is one of the two ways the approved payload
    # allows (id, name, or both) and the one these tests are about: name matching is what proposes
    # a missing type/threat to the curators. `scenario_title` is gone from the payload entirely.
    return {"entity_id": ENTITY, "asset_id": ASSET, "supporting_system_id": [SUPPORT],
            "threat_scenario": "A phished engineer laptop is used to deploy ransomware that "
                               "encrypts the SCADA historian over the flat OT network.",
            "risk_statement": "Loss of process history disrupts water treatment operations.",
            "threat_category_name": "Tampering", "threat_type_name": "Malware/Ransomware",
            "threat_name": "Ransomware on OT support systems",
            "mapped_controls": list(CONTROLS.values()), **overrides}


def _post(client, body: dict, key: str | None = "key-1"):
    headers = {"Idempotency-Key": key} if key is not None else {}
    return client.post("/v1/remediation-plans", json=body, headers=headers)


def _manual_body(**overrides) -> dict:
    return {"is_manual": True, "manual_scenario": _manual(**overrides), **_RISK}


def _count(model) -> int:
    from app.db.engine import db_session
    with db_session() as s:
        return s.execute(select(func.count()).select_from(model)).scalar()


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Real app + file-backed SQLite, the treatment router mounted, one asset owned by ENTITY with
    one supporting system, a small threat library and Control Library, and the plan enqueue
    stubbed (enqueue_treatment_plan is the documented seam)."""
    db_path = tmp_path / "remediation.db"
    monkeypatch.setenv("TSG_DB_DSN", f"sqlite:///{db_path}")
    monkeypatch.setenv("TSG_RISK_MODULE_ENABLED", "true")
    from app.core.config import get_settings
    from app.db.engine import _sessionmaker, get_engine
    get_settings.cache_clear()
    get_engine.cache_clear()
    _sessionmaker.cache_clear()

    # Wired BEFORE the app engine opens its first connection ("connect" hooks only reach new
    # ones). The pysqlite workaround the accept/promote suites use: without it, RELEASE SAVEPOINT
    # — which dal.create_session and the library upserts emit via begin_nested — silently COMMITS
    # the open transaction, so the all-or-nothing save could never be proven here (SQL Server
    # keeps the whole save in one transaction; this makes SQLite do the same).
    app_engine = get_engine()
    register_sqlite_json_value(app_engine)

    @event.listens_for(app_engine, "connect")
    def _no_implicit_txn(dbapi_connection, _record):
        dbapi_connection.isolation_level = None

    @event.listens_for(app_engine, "begin")
    def _explicit_begin(conn):
        conn.exec_driver_sql("BEGIN")

    engine = create_engine(f"sqlite:///{db_path}", future=True)
    for tbl in (m.Scenario_Session, m.Subsystem_Stage_State, m.Identified_Threat,
                m.Scoped_Threat, m.Threat_Scenario, m.Scenario_Audit, m.Threat_Category,
                m.Threat_Type, m.Threat_Catalogue, m.ThreatType_ThreatActor_Map,
                m.Threat_Catalogue_Category_Map, m.Control_Library, m.Control_Standard,
                m.Control_Library_Standard_Map, m.Threat_Scenario_Control_Map,
                m.Risk_Treatment_Plan, m.Threat_Actor, m.Prompt_Log,
                m.ctm_scan_entity, m.ctm_scan_entity_bu, m.onboarding_supporting_systems,
                m.ctm_scan_entity_supporting_system, m.Config_Tuning,
                m.Grounding_Calibration_Run):
        tbl.__table__.create(engine, checkfirst=True)
    engine.dispose()

    from app.db.engine import db_session
    with db_session() as s:
        s.execute(m.Threat_Category.__table__.insert().values(
            ThreatCategoryID=CATEGORY_ID, ThreatCategoryName="Tampering", IsActive=True,
            IsDeleted=False))
        s.execute(m.Threat_Type.__table__.insert().values(
            ThreatTypeID=TYPE_ID, ThreatTypeName="Malware/Ransomware",
            ThreatCategoryID=CATEGORY_ID, IsActive=True, IsDeleted=False,
            Source="functional_team_excel"))
        s.execute(m.Threat_Catalogue.__table__.insert().values(
            ThreatCatalogueID=CATALOGUE_ID, ThreatTypeID=TYPE_ID,
            ThreatName="Ransomware on OT support systems", IsActive=True, IsDeleted=False,
            Source="functional_team_excel"))
        for cid, code in (*CONTROLS.items(), RETIRED_CONTROL):
            s.execute(m.Control_Library.__table__.insert().values(
                ControlLibraryID=cid, ControlCode=code, ITOT="OT", Domain="Endpoint Security",
                ControlName=f"Control {code}", ControlDescription="-",
                IsActive=cid != RETIRED_CONTROL[0], IsDeleted=False))
        s.execute(m.ctm_scan_entity.__table__.insert().values(
            id=ASSET, name="Water Treatment Plant", criticality=3, type="Plant",
            is_deleted=False))
        s.execute(m.ctm_scan_entity_bu.__table__.insert().values(
            ctm_scan_entity_id=ASSET, group_id=int(ENTITY), service_id=None))
        s.execute(m.onboarding_supporting_systems.__table__.insert().values(
            id=SUPPORT, name="SCADA Historian", is_deleted=False))
        s.execute(m.ctm_scan_entity_supporting_system.__table__.insert().values(
            ctm_scan_entity_id=ASSET, onboarding_supporting_system_id=SUPPORT))
        s.commit()

    import app.api.treatment as treatment_api
    monkeypatch.setattr(treatment_api, "enqueue_treatment_plan", lambda *a, **k: None)

    from app.api.deps import Principal, get_principal
    from app.main import create_app
    app = create_app()
    app.dependency_overrides[get_principal] = lambda: Principal(
        claims={"sub": USER}, entities={ENTITY}, client_id="remediation-test", tenant_id=TENANT)
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_manual_scenario_gets_its_plan_in_one_call(client):
    """The sample request: saved like a generated scenario, accepted, controls as sent, plan
    started — and every existing endpoint works on the returned ids."""
    from app.db.engine import db_session

    r = _post(client, _manual_body())
    assert r.status_code == 202, r.text
    body = r.json()
    assert (body["is_manual"], body["replayed"], body["status"]) == (True, False, "RUNNING")
    sid, scid = body["session_id"], body["scenario_id"]

    with db_session() as s:
        ses = s.execute(select(m.Scenario_Session).where(
            m.Scenario_Session.SessionID == sid)).scalar_one()
        assert (ses.Mode, ses.SessionStatus, ses.CurrentStage, ses.StageStatus) == (
            "MANUAL", SessionStatus.completed, WorkflowStage.REVIEW, StageStatus.AWAITING_DECISION)
        stages = {r.Level: r.Status for r in s.execute(select(m.Subsystem_Stage_State).where(
            m.Subsystem_Stage_State.SessionID == sid)).scalars()}
        assert stages == {SubsystemLevel.THREATS: StageStatus.COMPLETE,
                          SubsystemLevel.SCENARIOS: StageStatus.AWAITING_DECISION,
                          SubsystemLevel.LOCK: StageStatus.IDLE}
        threat = s.execute(select(m.Identified_Threat).where(
            m.Identified_Threat.SessionID == sid)).scalar_one()
        # G6: a person's threat is not AI-generated at either level.
        assert (threat.IsThreatAIGenerated, threat.IsThreatTypeAIGenerated) == (False, False)
        assert (threat.ThreatTypeID, threat.ThreatCatalogueID, threat.ThreatCategoryID,
                threat.GroundingStatus) == (TYPE_ID, CATALOGUE_ID, CATEGORY_ID, "verified")
        out = s.execute(select(m.Threat_Scenario).where(
            m.Threat_Scenario.SessionID == sid)).scalar_one()
        assert out.ScenarioSource == "manual" and out.Accepted == 1 and out.IdentityHash
        assert out.ControlsMappedAt is not None
        ranked = [r.ControlLibraryID for r in s.execute(
            select(m.Threat_Scenario_Control_Map).where(m.Threat_Scenario_Control_Map.ScenarioID == scid)
            .order_by(m.Threat_Scenario_Control_Map.MapRank)).scalars()]
        assert ranked == list(CONTROLS)
        plan = s.execute(select(m.Risk_Treatment_Plan).where(
            m.Risk_Treatment_Plan.ScenarioID == scid)).scalar_one()
        snap = json.loads(plan.InputSnapshotJSON)
        assert [c["control_code"] for c in snap["existing_controls"]["library_mapped"]] == list(
            CONTROLS.values())
        assert snap["threat"]["type"] == "Malware/Ransomware"
        events = {a.EventType for a in s.execute(select(m.Scenario_Audit).where(
            m.Scenario_Audit.SessionID == sid)).scalars()}
        assert {"session_started", "scenario_accepted", "scenarios_accepted", "review_decision",
                "treatment_plan_requested"} <= events
        # Nothing was proposed to the library: every name matched an existing entry.
        assert "library_promoted" not in events

    # Existing endpoints on the manual ids, unchanged.
    plan_resp = client.get(f"/v1/sessions/{sid}/scenarios/{scid}/treatment-plan")
    assert plan_resp.status_code == 200 and plan_resp.json()["scenario_source"] == "manual"
    status = client.get(f"/v1/sessions/{sid}/scenarios/{scid}/treatment-plan/status")
    assert status.status_code == 200, status.text
    assert client.get(f"/v1/sessions/{sid}").json()["mode"] == "MANUAL"
    card = client.get(f"/v1/sessions/{sid}/results").json()["scenarios"][0]
    assert card["scenario_source"] == "manual"
    assert card["threat"]["is_threat_ai_generated"] is False
    accepted = client.get(f"/v1/sessions/{sid}/accepted-scenarios").json()["scenarios"]
    assert accepted[0]["scenario_source"] == "manual"


def test_replay_returns_the_original_and_never_saves_twice(client):
    """G1 + G12."""
    first = _post(client, _manual_body())
    assert first.status_code == 202, first.text
    sessions_before = _count(m.Scenario_Session)

    again = _post(client, _manual_body())
    assert again.status_code == 200, again.text
    assert again.json()["replayed"] is True
    assert (again.json()["session_id"], again.json()["scenario_id"], again.json()["plan_id"]) == (
        first.json()["session_id"], first.json()["scenario_id"], first.json()["plan_id"])
    assert _count(m.Scenario_Session) == sessions_before
    assert _count(m.Risk_Treatment_Plan) == 1

    # The same key for another asset is somebody else's request, never a replay.
    other = _post(client, _manual_body(asset_id=ASSET + 1))
    assert other.status_code == 409, other.text
    assert other.json()["error_code"] == "idempotency_key_conflict"


@pytest.mark.parametrize("body, key", [
    (_manual_body(threat_category_name="Not a category"), "k"),
    (_manual_body(threat_type_name="   "), "k"),              # G8: blank -> the pair names nothing
    (_manual_body(threat_name="--"), "k"),                    # G8: punctuation only
    (_manual_body(mapped_controls=["CII-CID-404"]), "k"),     # unknown code
    (_manual_body(mapped_controls=[RETIRED_CONTROL[1]]), "k"),  # retired code
    (_manual_body(mapped_controls=["CII-CID-213", "cii-cid-213"]), "k"),  # duplicate
    # `mapped_controls: []` used to be here as "none". It is no longer a 422: the approved payload
    # makes the field optional, and a manual scenario sent without controls is SAVED with none and
    # says so in its plan (nothing is topped up — top-up is for AI scenarios only). Pinned as an
    # accepted request in test_remediation_payload_contract.py instead.
    (_manual_body(), None),                                  # missing Idempotency-Key
    ({**_manual_body(), "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e"}, "k"),  # G11
    ({"is_manual": False, **_RISK}, "k"),                    # G11: no ids
])
def test_invalid_requests_are_refused_and_nothing_is_saved(client, body, key):
    r = _post(client, body, key=key)
    assert r.status_code == 422, r.text
    assert _count(m.Scenario_Session) == 0
    assert _count(m.Threat_Type) == 1 and _count(m.Threat_Catalogue) == 1


def test_asset_not_owned_is_403(client):
    from app.db.engine import db_session
    with db_session() as s:
        s.execute(m.ctm_scan_entity.__table__.insert().values(
            id=777, name="Someone else's", criticality=3, type="Plant", is_deleted=False))
        s.execute(m.ctm_scan_entity_bu.__table__.insert().values(
            ctm_scan_entity_id=777, group_id=999, service_id=None))
        s.commit()
    r = _post(client, _manual_body(asset_id=777))
    assert r.status_code == 403, r.text
    assert _count(m.Scenario_Session) == 0


def test_missing_library_entries_are_proposed_pending_manual_with_their_author(client):
    """G7: the edge case — type and threat not in the library."""
    from app.db import dal
    from app.db.engine import db_session

    r = _post(client, _manual_body(threat_type_name="Firmware Backdoor",
                                   threat_name="Backdoored PLC firmware update"))
    assert r.status_code == 202, r.text
    sid = r.json()["session_id"]
    with db_session() as s:
        new_type = s.execute(select(m.Threat_Type).where(
            m.Threat_Type.ThreatTypeName == "Firmware Backdoor")).scalar_one()
        new_threat = s.execute(select(m.Threat_Catalogue).where(
            m.Threat_Catalogue.ThreatName == "Backdoored PLC firmware update")).scalar_one()
        for row in (new_type, new_threat):
            assert (row.IsActive, row.Source, row.CreatedBy) == (False, "manual", USER)
        assert new_threat.ThreatTypeID == new_type.ThreatTypeID
        link = s.execute(select(m.Threat_Catalogue_Category_Map).where(
            m.Threat_Catalogue_Category_Map.ThreatCatalogueID == new_threat.ThreatCatalogueID)
        ).scalar_one()
        assert link.ThreatCategoryID == CATEGORY_ID
        threat = s.execute(select(m.Identified_Threat).where(
            m.Identified_Threat.SessionID == sid)).scalar_one()
        # Linked to the pending proposal, but not "verified": curators have not approved it.
        assert (threat.ThreatCatalogueID, threat.GroundingStatus) == (
            new_threat.ThreatCatalogueID, "unverified")
        audit = s.execute(select(m.Scenario_Audit).where(
            m.Scenario_Audit.SessionID == sid,
            m.Scenario_Audit.EventType == "library_promoted")).scalar_one()
        assert audit.ActorUserID == USER
        assert json.loads(audit.DetailJSON)["statuses"] == {"threat_type": "inserted",
                                                            "threat": "inserted"}
        pending = dal.pending_library_threats(s)
        assert [(p["ThreatName"], p["Source"], p["CreatedBy"]) for p in pending] == [
            ("Backdoored PLC firmware update", "manual", USER)]

    # A second person writing the same threat reuses the pending entries — never a twin.
    again = _post(client, _manual_body(threat_type_name="firmware backdoor",
                                       threat_name="Backdoored PLC firmware update"), key="key-2")
    assert again.status_code == 202, again.text
    assert _count(m.Threat_Type) == 2 and _count(m.Threat_Catalogue) == 2


def test_curator_rejected_threat_is_never_proposed_again(client):
    """G9."""
    from app.db.engine import db_session
    with db_session() as s:
        s.execute(m.Threat_Catalogue.__table__.insert().values(
            ThreatCatalogueID=500, ThreatTypeID=TYPE_ID, ThreatName="Rejected wording",
            IsActive=False, IsDeleted=True, Source="ai_generated"))
        s.commit()
    r = _post(client, _manual_body(threat_name="Rejected wording"))
    assert r.status_code == 202, r.text
    with db_session() as s:
        live = s.execute(select(func.count()).select_from(m.Threat_Catalogue).where(
            m.Threat_Catalogue.ThreatName == "Rejected wording",
            m.Threat_Catalogue.IsDeleted == False)).scalar()
        assert live == 0
        threat = s.execute(select(m.Identified_Threat).where(
            m.Identified_Threat.SessionID == r.json()["session_id"])).scalar_one()
        assert (threat.ThreatName, threat.ThreatCatalogueID) == ("Rejected wording", None)

    # ...and with a type the library has never held either, the trail must SAY so. The audit row
    # is the only durable record of what a save did to the library; defaulting the status to
    # "existing" claimed the library already held this type, beside a null threat_type_id — the
    # exact question a curator reads this trail to answer.
    types_before = _count(m.Threat_Type)
    r2 = _post(client, _manual_body(threat_name="Rejected wording", threat_type_name="Never Heard Of It"),
               key="rejected-with-a-new-type")
    assert r2.status_code == 202, r2.text
    assert _count(m.Threat_Type) == types_before, "a type was minted for a rejected threat"
    with db_session() as s:
        audit = s.execute(select(m.Scenario_Audit).where(
            m.Scenario_Audit.SessionID == r2.json()["session_id"],
            m.Scenario_Audit.EventType == "library_promoted")).scalar_one()
        assert json.loads(audit.DetailJSON)["statuses"] == {
            "threat_type": "not_proposed", "threat": "rejected_by_curator"}


def test_rejecting_the_last_threat_clears_its_orphan_pending_type(client):
    """A pending type whose last live threat is rejected is unreachable ever after: the curator
    queue lists catalogue rows, approve/reject take catalogue ids, and the by-name lookup ignores
    tombstones — so the row would sit there forever while the next save minted the name again.
    It goes with its last child; an ACTIVE type, or one with threats left, is never touched."""
    from app.api.threat_intel import _remove_orphan_pending_type
    from app.db.engine import db_session

    r = _post(client, _manual_body(threat_type_name="Firmware Backdoor",
                                   threat_name="Backdoored PLC firmware update"))
    assert r.status_code == 202, r.text
    with db_session() as s:
        pending = s.execute(select(m.Threat_Catalogue).where(
            m.Threat_Catalogue.ThreatName == "Backdoored PLC firmware update")).scalar_one()
        type_id = pending.ThreatTypeID
        # what reject_library_threats does to the catalogue row, then the cleanup under test
        s.execute(update(m.Threat_Catalogue)
                  .where(m.Threat_Catalogue.ThreatCatalogueID == pending.ThreatCatalogueID)
                  .values(IsDeleted=True, IsActive=False))
        assert _remove_orphan_pending_type(s, type_id, USER) is True
        # the seeded ACTIVE type still holds its threat: never touched
        assert _remove_orphan_pending_type(s, TYPE_ID, USER) is False
        s.commit()
    with db_session() as s:
        assert s.get(m.Threat_Type, type_id).IsDeleted is True
        assert s.get(m.Threat_Type, TYPE_ID).IsDeleted is False


def test_a_cleaned_up_orphan_type_does_not_poison_its_name(client):
    """A pending type is removed when its last threat is rejected — that is cleanup, NOT a verdict
    on the name. A later scenario naming that type, with a threat nobody rejected, must be
    proposed normally; the earlier code read the cleanup's tombstone as a curator decision and
    filed every future save under no type at all. The REJECTED THREAT stays refused either way."""
    from app.db.engine import db_session

    assert _post(client, _manual_body(threat_type_name="Firmware Backdoor",
                                      threat_name="Backdoored PLC firmware update")).status_code == 202
    with db_session() as s:      # what reject + orphan cleanup leave behind
        s.execute(update(m.Threat_Catalogue)
                  .where(m.Threat_Catalogue.ThreatName == "Backdoored PLC firmware update")
                  .values(IsDeleted=True, IsActive=False))
        s.execute(update(m.Threat_Type)
                  .where(m.Threat_Type.ThreatTypeName == "Firmware Backdoor")
                  .values(IsDeleted=True, IsActive=False))
        s.commit()

    fresh = _post(client, _manual_body(threat_type_name="Firmware Backdoor",
                                       threat_name="Tampered relay firmware"), key="key-2")

    assert fresh.status_code == 202, fresh.text
    with db_session() as s:
        threat = s.execute(select(m.Identified_Threat).where(
            m.Identified_Threat.SessionID == fresh.json()["session_id"])).scalar_one()
        assert threat.ThreatTypeID is not None, "a cleanup tombstone blocked an honest proposal"
        assert threat.ThreatCatalogueID is not None
        proposed = s.get(m.Threat_Catalogue, threat.ThreatCatalogueID)
        assert (proposed.ThreatName, proposed.IsActive, proposed.Source) == (
            "Tampered relay firmware", False, "manual")

    # the curator's actual decision still stands: that threat name is never proposed again
    again = _post(client, _manual_body(threat_type_name="Firmware Backdoor",
                                       threat_name="Backdoored PLC firmware update"), key="key-3")
    assert again.status_code == 202, again.text
    with db_session() as s:
        threat = s.execute(select(m.Identified_Threat).where(
            m.Identified_Threat.SessionID == again.json()["session_id"])).scalar_one()
        assert threat.ThreatCatalogueID is None, "a rejected threat was proposed again"
        live = s.execute(select(func.count()).select_from(m.Threat_Catalogue).where(
            m.Threat_Catalogue.ThreatName == "Backdoored PLC firmware update",
            m.Threat_Catalogue.IsDeleted == False)).scalar()
        assert live == 0


SPOOFING_ID, DOS_ID, PHISHING_TYPE_ID = 1, 4, 90


def _seed_library(*, categories=(), types=(), maps=()):
    """Extra library rows for one test: (id, name) categories, (id, name) types under Tampering,
    (catalogue, category) map rows."""
    from app.db.engine import db_session
    with db_session() as s:
        for cid, name in categories:
            s.execute(m.Threat_Category.__table__.insert().values(
                ThreatCategoryID=cid, ThreatCategoryName=name, IsActive=True, IsDeleted=False))
        for tid, name in types:
            s.execute(m.Threat_Type.__table__.insert().values(
                ThreatTypeID=tid, ThreatTypeName=name, ThreatCategoryID=CATEGORY_ID,
                IsActive=True, IsDeleted=False, Source="functional_team_excel"))
        for cat_id, category in maps:
            s.execute(m.Threat_Catalogue_Category_Map.__table__.insert().values(
                ThreatCatalogueID=cat_id, ThreatCategoryID=category))
        s.commit()


def _refused_on(r, field: str, says: str) -> None:
    """A 422 on manual_scenario.<field> whose message names the library's value — and nothing
    saved.

    `field` is checked against the MODEL first, deliberately. It used to be a bare string compared
    to the error's `loc`, so when the payload renamed threat_type -> threat_type_name the three
    callers below failed with a confusing "'threat_type_name' == 'threat_type'" mismatch that reads
    like the ROUTE regressed, when the route was right and the test was stale. Asserting the field
    exists turns that into "no such field", which names the real problem and cannot be misread."""
    from app.api.schemas_references import ManualThreatIdentity

    assert field in ManualThreatIdentity.model_fields, (
        f"{field!r} is not a field of ManualThreatIdentity — the payload was renamed and this test "
        f"was not updated. Fields: {sorted(ManualThreatIdentity.model_fields)}")
    assert r.status_code == 422, r.text
    (err,) = r.json()["details"]["errors"]
    assert err["loc"][-1] == field and says in err["msg"], err
    assert _count(m.Scenario_Session) == 0 and _count(m.Identified_Threat) == 0


def test_a_library_threat_sent_with_another_type_is_refused_naming_its_type(client):
    """P1 rule 1: the library files 'Ransomware on OT support systems' under Malware/Ransomware,
    so sending it as a Phishing threat is a 422 — never a Phishing threat linked to the
    Malware/Ransomware row."""
    _seed_library(types=[(PHISHING_TYPE_ID, "Phishing")])
    r = _post(client, _manual_body(threat_type_name="Phishing"))
    _refused_on(r, "threat_type_name", "filed under 'Malware/Ransomware'")
    assert _count(m.Threat_Type) == 2 and _count(m.Threat_Catalogue) == 1


def test_a_category_the_library_does_not_file_the_threat_under_is_refused(client):
    """P1 rule 2: Spoofing + Malware/Ransomware + a threat the library files under Tampering."""
    _seed_library(categories=[(SPOOFING_ID, "Spoofing")])
    r = _post(client, _manual_body(threat_category_name="Spoofing"))
    _refused_on(r, "threat_category_name", "'Tampering'")


def test_a_twin_filed_under_another_type_after_the_library_read_is_still_refused(
        client, monkeypatch):
    """P1 rule 1 has a SECOND wall, and only this reaches it. _library_identity READS the library,
    and the mint happens further down the same transaction — so a curator or a library import can
    file the person's threat name under another type in between. UX_ThreatCatalogue_NaturalKey is
    on the name ALONE, so the mint then lands on THEIR row, and handing that row back would save
    the scenario silently linked to another type's threat: the mis-link the person is never told
    about. The index must answer exactly as the read would have — 422 on threat_type naming the
    library's type, nothing saved, not even the twin.

    The race is staged, not faked: the twin is inserted on the request's OWN session at the last
    rung before the mint, so the INSERT really does violate the index. The index is created here
    because the fixture builds its tables from the models, which carry no unique index at all —
    without it nothing would collide and the guard could never fire."""
    from app.db import dal
    from app.db.engine import get_engine

    _seed_library(types=[(PHISHING_TYPE_ID, "Phishing")])
    with get_engine().begin() as conn:   # raw DDL, filtered like production: no Index object on
        conn.exec_driver_sql(            # the shared metadata other test files share
            "CREATE UNIQUE INDEX UX_ThreatCatalogue_NaturalKey "
            "ON Threat_Catalogue(ThreatName) WHERE IsDeleted = 0")

    real_lookup, landed = dal.find_catalogue_id_by_norm_name, []

    def _a_curator_files_it_under_malware_ransomware(sess, type_id, name):
        if not landed:                   # once, between the library read and the mint
            sess.execute(m.Threat_Catalogue.__table__.insert().values(
                ThreatCatalogueID=600, ThreatTypeID=TYPE_ID, ThreatName=name,
                IsActive=True, IsDeleted=False, Source="functional_team_excel"))
            landed.append(600)
        return real_lookup(sess, type_id, name)   # type-scoped: still None under Phishing

    monkeypatch.setattr(dal, "find_catalogue_id_by_norm_name",
                        _a_curator_files_it_under_malware_ransomware)

    r = _post(client, _manual_body(threat_type_name="Phishing",
                                   threat_name="Backdoored PLC firmware update"))

    assert landed == [600], "the twin never landed: the save never reached the mint"
    _refused_on(r, "threat_type_name", "filed under 'Malware/Ransomware'")
    assert _count(m.Threat_Catalogue) == 1, "the twin, or a mint under Phishing, survived the 422"


@pytest.mark.parametrize("manual_first", [False, True])
def test_a_key_is_never_shared_between_an_ai_run_and_a_manual_save(client, monkeypatch,
                                                                   manual_first):
    """G12's second half — the KIND check, which nothing exercised.

    Both routes store the caller's Idempotency-Key in the SAME (EntityID, key) space, so one line
    in dal.reserve_idempotency_key_or_get_existing separates them. Delete it and the whole suite
    still passes, while the two directions each corrupt: an AI key replayed by a manual request
    hands back the AI session, so the person's scenario is never saved and the response names a
    scenario that does not exist; a manual key replayed by POST /v1/sessions reports a MANUAL
    session as a started run that will never generate anything, and the client polls it forever.
    Both must be 409, and this drives the real routes to prove it."""
    from app.api import sessions as sessions_api
    from app.db.engine import db_session
    monkeypatch.setattr(sessions_api, "enqueue_pipeline", lambda *a, **k: None)
    key = "one-key-two-kinds"
    ai_body = {"entity_id": ENTITY, "asset_id": ASSET, "supporting_system_id": [SUPPORT]}

    def _ai():
        return client.post("/v1/sessions", json=ai_body, headers={"Idempotency-Key": key})

    first, second = (lambda: _post(client, _manual_body(), key=key), _ai) if manual_first \
        else (_ai, lambda: _post(client, _manual_body(), key=key))
    assert first().status_code in (200, 202), "the first request of the pair was refused"
    clash = second()
    assert clash.status_code == 409, clash.text
    assert clash.json()["error_code"] == "idempotency_key_conflict"

    with db_session() as s:
        modes = [r.Mode for r in s.execute(select(m.Scenario_Session)).scalars()]
        assert modes == ["MANUAL" if manual_first else "AUTO"], \
            "the refused request created a second session, or replayed into the wrong one"


def test_an_asset_that_leaves_the_entity_mid_save_is_refused(client, monkeypatch):
    """The ownership re-check inside the write transaction, which nothing exercised.

    The save resolves the asset in a READ transaction, then makes an advisory moderation call,
    then writes. A curator or an integration can move that asset to another entity inside that
    window, and trusting the read-phase answer would save, accept and plan someone else's asset
    for its former owner. validate_scenario is the seam that sits between the two transactions,
    so moving the asset there reproduces the window exactly."""
    from app.api import sessions as sessions_api
    from app.db.engine import db_session

    real = sessions_api.validate_scenario

    def _move_the_asset(*a, **k):
        with db_session() as s:      # its own transaction, like the real curator would
            s.execute(update(m.ctm_scan_entity_bu)
                      .where(m.ctm_scan_entity_bu.ctm_scan_entity_id == ASSET)
                      .values(group_id=int(ENTITY) + 1))
            s.commit()
        return real(*a, **k)
    monkeypatch.setattr(sessions_api, "validate_scenario", _move_the_asset)

    r = _post(client, _manual_body(), key="asset-moved-mid-save")
    assert r.status_code == 403, r.text
    for model in (m.Scenario_Session, m.Threat_Scenario, m.Identified_Threat,
                  m.Threat_Scenario_Control_Map, m.Risk_Treatment_Plan):
        assert _count(model) == 0, f"{model.__tablename__} kept a row for the former owner"


def test_a_hand_written_threat_publishes_no_relevance_score(client):
    """No scoring pass runs for a threat a PERSON chose — scoping.Scored is built directly with
    the session's base score, because Scoped_Threat.Score and .ScopeRank are NOT NULL and the row
    has to be storable. Published, those placeholders read as a real relevance score: on the
    cross-session register, which sorts best-first, a hand-written threat sat at 60.0/rank 1,
    numerically indistinguishable from an AI threat that genuinely landed there. The columns keep
    their values (no schema change may touch them); the WIRE says null, which is the truth."""
    from app.db.engine import db_session

    sid, scid = (lambda b: (b["session_id"], b["scenario_id"]))(
        _post(client, _manual_body()).json())

    with db_session() as s:
        scoped = s.execute(select(m.Scoped_Threat).where(
            m.Scoped_Threat.SessionID == sid)).scalar_one()
        # The columns still carry their placeholders — this is a presentation rule, not a write.
        assert scoped.SelectionKind == "manual_entry"
        assert scoped.Score is not None and scoped.ScopeRank is not None

    card = client.get(f"/v1/sessions/{sid}/results").json()["scenarios"][0]
    assert (card["threat"]["score"], card["threat"]["scope_rank"]) == (None, None)
    accepted = client.get(f"/v1/sessions/{sid}/accepted-scenarios").json()["scenarios"][0]
    assert (accepted["threat"]["score"], accepted["threat"]["scope_rank"]) == (None, None)
    listed = client.get(f"/v1/entities/{ENTITY}/scenarios").json()   # a bare list
    mine = [x for x in listed if x["scenario_id"] == scid]
    assert mine and (mine[0]["threat"]["score"], mine[0]["threat"]["scope_rank"]) == (None, None)

    # THE TREATMENT SURFACES, which this test used to skip — and which is exactly why the bug
    # survived here. dal_treatment's selects added st.Score/st.ScopeRank by hand and left
    # SelectionKind behind, so _threat_block's `.get()` took the else branch and republished the
    # placeholders. These two are the pages a GRC reviewer signs.
    plan = client.get(f"/v1/sessions/{sid}/scenarios/{scid}/treatment-plan").json()
    assert (plan["threat"]["score"], plan["threat"]["scope_rank"]) == (None, None), (
        "the plan GET published a hand-written threat's placeholder score")
    reg = client.get(f"/v1/entities/{ENTITY}/treatment-plans?include_plan=true").json()
    row = next(x for x in reg["plans"] if x["scenario_id"] == scid)
    assert (row["threat"]["score"], row["threat"]["scope_rank"]) == (None, None), (
        "the entity register published a hand-written threat's placeholder score")


def test_a_refusal_after_the_save_names_what_was_saved(client, monkeypatch):
    """G10, end to end through the real error handler.

    The route's published description promises: "If a manual scenario was saved but the plan was
    then refused, the 409 carries its session_id and scenario_id." The route DID attach them, and
    _handle_treatment_conflict then built its envelope from `reason` alone and dropped them — so
    the client was handed a conflict naming no resource, for a scenario already committed and
    accepted on its behalf. Driven through TestClient so the real handler renders the body, not
    the raise site."""
    from app.api import treatment as treatment_mod
    from app.pipeline.treatment import TreatmentConflict

    def _refuse(*_a, **_k):
        raise TreatmentConflict("a plan already exists", reason="plan_already_exists")
    monkeypatch.setattr(treatment_mod, "_launch_generation", _refuse)

    r = _post(client, _manual_body(), key="post-save-refusal")
    assert r.status_code == 409, r.text
    details = r.json()["details"]
    assert details["reason"] == "plan_already_exists"
    # The ids of what the save COMMITTED before the plan was refused.
    assert details["session_id"] and details["scenario_id"]
    from app.db.engine import db_session
    with db_session() as s:
        out = s.execute(select(m.Threat_Scenario).where(
            m.Threat_Scenario.ScenarioID == details["scenario_id"])).scalar_one()
        assert out.SessionID == details["session_id"] and out.ScenarioSource == "manual"


def test_every_plan_surface_that_publishes_provenance_agrees(client):
    """G6 across every plan surface that carries the field, in BOTH register shapes.

    The register's two branches build TreatmentRegisterRow at two different call sites from two
    different column sets, and only one of them was passing the value — so `?include_plan=true`
    and the default answered differently about the same plan. The poll route is deliberately NOT
    here: it replies with TreatmentPlanStatusSummary, which publishes lifecycle and review state
    only and carries no scenario data at all."""
    body = _post(client, _manual_body()).json()
    sid, scid = body["session_id"], body["scenario_id"]

    plan = client.get(f"/v1/sessions/{sid}/scenarios/{scid}/treatment-plan")
    assert plan.status_code == 200, plan.text
    answers = {"plan": plan.json()["scenario_source"]}
    for flag in ("false", "true"):
        page = client.get(f"/v1/entities/{ENTITY}/treatment-plans", params={"include_plan": flag})
        assert page.status_code == 200, page.text
        row = [x for x in page.json()["plans"] if x["scenario_id"] == scid]
        assert row, f"the register lost the plan (include_plan={flag})"
        answers[f"register[include_plan={flag}]"] = row[0]["scenario_source"]

    assert set(answers.values()) == {"manual"}, answers


def test_the_entity_register_publishes_provenance(client):
    """G6 on the page a GRC reviewer SIGNS. The register is the answer to "which Critical risks
    still have no approved plan?", and it published `scenario_source: null` on every row — both
    of its branches built TreatmentRegisterRow without the field, so the column it already
    selected never reached the wire. A reviewer could not tell a plan written against a person's
    scenario from one written against the AI's."""
    _post(client, _manual_body())

    for include_plan in (False, True):
        page = client.get(f"/v1/entities/{ENTITY}/treatment-plans",
                          params={"include_plan": str(include_plan).lower()})
        assert page.status_code == 200, page.text
        rows = page.json()["plans"]
        assert rows, f"the register lost the manual plan (include_plan={include_plan})"
        assert [r["scenario_source"] for r in rows] == ["manual"] * len(rows), include_plan


def test_the_event_stream_stays_open_for_a_manual_session(client):
    """The SSE stream is the manual flow's ONLY live signal, and nothing tested it.

    A MANUAL session is born at REVIEW/AWAITING_DECISION and never moves, so no stage,
    subsystem_started or session_entered_review event can ever fire on it — work that never ran
    publishes nothing. The single event a client will ever receive is `treatment_plan_result`,
    after the plan commits. Whether it receives even that is decided by `_stream_still_open`,
    which every test in tests/test_sse_stream_lifecycle.py monkeypatches away, so the real gate
    had never been run against a real manual session. It must answer OPEN — if it ever closed
    here (say, because `manual_session` were added to review_gate_reason), the stream would
    reconcile and hang up before the plan finished, with no test noticing.
    """
    from app.api import sessions as sessions_mod
    from app.api.deps import Principal

    sid = _post(client, _manual_body()).json()["session_id"]
    principal = Principal(claims={"sub": USER}, entities={ENTITY}, client_id="c", tenant_id=TENANT)

    # The reconcile snapshot the stream sends first, built by the real loader.
    board = sessions_mod._load_events_board(sid, principal)
    assert board["session_id"] == sid and board["mode"] == "MANUAL"
    # The value the SSE contract guide documents for this snapshot. Asserted here so the guide
    # and the board cannot drift: a client branches its whole review UI on this field.
    assert board["progress"]["overall"] == "complete"
    # ...and the real per-tick gate, unpatched.
    assert sessions_mod._stream_still_open(sid, principal, False) is True


def test_every_model_publishing_scenario_source_shares_one_vocabulary():
    """G6: four models publish `scenario_source`, and each once carried its OWN hand-written value
    list. That is how `manual` came to be documented on three of them and not on ScenarioResult —
    the results card, the busiest scenario response, told clients the set was `generated |
    library` long after a person could author one. One shared constant now holds the list, and
    this refuses a fifth model that writes its own, or a value the writer stores but nobody
    documents."""
    from pydantic import BaseModel

    from app.api import schemas, schemas_treatment
    from app.api.schemas import SCENARIO_SOURCE_DOC
    from app.core.enums import ContentSource

    # Everything tasks._build_scenario_output_row can store must be named.
    for value in ("generated", "library", *(str(v) for v in ContentSource)):
        assert f"`{value}`" in SCENARIO_SOURCE_DOC, f"the wire can be {value!r}, the docs cannot"

    publishers = [obj for mod in (schemas, schemas_treatment) for obj in vars(mod).values()
                  if isinstance(obj, type) and issubclass(obj, BaseModel)
                  and "scenario_source" in obj.model_fields]
    assert len(publishers) >= 4, "the field moved — this test stopped looking at anything"
    for model in publishers:
        # startswith, not ==: a model may APPEND its own nuance, never replace the value list.
        assert (model.model_fields["scenario_source"].description or "").startswith(
            SCENARIO_SOURCE_DOC), f"{model.__name__} documents scenario_source its own way"

    # The library half of the same vocabulary. A hand-written scenario proposes PENDING library
    # rows stamped with this value, and the curator queue is where a curator decides whether to
    # believe them — so the one field that separates a person's proposal from an AI promotion
    # must name it. (created_by cannot: promote records the clicking curator's id there too.)
    for value in (str(v) for v in ContentSource):
        assert f"`{value}`" in (schemas.PendingLibraryRow.model_fields["source"].description or ""), \
            f"the curator queue can publish source={value!r} and does not document it"


def test_no_mapping_pass_can_ever_select_a_manual_scenario(client):
    """G3, driven through the REAL selection functions instead of asserting the stamp.

    "TSG never replaces the controls you sent" rested on a comment naming dal.control_map_owed — a
    function this tree does not have. What actually holds is two predicates in control_mapping, so
    this drives both, for BOTH kinds of hand-written scenario, clearing ONE reason at a time and
    showing that every remaining reason still holds by itself. A cleared reason must eventually
    make the row APPEAR, or "absent" could be an unrelated filter and this test would keep passing
    with the protection gone — which is how an earlier fix in this area was caught.

    THE THREE REASONS, and why the count grew. Both predicates require `ControlsMappedAt IS NULL`
    and both now require `ScenarioSource` not to be `manual`; eligible_outputs additionally
    requires no Threat_Scenario_Control_Map rows. Only the source test holds for EVERY manual
    scenario: since 2026-09 `mapped_controls` is optional, so a manual scenario saved with NO
    controls has no map rows to be excluded by, and for that row the stamp was briefly the only
    protection there was — a mutable timestamp carrying the owner's most explicit requirement
    ("only for threat scenario generated by AI not for the manual threat scenario"). Hence the
    second scenario below: the guards must be proven against the kind that has no controls too,
    because that kind is the one that broke the old two-guard claim.
    """
    from app.db.engine import db_session
    from app.pipeline import control_mapping

    # `mapped_controls=[]` is the payload's documented way of saying "no controls" (omitted, null,
    # "" and [] are all the same request), so these two rows are the two kinds of manual scenario
    # the save can produce.
    kinds = {}
    for kind, key, controls in (("the author's controls", "key-1", list(CONTROLS.values())),
                                ("no controls at all", "key-2", [])):
        body = _post(client, _manual_body(mapped_controls=controls), key=key).json()
        kinds[kind] = (body["session_id"], body["scenario_id"])

    with db_session() as s:
        def _stamp(scenario_id, mapped_at):
            s.execute(update(m.Threat_Scenario)
                      .where(m.Threat_Scenario.ScenarioID == scenario_id)
                      .values(ControlsMappedAt=mapped_at))

        def _source(scenario_id, value):
            s.execute(update(m.Threat_Scenario)
                      .where(m.Threat_Scenario.ScenarioID == scenario_id)
                      .values(ScenarioSource=value))

        def _map_row_count(scenario_id):
            return s.execute(select(func.count()).select_from(m.Threat_Scenario_Control_Map)
                             .where(m.Threat_Scenario_Control_Map.ScenarioID == scenario_id)
                             ).scalar()

        def _selected(session_id):
            """What BOTH selection paths would hand to a mapping pass right now."""
            return ([r[0] for r in control_mapping.eligible_outputs(s, session_id)],
                    [row[0] for row in control_mapping.sessions_awaiting_control_mapping(s)])

        # The sweep also demands a stale stage lease, on EVERY session it could return; backdate
        # both so the only thing left keeping either row out is the mapping state this test is
        # about, and so a sweep assertion below can never pass because of a lease instead.
        s.execute(update(m.Subsystem_Stage_State)
                  .where(m.Subsystem_Stage_State.Level == SubsystemLevel.SCENARIOS)
                  .values(UpdatedAt=datetime(2026, 8, 26, tzinfo=UTC)))

        for kind, (sid, scid) in kinds.items():
            stamped = s.execute(select(m.Threat_Scenario.ControlsMappedAt)
                                .where(m.Threat_Scenario.ScenarioID == scid)).scalar_one()
            assert stamped is not None, f"{kind}: the save stamps every manual row"

            # Every guard in place: neither path offers this row to a mapping pass.
            assert _selected(sid) == ([], []), kind

            # Reason 1 alone gone — the STAMP. The other two must still hold, and for the
            # control-less kind that means the source test is holding on its own already.
            _stamp(scid, None)
            assert _selected(sid) == ([], []), f"{kind}: cleared stamp"
            _stamp(scid, _now())

            # Reason 2 alone gone — PROVENANCE. The stamp must still hold both paths.
            _source(scid, "generated")
            assert _selected(sid) == ([], []), f"{kind}: source no longer manual"
            _source(scid, "manual")

            # Reason 3 alone gone — the MAP ROWS. eligible_outputs' own extra condition, and the
            # one that is VACUOUS for a scenario saved without controls: there is nothing to
            # delete, which is precisely why it cannot be the guard that protects that kind.
            expected_rows = len(CONTROLS) if kind == "the author's controls" else 0
            assert _map_row_count(scid) == expected_rows, kind
            s.execute(m.Threat_Scenario_Control_Map.__table__.delete().where(
                m.Threat_Scenario_Control_Map.ScenarioID == scid))
            assert _selected(sid) == ([], []), f"{kind}: map rows deleted"

            # Stamp gone AND map rows gone: the state a control-less manual row would be born in
            # if the save ever stopped stamping. ONLY the source test is left, and it holds.
            _stamp(scid, None)
            assert _selected(sid) == ([], []), f"{kind}: provenance is the last guard standing"

            # Every reason gone: BOTH paths now select the row. This is the reachability proof —
            # without it each assertion above could be an unrelated filter quietly excluding this
            # session, and the test would keep passing with all three guards deleted.
            _source(scid, "generated")
            assert _selected(sid) == ([scid], [sid]), f"{kind}: reachable once nothing guards it"

            # Back to a real manual row before the next kind, so the sweep assertions there
            # (which range over every session in the database) stay about that row alone.
            _source(scid, "manual")
            _stamp(scid, _now())


def test_save_is_all_or_nothing(client, monkeypatch):
    """G2: an acceptance that fails takes the whole save with it."""
    from app.api import sessions as sessions_mod

    def _boom(*_a, **_k):
        raise RuntimeError("decision writer down")
    monkeypatch.setattr(sessions_mod, "accept_new_manual_scenario", _boom)
    with pytest.raises(RuntimeError):
        _post(client, _manual_body(threat_type_name="Firmware Backdoor", threat_name="Brand new wording"))
    for model in (m.Scenario_Session, m.Subsystem_Stage_State, m.Identified_Threat,
                  m.Scoped_Threat, m.Threat_Scenario, m.Threat_Scenario_Control_Map,
                  m.Scenario_Audit, m.Risk_Treatment_Plan):
        assert _count(model) == 0, model.__tablename__
    assert _count(m.Threat_Type) == 1 and _count(m.Threat_Catalogue) == 1


def test_ai_never_rewrites_or_adds_to_a_manual_scenario(client, monkeypatch):
    """G5: the route refuses (before any lock or queue), and so does the worker."""
    from app.api import sessions as sessions_mod
    from app.db import dal
    from app.db.engine import db_session
    from app.pipeline import cascade

    def _never(*_a, **_k):
        raise AssertionError("the AI must never be queued for a manual session")
    monkeypatch.setattr(sessions_mod, "enqueue_regeneration", _never)
    monkeypatch.setattr(sessions_mod, "enqueue_next_set", _never)

    r = _post(client, _manual_body())
    sid, scid = r.json()["session_id"], r.json()["scenario_id"]
    with db_session() as s:
        text_before = s.execute(select(m.Threat_Scenario.ScenarioJSON).where(
            m.Threat_Scenario.ScenarioID == scid)).scalar_one()

    for path, payload in ((f"/v1/sessions/{sid}/regenerate/scenarios", {"scenario_ids": [scid]}),
                          (f"/v1/sessions/{sid}/scenarios/next-set", None)):
        resp = client.post(path, json=payload) if payload is not None else client.post(path)
        assert resp.status_code == 409, (path, resp.text)
        assert resp.json()["details"]["reason"] == "manual_session", resp.text

    # The worker is the second wall: even a message that reached it writes no scenario. The
    # refusal must be the reason it stops — so the first thing AFTER the guard raises, and the
    # call carries REAL targets: with target_ids=None every granularity dies on 'no_target_ids'
    # first, which is why this half used to pass with the guard deleted.
    def _guard_bypassed(*_a, **_k):
        raise AssertionError("the guard let an AI write through on a MANUAL session")
    monkeypatch.setattr(cascade, "_resolve_regen_context", _guard_bypassed)

    published: list = []
    monkeypatch.setattr(cascade, "_publish_regen_result",
                        lambda *a, reason=None, **k: published.append(reason))

    def _reset_scenarios_stage(s):
        # What the real route does before queueing (reserve at a new epoch). settle_unstarted
        # claims the stage, and a settled MANUAL session sits at AWAITING_DECISION, so without
        # this the refusal records nothing to assert on.
        s.execute(update(m.Subsystem_Stage_State)
                  .where(m.Subsystem_Stage_State.SessionID == sid,
                         m.Subsystem_Stage_State.Level == SubsystemLevel.SCENARIOS)
                  .values(Status=StageStatus.IDLE))
        s.commit()

    with db_session() as s:
        session_row = dict(dal.load_session(s, sid))
        _reset_scenarios_stage(s)
        cascade.run_regeneration(s, session_row, 0, "scenario", [scid], 1, None, str(uuid.uuid4()))
        s.commit()
        _reset_scenarios_stage(s)
        cascade.run_next_set(s, session_row, 0, 1, 0, None, str(uuid.uuid4()))
        s.commit()
    with db_session() as s:
        rows = s.execute(select(m.Threat_Scenario).where(
            m.Threat_Scenario.SessionID == sid)).scalars().all()
        assert [(r.ScenarioID, r.ScenarioJSON, r.Superseded) for r in rows] == [
            (scid, text_before, 0)]
    assert "manual_session" in published, f"the worker settled for another reason: {published}"


def test_generated_scenario_through_the_same_endpoint(client):
    """is_manual=false is today's request by another address — and a MANUAL session's own ids
    work on it too, so both kinds really do share one door."""
    manual = _post(client, _manual_body()).json()
    r = client.post("/v1/remediation-plans", json={
        "is_manual": False, "session_id": manual["session_id"],
        "scenario_id": manual["scenario_id"], **_RISK})
    # The plan already exists — proof the flag routed to the same create the path route uses.
    assert r.status_code == 409 and r.json()["details"]["reason"] == "plan_already_exists", r.text




def _library_of(payload: dict) -> dict | None:
    """The block, however the surface nests it."""
    return payload.get("library")


def test_the_curator_verdict_reaches_the_caller_on_every_surface(client):
    """The gap the live run exposed: a curator declines a wording, the scenario still saves, and
    the caller sees only `grounding_status: unverified` — identical to "new, awaiting review". So
    they resubmit forever while the decision sits in an audit row no API returns.

    The block says which it is, in one shape, on every surface that shows the scenario. `name`
    holds a NAME and `status` holds the verdict — they are different facts and were briefly the
    same field."""
    from app.db.engine import db_session

    with db_session() as s:      # a curator has already refused this exact wording
        s.execute(m.Threat_Catalogue.__table__.insert().values(
            ThreatCatalogueID=770, ThreatTypeID=TYPE_ID, ThreatName="Declined wording",
            IsActive=False, IsDeleted=True, Source="ai_generated"))
        s.commit()

    body = _post(client, _manual_body(threat_name="Declined wording"), key="verdict-surfaces").json()
    sid, scid = body["session_id"], body["scenario_id"]

    receipt = body["library"]
    assert receipt["threat"] == {"name": "Declined wording", "status": "rejected_by_curator"}
    assert receipt["threat_type"]["name"] == "Malware/Ransomware"   # a NAME, never a status
    assert "declined it" in (receipt["message"] or "")

    surfaces = {
        "results": client.get(f"/v1/sessions/{sid}/results").json()["scenarios"][0],
        "accepted": client.get(f"/v1/sessions/{sid}/accepted-scenarios").json()["scenarios"][0],
        "entity list": next(x for x in client.get(f"/v1/entities/{ENTITY}/scenarios").json()
                            if x["scenario_id"] == scid),
        "plan": client.get(f"/v1/sessions/{sid}/scenarios/{scid}/treatment-plan").json(),
    }
    for name, payload in surfaces.items():
        block = _library_of(payload)
        assert block is not None, f"{name} published no library block"
        assert block["threat"]["status"] == "rejected_by_curator", name
        assert block["threat"]["name"] == "Declined wording", name

    # ...and the replay says the same thing, rather than dropping the warning on a retry.
    again = _post(client, _manual_body(threat_name="Declined wording"), key="verdict-surfaces").json()
    assert again["library"] == receipt


def test_a_new_proposal_says_it_is_awaiting_review_and_a_match_says_nothing(client):
    """The other two outcomes. `inserted` explains why a brand-new threat is unverified TODAY and
    may not be tomorrow; a plain match earns NO message, because a UI must not raise a banner to
    announce that nothing happened."""
    fresh = _post(client, _manual_body(threat_type_name="Brand New Type",
                                       threat_name="Brand new threat wording"),
                  key="awaiting-review").json()["library"]
    assert fresh["threat"]["status"] == "inserted"
    assert fresh["threat_type"] == {"name": "Brand New Type", "status": "inserted"}
    assert "awaiting" in (fresh["message"] or "").lower()

    matched = _post(client, _manual_body(), key="plain-match").json()["library"]
    assert matched["threat"]["status"] == "existing"
    assert matched["threat_type"]["status"] == "existing"
    assert matched["message"] is None, "a banner was raised for 'nothing happened'"


def test_an_ai_scenario_publishes_no_library_block(client):
    """A generated scenario proposes nothing to the library, so the block would be noise on every
    AI card. Null, not an empty object every UI would have to special-case.

    The provenance is flipped on a saved row rather than driving the whole pipeline: this asserts
    the READER's rule (publish only for `manual`), and the writer's provenance is pinned by its
    own tests."""
    from app.db.engine import db_session

    body = _post(client, _manual_body(), key="ai-branch").json()
    sid, scid = body["session_id"], body["scenario_id"]
    assert body["library"] is not None, "a manual save must carry the block"

    with db_session() as s:
        s.execute(update(m.Threat_Scenario)
                  .where(m.Threat_Scenario.ScenarioID == scid)
                  .values(ScenarioSource="generated"))
        s.commit()

    card = client.get(f"/v1/sessions/{sid}/results").json()["scenarios"][0]
    assert card["scenario_source"] == "generated"
    assert card["library"] is None


def test_a_row_without_the_threat_join_publishes_no_library_block():
    """Found on a live stack: GET /v1/entities/{id}/treatment-plans returned
    `library.threat.name == ""` with `status: "existing"` — a positive claim about a library entry
    built from columns the query never selected.

    CAUSE: dal_treatment.entity_plan_rows adds the Identified_Threat join only under
    ?include_plan=true, so the register's DEFAULT page carries ScenarioSource but no names, and
    `.get(...) or ""` turned "column absent" into an empty name. It sat beside a `threat` block
    that was already null for exactly the same reason.

    The block is a SIBLING of the threat block, so it must vanish where the threat block does. A
    name field that cannot hold a name publishes nothing."""
    from app.api.sessions import _library_block

    named = {"ScenarioSource": "manual", "ScenarioID": "s1",
             "ThreatName": "Ransomware on OT support systems", "LibraryThreatName": None,
             "ThreatType": "Malware/Ransomware", "LibraryThreatType": None}
    block = _library_block(named, {})
    assert block is not None, "a row carrying the threat join must still publish the block"
    assert block["threat"]["name"] == "Ransomware on OT support systems"
    assert block["threat_type"]["name"] == "Malware/Ransomware"

    lifecycle_only = {k: v for k, v in named.items()
                      if k in ("ScenarioSource", "ScenarioID")}  # a row with no threat join
    assert _library_block(lifecycle_only, {}) is None, (
        "a row with no threat join must publish null, not a block naming the empty string")


def test_the_register_publishes_the_library_block_on_its_default_page(client):
    """The guard above silenced the fabricated `{"name": ""}` — and, on its own, ALSO removed the
    block from the register's default page, because that select carried no threat join at all.
    `?include_plan` widens what a row CONTAINS; it must not change what the page SAYS about the
    library, and a reviewer opening the register should not have to know a query parameter to be
    told a curator declined the wording.

    So the four name columns now ride the default select too. This asserts both halves: present
    and correctly NAMED with and without include_plan."""
    body = _post(client, _manual_body()).json()
    scid = body["scenario_id"]

    for query in ("", "?include_plan=true"):
        reg = client.get(f"/v1/entities/{ENTITY}/treatment-plans{query}").json()
        row = next(x for x in reg["plans"] if x["scenario_id"] == scid)
        lib = row["library"]
        assert lib is not None, f"the register dropped the library block on '{query or 'default'}'"
        # The REQUEST's names are `threat_name`/`threat_type_name` since the 2026-09 payload; the
        # RESPONSE block's keys (`threat`, `threat_type`) are unchanged.
        assert lib["threat"]["name"] == _manual_body()["manual_scenario"]["threat_name"], (
            f"a name field published '{lib['threat']['name']}' on '{query or 'default'}'")
        assert lib["threat_type"]["name"] == _manual_body()["manual_scenario"]["threat_type_name"]


# --- AI-scenario control top-up (POST /v1/remediation-plans, is_manual=false) ----------------------
EXTRA_CONTROLS = {300 + i: f"CII-CID-{300 + i}" for i in range(6)}


def _ai_scenario_with(client, keep: set[int]) -> tuple[str, str]:
    """A saved scenario flipped to AI provenance, planless, with only `keep` of its controls mapped,
    and six more live library controls available to top up from."""
    from app.db.engine import db_session
    saved = _post(client, _manual_body(), key=f"top-up-{uuid.uuid4()}").json()
    sid, scid = saved["session_id"], saved["scenario_id"]
    with db_session() as s:
        s.execute(update(m.Threat_Scenario).where(m.Threat_Scenario.ScenarioID == scid)
                  .values(ScenarioSource="generated"))
        s.execute(m.Risk_Treatment_Plan.__table__.delete())
        s.execute(m.Threat_Scenario_Control_Map.__table__.delete().where(
            m.Threat_Scenario_Control_Map.ScenarioID == scid,
            m.Threat_Scenario_Control_Map.ControlLibraryID.not_in(keep)))
        for cid, code in EXTRA_CONTROLS.items():
            if s.get(m.Control_Library, cid) is None:
                s.execute(m.Control_Library.__table__.insert().values(
                    ControlLibraryID=cid, ControlCode=code, ITOT="OT", Domain="Network",
                    ControlName=f"Control {code}", ControlDescription="-",
                    IsActive=True, IsDeleted=False))
        s.commit()
    return sid, scid


def _fake_grounding(monkeypatch, *, score=30.0, boom=False):
    """Stands in for embed + rerank: every pooled control, best-first, all BELOW min_score but
    ABOVE control_map_backfill_min_score, so a pass proves the backfill. Records each query.

    The score used to be 5.0, from when the top-up took the nearest match with no cutoff at all.
    It now shares `select_applicable_controls` with the mapping pass, so a candidate under the
    backfill floor (25.0) is never written — see
    test_a_top_up_never_writes_a_control_below_the_backfill_floor, which pins that directly."""
    from app.pipeline import control_mapping, grounding
    calls: list[tuple[str, list[int]]] = []

    def _ground(_llm, queries, rows, _s, **_k):
        if boom:
            raise RuntimeError("reranker down")
        calls.append((queries[0][0], [r["ControlLibraryID"] for r in rows]))
        return [grounding.ControlMatches(
            [(r, score - i * 0.1) for i, r in enumerate(rows)], True)]
    monkeypatch.setattr(control_mapping.grounding, "ground_control_queries", _ground)
    monkeypatch.setattr(control_mapping, "get_llm", lambda: object())
    return calls


def _mapped(scid: str) -> list[tuple[int, int]]:
    from app.db.engine import db_session
    cm = m.Threat_Scenario_Control_Map
    with db_session() as s:
        return [tuple(r) for r in s.execute(select(cm.ControlLibraryID, cm.MapRank)
                                            .where(cm.ScenarioID == scid).order_by(cm.MapRank))]


def _ai_post(client, sid, scid):
    return client.post("/v1/remediation-plans", json={
        "is_manual": False, "session_id": sid, "scenario_id": scid, **_RISK})


def test_an_ai_scenario_short_of_controls_is_topped_up_before_its_plan(client, monkeypatch):
    calls = _fake_grounding(monkeypatch)
    sid, scid = _ai_scenario_with(client, keep={213})
    r = _ai_post(client, sid, scid)
    assert r.status_code == 202, r.text
    rows = _mapped(scid)
    ids = [cid for cid, _ in rows]
    assert len(ids) == 5 == len(set(ids)) and 213 in ids
    assert RETIRED_CONTROL[0] not in ids                       # live library rows only
    assert [rank for _, rank in rows] == sorted(rank for _, rank in rows)
    # Category, threat and type all steer the query. The pool is the pipeline's UNFILTERED list
    # (so the embedding-matrix cache hits) and the already-mapped 213 is still never re-picked.
    query, pool = calls[0]
    assert "Tampering" in query and "Ransomware on OT support systems" in query
    assert 213 in pool and ids.count(213) == 1
    from app.db.engine import db_session
    with db_session() as s:
        snap = json.loads(s.execute(select(m.Risk_Treatment_Plan.InputSnapshotJSON)).scalar())
        audit = s.execute(select(m.Scenario_Audit.DetailJSON).where(
            m.Scenario_Audit.ScenarioID == scid,
            m.Scenario_Audit.EventType == "controls_mapped")).scalar()
    assert snap["existing_controls"]["library_mapped_count"] == 5
    assert json.loads(audit)["source"] == "remediation_top_up"
    assert json.loads(audit)["below_min_score"] == 4           # nearest-match fallback recorded


def test_an_ai_scenario_already_at_the_floor_costs_no_grounding(client, monkeypatch):
    calls = _fake_grounding(monkeypatch)
    sid, scid = _ai_scenario_with(client, keep=set(CONTROLS))
    from app.core.config import get_settings
    # control_map_min_count, not the deprecated remediation_control_min_count: the top-up now fills
    # to the same floor the mapping pass applies, so this is the knob that decides "already there".
    monkeypatch.setattr(get_settings(), "control_map_min_count", 3)
    assert _ai_post(client, sid, scid).status_code == 202
    assert calls == [] and len(_mapped(scid)) == 3


def test_a_manual_scenario_is_never_topped_up(client, monkeypatch):
    calls = _fake_grounding(monkeypatch)
    saved = _post(client, _manual_body(), key="manual-no-top-up").json()
    assert calls == [] and len(_mapped(saved["scenario_id"])) == 3
    # The same manual scenario reached through its ids on the is_manual=false branch.
    from app.db.engine import db_session
    with db_session() as s:
        s.execute(m.Risk_Treatment_Plan.__table__.delete())
        s.commit()
    assert _ai_post(client, saved["session_id"], saved["scenario_id"]).status_code == 202
    assert calls == [] and len(_mapped(saved["scenario_id"])) == 3


def test_top_up_switched_off_in_env_leaves_controls_alone(client, monkeypatch):
    calls = _fake_grounding(monkeypatch)
    sid, scid = _ai_scenario_with(client, keep={213})
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "remediation_control_top_up_enabled", False)
    assert _ai_post(client, sid, scid).status_code == 202
    assert calls == [] and [cid for cid, _ in _mapped(scid)] == [213]


def test_a_dead_reranker_still_gets_the_plan(client, monkeypatch):
    _fake_grounding(monkeypatch, boom=True)
    sid, scid = _ai_scenario_with(client, keep={213})
    assert _ai_post(client, sid, scid).status_code == 202
    assert [cid for cid, _ in _mapped(scid)] == [213]
    # Fail-open must not look complete: the reviewer is told the floor was missed.
    from app.db.engine import db_session
    with db_session() as s:
        snap = json.loads(s.execute(select(m.Risk_Treatment_Plan.InputSnapshotJSON)).scalar())
    assert any("top-up could not reach the floor" in w for w in snap["warnings"]), snap["warnings"]


def test_a_top_up_never_writes_a_control_below_the_backfill_floor(client, monkeypatch):
    """REPLACES the pick_top_up unit test, whose function is gone with the rule it implemented:
    "best `need` distinct controls, deliberately NO min-score cut". That is how a remediation plan
    came to carry a control scoring 3 out of 100, presented like a real match.

    The top-up now shares `select_applicable_controls` with the mapping pass, so a candidate below
    control_map_backfill_min_score may never be added, whatever the shortfall. A scenario the
    library cannot cover comes back SHORT — and the plan's own snapshot says so, which is the
    honest answer the padded version could never give."""
    calls = _fake_grounding(monkeypatch, score=5.0)   # every candidate under the 25.0 floor
    sid, scid = _ai_scenario_with(client, keep={213})
    assert _ai_post(client, sid, scid).status_code == 202
    assert calls, "the grounding still ran — this is a floor decision, not a skipped request"
    assert [cid for cid, _ in _mapped(scid)] == [213], "nothing below the floor may be added"
    from app.db.engine import db_session
    with db_session() as s:
        snap = json.loads(s.execute(select(m.Risk_Treatment_Plan.InputSnapshotJSON)).scalar())
    assert any("top-up could not reach the floor" in w for w in snap["warnings"]), snap["warnings"]


def test_a_refused_plan_request_spends_no_grounding(client, monkeypatch):
    """Already planned → 409 as before, and the top-up never ran."""
    calls = _fake_grounding(monkeypatch)
    sid, scid = _ai_scenario_with(client, keep={213})
    assert _ai_post(client, sid, scid).status_code == 202
    calls.clear()
    r = _ai_post(client, sid, scid)
    assert r.status_code == 409 and calls == []


@pytest.mark.parametrize("dates, status", [
    ({}, 202),
    ({"mitigation_start_date": None, "mitigation_end_date": None}, 202),
    ({"mitigation_start_date": "", "mitigation_end_date": ""}, 202),
    ({"mitigation_start_date": "2026-13-40", "mitigation_end_date": "2026-12-31"}, 422),
    ({"mitigation_start_date": 123, "mitigation_end_date": "2026-12-31"}, 422),
    ({"mitigation_start_date": "2026-10-01"}, 422),
])
def test_mitigation_dates_are_optional_but_typed_for_both_kinds(client, monkeypatch, dates, status):
    _fake_grounding(monkeypatch)
    risk = {k: v for k, v in _RISK.items() if not k.startswith("mitigation_")} | dates
    manual = _post(client, {"is_manual": True, "manual_scenario": _manual(), **risk},
                   key=f"dates-{uuid.uuid4()}")
    assert manual.status_code == status, manual.text
    sid, scid = _ai_scenario_with(client, keep={213})
    ai = client.post("/v1/remediation-plans", json={
        "is_manual": False, "session_id": sid, "scenario_id": scid, **risk})
    assert ai.status_code == status, ai.text
