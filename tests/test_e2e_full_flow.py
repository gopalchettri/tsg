"""A GENUINE end-to-end test: real HTTP requests via TestClient against the real FastAPI app
(app.main.create_app()), a real file-backed SQLite database wired through the production
get_engine()/db_session() seam (TSG_DB_DSN env var — no monkeypatching of the DB layer at all),
and real Pydantic response-model serialization.

WHY THIS FILE EXISTS: every other test in this suite calls pipeline functions directly against
a hand-built session — proven correct at the function level (400+ tests), but NEVER through
FastAPI's request parsing, `Depends` dependency injection, or response-model serialization.
`LibraryPromotionResponse`/`PromotedRef`'s JSON shape had literally never been produced by a
real HTTP call before this file.

SCOPE, stated honestly: this drives results -> accept -> promote-to-library -> accepted-
scenarios as one continuous real-HTTP flow, seeded with a session already at the REVIEW
barrier (an already-generated, already-scoped threat+scenario — the same state
test_accept_any_version.py already validates as reachable). It also covers session creation,
cancel, next-set, and regenerate as real HTTP calls (added 2026-08-28, closing a gap an audit
of the app's 73 registered routes found: those 4 had zero test coverage of any kind). None of
these re-drive the actual async generation/regeneration work: `enqueue_pipeline`/
`enqueue_next_set`/`enqueue_regeneration` are all documented as "indirection so tests can run
... synchronously instead of via a broker" — each is monkeypatched to a no-op here, same as the
existing seam is designed for, rather than needing a FakeLLM that answers every prompt shape
the whole Stage-1/2/3/4 pipeline can ask (a separate undertaking already covered exhaustively
at the function level elsewhere in this suite). This file's job is narrower and different:
prove the HTTP/DI/serialization layer itself is correct, not re-prove pipeline logic that
hundreds of other tests already pin.
"""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from app.core.enums import SessionStatus, StageStatus, SubsystemLevel, WorkflowStage
from app.db import models as m

TENANT, ENTITY, USER = "t", "86", "u1"


def _now():
    return datetime.now(UTC)


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A real app, a real (file-backed, so every route's own db_session() call shares it)
    SQLite database, and a Principal injected via the documented dependency-override seam
    (app/api/deps.py: "Tests override get_principal via app.dependency_overrides")."""
    db_path = tmp_path / "e2e.db"
    monkeypatch.setenv("TSG_DB_DSN", f"sqlite:///{db_path}")

    # The per-test autouse fixture in conftest.py already clears these lru_caches on both
    # setup and teardown; clearing again here (after setenv, before first use) guarantees THIS
    # test's get_engine() actually reads the env var we just set rather than a stale instance.
    from app.core.config import get_settings
    from app.db.engine import _sessionmaker, get_engine
    get_settings.cache_clear()
    get_engine.cache_clear()
    _sessionmaker.cache_clear()

    engine = create_engine(f"sqlite:///{db_path}", future=True)
    for tbl in (m.Scenario_Session, m.Subsystem_Stage_State, m.Identified_Threat,
                m.Scoped_Threat, m.Threat_Scenario, m.Scenario_Audit,
                m.Threat_Type, m.Threat_Catalogue, m.ThreatType_ThreatActor_Map,
                m.Threat_Catalogue_Category_Map, m.Control_Library,
                m.Threat_Scenario_Control_Map,
                # Platform-owned tables gather_asset_details() reads for session creation.
                m.ctm_scan_entity, m.ctm_scan_entity_bu, m.onboarding_supporting_systems,
                m.ctm_scan_entity_supporting_system, m.Config_Tuning):
        tbl.__table__.create(engine, checkfirst=True)
    engine.dispose()  # the app's own get_engine() opens the real pooled connections from here

    from app.api.deps import Principal, get_principal
    from app.main import create_app

    app = create_app()
    app.dependency_overrides[get_principal] = lambda: Principal(
        claims={"sub": USER}, entities={ENTITY}, client_id="e2e-test", tenant_id=TENANT)
    # Deliberately NOT `with TestClient(app) as c:` — that triggers the ASGI lifespan, whose
    # assert_sse_graceful_shutdown_wired() fail-fast check requires a real uvicorn Server.serve()
    # process (it introspects the live SIGTERM handler) and legitimately cannot pass under
    # TestClient. That check verifies process/deployment wiring, not request handling — no route
    # under test here reads anything lifespan sets on app.state, so skipping it is safe and in
    # scope (this file proves the HTTP/DI/serialization layer, not deployment startup gates).
    yield TestClient(app)
    app.dependency_overrides.clear()


def _seed_reviewable_session(client) -> tuple[str, str, str]:
    """One session at the REVIEW barrier with one grounded, catalogue-linked, unaccepted
    scenario ready to accept and promote — via the app's OWN engine (get_engine(), the exact
    same one every route call uses), proving the seed and the routes agree on where the data
    lives. Returns (session_id, scenario_id, threat_id)."""
    from app.db.engine import db_session

    sid, tid, oid, stid = (str(uuid.uuid4()) for _ in range(4))
    with db_session() as s:
        s.execute(m.Threat_Type.__table__.insert().values(
            ThreatTypeID=7, ThreatTypeName="Ransomware", ThreatCategoryID=None,
            IsActive=True, IsDeleted=False))
        s.execute(m.Scenario_Session.__table__.insert().values(
            SessionID=sid, TenantID=TENANT, EntityID=ENTITY, UserID=USER, AssetID=7,
            AssetName="E2E Historian", SessionStatus=SessionStatus.completed,
            CompletedAt=_now(), CurrentStage=WorkflowStage.REVIEW,
            StageStatus=StageStatus.AWAITING_DECISION, Mode="AUTO",
            CurrentSubsystemIndex=0, SubsystemsJSON="[]",
            CreatedAt=_now(), UpdatedAt=_now()))
        for level, status in ((SubsystemLevel.LOCK, StageStatus.IDLE),
                              (SubsystemLevel.SCENARIOS, StageStatus.AWAITING_DECISION)):
            s.execute(m.Subsystem_Stage_State.__table__.insert().values(
                StateID=str(uuid.uuid4()), SessionID=sid, TenantID=TENANT, EntityID=ENTITY,
                SubsystemID=0, Level=level, Status=status, GenerationEpoch=1,
                LeaseExpiresAt=_now() + timedelta(minutes=10), AttemptCount=1,
                UpdatedAt=_now(), CreatedAt=_now()))
        s.execute(m.Identified_Threat.__table__.insert().values(
            ThreatID=tid, SessionID=sid, TenantID=TENANT, EntityID=ENTITY, UserID=USER,
            SubsystemID=0, ThreatCategory="Tampering", ThreatType="Ransomware",
            ThreatName="Ransomware encrypts historian data", GenericName="Ransomware encrypts data",
            Description="Encrypts stored data at rest and demands payment.",
            ThreatTypeID=7, ThreatCatalogueID=None,
            ThreatActorsJSON=json.dumps({"actors": [], "actor_ids": [], "validated": True}),
            GroundingStatus="unverified", Superseded=0, CreatedAt=_now()))
        s.execute(m.Scoped_Threat.__table__.insert().values(
            ScopedThreatID=stid, SessionID=sid, TenantID=TENANT, EntityID=ENTITY, UserID=USER,
            SubsystemID=0, ThreatID=tid, Score=80.0, ScopeRank=1, Selected=1,
            Superseded=0, CreatedAt=_now()))
        s.execute(m.Threat_Scenario.__table__.insert().values(
            ScenarioID=oid, SessionID=sid, TenantID=TENANT, EntityID=ENTITY, UserID=USER,
            SubsystemID=0, ScopedThreatID=stid, Status="complete",
            ScenarioJSON=json.dumps({"scenario_title": "Ransomware locks the historian",
                                    "scenario_statement": "An attacker encrypts stored data.",
                                    "risk_statement": "Historian data becomes unrecoverable."}),
            Accepted=0, Superseded=0, IdentityHash="e2e-hash", ScenarioNumber=1,
            GenerationEpoch=1, CreatedAt=_now()))
        s.commit()
    return sid, oid, tid


def test_results_accept_promote_accepted_scenarios_real_http_flow(client):
    """The continuous flow, real HTTP throughout: GET results (pending) -> POST accept ->
    POST promote-to-library -> GET accepted-scenarios. Every response is parsed as the real
    Pydantic response model FastAPI produced — not a hand-built dict."""
    sid, oid, tid = _seed_reviewable_session(client)

    # 1. GET /results — the scenario is visible and NOT yet accepted.
    r = client.get(f"/v1/sessions/{sid}/results")
    assert r.status_code == 200, r.text
    results = r.json()
    assert results["session_id"] == sid
    scenarios = results["scenarios"]
    assert len(scenarios) == 1
    assert scenarios[0]["scenario_id"] == oid
    assert scenarios[0]["accepted"] is False
    assert scenarios[0]["threat"]["threat_id"] == tid
    assert scenarios[0]["threat"]["threat_catalogue_id"] is None

    # 2. POST /accept — real HTTP, real accept_session, real AcceptResponse serialization.
    r = client.post(f"/v1/sessions/{sid}/accept", json={"mode": "all"})
    assert r.status_code == 200, r.text
    accept_body = r.json()
    assert accept_body["accepted_count"] == 1
    assert accept_body["status"] == str(SessionStatus.completed)

    # 3. POST promote-to-library — the exact route/response shape the audit found had NEVER
    # been produced by a real HTTP call. Asserts the LibraryPromotionResponse/PromotedRef
    # Pydantic round-trip, not a hand-built PromotionResult namedtuple.
    r = client.post(f"/v1/sessions/{sid}/scenarios/{oid}/promote-to-library")
    assert r.status_code == 200, r.text
    promo = r.json()
    assert promo["success"] is True
    assert promo["created_count"] == 1           # only the catalogue row is new — the type was pre-seeded live
    assert promo["threat_type"]["status"] == "existing"
    assert promo["threat_type"]["id"] == 7       # reused the live type, not re-minted
    assert promo["threat"]["status"] == "inserted"
    new_catalogue_id = promo["threat"]["id"]
    assert isinstance(new_catalogue_id, int)
    assert promo["threat"]["name"] == "Ransomware encrypts data"
    assert promo["threat_actors"] == []          # no stored actors on this seed
    assert promo["controls"] == [] and promo["controls_mapped"] is False

    # Calling it again must be idempotent — EXISTING, not a second insert (real HTTP, same
    # route, proving the reuse gate holds over a genuine second request/response cycle).
    r2 = client.post(f"/v1/sessions/{sid}/scenarios/{oid}/promote-to-library")
    assert r2.status_code == 200, r2.text
    assert r2.json()["threat"]["status"] == "existing"
    assert r2.json()["threat"]["id"] == new_catalogue_id
    assert r2.json()["created_count"] == 0

    # 4. GET /accepted-scenarios — the promoted threat's catalogue id is now visible on the
    # SAME threat, on a completely separate read route, through its own real HTTP call.
    r = client.get(f"/v1/sessions/{sid}/accepted-scenarios")
    assert r.status_code == 200, r.text
    accepted = r.json()["scenarios"]
    assert len(accepted) == 1
    assert accepted[0]["scenario_id"] == oid
    assert accepted[0]["threat"]["threat_catalogue_id"] == new_catalogue_id
    assert accepted[0]["threat"]["threat_catalogue_id"] == new_catalogue_id


def test_promote_before_accept_is_refused_over_real_http(client):
    """The gate real HTTP callers actually hit: promoting a still-pending scenario must 409
    with the documented reason, not silently succeed or 500."""
    sid, oid, _tid = _seed_reviewable_session(client)

    r = client.post(f"/v1/sessions/{sid}/scenarios/{oid}/promote-to-library")
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["error_code"] == "accept_conflict"
    assert body["details"]["reason"] is not None


def test_unauthorized_entity_gets_403(client):
    """Object-level authz over real HTTP: a session id that exists but is outside the
    Principal's authorized entities must 403 (app/api/errors.py's EntityForbidden handler —
    the entity boundary is deliberately visible to an authenticated-but-wrong-entity caller;
    see get_authorized_session's own docstring and test_header_auth.py's EntityForbidden
    coverage for the established, function-level-tested contract this pins at the HTTP layer)."""
    sid, _oid, _tid = _seed_reviewable_session(client)

    from app.api.deps import Principal, get_principal
    client.app.dependency_overrides[get_principal] = lambda: Principal(
        claims={"sub": "someone-else"}, entities={"other-entity"},
        client_id="e2e-test", tenant_id=TENANT)
    r = client.get(f"/v1/sessions/{sid}/results")
    assert r.status_code == 403, r.text
    assert r.json()["error_code"] == "forbidden"


def _seed_asset_and_subsystem(asset_id: int = 7, subsystem_id: int = 41) -> None:
    """One ctm_scan_entity (asset) owned by ENTITY, with one linked supporting system — the
    platform-owned data gather_asset_details() needs. No sector (optional on CreateSessionBody)
    and no Config_Tuning rows (empty = pure config defaults, per tuning.resolve_snapshot)."""
    from app.db.engine import db_session

    with db_session() as s:
        s.execute(m.ctm_scan_entity.__table__.insert().values(
            id=asset_id, name="E2E Demo Pumping Station", criticality=3,
            type="Pumping Station", is_deleted=False))
        s.execute(m.ctm_scan_entity_bu.__table__.insert().values(
            ctm_scan_entity_id=asset_id, group_id=int(ENTITY), service_id=None))
        s.execute(m.onboarding_supporting_systems.__table__.insert().values(
            id=subsystem_id, name="SCADA HMI", is_deleted=False))
        s.execute(m.ctm_scan_entity_supporting_system.__table__.insert().values(
            ctm_scan_entity_id=asset_id, onboarding_supporting_system_id=subsystem_id))
        s.commit()


def test_create_session_over_real_http(client, monkeypatch):
    """POST /v1/sessions — the actual generation entry point, previously untested at any level.
    enqueue_pipeline is monkeypatched to a no-op (the documented seam: "indirection so tests
    can run synchronously instead of via a broker") so this proves the HTTP-facing behavior —
    request validation, ownership/capacity checks, the Scenario_Session row, response shape —
    without needing a Celery worker or a FakeLLM for the whole generation pipeline."""
    from app.api import sessions as sessions_mod
    from app.db.engine import db_session

    asset_id, subsystem_id = 501, 601
    _seed_asset_and_subsystem(asset_id, subsystem_id)

    calls = []
    monkeypatch.setattr(sessions_mod, "enqueue_pipeline", lambda sid: calls.append(sid))

    r = client.post("/v1/sessions", json={
        "asset_id": asset_id, "entity_id": ENTITY, "supporting_system_id": [subsystem_id]})
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["user_id"] == USER
    sid = body["session_id"]

    assert calls == [sid], "enqueue_pipeline must be called exactly once, with the new session id"
    with db_session() as s:
        row = s.execute(m.Scenario_Session.__table__.select()
                        .where(m.Scenario_Session.SessionID == sid)).mappings().first()
    assert row is not None
    assert row["AssetName"] == "E2E Demo Pumping Station"
    assert row["EntityID"] == ENTITY


def test_cancel_session_over_real_http(client):
    """POST /v1/sessions/{id}/cancel — previously untested at any level. Cancels an
    in-progress (SessionStatus.active) session — cancel_session's CAS fence only permits
    that status; a session already at the REVIEW barrier (SessionStatus.completed, per
    _seed_reviewable_session) is correctly NOT cancellable here, so this seeds its own
    minimal active session rather than reusing that helper. Confirms the status flip +
    audit row, and that a second cancel 409s (CAS-fenced, not a silent re-flip)."""
    from app.db.engine import db_session

    sid = str(uuid.uuid4())
    with db_session() as s:
        s.execute(m.Scenario_Session.__table__.insert().values(
            SessionID=sid, TenantID=TENANT, EntityID=ENTITY, UserID=USER, AssetID=9,
            AssetName="E2E Demo In-Progress", SessionStatus=SessionStatus.active,
            CurrentStage=WorkflowStage.THREAT_IDENTIFICATION, StageStatus=StageStatus.IDLE,
            Mode="AUTO", CurrentSubsystemIndex=0, SubsystemsJSON="[]",
            CreatedAt=_now(), UpdatedAt=_now()))
        s.commit()

    r = client.post(f"/v1/sessions/{sid}/cancel")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["session_id"] == sid
    assert body["status"] == str(SessionStatus.cancelled)

    with db_session() as s:
        row = s.execute(m.Scenario_Session.__table__.select()
                        .where(m.Scenario_Session.SessionID == sid)).mappings().first()
        audit = s.execute(m.Scenario_Audit.__table__.select()
                        .where(m.Scenario_Audit.SessionID == sid)).mappings().first()
    assert row["SessionStatus"] == SessionStatus.cancelled
    assert audit is not None and audit["EventType"] == "session_cancelled"

    r2 = client.post(f"/v1/sessions/{sid}/cancel")
    assert r2.status_code == 409, r2.text


def test_next_set_over_real_http(client, monkeypatch):
    """POST /v1/sessions/{id}/scenarios/next-set — previously untested at any level.
    enqueue_next_set monkeypatched to a no-op, same seam/reasoning as session creation above."""
    from app.api import sessions as sessions_mod

    sid, _oid, _tid = _seed_reviewable_session(client)
    calls = []
    monkeypatch.setattr(sessions_mod, "enqueue_next_set",
                        lambda session_id, subsystem_id, epoch, threats_epoch:
                        calls.append((session_id, subsystem_id, epoch, threats_epoch)))

    r = client.post(f"/v1/sessions/{sid}/scenarios/next-set")
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["session_id"] == sid
    assert len(calls) == 1 and calls[0][0] == sid


def test_regenerate_over_real_http(client, monkeypatch):
    """POST /v1/sessions/{id}/regenerate/scenarios — previously untested at any level.
    enqueue_regeneration monkeypatched to a no-op, same seam/reasoning as session creation."""
    from app.api import sessions as sessions_mod

    sid, oid, _tid = _seed_reviewable_session(client)
    calls = []
    monkeypatch.setattr(sessions_mod, "enqueue_regeneration",
                        lambda session_id, subsystem_id, granularity, target_ids, epoch, user_note:
                        calls.append((session_id, target_ids)))

    r = client.post(f"/v1/sessions/{sid}/regenerate/scenarios", json={"scenario_ids": [oid]})
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["session_id"] == sid
    assert len(calls) == 1 and calls[0][0] == sid and calls[0][1] == [oid]
