"""Admission control (SDD §12, [R9]) — a soft backpressure ceiling on concurrent
active sessions, and Idempotency-Key dedup on session creation.
"""
from __future__ import annotations

import pytest
from sqlalchemy import inspect

from app.core.config import get_settings
from app.db import dal
from tests.conftest import make_client, session_body
from tests.test_slice import _seed_session


def test_backpressure_503_at_ceiling(db, monkeypatch):
    monkeypatch.setattr(get_settings(), "max_active_sessions", 1)
    _seed_session(db, asset_id=100)
    with pytest.raises(dal.CapacityExceeded):
        dal.assert_capacity_available(db)


def test_backpressure_allows_under_ceiling(db):
    _seed_session(db, asset_id=100)
    dal.assert_capacity_available(db)  # default ceiling (100) — no raise


def test_idempotency_key_returns_same_session(engine, monkeypatch):
    monkeypatch.setattr("app.api.sessions.enqueue_pipeline", lambda sid: None)
    client = make_client({"5"})
    headers = {"Idempotency-Key": "k1"}
    r1 = client.post("/v1/sessions", json=session_body(100), headers=headers)
    r2 = client.post("/v1/sessions", json=session_body(100), headers=headers)
    assert r1.json()["session_id"] == r2.json()["session_id"]
    assert r2.status_code == 200


def test_idempotency_key_conflict_different_body(engine, monkeypatch):
    monkeypatch.setattr("app.api.sessions.enqueue_pipeline", lambda sid: None)
    client = make_client({"5"})
    headers = {"Idempotency-Key": "k2"}
    client.post("/v1/sessions", json=session_body(100), headers=headers)
    r2 = client.post("/v1/sessions", json=session_body(200), headers=headers)
    assert r2.status_code == 409
    assert r2.json()["error_code"] == "idempotency_key_conflict"


def test_idempotency_key_migration_index_exists(engine):
    idx_names = {ix["name"] for ix in inspect(engine).get_indexes("Scenario_Session")}
    assert "UX_Session_IdempotencyKey" in idx_names


def test_create_session_race_distinguishes_idempotency_from_asset_conflict(db):
    """Simulates the race window reserve_idempotency_key_or_get_existing's pre-check
    can't see: two create_session calls, same (entity, idempotency_key), DIFFERENT
    asset. The second must raise IdempotencyKeyConflict carrying the real winning
    session id — not SessionConflict(None), which is what an exception handler that
    assumes the M4 asset index always fired (without checking the idempotency-key
    index first) would incorrectly produce, since the two rows don't share an asset."""
    import uuid

    from app.core.enums import SessionMode, SessionStatus, StageStatus, WorkflowStage
    from app.db.dal import now

    base = {
        "TenantID": "default", "UserID": "u1", "EntityID": "5", "SessionStatus": SessionStatus.active,
        "CurrentStage": WorkflowStage.THREAT_IDENTIFICATION, "StageStatus": StageStatus.IDLE, "Mode": SessionMode.AUTO,
        "CurrentSubsystemIndex": 0, "SubsystemsJSON": "[]", "CreatedAt": now(), "UpdatedAt": now(),
        "IdempotencyKey": "shared-key",
    }
    winner_id = str(uuid.uuid4())
    dal.create_session(db, {**base, "SessionID": winner_id, "AssetName": "CAD", "AssetID": "100"})

    with pytest.raises(dal.IdempotencyKeyConflict) as exc_info:
        dal.create_session(db, {**base, "SessionID": str(uuid.uuid4()), "AssetName": "EPCR", "AssetID": "200"})
    assert exc_info.value.existing_session_id == winner_id
