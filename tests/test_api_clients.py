"""Admin key-management API (app/api/api_clients.py) — create / list / revoke.

SQLite stands in for the real DB; the router's `db_session` is monkeypatched to it. The gate
(`require_admin`) is a router-level FastAPI dependency, so calling the endpoint functions
directly (as here) exercises the handler logic without the HTTP layer.
"""
from __future__ import annotations

import hashlib
from contextlib import contextmanager

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api import api_clients
from app.api.schemas import CreateApiClientBody
from app.db import dal
from app.db import models as m


@pytest.fixture
def Sess():
    eng = create_engine("sqlite://")
    m.API_Client.__table__.create(eng)
    return sessionmaker(bind=eng, future=True)


@pytest.fixture
def wire(Sess, monkeypatch):
    @contextmanager
    def fake_session():
        s = Sess()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()
    monkeypatch.setattr(api_clients, "db_session", fake_session)
    return Sess


# --- DAL: the storage contract ---

def test_create_stores_only_hash_and_authenticates(Sess):
    kh = hashlib.sha256(b"secretX").hexdigest()
    with Sess() as s:
        dal.create_api_client(s, "cid", "Name", "tsg", kh, "admin1")
        s.commit()
    with Sess() as s:
        # the secret authenticates for its module; the row carries the hash, never the secret
        assert dal.api_client_id_for_key_hash(s, kh, "tsg") == "cid"
        rows = dal.list_api_clients(s)
        assert rows[0]["client_id"] == "cid"
        assert "key_hash" not in rows[0] and "KeyHash" not in rows[0]   # list never leaks the hash
        assert rows[0]["created_by"] == "admin1"


def test_revoke_disables_key_and_is_idempotent(Sess):
    kh = hashlib.sha256(b"secretY").hexdigest()
    with Sess() as s:
        dal.create_api_client(s, "cid2", "N", "tsg", kh, "admin1")
        s.commit()
    with Sess() as s:
        assert dal.revoke_api_client(s, "cid2", "admin2") is True
        s.commit()
    with Sess() as s:
        assert dal.api_client_id_for_key_hash(s, kh, "tsg") is None     # revoked -> no auth
        assert dal.revoke_api_client(s, "cid2", "admin2") is False      # already inactive
        assert dal.revoke_api_client(s, "nope", "admin2") is False      # unknown


# --- Router: create returns the secret once; duplicate -> 409; revoke unknown -> 404 ---

def test_router_create_returns_secret_and_authenticates(wire):
    Sess = wire
    body = CreateApiClientBody(client_id="cidR", name="Shield chatbot", module="chatbot")
    resp = api_clients.create_api_client(body, x_user_id="admin1")
    assert resp.client_id == "cidR" and resp.module == "chatbot"
    assert len(resp.secret) == 64                                       # 32 bytes hex
    with Sess() as s:
        kh = hashlib.sha256(resp.secret.encode()).hexdigest()
        assert dal.api_client_id_for_key_hash(s, kh, "chatbot") == "cidR"   # the returned secret works
        assert dal.api_client_id_for_key_hash(s, kh, "tsg") is None         # ...only for its module


def test_router_create_duplicate_is_409(wire):
    body = CreateApiClientBody(client_id="dupe", name="N", module="tsg")
    api_clients.create_api_client(body, x_user_id="admin1")
    with pytest.raises(HTTPException) as e:
        api_clients.create_api_client(body, x_user_id="admin1")
    assert e.value.status_code == 409


def test_router_revoke_unknown_is_404(wire):
    with pytest.raises(HTTPException) as e:
        api_clients.revoke_api_client("ghost", x_user_id="admin1")
    assert e.value.status_code == 404


def test_missing_user_id_is_400(wire):
    # X-User-Id is required so CreatedBy/RevokedBy is never null (audit attribution).
    body = CreateApiClientBody(client_id="cidZ", name="N", module="tsg")
    with pytest.raises(HTTPException) as e:
        api_clients.create_api_client(body, x_user_id="")
    assert e.value.status_code == 400
    with pytest.raises(HTTPException) as e:
        api_clients.revoke_api_client("anything", x_user_id="   ")
    assert e.value.status_code == 400
