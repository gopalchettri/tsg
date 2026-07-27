"""Threat-library import — shared core (app/pipeline/threat_library_import.py),
dal.upsert_threat_rule, and the admin API (app/api/threat_library_import.py).

Covers the review-found invariants specifically: validation failures are
ThreatLibraryImportError (never SystemExit — a Celery worker-killer), dry-run writes
nothing, real runs are idempotent under rerun/redelivery (natural-key upserts + the
0027 unique index), auto-written rules are boost-only relevance_flag rows visible in
the result's ot_rules, the embeddings follow-up is dispatched only AFTER the import's
own transaction committed, and the two admin job families cannot poll each other."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.core.config import get_settings
from app.db import dal
from app.db import models as m
from app.pipeline.threat_library_import import ThreatLibraryImportError, run_import

_KEY = "test-admin-key-123"

# One ICS technique whose only tactic maps to [Tampering] — the single STRIDE category
# the conftest seed provides — so import_records never trips the missing-category guard.
_ICS_BUNDLE = {
    "objects": [{
        "type": "attack-pattern",
        "name": "Modify Parameter",
        "description": "Adversaries may modify parameters on a controller.",
        "external_references": [{"source_name": "mitre-attack", "external_id": "T0836"}],
        "kill_chain_phases": [{"kill_chain_name": "mitre-ics-attack",
                               "phase_name": "impair-process-control"}],
    }]
}
_PYTM_TAMPER = [{"SID": "INP01", "description": "Buffer overflow via crafted input", "details": "d"}]


def _count(sess, table):
    return sess.execute(select(func.count()).select_from(table)).scalar()


# ---------------------------------------------------------------- shared core
def test_run_import_dry_run_writes_nothing(db):
    types_before = _count(db, m.Threat_Type)
    rules_before = _count(db, m.Config_Threat_Rule)
    result = run_import(db, "attack_ics", file_content=json.dumps(_ICS_BUNDLE), dry_run=True)
    assert result["dry_run"] is True
    assert result["types"] == 1 and result["threats"] == 1
    assert result["new_category_links"] is None  # unknowable without writing
    assert result["after_count"] == result["before_count"]
    assert result["ot_rules"] == [{"threat_type_id": None, "rule_key": "asset_type",
                                   "threat_type_name": "ICS ATT&CK – Impair Process Control"}]
    assert _count(db, m.Threat_Type) == types_before
    assert _count(db, m.Config_Threat_Rule) == rules_before


def test_run_import_real_run_writes_and_reruns_idempotently(db):
    r1 = run_import(db, "attack_ics", file_content=json.dumps(_ICS_BUNDLE))
    db.commit()
    assert r1["threats"] == 1 and r1["after_count"] == r1["before_count"] + 1
    [rule1] = r1["ot_rules"]
    assert rule1["threat_type_id"] is not None and "threat_rule_id" in rule1
    row = db.execute(select(m.Config_Threat_Rule).where(
        m.Config_Threat_Rule.ThreatRuleID == rule1["threat_rule_id"])).scalar_one()
    assert row.RuleType == "relevance_flag"  # BOOST-ONLY by design — never tech_gate
    assert row.RuleValue == "OT" and row.CreatedBy == "auto:mitre_attack_ics"
    assert json.loads(row.Metadata) == {"weight": 10.0}

    # Rerun (same as a Celery crash-redelivery): every write is a natural-key upsert,
    # so nothing duplicates — critically not the rule row, whose duplication would
    # silently DOUBLE the score boost (scoping sums fired weights).
    rules_after_first = _count(db, m.Config_Threat_Rule)
    r2 = run_import(db, "attack_ics", file_content=json.dumps(_ICS_BUNDLE))
    assert r2["after_count"] == r1["after_count"]
    assert r2["ot_rules"][0]["threat_rule_id"] == rule1["threat_rule_id"]
    assert _count(db, m.Config_Threat_Rule) == rules_after_first


def test_run_import_validation_failures_raise_import_error_never_systemexit(db):
    with pytest.raises(ThreatLibraryImportError, match="via_taxii is only supported"):
        run_import(db, "pytm", via_taxii=True)
    with pytest.raises(ThreatLibraryImportError, match="not both"):
        run_import(db, "attack", file_content="{}", via_taxii=True)
    with pytest.raises(ThreatLibraryImportError, match="unknown source"):
        run_import(db, "nope")
    with pytest.raises(ThreatLibraryImportError, match="not valid JSON"):
        run_import(db, "pytm", file_content="{nope")
    # Wrong shape for the source (a STIX bundle uploaded as pytm) — clean 422-class
    # error, not an AttributeError from deep inside the adapter.
    with pytest.raises(ThreatLibraryImportError, match="does not match the 'pytm' format"):
        run_import(db, "pytm", file_content='{"objects": []}')
    # Unseeded STRIDE category (conftest seeds only Tampering; DO -> Denial of Service).
    with pytest.raises(ThreatLibraryImportError, match="STRIDE categories missing"):
        run_import(db, "pytm", file_content=json.dumps([{"SID": "DO01", "description": "flood"}]))


def test_run_import_zero_usable_records_warns_instead_of_reading_like_success(db):
    result = run_import(db, "pytm", file_content=json.dumps([{"SID": "ZZ99", "description": "x"}]))
    assert result["threats"] == 0 and result["skipped_count"] == 1
    assert "0 usable threats" in result["warning"]


def test_run_import_misp_actors_shape(db):
    data = {"values": [{"value": "APT Test", "meta": {"sectors": ["critical infrastructure"]}}]}
    result = run_import(db, "misp_actors", file_content=json.dumps(data))
    assert result["actors_upserted"] == 1
    assert "types" not in result and "ot_rules" not in result
    assert db.execute(select(m.Threat_Actor.ThreatActorID).where(
        m.Threat_Actor.ThreatActorName == "APT Test")).scalar() is not None


# ---------------------------------------------------------------- DAL primitive
def test_upsert_threat_rule_idempotent_on_duplicate_natural_key(db):
    a = dal.upsert_threat_rule(db, 10, "relevance_flag", "asset_type", "OT", 10.0, "auto:test")
    db.commit()
    assert dal.upsert_threat_rule(db, 10, "relevance_flag", "asset_type", "OT", 10.0, "auto:test") == a
    assert db.execute(select(func.count()).select_from(m.Config_Threat_Rule).where(
        m.Config_Threat_Rule.ThreatTypeID == 10)).scalar() == 1
    # A genuinely different natural key is a new row, not a collision.
    b = dal.upsert_threat_rule(db, 10, "relevance_flag", "asset_type", "IT", 10.0, "auto:test")
    assert b != a


# ---------------------------------------------------------------- admin API
@pytest.fixture()
def import_client(engine, monkeypatch):
    monkeypatch.setattr(get_settings(), "admin_api_key", _KEY)
    from app.api import admin_jobs
    from app.api.deps import Principal, get_principal
    from app.main import create_app
    from app.pipeline import celery_app as celery_module
    from app.pipeline import embeddings
    from tests.test_admin_embeddings_api import _FakeJobRedis

    app = create_app()
    app.dependency_overrides[get_principal] = lambda: Principal(claims={"sub": "u1"}, entities=set())
    fake = _FakeJobRedis()
    monkeypatch.setattr(admin_jobs, "_slot_redis", lambda: fake)
    # The eager-run embeddings follow-up must not hit a real LLM. The fake update_group
    # counts Threat_Type rows through ITS OWN session — proving the follow-up job's
    # fresh transaction sees the import's rows, i.e. dispatch happened AFTER commit
    # (the transaction-boundary regression this feature's review caught).
    seen_type_counts: list[int] = []

    def _fake_update_group(sess, llm, group):
        seen_type_counts.append(_count(sess, m.Threat_Type))
        return 0

    monkeypatch.setattr(celery_module, "get_llm", lambda: None)
    monkeypatch.setattr(embeddings, "update_group", _fake_update_group)
    celery_module.celery_app.conf.task_always_eager = True
    celery_module.celery_app.conf.task_store_eager_result = True
    client = TestClient(app)
    client._seen_type_counts = seen_type_counts  # exposed for the follow-up test
    try:
        yield client
    finally:
        celery_module.celery_app.conf.task_always_eager = False
        celery_module.celery_app.conf.task_store_eager_result = False


def _post_import(client, body, key=_KEY):
    """The source is the addressed RESOURCE now, so it comes out of the body and into the
    path — tests keep passing it in `body` for readability and it is lifted here."""
    headers = {"X-Admin-Key": key} if key is not None else {}
    body = dict(body)
    source = body.pop("source", "attack_ics")
    return client.post(f"/v1/tsg/threat-library/sources/{source}/import", json=body, headers=headers)


def _import_status(client, job_id):
    return client.get(f"/v1/tsg/threat-library/imports/{job_id}", headers={"X-Admin-Key": _KEY})


def test_api_dry_run_happy_path(import_client):
    r = _post_import(import_client, {"source": "attack_ics", "dry_run": True,
                                     "file_content": json.dumps(_ICS_BUNDLE)})
    assert r.status_code == 202
    status = _import_status(import_client, r.json()["job_id"]).json()
    assert status["state"] == "SUCCESS"
    assert status["result"]["dry_run"] is True and len(status["result"]["ot_rules"]) == 1
    assert "embeddings_job_id" not in status["result"]  # nothing to refresh on a preview


def test_api_real_run_reports_rules_and_pollable_embeddings_job(import_client):
    r = _post_import(import_client, {"source": "attack_ics", "file_content": json.dumps(_ICS_BUNDLE)})
    assert r.status_code == 202
    result = _import_status(import_client, r.json()["job_id"]).json()["result"]
    assert result["ot_rules"][0]["threat_rule_id"] is not None
    # The follow-up embeddings job id must be pollable on ITS OWN family's status route
    # (the worker-side mark_admin_job call — without it this GET would 404).
    emb = import_client.get(f"/v1/tsg/threat-library/embeddings/status/{result['embeddings_job_id']}",
                            headers={"X-Admin-Key": _KEY})
    assert emb.status_code == 200
    # And its update_group ran against a session that already saw the imported type —
    # dispatch strictly after the import's commit.
    assert import_client._seen_type_counts and all(n >= 3 for n in import_client._seen_type_counts)


def test_api_validation_matrix(import_client, monkeypatch):
    def code(body):
        return _post_import(import_client, body).status_code

    assert code({"source": "nope"}) == 404  # unknown source = missing RESOURCE, not a bad body field
    assert code({"source": "attack", "file_content": "{}", "via_taxii": True}) == 422
    assert code({"source": "pytm", "via_taxii": True}) == 422
    assert code({"source": "pytm", "file_content": "{nope"}) == 422
    assert code({"source": "pytm", "file_content": '{"objects": []}'}) == 422  # wrong shape for source
    monkeypatch.setattr(get_settings(), "threat_library_import_max_upload_mb", 1)
    # [REVIEW-FIX] 413, not 422, and from BodySizeLimitMiddleware rather than _validate: the
    # handler's own cap only ran after FastAPI had already buffered and json-parsed the whole
    # body on the event loop — work that happens before dependencies resolve, so before
    # require_admin. An unauthenticated caller could make the server parse an arbitrarily large
    # document. The guard now sits in front of the body read; 413 is the correct status for it.
    assert code({"source": "pytm", "file_content": "a" * (1024 * 1024 + 16)}) == 413


def test_api_families_cannot_poll_each_other(import_client, monkeypatch):
    from app.pipeline import embeddings
    monkeypatch.setattr(embeddings, "update_group", lambda sess, llm, g: 0)

    import_job = _post_import(import_client, {"source": "attack_ics", "dry_run": True,
                                              "file_content": json.dumps(_ICS_BUNDLE)}).json()["job_id"]
    emb_job = import_client.post("/v1/tsg/threat-library/embeddings/update", json={},
                                 headers={"X-Admin-Key": _KEY}).json()["job_id"]
    # Cross-family polls must 404 — family-scoped markers are the authorization boundary.
    assert import_client.get(f"/v1/tsg/threat-library/embeddings/status/{import_job}",
                             headers={"X-Admin-Key": _KEY}).status_code == 404
    assert _import_status(import_client, emb_job).status_code == 404


def test_api_requires_admin_key(import_client):
    assert _post_import(import_client, {"source": "pytm"}, key=None).status_code == 401
