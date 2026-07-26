"""Admin API for threat-library embedding maintenance (app/api/admin.py) — gated by a static
X-Admin-Key header AND a valid JWT (app.api.deps.require_admin / get_principal). Each action
dispatches app.pipeline.celery_app.admin_embedding_action_task and returns 202 + a job_id;
the eventual result is polled via GET .../status/{job_id}, same dispatch-then-poll shape as
run_pipeline_task/regenerate_task."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings

_KEY = "test-admin-key-123"


class _FakeJobRedis:
    """In-memory stand-in for the setex/exists primitives _enqueue/get_status need for the
    provenance marker (real Redis is reachable in this dev environment, but the suite
    shouldn't depend on that — mirrors test_embeddings.py's _FakeLockRedis)."""
    def __init__(self):
        self.store: dict[str, str] = {}

    def setex(self, key, ttl, value):
        self.store[key] = value

    def exists(self, key):
        return key in self.store


@pytest.fixture()
def admin_client(monkeypatch):
    monkeypatch.setattr(get_settings(), "admin_api_key", _KEY)
    from app.api import admin_jobs
    from app.api.deps import Principal, get_principal
    from app.main import create_app
    from app.pipeline.celery_app import celery_app

    app = create_app()
    # Admin routes now ALSO require a valid JWT (app.api.deps.get_principal, same mechanism
    # every other endpoint uses) purely to attribute the audit log to a real user_id — override
    # it here exactly like conftest.make_client does for every other authenticated route.
    app.dependency_overrides[get_principal] = lambda: Principal(claims={"sub": "u1"}, entities=set())
    # ONE shared fake instance: the marker write and get_status's later check must see the
    # same store. Patched in admin_jobs (the markers' home since the import-API refactor).
    _fake_job_redis = _FakeJobRedis()
    monkeypatch.setattr(admin_jobs, "_slot_redis", lambda: _fake_job_redis)
    # Runs each queued task in-process instead of via a real broker — same eager-mode pattern
    # test_celery_app.py already uses for run_pipeline_task/regenerate_task.
    # task_store_eager_result=True is required too: eager mode alone keeps the result only on
    # the in-memory EagerResult object, never writing it to the backend, so a SEPARATE
    # AsyncResult(job_id) lookup (exactly what GET .../status/{job_id} does) would otherwise
    # find nothing.
    celery_app.conf.task_always_eager = True
    celery_app.conf.task_store_eager_result = True
    try:
        yield TestClient(app)
    finally:
        celery_app.conf.task_always_eager = False
        celery_app.conf.task_store_eager_result = False


def _post(client, action, body, key=_KEY):
    headers = {"X-Admin-Key": key} if key is not None else {}
    return client.post(f"/v1/tsg/threat-library/embeddings/{action}", json=body, headers=headers)


def _status(client, job_id, key=_KEY):
    headers = {"X-Admin-Key": key} if key is not None else {}
    return client.get(f"/v1/tsg/threat-library/embeddings/status/{job_id}", headers=headers)


def _run(client, action, body, key=_KEY):
    """POST (queue) then immediately GET status — under task_always_eager the task has already
    finished by the time .delay() returns, so the very next poll sees its final state."""
    r = _post(client, action, body, key=key)
    assert r.status_code == 202
    job_id = r.json()["job_id"]
    return _status(client, job_id, key=key)


# --- auth ---
def test_401_without_key(admin_client):
    assert _post(admin_client, "update", {}, key=None).status_code == 401


def test_401_with_wrong_key(admin_client):
    assert _post(admin_client, "update", {}, key="wrong").status_code == 401


def test_401_when_admin_api_key_unconfigured(monkeypatch):
    monkeypatch.setattr(get_settings(), "admin_api_key", "")
    from app.api.deps import Principal, get_principal
    from app.main import create_app

    app = create_app()
    app.dependency_overrides[get_principal] = lambda: Principal(claims={"sub": "u1"}, entities=set())
    client = TestClient(app)
    assert _post(client, "update", {}, key="").status_code == 401  # empty key must never match empty config


def test_401_without_jwt_even_with_a_valid_admin_key(monkeypatch):
    # The static key alone is no longer sufficient — get_principal's JWT validation (required
    # for audit-trail identity) is a SEPARATE, additional gate. auth_dev_mode is forced off
    # (this dev environment's own .env otherwise bypasses JWT entirely) so the request actually
    # exercises the real "no Authorization header" -> AuthError path, not the dev bypass.
    monkeypatch.setattr(get_settings(), "admin_api_key", _KEY)
    monkeypatch.setattr(get_settings(), "auth_dev_mode", False)
    from app.main import create_app

    client = TestClient(create_app())
    assert _post(client, "update", {}).status_code == 401


def test_status_requires_admin_key_too(admin_client):
    assert _status(admin_client, "whatever-job-id", key="wrong").status_code == 401


# --- queue contract ---
def test_valid_action_returns_202_and_a_job_id(admin_client, monkeypatch):
    from app.pipeline import embeddings

    monkeypatch.setattr(embeddings, "update_group", lambda sess, llm, g: 1)
    r = _post(admin_client, "update", {})
    assert r.status_code == 202
    assert r.json()["job_id"]  # non-empty


def test_status_404s_for_an_id_this_router_never_queued(admin_client):
    # [REVIEW-FIX] run_pipeline_task/regenerate_task/reap_task/self_check_task share the same
    # Celery app/result backend as admin_embedding_action_task — without a provenance check,
    # AsyncResult(job_id) would happily report on ANY of their ids too. A garbage id (or any id
    # this router never wrote a tsg:admin:job: marker for) must 404, not report Celery's own
    # generic "PENDING" (which would otherwise mask the fact that nothing was ever verified).
    r = _status(admin_client, "no-such-job-id-at-all")
    assert r.status_code == 404


def test_status_404s_even_when_the_foreign_task_id_has_a_real_celery_result(admin_client, monkeypatch):
    # Stronger version of the test above: prove the provenance check runs BEFORE the
    # AsyncResult lookup even when that id genuinely resolves to something in Celery's own
    # backend (simulating a real run_pipeline_task/reap_task id an admin caller learned about
    # from elsewhere, e.g. logs or Subsystem_Stage_State.ActiveTaskID) — it must still 404,
    # never leak that other task's state/result.
    from app.pipeline.celery_app import celery_app

    other_task_id = "foreign-task-id-belongs-to-reap-task"
    # Write a real Celery result under this id directly, bypassing admin_embedding_action_task
    # entirely (as reap_task itself would), to prove the check isn't accidentally keyed off
    # "does AsyncResult find something" — it must 404 regardless of what Celery itself knows.
    celery_app.backend.store_result(other_task_id, ["session-1", "session-2"], "SUCCESS")
    r = _status(admin_client, other_task_id)
    assert r.status_code == 404


# --- audit trail ordering ---
def test_audit_log_fires_only_after_a_successful_enqueue(admin_client, monkeypatch):
    # [REVIEW-FIX] _audit used to fire BEFORE _enqueue — a broker failure would leave a
    # permanent "queued" audit record for an action that never actually reached Celery. Now
    # _enqueue runs first; if it raises, _audit must never fire at all.
    from app.api import admin as admin_module
    from app.pipeline.celery_app import admin_embedding_action_task

    logged = []
    monkeypatch.setattr(admin_module.log, "warning", lambda event, **kw: logged.append((event, kw)))

    def boom(*a, **kw):
        raise ConnectionError("broker down")

    monkeypatch.setattr(admin_embedding_action_task, "delay", boom)
    # TestClient's default raise_server_exceptions=True re-raises the underlying exception to
    # the test even though a real deployment would see a normal 500 via errors.py's catch-all
    # handler — the exception itself is what proves it wasn't masked by a premature audit log.
    with pytest.raises(ConnectionError):
        _post(admin_client, "update", {"group": "threat_type"})
    assert logged == []  # never claimed the action was queued when it in fact never was


def test_audit_log_includes_the_job_id_for_correlation(admin_client, monkeypatch):
    from app.pipeline import embeddings

    monkeypatch.setattr(embeddings, "update_group", lambda sess, llm, g: 1)
    captured = {}
    from app.api import admin as admin_module

    monkeypatch.setattr(admin_module.log, "warning", lambda event, **kw: captured.update(kw))
    r = _post(admin_client, "update", {"group": "threat_type"})
    assert captured["job_id"] == r.json()["job_id"]


# --- dispatch mechanism ---
def test_update_dispatches_via_delay_not_a_synchronous_call(admin_client, monkeypatch):
    # [REVIEW-FIX] Under task_always_eager, .delay() and .apply() are behaviorally identical,
    # so nothing else in this file would catch a regression that silently swapped the async
    # .delay() dispatch for an inline/synchronous call (defeating the whole point of this
    # architecture — an HTTP request no longer blocking on LLM/DB work). This test patches
    # .delay() itself and asserts it — specifically, not some other entry point — was called.
    from app.pipeline import embeddings
    from app.pipeline.celery_app import admin_embedding_action_task

    monkeypatch.setattr(embeddings, "update_group", lambda sess, llm, g: 1)
    calls = []
    original_delay = admin_embedding_action_task.delay

    def spy_delay(*a, **kw):
        calls.append((a, kw))
        return original_delay(*a, **kw)

    monkeypatch.setattr(admin_embedding_action_task, "delay", spy_delay)
    r = _post(admin_client, "update", {"group": "threat_type"})
    assert r.status_code == 202
    assert calls == [(("update", "threat_type", None), {})]


# --- update ---
def test_update_returns_rows_processed_per_group(admin_client, monkeypatch):
    from app.pipeline import embeddings

    monkeypatch.setattr(embeddings, "update_group",
                        lambda sess, llm, g: {"threat_type": 5, "threat_catalogue": 7, "control_library": 3}[g])
    r = _run(admin_client, "update", {})
    assert r.status_code == 200
    body = r.json()
    assert body["state"] == "SUCCESS"
    assert body["rows_processed"] == {"threat_type": 5, "threat_catalogue": 7, "control_library": 3}
    assert body["vectors_deleted"] is None


def test_update_single_group(admin_client, monkeypatch):
    from app.pipeline import embeddings

    monkeypatch.setattr(embeddings, "update_group", lambda sess, llm, g: 3)
    r = _run(admin_client, "update", {"group": "threat_type"})
    assert r.json()["rows_processed"] == {"threat_type": 3}


def test_update_partial_failure_does_not_sink_other_group(admin_client, monkeypatch):
    from app.pipeline import embeddings

    def flaky(sess, llm, g):
        if g == "threat_type":
            raise RuntimeError("boom")
        return 9

    monkeypatch.setattr(embeddings, "update_group", flaky)
    r = _run(admin_client, "update", {})
    assert r.status_code == 200
    assert r.json()["state"] == "SUCCESS"  # the JOB succeeds overall — one group's own error
    rows = r.json()["rows_processed"]      # string doesn't fail the whole task (_for_each_group)
    assert rows["threat_catalogue"] == 9
    assert rows["threat_type"].startswith("error:")


# --- create ---
def test_create_requires_group_and_names(admin_client):
    assert _post(admin_client, "create", {"group": "threat_type"}).status_code == 422
    assert _post(admin_client, "create", {"names": ["x"]}).status_code == 422


def test_create_embeds_only_the_named_items(admin_client, monkeypatch):
    from app.pipeline import embeddings

    captured = {}

    def fake_create_items(sess, llm, group, names):
        captured.update(group=group, names=names)
        return len(names)

    monkeypatch.setattr(embeddings, "create_items", fake_create_items)
    r = _run(admin_client, "create", {"group": "threat_catalogue", "names": ["Bootloader implant"]})
    assert r.status_code == 200
    assert r.json()["rows_processed"] == {"threat_catalogue": 1}
    assert captured == {"group": "threat_catalogue", "names": ["Bootloader implant"]}


# --- recreate ---
def test_recreate_names_requires_explicit_group(admin_client):
    assert _post(admin_client, "recreate", {"names": ["x"]}).status_code == 422


def test_recreate_passes_names_through_to_the_underlying_function(admin_client, monkeypatch):
    from app.pipeline import embeddings

    captured = {}

    def fake_recreate(sess, llm, group, names=None):
        captured.update(group=group, names=names)
        return 1

    monkeypatch.setattr(embeddings, "recreate_group", fake_recreate)
    r = _run(admin_client, "recreate", {"group": "threat_type", "names": ["Firmware Tampering"]})
    assert r.status_code == 200
    assert captured == {"group": "threat_type", "names": ["Firmware Tampering"]}


def test_recreate_conflict_surfaces_as_failure_state_on_status_poll(admin_client, monkeypatch):
    # A concurrent recreate already holds this group's lock. Now that the actual work runs
    # inside the Celery task rather than inline in the POST, the conflict can only surface once
    # the caller polls status — state=FAILURE + the EmbeddingBusy message, NOT an HTTP 409 on
    # the original request (that request already returned 202 before the task ever ran).
    from app.pipeline import embeddings

    def busy(sess, llm, group, names=None):
        raise embeddings.EmbeddingBusy(f"group {group!r} is already being recreated/deleted")

    monkeypatch.setattr(embeddings, "recreate_group", busy)
    r = _run(admin_client, "recreate", {"group": "threat_type"})
    assert r.status_code == 200  # the POLL succeeded; the JOB failed
    body = r.json()
    assert body["state"] == "FAILURE"
    assert "already being recreated" in body["error"]


# --- delete ---
def test_delete_requires_group_or_names(admin_client):
    assert _post(admin_client, "delete", {}).status_code == 422


def test_delete_names_requires_explicit_group(admin_client):
    assert _post(admin_client, "delete", {"names": ["x"]}).status_code == 422


def test_delete_reports_vectors_deleted_not_rows_processed(admin_client, monkeypatch):
    from app.pipeline import embeddings

    monkeypatch.setattr(embeddings, "delete_group", lambda sess, g, names=None: 4)
    r = _run(admin_client, "delete", {"group": "threat_type"})
    assert r.status_code == 200
    body = r.json()
    assert body["vectors_deleted"] == {"threat_type": 4}
    assert body["rows_processed"] is None


def test_delete_scopes_to_names_when_given(admin_client, monkeypatch):
    from app.pipeline import embeddings

    captured = {}

    def fake_delete(sess, group, names=None):
        captured.update(group=group, names=names)
        return 1

    monkeypatch.setattr(embeddings, "delete_group", fake_delete)
    r = _run(admin_client, "delete", {"group": "threat_catalogue", "names": ["Bootloader implant"]})
    assert r.status_code == 200
    assert captured == {"group": "threat_catalogue", "names": ["Bootloader implant"]}


# --- audit trail identity ---
def test_audit_log_records_the_jwt_callers_user_id(admin_client, monkeypatch):
    from app.api import admin as admin_module
    from app.pipeline import embeddings

    captured = {}

    class _FakeLog:
        def warning(self, event, **kw):
            captured.update(kw)

    monkeypatch.setattr(admin_module, "log", _FakeLog())
    monkeypatch.setattr(embeddings, "update_group", lambda sess, llm, g: 1)
    _post(admin_client, "update", {"group": "threat_type"})
    assert captured["user_id"] == "u1"  # from admin_client's overridden Principal(claims={"sub": "u1"})
