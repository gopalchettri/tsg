"""Celery task wiring (app/pipeline/celery_app.py) — [REVIEW-FIX] previously nothing tested
that run_pipeline_task/regenerate_task actually carry autoretry_for=(LLMSlotUnavailable,) or
that Celery genuinely retries on it; a typo'd/omitted decorator would have silently turned
"retries automatically" into "crashes the task," undetected by anything else in the suite."""
from __future__ import annotations

import pytest

from app.pipeline import celery_app
from app.pipeline.llm import LLMSlotUnavailable


def test_init_worker_calls_log_litellm_key_info(monkeypatch):
    # [REVIEW-FIX] log_litellm_key_info was defined and unit-tested in isolation but never
    # actually wired into _init_worker, so the feature never shipped despite looking done —
    # this proves the real worker-boot path calls it, not just that the function works alone.
    monkeypatch.setattr("app.core.config.assert_security_posture", lambda: None)
    monkeypatch.setattr("app.db.invariants.verify_startup", lambda engine: None)
    monkeypatch.setattr("app.pipeline.local_models.validate_local_models", lambda **kw: None)
    monkeypatch.setattr("app.pipeline.llm.verify_litellm_models", lambda: None)
    calls = []
    monkeypatch.setattr("app.pipeline.llm.log_litellm_key_info", lambda: calls.append(1))
    celery_app._init_worker()
    assert calls == [1]


def test_init_worker_rejects_prefork_pool(monkeypatch):
    # The worker_pool="gevent" setting was removed (it tripped Celery's W_POOL_SETTING warning),
    # so a bare `celery worker` now resolves to prefork — which FORKS a process celery_worker.py
    # has already monkey-patched, giving every child a broken hub. That must fail loudly, and
    # -P solo must still be allowed (it never forks; .vscode/launch.json debugs with it).
    monkeypatch.setattr("app.core.config.assert_security_posture", lambda: None)
    monkeypatch.setattr("app.db.invariants.verify_startup", lambda engine: None)
    monkeypatch.setattr("app.pipeline.local_models.validate_local_models", lambda **kw: None)
    monkeypatch.setattr("app.pipeline.llm.verify_litellm_models", lambda: None)
    monkeypatch.setattr("app.pipeline.llm.log_litellm_key_info", lambda: None)

    class _Pool:
        pass

    class _Sender:
        pool_cls = _Pool

    _Pool.__module__ = "celery.concurrency.prefork"
    with pytest.raises(RuntimeError, match="prefork"):
        celery_app._init_worker(sender=_Sender)
    # Deliberately NOT looping over gevent/solo to assert "does not raise": past the guard,
    # _init_worker runs the real boot — verify_litellm_models plus resolve_thresholds(
    # allow_calibration=True), i.e. minutes of billed Azure paraphrase calls per invocation.
    # test_init_worker_calls_log_litellm_key_info above already drives that path once with
    # sender=None, which is the same non-prefork branch this guard permits.


def test_no_green_worker_pool_setting():
    # celery/worker/components.py warns whenever conf.worker_pool is in {eventlet, gevent} —
    # regardless of -P — so the key must stay absent for a clean boot log.
    assert celery_app.celery_app.conf.worker_pool not in {"gevent", "eventlet"}


def test_run_pipeline_task_autoretry_wiring():
    assert LLMSlotUnavailable in celery_app.run_pipeline_task.autoretry_for
    assert celery_app.run_pipeline_task.max_retries is None
    assert celery_app.run_pipeline_task.retry_backoff is True


def test_regenerate_task_autoretry_wiring():
    assert LLMSlotUnavailable in celery_app.regenerate_task.autoretry_for
    assert celery_app.regenerate_task.max_retries is None
    assert celery_app.regenerate_task.retry_backoff is True


def test_admin_embedding_action_task_autoretry_wiring():
    assert LLMSlotUnavailable in celery_app.admin_embedding_action_task.autoretry_for
    assert celery_app.admin_embedding_action_task.max_retries is None
    assert celery_app.admin_embedding_action_task.retry_backoff is True


def test_admin_embedding_action_task_actually_retries_on_llm_slot_unavailable(monkeypatch):
    calls = {"n": 0}

    def flaky(sess, llm, g):
        calls["n"] += 1
        if calls["n"] == 1:
            raise LLMSlotUnavailable("no free slot")
        return 3  # second attempt succeeds

    monkeypatch.setattr(celery_app.embeddings, "update_group", flaky)
    celery_app.celery_app.conf.task_always_eager = True
    try:
        result = celery_app.admin_embedding_action_task.apply(
            args=["update", "threat_type", None], throw=False)
    finally:
        celery_app.celery_app.conf.task_always_eager = False
    assert result.successful()
    assert result.result == {"rows_processed": {"threat_type": 3}}
    assert calls["n"] == 2  # crashed once (LLMSlotUnavailable), Celery retried, second succeeded


def test_admin_embedding_action_task_create_requires_group_and_names():
    """[REVIEW-FIX] app/api/admin.py's create route already rejects a missing group/names
    before ever enqueueing — but this task is reachable outside that one HTTP route (Flower,
    tests, a future caller). Without its own guard, create_items(sess, llm, group, names)
    crashes on len(None) instead of failing with a clear error. Calls the task directly
    (bypassing the API layer entirely) to prove the guard lives on the task itself, not just
    at its one current caller."""
    celery_app.celery_app.conf.task_always_eager = True
    try:
        result = celery_app.admin_embedding_action_task.apply(
            args=["create", None, None], throw=False)
    finally:
        celery_app.celery_app.conf.task_always_eager = False
    assert result.failed()
    assert isinstance(result.result, ValueError)
    assert "create requires" in str(result.result)


def test_run_pipeline_task_actually_retries_on_llm_slot_unavailable(monkeypatch, engine):
    """Directly exercises Celery's own retry mechanism (not just the decorator's presence):
    eager .apply() with throw=False actually performs the retry loop in-process (confirmed
    empirically — max_retries=None means it keeps retrying, so the stub below must
    eventually succeed or this would loop forever). The task must be RE-INVOKED on
    LLMSlotUnavailable, not crash — proving the decorator wiring genuinely works, not just
    that it's present."""
    calls = {"n": 0}

    def flaky(sess, session_id, llm, task_id):
        calls["n"] += 1
        if calls["n"] == 1:
            raise LLMSlotUnavailable("no free slot")
        return None  # second attempt succeeds

    monkeypatch.setattr(celery_app, "_process_all_supporting_systems", flaky)
    celery_app.celery_app.conf.task_always_eager = True
    try:
        result = celery_app.run_pipeline_task.apply(args=["dummy-session-id"], throw=False)
    finally:
        celery_app.celery_app.conf.task_always_eager = False
    assert result.successful()
    assert calls["n"] == 2  # crashed once (LLMSlotUnavailable), Celery retried, second attempt succeeded
