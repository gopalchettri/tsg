"""Item 4 / verification 3: `generation_epoch` on all three publish sites item 4 touches --
`_record_failure`, `_send_to_review`, `_announce_generation_started` -- not just the first one a
quick check would land on. Item 27 / verification 9 (runtime half): the `error` event's `scope`
field must carry the CORRECT value for each real failure shape -- "stage" for a single-subsystem
stage failure (`_record_failure`), "session" for a total-session failure (`_mark_session_failed`)
-- not just be documented in the schema.

`sess` is a bare `unittest.mock.MagicMock`: every function under test here writes through
`dal.append_audit`/`execute_dml`, both stubbed, so no real DB round trip is needed to observe
what `bus.publish` was handed.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import app.pipeline.tasks as tasks_mod
from app.core.enums import SSEEventType
from app.db import dal
from app.sse import bus


def _capture_publish(monkeypatch) -> list[dict]:
    calls: list[dict] = []
    monkeypatch.setattr(bus, "publish", lambda sid, ev: calls.append(ev))
    return calls


def test_record_failure_publishes_epoch_and_stage_scope(monkeypatch):
    calls = _capture_publish(monkeypatch)
    monkeypatch.setattr(dal, "append_audit", lambda *a, **k: None)
    sess = MagicMock()
    ss = {"SessionID": "s1", "TenantID": "t", "EntityID": "e"}

    tasks_mod._record_failure(sess, ss, subsystem_id=0, exc=RuntimeError("boom"), epoch=7)

    assert len(calls) == 1
    assert calls[0]["generation_epoch"] == 7
    assert calls[0]["scope"] == "stage"
    assert calls[0]["type"] == str(SSEEventType.error)
    assert calls[0]["subsystem_id"] == 0


def test_send_to_review_publishes_epoch(monkeypatch):
    calls = _capture_publish(monkeypatch)
    monkeypatch.setattr(dal, "append_audit", lambda *a, **k: None)
    monkeypatch.setattr(tasks_mod, "execute_dml", lambda sess, stmt: MagicMock(rowcount=1))
    sess = MagicMock()
    ss = {"SessionID": "s2", "TenantID": "t", "EntityID": "e"}

    ok = tasks_mod._send_to_review(sess, ss, epoch=9)

    assert ok is True
    assert len(calls) == 1
    assert calls[0]["generation_epoch"] == 9
    assert calls[0]["type"] == str(SSEEventType.session_entered_review)


def test_send_to_review_publishes_nothing_when_cas_misses(monkeypatch):
    """rowcount != 1 means another writer already moved the session -- must not publish a stale
    'entered review' event for a transition that didn't actually happen here."""
    calls = _capture_publish(monkeypatch)
    monkeypatch.setattr(dal, "append_audit", lambda *a, **k: None)
    monkeypatch.setattr(tasks_mod, "execute_dml", lambda sess, stmt: MagicMock(rowcount=0))
    sess = MagicMock()
    ss = {"SessionID": "s2b", "TenantID": "t", "EntityID": "e"}

    ok = tasks_mod._send_to_review(sess, ss, epoch=9)

    assert ok is False
    assert calls == []


def test_announce_generation_started_publishes_epoch(monkeypatch):
    calls = _capture_publish(monkeypatch)
    monkeypatch.setattr(dal, "append_audit", lambda *a, **k: None)
    monkeypatch.setattr(dal, "subsystem_has_pending_work", lambda *a, **k: True)
    sess = MagicMock()
    ss = {"SessionID": "s3", "TenantID": "t", "EntityID": "e"}

    tasks_mod._announce_generation_started(sess, ss, subsystem_id=0, epoch=3)

    assert len(calls) == 1
    assert calls[0]["generation_epoch"] == 3
    assert calls[0]["type"] == str(SSEEventType.subsystem_started)


def test_announce_generation_started_publishes_nothing_without_pending_work(monkeypatch):
    """A redelivery of already-finished work must not re-announce it."""
    calls = _capture_publish(monkeypatch)
    monkeypatch.setattr(dal, "subsystem_has_pending_work", lambda *a, **k: False)
    sess = MagicMock()
    ss = {"SessionID": "s3b", "TenantID": "t", "EntityID": "e"}

    tasks_mod._announce_generation_started(sess, ss, subsystem_id=0, epoch=3)

    assert calls == []


def test_mark_session_failed_publishes_session_scope(monkeypatch):
    """Verification 9's other half: a TOTAL session failure carries scope='session', not
    'stage' -- the two real shapes of the dual-scope `error` event, both checked here."""
    calls = _capture_publish(monkeypatch)
    monkeypatch.setattr(dal, "append_audit", lambda *a, **k: None)
    monkeypatch.setattr(tasks_mod, "execute_dml", lambda sess, stmt: MagicMock(rowcount=1))
    sess = MagicMock()
    ss = {"SessionID": "s4", "TenantID": "t", "EntityID": "e"}

    ok = tasks_mod._mark_session_failed(sess, ss)

    assert ok is True
    assert len(calls) == 1
    assert calls[0]["scope"] == "session"
    assert calls[0]["type"] == str(SSEEventType.error)
    assert "subsystem_id" not in calls[0]  # session-scoped: no single subsystem to attribute it to


if __name__ == "__main__":
    print("run via pytest")
