"""Plan Phase 4 (SSE contract/data-model) sanity checks — no DB, no network.

Covers the two places real branching logic changed: (1) the typed event models' Literal
enforcement (StageCompletedEvent's two-value status, ErrorEvent's now-optional scope), and
(2) SessionProgress.error_message's breaking str -> dict[str, str] change (item 7).
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.api.schemas import ErrorEvent, RegenSummary, SessionProgress, StageCompletedEvent
from app.core.enums import SSEEventType, StageStatus


def test_stage_completed_accepts_both_real_statuses():
    """THREATS -> COMPLETE and SCENARIOS -> AWAITING_DECISION are both real traffic
    (tasks.py:668 and tasks.py:1327 via the same _send_live_update call) — a naive
    single-value Literal would reject one of them."""
    for status in (StageStatus.COMPLETE, StageStatus.AWAITING_DECISION):
        StageCompletedEvent(type=SSEEventType.stage_completed, session_id="s", subsystem_id=0,
                            stage="THREATS", status=status, generation_epoch=1,
                            ts="2026-01-01T00:00:00Z")


def test_stage_completed_rejects_running():
    """RUNNING is stage_started's value, never stage_completed's — the two-value Literal
    must still reject a third value, not degrade to the bare StageStatus enum."""
    with pytest.raises(ValidationError):
        StageCompletedEvent(type=SSEEventType.stage_completed, session_id="s", subsystem_id=0,
                            stage="THREATS", status=StageStatus.RUNNING, generation_epoch=1,
                            ts="2026-01-01T00:00:00Z")


def test_error_event_scope_optional_but_constrained():
    """scope is optional (reaper.py's 3 error sites don't set it yet — a documented gap), but
    when present must be exactly 'stage' or 'session'."""
    ErrorEvent(type=SSEEventType.error, session_id="s", message="m", ts="2026-01-01T00:00:00Z")
    ErrorEvent(type=SSEEventType.error, session_id="s", scope="stage", message="m",
            ts="2026-01-01T00:00:00Z")
    with pytest.raises(ValidationError):
        ErrorEvent(type=SSEEventType.error, session_id="s", scope="subsystem", message="m",
                ts="2026-01-01T00:00:00Z")


def test_session_progress_error_message_is_dict_keyed_by_stage():
    """Item 7 (breaking change): error_message is dict[str, str] keyed by stage, not a single
    str — two simultaneous stage failures must both survive."""
    p = SessionProgress(threats="ERROR", scenarios="ERROR", overall="error",
                        error_message={"threats": "threats failed", "scenarios": "scenarios failed"})
    assert p.error_message == {"threats": "threats failed", "scenarios": "scenarios failed"}
    # default is an empty dict, not None -- a clean board has no key to check for.
    assert SessionProgress(threats="IDLE", scenarios="IDLE", overall="pending").error_message == {}
    # the OLD shape (a bare string) must now be rejected -- proof the type actually changed.
    with pytest.raises(ValidationError):
        SessionProgress(threats="ERROR", scenarios="IDLE", overall="error",
                        error_message="threats failed")


def test_last_regen_round_trips_the_audit_detail_shape():
    """RegenSummary must validate straight off _build_regen_audit_detail's DetailJSON keys
    (cascade.py) with no renaming -- build_board() passes that dict through unmodified."""
    detail = {"target_ids": ["t1"], "requested_ids": ["o1"], "replacements": [{"old": "o1", "new": "o2"}],
            "failed_threat_ids": [], "rescored_threat_ids": [], "epoch": 3, "user_note": None}
    summary = RegenSummary.model_validate(detail)
    assert summary.epoch == 3
    assert summary.replacements == [{"old": "o1", "new": "o2"}]


if __name__ == "__main__":
    test_stage_completed_accepts_both_real_statuses()
    test_stage_completed_rejects_running()
    test_error_event_scope_optional_but_constrained()
    test_session_progress_error_message_is_dict_keyed_by_stage()
    test_last_regen_round_trips_the_audit_detail_shape()
    print("ok")
