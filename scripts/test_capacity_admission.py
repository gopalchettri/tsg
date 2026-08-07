#!/usr/bin/env python
"""Self-check for app.db.dal.assert_capacity_available's admission-control logic.

Regression guard for the bug where `max_active_sessions=0` (the shipped default,
documented and intended as "no cap" the same way `max_active_sessions_per_entity=0`
already is) instead made EVERY session-creation request fail with 503
capacity_exceeded, because `count >= 0` is always true. No real DB or FastAPI app
needed — `assert_capacity_available` only ever calls `sess.execute(...)`, so a
fake session stubs that out.

    python scripts/test_capacity_admission.py

Exit codes: 0 = all cases passed · 1 = a case behaved unexpectedly.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # make `app` importable

import app.db.dal as dal  # noqa: E402


class _FakeSettings:
    def __init__(self, max_active_sessions, max_active_sessions_per_entity):
        self.max_active_sessions = max_active_sessions
        self.max_active_sessions_per_entity = max_active_sessions_per_entity


class _FakeResult:
    """Stands in for the SQLAlchemy CursorResult `sess.execute(...)` returns —
    `.scalar()` for count_active_sessions's single-column query, `.one()` for
    assert_capacity_available's two-column (total, entity_total) query."""
    def __init__(self, total, entity_total):
        self._total = total
        self._entity_total = entity_total

    def scalar(self):
        return self._total

    def one(self):
        return (self._total, self._entity_total)


class _FakeSession:
    def __init__(self, total, entity_total=0):
        self._result = _FakeResult(total, entity_total)

    def execute(self, _query):
        return self._result


def _check(name, max_active_sessions, max_active_sessions_per_entity, total, entity_total,
           entity_id, should_raise):
    dal.get_settings = lambda: _FakeSettings(max_active_sessions, max_active_sessions_per_entity)
    sess = _FakeSession(total, entity_total)
    raised = False
    try:
        dal.assert_capacity_available(sess, entity_id=entity_id)
    except dal.CapacityExceeded:
        raised = True
    status = "OK" if raised == should_raise else "FAIL"
    print(f"{status}  {name}  (raised={raised}, expected={should_raise})")
    return status == "OK"


def main() -> int:
    real_get_settings = dal.get_settings
    cases = [
        # global cap disabled (0) + no per-entity cap -> must NOT reject, regardless of count
        ("disabled global cap, 0 active, no entity", 0, 0, 0, 0, None, False),
        ("disabled global cap, 50 active, no entity", 0, 0, 50, 0, None, False),
        ("disabled global cap, entity given, per-entity also disabled", 0, 0, 3, 0, "5", False),
        # global cap enabled -> enforced once reached, not before
        ("global cap=2, count=1 -> under", 2, 0, 1, 0, None, False),
        ("global cap=2, count=2 -> at ceiling", 2, 0, 2, 0, None, True),
        # per-entity cap enforced independently of a disabled global cap
        ("global disabled, per-entity cap=1, entity at cap", 0, 1, 3, 1, "5", True),
        ("global disabled, per-entity cap=1, entity under cap", 0, 1, 3, 0, "5", False),
        # entity-aware branch still enforces the global cap when both are set
        ("global cap=1, per-entity cap=5, total at global ceiling", 1, 5, 1, 0, "5", True),
    ]
    try:
        results = [_check(*case) for case in cases]
    finally:
        dal.get_settings = real_get_settings
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
