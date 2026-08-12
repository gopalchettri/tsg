"""Plan Phase 2 (`stream_events()` rewrite) -- the terminal-state guarantee itself, unit-tested
at the generator level (no live Redis/MSSQL needed): `session_events()` is called directly, and
`response.body_iterator` (sse_starlette's `EventSourceResponse` stores the async generator
verbatim -- see sse_starlette/sse.py's `__init__`) is driven by hand.

Verification 1's specific, highest-risk claim: stub `bus.publish` to a no-op and the stream must
STILL reach a terminal close, driven purely by the `SUBSCRIBE_TICK`-driven DB status check
(`_stream_still_open`), never by the publish succeeding. The fast "accept publishes, subscriber
wakes on the message" path is intentionally never exercised here -- proving that path works would
say nothing about the guarantee item 1 actually claims.
"""
from __future__ import annotations

import asyncio
import json

import app.api.sessions as sessions_mod
from app.api.deps import Principal
from app.sse import bus


def _principal() -> Principal:
    return Principal(claims={"sub": "1138"}, entities={"86"}, client_id="shield", tenant_id="DESC")


def _drive(session_id: str, principal: Principal) -> list[dict]:
    """Call the real route function and manually pump its body_iterator to completion --
    exercises the exact generator `stream_events()` builds, without a live ASGI transport."""

    async def run():
        response = await sessions_mod.session_events(session_id, principal)
        events = []
        async for chunk in response.body_iterator:
            events.append(chunk)
        return events

    return asyncio.run(run())


def test_stubbed_publish_terminal_state_closes_stream(monkeypatch):
    """Verification 1 (the stubbed-publish repro): `bus.publish` is a genuine no-op for the whole
    test -- nothing ever reaches Redis via the fast path. `bus.subscribe` only ever yields
    SUBSCRIBE_TICK (consistent with "no message ever arrives"). The DB-side status flips to
    terminal on the SECOND tick (mirroring accept()'s own commit, independent of the publish
    call it also makes) -- the stream must close there, not hang forever."""
    monkeypatch.setattr(bus, "publish", lambda *a, **k: None)  # the fast path: a true no-op

    board = {"session_id": "s-terminal", "entity_id": "86", "session_status": "active"}
    monkeypatch.setattr(sessions_mod, "_load_events_board", lambda sid, principal: board)

    async def fake_subscribe(session_id):
        # Ticks forever if the caller keeps asking -- proves the loop never dies "for free";
        # only the _stream_still_open check below is allowed to end it.
        while True:
            yield bus.SUBSCRIBE_TICK

    monkeypatch.setattr(bus, "subscribe", fake_subscribe)

    tick_calls = {"n": 0}

    def fake_still_open(session_id, principal, verify_membership):
        # Tick 1: DB still says active (worker hasn't committed the accept yet).
        # Tick 2: DB now says terminal -- the accept's OWN commit, nothing to do with the
        # (stubbed, no-op) publish call accept() also makes on that same code path.
        tick_calls["n"] += 1
        return tick_calls["n"] < 2

    monkeypatch.setattr(sessions_mod, "_stream_still_open", fake_still_open)

    events = _drive(board["session_id"], _principal())

    # Exactly one event reached the wire: the initial reconcile. No real Redis message ever
    # arrived (bus.subscribe yields only ticks), yet the generator still terminated.
    assert len(events) == 1
    assert events[0]["event"] == "reconcile"
    assert tick_calls["n"] == 2  # closed on the second tick's DB check, not before

    # The per-process concurrency slot (item 12) must be released on this path too, or a stubbed
    # publish would also leak the SSE capacity cap.
    assert not sessions_mod._sse_semaphore().locked()


def test_reconcile_event_carries_type_discriminator(monkeypatch):
    """Item 26: the wire-level reconcile payload must carry an actual "type": "reconcile" key --
    `build_board()`'s own dict never does (it is also served, verbatim, by the polling GET)."""
    monkeypatch.setattr(bus, "publish", lambda *a, **k: None)
    board = {"session_id": "s-reconcile", "entity_id": "86", "session_status": "active"}
    monkeypatch.setattr(sessions_mod, "_load_events_board", lambda sid, principal: board)

    async def fake_subscribe(session_id):
        yield bus.SUBSCRIBE_TICK

    monkeypatch.setattr(bus, "subscribe", fake_subscribe)
    monkeypatch.setattr(sessions_mod, "_stream_still_open", lambda *a, **k: False)

    events = _drive(board["session_id"], _principal())
    payload = json.loads(events[0]["data"])
    assert payload["type"] == "reconcile"
    assert payload["session_id"] == board["session_id"]
    # build_board's own fields must still ride along unmodified.
    assert payload["entity_id"] == "86"


def test_stream_stays_open_while_session_active(monkeypatch):
    """Control case: as long as `_stream_still_open` keeps saying True, the generator must keep
    consuming ticks rather than closing early on some unrelated condition."""
    monkeypatch.setattr(bus, "publish", lambda *a, **k: None)
    board = {"session_id": "s-open", "entity_id": "86", "session_status": "active"}
    monkeypatch.setattr(sessions_mod, "_load_events_board", lambda sid, principal: board)

    tick_count = 5

    async def fake_subscribe(session_id):
        for _ in range(tick_count):
            yield bus.SUBSCRIBE_TICK

    monkeypatch.setattr(bus, "subscribe", fake_subscribe)
    calls = {"n": 0}

    def fake_still_open(*a, **k):
        calls["n"] += 1
        return True  # never terminal -- the generator exhausts bus.subscribe() itself instead

    monkeypatch.setattr(sessions_mod, "_stream_still_open", fake_still_open)

    events = _drive(board["session_id"], _principal())
    assert len(events) == 1  # only the reconcile -- every tick was consumed, none re-yielded
    assert calls["n"] == tick_count


def test_verify_membership_revocation_closes_stream(monkeypatch):
    """Item 30, same consolidated tick handler: when verify_membership is on and the (user,
    entity) pair stops resolving, the stream must close on the very next tick."""
    monkeypatch.setattr(bus, "publish", lambda *a, **k: None)
    board = {"session_id": "s-revoked", "entity_id": "86", "session_status": "active"}
    monkeypatch.setattr(sessions_mod, "_load_events_board", lambda sid, principal: board)

    async def fake_subscribe(session_id):
        while True:
            yield bus.SUBSCRIBE_TICK

    monkeypatch.setattr(bus, "subscribe", fake_subscribe)

    seen_verify_membership = []

    def fake_still_open(session_id, principal, verify_membership):
        seen_verify_membership.append(verify_membership)
        return False  # simulates dal.user_has_entity() now returning False

    monkeypatch.setattr(sessions_mod, "_stream_still_open", fake_still_open)
    settings = sessions_mod.get_settings()
    monkeypatch.setattr(settings, "verify_membership", True)

    events = _drive(board["session_id"], _principal())
    assert len(events) == 1
    assert seen_verify_membership == [True]


if __name__ == "__main__":
    print("run via pytest")
