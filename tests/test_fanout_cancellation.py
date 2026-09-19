"""fanout.map_settled: a fan-out's children die with their parent.

THE BUG (18 Sep): the reaper revoked a run (terminate=True kills the TASK greenlet), but its
`with ThreadPoolExecutor` workers were not its children — every queued scenario and embedding batch
kept running for 29 more minutes and starved the next run into being reaped too.

The gevent branch is driven directly (`_gevent_patched` forced True): gevent's Pool needs no
monkey-patching as long as the children yield through gevent, which gevent.sleep does.
"""
from __future__ import annotations

import gevent
import pytest

from app.pipeline import fanout


@pytest.fixture(params=[True, False], ids=["gevent", "threads"])
def mode(request, monkeypatch):
    monkeypatch.setattr(fanout, "_gevent_patched", lambda: request.param)
    return request.param


def test_killing_the_parent_kills_every_child(monkeypatch) -> None:
    monkeypatch.setattr(fanout, "_gevent_patched", lambda: True)
    started, finished, unwound = [], [], []

    def child(i):
        started.append(i)
        try:
            gevent.sleep(0.5)          # an LLM call / DB call / model-pool wait
            finished.append(i)
        finally:
            unwound.append(i)          # a child's own cleanup (sessions close) still runs

    parent = gevent.spawn(fanout.map_settled, child, range(6), max_workers=2)
    gevent.sleep(0.1)
    parent.kill()                      # the reaper's revoke(terminate=True)
    gevent.sleep(0.8)                  # long enough for any survivor to finish or start more
    assert started == [0, 1], "a queued item started after its parent was killed"
    assert finished == [], "an in-flight child outlived its parent"
    assert sorted(unwound) == [0, 1]


def test_results_are_settled_in_input_order(mode) -> None:
    def fn(i):
        if i == 2:
            raise ValueError("bad item")
        if mode:
            gevent.sleep(0.01 * (5 - i))   # finish out of order
        return i * 10

    out = fanout.map_settled(fn, range(5), max_workers=3)
    assert [v for v, _ in out] == [0, 10, None, 30, 40]
    assert [type(e).__name__ if e else None for _, e in out] == [None, None, "ValueError", None, None]


def test_a_childs_base_exception_is_never_swallowed(mode) -> None:
    """A captured Exception is a result; a KeyboardInterrupt/GreenletExit/Timeout is not."""
    def fn(i):
        if i == 1:
            raise KeyboardInterrupt
        return i

    with pytest.raises(KeyboardInterrupt):
        fanout.map_settled(fn, range(3), max_workers=2)


def test_empty_input_spawns_nothing(mode) -> None:
    assert fanout.map_settled(lambda i: i, [], max_workers=4) == []
