"""_group_lock's swap from a hand-rolled Redis SET/EXPIRE lock to redis.lock.Lock.

No fakeredis dependency and no live Redis exists anywhere else in this suite (every other
Redis-touching test either sets max_concurrent_llm_calls=0 to no-op _llm_slot, or monkeypatches
it away entirely) -- so this pins the 3 correctness requirements the swap could silently get
wrong with a MINIMAL fake that runs Lock's real Lua-script logic in Python instead of asking a
Lua interpreter for it:

1. Fails open (does not raise) when Redis is unreachable.
2. The background heartbeat thread can actually extend a lock the MAIN thread acquired --
   only true if thread_local=False is wired correctly; the library defaults to True -- and it
   really RESETS the TTL (replace_ttl=True), not grows it additively across ticks.
3. Losing ownership mid-hold (a stale-timeout takeover) is swallowed silently on both the
   renewal tick and the final release, not surfaced as a warning.
4. A second concurrent acquire on the SAME group is rejected (EmbeddingBusy), not raced.
5. A genuinely unexpected error (not just lost ownership) during renewal or release IS still
   logged as a warning -- proving the except LockNotOwnedError / except Exception split is a
   real behavioral distinction, not just two clauses that happen to both go quiet.
"""
from __future__ import annotations

import time
from types import SimpleNamespace

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.lock import Lock

from app.core.config import get_settings
from app.pipeline import embeddings

_KEY = "tsg:embed-lock:{}"


class _FakeScript:
    """Stands in for redis.commands.core.Script. Real Script.__call__ always executes
    against the `client` kwarg passed at call time (falls back to the registering client
    only if none is given) -- Lock.do_extend/do_release always pass client=self.redis, so
    dispatching on that kwarg here is what makes this safe to reuse even though Lock caches
    the registered Script objects at the CLASS level across every test in this file."""

    def __init__(self, kind: str):
        self.kind = kind

    def __call__(self, keys, args, client=None):
        (name,) = keys
        if self.kind == "release":
            (token,) = args
            return client._run_release(name, token)
        if self.kind == "extend":
            token, additional_ms, replace = args
            return client._run_extend(name, token, additional_ms, replace)
        raise NotImplementedError(self.kind)  # reacquire: _group_lock never calls it


class _FakeRedis:
    """In-memory stand-in for redis.Redis -- just the surface Lock actually calls
    (set/get/register_script), with the 3 fixed Lock Lua scripts reimplemented in Python."""

    def __init__(self):
        self._store: dict[str, tuple[bytes, float | None]] = {}  # name -> (token, expire_at)
        self.extend_calls = 0
        self.release_calls = 0

    def _live(self, name):
        v = self._store.get(name)
        if v is None:
            return None
        token, expire_at = v
        if expire_at is not None and expire_at <= time.monotonic():
            del self._store[name]
            return None
        return token

    def set(self, name, value, nx=False, px=None):
        if nx and self._live(name) is not None:
            return False
        expire_at = time.monotonic() + px / 1000 if px else None
        self._store[name] = (value, expire_at)
        return True

    def get(self, name):
        return self._live(name)

    def get_encoder(self):
        return SimpleNamespace(encode=lambda s: s.encode() if isinstance(s, str) else s)

    def register_script(self, script_text):
        if script_text == Lock.LUA_RELEASE_SCRIPT:
            return _FakeScript("release")
        if script_text == Lock.LUA_EXTEND_SCRIPT:
            return _FakeScript("extend")
        if script_text == Lock.LUA_REACQUIRE_SCRIPT:
            return _FakeScript("reacquire")
        raise NotImplementedError(script_text)

    def _run_release(self, name, token):
        self.release_calls += 1
        if self._live(name) != token:
            return 0
        del self._store[name]
        return 1

    def _run_extend(self, name, token, additional_ms, replace):
        self.extend_calls += 1
        if self._live(name) != token:
            return 0
        cur_token, expire_at = self._store[name]
        new_ms = int(additional_ms)
        if replace == "0":
            remaining_ms = max(0.0, (expire_at - time.monotonic()) * 1000) if expire_at else 0.0
            new_ms += remaining_ms
        self._store[name] = (cur_token, time.monotonic() + new_ms / 1000)
        return 1


@pytest.fixture(autouse=True)
def _reset_lock_script_cache():
    """Lock.register_scripts() only calls client.register_script() once per process (cached
    on the CLASS, not the instance) -- reset it so each test's fake actually gets asked."""
    Lock.lua_release = Lock.lua_extend = Lock.lua_reacquire = None
    yield
    Lock.lua_release = Lock.lua_extend = Lock.lua_reacquire = None


def test_fails_open_when_redis_is_unreachable(monkeypatch):
    warnings = []
    monkeypatch.setattr(embeddings, "_slot_redis",
                        lambda: (_ for _ in ()).throw(RedisConnectionError("no route to host")))
    monkeypatch.setattr(embeddings.log, "warning", lambda event, **kw: warnings.append(event))

    ran = False
    with embeddings._group_lock("g1"):
        ran = True

    assert ran  # the caller's body still runs -- availability wins over the guard
    assert warnings == ["embeddings.group_lock_redis_unavailable_fail_open"]


def test_heartbeat_thread_extends_a_lock_it_did_not_itself_acquire(monkeypatch):
    """thread_local=False check: acquire() runs on the test (main) thread; renewal runs on
    a background thread. Left at the library default (True), that thread would never see
    the token, every extend() would raise plain LockError, and it'd be silently swallowed
    as a warning with zero actual renewals -- this proves real renewals happen instead."""
    fake = _FakeRedis()
    warnings = []
    monkeypatch.setattr(embeddings, "_slot_redis", lambda: fake)
    monkeypatch.setattr(embeddings.log, "warning", lambda event, **kw: warnings.append(event))

    s = get_settings()
    key = _KEY.format("g2")
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(s, "embedding_group_lock_ttl_seconds", 1, raising=False)
        with embeddings._group_lock("g2"):
            time.sleep(0.9)  # >= 2 heartbeat ticks at interval = ttl/3 ~= 0.33s
            remaining_seconds = fake._store[key][1] - time.monotonic()

    assert fake.extend_calls >= 1
    assert warnings == []
    # replace_ttl=True resets the TTL to the full ~1s on every tick. A regression to additive
    # (replace_ttl=False/omitted -- the exact bug embeddings.py's own comment warns against)
    # would compound across >=2 ticks and leave several seconds of TTL remaining instead; 1.5s
    # gives headroom for scheduling jitter while still catching that regression.
    assert remaining_seconds <= 1.5


def test_lost_ownership_mid_hold_degrades_gracefully(monkeypatch):
    """A stale-timeout takeover (someone else now holds the key) must not surface as a
    warning on either the renewal tick or the final release -- LockNotOwnedError caught,
    not raised, on both paths."""
    fake = _FakeRedis()
    warnings = []
    monkeypatch.setattr(embeddings, "_slot_redis", lambda: fake)
    monkeypatch.setattr(embeddings.log, "warning", lambda event, **kw: warnings.append(event))

    s = get_settings()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(s, "embedding_group_lock_ttl_seconds", 1, raising=False)
        with embeddings._group_lock("g3"):
            fake._store[_KEY.format("g3")] = (b"someone-elses-token", None)  # simulate takeover
            time.sleep(0.9)  # let a heartbeat tick land on the mismatch too

    assert warnings == []


def test_second_concurrent_acquire_on_the_same_group_raises_embedding_busy(monkeypatch):
    """The whole reason _group_lock exists: two concurrent recreate_group/delete_group calls
    on the SAME group must not both proceed -- the second one gets EmbeddingBusy (409), not a
    race. Nothing else in this file holds the lock in one call while acquiring it again in a
    second, concurrent call, so this is the only test that actually exercises that path."""
    fake = _FakeRedis()
    monkeypatch.setattr(embeddings, "_slot_redis", lambda: fake)
    monkeypatch.setattr(embeddings.log, "warning", lambda event, **kw: None)

    with embeddings._group_lock("g4"):
        with pytest.raises(embeddings.EmbeddingBusy):
            with embeddings._group_lock("g4"):
                pass  # unreachable -- acquire() must fail before the body ever runs


def test_unexpected_error_during_renewal_is_logged_not_swallowed(monkeypatch):
    """except LockNotOwnedError: pass / except Exception: log.warning(...) is a deliberate
    split, not two clauses that both happen to go quiet -- a genuinely unexpected failure
    (not just a stale-timeout takeover) must still surface as a warning, or a stuck/misbehaving
    renewal would go silently unobserved."""
    fake = _FakeRedis()
    warnings = []
    monkeypatch.setattr(embeddings, "_slot_redis", lambda: fake)
    monkeypatch.setattr(embeddings.log, "warning", lambda event, **kw: warnings.append(event))
    monkeypatch.setattr(fake, "_run_extend",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))

    s = get_settings()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(s, "embedding_group_lock_ttl_seconds", 1, raising=False)
        with embeddings._group_lock("g5"):
            time.sleep(0.5)  # >= 1 heartbeat tick at interval = ttl/3 ~= 0.33s

    assert "embeddings.group_lock_renewal_failed" in warnings


def test_unexpected_error_during_release_is_logged_not_swallowed(monkeypatch):
    """Same distinction as above, for the final release instead of a heartbeat tick."""
    fake = _FakeRedis()
    warnings = []
    monkeypatch.setattr(embeddings, "_slot_redis", lambda: fake)
    monkeypatch.setattr(embeddings.log, "warning", lambda event, **kw: warnings.append(event))

    s = get_settings()
    with pytest.MonkeyPatch.context() as mp:
        # Long TTL -- no heartbeat tick should fire during this test's near-instant body, so
        # the only possible warning is the one under test.
        mp.setattr(s, "embedding_group_lock_ttl_seconds", 30, raising=False)
        with embeddings._group_lock("g6"):
            monkeypatch.setattr(fake, "_run_release",
                                lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))

    assert warnings == ["embeddings.group_lock_release_failed"]
