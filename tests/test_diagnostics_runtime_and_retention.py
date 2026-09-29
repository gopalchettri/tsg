"""The two operational halves of diagnostics: the runtime switch, and the purge that bounds it.

WHY THE SWITCH IS IN REDIS AND NOT IN A VARIABLE. TSG runs one API process and N Celery workers,
and the pipeline runs in the workers. A toggle held in one process's memory changes nothing in the
others: you would flip it, watch the API agree, and capture would carry on unchanged in the only
place that matters. Redis is the shared store this deployment already runs, so the switch reaches
every process without a new dependency.

WHY IT IS CACHED. `log_enabled()` is consulted PER LOG RECORD. An uncached read would put a Redis
round trip on every log call — turning an observability feature into a latency problem, which is
the opposite of the trade this whole effort is making.

WHY THE PURGE IS NOT OPTIONAL. Without it, the table added to make failures diagnosable eventually
becomes the failure. It is also the enforcement half of the retention promise: a horizon nothing
acts on is a statement, not a control.
"""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app.core import diagnostics
from app.db import models as m
from app.db.dal import now


class _FakeRedis:
    """A dict with Redis's method names. Enough to pin the LOGIC, which is what these tests are
    about — the redis client library is not under test here."""

    def __init__(self, *, broken: bool = False):
        self.store: dict[str, str] = {}
        self.broken = broken
        self.reads = 0

    def get(self, key):
        self.reads += 1
        if self.broken:
            raise ConnectionError("redis is down")
        return self.store.get(key)

    def set(self, key, value, ex=None):
        if self.broken:
            raise ConnectionError("redis is down")
        self.store[key] = value

    def delete(self, key):
        if self.broken:
            raise ConnectionError("redis is down")
        self.store.pop(key, None)


@pytest.fixture
def redis(monkeypatch):
    """Point the override at a fake, and un-pin the cache that conftest freezes for every test.

    conftest sets `_override_cache` to never expire so no ordinary test opens a socket to the real
    Redis this machine runs. A test that is ABOUT the override has to say so and reset it — the
    same declared-never-inherited rule as every other setting there."""
    fake = _FakeRedis()
    monkeypatch.setattr(diagnostics, "_override_redis", lambda: fake)
    diagnostics._override_cache = (0.0, None)
    yield fake
    diagnostics._override_cache = (float("inf"), None)


# --- the switch -----------------------------------------------------------------------------------

def test_the_override_beats_the_deployed_setting(redis, monkeypatch):
    """The point of a runtime switch: change capture without a redeploy, without a restart, and
    without losing the state you were trying to reproduce."""
    monkeypatch.setenv("TSG_DIAGNOSTIC_DB_CATEGORIES", "none")
    from app.core.config import get_settings
    get_settings.cache_clear()

    assert diagnostics.active_categories() == "none"

    diagnostics.set_override("exceptions,retries")
    assert diagnostics.active_categories() == "exceptions,retries", (
        "the runtime override did not win over the deployed value — the switch does nothing")


def test_clearing_the_override_falls_back_and_is_not_the_same_as_off(redis, monkeypatch):
    """`null` and `"none"` are different answers, and confusing them is how an environment ends up
    silently uninstrumented. Cleared means "use what was deployed"; "none" means "capture nothing,
    whatever was deployed"."""
    monkeypatch.setenv("TSG_DIAGNOSTIC_DB_CATEGORIES", "all")
    from app.core.config import get_settings
    get_settings.cache_clear()

    diagnostics.set_override("none")
    assert diagnostics.active_categories() == "none"

    diagnostics.set_override(None)
    assert diagnostics.active_categories() == "all", (
        "clearing the override did not fall back to the deployed value")


def test_the_switch_is_read_from_the_shared_store_not_from_memory(redis, monkeypatch):
    """THE MULTI-PROCESS PROPERTY, and the entire reason this is not a module variable.

    Another process writing the key is simulated by writing it directly — no call to set_override.
    If the value were held in memory this reader would never see it, and the real system would
    behave exactly that way: the API would report the change and the workers would ignore it."""
    monkeypatch.setenv("TSG_DIAGNOSTIC_DB_CATEGORIES", "none")
    from app.core.config import get_settings
    get_settings.cache_clear()

    redis.store[diagnostics._OVERRIDE_KEY] = "all"      # as if another process had set it
    diagnostics._override_cache = (0.0, None)           # this process's copy lapses

    assert diagnostics.active_categories() == "all", (
        "a change made by another process was not observed — the switch would reach the API and "
        "never reach the workers, where the pipeline actually runs")


def test_the_switch_is_not_read_once_per_log_record(redis, monkeypatch):
    """THE IO PROPERTY. log_enabled() runs per log record; an uncached read would put a Redis
    round trip on every log call. Counted at the client, because a cache that silently stopped
    applying would leave every other test passing."""
    monkeypatch.setenv("TSG_DIAGNOSTIC_DB_CATEGORIES", "none")
    from app.core.config import get_settings
    get_settings.cache_clear()

    for _ in range(500):
        diagnostics.active_categories()

    assert redis.reads <= 2, (
        f"500 calls made {redis.reads} Redis reads — the cache is not applying, and every log "
        "line in the system would carry a network round trip")


def test_redis_being_down_degrades_the_switch_and_nothing_else(monkeypatch):
    """An observability switch must never be the thing that breaks the system it observes. With
    Redis unreachable the deployed value applies, and reading it does not raise."""
    broken = _FakeRedis(broken=True)
    monkeypatch.setattr(diagnostics, "_override_redis", lambda: broken)
    monkeypatch.setenv("TSG_DIAGNOSTIC_DB_CATEGORIES", "exceptions")
    from app.core.config import get_settings
    get_settings.cache_clear()
    diagnostics._override_cache = (0.0, None)
    try:
        assert diagnostics.active_categories() == "exceptions"
        assert diagnostics.log_enabled() is False      # must answer, not explode
    finally:
        diagnostics._override_cache = (float("inf"), None)


def test_a_dead_redis_is_not_retried_on_every_single_call(monkeypatch):
    """The back-off, and it is a correctness property rather than a nicety: without it a Redis
    outage means a connect timeout on EVERY log record, so the outage would degrade logging
    instead of only the toggle."""
    broken = _FakeRedis(broken=True)
    monkeypatch.setattr(diagnostics, "_override_redis", lambda: broken)
    from app.core.config import get_settings
    get_settings.cache_clear()
    diagnostics._override_cache = (0.0, None)
    try:
        for _ in range(200):
            diagnostics.active_categories()
        assert broken.reads <= 2, (
            f"a dead Redis was dialled {broken.reads} times — during an outage every log call "
            "would pay a connect timeout")
    finally:
        diagnostics._override_cache = (float("inf"), None)


def test_setting_the_override_is_loud_when_it_fails(monkeypatch):
    """The ONE place in diagnostics that raises, deliberately. Everywhere else a swallowed error
    costs a row; here it would tell an operator the switch moved when it did not, and they would
    then trust an answer about what is captured that is simply false."""
    broken = _FakeRedis(broken=True)
    monkeypatch.setattr(diagnostics, "_override_redis", lambda: broken)
    with pytest.raises(ConnectionError):
        diagnostics.set_override("all")


def test_an_expiring_override_is_available(redis):
    """The safety valve for `logs`. That category writes personal data durably, and the realistic
    mistake is not a bad decision but a forgotten one — switched on to reproduce something, still
    on a month later, in every backup taken since."""
    captured = {}
    redis.set = lambda k, v, ex=None: captured.update(key=k, value=v, ex=ex)

    diagnostics.set_override("logs", 1800)

    assert captured["ex"] == 1800, (
        "the expiry was dropped — an operator who said 'on for 30 minutes' would have left a "
        "durable recording of prompt text running indefinitely")


# --- the purge -------------------------------------------------------------------------------------

@pytest.fixture
def db(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'purge.db').as_posix()}", future=True)
    m.Diagnostic_Event.__table__.create(engine)
    m.Application_Log.__table__.create(engine)
    return sessionmaker(engine, future=True)


def _add(sess, table, age_days: int):
    stamp = now() - timedelta(days=age_days)
    if table is m.Diagnostic_Event:
        sess.add(m.Diagnostic_Event(DiagnosticID=str(uuid.uuid4()), CreatedAt=stamp,
                                    Kind="stage_error", ExceptionClass="Timeout"))
    else:
        sess.add(m.Application_Log(LogID=str(uuid.uuid4()), CreatedAt=stamp, Level="INFO"))


def _count(sess, table) -> int:
    return sess.execute(select(func.count()).select_from(table.__table__)).scalar()


def test_each_table_is_purged_on_its_own_horizon(db, monkeypatch):
    """THE REASON THERE ARE TWO TABLES, made to bite.

    Diagnostic_Event holds rare, valuable rows and is kept for weeks. Application_Log takes every
    line at INFO and above and is kept for days. One shared horizon would either throw away
    failure records too early or keep the log flood far too long — and a single table would have
    forced exactly that."""
    monkeypatch.setenv("TSG_DIAGNOSTIC_RETENTION_DAYS", "30")
    monkeypatch.setenv("TSG_APPLICATION_LOG_RETENTION_DAYS", "7")
    from app.core.config import get_settings
    get_settings.cache_clear()

    from app.pipeline.reaper import purge_expired_diagnostics

    with db() as sess:
        _add(sess, m.Diagnostic_Event, 10)      # inside 30 days -> kept
        _add(sess, m.Diagnostic_Event, 40)      # past 30 days   -> purged
        _add(sess, m.Application_Log, 3)        # inside 7 days  -> kept
        _add(sess, m.Application_Log, 10)       # past 7 days    -> purged, though a diagnostic
        sess.commit()                           #                   of the same age survives

        purge_expired_diagnostics(sess)

        assert _count(sess, m.Diagnostic_Event) == 1, "the diagnostics horizon was not applied"
        assert _count(sess, m.Application_Log) == 1, (
            "the log horizon was not applied — a 10-day-old log line outlived its retention while "
            "a 10-day-old diagnostic correctly survived, which is the whole distinction")


def test_nothing_inside_the_horizon_is_ever_removed(db, monkeypatch):
    """The converse, and the more dangerous direction: a purge that is too eager destroys the
    record of the incident someone is in the middle of investigating."""
    monkeypatch.setenv("TSG_DIAGNOSTIC_RETENTION_DAYS", "30")
    from app.core.config import get_settings
    get_settings.cache_clear()

    from app.pipeline.reaper import purge_expired_diagnostics

    with db() as sess:
        for age in (0, 1, 29):
            _add(sess, m.Diagnostic_Event, age)
        sess.commit()

        purge_expired_diagnostics(sess)

        assert _count(sess, m.Diagnostic_Event) == 3, "the purge deleted rows still in retention"


def test_a_failing_purge_never_takes_the_reaper_down_with_it():
    """Housekeeping must not fail the tick. The reaper's real job is recovering stuck sessions —
    an asset lock that never releases returns 409 forever — and that must not stop because a
    DELETE could not run."""
    from app.pipeline.reaper import purge_expired_diagnostics

    class _BrokenSession:
        def execute(self, *_a, **_k):
            raise RuntimeError("database is gone")

        def rollback(self):
            pass

    removed = purge_expired_diagnostics(_BrokenSession())     # must not raise

    assert removed == {"Diagnostic_Event": 0, "Application_Log": 0}, (
        "a failed purge must report nothing removed, not pretend it worked")
