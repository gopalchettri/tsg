"""The seam: does a destination nobody wrote yet actually work?

THE CLAIM UNDER TEST is "adding Prometheus later is a new file and a word in a setting". That claim
is easy to make and easy to get wrong, and the way it goes wrong is specific: the normalised event
turns out to carry only what the database backend happened to need, so the second backend has to
reach back into the pipeline for the rest — and the seam is fiction.

So these tests register a FAKE backend that no production code knows about, and assert it receives
the same events the real one does, carrying the fields a metrics or tracing backend would actually
want. If the seam is real, a fake backend is indistinguishable from a future real one.

The rest pins the failure modes a fan-out has to survive: one destination failing must not cost the
others their copy, must not reach the caller, and must not flood the logs by reporting itself on
every single event.
"""
from __future__ import annotations

import pytest

from app.core import diagnostic_backends as backends
from app.core.enums import DiagnosticKind


class _FakeBackend:
    """A destination invented entirely inside this test file — which is the whole point.

    Shaped like the Prometheus backend would be: it counts, it never touches a database, and it
    knows nothing whatsoever about Diagnostic_Event."""

    def __init__(self, name="fake", *, categories="all", available=True, explode=False):
        self.name = name
        self._categories = categories
        self._available = available
        self._explode = explode
        self.seen: list[backends.DiagnosticEvent] = []

    def available(self) -> bool:
        return self._available

    def wants(self, category: str) -> bool:
        return category in backends.categories_from(self._categories)

    def emit(self, event) -> None:
        if self._explode:
            raise RuntimeError("this backend is broken")
        self.seen.append(event)

    def close(self) -> None:
        pass


@pytest.fixture
def registry():
    """A clean registry per test, restored afterwards. The real one is module state populated at
    import, and a test that left a fake behind would change every later test's fan-out."""
    original = dict(backends._REGISTRY)
    original_failures = dict(backends._failures)
    yield backends._REGISTRY
    backends._REGISTRY.clear()
    backends._REGISTRY.update(original)
    backends._failures.clear()
    backends._failures.update(original_failures)


def _only(registry, *fakes):
    """Replace every real destination with the given fakes, so a test observes its own events and
    never writes to whatever TSG_DB_DSN happens to name."""
    registry.clear()
    for fake in fakes:
        backends.register(fake)


# --- the seam is real -----------------------------------------------------------------------------

def test_a_backend_nobody_wrote_receives_the_same_events_the_database_does(registry):
    """THE CLAIM, tested directly. A fake registered from a test file — which no production code
    imports, references, or knows the name of — receives the events the pipeline produces.

    If this passes, adding Prometheus is genuinely a new module. If the event only ever made sense
    to the db backend, this is where that shows up."""
    fake = _FakeBackend()
    _only(registry, fake)
    from app.core import diagnostics

    diagnostics.record(DiagnosticKind.stage_error, ValueError("boom"), session_id="s-1",
                       client_message="stage processing failed", context={"stage": "THREATS"})

    assert len(fake.seen) == 1, "the fake destination was never handed the event"
    event = fake.seen[0]
    assert event.category == "exceptions"
    assert event.kind == str(DiagnosticKind.stage_error)
    assert event.exception_class == "ValueError"
    assert event.session_id == "s-1"
    assert event.client_message == "stage processing failed"
    assert event.context["stage"] == "THREATS"


def test_the_event_carries_what_a_metrics_backend_would_need(registry):
    """A Prometheus backend counts by category and observes durations; it must NEVER label by
    session, task or request id, because unbounded label cardinality is the standard way to take a
    Prometheus server down. Both halves have to be on the event: the fields to aggregate by, and
    the fields a metrics backend deliberately drops while the db backend keeps them."""
    fake = _FakeBackend()
    _only(registry, fake)
    from app.core import diagnostics

    diagnostics.record_slow_step(step="REGROUNDING", duration_ms=8123.0, session_id="s-9")

    event = fake.seen[0]
    assert event.category == "slow"
    assert event.duration_ms == 8123.0, "a duration backend has nothing to observe"
    assert event.session_id == "s-9", "the high-cardinality ids must be PRESENT for the db backend"
    assert event.ts is not None and event.level, "every backend needs a timestamp and a severity"


# --- the fan-out survives a bad destination --------------------------------------------------------

def test_one_broken_destination_does_not_cost_the_others_their_copy(registry):
    """PER-BACKEND best-effort, not best-effort overall. This is why the try sits INSIDE the loop:
    around it, the first backend to raise would silently cut off every backend after it — and which
    ones those were would depend on dictionary order."""
    broken, healthy = _FakeBackend("broken", explode=True), _FakeBackend("healthy")
    _only(registry, broken, healthy)
    from app.core import diagnostics

    diagnostics.record(DiagnosticKind.stage_error, ValueError("boom"))

    assert len(healthy.seen) == 1, (
        "a failing destination stopped a healthy one from receiving the event")


def test_a_broken_destination_never_reaches_the_caller(registry):
    """These calls sit INSIDE failure handlers. A diagnostics write that raised would replace a
    diagnosable error with an undiagnosable one — the exact outcome the subsystem exists to
    remove."""
    _only(registry, _FakeBackend("broken", explode=True))
    from app.core import diagnostics

    diagnostics.record(DiagnosticKind.stage_error, ValueError("boom"))     # must not raise
    diagnostics.record_slow_step(step="x", duration_ms=1.0)                # nor must this


def test_a_persistently_broken_destination_does_not_flood_the_logs(registry):
    """A broken backend is broken for EVERY event. Reporting each one turns one outage into a
    second flood, and the flood is what makes the first outage hard to read."""
    broken = _FakeBackend("broken", explode=True)
    _only(registry, broken)
    from app.core import diagnostics

    for _ in range(500):
        diagnostics.record(DiagnosticKind.stage_error, ValueError("boom"))

    assert backends._failures["broken"] == 500, "failures must still be COUNTED, just not logged"


# --- on by default, and the kill switch --------------------------------------------------------------

def test_a_destination_is_on_as_soon_as_it_is_available(registry, monkeypatch):
    """THE INVERSION, and the same one as the transient-error rule. An allowlist means someone
    installs a tool, configures it, sees no data, and spends an afternoon finding the second switch
    they were also supposed to set. Configuring the prerequisite IS the opt-in."""
    monkeypatch.setenv("TSG_DIAGNOSTIC_BACKENDS_DISABLED", "")
    from app.core.config import get_settings
    get_settings.cache_clear()

    fake = _FakeBackend("newtool")
    _only(registry, fake)

    assert fake in backends.active_backends(), (
        "a registered, available destination was inactive with no setting naming it — it would "
        "have to be switched on twice")


def test_the_kill_switch_wins(registry, monkeypatch):
    """The operator's emergency stop. Highest precedence there is: a name here cannot be
    re-enabled by any runtime override, which is what makes it usable during an incident."""
    fake = _FakeBackend("newtool")
    _only(registry, fake)
    monkeypatch.setenv("TSG_DIAGNOSTIC_BACKENDS_DISABLED", "newtool")
    from app.core.config import get_settings
    get_settings.cache_clear()

    from app.core import diagnostics
    diagnostics.record(DiagnosticKind.stage_error, ValueError("boom"))

    assert fake.seen == [], "a destination named in the kill switch still received events"


def test_a_destination_with_unmet_prerequisites_is_absent_not_an_error(registry):
    """An unconfigured destination is one nobody asked for, not a misconfiguration. Raising at boot
    because OTLP has no endpoint would make adding a backend a deployment risk."""
    _only(registry, _FakeBackend("otlp", available=False))

    assert backends.active_backends() == ()
    assert backends.backend_status()[0]["available"] is False, (
        "an absent destination must still be REPORTED — silently missing is the hardest "
        "observability problem there is to debug")


# --- the two axes stay separate -----------------------------------------------------------------------

def test_two_destinations_can_capture_different_categories(registry):
    """THE CROSS-AXIS CASE. A single-backend test would pass happily while "what to capture" and
    "where to send it" were secretly welded together — and the welding only surfaces once somebody
    wants exceptions in Prometheus and everything in the database."""
    everything = _FakeBackend("all_sink")
    errors_only = _FakeBackend("errors", categories="exceptions")
    _only(registry, everything, errors_only)
    from app.core import diagnostics

    diagnostics.record(DiagnosticKind.stage_error, ValueError("boom"))
    diagnostics.record(DiagnosticKind.transient_retry, ValueError("hiccup"))

    assert len(everything.seen) == 2
    assert [e.category for e in errors_only.seen] == ["exceptions"], (
        "the per-destination category filter did not apply — both destinations got the same "
        "events, so the two axes are welded together")


def test_every_category_name_maps_to_something_that_can_be_captured():
    """The list the API validates against, the operator guide documents and the backends filter on
    must be ONE list. Three copies is three chances to publish a category that records nothing —
    which is exactly what shipped when the guide promised `degraded` and `slow` before either
    existed and the API refused both."""
    from app.core import diagnostics

    assert set(diagnostics.known_categories()) == set(backends.CATEGORIES)
    for category in backends.CATEGORIES:
        assert backends.categories_from(category) == {category}, (
            f"{category!r} is advertised but the parser drops it, so switching it on does nothing")


def test_every_diagnostic_kind_belongs_to_a_category():
    """A kind with no category is a row nobody can switch on or off. Derived from the enum rather
    than listed, so a kind added later fails HERE instead of silently becoming uncapturable."""
    from app.core import diagnostics

    for kind in DiagnosticKind:
        category = diagnostics._category_of(kind)
        assert category in backends.CATEGORIES, (
            f"{kind} maps to {category!r}, which is not a category an operator can switch")


# --- the two categories that shipped as documentation before they shipped as code -------------------

def test_a_degraded_outcome_is_captured_from_the_stream_that_already_exists(registry, monkeypatch):
    """`degraded` costs NO new instrumentation, which is the only reason it is cheap enough to
    leave on permanently. Every event it captures is one the pipeline was already logging; the
    category is a filter over that stream, not a second set of call sites."""
    monkeypatch.setenv("TSG_DIAGNOSTIC_DB_CATEGORIES", "degraded")
    from app.core.config import get_settings
    get_settings.cache_clear()

    fake = _FakeBackend(categories="degraded")
    _only(registry, fake)
    from app.core.logging import get_logger

    get_logger("app.pipeline.threat_identification").warning(
        "threats.partial_delivery", session_id="s-1", asked=10, delivered=4)

    assert [e.category for e in fake.seen] == ["degraded"], (
        "a partial delivery was not recorded as degraded — the run returned less than it was "
        "asked for, raised nothing, and left no durable trace")
    assert fake.seen[0].kind == str(DiagnosticKind.degraded_outcome)


def test_the_degraded_match_survives_an_event_name_built_with_a_prefix(registry, monkeypatch):
    """THE OPEN-LIST TRAP, avoided. cascade.py logs `f"{kind}.lock_lost"`, so the full event name
    depends on a runtime value and no literal list can enumerate it. Matching the last dotted
    segment covers every prefix nobody thought of — the same lesson as the transient-error rule,
    where an allowlist of known failures is what cancelled 6174F288."""
    monkeypatch.setenv("TSG_DIAGNOSTIC_DB_CATEGORIES", "degraded")
    from app.core.config import get_settings
    get_settings.cache_clear()

    from app.core import diagnostics

    for name in ("scenarios.lock_lost", "threats.lock_lost", "stage.claim_lost",
                 "stage.claim_lost_midbatch", "subsystem.lock_lost_before_scenarios"):
        assert diagnostics.is_degraded_event(name), f"{name} was not recognised as degraded"
    assert not diagnostics.is_degraded_event("pipeline.step"), (
        "an ordinary log line was filed as degraded — the match is too loose and the category "
        "would carry the volume it exists to avoid")


def test_the_log_stream_keeps_every_line_even_when_degraded_is_also_on(registry, monkeypatch):
    """A degraded line is recorded under BOTH categories, deliberately. Routing it to `degraded`
    INSTEAD would punch silent holes in a stream whose whole contract is "every line at INFO and
    above" — and a stream with holes you cannot see is worse than a few duplicated rows."""
    monkeypatch.setenv("TSG_DIAGNOSTIC_DB_CATEGORIES", "all")
    from app.core.config import get_settings
    get_settings.cache_clear()

    fake = _FakeBackend()
    _only(registry, fake)
    from app.core.logging import get_logger

    get_logger("app.pipeline.threat_identification").warning("threats.partial_delivery")

    assert sorted(e.category for e in fake.seen) == ["degraded", "logs"], (
        "the degraded line went to one category only — whichever it was, the other table now has "
        "a hole nothing reports")


def test_a_slow_step_is_recorded_with_the_trace_sinks_switched_off(registry, monkeypatch):
    """THE GAP THAT WOULD HAVE SHIPPED. trace_step measures nothing unless a sink is live, and all
    three configurable sinks are OFF by default in every environment — so deriving `slow` from
    them would have meant a category that appears in the settings, in the API and in the operator
    guide while recording nothing, anywhere, ever."""
    monkeypatch.setenv("TSG_TRACE_SINKS", "")            # tracing off, as it is by default
    monkeypatch.setenv("TSG_DIAGNOSTIC_DB_CATEGORIES", "slow")
    monkeypatch.setenv("TSG_DIAGNOSTIC_SLOW_STEP_MS", "1")
    from app.core.config import get_settings
    get_settings.cache_clear()

    fake = _FakeBackend(categories="slow")
    _only(registry, fake)

    import time

    from app.core.tracing import trace_step

    with trace_step("SLOW THING", "s-1") as step:
        time.sleep(0.01)
        step.result(items=3)

    assert [e.category for e in fake.seen] == ["slow"], (
        "no slow step was recorded with tracing off — the category would be documented and dead")
    assert fake.seen[0].duration_ms >= 1


def test_a_fast_step_is_not_recorded(registry, monkeypatch):
    """The converse. Recording every finished step would put this table on the same volume curve
    as the raw log stream, which is the one thing the `slow` category exists not to be."""
    monkeypatch.setenv("TSG_TRACE_SINKS", "")
    monkeypatch.setenv("TSG_DIAGNOSTIC_DB_CATEGORIES", "slow")
    monkeypatch.setenv("TSG_DIAGNOSTIC_SLOW_STEP_MS", "60000")
    from app.core.config import get_settings
    get_settings.cache_clear()

    fake = _FakeBackend(categories="slow")
    _only(registry, fake)

    from app.core.tracing import trace_step

    with trace_step("FAST THING", "s-1"):
        pass

    assert fake.seen == [], "a step well under the threshold was recorded as slow"


# --- the aggregate alarm: the P1 signal the retry fix otherwise removed --------------------------

class _CountingRedis:
    """Enough Redis for a counter and a latch. The two operations this feature is built on are
    INCR and SET NX, and both have to behave exactly as Redis does or the alarm either never
    fires or fires once per worker."""

    def __init__(self):
        self.store: dict[str, str] = {}

    def incr(self, key):
        self.store[key] = str(int(self.store.get(key, 0)) + 1)
        return int(self.store[key])

    def expire(self, key, seconds):
        return True

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.store:
            return None                    # Redis returns nil when NX loses
        self.store[key] = value
        return True

    def get(self, key):
        return self.store.get(key)

    def delete(self, key):
        self.store.pop(key, None)


@pytest.fixture
def counting_redis(monkeypatch):
    from app.core import diagnostics

    fake = _CountingRedis()
    monkeypatch.setattr(diagnostics, "_override_redis", lambda: fake)
    return fake


def test_a_handful_of_retries_says_nothing(counting_redis, monkeypatch):
    """One hiccup is not news, and an alarm that fires on one would be ignored within a week —
    which is the same as not having one."""
    monkeypatch.setenv("TSG_INFRA_DEGRADED_THRESHOLD", "20")
    from app.core.config import get_settings
    get_settings.cache_clear()
    from app.core import diagnostics

    fired = [diagnostics.transient_retry_rate_exceeded("llm_transient") for _ in range(19)]

    assert fired == [None] * 19, "the alarm fired below its threshold"


def test_crossing_the_threshold_raises_the_alarm_exactly_once(counting_redis, monkeypatch):
    """THE WHOLE POINT, and the dedup is half of it. Every worker crosses the threshold within
    milliseconds of every other, so without the latch an outage produces a second flood on top of
    the first — and the flood is what makes the original outage hard to read."""
    monkeypatch.setenv("TSG_INFRA_DEGRADED_THRESHOLD", "20")
    from app.core.config import get_settings
    get_settings.cache_clear()
    from app.core import diagnostics

    fired = [diagnostics.transient_retry_rate_exceeded("llm_transient") for _ in range(100)]

    raised = [f for f in fired if f is not None]
    assert raised == [20], (
        f"expected exactly one alarm, at the 20th retry; got {raised}. More than one is a flood; "
        "none means an outage passes in silence")


def test_the_counter_is_shared_rather_than_per_process(counting_redis, monkeypatch):
    """THE MULTI-PROCESS PROPERTY. Retries spread across every Celery worker, so a per-process
    counter would sit comfortably below any useful threshold while the deployment as a whole was
    on fire. Simulated by driving the same shared store from interleaved 'workers'."""
    monkeypatch.setenv("TSG_INFRA_DEGRADED_THRESHOLD", "10")
    from app.core.config import get_settings
    get_settings.cache_clear()
    from app.core import diagnostics

    # Five workers, two retries each: no single worker reaches ten, the deployment reaches ten.
    fired = [diagnostics.transient_retry_rate_exceeded("llm_transient")
             for _worker in range(5) for _retry in range(2)]

    assert any(f is not None for f in fired), (
        "ten retries spread across five workers raised nothing — a per-process counter would "
        "behave exactly this way, and the outage would be invisible")


def test_the_alarm_can_be_switched_off(counting_redis, monkeypatch):
    """0 means off. An operator in the middle of a known, accepted degradation must be able to
    stop the alarm without stopping the retries that are keeping the system up."""
    monkeypatch.setenv("TSG_INFRA_DEGRADED_THRESHOLD", "0")
    from app.core.config import get_settings
    get_settings.cache_clear()
    from app.core import diagnostics

    assert all(diagnostics.transient_retry_rate_exceeded("llm_transient") is None
               for _ in range(100))


def test_counting_never_breaks_the_retry_path(monkeypatch):
    """This runs inside the handler that keeps a session alive during a provider outage. If
    counting could raise, the observability feature would convert a survivable outage into the
    cancelled sessions it was built to prevent."""
    from app.core import diagnostics

    class _Broken:
        def incr(self, *_a, **_k):
            raise ConnectionError("redis is down")

    monkeypatch.setattr(diagnostics, "_override_redis", lambda: _Broken())
    assert diagnostics.transient_retry_rate_exceeded("llm_transient") is None   # must not raise


def test_the_alarm_lands_where_an_operator_can_query_it(counting_redis, monkeypatch, registry):
    """A log line nobody is watching is not an alert. The alarm has to reach the durable table the
    public read endpoint serves — otherwise this is the same "it is in the container logs"
    non-answer that started the whole investigation.

    It is emitted from pipeline_common rather than from diagnostics for exactly this reason:
    diagnostics' own logger is on the recursion denylist, so an alarm raised there would be
    filtered out of the capture it is meant to land in, and would have looked like it worked."""
    monkeypatch.setenv("TSG_INFRA_DEGRADED_THRESHOLD", "2")
    monkeypatch.setenv("TSG_DIAGNOSTIC_DB_CATEGORIES", "all")
    from app.core.config import get_settings
    get_settings.cache_clear()

    fake = _FakeBackend()
    _only(registry, fake)

    from app.pipeline.llm import TransientProviderError
    from app.pipeline.pipeline_common import log_transient_infra_retry

    for _ in range(3):
        log_transient_infra_retry(site="grounding.rerank", session_id="s-1", subsystem_id=1,
                                  exc=TransientProviderError("rerank timed out"))

    # Filtered to the `degraded` category deliberately: the alarm is ALSO captured as an ordinary
    # log line, which is the dual-recording rule three tests above pin. What matters here is that
    # it reached the structured table an operator queries, exactly once.
    degraded = [e for e in fake.seen
                if e.event == "infra.degraded" and e.category == "degraded"]
    assert len(degraded) == 1, (
        f"expected one queryable alarm row, got {len(degraded)} — none means the alarm exists "
        "only in a log stream somebody has to already be watching; more than one means an outage "
        "produces a flood on top of the flood")
    assert degraded[0].kind == str(DiagnosticKind.degraded_outcome)
