"""Boot guards: what must stop the worker PROCESS, plus the scheduling and dependency gates.

THE DEFECT PINNED HERE. celery.utils.dispatch.signal.send CATCHES whatever a receiver raises,
logs "Signal handler ... raised", and continues. So every guard in _init_worker, commented
"fail-closed", was advisory: the worker logged the error, reported `ready`, and pulled tasks.
The raise also aborted the rest of the handler, silently skipping verify_startup and the
local-model warm-up. Anything meant to stop the worker therefore has to stop the PROCESS —
which is what the os._exit test below exercises end to end rather than by reading the source.
"""
from __future__ import annotations

import pytest

from app.core import config as cfg


def test_unverified_llm_model_also_kills_the_process(monkeypatch):
    """THE regression this test exists to pin. verify_litellm_models' own comment claimed
    "fail-fast: same discipline" as the checks above it, but its retry loop was left OUTSIDE
    the try/except BaseException block -- so a misconfigured/unreachable litellm proxy raised
    straight into Celery's signal dispatch, which swallows it, and the worker reported ready
    anyway with an unverified model. Now moved inside the same guard; this proves it stays
    there by actually exercising the failure through _init_worker end to end, not just reading
    the source."""
    from app.pipeline import celery_app

    class _Exited(Exception):
        pass

    def _fake_exit(code):
        raise _Exited(code)

    monkeypatch.setattr(celery_app.os, "_exit", _fake_exit)
    monkeypatch.setattr("app.db.invariants.verify_startup", lambda *a, **k: None)
    monkeypatch.setattr("app.pipeline.local_models.validate_local_models", lambda *a, **k: None)
    monkeypatch.setattr("app.pipeline.llm.verify_litellm_models",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("proxy unreachable")))

    with pytest.raises(_Exited) as caught:
        celery_app._init_worker(sender=None)
    assert caught.value.args[0] == 1, "an unverified model must exit non-zero, not report ready"


def test_intel_refresh_is_scheduled_only_by_an_explicit_interval():
    """threat-intel fetching is admin-triggered (POST /v1/tsg/threat-intel/feeds/refresh and
    .../feeds/{feed}/refresh) UNLESS TSG_INTEL_REFRESH_INTERVAL_SECONDS > 0, in which case beat
    runs the same fan-out on that period (SDD §33: configured source refresh on a scheduler).
    beat_schedule is built at import from Settings, so the check pins the entry to the live
    setting: absent at 0, present with exactly the configured period otherwise. intel_enabled
    only gates prompt injection (tasks.py::_fetch_intel), never scheduling."""
    from app.core.config import get_settings
    from app.pipeline import celery_app

    interval = get_settings().intel_refresh_interval_seconds
    entry = celery_app.celery_app.conf.beat_schedule.get("intel-refresh")
    if interval > 0:
        assert entry == {"task": "tsg.intel_refresh_all", "schedule": interval}
    else:
        assert entry is None


def test_beat_gates_are_pinned_on_both_sides():
    """Both gated entries, in BOTH states.

    The previous version read the LIVE setting and branched on it, so under the default (enabled)
    the `assert entry is None` arm never executed in CI — an off-branch regression would have
    shipped silently, and off is precisely the state about to be relied on across four
    environments. `_build_beat_schedule` exists so both arms are reachable without reloading
    celery_app, which would re-register every task."""
    from app.core.config import Settings
    from app.pipeline.celery_app import _build_beat_schedule

    on = _build_beat_schedule(Settings(_env_file=None, control_map_sweep_enabled=True,
                                       control_map_sweep_interval_seconds=300.0,
                                       intel_refresh_interval_seconds=86400))
    off = _build_beat_schedule(Settings(_env_file=None, control_map_sweep_enabled=False,
                                        intel_refresh_interval_seconds=0))

    # map-controls-sweep is NO LONGER gated here, and that is the fix, not a regression. Reading
    # control_map_sweep_enabled in this builder made it a BOOT-TIME decision: the schedule is
    # built once at import, so flipping the variable changed nothing until beat itself was
    # restarted — a switch that did not switch. The gate moved into map_controls_sweep_task,
    # which re-reads it every tick (see the two tests below). The entry must therefore be present
    # in BOTH schedules; if it ever vanishes from `off` again, the setting has silently gone back
    # to being unusable without a beat restart.
    for schedule in (on, off):
        assert schedule["map-controls-sweep"]["task"] == "tsg.map_controls_sweep"
    assert on["map-controls-sweep"]["schedule"] == 300.0
    assert on["intel-refresh"] == {"task": "tsg.intel_refresh_all", "schedule": 86400}
    assert "intel-refresh" not in off
    # An ungated entry must survive both ways — a gate must never take the reaper with it.
    for schedule in (on, off):
        assert schedule["reap-stuck-sessions"]["task"] == "tsg.reap"
        assert schedule["operational-self-check"]["task"] == "tsg.self_check"


def test_live_beat_schedule_is_the_builders_output():
    """Ties the pure builder to the real Celery config. Without this the test above could pin a
    function nothing actually uses — the failure mode that let canonical_types sit dead in this
    same codebase until it was found by accident."""
    from app.core.config import get_settings
    from app.pipeline import celery_app

    assert celery_app.celery_app.conf.beat_schedule == \
        celery_app._build_beat_schedule(get_settings())


# --- The installed-dependency guard -------------------------------------------------------
# Found live: the API on :8000 had been launched with the GLOBAL interpreter instead of the
# project venv, so it served sse_starlette 3.0.3 against code written for >=3.4.6. Nothing
# noticed. Import succeeded, boot succeeded, /ready reported database/redis/mongo/workers all
# "ok" -- and all three admin job streams (embeddings, grounding calibration, threat-intel
# refresh) returned an opaque 500 on EVERY request, because EventSourceResponse.__init__ had no
# `shutdown_grace_period` parameter. A version-pin in pyproject.toml cannot catch that: the
# wrong interpreter never reads it. Only the running process can answer the question.


class _OldEventSourceResponse:
    """Stands in for sse_starlette < 3.4: no ping_message_factory, send_timeout or
    shutdown_grace_period."""

    def __init__(self, content, status_code=200, headers=None, media_type=None, ping=None):
        pass


def test_too_old_sse_starlette_refuses_to_boot():
    with pytest.raises(RuntimeError, match="shutdown_grace_period"):
        cfg.assert_sse_library_supports_our_calls(_OldEventSourceResponse)


def test_the_error_names_the_wrong_interpreter_as_the_likely_cause():
    """The failure mode is a mis-launched process, not a bad pin -- so the message has to point
    the reader at sys.prefix. Told "unexpected keyword argument" alone, the natural (and wrong)
    conclusion is that the code is broken."""
    with pytest.raises(RuntimeError, match="interpreter"):
        cfg.assert_sse_library_supports_our_calls(_OldEventSourceResponse)


def test_the_installed_sse_starlette_actually_satisfies_the_guard():
    """The other half: the guard must pass against what this environment really has, or it is a
    tripwire that only ever cries wolf."""
    cfg.assert_sse_library_supports_our_calls()


def test_the_sweep_task_declines_every_tick_while_disabled(monkeypatch):
    """The gate in its NEW home, for the SCHEDULED caller only. Beat always schedules the sweep
    now, so the task is the only thing that can honour TSG_CONTROL_MAP_SWEEP_ENABLED — and it must
    do so without paying for a tick it will not run: no DB session, no model, no lock. Anything
    else turns "disabled" into a connection and a reranker load every interval, forever."""
    from types import SimpleNamespace

    from app.pipeline import celery_app as ca

    def _never(*_a, **_k):
        raise AssertionError("a disabled tick opened a resource")
    monkeypatch.setattr(ca, "get_settings",
                        lambda: SimpleNamespace(control_map_sweep_enabled=False))
    monkeypatch.setattr(ca, "db_session", _never)
    monkeypatch.setattr(ca, "get_llm", _never)

    assert ca.map_controls_sweep_task(scheduled=True) == []


def test_the_sweep_task_runs_when_enabled(monkeypatch):
    """The other arm — the gate must not be a permanent off switch. Both arms are pinned because
    the previous version of this gate had only one reachable in CI, which is exactly how it came
    to be wrong."""
    from contextlib import contextmanager
    from types import SimpleNamespace

    from app.pipeline import celery_app as ca

    @contextmanager
    def _sess():
        yield "session"
    monkeypatch.setattr(ca, "get_settings",
                        lambda: SimpleNamespace(control_map_sweep_enabled=True))
    monkeypatch.setattr(ca, "db_session", _sess)
    monkeypatch.setattr(ca, "get_llm", lambda: "llm")
    monkeypatch.setattr(ca.cascade, "run_control_map_sweep", lambda s, llm: ["swept-1"])

    assert ca.map_controls_sweep_task() == ["swept-1"]


def test_a_manual_sweep_runs_while_the_schedule_is_disabled(monkeypatch):
    """THE REGRESSION THIS SHAPE EXISTS FOR, and the one an adversarial audit caught after the
    suite did not. The gate first landed on the TASK, and both manual drains publish that same
    task — so POST /v1/tsg/control-map/sweep and the documented
    `celery ... call tsg.map_controls_sweep` silently returned [] whenever the setting was off.
    A no-op in the exact state they exist for, and a regression of the CLI path, which had no
    gate at all before. The decline now belongs to the SCHEDULED tick: a caller that does not
    claim to be beat always runs, by construction rather than by a second code path."""
    from contextlib import contextmanager
    from types import SimpleNamespace

    from app.pipeline import celery_app as ca

    @contextmanager
    def _sess():
        yield "session"
    monkeypatch.setattr(ca, "get_settings",
                        lambda: SimpleNamespace(control_map_sweep_enabled=False))
    monkeypatch.setattr(ca, "db_session", _sess)
    monkeypatch.setattr(ca, "get_llm", lambda: "llm")
    monkeypatch.setattr(ca.cascade, "run_control_map_sweep", lambda s, llm: ["drained-1"])

    # The default — what the admin route and a bare `celery call` produce.
    assert ca.map_controls_sweep_task() == ["drained-1"]
    # ...while beat's own tick, which marks itself, still declines.
    assert ca.map_controls_sweep_task(scheduled=True) == []


def test_beat_marks_its_own_tick_as_scheduled():
    """Without this kwarg the flag governs NOTHING: the task only declines for a scheduled
    caller, so an entry that omits it would sweep every interval no matter what the setting says.
    The gate and the entry are two halves of one mechanism."""
    from app.core.config import Settings
    from app.pipeline.celery_app import _build_beat_schedule

    entry = _build_beat_schedule(Settings(_env_file=None))["map-controls-sweep"]
    assert entry["kwargs"] == {"scheduled": True}, entry
