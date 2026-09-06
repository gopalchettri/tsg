"""Celery transport wiring — kept separate from the pipeline work.

`acks_late` + the stage CAS make a crash-redelivery safe (finished stages skip, mid-flight
resume); the reaper recovers a session whose worker died so the lock never leaks.
`reject_on_worker_lost` is effectively inert under gevent — it needs a supervisor to notice a
killed *child*, but a SIGKILL takes the single gevent process down whole; `visibility_timeout`
below is the real redelivery mechanism.

NEVER monkey-patch gevent here — the FastAPI app and `celery beat` import this module on
asyncio, where patching select/socket hangs every request. celery_worker.py is the patch-first
entrypoint for `celery worker`.
"""
from __future__ import annotations

import os
import sys
import time

import structlog
from celery import Celery  # type: ignore[import-untyped]
from celery.signals import (  # type: ignore[import-untyped]
    task_failure,
    task_postrun,
    task_prerun,
    task_rejected,
    task_revoked,
    task_unknown,
    worker_init,
    worker_process_init,
)

from app.api.admin_jobs import (
    FAMILY_EMBEDDINGS,
    FAMILY_INTEL,
    emb_job_channel_key,
    grounding_job_channel_key,
    intel_job_channel_key,
    mark_admin_job,
)
from app.core.config import get_settings
from app.core.enums import (
    CeleryJobState,
    RegenGranularity,
    SSEEventType,
    StageStatus,
    TreatmentOutcomeReason,
)
from app.core.logging import configure_logging, get_logger
from app.db import dal
from app.db.dal import guid
from app.db.engine import db_session
from app.pipeline import cascade, embeddings, grounding, treatment
from app.pipeline.llm import LLMSlotUnavailable, get_llm
from app.pipeline.pipeline_common import TRANSIENT_INFRA_ERRORS
from app.pipeline.reaper import clean_up_abandoned_sessions
from app.pipeline.selfcheck import run_self_checks
from app.pipeline.tasks import _process_all_supporting_systems
from app.sse import bus

_s = get_settings()
log = get_logger(__name__)

# Bounded retry for _init_worker's verify_litellm_models() call — see its own comment below.
# Lives in Settings.llm_verify_max_attempts / Settings.llm_verify_retry_backoff_seconds now
# (defaults unchanged: 3 / 5.0).

#: The two queues this app uses. DEFAULT_QUEUE carries everything a user waits on; ADMIN_QUEUE
#: carries the heavy operator jobs listed in task_routes below. Named here, once, because five
#: launch surfaces (start.ps1, two compose files, deploy.yaml, the handbook) and a test all have
#: to agree on the spelling.
def forking_a_patched_process(pool_module: str) -> bool:
    """True only when BOTH conditions of the real hazard hold: the pool forks, AND gevent has
    already patched this process.

    Split out of _init_worker so it can be tested without booting a worker — reaching this line
    for real costs a DB round trip, a transformer load and an LLM probe. It used to test the
    pool alone, which was harmless while everything ran -P gevent and became a boot-killer the
    moment the `admin` queue's worker started running -P prefork on the UNPATCHED celery_app:
    a correctly configured worker refused at startup, with the API still accepting jobs for it.
    """
    if not pool_module.endswith("prefork"):
        return False
    from gevent import monkey

    return bool(monkey.is_module_patched("socket"))


DEFAULT_QUEUE = "celery"
ADMIN_QUEUE = "admin"


celery_app = Celery("tsg", broker=_s.celery_broker_url or _s.redis_url,
                    backend=_s.celery_result_backend or _s.redis_url)
celery_app.conf.update(
    result_expires=_s.result_expires_seconds,
    task_acks_late=True,
    task_reject_on_worker_lost=True,

    # Without this a task a worker is ACTIVELY RUNNING still reports PENDING — a 13-minute
    # embeddings re-embed reads exactly like "nothing ever consumed it" to the status routes
    # (observed live: job f8dd33f8 ran 791s while its poller saw PENDING throughout). One
    # backend write per task start; the STARTED state CeleryJobState documents becomes real.
    task_track_started=True,

    # Reserve only what each slot can RUN, not 4x it. The default multiplier (4) times the
    # `-c 50` every launch path uses (compose.prod.yml serves UAT+prod; start.ps1/run.ps1
    # default to 50 locally) had ONE worker pocketing ~200 minutes-long messages: a
    # scaled-out second worker sat idle behind the hoard, and anything still reserved past
    # visibility_timeout (below) was redelivered to another worker — harmless for the
    # CAS-fenced pipeline stages, real double-work for the two unfenced tasks
    # (import_threat_library, intel_refresh_feed). =1 with task_acks_late is Celery's own
    # documented posture for long-running tasks. Set HERE, like the events below — one
    # source of truth so dev, UAT and prod can never diverge on it.
    worker_prefetch_multiplier=1,

    # Task-lifecycle events. WITHOUT these a worker emits nothing, so Flower (or any other event
    # consumer) shows live workers and an EMPTY task list — the dashboard looks broken when it is
    # actually the producer that is silent. Set HERE, not as `-E` on each launch, so every path
    # (compose.prod.yml, start.ps1, a bare `celery worker`) is covered by one source of truth.
    # Cost is a few extra broker messages per task — negligible against minutes-long LLM stages.
    worker_send_task_events=True,   # worker: task-received/started/succeeded/failed
    task_send_sent_event=True,      # producer (the API): task-sent, so QUEUE latency is visible too
    # NO worker_pool="gevent" here, deliberately: the setting resolves too late for a
    # monkey-patch and celery warns (W_POOL_SETTING) on every boot. -P gevent is passed on every
    # launch path, and the prefork fail-fast in _init_worker covers a bare `celery worker`.

    # How long a message from a genuinely killed worker sits unredelivered. A reasoned starting
    # point, not derived from real P99 session duration (a run can process up to 50 subsystems
    # sequentially). Too short redelivers a still-running task (wasteful; claim_stage's CAS
    # prevents actual double-work), too long leaves an orphaned message idle.
    broker_transport_options={"visibility_timeout": _s.broker_visibility_timeout_seconds},

    # Global runaway backstop for EVERY task (per-task limits like intel_refresh_feed's 600/660
    # still override). Hard limit = visibility_timeout on purpose: past 3600s the broker
    # redelivers the message anyway, so the original attempt is killed right when its successor
    # becomes possible instead of both running. A killed pipeline task is recoverable by design —
    # claim_stage's CAS + the reaper treat it exactly like a crashed worker, and COMPLETE stages
    # are skipped on the retry. Enforced under gevent via gevent.Timeout (the -P gevent pool's
    # time-limit mechanism); the soft limit fires 5 minutes early where the pool honors it.
    # Both are now DERIVED from the same setting as visibility_timeout above, so the "hard limit =
    # visibility_timeout" rule above cannot silently break if that timeout is retuned per
    # environment (defaults unchanged: 3300 / 3600). The two single-subsystem tasks override BOTH
    # with a much tighter budget — see next_set_task / regenerate_task.
    # ---- QUEUE SPLIT -------------------------------------------------------------------
    # These four are CPU- and memory-heavy operator jobs: a 51 MB STIX parse, ~900 local
    # embeddings, a calibration sweep the route itself documents as 10-15 minutes. Sharing one
    # queue with user-facing generation was measured doing real harm -- a technique rebuild
    # dragged live generation from ~355s to 967s AND was itself killed at its 960s limit.
    #
    # They also want a DIFFERENT POOL. gevent is right for the LLM/DB waits that dominate
    # generation and buys nothing for CPU-bound work; the admin worker runs prefork/solo at
    # concurrency 1, which also caps memory to one heavy job at a time.
    #
    # Nothing about the API changes: apply_async reads the queue from here, and the status and
    # event routes look jobs up by id (a Redis marker plus the result backend), neither of which
    # is queue-aware. intel_refresh_feed deliberately STAYS on the default queue -- it is short
    # and I/O-bound, exactly what gevent is for, and beat schedules its fan-out.
    #
    # A route added here without a worker subscribing to that queue is a silent black hole: the
    # API returns 202 and the job never runs. tests/test_queue_routing.py pins the queue set
    # against the launch commands, and /ready reports per queue, so that cannot go unnoticed.
    task_routes={
        "tsg.rebuild_technique_reference": {"queue": ADMIN_QUEUE},
        "tsg.import_threat_library": {"queue": ADMIN_QUEUE},
        "tsg.admin_embedding_action": {"queue": ADMIN_QUEUE},
        "tsg.calibrate_grounding": {"queue": ADMIN_QUEUE},
    },
    task_soft_time_limit=_s.broker_visibility_timeout_seconds - 300,
    task_time_limit=_s.broker_visibility_timeout_seconds,
    beat_schedule={                    # the reaper must run on a schedule in production
        "reap-stuck-sessions": {"task": "tsg.reap", "schedule": _s.reaper_interval_seconds},
        # THE consumer of the control-mapping retry queue — without it, map_controls' three
        # "leave it for the next run" paths have no next run. See cascade.run_control_map_sweep.
        "map-controls-sweep": {"task": "tsg.map_controls_sweep",
                            "schedule": _s.control_map_sweep_interval_seconds},
        "operational-self-check": {"task": "tsg.self_check", "schedule": _s.self_check_interval_seconds},
        # threat-intel refresh is scheduled ONLY when TSG_INTEL_REFRESH_INTERVAL_SECONDS > 0
        # (SDD §33: configured source refresh runs on a scheduler). At 0 — the default — it stays
        # admin-triggered via POST /v1/tsg/threat-intel/feeds/refresh. Either path fans out
        # through dispatch_refresh below, so beat and the API label and track jobs identically.
        **({"intel-refresh": {"task": "tsg.intel_refresh_all",
                              "schedule": _s.intel_refresh_interval_seconds}}
           if _s.intel_refresh_interval_seconds > 0 else {}),
    },
)


@worker_init.connect        # fires exactly once per worker process, for EVERY pool type
@worker_process_init.connect  # fires per forked child under prefork specifically
def _init_worker(sender=None, **_):
    """Per-worker-process startup: verify posture/DB invariants and warm the models.

    BOTH signals are needed: `worker_process_init` is prefork-only and never fires under gevent,
    so without `worker_init` a gevent worker skips the security and local-model guards entirely.
    verify_startup repeats the API's check because a worker can be deployed independently."""
    # worker-only setup: imported here so merely importing this module (e.g. from FastAPI)
    # doesn't drag it in
    import gevent

    from app.core.config import assert_security_posture
    from app.db.engine import get_engine
    from app.db.invariants import verify_startup
    from app.pipeline.llm import log_litellm_key_info, verify_litellm_models
    from app.pipeline.local_models import validate_local_models

    configure_logging()
    # Set here, not at module import — the FastAPI app imports this module and must stay "api".
    embeddings.process_role = "worker"
    # Fail-fast on prefork, the one pool that FORKS: celery_worker.py monkey-patches gevent at
    # import time, so forking after that hands every child an inherited hub — silent,
    # intermittent hangs rather than a clean error. -P solo never forks and stays allowed.
    # CELERY SWALLOWS EXCEPTIONS RAISED IN SIGNAL RECEIVERS. celery.utils.dispatch.signal.send
    # catches whatever a receiver raises, logs "Signal handler ... raised", and carries on — so
    # every guard below was ADVISORY despite saying "fail-closed", and a worker that failed one
    # went on to report `ready` and pull tasks. Worse, the raise aborted the REST of this
    # handler, so a single failed guard also silently skipped the DB invariants, the gevent
    # threadpool sizing and the local-model warm-up.
    #
    # Anything meant to stop the worker therefore has to stop the PROCESS. sys.exit is no good
    # either: SystemExit is a BaseException, and the receiver dispatch catches it just the same.
    try:
        pool = getattr(getattr(sender, "pool_cls", None), "__module__", "")
        # The hazard is prefork AFTER gevent has been patched -- forking a patched process gives
        # every child a broken hub. It is NOT prefork itself. This used to test only the pool,
        # which was harmless while every worker ran -P gevent, and became a boot-killer the
        # moment the `admin` queue's worker started running -P prefork with the UNPATCHED
        # celery_app: correct configuration, refused at startup, jobs accepted and never run.
        # Ask the actual question.
        if forking_a_patched_process(pool):
            raise RuntimeError(
                "Celery worker started with the prefork pool in a process where gevent is "
                "already monkey-patched (-A app.pipeline.celery_worker) — forking now yields a "
                "broken hub per child. Either launch with `-P gevent`, or use the unpatched "
                "`-A app.pipeline.celery_app` for a prefork/solo worker (see the admin worker "
                "in docker/compose.prod.yml)."
            )
        assert_security_posture()      # fail-closed: same auth guard as the API
        verify_startup(get_engine())   # fail-fast: same DB invariant guard as the API
        # local_models.py::_offload runs on gevent's native thread pool, sized independently of
        # -c/--concurrency and otherwise capped at gevent's own default of 10. Set BEFORE
        # validate_local_models warms the models, so the ceiling holds from the first call.
        gevent.get_hub().threadpool.size = get_settings().local_model_threadpool_size
        validate_local_models(warm=True)   # fail-fast + warm so the 1st request is fast
        # MUST stay inside this same try: verify_litellm_models' own comment below already
        # claimed "fail-fast: same discipline" as the checks above it — it just wasn't actually
        # wrapped by the guard that discipline depends on. A raise anywhere between the `try:`
        # above and the `except` below now shares one enforcement point instead of two, so this
        # bug class (a fail-fast claim outside the only mechanism that makes it true) cannot
        # reopen by a future check being appended after the except block by mistake.
        verify_max_attempts = get_settings().llm_verify_max_attempts
        verify_backoff = get_settings().llm_verify_retry_backoff_seconds
        # verify_litellm_models goes through the same _llm_slot limiter as a real task, but this
        # signal handler is not a @celery_app.task, so autoretry_for never applies — several
        # replicas booting at once would raise LLMSlotUnavailable straight out of worker startup.
        for attempt in range(verify_max_attempts):
            try:
                verify_litellm_models()    # fail-fast, for whichever models route through the proxy
                break
            except LLMSlotUnavailable:
                if attempt == verify_max_attempts - 1:
                    raise
                time.sleep(verify_backoff * (attempt + 1))
    except BaseException as exc:  # noqa: BLE001 — deliberate: the point is that NOTHING escapes
        # this handler alive. Narrowing it would let some failure mode through to a worker that
        # then reports ready, which is the exact defect being fixed.
        from app.core.logging import get_logger
        get_logger(__name__).critical("worker.boot_guard_failed", error=repr(exc), exc_info=True)
        # Flush before _exit: os._exit skips atexit handlers and buffered stream teardown, and a
        # boot failure nobody can read is worse than the boot failure.
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.flush()
            except Exception:  # noqa: BLE001 — never mask the real failure with a flush error
                pass
        os._exit(1)
    log_litellm_key_info()             # observability only, never raises
    # Report the grounding threshold — READ-ONLY, and it queues NOTHING.
    #
    # This used to CALIBRATE here, and it was the single worst thing on the boot path. Every
    # receiver of `worker_init` runs BEFORE the consumer blueprint connects, so the worker is
    # invisible to `inspect ping` for the whole of it. Measured on this checkout: the sweep took
    # a rock-steady ~106s on top of a 9-94s model load, against start.ps1's 180s readiness
    # budget — a warm boot squeaked in at ~115s, a cold one missed at ~213s. Worse, the sweep
    # ABORTED every time (one near-duplicate library pair vetoed the old hard margin) and stored
    # nothing, so the next boot paid the same ~106s for the same nothing, forever.
    #
    # Boot cannot re-acquire that behaviour by accident: resolve_thresholds has no calibrate
    # switch left to set. Calibration is an explicit admin action
    # (POST /v1/tsg/grounding/calibrate) — a sweep costs 10-15 minutes and ~100 billed LLM calls,
    # which is not something a process restart should be able to trigger on its own.
    #
    # An uncalibrated pair is announced, loudly, and then served on the static default:
    # resolve_thresholds deliberately does not memoize that fallback, so the moment an admin
    # calibrates, this worker picks the real value up on its next resolve with no restart.
    from app.core.logging import get_logger
    from app.pipeline.grounding import resolve_thresholds
    try:
        with db_session() as sess:
            th = resolve_thresholds(sess, get_llm())
        if th.origin == "static_default":
            get_logger(__name__).warning(
                "grounding.threshold_uncalibrated", match_th=th.value,
                embedding_model=_s.embedding_model, reranker_model=_s.reranker_model,
                note="NO calibration stored for this embedding+reranker pair. Grounding will use "
                    "the static default, which was tuned for a DIFFERENT pair and may "
                    "misclassify. Run POST /v1/tsg/grounding/calibrate when ready — this worker "
                    "picks the result up automatically, no restart needed.")
        else:
            get_logger(__name__).info("grounding.threshold_resolved", match_th=th.value,
                                    origin=th.origin)
    except Exception:  # noqa: BLE001 — advisory only; the pipeline resolves lazily either way
        get_logger(__name__).warning("grounding.threshold_read_failed", exc_info=True)


def _publish_grounding_job_event(job_id: str | None, state: CeleryJobState, **fields) -> None:
    """Best-effort SSE hint for admin.py::calibration_events subscribers — same contract as
    _publish_emb_job_event: bus.publish's breaker applies, the endpoint's AsyncResult backstop
    covers a lost publish, and no job id (a synchronous call in tests) is a no-op."""
    if not job_id:
        return
    bus.publish(grounding_job_channel_key(job_id),
                {"type": str(SSEEventType.grounding_job_update), "job_id": job_id,
                "state": str(state), **fields})


# max_retries bounded for the same reason as admin_embedding_action_task: a permanent slot
# exhaustion must not retry a MULTI-MINUTE sweep forever. Reuses that cap rather than inventing
# a second knob for the identical failure mode.
@celery_app.task(bind=True, name="tsg.calibrate_grounding",
                autoretry_for=(LLMSlotUnavailable,), retry_backoff=True,
                max_retries=_s.admin_embedding_max_retries)
def calibrate_grounding_task(self, force: bool = False, started_by: str | None = None,
                            client_id: str | None = None, run_id: str | None = None) -> dict:
    """Measure the grounding match threshold for the CURRENT embedding+reranker pair and record
    the run. NEVER queued automatically — the only trigger is POST /v1/tsg/grounding/calibrate.

    `run_id` is the ledger row the ROUTE already opened. The route opens it, not this task,
    because that INSERT is what the filtered unique index arbitrates: opening it here would put
    the guard behind the broker, where a duplicate request has already been accepted with a 202
    and there is nobody left to answer 409. Called without one (a direct `.delay()`, or a test),
    the task opens its own.

    `started_by`/`client_id` are the acting identity carried over the broker — the only reason
    the caller survives the hop into the worker. `started_by` is claimed (an unverified header);
    `client_id` is the authenticated API client. Both are recorded, neither is conflated.

    `force=True` re-measures even though this pair already has a successful run — the way to
    refresh a calibration after curating the library. Without it an already-calibrated pair is a
    no-op, because a sweep costs 10-15 minutes and ~100 billed LLM calls.

    A run that finds no signal is a task SUCCESS with match_th=null, recorded as `no_signal`: it
    measured correctly and the answer is "this model pair cannot separate them". That is a
    finding about the models, not a task failure, and conflating the two would send whoever reads
    it to the wrong place."""
    job_id = self.request.id
    _publish_grounding_job_event(job_id, CeleryJobState.STARTED, force=force, run_id=run_id)
    s = get_settings()
    key = (s.embedding_model, s.reranker_model)

    if not force:
        with db_session() as sess:
            existing = grounding.latest_successful_run(sess, key)
        if existing is not None:
            out = {"match_th": existing, "quality": None, "run_id": run_id,
                "embedding_model": key[0], "reranker_model": key[1],
                "skipped": "already_calibrated"}
            # Close the row the route opened — otherwise a skipped run sits `running` until the
            # stale window expires and blocks the next real calibration behind the unique index.
            # Recorded as `skipped`, NOT success: nothing was measured here. Writing a success row
            # (with a fabricated quality=0.0 and zero counts, as this once did) would put a
            # calibration that never happened into the audit trail — the exact falsehood the
            # ledger exists to prevent — and would read as a sweep that separated nothing.
            if run_id:
                grounding.record_calibration_finished(run_id, skipped=existing)
            _publish_grounding_job_event(job_id, CeleryJobState.SUCCESS, **out)
            return out

    if run_id is None:  # direct .delay() or a test — see the docstring
        run_id = grounding.record_calibration_started(
            key, job_id=job_id, started_by=started_by, started_by_client=client_id, forced=force)

    def _tick(phase: str, done: int, total: int) -> None:
        # One publish per sample would be hundreds of events on a multi-minute job; ~5% steps
        # keep the stream readable. The terminal event below is the load-bearing one.
        if total and (done == total or done % max(1, total // 20) == 0):
            _publish_grounding_job_event(job_id, CeleryJobState.STARTED,
                                        phase=phase, done=done, total=total, run_id=run_id)

    try:
        with db_session() as sess:
            result = grounding.calibrate(sess, get_llm(), s, progress=_tick)
    except BaseException as exc:
        # DO NOT close the row while a retry is still coming. Celery's autoretry wrapper sits
        # OUTSIDE this function and re-runs the SAME task id with the SAME argv — so `run_id` is
        # already set on the next attempt, `if run_id is None` above is False, and NO new
        # `running` row is opened. Closing here would therefore leave
        # UX_GroundingCalibration_Running with nothing to arbitrate for the whole retry: a
        # concurrent POST /calibrate would INSERT cleanly, answer 202 instead of 409, and a second
        # 10-15 minute ~100-billed-call sweep would run beside this one. Worse, this run's
        # eventual success UPDATEs by RunID with no status predicate and would flip the recorded
        # `failed` back to `success`, erasing the failure from the audit trail.
        #
        # LLMSlotUnavailable is an ORDINARY outcome here (a sweep issues ~100 billed chat calls),
        # so this is the common path, not a corner. Leave the row `running` while attempts remain
        # — settle_abandoned_runs' stale window still covers a genuinely killed worker — and
        # report RETRY, not a terminal FAILURE that would tear down SSE subscribers early. Only
        # the exhausted attempt closes the row. Same discrimination intel_refresh_feed_task uses.
        if isinstance(exc, LLMSlotUnavailable) and self.request.retries < self.max_retries:
            _publish_grounding_job_event(job_id, CeleryJobState.RETRY, run_id=run_id)
            raise
        grounding.record_calibration_finished(run_id, error=repr(exc))
        _publish_grounding_job_event(job_id, CeleryJobState.FAILURE, run_id=run_id,
                                    error=repr(exc))
        raise

    # ONE write: the measured value is a column of the record of the measurement, so there is no
    # "measured but not saved" window — and record_calibration_finished RAISES rather than
    # swallowing when the status is success, so a lost write fails the task instead of reporting
    # a number nobody stored. Storing the value separately is what previously let a finished
    # 15-minute sweep lose its answer to a Mongo blip and leave only a log line.
    grounding.record_calibration_finished(run_id, result=result)
    # No memo to invalidate: resolve_thresholds reads the ledger on every resolve, precisely so a
    # re-calibration reaches OTHER worker processes too — which popping a local dict never could.

    out = {**result._asdict(), "run_id": run_id,
        "embedding_model": key[0], "reranker_model": key[1]}
    from app.core.logging import get_logger
    get_logger(__name__).warning("grounding.calibration_complete", job_id=job_id, **out)
    _publish_grounding_job_event(job_id, CeleryJobState.SUCCESS, **out)
    return out


@task_prerun.connect
def _bind_task_context(task_id=None, task=None, args=None, **_kw) -> None:
    """Bind the session onto the LOG CONTEXT once per task, so every line the worker emits
    carries it without each call site passing it by hand.

    This is what makes worker logs filterable in Loki: `| json | session_id="..."` only works if
    the field is actually on the line, and today it is present only where somebody remembered to
    add it. Bound HERE, at the one place every task passes through, rather than at each task body.

    Every pipeline task takes session_id as its first positional argument; anything that does not
    simply binds no session, which is correct rather than wrong.
    """
    structlog.contextvars.bind_contextvars(
        task_id=task_id, task_name=getattr(task, "name", None))
    if args:
        structlog.contextvars.bind_contextvars(session_id=str(args[0]))


# --- Terminal-outcome visibility -------------------------------------------------------------
# WHY THESE EXIST. A task could previously leave the worker with NO record of its death: a
# next-set task was seen logging "received", running to its last stage write, and then producing
# nothing at all — no succeeded, no failed, no traceback — while the worker stayed healthy. The
# only evidence it ever ran was a `_LOCK` row it never released. Without a terminal signal there
# is nothing to alert on and nothing to debug from, so the four ways a task can end badly each get
# a log line here. `shadow=` renames tasks in Celery's own INFO lines, so `sender.name` is recorded
# explicitly — grepping for "tsg.next_set" in the raw log finds nothing.
def _session_of(args) -> str | None:
    """Every pipeline task takes session_id first; anything else simply has none."""
    return str(args[0]) if args else None


@task_failure.connect
def _log_task_failure(sender=None, task_id=None, exception=None, args=None, einfo=None, **_kw) -> None:
    """A task raised out of its body. Celery logs this too, but without session_id."""
    from app.core.logging import get_logger
    get_logger(__name__).error(
        "task.failed", task_name=getattr(sender, "name", None), task_id=task_id,
        session_id=_session_of(args), error=repr(exception), exc_info=einfo)


@task_revoked.connect
def _log_task_revoked(sender=None, request=None, terminated=None, signum=None, expired=None, **_kw) -> None:
    """A task was revoked — including reaper._revoke_zombie_tasks killing a frozen greenlet, which
    is the expected path for a task whose lease lapsed. `terminated` distinguishes a kill from a
    revoke-before-start; `expired` from the broker's own expiry."""
    from app.core.logging import get_logger
    get_logger(__name__).warning(
        "task.revoked", task_name=getattr(sender, "name", None),
        task_id=getattr(request, "id", None), session_id=_session_of(getattr(request, "args", None)),
        terminated=terminated, signum=str(signum), expired=expired)


@task_rejected.connect
def _log_task_rejected(sender=None, message=None, exc=None, **_kw) -> None:
    """The worker could not accept a message at all — it never became a task, so no other handler
    here will ever fire for it."""
    from app.core.logging import get_logger
    get_logger(__name__).error("task.rejected", error=repr(exc), message=repr(message)[:500],
                            exc_info=exc is not None)


@task_unknown.connect
def _log_task_unknown(sender=None, name=None, id=None, message=None, exc=None, **_kw) -> None:
    """A message named a task this worker does not have registered — a deploy skew, and otherwise
    completely silent: the sender got its 202 and nothing ever runs."""
    from app.core.logging import get_logger
    get_logger(__name__).error("task.unknown", task_name=name, task_id=id, error=repr(exc),
                            message=repr(message)[:500])


@task_postrun.connect
def _clear_task_context(**_kw) -> None:
    """MANDATORY counterpart to _bind_task_context. The worker runs -P gevent and reuses its
    greenlets, so without an explicit clear the previous task's session_id leaks into the next
    task's log lines — worse than having no session_id at all, because it is wrong rather than
    absent."""
    structlog.contextvars.clear_contextvars()


@celery_app.task(bind=True, name="tsg.run_pipeline",
                autoretry_for=(LLMSlotUnavailable, *TRANSIENT_INFRA_ERRORS),
                retry_backoff=True, max_retries=None)
def run_pipeline_task(self, session_id: str) -> None:
    """Runs the whole pipeline for one session; queued by the API on session creation.
    `self.request.id` is the run id stamped into each claimed stage, so the CAS can tell an
    acks_late redelivery from a fresh run.

    `autoretry_for`: a slot shortage or a transient DB error (TRANSIENT_INFRA_ERRORS —
    deadlock, connection reset) is temporary and the retry resumes via claim_stage's CAS.
    `max_retries=None` — AttemptCount's poison-terminal cap is the real ceiling.
    """
    with db_session() as sess:
        _process_all_supporting_systems(sess, session_id, get_llm(), self.request.id or guid())


# soft/time limits OVERRIDE the global ~55 minute pair: this task handles ONE subsystem and
# finishes in minutes, so the global budget let a frozen greenlet hold its `_LOCK` for the best
# part of an hour. Derived per environment (see Settings._derive_subsystem_task_limits) because no
# constant is right in both dev (720s lease) and UAT (2880s). The soft limit is what matters — it
# raises INSIDE the greenlet, so cascade._subsystem_lock's `finally` runs and the lock is released
# properly; the hard limit is only the backstop if the soft signal is ignored.
@celery_app.task(bind=True, name="tsg.regenerate",
                autoretry_for=(LLMSlotUnavailable, *TRANSIENT_INFRA_ERRORS),
                retry_backoff=True, max_retries=None,
                soft_time_limit=_s.subsystem_task_soft_limit_seconds,
                time_limit=_s.subsystem_task_hard_limit_seconds)
def regenerate_task(self, session_id: str, subsystem_id: int, granularity: str,
                    target_ids: list[str] | list[int] | None, epoch: int) -> None:
    """Redoes one or more scenarios of a session. Same `autoretry_for` reasoning as above.
    `epoch` is reserved once by the endpoint's session-level CAS and never minted here, so a
    redelivery re-executes at the SAME epoch and the CAS no-ops an already-terminal level."""
    with db_session() as sess:
        session = dal.load_session(sess, session_id)
        if session is None:
            return  # deleted or never existed by the time this task ran
        cascade.run_regeneration(sess, dict(session), subsystem_id, RegenGranularity(granularity),
                                target_ids, epoch, get_llm(), self.request.id or guid())


# Same per-subsystem limit override and the same reasoning as regenerate_task above. THIS is the
# task that hung in the field: it settled its SCENARIOS stage, then stopped without releasing the
# `_LOCK` or finalising the session, and nothing forced it out for the rest of the worker's life.
@celery_app.task(bind=True, name="tsg.next_set",
                autoretry_for=(LLMSlotUnavailable, *TRANSIENT_INFRA_ERRORS),
                retry_backoff=True, max_retries=None,
                soft_time_limit=_s.subsystem_task_soft_limit_seconds,
                time_limit=_s.subsystem_task_hard_limit_seconds)
def next_set_task(self, session_id: str, subsystem_id: int, epoch: int, threats_epoch: int) -> None:
    """Adds the next batch of unique, accumulating scenarios for one subsystem. Same
    `autoretry_for` and caller-reserved `epoch` reasoning as above. `threats_epoch` is the
    additive-find_threats epoch, also endpoint-reserved and held fixed here, so a redelivery
    skips a second AI call once that stage is COMPLETE at it."""
    with db_session() as sess:
        session = dal.load_session(sess, session_id)
        if session is None:
            return  # deleted or never existed by the time this task ran
        cascade.run_next_set(sess, dict(session), subsystem_id, epoch, threats_epoch,
                            get_llm(), self.request.id or guid())


# max_retries BOUNDED (and shared with the other slot-shortage tasks, same as
# calibrate_grounding_task): unlike run_pipeline/next_set/regenerate above, a plan row has NO
# AttemptCount column, so `max_retries=None` here had no ceiling at all — PlanID fences DUPLICATES,
# it does not count attempts. A sustained provider 429 retried forever and pinned the row RUNNING.
@celery_app.task(bind=True, name="tsg.generate_treatment_plan",
                autoretry_for=(LLMSlotUnavailable, *TRANSIENT_INFRA_ERRORS), retry_backoff=True,
                max_retries=_s.admin_embedding_max_retries)
def generate_treatment_plan_task(self, plan_id: str) -> None:
    """One Risk Treatment Plan attempt (docs/RISK_TREATMENT_PLAN_SDD.md §6.2); queued after the
    RUNNING row is committed. A retry (same task id) resumes via claim_plan's own-task branch, so
    a slot-exhausted OR transient-infra-interrupted attempt never wedges the row. No epoch — plan
    rows are never reused (regenerate = supersede + new row), so PlanID itself is the fence.

    The EXHAUSTED attempt parks the row terminally. Bounding the retries alone would only trade
    "retries forever" for "stuck in RUNNING forever, silently" — worse, because the retry traffic
    that would make someone look disappears. Same discrimination as calibrate_grounding_task:
    re-raise while attempts remain, close the row on the last one. Both exhaustion branches use
    TreatmentOutcomeReason.generation_failed ("retryable as-is") — NEVER timed_out, which
    api.treatment._present_status computes only as a read-time projection over a still-RUNNING
    row with a stalled clock; a row this branch closes is already ERROR, so writing timed_out
    here would persist a value the column's own contract says has no writer."""
    task_id = self.request.id or guid()  # ONE value: finish_plan's CAS is fenced on ActiveTaskID,
    #                                      which claim_plan committed under this exact id
    try:
        with db_session() as sess:
            treatment.run_treatment_generation(sess, plan_id, get_llm(), task_id)
    except (LLMSlotUnavailable, *TRANSIENT_INFRA_ERRORS) as exc:
        if self.request.retries < self.max_retries:
            raise  # attempts remain — autoretry_for backs off and re-runs
        transient = isinstance(exc, TRANSIENT_INFRA_ERRORS)
        message = ("a database issue interrupted every attempt — regenerate the plan "
                "(POST .../treatment-plan/regenerate)" if transient else
                "the AI service stayed busy for every attempt — regenerate the plan "
                "(POST .../treatment-plan/regenerate)")
        with db_session() as sess:
            dal.finish_plan(sess, plan_id, status=StageStatus.ERROR, task_id=task_id,
                            error_message=message,
                            error_reason=TreatmentOutcomeReason.generation_failed)
        from app.core.logging import get_logger  # module idiom: no module-level logger here
        get_logger(__name__).error("treatment.retries_exhausted", plan_id=plan_id,
                                transient_infra=transient, error_class=type(exc).__name__,
                                retries=self.request.retries, exc_info=True)
        raise


def _publish_emb_job_event(job_id: str | None, state: CeleryJobState, **fields) -> None:
    """Best-effort SSE hint for admin.py::job_events subscribers — bus.publish's breaker
    applies, and the endpoint's own AsyncResult backstop covers a publish that never arrives,
    so a lost event costs one poll interval, never correctness. No-op without a job id: the
    task body is callable synchronously (tests) where no Celery request id exists."""
    if not job_id:
        return
    bus.publish(emb_job_channel_key(job_id),
                {"type": str(SSEEventType.embedding_job_update), "job_id": job_id,
                "state": str(state), **fields})


# max_retries: bounded (TSG_ADMIN_EMBEDDING_MAX_RETRIES, default 10 — see config.py), NOT None
# like the pipeline tasks above: those have AttemptCount's poison-terminal cap as their real
# ceiling — this task has no such fence, so a permanent slot exhaustion would otherwise retry
# forever. Once the cap is spent Celery re-raises and the job goes FAILURE, which the status
# route's AsyncResult backstop surfaces to the poller. Decorator-time read, like the beat
# schedule's _s.* intervals above — a changed .env needs a worker restart to take effect.
@celery_app.task(bind=True, name="tsg.admin_embedding_action",
                autoretry_for=(LLMSlotUnavailable,), retry_backoff=True,
                max_retries=_s.admin_embedding_max_retries)
def admin_embedding_action_task(self, action: str, group: str | None, names: list[str] | None,
                                strict: bool = True) -> dict:
    """Background counterpart to app/api/admin.py's four embedding-cache routes; the caller polls
    GET .../status/{job_id} (durable truth) or streams GET .../events/{job_id} (live hints:
    STARTED, per-group progress, terminal state — published here, per-job channel).

    `create`/`update` are idempotent on retry (they only embed what's missing). `recreate`
    re-wipes and re-embeds every group in scope from scratch — wasted work, not a correctness bug.
    ponytail: accepted; revisit only if recreate is ever run against a much larger library.
    """
    job_id = self.request.id
    _publish_emb_job_event(job_id, CeleryJobState.STARTED, action=action)

    def _done(g: str, rows: int) -> int:
        # Fires as soon as fn(g) RETURNS, not once its write is durable — a multi-group sweep
        # (group=None) shares ONE db_session() across every group, committed once at the very
        # end, so a LATER group hitting EmbeddingBusy (a real per-group lock conflict,
        # _for_each_group re-raises it) rolls back everything, including a group this already
        # announced as done. Safe to leave as-is: this is a STARTED-scoped progress tick, never
        # the terminal event — the SAME hint-layer contract SSEEventType documents for
        # next_set_result/regen_result/treatment_plan_result applies here. The one claim that
        # must be durable, the terminal SUCCESS below, IS: it only fires after its db_session()
        # block has already exited (committed).
        _publish_emb_job_event(job_id, CeleryJobState.STARTED, action=action, group=g, rows=rows)
        return rows

    try:
        if action == "delete":
            # `strict` ON means "a name that matched nothing is an error" — right for the admin
            # route, where a typed name CAN be a typo. It is now always ON in practice: the one
            # caller that passed it OFF was the library CRUD API (deleted), which fed in names
            # from a row it had just renamed or soft-deleted, so strict reported FAILURE for a
            # delete that had nothing left to do. Kept as a parameter because this task is
            # reachable outside the route (Flower, tests) — see the create branch below.
            with db_session() as sess:
                out = {"vectors_deleted": embeddings._for_each_group(
                    group, lambda g: _done(g, embeddings.delete_group(sess, g, names, strict=strict)))}
        elif action == "create":
            # create_items can't fan out over "every group" like its siblings. The API route
            # enforces this too, but the task is reachable outside it (Flower, tests).
            if not group or not names:
                raise ValueError("create requires both group and names")
            with db_session() as sess:
                out = {"rows_processed": {group: _done(group, embeddings.create_items(
                    sess, get_llm(), group, names))}}
        elif action == "update":
            llm = get_llm()
            with db_session() as sess:
                out = {"rows_processed": embeddings._for_each_group(
                    group, lambda g: _done(g, embeddings.update_group(sess, llm, g)))}
        elif action == "recreate":
            llm = get_llm()
            with db_session() as sess:
                out = {"rows_processed": embeddings._for_each_group(
                    group, lambda g: _done(g, embeddings.recreate_group(sess, llm, g, names)))}
        else:
            raise ValueError(f"unknown admin embedding action: {action!r}")
    except LLMSlotUnavailable:
        # autoretry path — the SAME task id runs again; RETRY, never FAILURE, or a subscriber
        # would tear down on a job that is merely waiting for an LLM slot.
        _publish_emb_job_event(job_id, CeleryJobState.RETRY, action=action)
        raise
    except Exception as e:
        _publish_emb_job_event(job_id, CeleryJobState.FAILURE, action=action, error=str(e)[:500])
        raise
    _publish_emb_job_event(job_id, CeleryJobState.SUCCESS, action=action, **out)
    return out


@celery_app.task(name="tsg.reap")
def reap_task() -> list[str]:
    """Periodic stuck-job reaper; scheduled by `beat_schedule` above — run `celery beat` alongside
    the worker. clean_up_abandoned_sessions() already logs the cancelled set."""
    with db_session() as sess:
        return clean_up_abandoned_sessions(sess)



@celery_app.task(name="tsg.map_controls_sweep")
def map_controls_sweep_task() -> list[str]:
    """Periodic control-mapping retry sweep; scheduled by `beat_schedule` above.

    Unlike the reaper this one calls the model (grounding reranks), so it is bounded per tick by
    `control_mapping.SWEEP_LIMIT` and takes the per-subsystem lock — a slow tick must not starve
    foreground scenario generation of worker slots. run_control_map_sweep logs what it swept."""
    with db_session() as sess:
        return cascade.run_control_map_sweep(sess, get_llm())


def _publish_intel_job_event(job_id: str | None, state: CeleryJobState, **fields) -> None:
    """Best-effort SSE hint for threat_intel.py::job_events subscribers — same hint-layer
    contract as _publish_emb_job_event above. No-op without a job id: the task body is callable
    synchronously (tests) where no Celery request id exists."""
    if not job_id:
        return
    bus.publish(intel_job_channel_key(job_id),
                {"type": str(SSEEventType.intel_job_update), "job_id": job_id,
                "state": str(state), **fields})


@celery_app.task(
    bind=True,
    name="tsg.intel_refresh_feed",
    autoretry_for=(Exception,),
    retry_backoff=True,          # 1s, 2s, 4s … so a transient 5xx recovers on its own
    retry_backoff_max=300,
    retry_jitter=True,           # spread retries so five feeds can't sync into a thundering herd
    max_retries=3,
    # Bounded so ONE execution can never outlive the `visibility_timeout` (3600s) above. A
    # per-feed job_lock in the body (TTL = time_limit) keeps a redelivered or double-clicked
    # copy from walking the same feed alongside the first.
    soft_time_limit=600,         # raises SoftTimeLimitExceeded — refresh_one records it per feed
    time_limit=660,              # hard backstop if a fetch ignores the soft signal
)
def intel_refresh_feed_task(self, feed: str) -> int:
    """Refresh exactly ONE intel feed; returns the item count.

    Deliberately allowed to RAISE (unlike most tasks here) — the retry policy above is the point.
    `refresh_one` records the failure to the feed's status doc BEFORE re-raising, so the outcome
    survives an exhausted retry chain and an expired Celery result.

    `bind=True` only to read self.request.retries below — autoretry_for=(Exception,) means
    EVERY exception here is retried up to max_retries, so a flat except-publish-FAILURE would
    publish a false terminal state on a transient attempt that later succeeds, closing a
    subscriber's SSE stream early (job_events' terminal check). retries >= max_retries is the
    one case Celery's own autoretry wrapper will NOT retry again after this exception, so only
    THAT case is the real terminal FAILURE; every earlier attempt is a non-terminal RETRY hint,
    same distinction admin_embedding_action_task draws for LLMSlotUnavailable above."""
    from app.core.joblock import job_lock
    from app.intel.fetchers import RefreshAlreadyRunning, refresh_one
    from app.pipeline.llm import _slot_redis

    job_id = self.request.id
    _publish_intel_job_event(job_id, CeleryJobState.STARTED, feed=feed)
    try:
        # The lock lives HERE, not in the route (it returns 202 before this runs). TTL is the
        # hard time_limit, so a killed run can never hold a feed longer than it could have run.
        # Fails open when Redis is down (core.joblock): this guards redundant OTX/CISA traffic
        # and cursor clobbering, never correctness -- the upserts are idempotent.
        with job_lock(f"tsg:intel-refresh:{feed}", ttl=self.time_limit,
                    busy=RefreshAlreadyRunning(f"a refresh of {feed!r} is already running"),
                    redis_factory=_slot_redis):
            count = refresh_one(feed)
    except RefreshAlreadyRunning as exc:
        log.warning("intel.refresh_already_running", feed=feed)
        _publish_intel_job_event(job_id, CeleryJobState.FAILURE, feed=feed, error=str(exc)[:500])
        return 0
    except Exception as exc:
        state = CeleryJobState.FAILURE if self.request.retries >= self.max_retries else CeleryJobState.RETRY
        _publish_intel_job_event(job_id, state, feed=feed, error=str(exc)[:500])
        raise
    _publish_intel_job_event(job_id, CeleryJobState.SUCCESS, feed=feed, item_count=count)
    return count


@celery_app.task(
    bind=True,
    name="tsg.import_threat_library",
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_backoff_max=300,
    retry_jitter=True,
    max_retries=3,
    soft_time_limit=900,   # ATLAS costs two hops and CAPEC-sized payloads parse slowly
    time_limit=960,
)
def import_threat_library_task(self, source: str, dry_run: bool, activate: bool,
                            max_actors: int, user_id: str | None) -> dict:
    """Import ONE open-source threat library into the master tables.

    A ThreatLibraryImportError is TERMINAL and returned, never raised: it means the request or
    the fetched content is invalid, which no amount of retrying fixes, and `autoretry_for=
    (Exception,)` above would otherwise burn three attempts on a permanent failure. Everything
    else (a 5xx from GitHub, a dropped DB connection) DOES raise, so the retry policy applies —
    the same split intel_refresh_feed_task draws between transient and terminal.

    Never lets SystemExit escape: Celery reads one inside task code as a worker-shutdown signal,
    so an invalid request could otherwise kill every in-flight job on this worker (see
    app/intel/library_import.py's module docstring)."""
    from app.core.joblock import job_lock
    from app.db.engine import db_session
    from app.intel.library_import import (
        LOCK_TTL_SECONDS,
        ImportAlreadyRunning,
        ThreatLibraryImportError,
        lock_key,
        run_import,
    )
    from app.pipeline.llm import _slot_redis

    job_id = self.request.id
    _publish_intel_job_event(job_id, CeleryJobState.STARTED, source=source)
    try:
        # The lock lives HERE, not in the route: the route returns 202 and this runs later, so a
        # lock taken and released during the request would guard nothing. Fails open when Redis
        # is down (core.joblock) -- this guards redundant downloads and DB traffic, never
        # correctness, since the upserts are first-writer either way.
        with job_lock(lock_key(source), ttl=LOCK_TTL_SECONDS,
                    busy=ImportAlreadyRunning(
                        f"an import of {source!r} is already running"),
                    redis_factory=_slot_redis), db_session() as sess:
            result = run_import(sess, source, dry_run=dry_run, activate=activate,
                                max_actors=max_actors, started_by=user_id)
    except ThreatLibraryImportError as exc:
        result = {"source": source, "dry_run": dry_run, "error": str(exc)[:2000]}
        _publish_intel_job_event(job_id, CeleryJobState.FAILURE, source=source,
                                error=result["error"])
        return result
    except Exception as exc:
        state = CeleryJobState.FAILURE if self.request.retries >= self.max_retries else CeleryJobState.RETRY
        _publish_intel_job_event(job_id, state, source=source, error=str(exc)[:500])
        raise

    # Vectors LAST, and only after activation: embeddings._catalogue_texts selects on
    # tc.IsActive AND tt.IsActive (the warm set is deliberately the query set), so embedding
    # before activating silently skips every imported row and still reports success. Chaining it
    # here is what makes that ordering impossible to get wrong by hand. group=None covers
    # threat_type, threat_catalogue and threat_actor in one job; `update` skips anything that
    # already has a vector, so the extra groups cost nothing.
    if not dry_run and not result.get("error"):
        try:
            embed = admin_embedding_action_task.apply_async(args=("update", None, None), shadow=(
                f"embeddings update after {source} import · {dal.now():%Y-%m-%d %H:%M} UTC"))
            mark_admin_job(embed.id, FAMILY_EMBEDDINGS, "embeddings update", user_id)
            result["embedding_job_id"] = embed.id
        except Exception:
            log.warning("library_import.embedding_chain_failed", source=source, exc_info=True)
            result["embedding_job_id"] = None

    _publish_intel_job_event(job_id, CeleryJobState.SUCCESS, source=source,
                            threats=result.get("threats"), actors=result.get("actors_upserted"))
    return result


#: How long the technique rebuild may spend warming embedding vectors, and in what batch size.
#:
#: THE BUDGET ARITHMETIC, because the old limits were sized for a job this one no longer is.
#: 960s was chosen for "download and parse"; the embedding warm-up was added to the same task
#: later and never accounted for, and that mismatch killed every rebuild. Three changes make
#: 900/960 correct rather than merely unchanged:
#:   1. the corpus is PUBLISHED BEFORE warming, so a kill can no longer discard it;
#:   2. the sources are STREAMED, so build is ~15s measured (was a 51 MB whole-file parse);
#:   3. warming self-limits to the budget below.
#: Worst case is therefore ~615s of work (15 + 600) inside a 900s soft / 960s hard limit —
#: real headroom, derived, not guessed. Raise the budget, not the limits, if warming needs
#: longer; the limits only have to stay above it.
#:
#: On the `admin` queue's prefork pool the SOFT limit also fires for real. It silently never
#: does on gevent, which is why the best-effort `except` around the warm-up never got to run.
_TECHNIQUE_WARM_BUDGET_SECONDS = 600
_TECHNIQUE_WARM_BATCH = 32


@celery_app.task(
    bind=True,
    name="tsg.rebuild_technique_reference",
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_backoff_max=300,
    retry_jitter=True,
    max_retries=3,
    soft_time_limit=900,
    time_limit=960,
)
def rebuild_technique_reference_task(self, sources: list[str], user_id: str | None) -> dict:
    """Rebuild the ATT&CK/CAPEC technique corpus scenario prompts consult.

    Same terminal-vs-transient split as import_threat_library_task: a ThreatLibraryImportError
    means the request or the fetched content is invalid, which retrying cannot fix, so it is
    returned rather than raised.

    PUBLISHES FIRST, then warms the embedding vectors within whatever time budget is left. The
    warm-up still happens inside this job -- its cost and failures belong to an operator, not to
    whichever user happens to trigger the first scenario after a rebuild -- but it can no longer
    take the corpus down with it.

    It used to warm BEFORE publishing, and that lost every rebuild on a CPU-only box. Three
    facts compound: an uncached local embed measures 4-6.6s per passage here, so ~900 passages
    need 60-99 minutes; `soft_time_limit` DOES NOT FIRE on the gevent pool, so the best-effort
    `except` below never got a chance to run; and `time_limit` then hard-killed the task at 960s.
    Because publish() came last, a corpus that had built correctly in 15 seconds was discarded
    every single time -- the exact opposite of the "an un-warmed corpus still works" intent
    stated below. Publishing first makes that intent true instead of aspirational."""
    from app.intel.library_import import ThreatLibraryImportError
    from app.intel.technique_reference import COLLECTION, build_entries, passage_text, publish

    job_id = self.request.id
    _publish_intel_job_event(job_id, CeleryJobState.STARTED, sources=sources)
    try:
        entries, skipped = build_entries(sources)
    except ThreatLibraryImportError as exc:
        result = {"sources": sources, "error": str(exc)[:2000]}
        _publish_intel_job_event(job_id, CeleryJobState.FAILURE, error=result["error"])
        return result
    except Exception as exc:
        state = CeleryJobState.FAILURE if self.request.retries >= self.max_retries else CeleryJobState.RETRY
        _publish_intel_job_event(job_id, state, error=str(exc)[:500])
        raise

    # Durable FIRST: everything below is best-effort and must never risk the corpus.
    built_at = dal.now()
    total = publish(entries, built_at)

    _publish_intel_job_event(job_id, CeleryJobState.STARTED, stage="embedding",
                            total=len(entries))
    warmed = None
    try:
        from app.core.config import get_settings as _gs
        from app.pipeline.embeddings import get_vectors
        from app.pipeline.llm import get_llm

        limit = _gs().max_embed_chars
        texts = [passage_text(e, limit) for e in entries]
        # Warm in batches against a DEADLINE rather than in one call. The hard time limit is the
        # only limit that fires on the gevent pool, and it kills the task outright -- so the work
        # has to stop itself before then, or the job reports FAILURE for a rebuild that actually
        # succeeded. Partial warming is a real outcome, reported as such in `warmed`.
        deadline = time.monotonic() + _TECHNIQUE_WARM_BUDGET_SECONDS
        llm, model_id = get_llm(), _gs().embedding_model
        warmed = 0
        for i in range(0, len(texts), _TECHNIQUE_WARM_BATCH):
            if time.monotonic() > deadline:
                log.warning("technique_reference.warm_budget_exhausted",
                            warmed=warmed, total=len(texts))
                break
            batch = texts[i:i + _TECHNIQUE_WARM_BATCH]
            get_vectors(llm, batch, model_id=model_id, group=COLLECTION, kind="passage")
            warmed += len(batch)
    except Exception:
        # Best-effort: an un-warmed corpus still works, the first lookup just pays for the
        # embedding. Never a reason to withhold a corpus that built correctly.
        log.warning("technique_reference.warm_failed", exc_info=True)

    result = {"sources": sources, "total": total, "warmed": warmed,
            "skipped_count": len(skipped), "built_at": str(built_at)}
    log.info("technique_reference.rebuilt", user_id=user_id, **{k: result[k]
            for k in ("sources", "total", "skipped_count")})
    _publish_intel_job_event(job_id, CeleryJobState.SUCCESS, total=total)
    return result


def dispatch_refresh(feeds: list[str], user_id: str | None) -> dict[str, str]:
    """Queue one intel_refresh_feed job per feed — THE fan-out, shared by the admin API
    (threat_intel._dispatch) and intel_refresh_all_task so both paths label and track jobs
    identically. One job per feed rather than one job for all, so a slow or broken feed can
    neither delay nor fail the others. No entity_id in the shadow label: cross-tenant by
    design. Returns feed -> job id."""
    jobs: dict[str, str] = {}
    for feed in feeds:
        task = intel_refresh_feed_task.apply_async(args=(feed,), shadow=(
            f"intel-refresh: {feed} · by {user_id} · {dal.now():%Y-%m-%d %H:%M} UTC"))
        mark_admin_job(task.id, FAMILY_INTEL, f"intel-refresh: {feed}", user_id)  # best-effort — see admin_jobs.mark_admin_job
        jobs[feed] = task.id
    return jobs


@celery_app.task(name="tsg.intel_refresh_all")
def intel_refresh_all_task() -> dict[str, str]:
    """Beat entry point (TSG_INTEL_REFRESH_INTERVAL_SECONDS > 0): refresh every enabled feed
    exactly as the admin route does. Cheap — it only enqueues; the per-feed jobs do the work."""
    from app.intel.fetchers import enabled_feed_names

    jobs = dispatch_refresh(enabled_feed_names(), user_id="beat")
    log.info("intel.scheduled_refresh_dispatched", jobs=jobs)
    return jobs


@celery_app.task(name="tsg.self_check")
def self_check_task() -> list[str]:
    """Periodic operational self-check (tempdb growth, pool saturation, active-session ceiling);
    scheduled by `beat_schedule` above. run_self_checks() already logs every check that fires.
    Also the SDD SOURCE_STALE signal for live intel: an enabled feed with no successful refresh
    inside TSG_INTEL_STALE_AFTER_SECONDS is logged so monitoring can alert on it."""
    with db_session() as sess:
        fired = run_self_checks(sess)
    try:
        from app.intel.fetchers import feed_status

        for f in feed_status():
            if f["stale"]:
                last_ok = f["last_success_at"]
                log.warning("intel.feed_stale", feed=f["feed"],
                            last_success_at=last_ok.isoformat() if last_ok else None,
                            last_error=f["last_error"])
                fired.append(f"intel.feed_stale:{f['feed']}")
    except Exception:  # a self-check never breaks the self-check
        log.warning("intel.stale_check_failed", exc_info=True)
    return fired
