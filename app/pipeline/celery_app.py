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
    task_postrun,
    task_prerun,
    worker_init,
    worker_process_init,
)

from app.api.admin_jobs import (
    emb_job_channel_key,
    grounding_job_channel_key,
    intel_job_channel_key,
)
from app.core.config import get_settings
from app.core.enums import (
    CeleryJobState,
    RegenGranularity,
    SSEEventType,
    StageStatus,
    TreatmentOutcomeReason,
)
from app.core.logging import configure_logging
from app.db import dal
from app.db.dal import guid
from app.db.engine import db_session
from app.pipeline import cascade, embeddings, grounding, treatment
from app.pipeline.llm import LLMSlotUnavailable, get_llm
from app.pipeline.reaper import clean_up_abandoned_sessions
from app.pipeline.selfcheck import run_self_checks
from app.pipeline.tasks import _process_all_supporting_systems
from app.sse import bus

_s = get_settings()

# Bounded retry for _init_worker's verify_litellm_models() call — see its own comment below.
# Lives in Settings.llm_verify_max_attempts / Settings.llm_verify_retry_backoff_seconds now
# (defaults unchanged: 3 / 5.0).

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
    broker_transport_options={"visibility_timeout": 3600},

    # Global runaway backstop for EVERY task (per-task limits like intel_refresh_feed's 600/660
    # still override). Hard limit = visibility_timeout on purpose: past 3600s the broker
    # redelivers the message anyway, so the original attempt is killed right when its successor
    # becomes possible instead of both running. A killed pipeline task is recoverable by design —
    # claim_stage's CAS + the reaper treat it exactly like a crashed worker, and COMPLETE stages
    # are skipped on the retry. Enforced under gevent via gevent.Timeout (the -P gevent pool's
    # time-limit mechanism); the soft limit fires 5 minutes early where the pool honors it.
    task_soft_time_limit=3300,
    task_time_limit=3600,
    beat_schedule={                    # the reaper must run on a schedule in production
        "reap-stuck-sessions": {"task": "tsg.reap", "schedule": _s.reaper_interval_seconds},
        # THE consumer of the control-mapping retry queue — without it, map_controls' three
        # "leave it for the next run" paths have no next run. See cascade.run_control_map_sweep.
        "map-controls-sweep": {"task": "tsg.map_controls_sweep",
                            "schedule": _s.control_map_sweep_interval_seconds},
        "operational-self-check": {"task": "tsg.self_check", "schedule": _s.self_check_interval_seconds},
        # threat-intel refresh is deliberately NOT scheduled here — see intel_refresh_task's
        # docstring: it is admin-triggered only, same posture as calibrate_grounding_task.
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
        if pool.endswith("prefork"):
            raise RuntimeError(
                "Celery worker started with the prefork pool, but app.pipeline.celery_worker has "
                "already monkey-patched gevent — forking now yields a broken hub per child. "
                "Launch with `-P gevent` (see start.ps1 / docker/compose.prod.yml)."
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


@task_postrun.connect
def _clear_task_context(**_kw) -> None:
    """MANDATORY counterpart to _bind_task_context. The worker runs -P gevent and reuses its
    greenlets, so without an explicit clear the previous task's session_id leaks into the next
    task's log lines — worse than having no session_id at all, because it is wrong rather than
    absent."""
    structlog.contextvars.clear_contextvars()


@celery_app.task(bind=True, name="tsg.run_pipeline",
                autoretry_for=(LLMSlotUnavailable,), retry_backoff=True, max_retries=None)
def run_pipeline_task(self, session_id: str) -> None:
    """Runs the whole pipeline for one session; queued by the API on session creation.
    `self.request.id` is the run id stamped into each claimed stage, so the CAS can tell an
    acks_late redelivery from a fresh run.

    `autoretry_for=(LLMSlotUnavailable,)`: a slot shortage is temporary and the retry resumes via
    claim_stage's CAS. `max_retries=None` — AttemptCount's poison-terminal cap is the real ceiling.
    """
    with db_session() as sess:
        _process_all_supporting_systems(sess, session_id, get_llm(), self.request.id or guid())


@celery_app.task(bind=True, name="tsg.regenerate",
                autoretry_for=(LLMSlotUnavailable,), retry_backoff=True, max_retries=None)
def regenerate_task(self, session_id: str, subsystem_id: int, granularity: str,
                    target_ids: list[str] | list[int] | None, epoch: int, user_note: str | None = None) -> None:
    """Redoes one or more scenarios of a session. Same `autoretry_for` reasoning as above.
    `epoch` is reserved once by the endpoint's session-level CAS and never minted here, so a
    redelivery re-executes at the SAME epoch and the CAS no-ops an already-terminal level."""
    with db_session() as sess:
        session = dal.load_session(sess, session_id)
        if session is None:
            return  # deleted or never existed by the time this task ran
        cascade.run_regeneration(sess, dict(session), subsystem_id, RegenGranularity(granularity),
                                target_ids, epoch, get_llm(), self.request.id or guid(), user_note=user_note)


@celery_app.task(bind=True, name="tsg.next_set",
                autoretry_for=(LLMSlotUnavailable,), retry_backoff=True, max_retries=None)
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
                autoretry_for=(LLMSlotUnavailable,), retry_backoff=True,
                max_retries=_s.admin_embedding_max_retries)
def generate_treatment_plan_task(self, plan_id: str) -> None:
    """One Risk Treatment Plan attempt (docs/RISK_TREATMENT_PLAN_SDD.md §6.2); queued after the
    RUNNING row is committed. A retry (same task id) resumes via claim_plan's own-task branch, so
    a slot-exhausted attempt never wedges the row. No epoch — plan rows are never reused
    (regenerate = supersede + new row), so PlanID itself is the fence.

    The EXHAUSTED attempt parks the row terminally. Bounding the retries alone would only trade
    "retries forever" for "stuck in RUNNING forever, silently" — worse, because the retry traffic
    that would make someone look disappears. Same discrimination as calibrate_grounding_task:
    re-raise while attempts remain, close the row on the last one."""
    task_id = self.request.id or guid()  # ONE value: finish_plan's CAS is fenced on ActiveTaskID,
    #                                      which claim_plan committed under this exact id
    try:
        with db_session() as sess:
            treatment.run_treatment_generation(sess, plan_id, get_llm(), task_id)
    except LLMSlotUnavailable:
        if self.request.retries < self.max_retries:
            raise  # attempts remain — autoretry_for backs off and re-runs
        with db_session() as sess:
            dal.finish_plan(sess, plan_id, status=StageStatus.ERROR, task_id=task_id,
                            error_message="the AI service stayed busy for every attempt — "
                                        "regenerate the plan (POST .../treatment-plan/regenerate)",
                            error_reason=TreatmentOutcomeReason.timed_out)
        from app.core.logging import get_logger  # module idiom: no module-level logger here
        get_logger(__name__).error("treatment.slot_retries_exhausted", plan_id=plan_id,
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


@celery_app.task(name="tsg.intel_refresh")
def intel_refresh_task() -> dict[str, str]:
    """Pull of the open threat-intel feeds into the Mongo `threat_intel` cache. NEVER queued
    automatically — the only triggers are `POST /v1/tsg/threat-intel/feeds/refresh` and
    `POST /v1/tsg/threat-intel/feeds/{feed}/refresh` (both admin-gated). `intel_enabled` no
    longer gates this task; it now only gates whether `_fetch_intel` injects cached intel into
    a scenario-generation prompt (app/pipeline/tasks.py).

    DISPATCHER, not a worker: one `tsg.intel_refresh_feed` job per enabled feed, returning
    {feed: job_id}. The fan-out buys per-feed isolation — a slow or broken feed can't delay the
    others, and each records its own outcome for the per-feed status API."""
    # This module has no module-level logger; a bare `log` raises NameError on every scheduled run
    # AFTER the jobs are dispatched, so the feeds refresh but the dispatcher always ends FAILURE.
    from app.core.logging import get_logger
    from app.intel.fetchers import enabled_feed_names  # local import, mirrors admin-task style

    jobs = {feed: intel_refresh_feed_task.delay(feed).id for feed in enabled_feed_names()}
    get_logger(__name__).info("intel.refresh_dispatched", feeds=list(jobs))
    return jobs


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
    # Bounded so ONE execution can never outlive the `visibility_timeout` (3600s) above. Unlike
    # the pipeline tasks this has no CAS fence: a redelivered copy just re-fetches and re-upserts,
    # so two (then three, hourly) copies of one slow feed run concurrently. Real risk because
    # fetch_ics_advisories issues up to 200 SEQUENTIAL requests with only per-socket timeouts.
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
    from app.intel.fetchers import refresh_one

    job_id = self.request.id
    _publish_intel_job_event(job_id, CeleryJobState.STARTED, feed=feed)
    try:
        count = refresh_one(feed)
    except Exception as exc:
        state = CeleryJobState.FAILURE if self.request.retries >= self.max_retries else CeleryJobState.RETRY
        _publish_intel_job_event(job_id, state, feed=feed, error=str(exc)[:500])
        raise
    _publish_intel_job_event(job_id, CeleryJobState.SUCCESS, feed=feed, item_count=count)
    return count


@celery_app.task(name="tsg.self_check")
def self_check_task() -> list[str]:
    """Periodic operational self-check (tempdb growth, pool saturation, active-session ceiling);
    scheduled by `beat_schedule` above. run_self_checks() already logs every check that fires."""
    with db_session() as sess:
        return run_self_checks(sess)
