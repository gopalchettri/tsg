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

import time

from celery import Celery, current_task  # type: ignore[import-untyped]
from celery.signals import worker_init, worker_process_init  # type: ignore[import-untyped]

from app.api.admin_jobs import emb_job_channel_key, import_job_channel_key, intel_job_channel_key
from app.core.config import get_settings
from app.core.enums import CeleryJobState, RegenGranularity, SSEEventType
from app.core.logging import configure_logging
from app.db import dal
from app.db.dal import guid
from app.db.engine import db_session
from app.pipeline import cascade, embeddings, treatment
from app.pipeline.llm import LLMSlotUnavailable, get_llm
from app.pipeline.reaper import clean_up_abandoned_sessions, retry_failed_promotions
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
    beat_schedule={                    # the reaper must run on a schedule in production
        "reap-stuck-sessions": {"task": "tsg.reap", "schedule": _s.reaper_interval_seconds},
        "retry-failed-promotions": {"task": "tsg.retry_promotions",
                                    "schedule": _s.promotion_retry_interval_seconds},
        "operational-self-check": {"task": "tsg.self_check", "schedule": _s.self_check_interval_seconds},
        # live threat-intel refresh — opt-in (TSG_INTEL_ENABLED); absent entirely when off
        **({"intel-refresh": {"task": "tsg.intel_refresh", "schedule": _s.intel_refresh_interval_seconds}}
        if _s.intel_enabled else {}),
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
    pool = getattr(getattr(sender, "pool_cls", None), "__module__", "")
    if pool.endswith("prefork"):
        raise RuntimeError(
            "Celery worker started with the prefork pool, but app.pipeline.celery_worker has "
            "already monkey-patched gevent — forking now yields a broken hub per child. "
            "Launch with `-P gevent` (see start.ps1 / docker/compose.prod.yml)."
        )
    assert_security_posture()          # fail-closed: same auth guard as the API
    verify_startup(get_engine())       # fail-fast: same DB invariant guard as the API
    # local_models.py::_offload runs on gevent's native thread pool, sized independently of
    # -c/--concurrency and otherwise capped at gevent's own default of 10. Set BEFORE
    # validate_local_models warms the models, so the ceiling holds from the first call.
    gevent.get_hub().threadpool.size = get_settings().local_model_threadpool_size
    validate_local_models(warm=True)   # fail-fast + warm the local models so the 1st request is fast
    verify_max_attempts = get_settings().llm_verify_max_attempts
    verify_backoff = get_settings().llm_verify_retry_backoff_seconds
    # verify_litellm_models goes through the same _llm_slot limiter as a real task, but this
    # signal handler is not a @celery_app.task, so autoretry_for never applies — several replicas
    # booting at once would raise LLMSlotUnavailable straight out of worker startup.
    for attempt in range(verify_max_attempts):
        try:
            verify_litellm_models()    # fail-fast: same discipline, for whichever models route through the proxy
            break
        except LLMSlotUnavailable:
            if attempt == verify_max_attempts - 1:
                raise
            time.sleep(verify_backoff * (attempt + 1))
    log_litellm_key_info()             # observability only, never raises
    # Warm the per-model-pair grounding thresholds OUTSIDE any stage lease: the first resolution
    # for a new embedding+reranker pair auto-calibrates (a bounded paraphrase+scoring pass), which
    # at boot is a one-time deploy cost but inside find_threats would burn lease time.
    # allow_calibration=True ONLY here, so the expensive pass can never run in a leased stage.
    # Best-effort: on failure workers resolve lazily later, at worst on the static defaults.
    from app.pipeline.grounding import resolve_thresholds
    for attempt in range(verify_max_attempts):
        try:
            with db_session() as sess:
                resolve_thresholds(sess, get_llm(), allow_calibration=True)
            break
        except LLMSlotUnavailable:
            if attempt == verify_max_attempts - 1:
                from app.core.logging import get_logger
                get_logger(__name__).warning("grounding.threshold_warmup_slots_exhausted")
                break
            time.sleep(verify_backoff * (attempt + 1))
        except Exception:  # noqa: BLE001 — warm-up only; never blocks worker boot
            from app.core.logging import get_logger
            get_logger(__name__).warning("grounding.threshold_warmup_failed", exc_info=True)
            break


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


@celery_app.task(bind=True, name="tsg.generate_treatment_plan",
                autoretry_for=(LLMSlotUnavailable,), retry_backoff=True, max_retries=None)
def generate_treatment_plan_task(self, plan_id: str) -> None:
    """One Risk Treatment Plan attempt (docs/RISK_TREATMENT_PLAN_SDD.md §6.2); queued after the
    RUNNING row is committed. A retry (same task id) resumes via claim_plan's own-task branch, so
    a slot-exhausted attempt never wedges the row. No epoch — plan rows are never reused
    (regenerate = supersede + new row), so PlanID itself is the fence."""
    with db_session() as sess:
        treatment.run_treatment_generation(sess, plan_id, get_llm(), self.request.id or guid())


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


@celery_app.task(bind=True, name="tsg.admin_embedding_action",
                autoretry_for=(LLMSlotUnavailable,), retry_backoff=True, max_retries=None)
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
            # `strict` stays ON for the admin route (a typed name CAN be a typo) and is turned OFF by
            # library_crud.py, whose names come from a row it just renamed or soft-deleted — no longer
            # ACTIVE, so strict made every such edit report FAILURE for a delete with nothing to do.
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
    except Exception as e:  # noqa: BLE001 — publish the terminal hint, then let Celery record FAILURE
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


@celery_app.task(name="tsg.retry_promotions")
def retry_promotions_task() -> list[str]:
    """Periodic library-promotion retry sweep; scheduled by `beat_schedule` above.
    retry_failed_promotions() already logs what it retried (and no-ops, logging why, when
    promotion_auto_retry_enabled is off)."""
    with db_session() as sess:
        return retry_failed_promotions(sess)


@celery_app.task(name="tsg.intel_refresh")
def intel_refresh_task() -> dict[str, str]:
    """Scheduled pull of the open threat-intel feeds into the Mongo `threat_intel` cache. Gated
    by `intel_enabled`.

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
    except Exception as exc:  # noqa: BLE001 — publish a hint, then let autoretry_for decide
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


def _publish_import_job_event(job_id: str | None, state: CeleryJobState, **fields) -> None:
    """Best-effort SSE hint for threat_library_import.py::job_events subscribers — same
    hint-layer contract as _publish_emb_job_event above (bus.publish's breaker applies, the
    endpoint's own AsyncResult backstop covers a lost publish). No-op without a job id: the
    task body is callable synchronously (tests) where no Celery request id exists."""
    if not job_id:
        return
    bus.publish(import_job_channel_key(job_id),
                {"type": str(SSEEventType.import_job_update), "job_id": job_id,
                "state": str(state), **fields})


@celery_app.task(name="tsg.import_threat_library")
def import_threat_library_task(source: str, file_content: str | None, via_taxii: bool,
                            max_actors: int, dry_run: bool, started_by: str | None = None) -> dict:
    """Background counterpart to app/api/threat_library_import.py: runs the same run_import the
    CLI script drives, then (real runs only) dispatches the embeddings refresh.

    ORDERING IS LOAD-BEARING: the import commits inside its OWN db_session block first, and the
    embeddings dispatch happens strictly after that block exits — otherwise the embeddings task's
    fresh session reads a snapshot without the new rows. A SEPARATE job, so a late embeddings
    failure can never roll back a successful import. No autoretry_for (no LLM calls); a
    crash-redelivery is safe because every write path is a natural-key upsert.

    ponytail: file_content rides the Redis broker as a plain (size-capped) string — move to a
    shared blob store + a reference argument if much larger bundles are ever needed."""
    from app.api.admin_jobs import FAMILY_EMBEDDINGS, mark_admin_job  # local import, mirrors admin-task style
    from app.pipeline import threat_library_import

    # ties the history row to the job the status route polls; None when called directly
    job_id = getattr(getattr(current_task, "request", None), "id", None)
    _publish_import_job_event(job_id, CeleryJobState.STARTED, source=source)
    # started_by lands in Threat_Library_Import_Run.StartedBy AND CreatedBy on every row this run
    # creates; run_import falls back to 'auto:<tag>' when there is no caller.
    run_id = threat_library_import.record_import_started(source, dry_run=dry_run, job_id=job_id,
                                                        started_by=started_by)
    try:
        with db_session() as sess:
            stats = threat_library_import.run_import(
                sess, source, file_content=file_content, via_taxii=via_taxii,
                max_actors=max_actors, dry_run=dry_run, started_by=started_by)
    except Exception as exc:  # noqa: BLE001 — record the failure, then let Celery mark FAILURE
        # Own transaction, outside the rolled-back import session: a failed import that left no
        # trace is the case an operator most needs to see.
        threat_library_import.record_import_finished(run_id, error=f"{type(exc).__name__}: {exc}")
        _publish_import_job_event(job_id, CeleryJobState.FAILURE, source=source,
                                error=f"{type(exc).__name__}: {exc}"[:500])
        raise
    threat_library_import.record_import_finished(run_id, stats=stats)
    if not dry_run and source != "misp_actors":
        # The import is ALREADY COMMITTED here, so a failed dispatch must not mark the job
        # FAILURE — that reports an applied import as failed and invites a redundant re-run over
        # a transient broker blip. Degrade instead: say the refresh still needs running.
        try:
            embed_job = admin_embedding_action_task.delay("update", None, None)
            # Without the marker the returned id 404s on /embeddings/status — the marker is that
            # route's authorization check.
            mark_admin_job(embed_job.id, FAMILY_EMBEDDINGS)
            stats["embeddings_job_id"] = embed_job.id
        except Exception:  # noqa: BLE001 — the committed import is the job's real outcome
            from app.core.logging import get_logger
            get_logger(__name__).warning("threat_library_import.embeddings_dispatch_failed",
                                        source=source, exc_info=True)
            stats["embeddings_job_id"] = None
            stats["warning"] = ((stats.get("warning", "") + " ") if stats.get("warning") else "") + (
                "import committed, but the follow-up embeddings refresh could not be queued — "
                "run POST /v1/tsg/threat-library/embeddings/update, or the new rows stay "
                "unmatchable by grounding")
    # stats already carries "source" (run_import sets it) — no source= kwarg here, or this
    # collides as a duplicate keyword argument.
    _publish_import_job_event(job_id, CeleryJobState.SUCCESS, **stats)
    return stats
