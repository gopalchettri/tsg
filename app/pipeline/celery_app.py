""" this file connects the web server to the background workers
through a job queue (Celery) — it does NOT do any AI work itself, it just says
"here's a job, go run it" and "here's how to check for crashed sessions."

Celery transport wiring — kept separate from the pipeline work.

`acks_late` + `reject_on_worker_lost` mean a worker crash redelivers the task; the
stage Compare-And-Swap (CAS) makes that safe (finished stages skip, mid-flight resume). The
reaper recovers a session whose worker died so the lock never leaks.

`reject_on_worker_lost`'s own requeue signal is effectively inert under `worker_pool="gevent"`
(set below): it relies on a supervising process detecting a killed *child* — the prefork
model this app does NOT use. A SIGKILL of the single gevent worker process takes down the
Consumer, connection, and every in-flight greenlet at once, leaving nothing alive to
reject/requeue anything. Redelivery for THIS deployment's actual pool type depends entirely
on the Redis broker's own `visibility_timeout` below — that, not this flag, is the real
recovery mechanism when a worker is killed outright rather than raising inside a task.

This module does NOT monkey-patch gevent, even though the worker runs a gevent pool
(celery_worker.py) — it is also imported directly by the FastAPI app (for
run_pipeline_task.delay()/regenerate_task.delay()) and by celery beat, both of
which run on asyncio, not gevent. gevent's monkey-patch rewrites select/socket at
the process level; doing that inside an asyncio process corrupts its own I/O loop —
reproduced live as every POST /v1/sessions hanging forever once patching briefly
lived here. celery_worker.py is the real, patch-first entrypoint for celery worker;
this module stays patch-free and safe for every process that imports it.
"""
from __future__ import annotations

import time

from celery import Celery  # type: ignore[import-untyped]
from celery.signals import worker_init, worker_process_init  # type: ignore[import-untyped]

from app.core.config import get_settings
from app.core.enums import RegenGranularity
from app.core.logging import configure_logging
from app.db import dal
from app.db.dal import guid
from app.db.engine import db_session
from app.pipeline import cascade, embeddings
from app.pipeline.llm import LLMSlotUnavailable, get_llm
from app.pipeline.reaper import clean_up_abandoned_sessions
from app.pipeline.selfcheck import run_self_checks
from app.pipeline.tasks import _process_all_supporting_systems

_s = get_settings()

# Bounded retry for _init_worker's verify_litellm_models() call — see its own comment below.
_LLM_VERIFY_MAX_ATTEMPTS = 3
_LLM_VERIFY_RETRY_BACKOFF_SECONDS = 5.0

celery_app = Celery("tsg", broker=_s.celery_broker_url or _s.redis_url,
                    backend=_s.celery_result_backend or _s.redis_url)
celery_app.conf.update(
    result_expires=_s.result_expires_seconds,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    # NO worker_pool="gevent" here, deliberately: celery/worker/components.py warns
    # (W_POOL_SETTING) on every boot when a green pool comes from the SETTING rather than -P,
    # because the setting resolves too late for a monkey-patch to be applied early enough. We
    # patch at import time in celery_worker.py and pass -P gevent on every launch path
    # (start.ps1, docker/compose.prod.yml, both run-books, README), so the setting was pure
    # noise. Its one real job — making a bare `celery worker` pick gevent rather than prefork
    # (celery/bin/worker.py falls back to conf.worker_pool only when -P is absent) — is now
    # covered by the prefork fail-fast in _init_worker below.

    # Redis/Kombu's own default (~3600s) was previously left implicit — made explicit here so
    # it's a deliberate, documented, easily-tunable value instead of an invisible library
    # default. This bounds how long a message from a genuinely killed worker sits unredelivered
    # (see the docstring above); it's a reasoned starting point, not derived from real session-
    # duration data (a run can process up to 50 subsystems sequentially — see schemas.py's
    # _MAX_BATCH — so there's no tight, safe lower bound without knowing this deployment's real
    # P99 session duration). Setting it too short risks Celery redelivering a still-legitimately-
    # running task (wasteful, though claim_stage's CAS prevents actual double-work); too long
    # leaves an orphaned message idle longer. _process_all_supporting_systems' own REVIEW-stage
    # guard is the real safety net against a late redelivery mutating a session a human is
    # already reviewing — this timeout only bounds how long that guard might need to matter for.
    broker_transport_options={"visibility_timeout": 3600},
    beat_schedule={                    # the reaper must run on a schedule in production
        "reap-stuck-sessions": {"task": "tsg.reap", "schedule": _s.reaper_interval_seconds},
        "operational-self-check": {"task": "tsg.self_check", "schedule": _s.self_check_interval_seconds},
        # live threat-intel refresh — opt-in (TSG_INTEL_ENABLED); absent entirely when off
        **({"intel-refresh": {"task": "tsg.intel_refresh", "schedule": _s.intel_refresh_interval_seconds}}
        if _s.intel_enabled else {}),
    },
)


@worker_init.connect        # fires exactly once per worker process, for EVERY pool type
@worker_process_init.connect  # fires per forked child under prefork specifically 
def _init_worker(sender=None, **_):
    """ runs once, right when a worker process starts up, to
    double-check its settings are safe and to pre-load the AI models so the
    very first real request doesn't have to wait for that loading.

    `worker_process_init` is prefork-only (fires per forked child) — it NEVER
    fires under the gevent pool (`-P gevent`), which is what this service
    actually runs. Without `worker_init` (fires once for any pool, before
    the pool even starts), a gevent worker would silently skip the fail-closed
    security-posture guard and the fail-fast local-model check entirely — the same
    root cause `configure_logging`'s own eager-import-time fix addresses for logging.

    verify_startup is included here too, not just in the API's startup hook (main.py)
    — a worker can be deployed as its own process, independently of the API, and
    would otherwise never check that the database it's about to run CAS writes and
    stage locking against actually has the required indexes/columns/RCSI setting."""
    # imported here (not at the top of the file) so this worker-only setup code only
    # loads when a worker process actually starts, not whenever any other process
    # (e.g. the FastAPI app) merely imports this module
    from app.core.config import assert_security_posture
    from app.db.engine import get_engine
    from app.db.invariants import verify_startup
    import gevent

    from app.pipeline.llm import log_litellm_key_info, verify_litellm_models
    from app.pipeline.local_models import validate_local_models

    configure_logging()
    # Provenance for new embedding-cache docs (embeddings._l2_write created_by). Set here, not
    # at module import — this module is also imported by the FastAPI app, which must stay "api".
    embeddings.process_role = "worker"
    # Fail-fast on prefork, the one pool that FORKS: celery_worker.py monkey-patches gevent at
    # import time, so forking after that hands every child a hub inherited from the parent —
    # silent, intermittent hangs rather than a clean error. Only prefork is rejected, not
    # "anything but gevent": -P solo is a legitimate single-process debug path (.vscode/
    # launch.json) and never forks. sender is None only when a test calls this directly.
    pool = getattr(getattr(sender, "pool_cls", None), "__module__", "")
    if pool.endswith("prefork"):
        raise RuntimeError(
            "Celery worker started with the prefork pool, but app.pipeline.celery_worker has "
            "already monkey-patched gevent — forking now yields a broken hub per child. "
            "Launch with `-P gevent` (see start.ps1 / docker/compose.prod.yml)."
        )
    assert_security_posture()          # fail-closed: same auth guard as the API
    verify_startup(get_engine())       # fail-fast: same DB invariant guard as the API
    # [REVIEW-FIX] local embedding/reranker calls (local_models.py::_offload) run on gevent's
    # native thread pool, sized independently of the -c/--concurrency worker setting above —
    # was silently capped at gevent's own built-in default (10) with no way to see or change
    # it. Set BEFORE validate_local_models warms the models below, so the real ceiling is in
    # effect from the very first local-model call.
    gevent.get_hub().threadpool.size = get_settings().local_model_threadpool_size
    validate_local_models(warm=True)   # fail-fast + warm the local models so the 1st request is fast
    # verify_litellm_models's own chat()/embed() call goes through the SAME _llm_slot concurrency
    # limiter every real task call does — but this signal handler isn't a @celery_app.task, so
    # Celery's autoretry_for never applies here. Several worker replicas booting at once under a
    # configured max_concurrent_llm_calls cap could otherwise raise LLMSlotUnavailable straight out
    # of worker startup instead of transparently retrying, exactly during the highest-contention
    # moment (a coordinated restart/scale-out) the slot mechanism is meant to survive gracefully.
    for attempt in range(_LLM_VERIFY_MAX_ATTEMPTS):
        try:
            verify_litellm_models()    # fail-fast: same discipline, for whichever models route through the proxy
            break
        except LLMSlotUnavailable:
            if attempt == _LLM_VERIFY_MAX_ATTEMPTS - 1:
                raise
            time.sleep(_LLM_VERIFY_RETRY_BACKOFF_SECONDS * (attempt + 1))
    log_litellm_key_info()             # [REVIEW-FIX] was defined but never called — observability only, never raises
    # Warm the per-model-pair grounding thresholds OUTSIDE any stage lease: the first resolution
    # for a new embedding+reranker pair auto-calibrates (a bounded paraphrase+scoring pass) — at
    # boot that is a one-time deploy cost; deferred to the first pipeline run it would burn lease
    # time inside find_threats. Best-effort: on any failure workers resolve lazily later and, at
    # worst, fall back to the static defaults with a warning (grounding.resolve_thresholds).
    # allow_calibration=True ONLY here: this is the one place the expensive pass may run, so it
    # can never execute inside a leased pipeline stage. Same bounded LLMSlotUnavailable retry as
    # verify_litellm_models above — a coordinated restart under max_concurrent_llm_calls is
    # exactly when the paraphrase calls contend, and giving up there would leave this worker on
    # static thresholds for its whole life.
    from app.pipeline.grounding import resolve_thresholds
    for attempt in range(_LLM_VERIFY_MAX_ATTEMPTS):
        try:
            with db_session() as sess:
                resolve_thresholds(sess, get_llm(), allow_calibration=True)
            break
        except LLMSlotUnavailable:
            if attempt == _LLM_VERIFY_MAX_ATTEMPTS - 1:
                from app.core.logging import get_logger
                get_logger(__name__).warning("grounding.threshold_warmup_slots_exhausted")
                break
            time.sleep(_LLM_VERIFY_RETRY_BACKOFF_SECONDS * (attempt + 1))
        except Exception:  # noqa: BLE001 — warm-up only; never blocks worker boot
            from app.core.logging import get_logger
            get_logger(__name__).warning("grounding.threshold_warmup_failed", exc_info=True)
            break


@celery_app.task(bind=True, name="tsg.run_pipeline",
                autoretry_for=(LLMSlotUnavailable,), retry_backoff=True, max_retries=None)
def run_pipeline_task(self, session_id: str) -> None:
    """ this is the background job that runs the whole 2-stage
    AI pipeline for one session, kicked off right after a user creates it.

    Entry point queued by the API on session creation; `self.request.id` becomes
    the run id `_process_all_supporting_systems` stamps into each claimed stage, so a worker-crash
    redelivery (`acks_late`) is distinguishable from a fresh run for the stage Compare-And-Swap (CAS)

    `autoretry_for=(LLMSlotUnavailable,)`: a confirmed "no free LLM call slot" is temporary,
    not a bug — Celery retries this SAME task id shortly (backoff), which resumes exactly like
    a crash-redelivery does via claim_stage's existing CAS/resume logic. `max_retries=None`
    because `Subsystem_Stage_State.AttemptCount`'s own poison-terminal cap (dal.claim_stage) is
    the real ceiling here, not a second, independent Celery-level one.
    """
    with db_session() as sess:
        _process_all_supporting_systems(sess, session_id, get_llm(), self.request.id or guid())


@celery_app.task(bind=True, name="tsg.regenerate",
                autoretry_for=(LLMSlotUnavailable,), retry_backoff=True, max_retries=None)
def regenerate_task(self, session_id: str, subsystem_id: int, granularity: str,
                    target_ids: list[str] | list[int] | None, epoch: int, user_note: str | None = None) -> None:
    """ this is the background job that redoes one or more scenarios
    of a session when the user clicks "regenerate."

    Same `autoretry_for=(LLMSlotUnavailable,)` reasoning as run_pipeline_task above.

    `target_ids` carries the full requested list across the Celery task boundary — plain
    JSON-serializable list, no broker change needed (plan item 0). `epoch` is reserved once
    by the API endpoint's session-level CAS (not minted here) — a Celery redelivery of this
    exact task re-executes at the SAME epoch, so `claim_stage`'s CAS correctly no-ops once a
    level is already terminal, instead of destructively re-running the whole hop under a
    freshly-minted epoch."""
    with db_session() as sess:
        session = dal.load_session(sess, session_id)
        if session is None:
            # session was deleted or never existed by the time this task ran — nothing to regenerate
            return
        # convert the DB row into a plain dict before handing it to the cascade layer
        cascade.run_regeneration(sess, dict(session), subsystem_id, RegenGranularity(granularity),
                                target_ids, epoch, get_llm(), self.request.id or guid(), user_note=user_note)


@celery_app.task(bind=True, name="tsg.next_set",
                autoretry_for=(LLMSlotUnavailable,), retry_backoff=True, max_retries=None)
def next_set_task(self, session_id: str, subsystem_id: int, epoch: int, threats_epoch: int) -> None:
    """Background job for "generate next set": add the next batch of unique, accumulating
    scenarios for one subsystem. Same `autoretry_for=(LLMSlotUnavailable,)` and caller-reserved
    `epoch` reasoning as regenerate_task above — a redelivery re-executes at the SAME SCENARIOS
    epoch, so claim_stage's CAS no-ops a batch that already landed rather than double-generating.
    `threats_epoch` is the additive-find_threats epoch, ALSO reserved once by the endpoint and held
    fixed here, so a redelivery skips a second AI call once that stage is COMPLETE at it."""
    with db_session() as sess:
        session = dal.load_session(sess, session_id)
        if session is None:
            # session was deleted or never existed by the time this task ran — nothing to do
            return
        cascade.run_next_set(sess, dict(session), subsystem_id, epoch, threats_epoch,
                            get_llm(), self.request.id or guid())


@celery_app.task(name="tsg.admin_embedding_action",
                autoretry_for=(LLMSlotUnavailable,), retry_backoff=True, max_retries=None)
def admin_embedding_action_task(action: str, group: str | None, names: list[str] | None) -> dict:
    """Background counterpart to app/api/admin.py's four embedding-cache routes: the API only
    validates the request shape and queues this via .delay(), then the caller polls
    GET .../status/{job_id} against Celery's own AsyncResult (backed by the already-configured
    result backend) for the eventual outcome — same dispatch-then-poll shape as
    run_pipeline_task/regenerate_task above, and the same `autoretry_for=(LLMSlotUnavailable,)`
    reasoning: a confirmed "no free LLM call slot" is temporary, so Celery retries this exact
    job rather than the caller ever seeing a hard failure for a transient capacity squeeze.

    `create`/`update` are naturally idempotent on retry (they only embed what's missing).
    `recreate` re-wipes+re-embeds every group in `group`'s scope from scratch on a retry, even
    ones a partially-successful earlier attempt already finished — wasted work, not a
    correctness bug, and the real threat library is "tens of entries" (embeddings.py), so this
    is the same accepted, bounded cost as write_scenarios's own re-generation-on-retry note.
    `# ponytail: accepted; revisit only if recreate is ever run against a much larger library.`
    """
    if action == "delete":
        # sess: delete's strict check resolves no-vector names against the ACTIVE master rows,
        # so "already clean" repeats succeed idempotently while true typos still fail loudly.
        with db_session() as sess:
            return {"vectors_deleted": embeddings._for_each_group(
                group, lambda g: embeddings.delete_group(sess, g, names))}
    llm = get_llm()
    with db_session() as sess:
        if action == "create":
            # unlike its 3 siblings, create_items requires non-None group/names (it can't
            # fan out over "every group" the way update/recreate/delete can) — the API layer
            # (app/api/admin.py's create route) already enforces this before enqueueing, but
            # this task is reachable outside that one HTTP route (Flower, tests, a future
            # caller), so the guard belongs here too, not just at the one caller that happens
            # to exist today.
            if not group or not names:
                raise ValueError("create requires both group and names")
            return {"rows_processed": {group: embeddings.create_items(sess, llm, group, names)}}
        if action == "update":
            return {"rows_processed": embeddings._for_each_group(group, lambda g: embeddings.update_group(sess, llm, g))}
        if action == "recreate":
            return {"rows_processed": embeddings._for_each_group(
                group, lambda g: embeddings.recreate_group(sess, llm, g, names))}
    raise ValueError(f"unknown admin embedding action: {action!r}")


@celery_app.task(name="tsg.reap")
def reap_task() -> list[str]:
    """ runs automatically on a schedule (see `reaper_interval_seconds`
    in config) to find sessions whose worker crashed, and cleans them up so they
    don't stay stuck forever.

    Periodic stuck-job reaper; scheduled by `beat_schedule` above — run `celery beat` alongside the worker.
    `clean_up_abandoned_sessions()` already logs the cancelled set (`reaper.cancelled`) for every caller, so there's no second log here."""
    with db_session() as sess:
        return clean_up_abandoned_sessions(sess)


@celery_app.task(name="tsg.intel_refresh")
def intel_refresh_task() -> dict[str, int]:
    """ runs automatically on a schedule (see `intel_refresh_interval_seconds`
    in config, gated by `intel_enabled`) to pull the open threat-intel feeds —
    CISA KEV, CISA ICS advisories, OTX, URLhaus, configured TAXII servers — into
    the Mongo `threat_intel` cache that scenario generation reads for enrichment.

    Per-feed counts are returned for the beat log; a feed that failed reports -1.
    refresh_all is fail-soft per feed and fail-open on Mongo, so this task never
    raises for an ordinary outage — a down feed is a warning, not an incident."""
    from app.intel.fetchers import refresh_all  # local import, mirrors admin-task style

    return refresh_all()


@celery_app.task(name="tsg.self_check")
def self_check_task() -> list[str]:
    """ runs automatically on a schedule (see `self_check_interval_seconds`
    in config) to look for early warning signs of trouble — tempdb growth, a
    connection pool getting full, the active-session count approaching its ceiling
    — and log a warning for whichever ones it finds, so an operator's log-stack
    alert rules can catch them before they become an actual outage.

    Periodic operational self-check; scheduled by `beat_schedule` above — run `celery beat`
    alongside the worker, same as the reaper. `run_self_checks()` already logs
    (`selfcheck.*`) for every check that fires, so there's no second log here."""
    with db_session() as sess:
        return run_self_checks(sess)


@celery_app.task(name="tsg.import_threat_library")
def import_threat_library_task(source: str, file_content: str | None, via_taxii: bool,
                            max_actors: int, dry_run: bool) -> dict:
    """Background counterpart to app/api/threat_library_import.py — runs the same
    run_import the CLI script drives, then (real runs only) dispatches the existing
    embeddings-refresh task so the newly imported rows become matchable by grounding
    without anyone remembering scripts/refresh_embeddings.py.

    ORDERING IS LOAD-BEARING: the import commits inside its OWN db_session block FIRST;
    the embeddings dispatch happens strictly AFTER that block exits (commit done), so the
    embeddings task's fresh session is guaranteed to see the new rows — dispatching from
    inside the block could read an uncommitted snapshot and silently miss them, which is
    exactly the "forgot to refresh embeddings" gap this task exists to close. It is a
    SEPARATE job (not an in-transaction call) so a late embeddings failure can never roll
    back a fully-successful import; it also keeps its own LLMSlotUnavailable autoretry.
    This task itself makes NO LLM calls, so it carries no autoretry_for — validation
    failures land as a clean FAILURE state (ThreatLibraryImportError, never SystemExit),
    and a crash-redelivery is safe end to end: every write path is a natural-key upsert
    (upsert_threat_type/_catalogue/_actor/_rule).

    # ponytail: file_content rides the Redis broker as a plain (size-capped) string —
    # move to a shared blob store + a reference argument if much larger bundles are
    # ever needed."""
    from app.api.admin_jobs import FAMILY_EMBEDDINGS, mark_admin_job  # local import, mirrors admin-task style
    from app.pipeline import threat_library_import

    with db_session() as sess:
        stats = threat_library_import.run_import(
            sess, source, file_content=file_content, via_taxii=via_taxii,
            max_actors=max_actors, dry_run=dry_run)
    # Strictly after the with-block: the import's transaction has committed.
    if not dry_run and source != "misp_actors":
        # The import is ALREADY COMMITTED at this point, so a failure dispatching the follow-up
        # embeddings refresh must not mark the whole job FAILURE — that would report a fully
        # applied import as failed (and invite a redundant re-run) over a transient broker blip.
        # Degrade instead: report the import truthfully and say the refresh needs running.
        try:
            embed_job = admin_embedding_action_task.delay("update", None, None)
            # Without the marker the returned id would 404 on /embeddings/status —
            # the marker is that route's authorization check (admin_jobs.py).
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
    return stats
