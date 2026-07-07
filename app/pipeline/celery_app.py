""" this file connects the web server to the background workers
through a job queue (Celery) — it does NOT do any AI work itself, it just says
"here's a job, go run it" and "here's how to check for crashed sessions."

Celery transport wiring — kept separate from the pipeline work.

`acks_late` + `reject_on_worker_lost` mean a worker crash redelivers the task; the
stage Compare-And-Swap (CAS) makes that safe (finished stages skip, mid-flight resume). The
reaper recovers a session whose worker died so the lock never leaks.

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

from celery import Celery
from celery.signals import worker_init, worker_process_init

from app.core.config import get_settings
from app.core.enums import RegenGranularity
from app.core.logging import configure_logging
from app.db import dal
from app.db.dal import guid
from app.db.engine import db_session
from app.pipeline import cascade
from app.pipeline.llm import get_llm
from app.pipeline.reaper import clean_up_abandoned_sessions
from app.pipeline.tasks import _process_all_supporting_systems

_s = get_settings()

celery_app = Celery("tsg", broker=_s.celery_broker_url or _s.redis_url,
                    backend=_s.celery_result_backend or _s.redis_url)
celery_app.conf.update(
    result_expires=_s.result_expires_seconds,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_pool="gevent",              # I/O-bound LLM waits → high concurrency
    beat_schedule={                    # the reaper must run on a schedule in production
        "reap-stuck-sessions": {"task": "tsg.reap", "schedule": _s.reaper_interval_seconds},
    },
    # Deliberately ABSENT (do not "fix" these by adding config):
    #  * time_limit/soft_time_limit — Celery time limits only work on the prefork pool and
    #    are silently ignored under gevent (configured above). The real timeout mechanism is
    #    per-call LLM timeouts (llm.py, every call family) + the lease/reaper backstop.
    #  * autoretry_for — retries live in claim_stage's AttemptCount cap (which also bounds
    #    worker-loss redeliveries: the same-task RUNNING-resume claim increments it too, so a
    #    poison task stops being claimable after stage_max_attempts) + litellm num_retries;
    #    Celery-level retries on top would double-retry every failure.
)


@worker_init.connect        # fires exactly once per worker process, for EVERY pool type
@worker_process_init.connect  # fires per forked child under prefork specifically 
def _init_worker(**_):
    """ runs once, right when a worker process starts up, to
    double-check its settings are safe and to pre-load the AI models so the
    very first real request doesn't have to wait for that loading.

    `worker_process_init` is prefork-only (fires per forked child) — it NEVER
    fires under `worker_pool="gevent"` (configured above), which is what this
    service actually runs. Without `worker_init` (fires once for any pool, before
    the pool even starts), a gevent worker would silently skip the fail-closed
    security-posture guard and the fail-fast local-model check entirely — the same
    root cause `configure_logging`'s own eager-import-time fix addresses for logging."""
    from app.core.config import assert_security_posture
    from app.pipeline.local_models import validate_local_models

    configure_logging()
    assert_security_posture()          # fail-closed: same auth/binding guard as the API
    validate_local_models(warm=True)   # fail-fast + warm the local models so the 1st request is fast


@celery_app.task(bind=True, name="tsg.run_pipeline")
def run_pipeline_task(self, session_id: str) -> None:
    """ this is the background job that runs the whole 3-stage
    AI pipeline for one session, kicked off right after a user creates it.

    Entry point queued by the API on session creation; `self.request.id` becomes
    the run id `_process_all_supporting_systems` stamps into each claimed stage, so a worker-crash
    redelivery (`acks_late`) is distinguishable from a fresh run for the stage Compare-And-Swap (CAS)
    """
    with db_session() as sess:
        _process_all_supporting_systems(sess, session_id, get_llm(), self.request.id or guid())


@celery_app.task(bind=True, name="tsg.regenerate")
def regenerate_task(self, session_id: str, subsystem_id: int, granularity: str,
                    target_ids: list[str] | list[int] | None, epoch: int, user_note: str | None = None) -> None:
    """ this is the background job that redoes one or more scenarios
    of a session when the user clicks "regenerate."

    `target_ids` carries the full requested list across the Celery task boundary — plain
    JSON-serializable list, no broker change needed (plan item 0). `epoch` is reserved once
    by the API endpoint's session-level CAS (not minted here) — a Celery redelivery of this
    exact task re-executes at the SAME epoch, so `claim_stage`'s CAS correctly no-ops once a
    level is already terminal, instead of destructively re-running the whole hop under a
    freshly-minted epoch."""
    with db_session() as sess:
        session = dal.load_session(sess, session_id)
        if session is None:
            return
        cascade.run_regeneration(sess, dict(session), subsystem_id, RegenGranularity(granularity),
                                 target_ids, epoch, get_llm(), self.request.id or guid(), user_note=user_note)


@celery_app.task(name="tsg.reap")
def reap_task() -> list[str]:
    """ runs automatically on a schedule (see `reaper_interval_seconds`
    in config) to find sessions whose worker crashed, and cleans them up so they
    don't stay stuck forever.

    Periodic stuck-job reaper ([R1]); scheduled by `beat_schedule` above — run `celery beat` alongside the worker.
    `clean_up_abandoned_sessions()` already logs the cancelled set (`reaper.cancelled`) for every caller, so there's no second log here."""
    with db_session() as sess:
        return clean_up_abandoned_sessions(sess)
