"""Liveness / readiness probes for production orchestrators (OpenShift / K8s).

No authentication — these are called by the platform's health checks, not users.
`/health` = the process is up. `/ready` = every dependency the app actually
needs (database, Redis, and Mongo when it's in use) is reachable right now.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.api.schemas import LivenessReport, ReadinessReport
from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.engine import get_engine

router = APIRouter(tags=["Health"])
logger = get_logger(__name__)


@router.get("/health", response_model=LivenessReport,
            summary="Liveness check",
            description=(
                "Answers one question: is this process running? Always `200` while the app is up.\n\n"
                "**Use it for:** an orchestrator's liveness probe, deciding whether to restart the process.\n\n"
                "**It deliberately checks nothing else.** No database, no cache, no queue — a dependency "
                "being down is not a reason to restart a healthy process. Use the readiness endpoint for "
                "that.\n\n"
                "No authentication required."
            ))
def healthz() -> LivenessReport:
    """Liveness probe — returns 200 unconditionally, does not check DB reachability (that's readyz's job)."""
    return LivenessReport(status="ok")


def _check_database() -> bool:
    """SELECT 1 against SQL Server — nothing in this app works without it."""
    try:
        with get_engine().connect() as c:
            c.execute(text("SELECT 1"))
        return True
    except Exception:
        logger.exception("readyz.database_unreachable")
        return False


def _check_redis() -> bool:
    """PING against Redis (SSE pub/sub + Celery broker). A fresh, short-lived client —
    deliberately NOT app.sse.bus's cached singleton, which carries its own circuit-breaker
    state meant for the best-effort SSE publish hot path, not a readiness probe."""
    try:
        import redis  # imported here so this module doesn't require redis at import time

        s = get_settings()
        redis.Redis.from_url(
            s.redis_url,
            socket_connect_timeout=s.sse_subscribe_connect_timeout_seconds,
            socket_timeout=s.sse_subscribe_connect_timeout_seconds,
        ).ping()
        return True
    except Exception:
        logger.exception("readyz.redis_unreachable")
        return False


def _check_mongo() -> bool | None:
    """PING against MongoDB (the embedding cache's L2 store) — but only when this
    deployment actually uses it. `EMBEDDING_STORE=memory` never touches Mongo by
    design (config.py: "a Mongo outage degrades to memory"), so probing it there
    would raise a false alarm for a valid configuration. Returns None for "not
    applicable, skipped" — distinct from True/False, which mean "reachable"/"not"."""
    s = get_settings()
    if s.embedding_store != "mongo":
        return None
    try:
        import pymongo  # imported here so this module doesn't require pymongo at import time

        # `with` closes the client (and its background topology-monitor thread) on every call —
        # without it, a probe hit every few seconds for a pod's whole lifetime leaks a fresh
        # client's threads/sockets forever, same anti-pattern embeddings.py's own cached
        # @lru_cache MongoClient exists specifically to avoid.
        client: pymongo.MongoClient[dict[str, Any]]
        with pymongo.MongoClient(
            s.mongo_url,
            serverSelectionTimeoutMS=s.mongo_connect_timeout_ms,
            connectTimeoutMS=s.mongo_connect_timeout_ms,
            socketTimeoutMS=s.mongo_connect_timeout_ms,
        ) as client:
            client.admin.command("ping")
        return True
    except Exception:
        logger.exception("readyz.mongo_unreachable")
        return False


def _check_workers() -> dict[str, bool]:
    """Broadcast ping for live Celery workers over the broker. ADVISORY ONLY — reported in
    the payload and logs but never fails readiness: with no workers the API still serves
    every synchronous route and queued jobs simply wait, so evicting API pods here would
    turn a delay into a full outage. Monitoring alerts on checks.workers_<queue> / the log
    events. Returns one entry PER ROUTED QUEUE -- see the note on active_queues below for
    why a single any()-style answer is not good enough once tasks are routed."""
    try:
        from app.pipeline.celery_app import (  # local import, same pattern as redis/pymongo above
            ADMIN_QUEUE,
            DEFAULT_QUEUE,
            celery_app,
        )

        # NOT ping(limit=1). That returns on the FIRST worker to answer, which was fine while
        # one worker consumed everything -- but the app now routes heavy operator jobs to the
        # `admin` queue (celery_app.task_routes), and a healthy pipeline worker answering first
        # would mask a dead admin worker. The API would keep returning 202 for rebuilds and
        # imports that then never run: a silent black hole, which is strictly worse than the
        # slow-but-visible behaviour the queue split replaced.
        #
        # active_queues() asks every worker WHICH queues it consumes, so each queue is reported
        # on its own evidence.
        consumed: set[str] = set()
        for queues in (celery_app.control.inspect(timeout=1.0).active_queues() or {}).values():
            consumed.update(q["name"] for q in queues or ())
        missing = {DEFAULT_QUEUE, ADMIN_QUEUE} - consumed
        if missing:
            logger.warning("readyz.queue_unconsumed", missing=sorted(missing),
                           consumed=sorted(consumed))
        return {DEFAULT_QUEUE: DEFAULT_QUEUE in consumed, ADMIN_QUEUE: ADMIN_QUEUE in consumed}
    except Exception:
        logger.exception("readyz.workers_check_failed")
        return {DEFAULT_QUEUE: False, ADMIN_QUEUE: False}


@router.get("/ready", response_model=ReadinessReport,
            summary="Readiness check",
            description=(
                "Answers a different question from liveness: can this process actually serve traffic? It "
                "pings the database, the cache, the document store where used, and looks for a live "
                "background worker.\n\n"
                "**Use it for:** an orchestrator's readiness probe, and as your first check when you suspect "
                "a dependency is down.\n\n"
                "**Reading the result:** `200` with `ready` when healthy, `503` with `not_ready` naming the "
                "failed dependency otherwise. A `skipped` entry is normal, not a failure — on `mongo` it "
                "means this deployment's embedding cache is not backed by Mongo.\n\n"
                "**Watch out:** the worker check is advisory. It is reported for visibility but never turns "
                "the response into a `503` on its own, because the API still serves every immediate request "
                "with no workers; queued jobs simply wait.\n\n"
                "Failures never leak exception details. No authentication required."
            ))
def readyz():
    """Readiness probe — checks every dependency this app actually needs. Any one of
    them being unreachable (except Mongo when this deployment doesn't use it) returns
    503 so orchestrators pull the pod from rotation instead of crash-looping it. No
    internal exception detail is ever returned to the caller — each check logs its own
    failure server-side (see the `readyz.*_unreachable` events above) before this
    function reduces it to a plain ok/error/skipped label."""
    # Run concurrently, not sequentially — each check is its own blocking network round trip
    # with its own timeout; sequential execution would block for close to the SUM of the three
    # timeouts during a multi-dependency outage instead of the MAX, right when fast probe
    # turnaround matters most for the orchestrator to evict the pod from rotation.
    with ThreadPoolExecutor(max_workers=4) as pool:
        db_f = pool.submit(_check_database)
        redis_f = pool.submit(_check_redis)
        mongo_f = pool.submit(_check_mongo)
        workers_f = pool.submit(_check_workers)
        per_queue = workers_f.result()
        results = {"database": db_f.result(), "redis": redis_f.result(), "mongo": mongo_f.result(),
                "workers": any(per_queue.values())}
        # One key per queue, so "the admin worker is down" is a distinct, visible answer rather
        # than being averaged away by a healthy pipeline worker. `checks` is a mapping precisely
        # so the dependency set can vary (see ReadinessReport) -- these are additive keys, and
        # `workers` keeps its old meaning for anything already reading it.
        results.update({f"workers_{queue}": ok for queue, ok in per_queue.items()})
    checks = {name: ("skipped" if ok is None else "ok" if ok else "error") for name, ok in results.items()}
    # workers excluded on purpose — advisory, see _check_workers
    failing = [name for name, ok in results.items()
               if ok is False and not name.startswith("workers")]
    if failing:
        logger.warning("readyz.not_ready", failing=failing)
        # A plain JSONResponse, NOT a raise: this body is the ReadinessReport shape, not the
        # ErrorResponse envelope, because an orchestrator reads the per-dependency detail.
        # That is also why /ready must not take the shared UNAVAILABLE_RESPONSES fragment.
        return JSONResponse(status_code=503,
                            content=ReadinessReport(status="not_ready",
                                                    checks=checks).model_dump())
    return ReadinessReport(status="ready", checks=checks)
