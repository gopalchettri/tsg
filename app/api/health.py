"""Liveness / readiness probes for production orchestrators (OpenShift / K8s).

No authentication — these are called by the platform's health checks, not users.
`/health` = the process is up. `/readyz` = every dependency the app actually
needs (database, Redis, and Mongo when it's in use) is reachable right now.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.engine import get_engine

router = APIRouter(tags=["Health"])
logger = get_logger(__name__)


@router.get("/health")
def healthz() -> dict:
    """Liveness probe — returns 200 unconditionally, does not check DB reachability (that's readyz's job)."""
    return {"status": "ok"}


def _check_database() -> bool:
    """SELECT 1 against SQL Server — nothing in this app works without it."""
    try:
        with get_engine().connect() as c:
            c.execute(text("SELECT 1"))
        return True
    except Exception:  # noqa: BLE001 — report not-ready; log the detail SERVER-SIDE only
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
    except Exception:  # noqa: BLE001 — report not-ready; log the detail SERVER-SIDE only
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
    except Exception:  # noqa: BLE001 — report not-ready; log the detail SERVER-SIDE only
        logger.exception("readyz.mongo_unreachable")
        return False


@router.get("/readyz")
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
    with ThreadPoolExecutor(max_workers=3) as pool:
        db_f = pool.submit(_check_database)
        redis_f = pool.submit(_check_redis)
        mongo_f = pool.submit(_check_mongo)
        results = {"database": db_f.result(), "redis": redis_f.result(), "mongo": mongo_f.result()}
    checks = {name: ("skipped" if ok is None else "ok" if ok else "error") for name, ok in results.items()}
    failing = [name for name, ok in results.items() if ok is False]
    if failing:
        logger.warning("readyz.not_ready", failing=failing)
        return JSONResponse(status_code=503, content={"status": "not_ready", "checks": checks})
    return {"status": "ready", "checks": checks}
