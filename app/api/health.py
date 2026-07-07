"""Liveness / readiness probes for production orchestrators (OpenShift / K8s).

No authentication — these are called by the platform's health checks, not users.
`/healthz` = the process is up. `/readyz` = it can reach the database.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.db.engine import get_engine

router = APIRouter()
logger = logging.getLogger("tsg")


@router.get("/healthz")
def healthz() -> dict:
    """Liveness probe — returns 200 unconditionally, does not check DB reachability (that's readyz's job)."""
    return {"status": "ok"}


@router.get("/readyz")
def readyz():
    """Readiness probe — runs a trivial `SELECT 1` to confirm the database is reachable; returns 503 (not an exception) so orchestrators pull the pod from rotation instead of crash-looping it."""
    try:
        with get_engine().connect() as c:
            c.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001 — report not-ready; log the detail SERVER-SIDE only
        logger.exception("readiness probe: database not reachable")
        return JSONResponse(status_code=503, content={"status": "not_ready"})  # no internal detail to caller
    return {"status": "ready"}
