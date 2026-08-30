"""Provenance markers for admin-family background jobs (see admin.py for the full rationale).

Each family's status route answers ONLY for ids its own family marked, so no status route can
surface another task type's result.

DEPENDENCY-LIGHT ON PURPOSE (redis + settings + logging + dal only, no FastAPI, no Celery):
worker tasks in celery_app.py mark jobs too, so this must import without an api<->pipeline
cycle. dal.py itself only imports app.core.*/app.db.models, so pulling in dal.now() for the
marker timestamp below does not reopen that cycle.
"""
from __future__ import annotations

import json

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db import dal
from app.pipeline.llm import _slot_redis

log = get_logger(__name__)

_JOB_KEY_PREFIX = "tsg:admin:job:"
FAMILY_EMBEDDINGS = "emb"
FAMILY_INTEL = "intel"   # per-feed threat-intel refresh jobs (app/api/threat_intel.py)
FAMILY_GROUNDING = "grounding"  # grounding-threshold calibration sweeps (app/api/admin.py)


def _key(job_id: str, family: str) -> str:
    return f"{_JOB_KEY_PREFIX}{family}:{job_id}"


def emb_job_channel_key(job_id: str) -> str:
    """SSE bus channel id for one embeddings job — the ONE convention the worker publisher
    (celery_app.py::admin_embedding_action_task) and the API subscriber (admin.py::job_events)
    share, mirroring bus.channel()'s role for sessions. Joins the same tsg:sse: family as
    bus.channel()'s session channels — these ARE SSE channels, just admin-family ones — spelled
    out to match the SSEEventType name (embedding_job_update) rather than an abbreviation."""
    return f"tsg:sse:embedding-job:{job_id}"


def intel_job_channel_key(job_id: str) -> str:
    """Same convention as emb_job_channel_key, for one threat-intel feed-refresh job — shared
    by celery_app.py::intel_refresh_feed_task (publisher) and threat_intel.py::job_events
    (subscriber)."""
    return f"tsg:sse:intel-job:{job_id}"


def grounding_job_channel_key(job_id: str) -> str:
    """Same convention as emb_job_channel_key, for one grounding-calibration sweep — shared by
    celery_app.py::calibrate_grounding_task (publisher) and admin.py::calibration_events
    (subscriber)."""
    return f"tsg:sse:grounding-job:{job_id}"


def mark_admin_job(job_id: str, family: str, user_id: str | None = None) -> None:
    """Best-effort marker write (same TTL as the Celery result backend, so marker and
    result expire together). Fails open on the QUEUE side — a Redis blip must not block
    the job itself; the job merely becomes unpollable via its status route.

    The value carries who queued it and when — admin_job_exists below only ever calls
    r.exists(...) and never reads the value, so this is purely for an operator inspecting
    Redis directly (e.g. via RedisInsight) to see. No entity_id: admin actions are
    cross-tenant by design (same reasoning as the Celery shadow labels in admin.py/
    threat_intel.py)."""
    value = json.dumps({"user_id": user_id, "created_at": dal.now().isoformat()})
    try:
        _slot_redis().setex(_key(job_id, family), get_settings().result_expires_seconds, value)
    except Exception:
        log.warning("admin.job_marker_write_failed", job_id=job_id, family=family, exc_info=True)


def admin_job_exists(job_id: str, family: str) -> bool:
    """Deliberately NOT fail-open, unlike mark_admin_job above: this check guards
    AUTHORIZATION (which job a caller may read), so a Redis error must propagate and
    deny via the generic 500 handler, never silently let every job_id through.

    The embeddings fallback honors the pre-family marker shape (bare `tsg:admin:job:<id>`) so
    jobs queued before families existed stay pollable through their TTL — safe to delete."""
    r = _slot_redis()
    if r.exists(_key(job_id, family)):
        return True
    return family == FAMILY_EMBEDDINGS and bool(r.exists(f"{_JOB_KEY_PREFIX}{job_id}"))
