"""Provenance markers for admin-family background jobs (see admin.py for the full rationale).

Each family's status route answers ONLY for ids its own family marked, so no status route can
surface another task type's result.

DEPENDENCY-LIGHT ON PURPOSE (redis + settings + logging only, no FastAPI, no Celery): worker
tasks in celery_app.py mark jobs too, so this must import without an api<->pipeline cycle.
"""
from __future__ import annotations

from app.core.config import get_settings
from app.core.logging import get_logger
from app.pipeline.llm import _slot_redis

log = get_logger(__name__)

_JOB_KEY_PREFIX = "tsg:admin:job:"
FAMILY_EMBEDDINGS = "emb"
FAMILY_IMPORT = "import"
FAMILY_INTEL = "intel"   # per-feed threat-intel refresh jobs (app/api/threat_intel.py)


def _key(job_id: str, family: str) -> str:
    return f"{_JOB_KEY_PREFIX}{family}:{job_id}"


def emb_job_channel_key(job_id: str) -> str:
    """SSE bus channel id for one embeddings job — the ONE convention the worker publisher
    (celery_app.py::admin_embedding_action_task) and the API subscriber (admin.py::job_events)
    share, mirroring bus.channel()'s role for sessions. Namespaced so it can never collide
    with a session channel (session ids are bare UUIDs)."""
    return f"admin-emb:{job_id}"


def import_job_channel_key(job_id: str) -> str:
    """Same convention as emb_job_channel_key, for one threat-library-import job — shared by
    celery_app.py::import_threat_library_task (publisher) and
    threat_library_import.py::job_events (subscriber)."""
    return f"admin-import:{job_id}"


def intel_job_channel_key(job_id: str) -> str:
    """Same convention as emb_job_channel_key, for one threat-intel feed-refresh job — shared
    by celery_app.py::intel_refresh_feed_task (publisher) and threat_intel.py::job_events
    (subscriber)."""
    return f"admin-intel:{job_id}"


def mark_admin_job(job_id: str, family: str) -> None:
    """Best-effort marker write (same TTL as the Celery result backend, so marker and
    result expire together). Fails open on the QUEUE side — a Redis blip must not block
    the job itself; the job merely becomes unpollable via its status route."""
    try:
        _slot_redis().setex(_key(job_id, family), get_settings().result_expires_seconds, "1")
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
