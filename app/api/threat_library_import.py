"""Admin API — trigger a threat-library import over HTTP: the same job
scripts/import_threat_libraries.py runs from a shell, driving the same shared core
(app/pipeline/threat_library_import.py), so the two front doors can never drift.

Gated by the SAME two independent checks as admin.py (its module docstring is the
canonical rationale): the static X-Admin-Key header (require_admin — the authorization
gate; this touches shared cross-tenant threat-library data, not one entity's data) AND
a valid bearer JWT (get_principal), whose `sub` claim attributes the audit line to a
real caller.

Runs ASYNCHRONOUSLY — dispatch-then-poll, same shape as the embeddings routes: POST
validates everything it can BEFORE dispatching (a bad request never reaches the queue),
queues tsg.import_threat_library, marks the job id under the 'import' family
(app/api/admin_jobs.py — family separation keeps this status route from ever surfacing
an embeddings job's differently-shaped result, and vice versa), and returns 202 +
job_id. GET /status/{job_id} polls Celery's AsyncResult.
"""
from __future__ import annotations

import json

from celery.result import AsyncResult
from fastapi import APIRouter, Depends, Request

from app.api.admin_jobs import FAMILY_IMPORT, admin_job_exists, mark_admin_job
from app.api.deps import Principal, get_principal, require_admin
from app.api.schemas import ImportJobStatus, ThreatLibraryImportAccepted, ThreatLibraryImportBody
from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.dal import NotFoundError
from app.pipeline.celery_app import celery_app, import_threat_library_task
from app.pipeline.threat_library_import import URLS, ThreatLibraryImportError, check_source_shape

router = APIRouter(
    prefix="/v1/tsg/threat-library/import",
    tags=["Threat Library Admin"],
    dependencies=[Depends(require_admin)],
)
log = get_logger(__name__)


def _validate(body: ThreatLibraryImportBody) -> None:
    """Everything checkable without touching the DB, checked BEFORE dispatch — all 422
    via the ThreatLibraryImportError handler (errors.py). Includes the per-source shape
    sniff: valid JSON of the WRONG shape (e.g. a STIX bundle uploaded as source=pytm)
    would otherwise fail deep inside an adapter on the worker with a meaningless error."""
    if body.source not in URLS:
        raise ThreatLibraryImportError(f"unknown source {body.source!r} — valid: {sorted(URLS)}")
    if body.file_content is not None and body.via_taxii:
        # Reject the ambiguity outright instead of inheriting the CLI's silent
        # file-wins precedence (same discipline as admin.py's request guards).
        raise ThreatLibraryImportError("provide file_content OR via_taxii, not both")
    if body.via_taxii and body.source not in ("attack", "attack_ics"):
        raise ThreatLibraryImportError("via_taxii is only supported for attack / attack_ics")
    if body.file_content is not None:
        max_mb = get_settings().threat_library_import_max_upload_mb
        if len(body.file_content.encode("utf-8")) > max_mb * 1024 * 1024:
            raise ThreatLibraryImportError(
                f"file_content exceeds the {max_mb} MB limit (threat_library_import_max_upload_mb)")
        try:
            data = json.loads(body.file_content)
        except ValueError as exc:
            raise ThreatLibraryImportError(f"file_content is not valid JSON: {exc}") from exc
        check_source_shape(body.source, data)


def _enqueue(body: ThreatLibraryImportBody) -> ThreatLibraryImportAccepted:
    """Indirection so tests can run the import synchronously — same pattern as admin.py's
    _enqueue. file_content rides the broker as a plain string, bounded by the size cap
    checked in _validate.
    # ponytail: capped string through Redis; move to a shared blob store + a reference
    # argument if much larger bundles are ever needed."""
    task = import_threat_library_task.delay(body.source, body.file_content, body.via_taxii,
                                            body.max_actors, body.dry_run)
    mark_admin_job(task.id, FAMILY_IMPORT)  # best-effort — see admin_jobs.mark_admin_job
    return ThreatLibraryImportAccepted(job_id=task.id)


@router.post("", response_model=ThreatLibraryImportAccepted, status_code=202)
def start_import(body: ThreatLibraryImportBody, request: Request,
                 principal: Principal = Depends(get_principal)) -> ThreatLibraryImportAccepted:
    """Queue one library import (or a dry-run preview). Poll GET status/{job_id} for the
    outcome — including, on an OT-source real run, the auto-written boost-only scoring
    rules (`ot_rules`) and the follow-up embeddings job id (`embeddings_job_id`)."""
    _validate(body)
    accepted = _enqueue(body)
    # Audit AFTER the broker confirmed the job (admin.py's _audit ordering rationale).
    # has_file only — never the content itself.
    log.warning("admin.threat_library_import", action="import", source=body.source,
                dry_run=body.dry_run, via_taxii=body.via_taxii, max_actors=body.max_actors,
                has_file=body.file_content is not None, job_id=accepted.job_id,
                user_id=principal.user_id,
                source_ip=request.client.host if request.client else None)
    return accepted


@router.get("/status/{job_id}", response_model=ImportJobStatus)
def get_import_status(job_id: str, _principal: Principal = Depends(get_principal)) -> ImportJobStatus:
    """Polls Celery's AsyncResult for a job the POST above queued. The family-scoped
    marker check FIRST — it is the authorization boundary (admin.py's get_status
    docstring is the canonical rationale); an id this router never queued (or whose
    marker/result TTL expired), including any embeddings-family id, reports 404."""
    if not admin_job_exists(job_id, FAMILY_IMPORT):
        raise NotFoundError(f"unknown or expired job_id: {job_id!r}")
    result = AsyncResult(job_id, app=celery_app)
    if result.state == "FAILURE":
        return ImportJobStatus(state=result.state, error=str(result.result))
    if result.state == "SUCCESS":
        return ImportJobStatus(state=result.state, result=result.result)
    return ImportJobStatus(state=result.state)
