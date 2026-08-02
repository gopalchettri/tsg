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
from sqlalchemy import func, select

from app.api.admin_jobs import FAMILY_IMPORT, admin_job_exists, mark_admin_job
from app.api.deps import Principal, get_principal, require_admin
from app.api.schemas import (
    ImportJobStatus, SourceInventoryItem, SourcesInventoryResponse,
    ThreatLibraryImportAccepted, ThreatLibraryImportBody,
)
from app.core.config import get_settings
from app.core.logging import get_logger
from app.db import models as m
from app.db.dal import NotFoundError
from app.db.engine import db_session
from app.pipeline.celery_app import celery_app, import_threat_library_task
from app.pipeline.threat_library_import import (
    SOURCE_TAGS, URLS, ThreatLibraryImportError, check_source_shape, latest_runs_by_source,
)

router = APIRouter(
    prefix="/v1/tsg/threat-library",
    tags=["Threat Library Admin"],
    dependencies=[Depends(require_admin)],
)
log = get_logger(__name__)


def _validate(source: str, body: ThreatLibraryImportBody) -> None:
    """Everything checkable without touching the DB, checked BEFORE dispatch — all 422
    via the ThreatLibraryImportError handler (errors.py). Includes the per-source shape
    sniff: valid JSON of the WRONG shape (e.g. a STIX bundle uploaded as source=pytm)
    would otherwise fail deep inside an adapter on the worker with a meaningless error.

    `source` now arrives in the PATH (each source is its own addressable resource), so an
    unknown one is a 404 on the resource, not a 422 on a body field."""
    if source not in URLS:
        raise NotFoundError(f"unknown source {source!r} — valid: {sorted(URLS)}")
    if body.file_content is not None and body.via_taxii:
        # Reject the ambiguity outright instead of inheriting the CLI's silent
        # file-wins precedence (same discipline as admin.py's request guards).
        raise ThreatLibraryImportError("provide file_content OR via_taxii, not both")
    if body.via_taxii and source not in ("attack", "attack_ics"):
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
        check_source_shape(source, data)


def _enqueue(source: str, body: ThreatLibraryImportBody,
            started_by: str | None = None) -> ThreatLibraryImportAccepted:
    """Indirection so tests can run the import synchronously — same pattern as admin.py's
    _enqueue. file_content rides the broker as a plain string, bounded by the size cap
    checked in _validate.

    `started_by` is the only reason the caller's identity survives the hop into the worker: a
    Celery task has no request context, so anything not put on the message is unrecoverable
    there. It fills Threat_Library_Import_Run.StartedBy (NULL on every historical row, because
    this argument did not exist) and CreatedBy on the rows the import creates.
    # ponytail: capped string through Redis; move to a shared blob store + a reference
    # argument if much larger bundles are ever needed."""
    task = import_threat_library_task.delay(source, body.file_content, body.via_taxii,
                                            body.max_actors, body.dry_run, started_by)
    mark_admin_job(task.id, FAMILY_IMPORT)  # best-effort — see admin_jobs.mark_admin_job
    return ThreatLibraryImportAccepted(job_id=task.id)


@router.get("/sources", response_model=SourcesInventoryResponse)
def list_sources(_principal: Principal = Depends(get_principal)) -> SourcesInventoryResponse:
    """What is actually in the threat library, per source — the "which are imported, which
    are still pending?" answer in one call.

    EVERY known source is returned, imported or not, so a pending source is visibly
    `loaded=false` rather than simply absent (an absent row is indistinguishable from a
    source nobody knows about). Counts come from the `Source` column stamped on every
    imported row — three GROUP BY queries for the whole library, not one per source — and
    `last_run` from the import history, which is what makes "never attempted" and
    "attempted and failed" different states."""
    with db_session() as sess:
        types: dict[str | None, int] = {src: cnt for src, cnt in sess.execute(
            select(m.Threat_Type.Source, func.count()).group_by(m.Threat_Type.Source))}
        threats: dict[str | None, int] = {src: cnt for src, cnt in sess.execute(
            select(m.Threat_Catalogue.Source, func.count()).group_by(m.Threat_Catalogue.Source))}
        # Per-source, exactly like the two above. This was an unfiltered COUNT(*) over the whole
        # table reported as misp_actors' import count — Threat_Actor had no Source column, so the
        # 13 seeded actors and every AI-promoted one were attributed to a MISP import that never
        # created them. Rows written before Source existed have NULL and correctly count for
        # nothing here.
        actors: dict[str | None, int] = {src: cnt for src, cnt in sess.execute(
            select(m.Threat_Actor.Source, func.count()).group_by(m.Threat_Actor.Source))}
        runs = latest_runs_by_source(sess)
    items = []
    for source in sorted(URLS):
        tag = SOURCE_TAGS.get(source)
        type_count, threat_count = types.get(tag, 0), threats.get(tag, 0)
        # misp_actors writes actors, not catalogue rows — its "loaded" signal is the run
        # history plus the actor table, since it contributes nothing to the two counts above.
        actor_count = actors.get(tag, 0) if source == "misp_actors" else None
        last = runs.get(source)
        loaded = bool(type_count or threat_count) or (
            source == "misp_actors" and bool(last and last["status"] == "success" and not last["dry_run"]))
        items.append(SourceInventoryItem(
            source=source, source_tag=tag, loaded=loaded, type_count=type_count,
            threat_count=threat_count, actor_count=actor_count, last_run=last))
    return SourcesInventoryResponse(sources=items)


@router.post("/sources/{source}/import", response_model=ThreatLibraryImportAccepted, status_code=202)
def start_import(source: str, body: ThreatLibraryImportBody, request: Request,
                principal: Principal = Depends(get_principal)) -> ThreatLibraryImportAccepted:
    """Queue an import of ONE source (or a dry-run preview). Poll `GET ../imports/{job_id}`
    for the outcome — including, on an OT-source real run, the auto-written boost-only
    scoring rules (`ot_rules`) and the follow-up embeddings job id (`embeddings_job_id`).

    The source is the addressed RESOURCE, so every library has its own URL while the
    handler stays single — adding an eighth source remains a SOURCE_URLS entry, not a
    new route."""
    _validate(source, body)
    accepted = _enqueue(source, body, principal.user_id)
    # Audit AFTER the broker confirmed the job (admin.py's _audit ordering rationale).
    # has_file only — never the content itself.
    log.warning("admin.threat_library_import", action="import", source=source,
                dry_run=body.dry_run, via_taxii=body.via_taxii, max_actors=body.max_actors,
                has_file=body.file_content is not None, job_id=accepted.job_id,
                user_id=principal.user_id,
                source_ip=request.client.host if request.client else None)
    return accepted


@router.get("/imports/{job_id}", response_model=ImportJobStatus)
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
