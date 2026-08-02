"""Admin API — threat-library embedding cache maintenance (create/update/recreate/delete).

Gated by TWO independent checks, both required: the static X-Admin-Key header
(deps.require_admin) is the authorization gate — this is shared cross-tenant master data, so
the per-entity JWT model doesn't fit — and a valid bearer JWT (deps.get_principal) supplies the
`sub` that attributes the audit log to a real caller rather than "someone with the shared key".

Asynchronous: each POST validates, audits, queues admin_embedding_action_task and returns 202 +
a job_id. GET .../status/{job_id} polls Celery's own AsyncResult.
"""
from __future__ import annotations

from celery.result import AsyncResult
from fastapi import APIRouter, Depends, Request

from app.api.admin_jobs import FAMILY_EMBEDDINGS, admin_job_exists, mark_admin_job
from app.api.deps import Principal, get_principal, require_admin
from app.api.schemas import EmbeddingActionBody, EmbeddingJobAccepted, EmbeddingJobStatus
from app.core.logging import get_logger
from app.db.dal import NotFoundError
from app.pipeline.celery_app import admin_embedding_action_task, celery_app

router = APIRouter(
    prefix="/v1/tsg/threat-library/embeddings",
    tags=["Embeddings Admin"],
    dependencies=[Depends(require_admin)],
)
log = get_logger(__name__)


class AdminValidationError(Exception):
    """A structurally-valid but business-rule-invalid admin request -> 422, same envelope
    shape as every other domain error (registered in app/api/errors.py)."""


def _audit(request: Request, action: str, body: EmbeddingActionBody, principal: Principal, job_id: str) -> None:
    """Forensic trail for who/what/when a destructive action was queued.

    Fires AFTER _enqueue confirms the task reached the broker (the job_id proves it): logging
    first would leave a permanent record of an action that never ran when .delay() failed."""
    log.warning("admin.embedding_action", action=action, group=body.group, names=body.names,
                job_id=job_id, user_id=principal.user_id,
                source_ip=request.client.host if request.client else None)


def _require_group_when_names_given(body: EmbeddingActionBody) -> None:
    """A name alone doesn't say which table it's in — names scoping only makes sense against
    ONE explicit group, never against "every group" at once."""
    if body.names and not body.group:
        raise AdminValidationError("names requires a specific group — cannot scope names across all groups")


def _enqueue(action: str, body: EmbeddingActionBody) -> EmbeddingJobAccepted:
    """Queues the action (indirection so tests can run it synchronously) and records the
    provenance marker get_status below requires.

    Every other task shares this Celery app and result backend, so without the marker a bare
    AsyncResult(job_id) lookup cannot tell an admin job from any other task's id — get_status
    would return another tenant's pipeline exception text, or crash trying to `**` a list.
    The marker write is best-effort: an unreachable Redis leaves the job merely unpollable."""
    task = admin_embedding_action_task.delay(action, body.group, body.names)
    mark_admin_job(task.id, FAMILY_EMBEDDINGS)  # best-effort — see admin_jobs.mark_admin_job
    return EmbeddingJobAccepted(job_id=task.id)


@router.post("/create", response_model=EmbeddingJobAccepted, status_code=202)
def create(body: EmbeddingActionBody, request: Request,
        principal: Principal = Depends(get_principal)) -> EmbeddingJobAccepted:
    """Fingerprint specific NEW item(s) you name — for right after a threat is added."""
    if not body.group or not body.names:
        raise AdminValidationError("create requires both group and names")
    accepted = _enqueue("create", body)
    _audit(request, "create", body, principal, accepted.job_id)
    return accepted


@router.post("/update", response_model=EmbeddingJobAccepted, status_code=202)
def update(body: EmbeddingActionBody, request: Request,
        principal: Principal = Depends(get_principal)) -> EmbeddingJobAccepted:
    """Whole-group sync: embed whatever's missing across every active row (`group=None` =
    every group). `names` isn't part of this action's contract — see /create for targeted
    embedding of specific items."""
    accepted = _enqueue("update", body)
    _audit(request, "update", body, principal, accepted.job_id)
    return accepted


@router.post("/recreate", response_model=EmbeddingJobAccepted, status_code=202)
def recreate(body: EmbeddingActionBody, request: Request,
        principal: Principal = Depends(get_principal)) -> EmbeddingJobAccepted:
    """Wipe a group's (or named items') cached vectors, then re-embed them from scratch."""
    _require_group_when_names_given(body)
    accepted = _enqueue("recreate", body)
    _audit(request, "recreate", body, principal, accepted.job_id)
    return accepted


@router.post("/delete", response_model=EmbeddingJobAccepted, status_code=202)
def delete(body: EmbeddingActionBody, request: Request,
        principal: Principal = Depends(get_principal)) -> EmbeddingJobAccepted:
    """Wipe a group's (or named items') cached vectors — no re-embed.

    `group` and `names` cannot BOTH be omitted: unlike update/recreate (which rebuild and so
    self-heal), a bare `{}` here would silently wipe the ENTIRE cross-tenant cache."""
    if not body.group and not body.names:
        raise AdminValidationError(
            "delete requires group and/or names — refusing to wipe the entire cache with an empty request")
    _require_group_when_names_given(body)
    accepted = _enqueue("delete", body)
    _audit(request, "delete", body, principal, accepted.job_id)
    return accepted


@router.get("/status/{job_id}", response_model=EmbeddingJobStatus)
def get_status(job_id: str, _principal: Principal = Depends(get_principal)) -> EmbeddingJobStatus:
    """Polls Celery's AsyncResult for a job one of the four routes above queued.

    The provenance marker is checked FIRST: this route never calls require_entity, so without it
    any caller who learns another task's id (from logs, or Subsystem_Stage_State.ActiveTaskID)
    could poll ITS result here — a real authorization bypass. An id this router never queued
    (or whose TTL expired) reports 404, never a guess at Celery's state for it.

    Deliberately NOT fail-open on a Redis error, unlike _enqueue's marker write: that guards
    availability, this guards AUTHORIZATION, so an unreachable Redis must deny."""
    if not admin_job_exists(job_id, FAMILY_EMBEDDINGS):
        raise NotFoundError(f"unknown or expired job_id: {job_id!r}")
    result = AsyncResult(job_id, app=celery_app)
    if result.state == "FAILURE":
        return EmbeddingJobStatus(state=result.state, error=str(result.result))
    if result.state == "SUCCESS":
        return EmbeddingJobStatus(state=result.state, **(result.result or {}))
    return EmbeddingJobStatus(state=result.state)
