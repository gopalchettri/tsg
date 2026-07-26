"""Admin API — threat-library embedding cache maintenance (create/update/recreate/delete).

Gated by TWO independent checks, both required: a static X-Admin-Key header
(app.api.deps.require_admin — the actual authorization gate; TSG has no admin/curator role,
and this touches shared, cross-tenant master data, not one entity's data, so the per-entity
JWT model doesn't fit as the GATE) and a valid bearer JWT (app.api.deps.get_principal — the
SAME validation every other endpoint already uses), whose `sub` claim attributes the audit
log to a real caller instead of "someone with the shared key".

Runs ASYNCHRONOUSLY — same dispatch-then-poll shape as app/api/sessions.py's
run_pipeline_task/regenerate_task. Each POST route validates the request, writes the audit
log line, queues app.pipeline.celery_app.admin_embedding_action_task via .delay(), and returns
202 + a job_id immediately (no DB/LLM access happens inline in the HTTP request anymore).
GET .../status/{job_id} then polls Celery's own AsyncResult — backed by the already-configured
result backend, no new infrastructure — for the eventual rows_processed/vectors_deleted/error.
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
    tags=["Threat Library Admin"],
    dependencies=[Depends(require_admin)],
)
log = get_logger(__name__)


class AdminValidationError(Exception):
    """A structurally-valid but business-rule-invalid admin request -> 422, same envelope
    shape as every other domain error (registered in app/api/errors.py)."""


def _audit(request: Request, action: str, body: EmbeddingActionBody, principal: Principal, job_id: str) -> None:
    """Structured log line — the forensic trail for who/what/when a destructive action was
    queued. Fires AFTER _enqueue confirms the task actually reached the broker (job_id proves
    it), never before: logging it first would leave a permanent record claiming an action was
    queued even when .delay() itself failed (e.g. broker down) and nothing ever ran.
    `principal.user_id` (the JWT `sub` claim, required via get_principal below) names the real
    caller; the shared X-Admin-Key alone never could."""
    log.warning("admin.embedding_action", action=action, group=body.group, names=body.names,
                job_id=job_id, user_id=principal.user_id,
                source_ip=request.client.host if request.client else None)


def _require_group_when_names_given(body: EmbeddingActionBody) -> None:
    """A name alone doesn't say which table it's in — names scoping only makes sense against
    ONE explicit group, never against "every group" at once."""
    if body.names and not body.group:
        raise AdminValidationError("names requires a specific group — cannot scope names across all groups")


def _enqueue(action: str, body: EmbeddingActionBody) -> EmbeddingJobAccepted:
    """Indirection so tests can run the action synchronously instead of via a broker — same
    pattern as app/api/sessions.py's enqueue_pipeline/enqueue_regeneration. Also records a
    provenance marker (`tsg:admin:job:<id>`) for get_status below: run_pipeline_task,
    regenerate_task, reap_task, and self_check_task all share this SAME Celery app and result
    backend, so a bare AsyncResult(job_id) lookup has no way to tell "an admin job" apart from
    "any other task's id" — without this marker, get_status would happily return another
    tenant's pipeline-run exception text, or crash trying to ** a non-dict result (reap_task/
    self_check_task return list[str], not a dict) for an id this router never queued.
    Best-effort: if Redis is unreachable here, the marker write is skipped (fails open on the
    QUEUE side, same as the rest of this codebase's Redis usage) and the job simply becomes
    unpollable via status (report success anyway; get_settings().result_expires_seconds is the
    same TTL the result backend itself already uses, so the marker and the result it gates
    expire together)."""
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
    """Wipe a group's (or named items') cached vectors — no re-embed. [REVIEW-FIX] `group`
    and `names` cannot BOTH be omitted: unlike update/recreate (which rebuild and so
    self-heal), a bare `{}` here would silently wipe the ENTIRE cross-tenant cache with no
    extra friction — the one truly destructive, non-self-rebuilding action must require at
    least one explicit scope."""
    if not body.group and not body.names:
        raise AdminValidationError(
            "delete requires group and/or names — refusing to wipe the entire cache with an empty request")
    _require_group_when_names_given(body)
    accepted = _enqueue("delete", body)
    _audit(request, "delete", body, principal, accepted.job_id)
    return accepted


@router.get("/status/{job_id}", response_model=EmbeddingJobStatus)
def get_status(job_id: str, _principal: Principal = Depends(get_principal)) -> EmbeddingJobStatus:
    """Polls Celery's own AsyncResult for a job one of the four routes above queued — no new
    infrastructure beyond the provenance marker _enqueue writes above. That marker is checked
    FIRST: run_pipeline_task/regenerate_task/reap_task/self_check_task share this same Celery
    app/result backend, so without it, any caller who learns another task's id (e.g. from logs
    or Subsystem_Stage_State.ActiveTaskID) could poll ITS result here too — a real per-entity
    authorization bypass, since this route only checks the admin gates, never
    principal.require_entity(...). An id this router never queued (or whose marker/result TTL
    already expired) reports 404, never a guess at Celery's own state for it.

    Deliberately NOT fail-open on a Redis error here, unlike llm.py's concurrency limiter or
    _enqueue's own marker write above: those guard availability (an infra fault must never
    block a real call), but this check guards AUTHORIZATION (which job a caller may read) — an
    unreachable Redis must deny by falling through to the generic 500 handler, not silently
    let every job_id through."""
    if not admin_job_exists(job_id, FAMILY_EMBEDDINGS):
        raise NotFoundError(f"unknown or expired job_id: {job_id!r}")
    result = AsyncResult(job_id, app=celery_app)
    if result.state == "FAILURE":
        return EmbeddingJobStatus(state=result.state, error=str(result.result))
    if result.state == "SUCCESS":
        return EmbeddingJobStatus(state=result.state, **(result.result or {}))
    return EmbeddingJobStatus(state=result.state)
