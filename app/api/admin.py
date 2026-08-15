"""Admin API — threat-library embedding cache maintenance (create/update/recreate/delete).

Asynchronous: each POST validates, audits, queues admin_embedding_action_task and returns 202 +
a job_id. GET .../status/{job_id} polls Celery's own AsyncResult; GET .../events/{job_id}
streams the worker's live embedding_job_update hints over SSE.
"""
from __future__ import annotations

from celery.result import AsyncResult
from fastapi import APIRouter, Depends, Query, Request

from app.api.admin_jobs import FAMILY_EMBEDDINGS, admin_job_exists, emb_job_channel_key, mark_admin_job
from app.api.admin_sse import admin_job_event_stream
from app.api.deps import Principal, get_admin_principal, require_admin
from app.api.schemas import (
    CandidateResolutionResult,
    EmbeddingActionBody,
    EmbeddingJobAccepted,
    EmbeddingJobStatus,
    PendingCandidate,
    PendingCandidatesResponse,
    PendingPromotion,
    PendingPromotionsResponse,
    PromotionRetryResult,
)
from app.core.config import get_settings
from app.core.enums import CandidateStatus, CeleryJobState, SSEEventType
from app.core.logging import get_logger
from app.db import dal
from app.db.dal import NotFoundError
from app.db.engine import db_session
from app.pipeline.accept import AcceptConflict, eager_embed_promoted, resolve_candidate
from app.pipeline.llm import get_llm
from app.pipeline.celery_app import admin_embedding_action_task, celery_app
from app.pipeline.reaper import dismiss_promotion, retry_one_promotion

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
        principal: Principal = Depends(get_admin_principal)) -> EmbeddingJobAccepted:
    """Fingerprint specific NEW item(s) you name — for right after a threat is added."""
    if not body.group or not body.names:
        raise AdminValidationError("create requires both group and names")
    accepted = _enqueue("create", body)
    _audit(request, "create", body, principal, accepted.job_id)
    return accepted


@router.post("/update", response_model=EmbeddingJobAccepted, status_code=202)
def update(body: EmbeddingActionBody, request: Request,
        principal: Principal = Depends(get_admin_principal)) -> EmbeddingJobAccepted:
    """Whole-group sync: embed whatever's missing across every active row (`group=None` =
    every group). `names` isn't part of this action's contract — see /create for targeted
    embedding of specific items."""
    accepted = _enqueue("update", body)
    _audit(request, "update", body, principal, accepted.job_id)
    return accepted


@router.post("/recreate", response_model=EmbeddingJobAccepted, status_code=202)
def recreate(body: EmbeddingActionBody, request: Request,
        principal: Principal = Depends(get_admin_principal)) -> EmbeddingJobAccepted:
    """Wipe a group's (or named items') cached vectors, then re-embed them from scratch."""
    _require_group_when_names_given(body)
    accepted = _enqueue("recreate", body)
    _audit(request, "recreate", body, principal, accepted.job_id)
    return accepted


@router.post("/delete", response_model=EmbeddingJobAccepted, status_code=202)
def delete(body: EmbeddingActionBody, request: Request,
        principal: Principal = Depends(get_admin_principal)) -> EmbeddingJobAccepted:
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
def get_status(job_id: str, _principal: Principal = Depends(get_admin_principal)) -> EmbeddingJobStatus:
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
    state = CeleryJobState(result.state)  # total over Celery's vocabulary — see the enum
    if state is CeleryJobState.FAILURE:
        return EmbeddingJobStatus(state=state, error=str(result.result))
    if state is CeleryJobState.SUCCESS:
        return EmbeddingJobStatus(state=state, **(result.result or {}))
    return EmbeddingJobStatus(state=state)


@router.get("/events/{job_id}", responses={200: {"content": {"text/event-stream": {}}}})
async def job_events(job_id: str, _principal: Principal = Depends(get_admin_principal)):
    """SSE stream for one queued embedding action: a state snapshot on connect (a late
    subscriber to a finished job gets the terminal state immediately and the stream closes),
    then the worker's live `embedding_job_update` hints (STARTED, per-group progress,
    terminal). The marker gate is the same authorization boundary as get_status above.

    SSE stays a HINT layer (the session-stream contract applies here too): a dead worker or an
    open publish breaker sends nothing, so the shared implementation's tick backstop re-reads
    the real AsyncResult state on a fixed cadence and closes the stream itself once terminal —
    get_status remains the durable truth. Streaming mechanics live in admin_sse.py, shared with
    the import and intel-refresh job-events routes."""
    return await admin_job_event_stream(
        job_id, FAMILY_EMBEDDINGS, emb_job_channel_key, str(SSEEventType.embedding_job_update))


# ---------------------------------------------------------------------------
# Session-promotion admin — visibility and control over sessions whose library promotion
# (accept.py's isolated Phase 2) failed. The accept itself already succeeded for every session
# listed here; only the "add novel threats to the shared library" side-effect is pending.
# ---------------------------------------------------------------------------
promotions_router = APIRouter(
    prefix="/v1/tsg/sessions",
    tags=["Session Admin"],
    dependencies=[Depends(require_admin)],
)


def _to_pending_promotion(row, max_attempts: int) -> PendingPromotion:
    """Shared row -> response mapping for the list and detail promotion routes, so the two
    routes can never disagree about what a field means."""
    return PendingPromotion(
        session_id=row["SessionID"], entity_id=row["EntityID"], asset_id=row["AssetID"],
        asset_name=row["AssetName"], failed_at=row["PromotionFailedAt"].isoformat(),
        attempts=row["PromotionAttempts"], max_attempts=max_attempts,
        exhausted=row["PromotionAttempts"] >= max_attempts,
        error=row["PromotionError"], user_id=row["PromotionUserID"],
        completed_at=row["CompletedAt"].isoformat() if row["CompletedAt"] else None,
    )


@promotions_router.get("/promotions", response_model=PendingPromotionsResponse)
def list_promotions(
    limit: int = Query(default=100, ge=1, description="Max rows to return."),
    include_exhausted: bool = Query(
        default=True,
        description="Include sessions the automatic sweep has already given up on (still manually retryable)."),
    _principal: Principal = Depends(get_admin_principal),
) -> PendingPromotionsResponse:
    """Every session currently stuck on a failed library promotion, oldest failure first."""
    settings = get_settings()
    bounded_limit = min(limit, settings.promotion_list_max_limit)
    with db_session() as sess:
        rows = dal.list_pending_promotions(
            sess, limit=bounded_limit, include_exhausted=include_exhausted,
            max_attempts=settings.promotion_max_attempts)
    promotions = [_to_pending_promotion(row, settings.promotion_max_attempts) for row in rows]
    return PendingPromotionsResponse(promotions=promotions, total=len(promotions),
                                    auto_retry_enabled=settings.promotion_auto_retry_enabled)


@promotions_router.get("/promotions/{session_id}", response_model=PendingPromotion)
def get_promotion(session_id: str, _principal: Principal = Depends(get_admin_principal)) -> PendingPromotion:
    """One session's promotion-failure detail. 404 if it isn't currently in a failed state."""
    settings = get_settings()
    with db_session() as sess:
        row = dal.get_pending_promotion(sess, session_id)
    if row is None:
        raise NotFoundError(f"session {session_id!r} has no pending promotion failure")
    return _to_pending_promotion(row, settings.promotion_max_attempts)


@promotions_router.post("/promotions/{session_id}/retry", response_model=PromotionRetryResult)
def retry_promotion(session_id: str, principal: Principal = Depends(get_admin_principal)) -> PromotionRetryResult:
    """Force a retry now, instead of waiting for the next scheduled sweep. Synchronous: one
    retry is a single bounded operation (unlike the embeddings actions above, which can re-embed
    a whole group), so there is no need for the async job/poll pattern those use. Always
    available regardless of promotion_max_attempts — that cap only throttles the unattended
    sweep, never a human explicitly asking to retry."""
    with db_session() as sess:
        row = dal.get_pending_promotion(sess, session_id)
        if row is None:
            raise NotFoundError(f"session {session_id!r} has no pending promotion failure")
        outcome = retry_one_promotion(sess, session_id, row["EntityID"], row["PromotionUserID"])
    log.warning("admin.promotion_retry", session_id=session_id, outcome=outcome, user_id=principal.user_id)
    return PromotionRetryResult(session_id=session_id, outcome=outcome)


@promotions_router.delete("/promotions/{session_id}", response_model=PromotionRetryResult)
def dismiss_promotion_route(session_id: str, principal: Principal = Depends(get_admin_principal)) -> PromotionRetryResult:
    """Dismiss — stop tracking/retrying this session's failed promotion, without attempting it
    again. Serialized against any in-flight retry via the same per-session lock, so a dismiss can
    never be silently undone by a retry that was already mid-flight."""
    with db_session() as sess:
        row = dal.get_pending_promotion(sess, session_id)
        if row is None:
            raise NotFoundError(f"session {session_id!r} has no pending promotion failure")
        outcome = dismiss_promotion(sess, session_id, row["EntityID"], principal.user_id)
    log.warning("admin.promotion_dismissed", session_id=session_id, outcome=outcome, user_id=principal.user_id)
    return PromotionRetryResult(session_id=session_id, outcome=outcome)


# ---------------------------------------------------------------------------
# Threat-library candidate review — the curator workflow CandidateStatus's own docstring calls
# "reserved... set by the curator workflow when it lands". Lists and resolves
# Threat_Candidate_Review rows accept.py queues (always for an ambiguous triage verdict; also for
# a "genuinely novel" one when promotion_auto_approve_enabled is off).
# ---------------------------------------------------------------------------
candidates_router = APIRouter(
    prefix="/v1/tsg/threat-library/candidates",
    tags=["Threat Library Candidates"],
    dependencies=[Depends(require_admin)],
)


def _to_pending_candidate(row) -> PendingCandidate:
    """Shared row -> response mapping for the list and detail candidate routes."""
    return PendingCandidate(
        candidate_id=row["CandidateID"], session_id=row["SessionID"], entity_id=row["EntityID"],
        proposed_category=row["ProposedCategory"], proposed_type=row["ProposedType"],
        proposed_name=row["ProposedName"], proposed_generic_name=row["ProposedGenericName"],
        status=row["Status"], created_at=row["CreatedAt"].isoformat(),
    )


@candidates_router.get("", response_model=PendingCandidatesResponse)
def list_candidates(
    limit: int = Query(default=100, ge=1, description="Max rows to return."),
    _principal: Principal = Depends(get_admin_principal),
) -> PendingCandidatesResponse:
    """Every threat awaiting curator review, oldest first."""
    settings = get_settings()
    bounded_limit = min(limit, settings.promotion_list_max_limit)
    with db_session() as sess:
        rows = dal.list_pending_candidates(sess, limit=bounded_limit)
    candidates = [_to_pending_candidate(row) for row in rows]
    return PendingCandidatesResponse(candidates=candidates, total=len(candidates))


@candidates_router.get("/{candidate_id}", response_model=PendingCandidate)
def get_candidate_route(candidate_id: str, _principal: Principal = Depends(get_admin_principal)) -> PendingCandidate:
    """One candidate's full detail. 404 if the id doesn't exist."""
    with db_session() as sess:
        row = dal.get_candidate(sess, candidate_id)
    if row is None:
        raise NotFoundError(f"candidate {candidate_id!r} not found")
    return _to_pending_candidate(row)


def _resolve_and_respond(candidate_id: str, principal: Principal, *, approve: bool) -> CandidateResolutionResult:
    """Shared body for approve/reject: fetch, resolve, audit-log the admin action, respond —
    the only difference between the two routes below is the `approve` flag they pass in."""
    with db_session() as sess:
        candidate = dal.get_candidate(sess, candidate_id)
        if candidate is None:
            raise NotFoundError(f"candidate {candidate_id!r} not found")
        resolution = resolve_candidate(sess, candidate, principal.user_id, approve=approve)
    # db_session()'s `with` block has now committed (or raised) — the mint above, if any, is
    # durable. Eager-embed AFTER that, in a FRESH session, never inside the same block: doing it
    # before commit risks writing to Mongo for a name whose SQL row could still be rolled back by
    # a later failure in the same block (same orphan-vector trap run_promotion_phase avoids).
    if not resolution.won:
        raise AcceptConflict(f"candidate {candidate_id!r} was already reviewed")
    if resolution.promoted_names:
        with db_session() as sess:
            eager_embed_promoted(sess, get_llm(), resolution.promoted_names)
    status = CandidateStatus.accepted if approve else CandidateStatus.rejected
    log.warning("admin.candidate_resolved", candidate_id=candidate_id, status=status,
                user_id=principal.user_id)
    # resolve_candidate already computed these ids — no second read needed to report them.
    return CandidateResolutionResult(
        candidate_id=candidate_id, status=status,
        threat_type_id=resolution.type_id, threat_catalogue_id=resolution.catalogue_id)


@candidates_router.post("/{candidate_id}/approve", response_model=CandidateResolutionResult)
def approve_candidate(candidate_id: str, principal: Principal = Depends(get_admin_principal)) -> CandidateResolutionResult:
    """Approve — mint (or reuse) this candidate's Threat_Type/Threat_Catalogue entry into the
    shared library now. CAS-guarded: a candidate already reviewed by someone else returns 409,
    never re-runs the mint."""
    return _resolve_and_respond(candidate_id, principal, approve=True)


@candidates_router.post("/{candidate_id}/reject", response_model=CandidateResolutionResult)
def reject_candidate(candidate_id: str, principal: Principal = Depends(get_admin_principal)) -> CandidateResolutionResult:
    """Reject — close this candidate without adding anything to the shared library. Same
    CAS guard as approve."""
    return _resolve_and_respond(candidate_id, principal, approve=False)
