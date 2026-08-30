"""Admin API — threat-library embedding cache maintenance (create/update/recreate/delete).

Asynchronous: each POST validates, audits, queues admin_embedding_action_task and returns 202 +
a job_id. GET .../status/{job_id} polls Celery's own AsyncResult; GET .../events/{job_id}
streams the worker's live embedding_job_update hints over SSE.
"""
from __future__ import annotations

import json

from celery.result import AsyncResult
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy import update as sa_update
from sqlalchemy.exc import IntegrityError

from app.api.admin_jobs import (
    FAMILY_EMBEDDINGS,
    FAMILY_GROUNDING,
    admin_job_exists,
    emb_job_channel_key,
    grounding_job_channel_key,
    mark_admin_job,
)
from app.api.admin_sse import admin_job_event_stream
from app.api.deps import Principal, get_admin_principal, require_admin
from app.api.schemas import (
    UNAVAILABLE_RESPONSES,
    EmbeddingActionBody,
    EmbeddingJobAccepted,
    EmbeddingJobEvent,
    EmbeddingJobStatus,
    GroundingCalibrationAccepted,
    GroundingCalibrationBody,
    GroundingCalibrationHistory,
    GroundingCalibrationRun,
    GroundingCalibrationStatus,
    GroundingJobEvent,
    GroundingThresholdResponse,
)
from app.core.config import get_settings
from app.core.enums import (
    CalibrationStatus,
    CeleryJobState,
    SSEEventType,
)
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.db.dal import NotFoundError
from app.db.engine import db_session
from app.pipeline import grounding
from app.pipeline.celery_app import admin_embedding_action_task, calibrate_grounding_task, celery_app
from app.pipeline.llm import get_llm

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


def _enqueue(action: str, body: EmbeddingActionBody, user_id: str | None) -> EmbeddingJobAccepted:
    """Queues the action (indirection so tests can run it synchronously) and records the
    provenance marker get_status below requires.

    Every other task shares this Celery app and result backend, so without the marker a bare
    AsyncResult(job_id) lookup cannot tell an admin job from any other task's id — get_status
    would return another tenant's pipeline exception text, or crash trying to `**` a list.
    The marker write is best-effort: an unreachable Redis leaves the job merely unpollable.

    No entity_id in the shadow label: this is an admin action, cross-tenant by design."""
    task = admin_embedding_action_task.apply_async(
        args=(action, body.group, body.names), shadow=(
            f"embeddings {action}: {body.group or 'all groups'} · by {user_id} · "
            f"{dal.now():%Y-%m-%d %H:%M} UTC"))
    mark_admin_job(task.id, FAMILY_EMBEDDINGS, user_id)  # best-effort — see admin_jobs.mark_admin_job
    return EmbeddingJobAccepted(job_id=task.id)


@router.post("/create", response_model=EmbeddingJobAccepted, status_code=202)
def create(body: EmbeddingActionBody, request: Request,
        principal: Principal = Depends(get_admin_principal)) -> EmbeddingJobAccepted:
    """Fingerprint specific NEW item(s) you name — for right after a threat is added."""
    if not body.group or not body.names:
        raise AdminValidationError("create requires both group and names")
    accepted = _enqueue("create", body, principal.user_id)
    _audit(request, "create", body, principal, accepted.job_id)
    return accepted


@router.post("/update", response_model=EmbeddingJobAccepted, status_code=202)
def update(body: EmbeddingActionBody, request: Request,
        principal: Principal = Depends(get_admin_principal)) -> EmbeddingJobAccepted:
    """Whole-group sync: embed whatever's missing across every active row (`group=None` =
    every group). `names` isn't part of this action's contract — see /create for targeted
    embedding of specific items."""
    accepted = _enqueue("update", body, principal.user_id)
    _audit(request, "update", body, principal, accepted.job_id)
    return accepted


@router.post("/recreate", response_model=EmbeddingJobAccepted, status_code=202)
def recreate(body: EmbeddingActionBody, request: Request,
        principal: Principal = Depends(get_admin_principal)) -> EmbeddingJobAccepted:
    """Wipe a group's (or named items') cached vectors, then re-embed them from scratch."""
    _require_group_when_names_given(body)
    accepted = _enqueue("recreate", body, principal.user_id)
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
    accepted = _enqueue("delete", body, principal.user_id)
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


@router.get("/events/{job_id}",
            responses={200: {"model": EmbeddingJobEvent, "content": {"text/event-stream": {}},
                        "description": "SSE stream; each `data:` line is one EmbeddingJobEvent."}}
                    | UNAVAILABLE_RESPONSES)
async def job_events(job_id: str, _principal: Principal = Depends(get_admin_principal)):
    """SSE stream for one queued embedding action: a state snapshot on connect (a late
    subscriber to a finished job gets the terminal state immediately and the stream closes),
    then the worker's live `embedding_job_update` hints (STARTED, per-group progress,
    terminal). The marker gate is the same authorization boundary as get_status above.

    SSE stays a HINT layer (the session-stream contract applies here too): a dead worker or an
    open publish breaker sends nothing, so the shared implementation's tick backstop re-reads
    the real AsyncResult state on a fixed cadence and closes the stream itself once terminal —
    get_status remains the durable truth. Streaming mechanics live in admin_sse.py, shared with
    the grounding-calibration and intel-refresh job-events routes.

    Same header requirement as GET /v1/sessions/{session_id}/events: this is a fetch()+
    ReadableStream stream sent with the admin auth headers this API requires, so the browser's
    native `EventSource` API cannot consume it (it cannot set custom headers)."""
    return await admin_job_event_stream(
        job_id, FAMILY_EMBEDDINGS, emb_job_channel_key, str(SSEEventType.embedding_job_update))


# ---------------------------------------------------------------------------
# Grounding-threshold calibration — measure the match cutoff for the CURRENTLY configured
# embedding+reranker pair instead of pinning it by hand.
#
# Own prefix (not the embeddings one) because this is not a cache operation: it is a property of
# the MODEL PAIR, stored per pair in Mongo and reused by every worker and every later boot.
#
# Asynchronous for the same reason as the embedding routes, only more so — a sweep is
# `TSG_CALIBRATION_SAMPLE_SIZE` local rerank passes plus that many BILLED paraphrase calls, which
# runs into minutes. It is deliberately NOT on the worker boot path: worker_init runs before the
# worker registers on the broker, so a sweep there made every cold start miss its readiness
# window. Worker boot now queues this job and comes up immediately.
# ---------------------------------------------------------------------------
grounding_router = APIRouter(
    prefix="/v1/tsg/grounding",
    tags=["Grounding Admin"],
    dependencies=[Depends(require_admin)],
)


@grounding_router.get("/threshold", response_model=GroundingThresholdResponse)
def get_threshold(_principal: Principal = Depends(get_admin_principal)) -> GroundingThresholdResponse:
    """The match cutoff in force RIGHT NOW, with its provenance.

    Read-only and cheap — never calibrates (no allow_calibration), so this route is safe to poll.
    `origin` is the field that matters: 'static_default' means the number was tuned for a
    DIFFERENT model pair and every grounding decision made on it is provisional, which is the
    cue to POST /calibrate."""
    s = get_settings()
    with db_session() as sess:
        th = grounding.resolve_thresholds(sess, get_llm(), s)
    return GroundingThresholdResponse(
        value=th.value, origin=th.origin,
        embedding_model=s.embedding_model, reranker_model=s.reranker_model)


class CalibrationConflict(Exception):
    """A calibration for this model pair is already running -> 409 (see app/api/errors.py).

    Carries the in-flight RunID so the caller can poll that one instead of retrying blind — the
    same courtesy SessionConflict extends with its active_session_id."""

    def __init__(self, message: str, run_id: str | None = None) -> None:
        super().__init__(message)
        self.run_id = run_id


@grounding_router.post("/calibrate", response_model=GroundingCalibrationAccepted, status_code=202)
def calibrate(request: Request, body: GroundingCalibrationBody | None = None,
            principal: Principal = Depends(get_admin_principal)) -> GroundingCalibrationAccepted:
    """Start a calibration sweep for the current embedding+reranker pair; returns 202 + a job_id.

    THE ONLY WAY A CALIBRATION EVER STARTS. Nothing queues one automatically — a sweep is 10-15
    minutes and ~100 billed LLM calls, so it is a deliberate act with an accountable caller.

    The ledger row is opened HERE, before the task is queued, and that ordering IS the concurrency
    guard. `UX_GroundingCalibration_Running` is a unique index filtered on Status='running', so a
    second concurrent request's INSERT is refused by the database and becomes a 409. Checking "is
    one running?" in Python instead leaves a window where two requests both read "no" and both
    queue a sweep; the database has no such window. Queueing first would move the guard behind the
    broker, where the duplicate has already been promised a 202.

    Without `force`, a pair that already has a successful run is a no-op the job reports as
    skipped=already_calibrated. Send force=true after curating the library."""
    force = bool(body.force) if body else False
    s = get_settings()
    key = (s.embedding_model, s.reranker_model)
    try:
        run_id = grounding.record_calibration_started(
            key, job_id=None, started_by=principal.user_id,
            started_by_client=principal.client_id, forced=force)
    except IntegrityError as exc:
        # The unique index refused it: another sweep for this pair is in flight. Abandoned rows
        # were already settled inside record_calibration_started, so this one is genuinely LIVE.
        with db_session() as sess:
            live = grounding.running_run(sess, key)
        raise CalibrationConflict(
            "a calibration for this embedding+reranker pair is already running — poll it rather "
            "than starting a second 10-15 minute sweep",
            run_id=str(live.RunID) if live is not None else None) from exc

    try:
        task = calibrate_grounding_task.apply_async(
            args=(force, principal.user_id, principal.client_id, run_id), shadow=(
                f"grounding-calibrate: run {run_id} · by {principal.user_id} · "
                f"{dal.now():%Y-%m-%d %H:%M} UTC" + (" (forced)" if force else "")))
    except BaseException as exc:
        # The row is the lock, and it is opened BEFORE the queue on purpose. If the broker refuses
        # the publish there is no worker to close it, so close it here — otherwise every calibrate
        # request for the next calibration_stale_after_seconds gets a 409 pointing at a sweep that
        # never started. Scope is exactly this call: once .delay() returns the task owns the row,
        # and settling it from here would race a live sweep.
        grounding.record_calibration_finished(run_id, error=f"queueing failed: {exc!r}")
        raise
    mark_admin_job(task.id, FAMILY_GROUNDING, principal.user_id)  # best-effort — see admin_jobs.mark_admin_job
    _attach_job_id(run_id, task.id)
    # AFTER .delay() for the same reason _audit fires after _enqueue: logging first would leave a
    # permanent record of a sweep that never ran when the broker was unreachable. The ledger row
    # is deliberately written BEFORE — it is the lock, not the log.
    log.warning("admin.grounding_calibration", force=force, job_id=task.id, run_id=run_id,
                user_id=principal.user_id, client_id=principal.client_id,
                source_ip=request.client.host if request.client else None)
    return GroundingCalibrationAccepted(job_id=task.id, run_id=run_id)


def _attach_job_id(run_id: str, job_id: str) -> None:
    """Stamp the Celery task id onto the ledger row now that the broker has accepted it.

    Two steps because the row must exist BEFORE the task is queued (it is the concurrency guard),
    and the task id only exists after. Best-effort: JobID only cross-references the Celery result,
    and the row is already complete and correct without it."""
    try:
        with db_session() as sess:
            sess.execute(
                sa_update(m.Grounding_Calibration_Run)
                .where(m.Grounding_Calibration_Run.RunID == run_id)
                .values(JobID=job_id))
    except Exception:
        log.warning("admin.grounding_calibration_jobid_failed", run_id=run_id, job_id=job_id,
                    exc_info=True)


@grounding_router.get("/calibrations", response_model=GroundingCalibrationHistory)
def list_calibrations(limit: int = Query(default=50, ge=1, le=200),
                    _principal: Principal = Depends(get_admin_principal)) -> GroundingCalibrationHistory:
    """Calibration history, newest first — who ran it, when, and whether it passed.

    THE REASON THE LEDGER TABLE EXISTS. Celery's own result expires after
    TSG_RESULT_EXPIRES_SECONDS (1h by default), so `/calibrate/status/{job_id}` cannot answer
    "did last Tuesday's calibration succeed?" — and before this table a FAILED sweep wrote nothing
    at all. These rows are permanent.

    `status` is settled, not raw: a `running` row older than the stale window reads as `failed`
    with a synthesized cause, because it cannot still be running and saying otherwise misleads
    every consumer."""
    with db_session() as sess:
        rows = grounding.recent_runs(sess, limit)
        return GroundingCalibrationHistory(runs=[_to_calibration_run(r) for r in rows])


def _to_calibration_run(row) -> GroundingCalibrationRun:
    """Ledger row -> response. `status`/`error` go through the settling helpers so an abandoned
    run is reported as the failure it is."""
    return GroundingCalibrationRun(
        run_id=str(row.RunID), job_id=row.JobID,
        status=grounding.settled_status(row), started_by=row.StartedBy,
        started_by_client=row.StartedByClient,
        started_at=row.StartedAt, finished_at=row.FinishedAt,
        embedding_model=row.EmbeddingModel, reranker_model=row.RerankerModel,
        forced=bool(row.Forced), match_th=row.MatchTh, quality=row.Quality,
        negatives=row.NegativesCount, positives=row.PositivesCount,
        highest_negative=row.HighestNegative, lowest_positive=row.LowestPositive,
        near_duplicates=json.loads(row.NearDuplicatesJSON) if row.NearDuplicatesJSON else [],
        error=grounding.settled_error(row))


@grounding_router.get("/calibrate/status/{job_id}", response_model=GroundingCalibrationStatus)
def get_calibration_status(job_id: str,
                        _principal: Principal = Depends(get_admin_principal)) -> GroundingCalibrationStatus:
    """Polls one sweep's outcome — Celery's AsyncResult while it lives, the LEDGER after it dies.

    The provenance marker is checked FIRST, and is NOT fail-open on a Redis error — identical
    reasoning to get_status above: this route never calls require_entity, so without the marker
    any caller who learned another task's id could read ITS result here.

    The ledger fallback is what makes this route survivable. Celery's result and the marker share
    one TTL (an hour by default), so beyond that this used to 404 a sweep that had genuinely
    succeeded — the exact question an operator asks late. The ledger row is permanent, so a miss
    on the marker is now "look it up properly", not "never happened"."""
    if not admin_job_exists(job_id, FAMILY_GROUNDING):
        row = _calibration_row_by_job(job_id)
        if row is None:
            raise NotFoundError(f"unknown or expired job_id: {job_id!r}")
        return _status_from_row(row)
    result = AsyncResult(job_id, app=celery_app)
    state = CeleryJobState(result.state)
    if state is CeleryJobState.FAILURE:
        return GroundingCalibrationStatus(state=state, error=str(result.result))
    if state is CeleryJobState.SUCCESS:
        return GroundingCalibrationStatus(state=state, **(result.result or {}))
    return GroundingCalibrationStatus(state=state)


def _calibration_row_by_job(job_id: str):
    """The ledger row for a Celery task id, or None. Doubles as the authorization check the
    expired marker can no longer make: a job_id this router never queued has no row here."""
    with db_session() as sess:
        return sess.execute(
            select(m.Grounding_Calibration_Run)
            .where(m.Grounding_Calibration_Run.JobID == job_id)).scalars().first()


def _status_from_row(row) -> GroundingCalibrationStatus:
    """Ledger row -> the same shape the live Celery path returns, so a caller polling across the
    TTL boundary sees one contract rather than two. `no_signal` and `success` both map to a
    SUCCESS job state — the sweep ran; `match_th` being null is the finding."""
    settled = grounding.settled_status(row)
    # success / no_signal / skipped are all SUCCESSFUL JOBS — the task ran and returned. What
    # differs is what it found, which `match_th` and `skipped` below carry. Only `failed` means
    # the job itself raised; anything else is still in flight.
    state = (CeleryJobState.FAILURE if settled == CalibrationStatus.failed
            else CeleryJobState.SUCCESS if settled in (CalibrationStatus.success,
                                                        CalibrationStatus.no_signal,
                                                        CalibrationStatus.skipped)
            else CeleryJobState.STARTED)
    return GroundingCalibrationStatus(
        state=state, run_id=str(row.RunID), match_th=row.MatchTh, quality=row.Quality,
        skipped="already_calibrated" if settled == CalibrationStatus.skipped else None,
        negatives=row.NegativesCount, positives=row.PositivesCount,
        highest_negative=row.HighestNegative, lowest_positive=row.LowestPositive,
        near_duplicates=json.loads(row.NearDuplicatesJSON) if row.NearDuplicatesJSON else [],
        embedding_model=row.EmbeddingModel, reranker_model=row.RerankerModel,
        error=grounding.settled_error(row))


@grounding_router.get("/calibrate/events/{job_id}",
            responses={200: {"model": GroundingJobEvent, "content": {"text/event-stream": {}},
                        "description": "SSE stream; each `data:` line is one GroundingJobEvent."}}
                    | UNAVAILABLE_RESPONSES)
async def calibration_events(job_id: str, _principal: Principal = Depends(get_admin_principal)):
    """SSE stream for one calibration sweep: a state snapshot on connect, then the worker's live
    `grounding_job_update` hints — STARTED, then phase/done/total ticks as the negatives and
    positives passes progress, then the terminal result.

    Worth streaming rather than polling precisely because a sweep runs for MINUTES: the progress
    ticks are the only way to tell "still measuring" from "wedged". Same hint-layer contract as
    every other admin job stream — get_calibration_status stays the durable truth.

    Same header requirement as GET /v1/sessions/{session_id}/events: this is a fetch()+
    ReadableStream stream sent with the admin auth headers this API requires, so the browser's
    native `EventSource` API cannot consume it (it cannot set custom headers)."""
    return await admin_job_event_stream(
        job_id, FAMILY_GROUNDING, grounding_job_channel_key, str(SSEEventType.grounding_job_update))
