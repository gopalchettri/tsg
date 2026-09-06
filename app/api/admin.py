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
    mark_admin_job(task.id, FAMILY_EMBEDDINGS, f"embeddings {action}", user_id)  # best-effort — see admin_jobs.mark_admin_job
    return EmbeddingJobAccepted(job_id=task.id)


@router.post("/create", response_model=EmbeddingJobAccepted, status_code=202,
            summary="Embed specific library names",
            description=(
                "Computes AI vectors for the exact names you list, so they become matchable.\n\n"
                "**When to use:** you inserted rows straight into SQL, bypassing the app. Normal library "
                "editing refreshes vectors automatically and needs none of this.\n\n"
                "**Both `group` and `names` are required** — 'create' means embed exactly these. At most 50 "
                "names per call. Anything that already has a vector is skipped, so calling twice is harmless.\n\n"
                "**What you get:** `202` with a `job_id`. Poll the status endpoint or stream the events one."
            ))
def create(body: EmbeddingActionBody, request: Request,
        principal: Principal = Depends(get_admin_principal)) -> EmbeddingJobAccepted:
    """Fingerprint specific NEW item(s) you name — for right after a threat is added."""
    if not body.group or not body.names:
        raise AdminValidationError("create requires both group and names")
    accepted = _enqueue("create", body, principal.user_id)
    _audit(request, "create", body, principal, accepted.job_id)
    return accepted


@router.post("/update", response_model=EmbeddingJobAccepted, status_code=202,
            summary="Fill in any missing vectors",
            description=(
                "Embeds anything that has no vector yet and skips everything that does. This is the safe "
                "default — when you are unsure which action you need, use this one.\n\n"
                "**When to use:** a fresh environment where nothing has vectors yet, or after rows were added "
                "behind the app's back.\n\n"
                "**Body:** an empty `{}` checks every group. Add `group` to limit it to one. Re-running costs "
                "nothing extra. `names` is accepted but IGNORED by this action — use create or recreate when "
                "you need to target specific names.\n\n"
                "**Watch out:** this never deletes or rewrites an existing vector. If the underlying text "
                "changed, use recreate instead — update will leave the stale vector in place."
            ))
def update(body: EmbeddingActionBody, request: Request,
        principal: Principal = Depends(get_admin_principal)) -> EmbeddingJobAccepted:
    """Whole-group sync: embed whatever's missing across every active row (`group=None` =
    every group). `names` isn't part of this action's contract — see /create for targeted
    embedding of specific items."""
    accepted = _enqueue("update", body, principal.user_id)
    _audit(request, "update", body, principal, accepted.job_id)
    return accepted


@router.post("/recreate", response_model=EmbeddingJobAccepted, status_code=202,
            summary="Rebuild vectors from scratch",
            description=(
                "Deletes the existing vectors and computes fresh ones in a single step.\n\n"
                "**When to use:** the source text changed behind the app's back (a typo fixed directly in "
                "SQL), or you switched embedding models and every stored vector is now from the old one.\n\n"
                "**Body:** `group` is optional, but you almost always want it. **Omitting it rebuilds EVERY "
                "group**, deleting and re-embedding the entire cache, which is slow and costs real AI calls. "
                "`names` still requires an explicit `group`.\n\n"
                "**Why not update:** update only adds what is missing. After a model switch it would leave "
                "the old model's vectors alongside the new ones, giving you two sets for the same items."
            ))
def recreate(body: EmbeddingActionBody, request: Request,
        principal: Principal = Depends(get_admin_principal)) -> EmbeddingJobAccepted:
    """Wipe a group's (or named items') cached vectors, then re-embed them from scratch."""
    _require_group_when_names_given(body)
    accepted = _enqueue("recreate", body, principal.user_id)
    _audit(request, "recreate", body, principal, accepted.job_id)
    return accepted


@router.post("/delete", response_model=EmbeddingJobAccepted, status_code=202,
            summary="Remove vectors permanently",
            description=(
                "Deletes vectors and does not recompute anything.\n\n"
                "**When to use:** a row was hard-deleted straight in SQL and its vector is now an orphan that "
                "nothing will ever clean up.\n\n"
                "**Body:** `group` is required, optionally narrowed by `names`. A bare `{}` is rejected on "
                "purpose so nobody wipes the whole cache by accident, and `names` without `group` is rejected "
                "too.\n\n"
                "**Watch out:** this touches the vector store only. Your SQL tables are never changed."
            ))
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


@router.get("/status/{job_id}", response_model=EmbeddingJobStatus,
            summary="Check an embedding job",
            description=(
                "Reports how a queued embedding job is going.\n\n"
                "**Call it:** every few seconds after any of the four embedding actions, until `state` stops "
                "being `PENDING`, `STARTED` or `RETRY`. `RETRY` is NOT finished — the job hit a transient "
                "problem and is queued to run again.\n\n"
                "**Reading the result:** all four fields are always present. `rows_processed` and "
                "`vectors_deleted` are keyed by group and stay null until the job finishes; `error` is filled "
                "in only on failure.\n\n"
                "**Watch out:** job ids expire with the result backend, roughly an hour, after which this "
                "returns `404`. Requires the admin key plus a valid client key and user id."
            ))
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
                    | UNAVAILABLE_RESPONSES,
            summary="Stream an embedding job",
            description=(
                "Pushes an embedding job's progress live instead of you polling, and closes itself once the "
                "job finishes.\n\n"
                "**Worth using for:** rebuilding the control library, the one action slow enough to watch.\n\n"
                "**What arrives:** a snapshot of the job's current state immediately on connect, then a frame "
                "per group as the worker completes it, plus heartbeats. A retry frame can appear and does not "
                "close the stream.\n\n"
                "**Watch out:** connecting to a job that already finished gives you one terminal frame and an "
                "immediate close — earlier progress is never replayed. A terminal snapshot does carry the "
                "final counts or the error; what it never carries is the per-group progress fields, which "
                "only a running worker publishes. A browser's built-in `EventSource` cannot be used, because "
                "this needs custom headers."
            ))
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


@grounding_router.get("/threshold", response_model=GroundingThresholdResponse,
            summary="Get the current matching threshold",
            description=(
                "Reports the similarity cutoff the AI is grounding threats against right now, and where that "
                "number came from. Read-only and cheap — safe to poll from a dashboard.\n\n"
                "**`origin` is the field that matters.** `calibrated` means it was measured for exactly the "
                "embedding and reranker models running now, and can be trusted. `env_pinned` means it came "
                "from configuration because nothing has been calibrated for this model pair. `static_default` "
                "means it is the built-in fallback, tuned for a different model pair, and is provisional.\n\n"
                "**What to do:** if `origin` is anything but `calibrated`, run a calibration sweep."
            ))
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


@grounding_router.post("/calibrate", response_model=GroundingCalibrationAccepted, status_code=202,
            summary="Measure a new matching threshold",
            description=(
                "Starts a sweep that measures the right similarity cutoff for the embedding and reranker "
                "models running right now. This is the only way to start one through the API, and nothing "
                "queues one automatically, because a sweep is long and makes real AI calls. An operator can "
                "also run the same sweep from a maintenance script.\n\n"
                "**When to use:** the threshold endpoint reports anything other than `calibrated`, you "
                "swapped a model, or you curated the threat library and want a tighter number.\n\n"
                "**Body is optional.** Omitting it, or sending `{}`, is the same as `{\"force\": false}`.\n\n"
                "**Watch out:** without `force`, a model pair that already has a successful run finishes "
                "almost immediately reporting `already_calibrated` — the measurement never runs and no AI "
                "calls are made. Send `force: true` to genuinely re-measure. A second sweep for the same pair "
                "while one is running is refused.\n\n"
                "**What you get:** `202` with a `job_id` for polling and a permanent `run_id` for the ledger."
            ))
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
    mark_admin_job(task.id, FAMILY_GROUNDING, "grounding-calibrate" + (" (forced)" if force else ""),
                principal.user_id)  # best-effort — see admin_jobs.mark_admin_job
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


@grounding_router.get("/calibrations", response_model=GroundingCalibrationHistory,
            summary="List calibration history",
            description=(
                "Every calibration run, newest first, with who started it, when, and how it ended.\n\n"
                "**Call it:** to audit who last calibrated, or to check a model pair's history before "
                "deciding whether to run another sweep. `limit` defaults to 50 and caps at 200.\n\n"
                "**The five outcomes:** `running` (in flight), `success` (measured and stored), `no_signal` "
                "(ran, but no cutoff beat chance for this model pair — a finding, not a crash), `skipped` "
                "(declined to re-measure because one already existed), `failed`.\n\n"
                "**Watch out:** `started_by` is the user id the caller claimed and is not verified, since "
                "admin routes share one key. `started_by_client` is the API client it actually authenticated "
                "as, and that half is verified."
            ))
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


@grounding_router.get("/calibrate/status/{job_id}", response_model=GroundingCalibrationStatus,
            summary="Check a calibration sweep",
            description=(
                "Reports how a calibration sweep is going, and its measurement once it finishes.\n\n"
                "**Call it:** in a loop after starting a sweep, until `state` stops being `PENDING`, "
                "`STARTED` or `RETRY`.\n\n"
                "**Reading the result:** all thirteen fields are always present, with nulls for whatever does "
                "not apply yet. `quality` tells you whether to trust `match_th` — 1.0 is perfect separation, "
                "0.0 is no better than chance.\n\n"
                "**Watch out:** `SUCCESS` with a null `match_th` is a real, meaningful outcome, not a bug. It "
                "means the sweep ran and found that no cutoff separates real matches from impostors under "
                "this model pair. Late polls still work after the job id expires, because this falls back to "
                "the permanent ledger."
            ))
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
                    | UNAVAILABLE_RESPONSES,
            summary="Stream a calibration sweep",
            description=(
                "Pushes a calibration sweep's progress live, which beats polling for a job that runs 10-15 "
                "minutes.\n\n"
                "**What arrives:** a state snapshot immediately on connect, then progress ticks showing which "
                "phase is running and how far through it is, then a final frame carrying the measurement. "
                "Heartbeats keep the line alive in between.\n\n"
                "**Watch out:** the stream closes itself on success, failure or revocation. Connecting after "
                "the job finished gives you that terminal frame at once with no replay of the progress. "
                "Unlike the status endpoint, this stream has NO permanent fallback: once the job marker "
                "expires you get `404` here even though the status endpoint still answers from the ledger. A "
                "browser's built-in `EventSource` cannot be used, because this needs custom headers."
            ))
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
