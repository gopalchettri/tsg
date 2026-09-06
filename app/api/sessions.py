"""Session API — create / status board / results / accept / cancel / SSE.

Object-level authz: every route resolves the session's EntityID and checks
it is in the caller's authorized set — a valid token is not enough.
"""
from __future__ import annotations

import asyncio
import json
from collections.abc import Iterable
from datetime import datetime
from functools import lru_cache
from typing import Literal, NamedTuple, NoReturn

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Query
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import Principal, get_principal
from app.api.schemas import (
    UNAVAILABLE_RESPONSES,
    AcceptBody,
    AcceptedScenario,
    AcceptedScenariosResponse,
    AcceptResponse,
    CancelResponse,
    CreateSessionBody,
    CreateSessionResponse,
    ErrorEvent,
    ErrorResponse,
    HeartbeatEvent,
    LibraryPromotionResponse,
    MappedControl,
    NextSetResultEvent,
    PromotedRef,
    RegenerateResponse,
    RegenerateScenariosBody,
    RegenResultEvent,
    RejectBody,
    RejectResponse,
    ScenarioListItem,
    ScenarioResult,
    SessionAuditEvent,
    SessionAuditPage,
    SessionBoard,
    SessionEnteredReviewEvent,
    SessionResults,
    StageCompletedEvent,
    StageStartedEvent,
    StandardRef,
    SubsystemStartedEvent,
    TreatmentPlanResultEvent,
)
from app.core import tuning
from app.core.config import get_settings
from app.core.enums import (
    AuditEventType,
    ControlMappingExhaustionReason,
    RegenGranularity,
    ReviewGateReason,
    SessionMode,
    SessionStatus,
    SSEEventType,
    StageStatus,
    SubsystemLevel,
    SubsystemProgress,
    WorkflowStage,
)
from app.core.logging import get_logger
from app.core.naming import display_threat_names
from app.db import dal
from app.db import models as m
from app.db.dal import EntityForbidden, IdempotencyKeyConflict, RegenerateConflict, now
from app.db.engine import db_session
from app.pipeline import cascade, grounding, tasks
from app.pipeline.accept import (
    AcceptConflict,
    accept_session,
    ensure_review_gate,
    reject_scenarios,
    review_gate_reason,
)
from app.pipeline.celery_app import next_set_task, regenerate_task, run_pipeline_task
from app.pipeline.context import gather_asset_details
from app.pipeline.grounding import stored_actors
from app.pipeline.promote import promote_scenario_to_library
from app.pipeline.tasks import ASSET_UNIT_ID, set_up_progress_tracking
from app.sse import bus

log = get_logger(__name__)

router = APIRouter(prefix="/v1", tags=["Threat Scenario Generation"])

# Cross-session scenario reads get their own Swagger group. A SEPARATE router, not per-route
# tags: FastAPI APPENDS route tags to router tags, which would list these under BOTH groups.
scenarios_router = APIRouter(prefix="/v1", tags=["Scenarios"])

#: Hard cap on ancestry-walk hops in GET /results. Each hop is one sequential round trip
#: (it needs the previous hop's ids), so an unbounded walk lets one heavily-regenerated
#: scenario add round trips to a polled endpoint. A hop is one REGENERATION of a single
#: scenario, so this cap is far past any real review workflow; beyond it the chain truncates
#: and logs rather than growing without limit. Stated as the constant, never as a literal in
#: prose — the comment said "25" for a while after the value moved to 100.
_MAX_ANCESTRY_HOPS = 100


def enqueue_pipeline(session_id: str, entity_id: str, user_id: str | None) -> None:
    """Indirection so tests can run the pipeline synchronously instead of via a broker."""
    # shadow is an apply_async-level option, not a task kwarg — .delay(x, shadow=...) would pass
    # shadow straight into run_pipeline_task's own signature and crash it. Flower/`celery
    # inspect` display name only; routing and task args are unaffected. entity_id/user_id/
    # timestamp are purely for at-a-glance identification in Flower's task list.
    run_pipeline_task.apply_async(args=(session_id,), shadow=(
        f"generate: session {session_id} · entity {entity_id} · by {user_id} · "
        f"{dal.now():%Y-%m-%d %H:%M} UTC"))


# --- status board ---
def get_overall_status(threats: str, scenarios: str, session_status: str,
                       *, undecided: bool = False) -> SubsystemProgress:
    """Rolls the threat stage, scenario stage and session status into one display status.
    Checks run in priority order — first match wins.

    `undecided` — does any active scenario still lack an accept/reject (dal.has_undecided_
    scenarios). It is a PARAMETER rather than something derived here because this function is
    pure and stage-only, while the answer lives in the scenario rows.

    It is also what makes this rollup able to tell two genuinely different sessions apart. The
    stage status CANNOT: Subsystem_Stage_State.SCENARIOS parks at AWAITING_DECISION when
    generation reaches the review barrier and is never moved off it (accept_session does not
    rewrite it — deliberately, so decisions stay changeable). Keyed on the stage alone, a
    fully-reviewed session and an untouched one look identical forever.
    """
    vals = (threats, scenarios)
    if StageStatus.ERROR in vals:
        return SubsystemProgress.error
    if session_status == SessionStatus.cancelled:
        return SubsystemProgress.cancelled
    # Tested BEFORE `completed`, and the order is load-bearing: generation completes the session
    # at its review barrier (tasks._send_to_review) to release the asset, so a session still
    # awaiting a human is `completed` too. Testing `completed` first would report every one of
    # them as `complete` and the review queue would look empty.
    #
    # The `undecided` half is what the earlier stage-only version got wrong. Without it this
    # branch fires for a FULLY REVIEWED session as well — the stage never leaves the barrier —
    # so "nobody has reviewed this" and "every scenario accepted" reported the same value.
    # `session_status == completed` is load-bearing, not belt-and-braces. The SCENARIOS stage
    # reaches AWAITING_DECISION as soon as the scenario rows are written, but the SESSION is only
    # moved to completed/REVIEW later, by tasks._send_to_review, once control mapping finishes —
    # the longest step in the pipeline. Without this conjunct the board reported `awaiting_review`
    # for that whole window while every decision endpoint refused with
    # `409 accept_conflict / generation_in_progress`, because accept's gate reads the SESSION and
    # this rollup read only the stage. A live run caught it: overall said "a human must decide"
    # for ~3 minutes while the API rejected every decision. A UI switching on this field — which
    # is exactly what its own documentation instructs — showed a Review button that could not
    # work. The two now agree by construction: this field never claims a decision is possible
    # before the endpoint that takes it would accept one.
    if (scenarios == StageStatus.AWAITING_DECISION and undecided
            and session_status == SessionStatus.completed):
        return SubsystemProgress.awaiting_review
    if session_status == SessionStatus.completed:
        return SubsystemProgress.complete
    if all(v == StageStatus.IDLE for v in vals):
        return SubsystemProgress.pending
    return SubsystemProgress.in_progress


#: Gap cells returned on the board. The full list lives in the grounding_summary audit row;
#: this caps what a status poll carries, and `unexplained` remains the true count.
_MAX_BOARD_GAPS = 50


def _coverage_verdict(sess: Session, session_id: str) -> dict | None:
    """The board's per-supporting-system dimension: which (unit x STRIDE) cells this
    assessment left unanswered.

    Read from the newest grounding_summary audit row rather than recomputed — identification
    already did the work, and re-deriving it on a status poll would let the poll and the audit
    trail disagree about the same session. Same durable-mirror pattern as last_next_set.

    Absent/short rows return None rather than a zero verdict: "nobody has measured this yet" and
    "measured, nothing missing" must never look alike on a safety signal.

    TSG_COVERAGE_REPORTING_ENABLED, off by default (config.py) — an early return here, before the
    query, so a disabled deployment pays nothing extra per poll; find_threats already skips writing
    this data at all while the flag is off, so this guard is belt-and-suspenders against a stale
    row from before a flip, not the only thing making this safe."""
    if not get_settings().coverage_reporting_enabled:
        return None
    detail = dal.latest_coverage_verdict(sess, session_id)
    cov = (detail or {}).get("coverage")
    if not isinstance(cov, dict) or "cells" not in cov:
        return None
    # Audit gaps are [subsystem_id, category] pairs (JSON has no tuples); named on the wire.
    gaps = [{"subsystem_id": int(g[0]), "category": str(g[1])}
            for g in (cov.get("gaps") or [])
            if isinstance(g, (list, tuple)) and len(g) == 2][:_MAX_BOARD_GAPS]
    unexplained = int(cov.get("unexplained") or 0)
    return {
        "cells": int(cov.get("cells") or 0),
        "covered": int(cov.get("covered") or 0),
        "justified_na": int(cov.get("justified_na") or 0),
        "unexplained": unexplained,
        "complete": unexplained == 0,
        "units": [int(u) for u in (detail or {}).get("units") or []],
        "gaps": gaps,
    }


def _wire_stage_status(status: str) -> str:
    """DB status -> the value published on the wire.

    SCENARIOS_AWAITING_DECISION becomes COMPLETE. The generation STAGE genuinely is finished at
    that point — scenarios are written, controls are mapped — and the DB value redundantly
    repeats "SCENARIOS" inside a field already called `scenarios`, while the published OpenAPI
    example has always said AWAITING_DECISION, so docs and wire already disagreed.

    The review barrier is NOT lost, but it moved OFF this field: `overall` carries it instead,
    reporting `awaiting_review` while any active scenario is undecided and `complete` once every
    one has been decided (get_overall_status + dal.has_undecided_scenarios). There is no
    `progress.awaiting_decision` boolean — an earlier draft proposed one and it was never built,
    so do not go looking for it. A client asking "is generation done" reads this field; a client
    asking "does a human still owe a decision" reads `progress.overall`. Internally
    nothing moves — Subsystem_Stage_State keeps SCENARIOS_AWAITING_DECISION,
    which every claim, sweep predicate and stage_settled_at_epoch check still keys on. Changing
    the stored value would silently reopen the review barrier.
    """
    return str(StageStatus.COMPLETE) if status == StageStatus.AWAITING_DECISION else str(status)


def _stage_timings(session_id: str, rows, control_seconds) -> dict[str, float] | None:
    """progress.timings: seconds per step, DERIVED from the stored stamps so no stored duration
    can disagree with them. A step is absent until it has both ends ("not measured", never 0.0);
    `controls` comes off the session because control mapping owns no stage row.

    A span that comes out NEGATIVE is withheld and logged with both stamps: it is two stamps from
    different attempts (a reset that kept an old FinishedAt) or from two workers' clocks (claim on
    A, finish on B after a retry), not a duration - and a number that reads as one is worse than
    a hole. dal.span_seconds refuses it; this is where the operator finds out why.
    """
    timings: dict[str, float] = {}
    for row in rows:
        level = str(row["Level"]).lower()
        started, finished = row["StartedAt"], row["FinishedAt"]
        if started and finished and finished < started:
            log.warning("progress.negative_stage_span", session_id=session_id, level=level,
                        started_at=started.isoformat(), finished_at=finished.isoformat())
            continue
        seconds = dal.span_seconds(started, finished)
        if seconds is not None:
            timings[level] = seconds
    if control_seconds is not None:
        # Summed working seconds across sweep passes, NOT a span - see the field description.
        timings["controls"] = round(float(control_seconds), 2)
    return timings or None


def build_board(sess: Session, scenario_session: dict) -> dict:
    """The GET /sessions/{id} payload and the SSE reconnect-reconcile source.

    STAGE progress stays one flat object, not a list, and that is a decision rather than a
    leftover: ASSET_UNIT_ID is the only subsystem the pipeline schedules work for, because one
    scenario covers a threat across every supporting system it reaches. Per-subsystem stage rows
    would transition in lockstep and carry no information while breaking every client.

    The per-supporting-system dimension that DOES carry information is coverage — which
    (system x STRIDE) cells were answered — and that rides in `progress.coverage`."""
    stages: dict[str, str] = {}
    # BREAKING REST API CHANGE (plan item 7 — shipped last, deliberately separate from every
    # other change in this file): error_message used to be a single `str | None`, last-row-wins
    # across stages — a THREATS error and a SCENARIOS error at the same time silently dropped
    # one. Now a dict[str, str] keyed by stage ("threats"/"scenarios"), so each stage keeps its
    # own message. This reshapes SessionProgress on BOTH the polling `GET
    # /v1/sessions/{session_id}` response (this function's direct caller) and every SSE
    # `reconcile` event (also built from this function) — any existing typed consumer reading
    # `error_message` as `Optional[str]` hard-fails to parse the response the moment this ships.
    # See docs/SSE_SESSION_PROGRESS_CONTRACT_GUIDE.md.
    error_messages: dict[str, str] = {}
    rows = dal.stage_rows(sess, scenario_session["SessionID"])   # read once; timings ride it too
    for row in rows:
        level = str(row["Level"]).lower()
        stages[level] = str(row["Status"])
        if row["ErrorMessage"]:
            # Client-safe failure reason, deliberately kept on an AWAITING_DECISION row the
            # salvage path revived (dal.revive_errored_scenarios_to_review): it is the marker
            # that this review set may be PARTIAL, so a reviewer can tell it from a complete one.
            error_messages[level] = str(row["ErrorMessage"])
    t = stages.get("threats", StageStatus.IDLE)
    sc = stages.get("scenarios", StageStatus.IDLE)
    # Read from the scenario rows, not the stage: the stage parks at the barrier permanently, so
    # it cannot distinguish "nobody reviewed" from "all reviewed". Computed from the RAW status
    # too — _wire_stage_status maps AWAITING_DECISION to COMPLETE for publication only.
    undecided = (sc == StageStatus.AWAITING_DECISION
                 and dal.has_undecided_scenarios(sess, scenario_session["SessionID"]))
    overall = str(get_overall_status(t, sc, scenario_session["SessionStatus"], undecided=undecided))
    # Read once, used by both "what did my click do?" summaries below.
    _unit_locked = dal.subsystem_lock_is_held(sess, scenario_session["SessionID"], ASSET_UNIT_ID)
    return {
        "session_id": scenario_session["SessionID"], "entity_id": scenario_session["EntityID"],
        "asset_id": int(scenario_session["AssetID"]), "asset_name": scenario_session["AssetName"],
        "user_id": scenario_session["UserID"],
        "session_status": scenario_session["SessionStatus"],
        "current_stage": scenario_session["CurrentStage"],
        "stage_status": _wire_stage_status(scenario_session["StageStatus"]),
        "progress": {
            "threats": _wire_stage_status(t), "scenarios": _wire_stage_status(sc),
            "overall": overall,
            # Control mapping is the tail of scenario generation and the longest step in the
            # pipeline, so scenarios go visible well before their controls do. This is the
            # session-level roll-up a UI waits on before rendering the finished card.
            "controls": dal.control_mapping_progress(sess, scenario_session["SessionID"]),
            "error_message": error_messages,
            # ADDITIVE, like coverage below - an old client that ignores it behaves as before.
            # Seconds per step. `controls` is the ONE entry that is not a wall-clock span: control
            # mapping resumes across sweep ticks 300s apart, so it reports the seconds actually
            # SPENT mapping (dal.accumulate_control_map_seconds). See the field description.
            # Deliberately NO scenario total: generation runs several at a time, so per-scenario
            # durations overlap and summing them would contradict `scenarios` here.
            "timings": _stage_timings(scenario_session["SessionID"], rows,
                                      scenario_session.get("ControlMapSeconds")),
            # The DURABLE answer to "what did my last 'generate next set' click do?". The SSE
            # next_set_result event says the same thing, but publishing is best-effort with no
            # replay (app/sse/bus.py), so a polling client — or one whose stream dropped — has
            # only this. Because build_board also feeds the SSE reconnect-reconcile snapshot, a
            # client that missed the event learns the outcome the moment it reconnects.
            # Both summaries are WITHHELD while the subsystem lock is held. cascade.py commits
            # the regeneration_completed / next_set_outcome audit rows INSIDE
            # `with _subsystem_lock(...)`, so without this the epoch a client is explicitly told
            # to poll for ("confirm your click landed by polling until last_regen.epoch equals
            # the epoch you got back") became visible while the lock was still held -- and the
            # client's very next accept or next-set got `409 subsystem N is locked`. Observed
            # live, first try, on both routes. The published signal must mean "done AND you may
            # act", so it is not published until acting would actually succeed.
            # Trade-off, deliberately taken: while a NEW regen runs, the PREVIOUS one's summary
            # reads null rather than stale-but-complete. A client polling for its own epoch is
            # unaffected (it is waiting for a match either way), and a null that becomes correct
            # beats a value that invites a 409.
            "last_next_set": None if _unit_locked else dal.latest_next_set_outcome(
                sess, scenario_session["SessionID"], ASSET_UNIT_ID),
            # Plan item 3: same durable-mirror rationale as last_next_set above, for
            # /regenerate/scenarios instead of /scenarios/next-set — built from the
            # regeneration_completed audit row (app/pipeline/cascade.py::_stage_regen_audit).
            "last_regen": None if _unit_locked else dal.latest_regen_outcome(
                sess, scenario_session["SessionID"], ASSET_UNIT_ID),
            # ADDITIVE: a new key, unlike the error_message reshape above — an old client that
            # ignores it behaves exactly as before. It must not be ignored by a client that
            # SIGNS OFF assessments, though: coverage.complete=false means threats were not
            # identified for every (supporting system x STRIDE) pair.
            "coverage": _coverage_verdict(sess, scenario_session["SessionID"]),
        },
    }


def get_authorized_session(sess: Session, session_id: str, principal: Principal) -> dict:
    """Load-then-authorize helper shared by every route below: 404s before it 403s, so
    a caller outside the entity scope can't distinguish "doesn't exist" from "not yours"
    (object-level authz).

    Board load, not the full row: no route here reads the three nvarchar(max) JSON blobs."""
    row = dal.load_session_board(sess, session_id)
    if row is None:
        raise dal.NotFoundError(f"session {session_id} not found")
    if str(row["EntityID"]) not in principal.entities:  # object-level authz / IDOR guard
        raise EntityForbidden(f"session {session_id} not in caller's entity scope")
    # DELIBERATE: entity scope is the whole authorization boundary. Any authenticated colleague
    # in the entity may open, stream, export, regenerate and decide this assessment. An ownership
    # check was built here and removed on purpose — covering for a teammate on leave is normal,
    # and a second person approving a remediation plan is a requirement.
    #
    # Accountability is NOT weakened by that: dal.decide_scenarios writes one Scenario_Audit row
    # per decided scenario naming the acting user, so "who accepted this, and when" is answerable
    # whoever clicks. A DETECTIVE control, not a preventive one — a wrong decision is attributable
    # after the fact rather than blocked. Do not "fix" this back to an owner check without that
    # call being made again; tests/test_open_access.py pins the decision.
    return dict(row)


def _build_session_row(sid: str, tenant: str, body: CreateSessionBody, ctx: dict,
                    idempotency_key: str | None, user_id: str | None,
                    tuning_snapshot: dict) -> dict:
    """Assembles the new Scenario_Session row.

    `user_id` must be the AUTHENTICATED principal, never body input: this column feeds the
    audit trail, and a caller-supplied name makes it trustworthy on no row.

    `tuning_snapshot` freezes the session's business calibration (core.tuning) — resolved
    once HERE so every worker stage reads one rulebook, and a Config_Tuning edit only ever
    affects sessions created after it."""
    return {
        "SessionID": sid, "TenantID": tenant, "EntityID": str(body.entity_id),
        "UserID": str(user_id) if user_id is not None else None,
        "AssetName": ctx["asset"]["name"], "AssetID": str(body.asset_id),
        "SessionStatus": SessionStatus.active, "CurrentStage": WorkflowStage.THREAT_IDENTIFICATION,
        "StageStatus": StageStatus.IDLE, "Mode": SessionMode.AUTO, "CurrentSubsystemIndex": 0,
        "SubsystemsJSON": ctx["subsystems_json"], "SectorIDsJSON": json.dumps(ctx["sector_ids"]),
        "AssetContextJSON": ctx["asset_context_json"],
        "ScoringRulesSnapshotJSON": json.dumps(tuning_snapshot),
        "CreatedAt": now(), "UpdatedAt": now(),
        "IdempotencyKey": idempotency_key,
    }


# --- endpoints ---
@router.post("/sessions", status_code=202, response_model=CreateSessionResponse,
            responses=UNAVAILABLE_RESPONSES,
            summary="Start a threat-generation run",
            description=(
                "Starts a new AI run for one asset and returns immediately with a `session_id`.\n\n"
                "**Before you call:** the asset must have no other active session — one run per asset at a "
                "time. `entity_id` in the body must match your `X-Entity-Id` header.\n\n"
                "**What you get:** `202` with a `session_id`. This means queued, NOT finished — generation "
                "takes several minutes. Poll `GET /v1/sessions/{session_id}` until `progress.overall` reads "
                "`awaiting_review`, or stream `GET /v1/sessions/{session_id}/events`.\n\n"
                "**Watch out:** send an `Idempotency-Key` header if your caller might retry. Re-sending the "
                "same key returns `200` with the original session instead of creating a second one. Only "
                "`asset_id` is compared, so a retry with the same asset but different options returns the "
                "ORIGINAL session and silently ignores your new values. Re-using that key with a DIFFERENT "
                "`asset_id` is `409 idempotency_key_conflict`, and starting a second session while one is "
                "still active for the asset is `409 active_session_exists`."
            ))
def create_session(
    body: CreateSessionBody, principal: Principal = Depends(get_principal),
    # max_length matches IdempotencyKey nvarchar(200): unbounded, an over-long key is caught only
    # by MSSQL truncation, which raises DataError — NOT the IntegrityError dal.create_session
    # catches — so it escapes as a 500. Bound at the boundary → clean 422.
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", max_length=200),
) -> CreateSessionResponse | JSONResponse:
    """Creates the session row plus initial stage state and kicks off the pipeline
    task; an `Idempotency-Key` short-circuits to the existing session on retry instead
    of creating a duplicate (200 + `JSONResponse`, not the 202 the decorator declares)."""
    principal.require_entity(body.entity_id)
    # Tenant comes from the caller's X-Tenant-Id — get_principal now requires it, so a real
    # request always has one; only a Principal built by hand (tests) can arrive without one.
    tenant = principal.tenant_id or get_settings().tenant_id
    sid = dal.guid()
    with db_session() as sess:
        dal.assert_asset_owned_by_entity(sess, body.asset_id, body.entity_id)
        if idempotency_key:
            existing_id, conflict, existing_user_id = dal.reserve_idempotency_key_or_get_existing(
                sess, str(body.entity_id), idempotency_key, str(body.asset_id))
            if existing_id:  # `conflict` is only ever True alongside a found row
                if conflict:
                    raise IdempotencyKeyConflict(existing_id)
                return JSONResponse(status_code=200, content=CreateSessionResponse(
                    session_id=existing_id, user_id=existing_user_id).model_dump())

        dal.assert_capacity_available(sess, entity_id=body.entity_id)  # 503 before the more expensive gather_asset_details

        ctx = gather_asset_details(sess, asset_id=body.asset_id, entity_id=body.entity_id,
                            sector_id=body.sector_id, user_id=principal.user_id,
                            supporting_system_ids=body.supporting_system_id,
                            subsector_id=body.subsector_id)
        try:
            # Freeze the tuning rulebook NOW: a Config_Tuning row that breaks the scoring
            # invariants fails session creation with the curated message — it must surface to
            # whoever edited the row, never mint a session under broken arithmetic.
            tuning_snapshot = tuning.resolve_snapshot(dal.active_tuning_overrides(sess))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        dal.create_session(sess, _build_session_row(sid, tenant, body, ctx, idempotency_key,
                                                    principal.user_id, tuning_snapshot))
        set_up_progress_tracking(sess, sid, tenant, str(body.entity_id))
        dal.append_audit(sess, AuditID=dal.guid(), SessionID=sid, TenantID=tenant, EntityID=str(body.entity_id),
                        EventType=AuditEventType.session_started, ActorUserID=principal.user_id)
    try:
        enqueue_pipeline(sid, str(body.entity_id), principal.user_id)
    except Exception as exc:
        # Pattern A (see app/api/treatment.py's request_treatment_plan): the row is already
        # committed and holding the one-active-session-per-asset slot, so a bare re-raise would
        # leave it stuck there — unreachable by the client (no session_id in a raw 500) — until
        # the reaper's stale-grace window elapses. Cancel it now instead; releases the slot
        # immediately and gives the client a clear signal to retry.
        with db_session() as sess:
            # NO user_id: this is a recovery cancel after the broker refused the job, not a human
            # decision. CancelledBy stays NULL, which reads as "cancelled by the system" — naming
            # the requesting principal here would attribute a choice nobody made.
            dal.cancel_session(sess, sid)
        log.error("session.enqueue_failed", session_id=sid, error=repr(exc))
        raise HTTPException(
            status_code=503,
            detail=f"session {sid} could not be queued for processing and was cancelled — retry",
        ) from exc
    return CreateSessionResponse(session_id=sid, user_id=principal.user_id)


@router.get("/sessions/{session_id}", response_model=SessionBoard,
            summary="Check a session's progress",
            description=(
                "The status board for one session: what stage it is at and whether a human is still needed.\n\n"
                "**Call it:** repeatedly after creating a session, every 5-10 seconds.\n\n"
                "**The field that matters is `progress.overall`.** It is the only one that tracks the human "
                "side: `pending` (queued), `in_progress` (AI working), `awaiting_review` (AI done, someone "
                "must accept or reject), `complete` (every scenario decided), `error`, `cancelled`.\n\n"
                "**Watch out:** `session_status` reads `completed` as soon as the AI stops writing, long "
                "before anyone has reviewed anything, and `current_stage` then stays `REVIEW` forever. "
                "Neither means the session is finished. Use `progress.overall`.\n\n"
                "`progress.controls` is separate and finishes last, so scenarios appear before their mapped "
                "controls do. Wait for it to read `COMPLETE` before treating a scenario's control list as "
                "final. `ERROR` there is terminal, not a stage to wait through — mapping gave up after its "
                "attempt limit and nothing retries it automatically."
            ))
def get_session(session_id: str, principal: Principal = Depends(get_principal)) -> SessionBoard:
    """Status-board poll endpoint — same rollup logic the SSE reconnect uses,
    so polling and streaming clients never disagree on subsystem state."""
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)
        return SessionBoard.model_validate(build_board(sess, scenario_session))


def _scenario_select():
    """Scenario columns LEFT-joined via Scoped_Threat -> Identified_Threat (the chain
    dal.accepted_scenarios uses) so every row carries the threat_id it was generated from — plus
    the threat's own category/type/name/actors, so _scenario_narrative can merge them into
    the returned scenario body without a second query. ControlsMappedAt is NULL until Step-4 has
    been ATTEMPTED, which is what separates "still generating" from "nothing in the library
    matched".

    The ORDER BY lives HERE, not on the callers: all three scenario reads (/results,
    /accepted-scenarios, and the single-scenario fetch) build on this select, and without it SQL
    Server is free to return rows in any order it likes — which it does, varying with plan and
    cache state. /results is POLLED while generation runs, so an undefined order means a reviewer
    watches rows reshuffle between refreshes. Ordering
    once at the shared source fixes every reader and every reader added later; ordering per-caller
    is three chances to forget."""
    out, st, it = m.Threat_Scenario, m.Scoped_Threat, m.Identified_Threat
    return select(
        out.ScenarioID, out.ScenarioJSON, out.Accepted, out.ValidationJSON, out.GenerationEpoch,
        out.ScenarioNumber, out.ReplacesScenarioID, out.ControlsMappedAt, out.ControlMapAttempts,
        out.ScenarioSource,
        # Per-scenario generation span. gen_seconds is derived from these on the way out
        # (dal.span_seconds) rather than stored, so there is only ever one version of the fact.
        out.GenStartedAt, out.GenFinishedAt,
        # WHO decided, and when — rides this SELECT, so /results gains it at no extra round trip.
        out.AcceptedAt, out.AcceptedBy, out.RejectedAt, out.RejectedBy,
        # ONE shared threat-column list (dal.scenario_threat_columns) for all three scenario
        # reads — hand-maintained per-select subsets are what made /accepted-scenarios answer
        # ThemeID: null while /results carried it. st.Score/st.ScopeRank are THIS scenario's
        # own scoped row — the same join chain already in use.
        *dal.scenario_threat_columns(),
        st.Score, st.ScopeRank,
    ).select_from(out.__table__.outerjoin(st, out.ScopedThreatID == st.ScopedThreatID)
                .outerjoin(it, st.ThreatID == it.ThreatID)
    # ThreatID first so a threat's coexisting scenarios stay together, then the human-facing
    # ScenarioNumber, then scenario_id as the tie-break that makes the order TOTAL — ScenarioNumber
    # repeats across regenerated versions, so it cannot break ties on its own.
    ).order_by(it.ThreatID, out.ScenarioNumber, out.ScenarioID)


def _ancestry(sess: Session, sid: str, scenarios: list[dict]) -> dict[str, list[str]]:
    """scenario_id -> the ids it replaced, newest first. Walks ReplacesScenarioID in batched
    clustered-PK seeks: one query per chain DEPTH, and none at all when nothing was regenerated.
    Never `WHERE Superseded = 1` — no index serves that (both are filtered Superseded = 0), so it
    would degrade to a full scan on an endpoint clients poll.

    Called ONLY for ?include_replaced=true. The chains exist to fetch and order the retired
    bodies; nothing on the default read path consumes one, so a poll pays nothing for this.

    `SessionID == sid` is a TENANT BOUNDARY, not an optimisation. The caller was authorized for
    ONE session; ReplacesScenarioID is unvalidated data in a multi-tenant table with no foreign keys
    (the cycle guard below exists for the same reason), so an unscoped walk would hand another
    entity's scenario to this caller. Scoping here is sufficient for everything downstream,
    because the returned chains are the sole source of the ids /results goes on to fetch."""
    out = m.Threat_Scenario
    predecessor: dict[str, str | None] = {}
    frontier = {str(s["ReplacesScenarioID"]) for s in scenarios if s["ReplacesScenarioID"]}
    hops = 0
    while frontier and hops < _MAX_ANCESTRY_HOPS:
        hops += 1
        rows = sess.execute(
            select(out.ScenarioID, out.ReplacesScenarioID)
            .where(out.ScenarioID.in_(frontier), out.SessionID == sid)
        ).all()
        predecessor.update({str(oid): (str(prev) if prev else None) for oid, prev in rows})
        frontier = {str(prev) for _oid, prev in rows if prev and str(prev) not in predecessor}
    if frontier:
        # Truncated, not wrong: the chains built below simply stop here. Logged rather than
        # silently capped so a session that genuinely regenerates this deep is visible.
        log.warning("results.ancestry_truncated", session_id=sid, hops=hops,
                    unresolved=len(frontier))

    def _from(first, owner) -> list[str]:
        # Emits ONLY ids the scoped walk confirmed: `predecessor`'s keys mean "a row with this id
        # exists in THIS session", so hop 1 — which comes off the scenario row, not the walk — is
        # checked here too, keeping a cross-session or dangling pointer out of the result.
        # `not in seen` is the cycle guard: no FKs, so a loop must not hang the request thread.
        # `seen` starts holding the OWNER because a scenario cannot be its own ancestor: a self-
        # or ring-pointer would otherwise put the card in its own history, and since these ids
        # are now serialized as nested bodies that means a full duplicate of the card inside
        # itself. Dropping the id is the honest read of incoherent data.
        ids: list[str] = []
        cur, seen = first, {str(owner)}
        while cur and str(cur) in predecessor and str(cur) not in seen:
            seen.add(str(cur))
            ids.append(str(cur))
            cur = predecessor[str(cur)]
        return ids

    return {s["ScenarioID"]: _from(s["ReplacesScenarioID"], s["ScenarioID"]) for s in scenarios}


@router.get("/sessions/{session_id}/results", response_model=SessionResults,
            summary="Read the generated scenarios",
            description=(
                "Every scenario generated for this session, each with its threat, its adversaries and its "
                "mapped security controls.\n\n"
                "**Before you call:** wait until `progress.overall` reads `awaiting_review`. Calling earlier "
                "returns a short but perfectly valid-looking list, which is how a half-finished run gets "
                "mistaken for a finished one.\n\n"
                "**What you get:** the active scenarios, PLUS any scenario a human already DECIDED — accepted "
                "or rejected — even if a later regeneration replaced it. A decision is never hidden by a "
                "regeneration that came after it, so the list can legitimately contain superseded rows and "
                "can be longer than the number of current scenarios. Tell them apart by `accepted` and "
                "`rejected_at`. Match scenarios by `scenario_id`, never by position.\n\n"
                "**Watch out:** a scenario with `scenario: null` is a failure card — generation failed for "
                "that one threat. It cannot be accepted; regenerate it instead. Add `?include_replaced=true` "
                "to see the older versions a regeneration replaced, nested inside the scenario that replaced "
                "them."
            ))
def get_results(
    session_id: str,
    include_replaced: bool = Query(
        default=False,
        description=(
            "Also return the older scenario versions that regeneration replaced, nested inside "
            "the scenario that replaced them as its `replaced_scenarios` — newest first, and "
            "flat, so the whole history of a card is one array with no recursion. Each entry "
            "carries its full scenario text and the controls it had mapped, so a reviewer can "
            "compare a scenario against the version it superseded. Default false, in which case "
            "every card's `replaced_scenarios` is empty."
        ),
    ),
    principal: Principal = Depends(get_principal),
) -> SessionResults:
    """Returns the session's current (non-superseded) threats and scenarios.

    `include_replaced=true` nests the versions regeneration replaced inside the card that
    replaced them — full text plus the controls each had mapped."""
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)
        sid = scenario_session["SessionID"]
        entity_id = scenario_session["EntityID"]
        def get_current_rows(table, cols, *extra):
            """Columns for this session, excluding rows a prior regeneration superseded.
            `extra` predicates narrow further."""
            return [dict(r) for r in sess.execute(
                select(*cols).where(table.SessionID == sid, dal.active(table.Superseded), *extra)
            ).mappings()]

        out = m.Threat_Scenario
        # No separate threats query. Every threat it could return was, by its own EXISTS
        # predicate, one already backing an active scenario row — so each card now carries its
        # own threat (ScenarioResult.threat, read from the SAME row via _scenario_select's
        # join). That removes the two-lists-must-agree invariant entirely, along with the
        # missing_tids backfill query that existed only to repair it.
        # Current rows PLUS the accepted one: the accepted version may be superseded
        # (Accepted is decoupled from generation recency), and the default view must never
        # hide the very row the reviewer accepted. TWO statements, not one OR: this table's
        # only SessionID-leading indexes are all filtered (Superseded=0 / Accepted=1), an OR
        # implies neither filter, and _ancestry's docstring already outlaws the resulting
        # full-scan on a polled endpoint. Each half seeks its own filtered index; the second
        # is a near-free zero-row seek until an accept happens.
        scenarios = [dict(r) for r in sess.execute(
            _scenario_select().where(out.SessionID == sid, dal.active(out.Superseded))
        ).mappings()]
        seen_scenario_ids = {s["ScenarioID"] for s in scenarios}
        # THREE statements, one per filtered index — same reasoning as the two above, extended to
        # the reject side. A DECIDED row (accepted or rejected) is a human fact on the record, and
        # a later regeneration must not erase it from the default view. Rejections were the
        # asymmetry: an accepted row survived being superseded, a declined one silently vanished,
        # so a reviewer could not see what had already been turned down. Each seek is near-free
        # until a decision actually happens.
        for decided in (dal.accepted(out.Accepted), dal.rejected(out.RejectedAt)):
            scenarios += [dict(r) for r in sess.execute(
                _scenario_select().where(out.SessionID == sid, decided)
            ).mappings() if r["ScenarioID"] not in seen_scenario_ids]
            seen_scenario_ids = {s["ScenarioID"] for s in scenarios}
        # Only needed to fetch and order the retired bodies, so a polled /results issues no
        # ancestry query at all — however deep the session's regeneration history runs.
        chains = _ancestry(sess, sid, scenarios) if include_replaced else {}
        replaced: list[dict] = []
        if include_replaced:
            wanted = {oid for chain in chains.values() for oid in chain}
            if wanted:
                # Every id here came out of _ancestry's session-scoped walk, so the second
                # predicate is belt-and-braces on a tenant boundary rather than the load-bearing one.
                replaced = [dict(r) for r in sess.execute(
                    _scenario_select().where(out.ScenarioID.in_(wanted), out.SessionID == sid)
                ).mappings()]
        controls = _controls_by_output(sess, [s["ScenarioID"] for s in scenarios]
                                            + [r["ScenarioID"] for r in replaced])
        # One batched lookup for every actor name this response mentions — threats[] and every
        # scenario's nested threat block share it, so the same name can never resolve to two
        # different ids within one response.
        actor_ids = _actor_ids_from_blobs(
            sess, [r.get("ThreatActorsJSON") for rows_ in (scenarios, replaced) for r in rows_])
        by_id = {r["ScenarioID"]: r for r in replaced}

        def _nested(chain: list[str]) -> list[ScenarioResult]:
            """The card's own history, oldest-to-newest order preserved from the chain. Built
            without a `replaced` argument, which is what keeps nesting exactly one level deep.
            A chain id with no row (hard-deleted, or past _MAX_ANCESTRY_HOPS) is skipped rather
            than emitted as an entry with no body — the history truncates, it never lies."""
            return [_scenario_result(by_id[oid], controls.by_output.get(oid),
                                    actor_ids=actor_ids,
                                    unavailable=controls.unavailable)
                    for oid in chain if oid in by_id]

        return SessionResults(
            session_id=sid, entity_id=entity_id,
            asset_id=int(scenario_session["AssetID"]), asset_name=scenario_session["AssetName"],
            user_id=scenario_session["UserID"],
            # Readiness rides along so this endpoint stops looking finished when it isn't: the
            # scenario list is a live snapshot, and reading it mid-run returns a short-but-valid
            # list indistinguishable from a completed one. Reuses build_board rather than
            # re-deriving, so /results and the board can never disagree.
            progress=build_board(sess, scenario_session)["progress"],
            scenarios=[_scenario_result(s, controls.by_output.get(s["ScenarioID"]),
                                        _nested(chains.get(s["ScenarioID"]) or []),
                                        actor_ids=actor_ids,
                                        unavailable=controls.unavailable)
                    for s in scenarios],
        )


def _moderation_summary(validation_json: str | None) -> tuple[bool, bool | None, list[str]]:
    """Moderation flag out of a scenario's ValidationJSON, for a reviewer to see.

    `checked=False` means moderation never ran (off, or the service was unavailable) —
    deliberately distinct from checked-and-clean, which a single falsy `flagged` could not
    express. Parses defensively: a malformed blob must not 500 an unrelated field."""
    if not validation_json:
        return False, None, []
    try:
        report = json.loads(validation_json)
    except (json.JSONDecodeError, TypeError):
        return False, None, []
    moderation = report.get("moderation") if isinstance(report, dict) else None
    if not isinstance(moderation, dict) or not moderation.get("checked"):
        return False, None, []
    return True, bool(moderation.get("flagged")), list(moderation.get("categories") or [])


def _validation_summary(validation_json: str | None) -> tuple[str | None, list[str]]:
    """validate_scenario's structural/consistency report, for a reviewer to see. Same defensive
    parsing as _moderation_summary. A `None` status means missing/malformed — checked-and-clean
    is the string "ok"."""
    if not validation_json:
        return None, []
    try:
        report = json.loads(validation_json)
    except (json.JSONDecodeError, TypeError):
        return None, []
    if not isinstance(report, dict):
        return None, []
    status = report.get("validation_status")
    return (status if isinstance(status, str) else None), list(report.get("errors") or [])


class _Controls(NamedTuple):
    """A page's mapped controls, WITH whether the read actually happened.

    `by_output` empty + `unavailable` False = mapping ran and matched nothing, which schemas.py
    documents in three places as a genuine library-gap signal worth acting on. `unavailable` True
    = we never got to look. Those are different facts, and a bare `{}` could not tell them apart:
    one transient read error published EVERY scenario on the page as a library gap, next to
    `ControlsMapped: true`, which is read straight off the row and is perfectly correct. A
    reviewer had no way to distinguish a curated fact about the control library from a database
    blip — the same overloaded-empty defect grounding.ControlMatches.answered exists to kill on
    the write side, here on the read side.
    """
    by_output: dict[str, list[MappedControl]]
    unavailable: bool


def _controls_by_output(sess: Session, scenario_ids: list[str]) -> _Controls:
    """Step-4 mapped controls for a page of scenarios, grouped per scenario_id, best rank first.
    The Control_Library join filters to active rows — a control deactivated AFTER mapping must
    not keep surfacing. Standards ride along as names (Map → Control_Standard, active only)."""
    if not scenario_ids:
        return _Controls({}, False)
    cmap, lib = m.Threat_Scenario_Control_Map, m.Control_Library
    try:
        return _Controls(_query_controls(sess, scenario_ids, cmap, lib), False)
    except Exception:
        # STILL degrades rather than 500s: _actor_ids_by_name names that a shared contract, and a
        # secondary read must never take down the core results view. What changed is that it now
        # degrades HONESTLY — the fact rides out to the client instead of being swallowed into a
        # `{}` that reads as "your library has nothing for these threats".
        sess.rollback()  # leave the session clean for the caller's remaining work/commit
        log.warning("controls.read_failed", exc_info=True)
        return _Controls({}, True)


def _query_controls(sess: Session, scenario_ids: list[str], cmap, lib) -> dict[str, list[MappedControl]]:
    rows = sess.execute(
        select(cmap.ScenarioID, cmap.MapRank, cmap.Score,
            lib.ControlLibraryID, lib.ControlCode, lib.Domain, lib.ControlName)
        .join(lib, lib.ControlLibraryID == cmap.ControlLibraryID)
        .where(cmap.ScenarioID.in_(scenario_ids),
            lib.IsActive == True, lib.IsDeleted == False)
        .order_by(cmap.ScenarioID, cmap.MapRank)
    ).mappings().all()
    std_refs: dict[int, list[StandardRef]] = {}
    if rows:
        smap, std = m.Control_Library_Standard_Map, m.Control_Standard
        for cid, standard_id, name in sess.execute(
            select(smap.ControlLibraryID, std.StandardID, std.StandardName)
            .join(std, std.StandardID == smap.StandardID)
            .where(smap.ControlLibraryID.in_({r["ControlLibraryID"] for r in rows}),
                std.IsActive == True, std.IsDeleted == False)
            .order_by(std.StandardName)
        ):
            std_refs.setdefault(cid, []).append(
                StandardRef(standard_id=standard_id, standard_name=name))
    out: dict[str, list[MappedControl]] = {}
    for r in rows:
        out.setdefault(r["ScenarioID"], []).append(MappedControl(
            control_id=r["ControlLibraryID"], control_code=r["ControlCode"],
            domain=r["Domain"], control_name=r["ControlName"], map_rank=r["MapRank"],
            score=r["Score"],
            standards=std_refs.get(r["ControlLibraryID"], [])))
    return out


def _actor_ids_by_name(sess: Session, names: set[str]) -> dict[str, int]:
    """Threat_Actor primary keys for a page's actor names, one batched query. Actor names are
    written from the library itself (the model never invents one), so an exact-name match is the
    correct join; a name that no longer resolves stays absent and renders as ThreatActorID=null
    — visible, never silent. Same degrade-loudly contract as _controls_by_output: a failed read
    must never 500 the core results view."""
    if not names:
        return {}
    ta = m.Threat_Actor
    try:
        return {name: int(actor_id) for actor_id, name in sess.execute(
            select(ta.ThreatActorID, ta.ThreatActorName)
            .where(ta.ThreatActorName.in_(names),
                ta.IsActive == True, ta.IsDeleted == False))}
    except Exception:
        sess.rollback()  # leave the session clean for the caller's remaining work
        log.warning("actors.read_failed", exc_info=True)
        return {}


def _actor_ids_from_blobs(sess: Session, blobs: Iterable[str | None]) -> dict[str, int]:
    """{name: Threat_Actor key} for a page, preferring the ids STORED at identification time.

    _actor_ids_by_name resolves by name at read time, so it returns null the moment an actor is
    renamed, re-spelled or soft-deleted — the id silently disappears from the response even
    though the threat still names a real adversary. Stage 1 now persists `actor_ids` alongside
    the names, so the key is already in hand and no query is needed at all.

    The name lookup remains ONLY for rows written before actor_ids existed (and for a blob whose
    two lists disagree in length, which stored_actor_ids refuses to trust). One batched query
    covers whatever the stored ids did not.
    """
    resolved: dict[str, int] = {}
    unresolved: set[str] = set()
    for blob in blobs:
        names = stored_actors(blob)
        ids = grounding.stored_actor_ids(blob)
        if ids:
            resolved.update(zip(names, ids))
        else:
            unresolved.update(names)
    unresolved -= resolved.keys()
    if unresolved:
        resolved.update(_actor_ids_by_name(sess, unresolved))
    return resolved


def _actor_block(threat_row: dict | None,
                 actor_ids: dict[str, int] | None = None) -> list[dict]:
    """The scenario's adversaries, shaped as list[ThreatActorRef].

    A SIBLING of the threat block, not a field inside it — see ScenarioResult.actors. Built
    straight off the row rather than inside _threat_block so it survives the case _threat_block
    cannot: an OUTER-join miss returns threat=null, and actors stored on the row would otherwise
    vanish with it.

    `actor_ids` maps name -> Threat_Actor key, resolved in ONE batch by _actor_ids_from_blobs;
    a name with no id still appears, with actor_id null, because dropping it would silently
    shorten the adversary list."""
    actor_names = stored_actors((threat_row or {}).get("ThreatActorsJSON"))
    return [{"actor_id": (actor_ids or {}).get(n), "actor_name": n} for n in actor_names]


def _threat_block(threat_row: dict | None) -> dict | None:
    """The FULL threat a card was generated from, every database key included, shaped as
    ThreatResult.

    Built for the ENVELOPE (ScenarioResult.threat), never merged into the scenario narrative:
    a failed generation returns scenario=null, and a reviewer must still be able to see WHICH
    threat failed. Putting it inside the narrative made that information vanish exactly when it
    mattered most, and forced a parallel top-level threats[] list to compensate.

    Carries NO actors and NO controls — both are envelope siblings (_actor_block, and the
    controls list threaded through from _controls_by_output). Controls are keyed by ScenarioID,
    so they belong to the scenario, not the threat: one threat can father several scenarios that
    each map different controls, and nesting them here invited a de-duplication that would
    cross-wire them.

    None when the OUTER join found no Identified_Threat row — ThreatResult's required fields
    (ThreatType, GroundingStatus) only exist when the row does."""
    if not threat_row or not threat_row.get("ThreatID"):
        return None
    return {
        "threat_id": threat_row.get("ThreatID"),
        "threat_category": threat_row.get("ThreatCategory"),
        # The resolved key, not just the category TEXT — so a client can join on it.
        "threat_category_id": threat_row.get("ThreatCategoryID"),
        "threat_type": threat_row.get("ThreatType"),
        "threat_name": threat_row.get("ThreatName"),
        "threat_type_id": threat_row.get("ThreatTypeID"),
        "library_threat_type": threat_row.get("LibraryThreatType"),
        "library_threat_name": threat_row.get("LibraryThreatName"),
        "grounding_status": threat_row.get("GroundingStatus"),
        "threat_catalogue_id": threat_row.get("ThreatCatalogueID"),
        # Independent facts: a threat's TYPE and its specific catalogue entry are matched
        # against the library separately (tasks.py sets ThreatTypeID/ThreatCatalogueID from
        # two different grounding results) — a threat can invent a new catalogue entry under
        # an existing, already-curated type. Read from IsThreatTypeAIGenerated/IsThreatAIGenerated
        # — dedicated immutable columns, NOT derived from ThreatTypeID/ThreatCatalogueID, because
        # promote.py mutates both of those when it mints a new library row. bool() so SQLite's
        # 0/1 and MSSQL's bit serialize identically; None stays None (rows written before the
        # column existed).
        "is_threat_type_ai_generated": (None if threat_row.get("IsThreatTypeAIGenerated") is None
                                    else bool(threat_row.get("IsThreatTypeAIGenerated"))),
        "is_threat_ai_generated": (None if threat_row.get("IsThreatAIGenerated") is None
                                else bool(threat_row.get("IsThreatAIGenerated"))),
        "grounding_score": threat_row.get("GroundingScore"),
        "score": threat_row.get("Score"),
        "scope_rank": threat_row.get("ScopeRank"),
    }


def _scenario_narrative(scenario_json: str | None,
                        threat_row: dict | None = None) -> dict | None:
    """Projects one ScenarioJSON row for the API: the model's own prose, and nothing else.
    Presentation-layer only — ScenarioJSON is never rewritten.

    THE TWO POPS ARE LOAD-BEARING, do not delete them as dead code. ScenarioNarrative is
    `extra="allow"`, so ANY key left in this dict ships to the client whether or not the model
    declares it — removing the field declarations alone would have changed nothing on the wire.
    `controls` and `threat_actors` are envelope siblings now (ScenarioResult.controls/.actors),
    so they must be removed HERE to actually leave the narrative.
    `controls` additionally has to go because LEGACY rows still carry a model-authored
    `{name, why}` list under that key: this pop is what stops pre-redesign suggestion text
    resurfacing as though it were a Step-4 library match. The raw ScenarioJSON blob remains the
    archival copy.

    `threat_row` (a _scenario_select() row) carries the threat's own category/type/name — NOT
    part of the LLM's scenario JSON — merged in here so a caller only has one dict to read.
    None for callers with no threat context (a scenario built for logging/preview, say)."""
    # Silent on a corrupt blob (no warn_event): one bad row degrades to None and drops out of the
    # view rather than 500-ing it and hiding every other scenario in the session.
    scenario = dal.safe_json_dict(scenario_json)
    if scenario is None:
        return None
    if threat_row is not None:
        scenario["threat_category"] = threat_row.get("ThreatCategory")
        # DISPLAY PROSE prefers the curator's wording — via the ONE shared coalesce
        # (naming.display_threat_names), which the treatment presenters use too. The typed
        # siblings report both spellings separately (ThreatType AND LibraryThreatType), so
        # preferring one here hides nothing - and doing it in one place is what stops the
        # endpoints drifting apart again.
        scenario["threat_type"], scenario["threat_name"] = display_threat_names(threat_row)
    scenario.pop("controls", None)
    scenario.pop("threat_actors", None)
    return scenario


def _scenario_result(row: dict, controls: list[MappedControl] | None = None,
                    replaced: list[ScenarioResult] | None = None,
                    actor_ids: dict[str, int] | None = None,
                    *, unavailable: bool = False) -> ScenarioResult:
    controls_mapped = row["ControlsMappedAt"] is not None
    # .get(): not every select feeding this builder carries ControlMapAttempts yet — absent
    # reads as 0 attempts, i.e. never exhausted, same "missing column = safe default" contract
    # accepted_by/accepted_at etc. already use just below.
    controls_mapping_exhausted = (not controls_mapped and row.get("ControlMapAttempts", 0)
                                >= get_settings().control_map_max_attempts)
    checked, flagged, categories = _moderation_summary(row["ValidationJSON"])
    validation_status, validation_errors = _validation_summary(row["ValidationJSON"])
    return ScenarioResult(scenario_id=row["ScenarioID"],
                        scenario=_scenario_narrative(row["ScenarioJSON"], row),
                        # On the ENVELOPE, so a failure card (scenario=null) still says which
                        # threat failed — see _threat_block. actors/controls are siblings of it,
                        # so they survive an OUTER-join miss that nulls the threat.
                        threat=_threat_block(row),
                        actors=_actor_block(row, actor_ids),
                        controls=controls or [],
                        accepted=bool(row["Accepted"]),
                        # .get(): this builder is fed by more than one select, and a row that did
                        # not carry the column must publish null rather than KeyError a whole view.
                        accepted_by=row.get("AcceptedBy"), accepted_at=row.get("AcceptedAt"),
                        rejected_by=row.get("RejectedBy"), rejected_at=row.get("RejectedAt"),
                        moderation_checked=checked, moderation_flagged=flagged, moderation_categories=categories,
                        validation_status=validation_status, validation_errors=validation_errors,
                        generation_epoch=row["GenerationEpoch"],
                        scenario_number=row["ScenarioNumber"],
                        # .get(), same reason as accepted_by above: more than one select feeds
                        # this builder, and a row without the columns publishes null.
                        gen_started_at=row.get("GenStartedAt"),
                        gen_finished_at=row.get("GenFinishedAt"),
                        gen_seconds=dal.span_seconds(row.get("GenStartedAt"), row.get("GenFinishedAt")),
                        # NULL on every row written before the scenario library existed, and
                        # those were all authored for their own asset — so the legacy reading
                        # is "generated", not "unknown".
                        scenario_source=row["ScenarioSource"] or "generated",
                        controls_mapped=controls_mapped,
                        # Without this, ControlsMapped=true beside an empty list is the API's
                        # documented "the library genuinely has nothing" — a claim we cannot make
                        # when the read never returned.
                        controls_unavailable=unavailable,
                        controls_mapping_exhausted=controls_mapping_exhausted,
                        controls_mapping_exhaustion_reason=(
                            ControlMappingExhaustionReason.retry_budget_exhausted
                            if controls_mapping_exhausted else None),
                        replaced_scenarios=replaced or [])


def _subset_from_accept_body(body: AcceptBody) -> list[str] | None:
    """Translate the wire-level mode/scenario_ids pair into accept_session's existing
    `subset` contract: None = accept all, [] = accept none, a populated list = that subset."""
    if body.mode == "all":
        return None
    if body.mode == "none":
        return []
    return body.scenario_ids  # mode == "subset"; validator guarantees a non-empty list


# `responses` is not decoration: these 409 bodies are the ONLY place ReviewGateReason appears, and
# FastAPI emits a schema only for models reachable from a route. Without this declaration the enum
# never reaches /openapi.json, and a UI cannot generate the codes that tell it whether a blocked
# action is a dead end (session_completed/cancelled/generation_abandoned) or a spinner
# (generation_in_progress). That split is only trustworthy because accept.ensure_review_gate now
# PROVES a live lease before emitting generation_in_progress: while the code was inferred from the
# session's cached stage columns alone, a UI showing a spinner on it could spin forever against a
# worker that had already died.
_CONFLICT_RESPONSES: dict[int | str, dict] = {409: {"model": ErrorResponse, "description": "Conflict — see details.reason."}}


@router.post("/sessions/{session_id}/accept", response_model=AcceptResponse, responses=_CONFLICT_RESPONSES,
            summary="Accept scenarios",
            description=(
                "Records a reviewer's decision to keep scenarios. Each accepted scenario is stamped with who "
                "accepted it and when.\n\n"
                "**Before you call:** the session must have reached the review point. In practice that means "
                "`progress.overall` reads `awaiting_review`.\n\n"
                "**Three modes.** `all` accepts every current scenario. `subset` accepts only the ids you "
                "list. `none` accepts nothing.\n\n"
                "**Watch out:** `mode: \"none\"` decides NOTHING. It returns `200` with `accepted_count: 0` and "
                "leaves every scenario pending, so the session stays at `awaiting_review`. It is not a way to "
                "dismiss a session — to discard everything, use the reject endpoint instead.\n\n"
                "Repeatable. Accepting the same ids twice succeeds again and never changes who decided first. "
                "Accepting does not end the session; scenarios you leave undecided stay decidable on a later "
                "visit.\n\n"
                "Accepting a scenario you already declined is refused with `404` and the reason "
                "`already_rejected`. The two decisions are mutually exclusive per scenario."
            ))
def post_accept(session_id: str, body: AcceptBody, principal: Principal = Depends(get_principal)) -> AcceptResponse:
    """Records an accept decision on all or a subset of this session's scenarios. Repeatable:
    the session was already completed when generation finished, so scenarios left undecided stay
    pending and can be accepted on a later visit. Validation and the writes live in
    `accept_session`; this is the authz + HTTP wrapper."""
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)
        matched = accept_session(sess, session_id, scenario_session["EntityID"], principal.user_id,
                                subset=_subset_from_accept_body(body))
    return AcceptResponse(session_id=session_id, user_id=scenario_session["UserID"],
                        status=str(SessionStatus.completed), accepted_count=matched)


@router.post("/sessions/{session_id}/scenarios/{scenario_id}/promote-to-library",
            response_model=LibraryPromotionResponse, responses=_CONFLICT_RESPONSES,
            summary="Add a scenario's threat to the library",
            description=(
                "Copies one accepted scenario's threat type and threat into the shared threat library, so a "
                "future session on a similar asset can match it instead of the AI reinventing it.\n\n"
                "**Before you call:** the scenario must be accepted AND still be the current version. An "
                "accepted scenario that a later regeneration replaced is refused, even though it is still "
                "listed in the results. No request body.\n\n"
                "**What you get:** each item comes back `inserted` (new), `existing` (reused) or `failed`. "
                "Calling twice creates nothing and returns `created_count: 0` with everything `existing`.\n\n"
                "**Watch out:** promoting does not make the threat matchable yet. New library rows are "
                "created inactive, pending curator review, and matching only considers active rows. A curator "
                "has to approve it before any session can retrieve it.\n\n"
                "Controls are reported here but never written — they are already curated library data."
            ))
def post_promote_to_library(session_id: str, scenario_id: str,
                            principal: Principal = Depends(get_principal)) -> LibraryPromotionResponse:
    """Add this ACCEPTED scenario's threat type and threat to the library — Threat_Type for a
    new type, Threat_Catalogue for a new threat (name only - the catalogue's Description
    column was dropped 2026-08-30), a
    Threat_Catalogue_Category_Map row for its resolved category, and ThreatType_ThreatActor_Map
    links for its stored actors (actors attach per TYPE in this model). The ONLY library write
    path; every call is recorded in Scenario_Audit (who, when, per-item outcome).

    Anyone holding session_id + scenario_id may call it, but only accepted scenarios promote — a
    pending, rejected or superseded scenario returns 409 with a `details.reason` naming which.
    Nothing is created that already exists: each item comes back `inserted` (a new row) or
    `existing` (reused), so calling twice creates nothing and returns the same ids.

    "Already in the database" is judged on the NAME via app-owned normalization
    (core.naming.normalize_name, type-scoped), with UX_ThreatCatalogue_NaturalKey as the
    concurrency backstop.

    An EXISTING catalogue threat is returned by id and nothing else is touched — curation
    stays with the curators. Controls themselves are never created or curated by this call: a
    mapped control is already Control_Library master data, and the response merely reports the
    scenario's own mapping.

    Synchronous and direct: no Celery, no curator queue. Declared `def`, not `async def`, on
    purpose — the DB driver is synchronous, so FastAPI runs this in a threadpool; `async def`
    would block the event loop for every other request.
    """
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)
        result = promote_scenario_to_library(sess, scenario_session, scenario_id, principal.user_id)
    return LibraryPromotionResponse(
        session_id=session_id, scenario_id=str(scenario_id), success=result.success,
        created_count=result.created_count,
        threat_type=PromotedRef(**result.threat_type), threat=PromotedRef(**result.threat),
        threat_actors=[PromotedRef(**a) for a in result.threat_actors],
        controls=[MappedControl(**c) for c in result.controls],
        controls_mapped=result.controls_mapped)


@router.post("/sessions/{session_id}/scenarios/reject", response_model=RejectResponse,
            responses=_CONFLICT_RESPONSES,
            summary="Decline scenarios",
            description=(
                "Records a reviewer's decision to decline scenarios. Nothing is deleted — the scenario keeps "
                "its content and stays visible in the results.\n\n"
                "**Why it exists:** a scenario nobody has looked at and one a reviewer declined must not read "
                "the same on a risk register. Accept can only say yes or not-yet; this is how you say no.\n\n"
                "**Before you call:** same review point as accept.\n\n"
                "**Watch out:** accept and reject are mutually exclusive per scenario. Rejecting one you "
                "already accepted fails with `404` and the reason `already_accepted`. There is no un-reject — "
                "to get a fresh scenario in that slot, regenerate it.\n\n"
                "Declining counts as deciding, so rejecting the last undecided scenario moves "
                "`progress.overall` to `complete`. Repeatable, and it never overwrites who declined first."
            ))
def post_reject_scenarios(session_id: str, body: RejectBody,
                        principal: Principal = Depends(get_principal)) -> RejectResponse:
    """Explicitly decline scenarios, recording who declined them and when.

    The counterpart to accept, and the reason a scenario has three states rather than two: a
    pending scenario is one nobody has looked at, a rejected one is a decision somebody made and
    signed. Rejecting does not delete anything — the scenario keeps its content and stays in
    GET /results. Repeatable and order-independent with accept across visits, but the two are
    mutually exclusive per scenario: an already-accepted id comes back 404 'already_accepted'."""
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)
        matched = reject_scenarios(sess, session_id, scenario_session["EntityID"],
                                principal.user_id, body.scenario_ids)
    return RejectResponse(session_id=session_id, user_id=scenario_session["UserID"],
                        rejected_count=matched)


def enqueue_regeneration(session_id: str, subsystem_id: int, granularity: RegenGranularity,
                        target_ids: list[str] | list[int] | None, epoch: int,
                        entity_id: str, user_id: str | None) -> None:
    """Indirection so tests can run the cascade synchronously instead of via a broker."""
    regenerate_task.apply_async(
        args=(session_id, subsystem_id, str(granularity), target_ids, epoch),
        shadow=(f"regenerate: session {session_id} · subsystem {subsystem_id} · "
                f"entity {entity_id} · by {user_id} · {dal.now():%Y-%m-%d %H:%M} UTC"))


def _assert_regen_eligible(sess: Session, scenario_session: dict) -> dict:
    """Regeneration is only allowed while the session is parked at REVIEW waiting on a human decision.

    Returns the session row to use from here on: `ensure_review_gate` may have recovered an
    abandoned run and reloaded it, and the caller must not keep reading the stale snapshot.

    Delegates to the SAME gate the accept route uses, so "is this session decidable?" has exactly
    one answer everywhere — including the liveness check that stops a dead or hung worker being
    reported as "generation still in progress" (see accept.ensure_review_gate). Only the exception
    type differs, because these routes answer `regenerate_conflict`, not `accept_conflict`."""
    try:
        return dict(ensure_review_gate(sess, scenario_session))
    except AcceptConflict as exc:
        raise RegenerateConflict(str(exc), reason=exc.reason) from None


def _recover_from_enqueue_failure(session_id: str, subsystem_id: int, epoch: int,
                                exc: Exception, log_event: str) -> NoReturn:
    """Shared by _do_next_set/_do_regenerate: Pattern A, main-pipeline flavor (see
    create_session's docstring-level comment for the treatment-plan original). SCENARIOS was
    just reset to IDLE and committed by the caller before its broker call failed, so a bare
    re-raise leaves it there — decide_session_outcome returns None for any IDLE row, wedging the
    session out of REVIEW until the reaper's stale-grace window elapses.

    claim_stage (not finish_stage directly) is required because reset_stage_for_regen does NOT
    clear ActiveTaskID, so the row may still carry a prior attempt's stale claim id — a synthetic
    task_id is fine since nothing else is racing for this exact claim right now.

    Always raises HTTPException; never returns normally."""
    with db_session() as sess:
        fail_task_id = dal.guid()
        if dal.claim_stage(sess, session_id, subsystem_id, SubsystemLevel.SCENARIOS, epoch, fail_task_id):
            dal.finish_stage(sess, session_id, subsystem_id, SubsystemLevel.SCENARIOS,
                            StageStatus.ERROR, epoch, fail_task_id,
                            error="failed to queue generation — request it again")
        reloaded = dal.load_session(sess, session_id)
        if reloaded is not None:
            tasks.decide_session_outcome(sess, dict(reloaded))
    log.error(log_event, session_id=session_id, subsystem=subsystem_id, error=repr(exc))
    raise HTTPException(status_code=503,
                        detail="could not queue the request for processing — retry") from exc


def _do_regenerate(session_id: str, principal: Principal, subsystem_id: int, granularity: RegenGranularity,
                target_ids: list[str] | list[int] | None) -> RegenerateResponse:
    """Validates eligibility, guards against a concurrent regen/accept via a lock check plus a
    conditional UPDATE, resets the affected stage rows, hands off to the async regenerate task."""
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)
        scenario_session = _assert_regen_eligible(sess, scenario_session)

        cascade.get_threat_id_to_redo(sess, session_id, subsystem_id, granularity, target_ids)

        # bail out if another regenerate/accept already holds this subsystem's mutex lock
        lock_status = sess.execute(
            select(m.Subsystem_Stage_State.Status).where(
                m.Subsystem_Stage_State.SessionID == session_id,
                m.Subsystem_Stage_State.SubsystemID == subsystem_id,
                m.Subsystem_Stage_State.Level == SubsystemLevel.LOCK,
            )
        ).scalar()
        if lock_status == StageStatus.RUNNING:
            raise RegenerateConflict(f"subsystem {subsystem_id} is locked (regeneration/accept in progress)")
        # No session-row write at all. Regeneration rewrites scenarios that ALREADY exist, so it
        # must not re-reserve the asset (the session is completed, and re-reserving would block a
        # fresh session on the same asset for the duration) and it must not move CurrentStage —
        # the session stays parked at REVIEW/AWAITING_DECISION throughout, because that is still
        # true: a human is still deciding. Regen progress is read from the stage rows, not the
        # session row. The `_LOCK` check above screens the common race; the true arbiter is the
        # worker's dal.acquire_execution_lock, with next_epoch fencing anything stale.
        levels = cascade.LEVELS_BY_GRANULARITY[granularity]
        epoch = dal.next_epoch(sess, session_id, subsystem_id, levels)
        dal.reset_stage_for_regen(sess, session_id, subsystem_id, levels, epoch)

    try:
        enqueue_regeneration(session_id, subsystem_id, granularity, target_ids, epoch,
                            str(scenario_session["EntityID"]), scenario_session["UserID"])
    except Exception as exc:  # noqa: BLE001 — broker unreachable must not wedge SCENARIOS at IDLE
        _recover_from_enqueue_failure(session_id, subsystem_id, epoch, exc, "regen.enqueue_failed")
    # `epoch` goes back to the caller: a 202 only says "accepted", and this is the token that
    # lets a client tell ITS request's completion from a previous one's (see RegenerateResponse).
    return RegenerateResponse(session_id=session_id, user_id=scenario_session["UserID"],
                            status="regenerating", epoch=epoch)


@router.post("/sessions/{session_id}/regenerate/scenarios", status_code=202, response_model=RegenerateResponse,
            responses=_CONFLICT_RESPONSES | UNAVAILABLE_RESPONSES,
            summary="Rewrite specific scenarios",
            description=(
                "Rewrites only the scenarios you name and leaves their siblings untouched.\n\n"
                "**Before you call:** the session must be at the review point, and the ids must be current "
                "scenarios of this session.\n\n"
                "**What you get:** `202` with an `epoch`. Queued, not finished. Confirm your click landed by "
                "polling `GET /v1/sessions/{session_id}` until `progress.last_regen.epoch` equals the epoch "
                "you got back. Do not rely on the live event for this — it carries no epoch.\n\n"
                "**If every target fails, that epoch is never published at all.** Watch `progress.scenarios` "
                "and `progress.error_message` alongside it, or a failed rewrite will leave you polling "
                "forever.\n\n"
                "**Watch out:** the count normally stays the same, because this replaces rather than adds. "
                "The exception is regenerating a scenario you had already accepted: the accepted version "
                "stays in the results beside its replacement, so you will count one more. Tell them apart by "
                "`accepted`.\n\n"
                "There is no free-text steering field. If the AI fails on a rewrite, your original scenario "
                "is kept rather than destroyed."
            ))
def post_regenerate_scenarios(session_id: str, body: RegenerateScenariosBody,
                            principal: Principal = Depends(get_principal)) -> RegenerateResponse:
    """Rebuild one or more scenarios' narratives only — siblings untouched (scenarios 1, 2). Scoped
    to the session's asset (`session_id` in the URL is the sole identifier); `scenario_ids` alone
    picks which scenarios to redo."""
    return _do_regenerate(session_id, principal, ASSET_UNIT_ID, RegenGranularity.scenario,
                        body.scenario_ids)


def enqueue_next_set(session_id: str, subsystem_id: int, epoch: int, threats_epoch: int,
                    entity_id: str, user_id: str | None) -> None:
    """Indirection so tests can run the cascade synchronously instead of via a broker."""
    next_set_task.apply_async(
        args=(session_id, subsystem_id, epoch, threats_epoch),
        shadow=(f"next-set: session {session_id} · subsystem {subsystem_id} · "
                f"entity {entity_id} · by {user_id} · {dal.now():%Y-%m-%d %H:%M} UTC"))


def _do_next_set(session_id: str, principal: Principal, subsystem_id: int) -> RegenerateResponse:
    """Add the next accumulating batch of unique scenarios for one subsystem. Same eligibility /
    lock / CAS guards as _do_regenerate, but takes no target ids: which threats to serve is
    decided server-side by cascade.run_next_set."""
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)
        scenario_session = _assert_regen_eligible(sess, scenario_session)

        # bail out if another regenerate/accept/next-set already holds this subsystem's mutex lock
        lock_status = sess.execute(
            select(m.Subsystem_Stage_State.Status).where(
                m.Subsystem_Stage_State.SessionID == session_id,
                m.Subsystem_Stage_State.SubsystemID == subsystem_id,
                m.Subsystem_Stage_State.Level == SubsystemLevel.LOCK,
            )
        ).scalar()
        if lock_status == StageStatus.RUNNING:
            raise RegenerateConflict(f"subsystem {subsystem_id} is locked (regeneration/accept in progress)")
        # Next-set generates NEW scenarios, so unlike regenerate it DOES take the asset back for
        # the duration: CAS completed -> active. Losing that CAS means another execution already
        # holds the asset (or a fresh session claimed it while this reviewer was deciding), which
        # is a transient conflict the client can retry — not the terminal "session is over".
        # tasks._send_to_review flips it back to completed when generation reaches the barrier.
        # Two ways to lose the asset, and BOTH land here. The CAS loses when another execution
        # already re-reserved THIS session. IntegrityError fires when a different session claimed
        # the same asset while this reviewer was deciding — releasing the asset at the review
        # barrier is the whole point of the change, so that is now an ordinary outcome, and
        # UX_Session_ActiveAsset is the arbiter. Without this catch it is a 500.
        try:
            reserved = dal.reserve_session(sess, session_id)
        except IntegrityError as exc:
            raise RegenerateConflict(
                f"asset {scenario_session['AssetID']} is busy — another session holds it right "
                f"now; retry in a moment",
                reason=ReviewGateReason.asset_busy) from exc
        if not reserved:
            raise RegenerateConflict(
                f"asset {scenario_session['AssetID']} is busy — another generation holds it right "
                f"now; retry in a moment",
                reason=ReviewGateReason.asset_busy)

        # Reserve the THREATS epoch here too — once — and thread it through so a redelivery of the
        # task re-uses it and run_next_set's idempotency guard can skip a second additive
        # find_threats. Do NOT reset THREATS here: an IDLE THREATS row makes
        # decide_session_outcome return None (wedge) if the task is slow or lost; run_next_set
        # resets it (guarded) only if it actually needs the additive find_threats.
        epoch = dal.next_epoch(sess, session_id, subsystem_id, cascade.NEXT_SET_LEVELS)
        dal.reset_stage_for_regen(sess, session_id, subsystem_id, cascade.NEXT_SET_LEVELS, epoch)
        threats_epoch = dal.next_epoch(sess, session_id, subsystem_id, (SubsystemLevel.THREATS,))

    try:
        enqueue_next_set(session_id, subsystem_id, epoch, threats_epoch,
                        str(scenario_session["EntityID"]), scenario_session["UserID"])
    except Exception as exc:  # noqa: BLE001 — broker unreachable must not wedge SCENARIOS at IDLE
        _recover_from_enqueue_failure(session_id, subsystem_id, epoch, exc, "next_set.enqueue_failed")
    # The SCENARIOS epoch, not the THREATS one: it is the epoch run_next_set stamps on the
    # next_set_outcome audit row, so `last_next_set.epoch == this` is the client's exact
    # "my click landed" signal. Polling stage status instead cannot distinguish my click from
    # a concurrent one, which is how a mid-flight read looks finished.
    return RegenerateResponse(session_id=session_id, user_id=scenario_session["UserID"],
                            status="generating", epoch=epoch)


@router.post("/sessions/{session_id}/scenarios/next-set", status_code=202, response_model=RegenerateResponse,
            responses=_CONFLICT_RESPONSES | UNAVAILABLE_RESPONSES,
            summary="Generate more scenarios",
            description=(
                "Asks the AI for another batch of brand-new scenarios for the same asset. It adds; it never "
                "replaces. No request body.\n\n"
                "**Before you call:** the session must be at the review point.\n\n"
                "**What you get:** `202` with an `epoch`. Poll `GET /v1/sessions/{session_id}` until "
                "`progress.last_next_set.epoch` equals it, then read `progress.last_next_set.outcome`: "
                "`complete` means the full batch landed, `partial_retryable` means some generations failed "
                "and clicking again retries them, `exhausted` means nothing further exists for this asset and "
                "you should stop.\n\n"
                "**Watch out:** this briefly re-claims the asset while it runs, so a status poll mid-click "
                "can show `session_status` back at `active`. That is expected, and if someone else claims the "
                "asset during that window you get `409 regenerate_conflict` with the reason `asset_busy`, "
                "which is transient — retry it. A short result is not automatically a bug; `exhausted` is a "
                "correct final answer."
            ))
def post_next_set_scenarios(session_id: str, principal: Principal = Depends(get_principal)) -> RegenerateResponse:
    """Generate the next set of scenarios — 5 more unique threat scenarios that accumulate onto the
    existing ones for the session's asset, never superseding a prior batch. No request body: the
    asset is fully identified by `session_id` in the URL (a session is always exactly one asset).
    Returns 202 with status "generating"; a round that finds nothing new is not an error (the
    reviewer can retry)."""
    return _do_next_set(session_id, principal, ASSET_UNIT_ID)


@router.post("/sessions/{session_id}/cancel", response_model=CancelResponse,
            summary="Cancel a session",
            description=(
                "Aborts a session that is still generating, and frees its asset so a new session can start.\n\n"
                "**Before you call:** the session must still be `active`. Once generation reaches the review "
                "point the session is `completed` and cancel is refused with `409 cancel_conflict` — there is "
                "no way to cancel a session sitting in front of a reviewer, even an untouched one. The one "
                "exception is while a 'generate more' run is in flight, which briefly makes the session "
                "active again.\n\n"
                "**Watch out:** this does not stop the background work immediately. In-flight tasks notice on "
                "their own next check, so right after cancelling you may still see a stage running. That is "
                "expected."
            ))
def post_cancel(session_id: str, principal: Principal = Depends(get_principal)) -> CancelResponse:
    """Marks the session cancelled and audit-logs the actor; in-flight pipeline/regen
    tasks observe the status change on their own next CAS rather than being interrupted."""
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)
        # CAS-fenced: False means the session was already terminal (completed/cancelled by a
        # concurrent writer) — a conflict, not a silent re-flip of an already-decided session.
        # principal.user_id: THIS is the deliberate cancel, so the row records who chose it —
        # the same value the session_cancelled audit row below carries.
        if not dal.cancel_session(sess, session_id, principal.user_id):
            raise dal.CancelConflict(f"session {session_id} is no longer active")
        dal.append_audit(sess, AuditID=dal.guid(), SessionID=session_id, TenantID=scenario_session["TenantID"],
                        EntityID=scenario_session["EntityID"], EventType=AuditEventType.session_cancelled,
                        ActorUserID=principal.user_id)
    # Fast path only (item 1/item 30's sentinel-tick status check in stream_events() is the
    # actual close guarantee, and closes with or without this): an already-subscribed client
    # hears about the cancel near-instantly instead of waiting up to sse_ping_seconds for the
    # next tick. `type` is deliberately NOT an SSEEventType member — cancel/accept have no typed
    # contract in this plan (Section E enumerates only the 9 worker-driven kinds); this is an
    # informal nudge, not a documented event.
    bus.publish(session_id, {"type": "session_cancelled", "session_id": session_id,
                            "status": str(SessionStatus.cancelled), "ts": now().isoformat()})
    return CancelResponse(session_id=session_id, user_id=scenario_session["UserID"], status=str(SessionStatus.cancelled))


def _load_events_board(session_id: str, principal: Principal) -> dict:
    """The blocking DB load (authz + board) for `session_events`. Must run via
    `run_in_threadpool`: an `async def` route runs its body directly on the event loop, so
    synchronous pyodbc/SQLAlchemy calls here would block every other request on this worker."""
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)
        return build_board(sess, scenario_session)


def _stream_still_open(session_id: str, principal: Principal, verify_membership: bool) -> bool:
    """Item 1 + item 30's consolidated per-tick handler, run off the event loop (same reason as
    `_load_events_board`). Called once per `bus.SUBSCRIBE_TICK`, never per real event — this is
    the guarantee that closes the stream whether or not any `bus.publish` call ever arrives.

    False means the caller must close the generator: either the session is finished with this
    client (`load_session_board` returning None also counts, a hard-deleted row being the only way
    a valid session id stops resolving) or, when `verify_membership` is on, the (user, entity) pair
    no longer resolves (item 30). One function, one DB round trip per check — not two independent
    handlers racing their own queries.

    "Finished" is NOT `SessionStatus != active` any more. Generation completes the session at its
    review barrier to release the asset, so a session awaiting per-scenario decisions is
    `completed` while still very much live for this reviewer — closing on status alone would drop
    the stream at the exact moment the review UI opens. `review_gate_reason(row) is None` is the
    same predicate accept and regenerate gate on, reused here so the three cannot drift."""
    with db_session() as sess:
        row = dal.load_session_board(sess, session_id)
        if row is None:
            return False
        if str(row["SessionStatus"]) != str(SessionStatus.active) and review_gate_reason(row) is not None:
            return False
        if verify_membership:
            # Fail CLOSED on a missing user id: membership cannot be verified without one, and
            # dal.user_has_entity would raise TypeError on int(None) rather than deny.
            if principal.user_id is None:
                return False
            if not dal.user_has_entity(sess, principal.user_id, row["EntityID"]):
                return False
        return True


class SSEStreamCapacityExceeded(Exception):
    """`session_events()` is at the `sse_max_concurrent_streams` cap -> 503. Same soft/racy
    capacity-503 convention as `dal.CapacityExceeded`/`LLMSlotUnavailable` — see errors.py, which
    imports this to register its handler."""


@lru_cache
def _sse_semaphore() -> asyncio.Semaphore:
    """One per-process cap on concurrently open SSE streams, sized off the SAME setting
    (`sse_max_concurrent_streams`) that bounds `bus.py`'s shared subscriber connection pool
    (item 11) — so this semaphore can never admit a stream the pool has no connection for.
    `@lru_cache`, same singleton pattern as `bus._subscriber_pool()`, for the same reason: one
    instance for the life of this process, not one per request.

    ponytail: a plain in-process asyncio.Semaphore, not a Redis-backed cross-replica limiter —
    `sse_max_concurrent_streams` is documented (item 11) as a PER-PROCESS cap, matching the
    connection pool it's paired with. Upgrade to a shared limiter only if streams need capping
    across replicas, not just within one."""
    return asyncio.Semaphore(get_settings().sse_max_concurrent_streams)


# The stream has no response_model (it is not a single JSON body), so nothing about the events
# would otherwise appear in the spec — leaving a UI to hand-copy event shapes and reason codes out
# of the API guide. Declaring the payloads here puts them, and every enum they reference, into
# components.schemas so the client can be generated instead of transcribed.
# Declared via `model` (a union), NOT a hand-inlined model_json_schema(): FastAPI then registers
# both payloads AND every enum they reference in components.schemas. Inlining instead produces
# $defs-local refs that dangle once the spec is assembled.
# TreatmentPlanResultEvent is declared here even on deployments where risk_module_enabled is off:
# this router is always mounted, so gating a response-model union on a runtime flag would cost more
# machinery than a documented-but-unreachable event type is worth. Same posture as the other
# treatment schemas, which reach the spec through app/api/treatment.py's own models.
# Plan item 26: SessionBoard is bound here for `reconcile` — the ONLY union member with no
# `type: Literal[...]` discriminator field of its own (SessionBoard is shared with the polling
# GET /v1/sessions/{session_id}, which never sends a "type" key, so adding one to the model would
# misdescribe that response). The wire-level fix lives where the event is built, in
# stream_events() below: the streamed payload gets an actual `"type": "reconcile"` key stitched
# in, matching every other event's shape on the wire even though the schema here can't express it
# as a Literal without corrupting the polling GET's own schema.
_EVENT_STREAM_RESPONSES: dict[int | str, dict] = {
    200: {
        "model": (SessionBoard | StageStartedEvent | StageCompletedEvent | SubsystemStartedEvent
                | SessionEnteredReviewEvent | ErrorEvent | NextSetResultEvent | RegenResultEvent
                | TreatmentPlanResultEvent | HeartbeatEvent),
        "description": "SSE stream; each `data:` line is one event, ALL 10 kinds typed here "
                    "(reconcile + the 6 pipeline-lifecycle events + the 3 advisory result "
                    "events). Plan item 24: this is a fetch()+ReadableStream stream, sent with "
                    "the custom auth headers this API requires on every route — the native "
                    "browser `EventSource` API cannot set those headers, so it cannot consume "
                    "this endpoint; use fetch() with a ReadableStream reader (see "
                    "app/static/sse_test.html for a worked example), not `new EventSource(...)`. "
                    "`reconcile` is sent once per connect/reconnect, before any live event: the "
                    "full current SessionBoard, so a client never has to guess what it missed — "
                    "but it is a snapshot, not a delta, and it does NOT carry treatment-plan "
                    "state (see treatment_plan_result below). The 6 pipeline-lifecycle events "
                    "(stage_started/stage_completed/subsystem_started/session_entered_review/"
                    "error/heartbeat) are best-effort live progress narration; `error` is "
                    "dual-scope (see its `scope` field) and is NOT necessarily terminal on its "
                    "own — do not tear down UI on `error` alone, wait for "
                    "session_entered_review or a terminal session status. The 3 advisory result "
                    "events are best-effort and never replayed — treat them as a prompt to "
                    "refresh, and trust GET /v1/sessions/{session_id} for durable state. "
                    "A publish failure opens a circuit breaker that suppresses ALL events from "
                    "that worker process for a cooldown window, so a backstop poll is the recovery "
                    "path. `treatment_plan_result` is weaker still: plan state is NOT carried by "
                    "the `reconcile` event, and three outcomes never publish at all (dead worker, "
                    "LLM-capacity autoretry, cancel or a plain review verdict) — though an "
                    "approve that switches the active plan version DOES publish one after its "
                    "commit — recover with "
                    "GET /v1/sessions/{session_id}/treatment-plans and keep a slow poll. "
                    "Full field-by-field shapes: see the SessionProgress schema and the "
                    "per-event schemas published alongside it in this document.",
        "content": {"text/event-stream": {}},
    }
}


@router.get("/sessions/{session_id}/events",
            responses=_EVENT_STREAM_RESPONSES | UNAVAILABLE_RESPONSES,
            summary="Stream live session progress",
            description=(
                "Keeps a connection open and pushes session events as they happen, instead of you polling.\n\n"
                "**How to connect:** send `Accept: text/event-stream` with the same auth headers as every "
                "other route. A browser's built-in `EventSource` CANNOT be used here, because it cannot send "
                "custom headers — drive it with `fetch()` and a stream reader.\n\n"
                "**What arrives:** a `reconcile` event immediately with the full current board, then stage "
                "and result events as work completes, plus periodic heartbeats.\n\n"
                "**Watch out:** events are best-effort and are never replayed, so a dropped connection loses "
                "them silently. Always confirm anything important against the status board, which is durable. "
                "Some events that genuinely arrive are not listed in the generated schema, so make your event "
                "handler tolerate an unknown `type` rather than throwing."
            ))
async def session_events(session_id: str, principal: Principal = Depends(get_principal)):
    """SSE stream : sends the current board as a `reconcile` event before
    subscribing to live deltas, so a client that (re)connects mid-session never has to
    guess what it missed."""
    from sse_starlette.event import ServerSentEvent
    from sse_starlette.sse import EventSourceResponse
    from starlette.concurrency import run_in_threadpool

    settings = get_settings()
    # Item 12: gate BEFORE the threadpool board load — a non-blocking check (`.locked()` then an
    # immediate `.acquire()`, with no `await` between them, so nothing else on this single-
    # threaded event loop can interleave and steal the slot) rather than queuing behind a blocking
    # `.acquire()`, which would turn "at capacity" into a hung connection instead of a clean 503.
    sem = _sse_semaphore()
    if sem.locked():
        raise SSEStreamCapacityExceeded(
            f"at the {settings.sse_max_concurrent_streams}-stream SSE concurrency cap")
    await sem.acquire()
    try:
        board = await run_in_threadpool(_load_events_board, session_id, principal)
    except Exception:
        # Board load 404s/403s before the generator (and its own `finally`) ever starts —
        # release here or every rejected connect attempt leaks one slot of the cap.
        sem.release()
        raise
    # Key off the BOARD's session id, never the raw path param. Every publisher derives its
    # channel from that same canonical (lowercase) row value, and Redis pub/sub channel names are
    # byte-exact — so subscribing on an uppercase (or dashless/braced) path param opens a stream
    # that authorizes, reconciles, then receives NOTHING but heartbeats forever.
    canonical_session_id = board["session_id"]

    async def stream_events():
        try:
            # [R4] reconcile from the DB first, then stream live deltas (no replay log).
            # Item 26: stitch in "type": "reconcile" on the WIRE payload — `board` itself (also
            # served verbatim by GET /v1/sessions/{session_id}) never carries a "type" key, so
            # without this the reconcile event would be the only one on the stream with no
            # discriminator field a client can switch on (see _EVENT_STREAM_RESPONSES above).
            yield {"event": "reconcile", "data": json.dumps({**board, "type": str(SSEEventType.reconcile)})}
            async for ev in bus.subscribe(canonical_session_id):
                if ev is bus.SUBSCRIBE_TICK:
                    # Items 1 + 30, consolidated: the guarantee that closes the stream whether or
                    # not accept/cancel's own bus.publish (the fast path) ever arrives.
                    still_open = await run_in_threadpool(
                        _stream_still_open, canonical_session_id, principal, settings.verify_membership)
                    if not still_open:
                        return
                    continue
                yield {"event": ev.get("type", "message"), "data": json.dumps(ev)}
        finally:
            # Shielding isn't needed here the way bus.subscribe()'s own cleanup needs it (item
            # 15) — release() is synchronous, not an await that cancellation can cut short.
            sem.release()

    def _heartbeat() -> ServerSentEvent:
        return ServerSentEvent(
            data=json.dumps({"type": str(SSEEventType.heartbeat), "session_id": canonical_session_id,
                            "ts": now().isoformat()}),
            event=str(SSEEventType.heartbeat),
        )

    return EventSourceResponse(
        stream_events(), ping=settings.sse_ping_seconds, ping_message_factory=_heartbeat,
        # Item 2: force-close a stalled consumer in seconds, not the ~15 minutes a dead TCP peer
        # can otherwise take to surface. Item 20: bounded drain window on shutdown instead of an
        # instant cut — sized (25s) under gunicorn's 30s graceful-timeout (docker/compose.prod.yml).
        send_timeout=settings.sse_send_timeout_seconds,
        shutdown_grace_period=settings.sse_shutdown_grace_seconds,
    )


#: Paging + filter knobs for the session step trail. limit/offset are NOT optional: a session's
#: trail is O(scenarios x subsystems x regenerations).
_AUD_LIMIT = Query(default=100, ge=1, le=500, description="Page size.")
_AUD_OFFSET = Query(default=0, ge=0, description="Rows to skip.")


def _audit_event(row: dict) -> SessionAuditEvent:
    """One Scenario_Audit row -> one timeline entry, with its SUBJECT resolved.

    The subject is derived, not stored: a plan id means the step concerned that plan, else a
    scenario id means that scenario, else it concerned the session as a whole. Deriving it here
    keeps it in ONE place — a stored SubjectType column would be a third copy of a fact the event
    type and the two ids already determine between them."""
    detail = dal.safe_json_dict(row["DetailJSON"]) or {}
    # The COLUMN, not the JSON key: PlanID is indexed and seekable, and reading the blob was only
    # ever a workaround for the column not being populated. `detail` remains the fallback for rows
    # written before the column existed.
    plan_id = row.get("PlanID") or detail.get("plan_id")
    scenario_id = str(row["ScenarioID"]) if row["ScenarioID"] else None
    subject = "plan" if plan_id else ("scenario" if scenario_id else "session")
    return SessionAuditEvent(
        audit_id=str(row["AuditID"]), at=row["CreatedAt"], event=str(row["EventType"]),
        subject_type=subject, scenario_id=scenario_id, plan_id=plan_id,
        actor_user_id=row["ActorUserID"], actor_type=row["ActorType"],
        stage=row["Stage"], subsystem_id=row["SubsystemID"], decision=row["Decision"],
        detail=detail)


@router.get("/sessions/{session_id}/audit", response_model=SessionAuditPage,
            summary="Read a session's history",
            description=(
                "The session's step-by-step history, oldest first: who did what, to what, and when.\n\n"
                "**Call it:** any time. This is a plain read and is not gated by session state.\n\n"
                "**Filters:** `scenario_id` for one scenario's rows, `event` (repeatable) for specific event "
                "types, `actor` for one person, `since`/`until` for a time window, `limit` (max 500) and "
                "`offset` for paging.\n\n"
                "**Reading the result:** `actor_user_id` is filled in only on steps a human actually "
                "triggered. It is `null` with `actor_type: \"system\"` on everything the pipeline did by "
                "itself. A null there means the pipeline did it, not that data is missing — filtering by "
                "`actor` is how you isolate what a person did."
            ))
def get_session_audit(
    session_id: str,
    scenario_id: str | None = Query(default=None, description="Only steps concerning this scenario."),
    event: list[AuditEventType] | None = Query(default=None, description="Only these event types."),
    actor: str | None = Query(default=None, description="Only steps performed by this user id."),
    since: datetime | None = Query(default=None, description="Only steps at or after this time (UTC)."),
    until: datetime | None = Query(default=None, description="Only steps at or before this time (UTC)."),
    limit: int = _AUD_LIMIT,
    offset: int = _AUD_OFFSET,
    principal: Principal = Depends(get_principal),
) -> SessionAuditPage:
    """The session's step-by-step history, oldest first — who did what, when, and to what.

    Every step of every session has always been recorded; nothing read it back. The two existing
    audit endpoints cover treatment plans only, so the identification, scoping, generation, review
    and accept/reject steps had no read path at all.

    `event` is enum-typed on the way IN (a typo is a 422 you want immediately) but the RESPONSE
    reports it as a string: the column carries no database constraint, and one unrecognised
    historical value must not fail the whole page.

    Authorization is the shared entity check — 404 before 403, same as every session route."""
    with db_session() as sess:
        get_authorized_session(sess, session_id, principal)
        rows = dal.session_audit_rows(
            sess, session_id, scenario_id=scenario_id,
            events=[str(e) for e in event] if event else None,
            actor=actor, since=since, until=until, limit=limit, offset=offset)
        events = [_audit_event(dict(r)) for r in rows]
    return SessionAuditPage(session_id=session_id, limit=limit, offset=offset, events=events)


@router.get("/sessions/{session_id}/accepted-scenarios", response_model=AcceptedScenariosResponse,
            summary="List a session's accepted scenarios",
            description=(
                "Only the scenarios a reviewer accepted for this session — the clean feed for a risk register "
                "or downstream GRC tool. Drafts, declined and undecided scenarios never appear.\n\n"
                "**Call it:** any time the session exists, typically right after accepting.\n\n"
                "**Watch out:** a session nobody has reviewed yet returns `200` with an empty list — a valid "
                "answer, not an error. `completed_at` is stamped when GENERATION finished, not when anyone "
                "reviewed, so it is usually already set. It is null only while generation is still running, "
                "or if the session was cancelled."
            ))
def get_accepted_scenarios(session_id: str, principal: Principal = Depends(get_principal)) -> AcceptedScenariosResponse:
    """Returns the accepted, non-superseded scenarios for this session."""
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)
        rows = dal.accepted_scenarios(sess, scenario_session["SessionID"])
        controls = _controls_by_output(sess, [r["ScenarioID"] for r in rows])
        actor_ids = _actor_ids_from_blobs(sess, [r["ThreatActorsJSON"] for r in rows])
        return AcceptedScenariosResponse(
            asset_id=int(scenario_session["AssetID"]), entity_id=scenario_session["EntityID"],
            user_id=scenario_session["UserID"],
            session_id=scenario_session["SessionID"],
            completed_at=scenario_session["CompletedAt"],
            scenarios=[AcceptedScenario(
                scenario_id=r["ScenarioID"], subsystem_id=r["SubsystemID"],
                # BOTH spellings, no coalesce: what the model proposed and what it matched
                # are different facts, and a GRC reviewer defending this register needs to see
                # the difference rather than a silently-preferred one of the two.
                # The row goes in whole; _scenario_narrative owns the display preference.
                scenario=_scenario_narrative(r["ScenarioJSON"], r),
                threat=_threat_block(r),
                actors=_actor_block(r, actor_ids),
                controls=controls.by_output.get(r["ScenarioID"], []),
                # The accepted register is precisely where "who signed this off" belongs.
                # rejected_* stay null by construction: this endpoint returns accepted rows only,
                # and the two decisions are mutually exclusive in the database.
                accepted_by=r.get("AcceptedBy"), accepted_at=r.get("AcceptedAt"),
                controls_unavailable=controls.unavailable,
            ) for r in rows],
        )


# --- cross-session scenario reads (by user / by entity / by output id) ---

#: Paging + filter knobs shared by the two list routes below.
_SCN_LIMIT = Query(default=100, ge=1, le=500, description="Page size.")
_SCN_OFFSET = Query(default=0, ge=0, description="Rows to skip.")
_SCN_STATUS = Query(
    default=None,
    description="Narrow the list: 'active' | 'completed' | 'cancelled' filter by the owning "
                "session's status; 'accepted' returns only scenarios the user accepted.",
)
_SCN_SUPERSEDED = Query(
    default=False,
    description="Include scenarios that a regeneration has since replaced (hidden by default).",
)


def _scenario_list_item(row: dict, controls: list[MappedControl],
                        actor_ids: dict[str, int] | None = None,
                        *, unavailable: bool = False) -> ScenarioListItem:
    """One dal.scenario_rows/scenario_row row → response item. Same both-spellings rule and
    sibling actors/controls blocks as get_accepted_scenarios above."""
    return ScenarioListItem(
        scenario_id=row["ScenarioID"], subsystem_id=row["SubsystemID"],
        scenario=_scenario_narrative(row["ScenarioJSON"], row),
        threat=_threat_block(row),
        actors=_actor_block(row, actor_ids),
        controls=controls,
        session_id=row["SessionID"], entity_id=row["EntityID"], user_id=row["UserID"],
        session_status=row["SessionStatus"], scenario_number=row["ScenarioNumber"],
        accepted=bool(row["Accepted"]), superseded=bool(row["Superseded"]),
        accepted_by=row.get("AcceptedBy"), accepted_at=row.get("AcceptedAt"),
        rejected_by=row.get("RejectedBy"), rejected_at=row.get("RejectedAt"),
        created_at=row["CreatedAt"],
        # _scenario_read_select already carries ThreatActorsJSON — without this kwarg the list
        # routes would permanently return [] while /accepted-scenarios returns real actors.
        controls_unavailable=unavailable,
    )


def _list_scenarios(entity_ids: set[str], user_id: str | None, status: str | None,
                    include_superseded: bool, limit: int, offset: int) -> list[ScenarioListItem]:
    """Shared body of the two list routes: entity_ids must already be authorized.

    `user_id` is a FILTER, not an identity claim — naming a colleague is allowed and returns their
    rows, because entity scope is the authorization boundary here (see get_authorized_session for
    why that is deliberate)."""
    with db_session() as sess:
        rows = dal.scenario_rows(sess, entity_ids=entity_ids, user_id=user_id, status=status,
                                include_superseded=include_superseded, limit=limit, offset=offset)
        controls = _controls_by_output(sess, [r["ScenarioID"] for r in rows])  # one batch, no N+1
        actor_ids = _actor_ids_from_blobs(sess, [r["ThreatActorsJSON"] for r in rows])
        return [_scenario_list_item(r, controls.by_output.get(r["ScenarioID"], []), actor_ids,
                                    unavailable=controls.unavailable) for r in rows]


@scenarios_router.get("/users/{user_id}/scenarios", response_model=list[ScenarioListItem],
            summary="List scenarios by user",
            description=(
                "Every completed scenario one user created, across all their sessions, newest first. "
                "Scenarios whose generation failed never appear here.\n\n"
                "**Scoping:** results are always narrowed to your own authorized entity, whichever user you "
                "ask about.\n\n"
                "**Filters:** `status` accepts `active`, `completed` or `cancelled` (the owning session's "
                "state) or `accepted` (only what a human kept). `include_superseded=true` also returns "
                "replaced versions. `limit` (max 500) and `offset` page the result.\n\n"
                "**Watch out:** `status=accepted` always returns accepted scenarios even if they were later "
                "replaced, regardless of `include_superseded`. An empty list is a valid `200`."
            ))
def list_user_scenarios(
    user_id: str = Path(max_length=200, description="Session owner to list scenarios for. "
                        "A filter, not an identity claim — see below."),
    principal: Principal = Depends(get_principal),
    status: Literal["active", "completed", "cancelled", "accepted"] | None = _SCN_STATUS,
    include_superseded: bool = _SCN_SUPERSEDED,
    limit: int = _SCN_LIMIT,
    offset: int = _SCN_OFFSET,
) -> list[ScenarioListItem]:
    """Lists the scenarios this user created, newest first, across every session the caller
    is entitled to see. `user_id` is a FILTER, not an identity claim: results are always
    restricted to the caller's authorized entities, so a user's work in an entity outside
    the caller's scope stays invisible. Failure cards never appear."""
    return _list_scenarios(principal.entities, user_id, status, include_superseded, limit, offset)


@scenarios_router.get("/entities/{entity_id}/scenarios", response_model=list[ScenarioListItem],
            summary="List scenarios by entity",
            description=(
                "Every completed scenario belonging to one entity, across all users and sessions, newest "
                "first. Scenarios whose generation failed never appear here.\n\n"
                "**Before you call:** the `entity_id` in the path must match your `X-Entity-Id` header. "
                "Asking about another entity returns `403`.\n\n"
                "Same filters as the per-user list: `status`, `include_superseded`, `limit`, `offset`. An "
                "empty list is a valid `200`."
            ))
def list_entity_scenarios(
    entity_id: str = Path(max_length=200, description="Entity to list scenarios for. "
                        "Must be in the caller's authorized set."),
    principal: Principal = Depends(get_principal),
    status: Literal["active", "completed", "cancelled", "accepted"] | None = _SCN_STATUS,
    include_superseded: bool = _SCN_SUPERSEDED,
    limit: int = _SCN_LIMIT,
    offset: int = _SCN_OFFSET,
) -> list[ScenarioListItem]:
    """Lists every scenario under one entity (all users, all sessions), newest first.
    403 unless the entity is in the caller's authorized set."""
    principal.require_entity(entity_id)
    return _list_scenarios({str(entity_id)}, None, status, include_superseded, limit, offset)


@scenarios_router.get("/sessions/{session_id}/scenarios/{scenario_id}", response_model=ScenarioListItem,
            summary="Fetch one scenario",
            description=(
                "One specific scenario by id, with its threat, adversaries and mapped controls.\n\n"
                "**Required:** the `user_id` query parameter, which must be the session's owner. Omitting it "
                "is a `422`; giving the wrong one is a `404`.\n\n"
                "**Watch out:** every scenario-id miss returns `404` — unknown, belonging to another session, "
                "or not a GUID at all. A session id is different: one that exists but belongs to another "
                "entity returns `403`."
            ))
def get_scenario(
    session_id: str,
    scenario_id: str,
    user_id: str = Query(max_length=200, description="The session owner who created the scenario. "
                        "A mismatch 404s — filter semantics, no existence leak."),
    principal: Principal = Depends(get_principal),
) -> ScenarioListItem:
    """Fetches one scenario by id, whatever its flags — a direct scenario_id lookup is how a
    caller inspects superseded history or an error card (scenario is null on the latter).
    404 before 403, same as every session route."""
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)
        # user_id is a filter (like the list routes), so a mismatch is "no such resource
        # under this filter" — 404, not 403, or the response would leak that the id exists.
        if scenario_session["UserID"] != user_id:
            raise dal.NotFoundError(f"scenario {scenario_id} not found")
        row = dal.scenario_row(sess, scenario_session["SessionID"], scenario_id)
        if row is None:
            raise dal.NotFoundError(f"scenario {scenario_id} not found")
        controls = _controls_by_output(sess, [row["ScenarioID"]])
        actor_ids = _actor_ids_from_blobs(sess, [row["ThreatActorsJSON"]])
        return _scenario_list_item(dict(row), controls.by_output.get(row["ScenarioID"], []),
                                    actor_ids, unavailable=controls.unavailable)
