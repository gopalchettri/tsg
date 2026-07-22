"""Session API — create / status board / results / accept / cancel / SSE.

Object-level authz: every route resolves the session's EntityID and checks
it is in the caller's authorized set — a valid token is not enough. SSE reconnect
reconciles from the DB board.
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Header
from fastapi.responses import JSONResponse
from sqlalchemy import exists, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from app.api.deps import Principal, get_principal
from app.api.schemas import (
    AcceptBody, AcceptedScenario, AcceptedScenariosResponse, AcceptResponse, CancelResponse, CreateSessionBody,
    CreateSessionResponse, NextSetBody, RegenerateResponse, RegenerateScenariosBody, ScenarioResult, SessionBoard,
    SessionResults, ThreatResult,
)
from app.core.config import get_settings
from app.core.enums import (
    AuditEventType, RegenGranularity, SessionMode, SessionStatus, SSEEventType, StageStatus, SubsystemLevel,
    SubsystemProgress, WorkflowStage,
)
from app.db import dal
from app.db import models as m
from app.db.dal import EntityForbidden, IdempotencyKeyConflict, RegenerateConflict, now
from app.db.engine import db_session
from app.pipeline import cascade
from app.pipeline.accept import accept_session
from app.pipeline.celery_app import next_set_task, regenerate_task, run_pipeline_task
from app.pipeline.context import gather_asset_details
from app.pipeline.tasks import set_up_progress_tracking

router = APIRouter(prefix="/v1")


def enqueue_pipeline(session_id: str) -> None:
    """Indirection so tests can run the pipeline synchronously instead of via a broker."""
    run_pipeline_task.delay(session_id)


# --- status board ---
def get_overall_status(threats: str, scenarios: str, session_status: str) -> SubsystemProgress:
    """Rolls a subsystem's threat-stage and scenario-stage statuses (plus the overall
    session status) up into a single status for display. The checks below run in
    priority order — the first match wins."""
    vals = (threats, scenarios)
    # priority order: any error beats everything else, then session-level completed/
    # cancelled, then "waiting on a human decision", then plain idle vs. in-progress
    if StageStatus.ERROR in vals:
        return SubsystemProgress.error
    if session_status == SessionStatus.completed:
        return SubsystemProgress.complete
    if session_status == SessionStatus.cancelled:
        return SubsystemProgress.cancelled
    if scenarios == StageStatus.AWAITING_DECISION:
        return SubsystemProgress.awaiting_review
    if all(v == StageStatus.IDLE for v in vals):
        return SubsystemProgress.pending
    return SubsystemProgress.in_progress


def build_board(sess: Session, scenario_session: dict) -> dict:
    """The GET /sessions/{id} payload and the SSE reconnect-reconcile source."""
    # map each subsystem id to its display name, from the session's stored subsystem list
    names = {s["id"]: s["name"] for s in json.loads(scenario_session["SubsystemsJSON"])}
    pivot: dict[int, dict[str, str]] = {}
    # pivot the flat per-subsystem-per-level stage rows into
    # {subsystem_id: {"threats": status, "scenarios": status}}
    for row in dal.stage_rows(sess, scenario_session["SessionID"]):
        pivot.setdefault(row["SubsystemID"], {})[str(row["Level"]).lower()] = str(row["Status"])
    supporting_systems = []
    # build one board entry per subsystem, filling in the overall rollup status
    for ssid, stages in pivot.items():
        t = stages.get("threats", StageStatus.IDLE)
        sc = stages.get("scenarios", StageStatus.IDLE)
        supporting_systems.append({
            "id": ssid, "name": names.get(ssid),
            "stages": {"threats": t, "scenarios": sc},
            "overall": str(get_overall_status(t, sc, scenario_session["SessionStatus"])),
        })
    return {
        "session_id": scenario_session["SessionID"], "entity_id": scenario_session["EntityID"],
        "session_status": scenario_session["SessionStatus"],
        "current_stage": scenario_session["CurrentStage"], "stage_status": scenario_session["StageStatus"],
        "supporting_systems": supporting_systems,
    }


def get_authorized_session(sess: Session, session_id: str, principal: Principal) -> dict:
    """Load-then-authorize helper shared by every route below: 404s before it 403s, so
    a caller outside the entity scope can't distinguish "doesn't exist" from "not yours"
    (object-level authz)."""
    row = dal.load_session(sess, session_id)
    if row is None:
        raise dal.NotFoundError(f"session {session_id} not found")
    if str(row["EntityID"]) not in principal.entities:  # object-level authz / IDOR guard
        raise EntityForbidden(f"session {session_id} not in caller's entity scope")
    return dict(row)


def _build_session_row(sid: str, tenant: str, body: CreateSessionBody, ctx: dict,
                    idempotency_key: str | None) -> dict:
    """Assembles the new Scenario_Session row from the request body and the gathered asset context."""
    return {
        "SessionID": sid, "TenantID": tenant, "EntityID": str(body.entity_id),
        "UserID": str(body.user_id) if body.user_id is not None else None,
        "AssetName": ctx["asset"]["name"], "AssetID": str(body.asset_id),
        "SessionStatus": SessionStatus.active, "CurrentStage": WorkflowStage.THREAT_IDENTIFICATION,
        "StageStatus": StageStatus.IDLE, "Mode": SessionMode.AUTO, "CurrentSubsystemIndex": 0,
        "SubsystemsJSON": ctx["subsystems_json"], "SectorIDsJSON": json.dumps(ctx["sector_ids"]),
        "AssetContextJSON": ctx["asset_context_json"],
        "CreatedAt": now(), "UpdatedAt": now(),
        "IdempotencyKey": idempotency_key,
    }


# --- endpoints ---
@router.post("/sessions", status_code=202, response_model=CreateSessionResponse)
def create_session(
    body: CreateSessionBody, principal: Principal = Depends(get_principal),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> CreateSessionResponse | JSONResponse:
    """Creates the session row plus initial stage state and kicks off the pipeline
    task; an `Idempotency-Key` short-circuits to the existing session on retry instead
    of creating a duplicate (200 + `JSONResponse`, not the 202 the decorator declares)."""
    principal.require_entity(body.entity_id)
    tenant = get_settings().tenant_id
    sid = dal.guid()
    with db_session() as sess:
        dal.assert_asset_owned_by_entity(sess, body.asset_id, body.entity_id)
        if idempotency_key:
            existing_id, conflict = dal.reserve_idempotency_key_or_get_existing(
                sess, str(body.entity_id), idempotency_key, str(body.asset_id))
            if existing_id:  # `conflict` is only ever True alongside a found row
                if conflict:
                    raise IdempotencyKeyConflict(existing_id)
                # [REVIEW-FIX] previously a hand-rolled {"session_id": existing_id} dict — same
                # shape as CreateSessionResponse today, but drifts silently the moment that model
                # ever grows a field, and the raw dict skips response_model serialization/OpenAPI
                # documentation entirely. Routing through the model keeps this branch shape-locked
                # to the same contract the fresh-create (202) path returns.
                return JSONResponse(status_code=200, content=CreateSessionResponse(session_id=existing_id).model_dump())

        dal.assert_capacity_available(sess, entity_id=body.entity_id)  # 503 before the more expensive gather_asset_details

        ctx = gather_asset_details(sess, asset_id=body.asset_id, entity_id=body.entity_id,
                            sector_id=body.sector_id, user_id=body.user_id,
                            supporting_system_ids=body.supporting_system_id)
        dal.create_session(sess, _build_session_row(sid, tenant, body, ctx, idempotency_key))
        set_up_progress_tracking(sess, sid, tenant, str(body.entity_id), ctx["subsystems"])
        dal.append_audit(sess, AuditID=dal.guid(), SessionID=sid, TenantID=tenant, EntityID=str(body.entity_id),
                        EventType=AuditEventType.session_started, ActorUserID=body.user_id)
    enqueue_pipeline(sid)
    return CreateSessionResponse(session_id=sid)


@router.get("/sessions/{session_id}", response_model=SessionBoard)
def get_session(session_id: str, principal: Principal = Depends(get_principal)) -> SessionBoard:
    """Status-board poll endpoint — same rollup logic the SSE reconnect uses,
    so polling and streaming clients never disagree on subsystem state."""
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)
        return SessionBoard.model_validate(build_board(sess, scenario_session))


@router.get("/sessions/{session_id}/results", response_model=SessionResults)
def get_results(session_id: str, principal: Principal = Depends(get_principal)) -> SessionResults:
    """Returns the session's current (non-superseded) threats and scenarios, shaped
    into the API response schema."""
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)
        sid = scenario_session["SessionID"]
        entity_id = scenario_session["EntityID"]
        def get_current_rows(table, cols, *extra):
            """Selects the given columns for this session, excluding rows a prior
            regeneration superseded — the shared filter for both result kinds below.
            `extra` predicates narrow further (the threats query passes an EXISTS so
            only threats actually used for a scenario come back)."""
            return [dict(r) for r in sess.execute(
                select(*cols).where(table.SessionID == sid, table.Superseded == 0, *extra)
            ).mappings()]

        st, out = m.Scoped_Threat, m.Threat_Scenario_Output
        threats = get_current_rows(m.Identified_Threat,
                        [m.Identified_Threat.ThreatID, m.Identified_Threat.SubsystemID,
                        m.Identified_Threat.ThreatType, m.Identified_Threat.ThreatName,
                        m.Identified_Threat.GroundingStatus, m.Identified_Threat.ThreatCatalogueID],
                        # only threats that actually PRODUCED a scenario — trace Identified_Threat ->
                        # Scoped_Threat -> active Threat_Scenario_Output (linked by ScopedThreatID). A
                        # selected threat whose scenario failed to generate has no active output, so
                        # it's correctly excluded (stricter than "was Selected=1").
                        exists().where(st.ThreatID == m.Identified_Threat.ThreatID,
                                    st.SessionID == sid, st.Superseded == 0,
                                    out.ScopedThreatID == st.ScopedThreatID,
                                    out.SessionID == sid, out.Superseded == 0))
        scenarios = get_current_rows(m.Threat_Scenario_Output,
                            [m.Threat_Scenario_Output.OutputID, m.Threat_Scenario_Output.SubsystemID,
                            m.Threat_Scenario_Output.ScenarioJSON, m.Threat_Scenario_Output.Accepted,
                            m.Threat_Scenario_Output.ValidationJSON])
        # add entity_id to the result for downstream consumers — the same value every row shares, so just pick one
        return SessionResults(
            session_id=sid, entity_id=entity_id,
            threats=[ThreatResult(threat_id=t["ThreatID"], supporting_system_id=t["SubsystemID"],
                                threat_type=t["ThreatType"], threat_name=t["ThreatName"],
                                grounding_status=t["GroundingStatus"],
                                threat_catalogue_id=t["ThreatCatalogueID"]) for t in threats],
            scenarios=[_scenario_result(s) for s in scenarios],
        )


def _moderation_summary(validation_json: str | None) -> tuple[bool | None, list[str]]:
    """[REVIEW-FIX] pulls the moderation flag out of a scenario's ValidationJSON (llm.moderate's
    result, folded in by tasks.py::_moderation_report) for a reviewer to see. None for `flagged`
    means moderation was never checked (off by default, or the service was unavailable) — kept
    distinct from checked-and-clean (False) rather than collapsing both to one falsy value.
    Defensive against a missing/malformed blob, same as every other best-effort JSON parse in
    this codebase — a reviewer should never get a 500 over an unrelated field's shape."""
    if not validation_json:
        return None, []
    try:
        report = json.loads(validation_json)
    except (json.JSONDecodeError, TypeError):
        return None, []
    moderation = report.get("moderation") if isinstance(report, dict) else None
    if not isinstance(moderation, dict) or not moderation.get("checked"):
        return None, []
    return bool(moderation.get("flagged")), list(moderation.get("categories") or [])


def _validation_summary(validation_json: str | None) -> tuple[str | None, list[str]]:
    """Pulls validate_scenario's own structural/consistency report (missing fields, statement
    not referencing the threat, risk_statement not referencing the asset/critical service) out of
    a scenario's ValidationJSON for a reviewer to see — same reasoning, and same defensive
    parsing, as _moderation_summary above: a warning-status scenario was previously written to
    the DB but invisible to any human reviewer through this API. None for validation_status means
    the field is missing/malformed, not that it was checked and clean (that's the string "ok")."""
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


def _scenario_result(row: dict) -> ScenarioResult:
    flagged, categories = _moderation_summary(row["ValidationJSON"])
    validation_status, validation_errors = _validation_summary(row["ValidationJSON"])
    return ScenarioResult(output_id=row["OutputID"], supporting_system_id=row["SubsystemID"],
                        scenario=json.loads(row["ScenarioJSON"]) if row["ScenarioJSON"] else None,
                        accepted=bool(row["Accepted"]),
                        moderation_flagged=flagged, moderation_categories=categories,
                        validation_status=validation_status, validation_errors=validation_errors)


@router.post("/sessions/{session_id}/accept", response_model=AcceptResponse)
def post_accept(session_id: str, body: AcceptBody, principal: Principal = Depends(get_principal)) -> AcceptResponse:
    """Accepts all or a subset of scenarios and finalizes the session; the actual
    validation and state transition live in `accept_session`, this is just the authz +
    HTTP wrapper."""
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)
        accept_session(sess, session_id, scenario_session["EntityID"], principal.user_id, subset=body.subset)
    return AcceptResponse(session_id=session_id, status=str(SessionStatus.completed))


def enqueue_regeneration(session_id: str, subsystem_id: int, granularity: RegenGranularity,
                        target_ids: list[str] | list[int] | None, epoch: int, user_note: str | None) -> None:
    """Indirection so tests can run the cascade synchronously instead of via a broker."""
    regenerate_task.delay(session_id, subsystem_id, str(granularity), target_ids, epoch, user_note)


def _assert_regen_eligible(scenario_session: dict) -> None:
    """Regeneration is only allowed while the session is parked at REVIEW waiting on a human decision."""
    if (scenario_session["CurrentStage"] != WorkflowStage.REVIEW
            or scenario_session["StageStatus"] != StageStatus.AWAITING_DECISION):
        raise RegenerateConflict(
            f"session not at REVIEW (stage={scenario_session['CurrentStage']}, "
            f"status={scenario_session['StageStatus']})")


def _assert_subsystem_in_session(scenario_session: dict, subsystem_id: int, session_id: str) -> None:
    """Make sure the requested subsystem actually belongs to this session."""
    subsystems = json.loads(scenario_session["SubsystemsJSON"])
    if not any(s["id"] == subsystem_id for s in subsystems):
        raise dal.NotFoundError(f"subsystem {subsystem_id} not in session {session_id}")


def _do_regenerate(session_id: str, principal: Principal, subsystem_id: int, granularity: RegenGranularity,
                target_ids: list[str] | list[int] | None, user_note: str | None) -> RegenerateResponse:
    """Validates the session/subsystem is eligible for regeneration, guards against
    a concurrent regen/accept via a lock check plus a conditional UPDATE, then resets
    the affected stage rows and hands off to the async regenerate task."""
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)
        _assert_regen_eligible(scenario_session)
        _assert_subsystem_in_session(scenario_session, subsystem_id, session_id)

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
        # conditional UPDATE (compare-and-swap): only succeeds if the session is still
        # active and at REVIEW: rowcount != 1 means a concurrent request already moved it
        res: CursorResult = dal.execute_dml(
            sess,
            update(m.Scenario_Session)
            .where(m.Scenario_Session.SessionID == session_id,
                m.Scenario_Session.SessionStatus == SessionStatus.active,
                m.Scenario_Session.CurrentStage == WorkflowStage.REVIEW)
            .values(CurrentStage=WorkflowStage.SCENARIO_GENERATION, StageStatus=StageStatus.RUNNING, UpdatedAt=now())
        )
        if res.rowcount != 1:
            raise RegenerateConflict("another regeneration/accept won the race")
        
        levels = cascade.LEVELS_BY_GRANULARITY[granularity]
        epoch = dal.next_epoch(sess, session_id, subsystem_id, levels)
        dal.reset_stage_for_regen(sess, session_id, subsystem_id, levels, epoch)

    enqueue_regeneration(session_id, subsystem_id, granularity, target_ids, epoch, user_note)
    return RegenerateResponse(session_id=session_id, status="regenerating")


@router.post("/sessions/{session_id}/regenerate/scenarios", status_code=202, response_model=RegenerateResponse)
def post_regenerate_scenarios(session_id: str, body: RegenerateScenariosBody,
                            principal: Principal = Depends(get_principal)) -> RegenerateResponse:
    """Rebuild one or more scenarios' narratives only — siblings untouched (scenarios 1, 2)."""
    return _do_regenerate(session_id, principal, body.supporting_system_id, RegenGranularity.scenario,
                        body.output_ids, body.user_note)


def enqueue_next_set(session_id: str, subsystem_id: int, epoch: int, threats_epoch: int) -> None:
    """Indirection so tests can run the cascade synchronously instead of via a broker."""
    next_set_task.delay(session_id, subsystem_id, epoch, threats_epoch)


def _do_next_set(session_id: str, principal: Principal, subsystem_id: int) -> RegenerateResponse:
    """"Generate next set of scenarios": add the next accumulating batch of unique scenarios for
    one subsystem. Same eligibility / lock / CAS guards as _do_regenerate — only allowed at the
    REVIEW barrier, serialised against a concurrent regen/accept/next-set by the subsystem lock —
    but takes no target ids: which threats to serve is decided server-side by cascade.run_next_set
    (already-scored pool first, then a fresh coverage-aware AI batch)."""
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)
        _assert_regen_eligible(scenario_session)
        _assert_subsystem_in_session(scenario_session, subsystem_id, session_id)

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
        # conditional UPDATE (compare-and-swap): only succeeds while the session is still active
        # and at REVIEW — rowcount != 1 means a concurrent request already moved it.
        res: CursorResult = dal.execute_dml(
            sess,
            update(m.Scenario_Session)
            .where(m.Scenario_Session.SessionID == session_id,
                m.Scenario_Session.SessionStatus == SessionStatus.active,
                m.Scenario_Session.CurrentStage == WorkflowStage.REVIEW)
            .values(CurrentStage=WorkflowStage.SCENARIO_GENERATION, StageStatus=StageStatus.RUNNING, UpdatedAt=now())
        )
        if res.rowcount != 1:
            raise RegenerateConflict("another regeneration/accept won the race")

        # Reserve the SCENARIOS epoch and reset that level (same as a scenario regen). ALSO reserve
        # the THREATS epoch here — once — and thread it through so a redelivery/retry of the task
        # re-uses it and run_next_set's idempotency guard can skip a second additive find_threats.
        # Do NOT reset THREATS here: an IDLE THREATS row would make decide_session_outcome return
        # None (wedge) if the task is slow or lost; run_next_set resets it (guarded) only if it
        # actually needs the additive find_threats.
        epoch = dal.next_epoch(sess, session_id, subsystem_id, cascade.NEXT_SET_LEVELS)
        dal.reset_stage_for_regen(sess, session_id, subsystem_id, cascade.NEXT_SET_LEVELS, epoch)
        threats_epoch = dal.next_epoch(sess, session_id, subsystem_id, (SubsystemLevel.THREATS,))

    enqueue_next_set(session_id, subsystem_id, epoch, threats_epoch)
    return RegenerateResponse(session_id=session_id, status="generating")


@router.post("/sessions/{session_id}/scenarios/next-set", status_code=202, response_model=RegenerateResponse)
def post_next_set_scenarios(session_id: str, body: NextSetBody,
                            principal: Principal = Depends(get_principal)) -> RegenerateResponse:
    """Generate the next set of scenarios — 5 more unique threat scenarios that accumulate onto the
    existing ones for one supporting system, never superseding a prior batch. Returns 202 with
    status "generating"; a round that finds nothing new is not an error (the reviewer can retry)."""
    return _do_next_set(session_id, principal, body.supporting_system_id)


@router.post("/sessions/{session_id}/cancel", response_model=CancelResponse)
def post_cancel(session_id: str, principal: Principal = Depends(get_principal)) -> CancelResponse:
    """Marks the session cancelled and audit-logs the actor; in-flight pipeline/regen
    tasks observe the status change on their own next CAS rather than being interrupted."""
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)
        # CAS-fenced: False means the session was already terminal (completed/cancelled
        # by a concurrent writer) — surface that as a conflict rather than silently
        # flipping an already-decided session back to cancelled.
        if not dal.cancel_session(sess, session_id):
            raise dal.CancelConflict(f"session {session_id} is no longer active")
        dal.append_audit(sess, AuditID=dal.guid(), SessionID=session_id, TenantID=scenario_session["TenantID"],
                        EntityID=scenario_session["EntityID"], EventType=AuditEventType.session_cancelled,
                        ActorUserID=principal.user_id)
    return CancelResponse(session_id=session_id, status=str(SessionStatus.cancelled))


def _load_events_board(session_id: str, principal: Principal) -> dict:
    """The blocking DB load (authz + board) for `session_events`. Run via
    `run_in_threadpool` since this is the file's only `async def` route — a plain
    `def` route gets threadpool offload from Starlette automatically, but an `async
    def` runs its body directly on the event loop, so synchronous pyodbc/SQLAlchemy
    calls here would otherwise block every other concurrent request on this worker."""
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)
        return build_board(sess, scenario_session)


@router.get("/sessions/{session_id}/events")
async def session_events(session_id: str, principal: Principal = Depends(get_principal)):
    """SSE stream (§9.1): sends the current board as a `reconcile` event before
    subscribing to live deltas, so a client that (re)connects mid-session never has to
    guess what it missed ([R4])."""
    from sse_starlette.event import ServerSentEvent
    from sse_starlette.sse import EventSourceResponse
    from starlette.concurrency import run_in_threadpool

    from app.sse import bus

    board = await run_in_threadpool(_load_events_board, session_id, principal)

    async def stream_events():
        """The event generator EventSourceResponse iterates; captures `board` from the
        enclosing scope so the reconcile snapshot reflects the DB state at connect time."""
        # [R4] reconcile from the DB first, then stream live deltas (no replay log).
        yield {"event": "reconcile", "data": json.dumps(board)}
        async for ev in bus.subscribe(session_id):
            yield {"event": ev.get("type", "message"), "data": json.dumps(ev)}

    def _heartbeat() -> ServerSentEvent:
        """Builds the periodic heartbeat SSE event; passed to EventSourceResponse as
        `ping_message_factory` rather than called directly."""
        return ServerSentEvent(
            data=json.dumps({"type": str(SSEEventType.heartbeat), "session_id": session_id, "ts": now().isoformat()}),
            event=str(SSEEventType.heartbeat),
        )

    return EventSourceResponse(stream_events(), ping=get_settings().sse_ping_seconds, ping_message_factory=_heartbeat)



@router.get("/assets/{asset_id}/accepted-scenarios", response_model=AcceptedScenariosResponse)
def get_accepted_scenarios(asset_id: int, entity: str,
                        principal: Principal = Depends(get_principal)) -> AcceptedScenariosResponse:
    """Returns the accepted scenarios from the most recently completed session for this
    asset. If the asset has no completed session yet, returns an empty result rather
    than a 404."""
    with db_session() as sess:
        principal.require_entity(entity)
        dal.assert_asset_owned_by_entity(sess, asset_id, entity)
        scenario_session = dal.latest_completed_session(sess, entity, str(asset_id))
        # no completed session yet -> empty scenario list, not an error
        rows = dal.accepted_scenarios(sess, scenario_session["SessionID"]) if scenario_session else []
        return AcceptedScenariosResponse(
            asset_id=asset_id, entity_id=entity,
            session_id=scenario_session["SessionID"] if scenario_session else None,
            completed_at=scenario_session["CompletedAt"] if scenario_session else None,
            scenarios=[AcceptedScenario(
                output_id=r["OutputID"], supporting_system_id=r["SubsystemID"],
                threat_type_id=r["ThreatTypeID"], threat_catalogue_id=r["ThreatCatalogueID"],               
                # prefer the curated catalogue name/type; fall back to the freeform one if not linked to the library
                threat_type=r["LibraryThreatType"] or r["ThreatType"],
                threat_name=r["LibraryThreatName"] or r["ThreatName"],
                scenario=json.loads(r["ScenarioJSON"]) if r["ScenarioJSON"] else None,
            ) for r in rows],
        )
