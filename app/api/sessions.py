"""Session API — create / status board / results / accept / cancel / SSE.

Object-level authz: every route resolves the session's EntityID and checks
it is in the caller's authorized set — a valid token is not enough. SSE reconnect
reconciles from the DB board.
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Header
from fastapi.responses import JSONResponse
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.api.deps import Principal, get_principal
from app.api.schemas import (
    AcceptBody, AcceptedScenario, AcceptedScenariosResponse, AcceptResponse, CancelResponse, CreateSessionBody,
    CreateSessionResponse, ProfileResult, RegenerateResponse, RegenerateScenariosBody, ScenarioResult, SessionBoard,
    SessionResults, SupportingSystemBoard, ThreatResult,
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
from app.pipeline.celery_app import regenerate_task, run_pipeline_task
from app.pipeline.context import check_asset_belongs_to_entity, gather_asset_details
from app.pipeline.tasks import set_up_progress_tracking

router = APIRouter(prefix="/v1")


def enqueue_pipeline(session_id: str) -> None:
    """Indirection so tests can run the pipeline synchronously instead of via a broker."""
    run_pipeline_task.delay(session_id)


# --- status board ---
def get_overall_status(profile: str, threats: str, scenarios: str, session_status: str) -> SubsystemProgress:
    """Derived overall, evaluated top-to-bottom, first match wins. A subsystem
    that genuinely errored or completed still reports that specific fact even on a
    cancelled session (ERROR/COMPLETE checked first) — `cancelled` only applies where
    there's nothing more specific to say (e.g. AWAITING_DECISION would otherwise read
    as still-actionable on a session that's actually dead)."""
    vals = (profile, threats, scenarios)
    if StageStatus.ERROR in vals:
        return SubsystemProgress.error
    if all(v == StageStatus.COMPLETE for v in vals):
        return SubsystemProgress.complete
    if session_status == SessionStatus.cancelled:
        return SubsystemProgress.cancelled
    if scenarios == StageStatus.AWAITING_DECISION:
        return SubsystemProgress.awaiting_review
    if all(v == StageStatus.IDLE for v in vals):
        return SubsystemProgress.pending
    return SubsystemProgress.in_progress


def build_board(sess: Session, session: dict) -> dict:
    """The GET /sessions/{id} payload and the SSE reconnect-reconcile source."""
    names = {s["id"]: s["name"] for s in json.loads(session["SubsystemsJSON"])}
    pivot: dict[int, dict[str, str]] = {}
    for row in dal.stage_rows(sess, session["SessionID"]):
        pivot.setdefault(row["SubsystemID"], {})[str(row["Level"]).lower()] = str(row["Status"])
    supporting_systems = []
    for ssid, stages in pivot.items():
        p = stages.get("profile", StageStatus.IDLE)
        t = stages.get("threats", StageStatus.IDLE)
        sc = stages.get("scenarios", StageStatus.IDLE)
        supporting_systems.append({
            "id": ssid, "name": names.get(ssid),
            "stages": {"profile": p, "threats": t, "scenarios": sc},
            "overall": str(get_overall_status(p, t, sc, session["SessionStatus"])),
        })
    return {
        "session_id": session["SessionID"], "entity_id": session["EntityID"],
        "session_status": session["SessionStatus"],
        "current_stage": session["CurrentStage"], "stage_status": session["StageStatus"],
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


# --- endpoints ---
@router.post("/sessions", status_code=202, response_model=CreateSessionResponse)
def create_session(
    body: CreateSessionBody, principal: Principal = Depends(get_principal),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> CreateSessionResponse:
    """Creates the session row plus initial stage state and kicks off the pipeline
    task; an `Idempotency-Key` short-circuits to the existing session on retry instead
    of creating a duplicate."""
    principal.require_entity(body.entity_id)
    tenant = get_settings().tenant_id
    sid = dal.guid()
    with db_session() as sess:
        if idempotency_key:
            existing_id, conflict = dal.reserve_idempotency_key_or_get_existing(
                sess, str(body.entity_id), idempotency_key, str(body.asset_id))
            if conflict:
                raise IdempotencyKeyConflict(existing_id)
            if existing_id:
                return JSONResponse(status_code=200, content={"session_id": existing_id})

        dal.assert_capacity_available(sess)  # 503 before the more expensive gather_asset_details

        ctx = gather_asset_details(sess, asset_id=body.asset_id, entity_id=body.entity_id,
                              sector_id=body.sector_id, user_id=body.user_id)
        dal.create_session(sess, {
            "SessionID": sid, "TenantID": tenant, "EntityID": str(body.entity_id), "UserID": str(body.user_id),
            "AssetName": ctx["asset"]["name"], "AssetExternalID": str(body.asset_id),
            "SessionStatus": SessionStatus.active, "CurrentStage": WorkflowStage.PROFILE,
            "StageStatus": StageStatus.IDLE, "Mode": SessionMode.AUTO, "CurrentSubsystemIndex": 0,
            "SubsystemsJSON": ctx["subsystems_json"], "SectorIDsJSON": json.dumps(ctx["sector_ids"]),
            "CreatedAt": now(), "UpdatedAt": now(),
            "IdempotencyKey": idempotency_key,
        })
        set_up_progress_tracking(sess, sid, tenant, str(body.entity_id), ctx["subsystems"])
        dal.append_audit(sess, AuditID=dal.guid(), SessionID=sid, TenantID=tenant, EntityID=str(body.entity_id),
                         EventType=AuditEventType.session_started, ActorUserID=body.user_id)
    enqueue_pipeline(sid)
    return CreateSessionResponse(session_id=sid)


@router.get("/sessions/{session_id}", response_model=SessionBoard)
def get_session(session_id: str, principal: Principal = Depends(get_principal)) -> SessionBoard:
    """Status-board poll endpoint (§6.1) — same rollup logic the SSE reconnect uses,
    so polling and streaming clients never disagree on subsystem state."""
    with db_session() as sess:
        session = get_authorized_session(sess, session_id, principal)
        return SessionBoard.model_validate(build_board(sess, session))


@router.get("/sessions/{session_id}/results", response_model=SessionResults)
def get_results(session_id: str, principal: Principal = Depends(get_principal)) -> SessionResults:
    """Returns the current profiles/threats/scenarios for a session, filtered to the
    non-superseded rows a regenerate cycle leaves behind. REVIEW-ONLY surface (SDD §9):
    includes unaccepted/rejected rows for the human reviewer — downstream consumers
    must use `GET /v1/assets/{asset_id}/accepted-scenarios` instead ([R13])."""
    with db_session() as sess:
        session = get_authorized_session(sess, session_id, principal)
        sid = session["SessionID"]

        def get_current_rows(table, cols):
            """Selects the given columns for this session, excluding rows a prior
            regeneration superseded — the shared filter for all three result kinds below."""
            return [dict(r) for r in sess.execute(
                select(*cols).where(table.c.SessionID == sid, table.c.Superseded == 0)
            ).mappings()]

        profiles = get_current_rows(m.Subsystem_Profile,
                           [m.Subsystem_Profile.c.SubsystemID, m.Subsystem_Profile.c.ProfileJSON,
                            m.Subsystem_Profile.c.Accepted])
        threats = get_current_rows(m.Identified_Threat,
                          [m.Identified_Threat.c.ThreatID, m.Identified_Threat.c.SubsystemID,
                           m.Identified_Threat.c.ThreatType, m.Identified_Threat.c.ThreatName,
                           m.Identified_Threat.c.GroundingStatus, m.Identified_Threat.c.ThreatCatalogueID])
        scenarios = get_current_rows(m.Threat_Scenario_Output,
                            [m.Threat_Scenario_Output.c.OutputID, m.Threat_Scenario_Output.c.SubsystemID,
                             m.Threat_Scenario_Output.c.ScenarioJSON, m.Threat_Scenario_Output.c.Accepted])

        return SessionResults(
            session_id=sid,
            profiles=[ProfileResult(supporting_system_id=p["SubsystemID"],
                                    profile=json.loads(p["ProfileJSON"]),
                                    accepted=bool(p["Accepted"])) for p in profiles],
            threats=[ThreatResult(threat_id=t["ThreatID"], supporting_system_id=t["SubsystemID"],
                                  threat_type=t["ThreatType"], threat_name=t["ThreatName"],
                                  grounding_status=t["GroundingStatus"],
                                  threat_catalogue_id=t["ThreatCatalogueID"]) for t in threats],
            scenarios=[ScenarioResult(output_id=s["OutputID"], supporting_system_id=s["SubsystemID"],
                                      scenario=json.loads(s["ScenarioJSON"]) if s["ScenarioJSON"] else None,
                                      accepted=bool(s["Accepted"])) for s in scenarios],
        )


@router.post("/sessions/{session_id}/accept", response_model=AcceptResponse)
def post_accept(session_id: str, body: AcceptBody, principal: Principal = Depends(get_principal)) -> AcceptResponse:
    """Accepts all or a subset of scenarios and finalizes the session; the actual
    validation and state transition live in `accept_session`, this is just the authz +
    HTTP wrapper."""
    with db_session() as sess:
        session = get_authorized_session(sess, session_id, principal)
        accept_session(sess, session_id, session["EntityID"], principal.user_id, subset=body.subset)
    return AcceptResponse(session_id=session_id, status=str(SessionStatus.completed))


def enqueue_regeneration(session_id: str, subsystem_id: int, granularity: RegenGranularity,
                         target_ids: list[str] | list[int] | None, epoch: int, user_note: str | None) -> None:
    """Indirection so tests can run the cascade synchronously instead of via a broker."""
    regenerate_task.delay(session_id, subsystem_id, str(granularity), target_ids, epoch, user_note)


def _do_regenerate(session_id: str, principal: Principal, subsystem_id: int, granularity: RegenGranularity,
                   target_ids: list[str] | list[int] | None, user_note: str | None) -> RegenerateResponse:
    """Shared body for the `/regenerate/*` route (plan item 0/10): validates the
    target(s) and reserves the epoch under a session-level CAS ([R5]), then hands off to
    the async cascade; must run at REVIEW/AWAITING_DECISION and loses the race cleanly
    (RegenerateConflict) to a concurrent accept or regen."""
    with db_session() as sess:
        session = get_authorized_session(sess, session_id, principal)
        if session["CurrentStage"] != WorkflowStage.REVIEW or session["StageStatus"] != StageStatus.AWAITING_DECISION:
            raise RegenerateConflict(
                f"session not at REVIEW (stage={session['CurrentStage']}, status={session['StageStatus']})")

        subsystems = json.loads(session["SubsystemsJSON"])
        if not any(s["id"] == subsystem_id for s in subsystems):
            raise dal.NotFoundError(f"subsystem {subsystem_id} not in session {session_id}")

        # Fast, read-only, BATCHED check (plan item 2) — the same validation cascade.py
        # re-runs under the subsystem's _LOCK before it mutates anything (closes the gap
        # between them). Fails atomically on any missing/invalid id.
        cascade.get_threat_id_to_redo(sess, session_id, subsystem_id, granularity, target_ids)

        # Best-effort friendly pre-check (NOT the enforcement point — the task's own
        # acquire_lock CAS is): a currently-held lock means a regen/accept is in flight.
        lock_status = sess.execute(
            select(m.Subsystem_Stage_State.c.Status).where(
                m.Subsystem_Stage_State.c.SessionID == session_id,
                m.Subsystem_Stage_State.c.SubsystemID == subsystem_id,
                m.Subsystem_Stage_State.c.Level == SubsystemLevel.LOCK,
            )
        ).scalar()
        if lock_status == StageStatus.RUNNING:
            raise RegenerateConflict(f"subsystem {subsystem_id} is locked (regeneration/accept in progress)")

        # Session-level CAS: leave REVIEW so accept is blocked session-wide for the
        # duration of the regen (mutual exclusion, [R5]) — the real per-subsystem
        # mutex is the task's own acquire_lock; this is the session-wide half of it.
        res = sess.execute(
            update(m.Scenario_Session)
            .where(m.Scenario_Session.c.SessionID == session_id,
                  m.Scenario_Session.c.SessionStatus == SessionStatus.active,
                  m.Scenario_Session.c.CurrentStage == WorkflowStage.REVIEW)
            .values(CurrentStage=WorkflowStage.SCENARIO_GENERATION, StageStatus=StageStatus.RUNNING, UpdatedAt=now())
        )
        if res.rowcount != 1:
            raise RegenerateConflict("another regeneration/accept won the race")

        # Reserve the epoch NOW, inside this SAME CAS-protected transaction — exactly
        # once per logical request. A later Celery redelivery of the enqueued task
        # reuses this SAME epoch, so claim_stage's CAS (keyed on epoch) makes the
        # redelivery a true no-op once a level is already terminal — the same
        # idempotency guarantee the initial pipeline gets from its fixed _EPOCH.
        # Minting a fresh epoch inside the (possibly-redelivered) task itself would
        # defeat that guarantee, since every redelivery would compute a NEW epoch.
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


@router.post("/sessions/{session_id}/cancel", response_model=CancelResponse)
def post_cancel(session_id: str, principal: Principal = Depends(get_principal)) -> CancelResponse:
    """Marks the session cancelled and audit-logs the actor; in-flight pipeline/regen
    tasks observe the status change on their own next CAS rather than being interrupted."""
    with db_session() as sess:
        session = get_authorized_session(sess, session_id, principal)
        dal.cancel_session(sess, session_id)
        dal.append_audit(sess, AuditID=dal.guid(), SessionID=session_id, TenantID=session["TenantID"],
                         EntityID=session["EntityID"], EventType=AuditEventType.session_cancelled,
                         ActorUserID=principal.user_id)
    return CancelResponse(session_id=session_id, status=str(SessionStatus.cancelled))


@router.get("/sessions/{session_id}/events")
async def session_events(session_id: str, principal: Principal = Depends(get_principal)):
    """SSE stream (§9.1): sends the current board as a `reconcile` event before
    subscribing to live deltas, so a client that (re)connects mid-session never has to
    guess what it missed ([R4])."""
    from sse_starlette.event import ServerSentEvent
    from sse_starlette.sse import EventSourceResponse

    from app.sse import bus

    with db_session() as sess:
        session = get_authorized_session(sess, session_id, principal)
        board = build_board(sess, session)

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
        # SDD §9.1 requires `heartbeat` as a real, client-visible SSE event (so a
        # client can key liveness/reconnect logic off it, not just proxies) — NOT
        # sse-starlette's default raw `: ping` comment, which EventSource ignores
        # silently. Reusing `ping_message_factory` here means the library's own
        # periodic-timer machinery emits our documented event shape natively; no
        # custom keep-alive loop is written.
        return ServerSentEvent(
            data=json.dumps({"type": str(SSEEventType.heartbeat), "session_id": session_id, "ts": now().isoformat()}),
            event=str(SSEEventType.heartbeat),
        )

    return EventSourceResponse(stream_events(), ping=get_settings().sse_ping_seconds, ping_message_factory=_heartbeat)


# --- [R13] downstream consumer contract (SDD §9) ---
@router.get("/assets/{asset_id}/accepted-scenarios", response_model=AcceptedScenariosResponse)
def get_accepted_scenarios(asset_id: int, entity: str,
                           principal: Principal = Depends(get_principal)) -> AcceptedScenariosResponse:
    """Downstream consumer contract: the asset's CURRENT accepted
    scenarios — `Accepted=1 AND Superseded=0` rows from the LATEST completed session
    only (older completed sessions' rows are never cross-session superseded, so "all
    history" would mix stale generations into the current set; one current truth per
    asset mirrors the M4 one-active-session model — `session_id`/`completed_at` let a
    consumer detect set changes). Entity-scoped fail-closed : the caller must be
    authorized for `entity` AND the asset must belong to it — a mismatch is 403 without
    revealing whether the asset exists. No completed session yet → 200 + empty list.
    Read-audit is an open policy decision — tracked in the Gap Analysis,
    deliberately not implemented here."""
    with db_session() as sess:
        principal.require_entity(entity)                       # [R2] caller ↔ entity
        check_asset_belongs_to_entity(sess, asset_id, entity)   # [R2] entity ↔ asset binding
        session = dal.latest_completed_session(sess, entity, str(asset_id))
        rows = dal.accepted_scenarios(sess, session["SessionID"]) if session else []
        return AcceptedScenariosResponse(
            asset_id=asset_id, entity_id=entity,
            session_id=session["SessionID"] if session else None,
            completed_at=session["CompletedAt"] if session else None,
            scenarios=[AcceptedScenario(
                output_id=r["OutputID"], supporting_system_id=r["SubsystemID"],
                threat_type_id=r["ThreatTypeID"], threat_catalogue_id=r["ThreatCatalogueID"],
                # library-grounded terminology wins, raw AI text as fallback — the same
                # precedence the scenario prompts use (tasks._write_one_scenario)
                threat_type=r["LibraryThreatType"] or r["ThreatType"],
                threat_name=r["LibraryThreatName"] or r["ThreatName"],
                scenario=json.loads(r["ScenarioJSON"]) if r["ScenarioJSON"] else None,
            ) for r in rows],
        )
