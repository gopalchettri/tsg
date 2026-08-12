"""Session API — create / status board / results / accept / cancel / SSE.

Object-level authz: every route resolves the session's EntityID and checks
it is in the caller's authorized set — a valid token is not enough.
"""
from __future__ import annotations

import asyncio
import io
import json
from functools import lru_cache
from typing import Literal, NoReturn

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Query, Response
from fastapi.responses import JSONResponse
from sqlalchemy import exists, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from app.api.deps import Principal, get_principal
from app.api.results_excel import build_results_workbook
from app.api.schemas import (
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
    MappedControl,
    NextSetResultEvent,
    RegenerateResponse,
    RegenerateScenariosBody,
    RegenResultEvent,
    ScenarioListItem,
    ScenarioResult,
    SessionBoard,
    SessionEnteredReviewEvent,
    SessionResults,
    StageCompletedEvent,
    StageStartedEvent,
    SubsystemStartedEvent,
    ThreatResult,
    TreatmentPlanResultEvent,
)
from app.core import tuning
from app.core.config import get_settings
from app.core.enums import (
    AuditEventType,
    RegenGranularity,
    SessionMode,
    SessionStatus,
    SSEEventType,
    StageStatus,
    SubsystemLevel,
    SubsystemProgress,
    WorkflowStage,
)
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.db.dal import EntityForbidden, IdempotencyKeyConflict, RegenerateConflict, now
from app.db.engine import db_session
from app.pipeline import cascade, tasks
from app.pipeline.accept import accept_session, review_gate_reason
from app.pipeline.celery_app import next_set_task, regenerate_task, run_pipeline_task
from app.pipeline.context import gather_asset_details
from app.pipeline.grounding import stored_actors
from app.pipeline.tasks import ASSET_UNIT_ID, set_up_progress_tracking
from app.sse import bus

log = get_logger(__name__)

router = APIRouter(prefix="/v1", tags=["Sessions"])

# Cross-session scenario reads get their own Swagger group. A SEPARATE router, not per-route
# tags: FastAPI APPENDS route tags to router tags, which would list these under BOTH groups.
scenarios_router = APIRouter(prefix="/v1", tags=["Scenarios"])

#: Hard cap on ancestry-walk hops in GET /results. Each hop is one sequential round trip
#: (it needs the previous hop's ids), so an unbounded walk lets one heavily-regenerated
#: scenario add round trips to a polled endpoint. A hop is one REGENERATION of a single
#: scenario, so 25 is far past any real review workflow; beyond it the chain truncates and
#: logs rather than growing without limit.
_MAX_ANCESTRY_HOPS = 100


def enqueue_pipeline(session_id: str) -> None:
    """Indirection so tests can run the pipeline synchronously instead of via a broker."""
    run_pipeline_task.delay(session_id)


# --- status board ---
def get_overall_status(threats: str, scenarios: str, session_status: str) -> SubsystemProgress:
    """Rolls the threat stage, scenario stage and session status into one display status.
    Checks run in priority order — first match wins."""
    vals = (threats, scenarios)
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
    """The GET /sessions/{id} payload and the SSE reconnect-reconcile source.

    One flat progress object, not a list: ASSET_UNIT_ID is the only subsystem id the
    pipeline ever writes."""
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
    for row in dal.stage_rows(sess, scenario_session["SessionID"]):
        level = str(row["Level"]).lower()
        stages[level] = str(row["Status"])
        if row["ErrorMessage"]:
            # Client-safe failure reason, deliberately kept on an AWAITING_DECISION row the
            # salvage path revived (dal.revive_errored_scenarios_to_review): it is the marker
            # that this review set may be PARTIAL, so a reviewer can tell it from a complete one.
            error_messages[level] = str(row["ErrorMessage"])
    t = stages.get("threats", StageStatus.IDLE)
    sc = stages.get("scenarios", StageStatus.IDLE)
    return {
        "session_id": scenario_session["SessionID"], "entity_id": scenario_session["EntityID"],
        "asset_id": int(scenario_session["AssetID"]), "asset_name": scenario_session["AssetName"],
        "user_id": scenario_session["UserID"],
        "session_status": scenario_session["SessionStatus"],
        "current_stage": scenario_session["CurrentStage"], "stage_status": scenario_session["StageStatus"],
        "progress": {
            "threats": t, "scenarios": sc,
            "overall": str(get_overall_status(t, sc, scenario_session["SessionStatus"])),
            "error_message": error_messages,
            # The DURABLE answer to "what did my last 'generate next set' click do?". The SSE
            # next_set_result event says the same thing, but publishing is best-effort with no
            # replay (app/sse/bus.py), so a polling client — or one whose stream dropped — has
            # only this. Because build_board also feeds the SSE reconnect-reconcile snapshot, a
            # client that missed the event learns the outcome the moment it reconnects.
            "last_next_set": dal.latest_next_set_outcome(sess, scenario_session["SessionID"],
                                                        ASSET_UNIT_ID),
            # Plan item 3: same durable-mirror rationale as last_next_set above, for
            # /regenerate/scenarios instead of /scenarios/next-set — built from the
            # regeneration_completed audit row (app/pipeline/cascade.py::_stage_regen_audit).
            "last_regen": dal.latest_regen_outcome(sess, scenario_session["SessionID"],
                                                    ASSET_UNIT_ID),
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
        "TuningJSON": json.dumps(tuning_snapshot),
        "CreatedAt": now(), "UpdatedAt": now(),
        "IdempotencyKey": idempotency_key,
    }


# --- endpoints ---
@router.post("/sessions", status_code=202, response_model=CreateSessionResponse)
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
        enqueue_pipeline(sid)
    except Exception as exc:
        # Pattern A (see app/api/treatment.py's request_treatment_plan): the row is already
        # committed and holding the one-active-session-per-asset slot, so a bare re-raise would
        # leave it stuck there — unreachable by the client (no session_id in a raw 500) — until
        # the reaper's stale-grace window elapses. Cancel it now instead; releases the slot
        # immediately and gives the client a clear signal to retry.
        with db_session() as sess:
            dal.cancel_session(sess, sid)
        log.error("session.enqueue_failed", session_id=sid, error=repr(exc))
        raise HTTPException(
            status_code=503,
            detail=f"session {sid} could not be queued for processing and was cancelled — retry",
        ) from exc
    return CreateSessionResponse(session_id=sid, user_id=principal.user_id)


@router.get("/sessions/{session_id}", response_model=SessionBoard)
def get_session(session_id: str, principal: Principal = Depends(get_principal)) -> SessionBoard:
    """Status-board poll endpoint — same rollup logic the SSE reconnect uses,
    so polling and streaming clients never disagree on subsystem state."""
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)
        return SessionBoard.model_validate(build_board(sess, scenario_session))


def _scenario_select():
    """Scenario columns LEFT-joined via Scoped_Threat -> Identified_Threat (the chain
    dal.accepted_scenarios uses) so every row carries the threat_id it was generated from — plus
    the threat's own category/type/name/actors, so _scenario_with_controls can merge them into
    the returned scenario body without a second query. ControlsMappedAt is NULL until Step-4 has
    been ATTEMPTED, which is what separates "still generating" from "nothing in the library
    matched"."""
    out, st, it = m.Threat_Scenario_Output, m.Scoped_Threat, m.Identified_Threat
    return select(
        out.OutputID, out.ScenarioJSON, out.Accepted, out.ValidationJSON, out.GenerationEpoch,
        out.ScenarioNumber, out.ReplacesOutputID, out.ControlsMappedAt, it.ThreatID,
        it.ThreatCategory, it.ThreatType, it.ThreatName, it.ThreatActorsJSON,
    ).select_from(out.__table__.outerjoin(st, out.ScopedThreatID == st.ScopedThreatID)
                .outerjoin(it, st.ThreatID == it.ThreatID))


def _ancestry(sess: Session, sid: str, scenarios: list[dict]) -> dict[str, list[str]]:
    """OutputID -> the ids it replaced, newest first. Walks ReplacesOutputID in batched
    clustered-PK seeks: one query per chain DEPTH, and none at all when nothing was regenerated.
    Never `WHERE Superseded = 1` — no index serves that (both are filtered Superseded = 0), so it
    would degrade to a full scan on an endpoint clients poll.

    Called ONLY for ?include_replaced=true. The chains exist to fetch and order the retired
    bodies; nothing on the default read path consumes one, so a poll pays nothing for this.

    `SessionID == sid` is a TENANT BOUNDARY, not an optimisation. The caller was authorized for
    ONE session; ReplacesOutputID is unvalidated data in a multi-tenant table with no foreign keys
    (the cycle guard below exists for the same reason), so an unscoped walk would hand another
    entity's scenario to this caller. Scoping here is sufficient for everything downstream,
    because the returned chains are the sole source of the ids /results goes on to fetch."""
    out = m.Threat_Scenario_Output
    predecessor: dict[str, str | None] = {}
    frontier = {str(s["ReplacesOutputID"]) for s in scenarios if s["ReplacesOutputID"]}
    hops = 0
    while frontier and hops < _MAX_ANCESTRY_HOPS:
        hops += 1
        rows = sess.execute(
            select(out.OutputID, out.ReplacesOutputID)
            .where(out.OutputID.in_(frontier), out.SessionID == sid)
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

    return {s["OutputID"]: _from(s["ReplacesOutputID"], s["OutputID"]) for s in scenarios}


@router.get("/sessions/{session_id}/results", response_model=SessionResults)
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
                select(*cols).where(table.SessionID == sid, table.Superseded == 0, *extra)
            ).mappings()]

        st, out, it = m.Scoped_Threat, m.Threat_Scenario_Output, m.Identified_Threat
        threats = get_current_rows(it,
                        [it.ThreatID, it.ThreatType, it.ThreatName,
                        it.GroundingStatus, it.ThreatCatalogueID, it.ThreatActorsJSON,
                        # read at source — deliberately NOT denormalised onto Scoped_Threat,
                        # so the value can never drift from the row that owns it
                        it.GroundingScore],
                        # only threats with an ACTIVE scenario row — including a FAILURE CARD,
                        # deliberately (no Status filter here): the card is returned in
                        # scenarios[] with scenario:null, so its threat must stay in threats[]
                        # or the card would reference a threat this same response says does not
                        # exist. This comment used to claim failed threats were excluded — the
                        # code never did that, and the claim was the drift, not the behaviour.
                        exists().where(st.ThreatID == it.ThreatID,
                                    st.SessionID == sid, st.Superseded == 0,
                                    out.ScopedThreatID == st.ScopedThreatID,
                                    out.SessionID == sid, out.Superseded == 0))
        # One grouped round trip — never a join, which would fan out per variant row.
        scores = dal.threat_scores(sess, sid)
        scenarios = [dict(r) for r in sess.execute(
            _scenario_select().where(out.SessionID == sid, out.Superseded == 0)
        ).mappings()]
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
                    _scenario_select().where(out.OutputID.in_(wanted), out.SessionID == sid)
                ).mappings()]
        controls = _controls_by_output(sess, [s["OutputID"] for s in scenarios]
                                            + [r["OutputID"] for r in replaced])
        by_id = {r["OutputID"]: r for r in replaced}

        def _nested(chain: list[str]) -> list[ScenarioResult]:
            """The card's own history, oldest-to-newest order preserved from the chain. Built
            without a `replaced` argument, which is what keeps nesting exactly one level deep.
            A chain id with no row (hard-deleted, or past _MAX_ANCESTRY_HOPS) is skipped rather
            than emitted as an entry with no body — the history truncates, it never lies."""
            return [_scenario_result(by_id[oid], controls.get(oid))
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
            threats=[ThreatResult(threat_id=t["ThreatID"],
                                threat_type=t["ThreatType"], threat_name=t["ThreatName"],
                                grounding_status=t["GroundingStatus"],
                                threat_catalogue_id=t["ThreatCatalogueID"],
                                threat_actors=stored_actors(t["ThreatActorsJSON"]),
                                grounding_score=t["GroundingScore"],
                                score=scores.get(t["ThreatID"], {}).get("score"),
                                scope_rank=scores.get(t["ThreatID"], {}).get("scope_rank"))
                    for t in threats],
            scenarios=[_scenario_result(s, controls.get(s["OutputID"]),
                                        _nested(chains.get(s["OutputID"]) or []))
                    for s in scenarios],
        )


@router.get("/sessions/{session_id}/results.xlsx")
def get_results_excel(
    session_id: str,
    include_replaced: bool = Query(
        default=False,
        description="Same as /results — also include the older scenario versions that "
                    "regeneration replaced, as extra rows with is_replaced=true.",
    ),
    principal: Principal = Depends(get_principal),
) -> Response:
    """The same data as /results, as a single-sheet Excel workbook — one row per scenario.

    Calls get_results() directly rather than re-querying: the JSON and Excel outputs can never
    disagree on the underlying data, only presentation differs here. Authorization and
    404-before-403 come along for free from that same call."""
    results = get_results(session_id, include_replaced, principal)
    workbook = build_results_workbook(results)
    buffer = io.BytesIO()
    workbook.save(buffer)
    return Response(
        content=buffer.getvalue(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="session_{session_id}_results.xlsx"'},
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


def _safe_scenario_json(scenario_json: str | None) -> dict | None:
    """Parses a Threat_Scenario_Output row's ScenarioJSON. One corrupted row must never 500 the
    whole results view and hide every OTHER threat/scenario in the session."""
    if not scenario_json:
        return None
    try:
        parsed = json.loads(scenario_json)
    except (json.JSONDecodeError, TypeError):
        return None
    # Valid JSON that isn't an object ("[1,2]", "null", a bare string) parses fine and then dies
    # in response validation as a 500 — the exact whole-view failure this function prevents.
    return parsed if isinstance(parsed, dict) else None


def _controls_by_output(sess: Session, output_ids: list[str]) -> dict[str, list[MappedControl]]:
    """Step-4 mapped controls for a page of scenarios, grouped per OutputID, best rank first.
    The Control_Library join filters to active rows — a control deactivated AFTER mapping must
    not keep surfacing. Standards ride along as names (Map → Control_Standard, active only)."""
    if not output_ids:
        return {}
    cmap, lib = m.Threat_Scenario_Control_Map, m.Control_Library
    try:
        return _query_controls(sess, output_ids, cmap, lib)
    except Exception:
        # hasn't run yet must degrade to controls=[] with a loud log, not 500 the core reads.
        sess.rollback()  # leave the session clean for the caller's remaining work/commit
        log.warning("controls.read_failed", exc_info=True)
        return {}


def _query_controls(sess: Session, output_ids: list[str], cmap, lib) -> dict[str, list[MappedControl]]:
    rows = sess.execute(
        select(cmap.OutputID, cmap.MapRank, cmap.Score, cmap.SuggestedControl,
            lib.ControlLibraryID, lib.ControlCode, lib.Domain, lib.ControlName)
        .join(lib, lib.ControlLibraryID == cmap.ControlLibraryID)
        .where(cmap.OutputID.in_(output_ids),
            lib.IsActive == True, lib.IsDeleted == False)
        .order_by(cmap.OutputID, cmap.MapRank)
    ).mappings().all()
    std_names: dict[int, list[str]] = {}
    if rows:
        smap, std = m.Control_Library_Standard_Map, m.Control_Standard
        for cid, name in sess.execute(
            select(smap.ControlLibraryID, std.StandardName)
            .join(std, std.StandardID == smap.StandardID)
            .where(smap.ControlLibraryID.in_({r["ControlLibraryID"] for r in rows}),
                std.IsActive == True, std.IsDeleted == False)
            .order_by(std.StandardName)
        ):
            std_names.setdefault(cid, []).append(name)
    out: dict[str, list[MappedControl]] = {}
    for r in rows:
        out.setdefault(r["OutputID"], []).append(MappedControl(
            control_library_id=r["ControlLibraryID"], control_code=r["ControlCode"],
            domain=r["Domain"], control_name=r["ControlName"], rank=r["MapRank"],
            score=r["Score"], suggested_control=r["SuggestedControl"],
            standards=std_names.get(r["ControlLibraryID"], [])))
    return out


def _scenario_with_controls(scenario_json: str | None, controls: list[MappedControl],
                        controls_mapped: bool = True, threat_row: dict | None = None) -> dict | None:
    """Projects one ScenarioJSON row for the API: `controls` becomes the Step-4 grounded
    Control_Library matches, and the LLM's raw `{name, why}` suggestions they replace move to
    `suggested_controls`. Presentation-layer merge only — Threat_Scenario_Control_Map stays the
    single source of truth and ScenarioJSON is never rewritten.

    Both lists are reported: a suggestion that no map row names grounded to nothing — a library
    gap, visible nowhere else. Overwriting the raw list outright also blanked every scenario in
    the window between write and Step-4, making an in-progress read look like the model had
    proposed nothing. `why` is never persisted, so the rationale is a read-time join by name.

    `controls_mapped` gates `unmatched_suggestions`: mid-stage, every suggestion would otherwise
    look unmatched before mapping had run. Defaults True for the accepted-scenarios caller,
    where mapping is necessarily complete.

    `threat_row` (a _scenario_select() row) carries the threat's own category/type/name/actors —
    NOT part of the LLM's scenario JSON — merged in here so a caller only has one dict to read.
    None for callers with no threat context (a scenario built for logging/preview, say)."""
    scenario = _safe_scenario_json(scenario_json)
    if scenario is None:
        return None
    if threat_row is not None:
        scenario["threat_category"] = threat_row.get("ThreatCategory")
        scenario["threat_type"] = threat_row.get("ThreatType")
        scenario["threat_name"] = threat_row.get("ThreatName")
        scenario["threat_actors"] = stored_actors(threat_row.get("ThreatActorsJSON"))
    # Read the raw suggestions BEFORE overwriting the key they live under.
    raw = [c for c in (scenario.get("controls") or [])
        if isinstance(c, dict) and str(c.get("name") or "").strip()]
    # keyed on the same 500-char truncation the map row stored, so a long name still matches
    whys = {c["name"][:500]: c.get("why") for c in raw}
    scenario["suggested_controls"] = [{"name": c["name"], "why": c.get("why")} for c in raw]
    scenario["controls"] = [
        c.model_copy(update={"suggested_why": whys.get(c.suggested_control)}).model_dump()
        for c in controls
    ]
    if controls_mapped:
        matched = {c.suggested_control for c in controls if c.suggested_control}
        scenario["unmatched_suggestions"] = [
            {"name": c["name"], "why": c.get("why")} for c in raw if c["name"][:500] not in matched
        ]
    else:
        scenario["unmatched_suggestions"] = None
    return scenario


def _scenario_result(row: dict, controls: list[MappedControl] | None = None,
                    replaced: list[ScenarioResult] | None = None) -> ScenarioResult:
    controls_mapped = row["ControlsMappedAt"] is not None
    checked, flagged, categories = _moderation_summary(row["ValidationJSON"])
    validation_status, validation_errors = _validation_summary(row["ValidationJSON"])
    return ScenarioResult(output_id=row["OutputID"], threat_id=row["ThreatID"],
                        scenario=_scenario_with_controls(row["ScenarioJSON"], controls or [],
                                                        controls_mapped, row),
                        accepted=bool(row["Accepted"]),
                        moderation_checked=checked, moderation_flagged=flagged, moderation_categories=categories,
                        validation_status=validation_status, validation_errors=validation_errors,
                        generation_epoch=row["GenerationEpoch"],
                        scenario_number=row["ScenarioNumber"],
                        controls_mapped=controls_mapped,
                        replaced_scenarios=replaced or [])


def _subset_from_accept_body(body: AcceptBody) -> list[str] | None:
    """Translate the wire-level mode/output_ids pair into accept_session's existing
    `subset` contract: None = accept all, [] = accept none, a populated list = that subset."""
    if body.mode == "all":
        return None
    if body.mode == "none":
        return []
    return body.output_ids  # mode == "subset"; validator guarantees a non-empty list


# `responses` is not decoration: these 409 bodies are the ONLY place ReviewGateReason appears, and
# FastAPI emits a schema only for models reachable from a route. Without this declaration the enum
# never reaches /openapi.json, and a UI cannot generate the codes that tell it whether a blocked
# action is a dead end (session_completed/cancelled) or a spinner (generation_in_progress).
_CONFLICT_RESPONSES: dict[int | str, dict] = {409: {"model": ErrorResponse, "description": "Conflict — see details.reason."}}


@router.post("/sessions/{session_id}/accept", response_model=AcceptResponse, responses=_CONFLICT_RESPONSES)
def post_accept(session_id: str, body: AcceptBody, principal: Principal = Depends(get_principal)) -> AcceptResponse:
    """Accepts all or a subset of scenarios and finalizes the session; validation and the state
    transition live in `accept_session`, this is the authz + HTTP wrapper."""
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)
        matched = accept_session(sess, session_id, scenario_session["EntityID"], principal.user_id,
                                subset=_subset_from_accept_body(body))
    return AcceptResponse(session_id=session_id, user_id=scenario_session["UserID"],
                        status=str(SessionStatus.completed), accepted_count=matched)


def enqueue_regeneration(session_id: str, subsystem_id: int, granularity: RegenGranularity,
                        target_ids: list[str] | list[int] | None, epoch: int, user_note: str | None) -> None:
    """Indirection so tests can run the cascade synchronously instead of via a broker."""
    regenerate_task.delay(session_id, subsystem_id, str(granularity), target_ids, epoch, user_note)


def _assert_regen_eligible(scenario_session: dict) -> None:
    """Regeneration is only allowed while the session is parked at REVIEW waiting on a human decision."""
    gate = review_gate_reason(scenario_session)
    if gate is not None:
        reason, message = gate
        raise RegenerateConflict(message, reason=reason)


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
                target_ids: list[str] | list[int] | None, user_note: str | None) -> RegenerateResponse:
    """Validates eligibility, guards against a concurrent regen/accept via a lock check plus a
    conditional UPDATE, resets the affected stage rows, hands off to the async regenerate task."""
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)
        _assert_regen_eligible(scenario_session)

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

    try:
        enqueue_regeneration(session_id, subsystem_id, granularity, target_ids, epoch, user_note)
    except Exception as exc:  # noqa: BLE001 — broker unreachable must not wedge SCENARIOS at IDLE
        _recover_from_enqueue_failure(session_id, subsystem_id, epoch, exc, "regen.enqueue_failed")
    # `epoch` goes back to the caller: a 202 only says "accepted", and this is the token that
    # lets a client tell ITS request's completion from a previous one's (see RegenerateResponse).
    return RegenerateResponse(session_id=session_id, user_id=scenario_session["UserID"],
                            status="regenerating", epoch=epoch)


@router.post("/sessions/{session_id}/regenerate/scenarios", status_code=202, response_model=RegenerateResponse,
            responses=_CONFLICT_RESPONSES)
def post_regenerate_scenarios(session_id: str, body: RegenerateScenariosBody,
                            principal: Principal = Depends(get_principal)) -> RegenerateResponse:
    """Rebuild one or more scenarios' narratives only — siblings untouched (scenarios 1, 2). Scoped
    to the session's asset (`session_id` in the URL is the sole identifier); `output_ids` alone
    picks which scenarios to redo."""
    return _do_regenerate(session_id, principal, ASSET_UNIT_ID, RegenGranularity.scenario,
                        body.output_ids, body.user_note)


def enqueue_next_set(session_id: str, subsystem_id: int, epoch: int, threats_epoch: int) -> None:
    """Indirection so tests can run the cascade synchronously instead of via a broker."""
    next_set_task.delay(session_id, subsystem_id, epoch, threats_epoch)


def _do_next_set(session_id: str, principal: Principal, subsystem_id: int) -> RegenerateResponse:
    """Add the next accumulating batch of unique scenarios for one subsystem. Same eligibility /
    lock / CAS guards as _do_regenerate, but takes no target ids: which threats to serve is
    decided server-side by cascade.run_next_set."""
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)
        _assert_regen_eligible(scenario_session)

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

        # Reserve the THREATS epoch here too — once — and thread it through so a redelivery of the
        # task re-uses it and run_next_set's idempotency guard can skip a second additive
        # find_threats. Do NOT reset THREATS here: an IDLE THREATS row makes
        # decide_session_outcome return None (wedge) if the task is slow or lost; run_next_set
        # resets it (guarded) only if it actually needs the additive find_threats.
        epoch = dal.next_epoch(sess, session_id, subsystem_id, cascade.NEXT_SET_LEVELS)
        dal.reset_stage_for_regen(sess, session_id, subsystem_id, cascade.NEXT_SET_LEVELS, epoch)
        threats_epoch = dal.next_epoch(sess, session_id, subsystem_id, (SubsystemLevel.THREATS,))

    try:
        enqueue_next_set(session_id, subsystem_id, epoch, threats_epoch)
    except Exception as exc:  # noqa: BLE001 — broker unreachable must not wedge SCENARIOS at IDLE
        _recover_from_enqueue_failure(session_id, subsystem_id, epoch, exc, "next_set.enqueue_failed")
    # The SCENARIOS epoch, not the THREATS one: it is the epoch run_next_set stamps on the
    # next_set_outcome audit row, so `last_next_set.epoch == this` is the client's exact
    # "my click landed" signal. Polling stage status instead cannot distinguish my click from
    # a concurrent one, which is how a mid-flight read looks finished.
    return RegenerateResponse(session_id=session_id, user_id=scenario_session["UserID"],
                            status="generating", epoch=epoch)


@router.post("/sessions/{session_id}/scenarios/next-set", status_code=202, response_model=RegenerateResponse,
            responses=_CONFLICT_RESPONSES)
def post_next_set_scenarios(session_id: str, principal: Principal = Depends(get_principal)) -> RegenerateResponse:
    """Generate the next set of scenarios — 5 more unique threat scenarios that accumulate onto the
    existing ones for the session's asset, never superseding a prior batch. No request body: the
    asset is fully identified by `session_id` in the URL (a session is always exactly one asset).
    Returns 202 with status "generating"; a round that finds nothing new is not an error (the
    reviewer can retry)."""
    return _do_next_set(session_id, principal, ASSET_UNIT_ID)


@router.post("/sessions/{session_id}/cancel", response_model=CancelResponse)
def post_cancel(session_id: str, principal: Principal = Depends(get_principal)) -> CancelResponse:
    """Marks the session cancelled and audit-logs the actor; in-flight pipeline/regen
    tasks observe the status change on their own next CAS rather than being interrupted."""
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)
        # CAS-fenced: False means the session was already terminal (completed/cancelled by a
        # concurrent writer) — a conflict, not a silent re-flip of an already-decided session.
        if not dal.cancel_session(sess, session_id):
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

    False means the caller must close the generator: either the session left `active` (item 1 —
    `load_session_board` returning None also counts, a hard-deleted row being the only way a
    valid session id stops resolving) or, when `verify_membership` is on, the (user, entity) pair
    no longer resolves (item 30). One function, one DB round trip per check — not two independent
    handlers racing their own queries."""
    with db_session() as sess:
        row = dal.load_session_board(sess, session_id)
        if row is None or str(row["SessionStatus"]) != str(SessionStatus.active):
            return False
        if verify_membership and not dal.user_has_entity(sess, principal.user_id, row["EntityID"]):
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
                    "LLM-capacity autoretry, cancel/review) — recover with "
                    "GET /v1/sessions/{session_id}/treatment-plans and keep a slow poll. "
                    "Full field-by-field shapes and recovery paths: "
                    "docs/SSE_SESSION_PROGRESS_CONTRACT_GUIDE.md.",
        "content": {"text/event-stream": {}},
    }
}


@router.get("/sessions/{session_id}/events", responses=_EVENT_STREAM_RESPONSES)
async def session_events(session_id: str, principal: Principal = Depends(get_principal)):
    """SSE stream (§9.1): sends the current board as a `reconcile` event before
    subscribing to live deltas, so a client that (re)connects mid-session never has to
    guess what it missed ([R4])."""
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


@router.get("/sessions/{session_id}/accepted-scenarios", response_model=AcceptedScenariosResponse)
def get_accepted_scenarios(session_id: str, principal: Principal = Depends(get_principal)) -> AcceptedScenariosResponse:
    """Returns the accepted, non-superseded scenarios for this session."""
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)
        rows = dal.accepted_scenarios(sess, scenario_session["SessionID"])
        controls = _controls_by_output(sess, [r["OutputID"] for r in rows])
        return AcceptedScenariosResponse(
            asset_id=int(scenario_session["AssetID"]), entity_id=scenario_session["EntityID"],
            user_id=scenario_session["UserID"],
            session_id=scenario_session["SessionID"],
            completed_at=scenario_session["CompletedAt"],
            scenarios=[AcceptedScenario(
                output_id=r["OutputID"], supporting_system_id=r["SubsystemID"],
                threat_type_id=r["ThreatTypeID"], threat_catalogue_id=r["ThreatCatalogueID"],
                # prefer the curated catalogue name/type; fall back to the freeform one if not linked to the library
                threat_type=r["LibraryThreatType"] or r["ThreatType"],
                threat_name=r["LibraryThreatName"] or r["ThreatName"],
                # controls_mapped=True: an accepted scenario has necessarily passed Stage 2's tail
                # mapping step before the session could reach REVIEW/accept. threat_row reuses the
                # SAME library-preferred type/name computed above, so scenario.threat_type and the
                # sibling threat_type field can never disagree.
                scenario=_scenario_with_controls(
                    r["ScenarioJSON"], controls.get(r["OutputID"], []), True,
                    {"ThreatCategory": r["ThreatCategory"],
                    "ThreatType": r["LibraryThreatType"] or r["ThreatType"],
                    "ThreatName": r["LibraryThreatName"] or r["ThreatName"],
                    "ThreatActorsJSON": r["ThreatActorsJSON"]}),
                threat_actors=stored_actors(r["ThreatActorsJSON"]),
            ) for r in rows],
        )


# --- cross-session scenario reads (by user / by entity / by output id) ---

#: Paging + filter knobs shared by the two list routes below (same shape as library_crud's).
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


def _scenario_list_item(row: dict, controls: list[MappedControl]) -> ScenarioListItem:
    """One dal.scenario_rows/scenario_row row → response item. Same catalogue-name fallback
    and controls merge as get_accepted_scenarios above."""
    # Same library-preferred type/name as the sibling fields below, reused for the nested
    # threat_row so scenario.threat_type can never disagree with the top-level threat_type.
    threat_type = row["LibraryThreatType"] or row["ThreatType"]
    threat_name = row["LibraryThreatName"] or row["ThreatName"]
    return ScenarioListItem(
        output_id=row["OutputID"], supporting_system_id=row["SubsystemID"],
        threat_type_id=row["ThreatTypeID"], threat_catalogue_id=row["ThreatCatalogueID"],
        threat_type=threat_type, threat_name=threat_name,
        scenario=_scenario_with_controls(
            row["ScenarioJSON"], controls, row["ControlsMappedAt"] is not None,
            {"ThreatCategory": row["ThreatCategory"], "ThreatType": threat_type,
            "ThreatName": threat_name, "ThreatActorsJSON": row["ThreatActorsJSON"]}),
        session_id=row["SessionID"], entity_id=row["EntityID"], user_id=row["UserID"],
        session_status=row["SessionStatus"], scenario_number=row["ScenarioNumber"],
        accepted=bool(row["Accepted"]), superseded=bool(row["Superseded"]),
        created_at=row["CreatedAt"],
        # _scenario_read_select already carries ThreatActorsJSON — without this kwarg the list
        # routes would permanently return [] while /accepted-scenarios returns real actors.
        threat_actors=stored_actors(row["ThreatActorsJSON"]),
    )


def _list_scenarios(entity_ids: set[str], user_id: str | None, status: str | None,
                    include_superseded: bool, limit: int, offset: int) -> list[ScenarioListItem]:
    """Shared body of the two list routes: entity_ids must already be authorized."""
    with db_session() as sess:
        rows = dal.scenario_rows(sess, entity_ids=entity_ids, user_id=user_id, status=status,
                                include_superseded=include_superseded, limit=limit, offset=offset)
        controls = _controls_by_output(sess, [r["OutputID"] for r in rows])  # one batch, no N+1
        return [_scenario_list_item(r, controls.get(r["OutputID"], [])) for r in rows]


@scenarios_router.get("/users/{user_id}/scenarios", response_model=list[ScenarioListItem])
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


@scenarios_router.get("/entities/{entity_id}/scenarios", response_model=list[ScenarioListItem])
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


@scenarios_router.get("/sessions/{session_id}/scenarios/{output_id}", response_model=ScenarioListItem)
def get_scenario(
    session_id: str,
    output_id: str,
    user_id: str = Query(max_length=200, description="The session owner who created the scenario. "
                        "A mismatch 404s — filter semantics, no existence leak."),
    principal: Principal = Depends(get_principal),
) -> ScenarioListItem:
    """Fetches one scenario by id, whatever its flags — a direct output_id lookup is how a
    caller inspects superseded history or an error card (scenario is null on the latter).
    404 before 403, same as every session route."""
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)
        # user_id is a filter (like the list routes), so a mismatch is "no such resource
        # under this filter" — 404, not 403, or the response would leak that the id exists.
        if scenario_session["UserID"] != user_id:
            raise dal.NotFoundError(f"scenario {output_id} not found")
        row = dal.scenario_row(sess, scenario_session["SessionID"], output_id)
        if row is None:
            raise dal.NotFoundError(f"scenario {output_id} not found")
        controls = _controls_by_output(sess, [row["OutputID"]])
        return _scenario_list_item(dict(row), controls.get(row["OutputID"], []))
