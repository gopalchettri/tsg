"""Risk Treatment Plan routes — docs/RISK_TREATMENT_PLAN_SDD.md §5/§6.1.

Mounted by app/main.py ONLY when settings.risk_module_enabled (flag off → these paths 404 by
absence, zero handler code; the flag arms nothing else — no external tables are required).
Both routes are registered in app/api/route_audit.py::_ENTITY_SCOPED_ROUTES — registry entries
for an unmounted router are inert, but a mounted route missing from the registry fails boot.

POST takes the register's risk data IN the request body (TSG reads NO risk-module tables),
freezes it with TSG's own scenario/asset context into InputSnapshotJSON, inserts the RUNNING
plan row and enqueues; the GET on the same path is the poll endpoint (no separate job-status
route). The filtered unique index UX_TreatmentPlan_ActiveOutput — not any SELECT — is the
concurrent-POST arbiter.
"""
from __future__ import annotations

import io
import json
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.engine import RowMapping
from sqlalchemy.exc import IntegrityError

from app.api.deps import Principal, get_principal
from app.api.schemas import (
    ErrorResponse,
    TreatmentAuditEvent,
    TreatmentAuditTrail,
    TreatmentBoard,
    TreatmentBoardRow,
    TreatmentCancelResponse,
    TreatmentEntityAuditPage,
    TreatmentEvidence,
    TreatmentEvidenceAttempt,
    TreatmentPlanAccepted,
    TreatmentPlanBody,
    TreatmentPlanStatus,
    TreatmentRegisterPage,
    TreatmentRegisterRow,
    TreatmentReviewBody,
    TreatmentReviewResponse,
)
from app.api.sessions import get_authorized_session
from app.api.treatment_plan_excel import build_treatment_plans_workbook
from app.core.enums import (
    AuditEventType,
    RiskLevel,
    StageStatus,
    TreatmentGateReason,
    TreatmentOutcomeReason,
    TreatmentReviewStatus,
    TreatmentStrategy,
)
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.db.engine import db_session
from app.pipeline import treatment
from app.pipeline.celery_app import generate_treatment_plan_task
from app.pipeline.grounding import stored_actors
from app.pipeline.tasks import ASSET_UNIT_ID

log = get_logger(__name__)

router = APIRouter(prefix="/v1", tags=["Treatment Plans"])

# Same declaration idea as sessions._CONFLICT_RESPONSES: typing the 409 puts
# TreatmentGateReason into /openapi.json so the UI can generate the reason codes.
_CONFLICT_RESPONSES: dict[int | str, dict] = {
    409: {"model": ErrorResponse, "description": "Conflict — see details.reason."}}

_TIMED_OUT_MESSAGE = "generation timed out — request it again"

#: The poll GET serves these plan keys — the toolkit's output columns plus the title. Since the
#: AI's own schema was narrowed to exactly this set (prompts.treatment_prompt; see
#: docs/RISK_TREATMENT_PLAN_SDD.md §7.1/§7.3), PlanJSON no longer holds anything wider except
#: risk_identification_date — kept out of `plan` here because it's already surfaced as its own
#: top-level field on TreatmentPlanStatus, not to avoid duplicating it on the wire. This filter
#: now also doubles as defense-in-depth: if the model ever echoes a dropped field name back, it
#: is dropped here rather than reaching the client. Envelope fields are hidden the same way via
#: exclude=True on TreatmentPlanStatus.
_VISIBLE_PLAN_KEYS = (
    "title", "treatment_plan", "action_plan", "applicable_to_all_subsystems",
    "controls_to_be_implemented", "remediation_action_plan", "mitigation_timeline",
    "mitigation_owner", "risk_owner", "impacted_business_division")


def enqueue_treatment_plan(plan_id: str) -> None:
    """Indirection so tests can run the generation synchronously instead of via a broker."""
    generate_treatment_plan_task.delay(plan_id)


@router.post("/sessions/{session_id}/scenarios/{output_id}/treatment-plan", status_code=202,
            response_model=TreatmentPlanAccepted, responses=_CONFLICT_RESPONSES)
def post_treatment_plan(session_id: str, output_id: str, body: TreatmentPlanBody,
                        principal: Principal = Depends(get_principal)) -> TreatmentPlanAccepted:
    """Generate (or regenerate) the Mitigate treatment plan for one ACCEPTED scenario.

    Re-POST semantics: COMPLETE/ERROR plan → superseded and regenerated; fresh RUNNING plan →
    409 generation_in_progress; stale RUNNING plan (progress clock older than
    treatment_stale_seconds) → taken over. The register's risk data arrives IN the body (TSG
    reads no risk-module tables); everything is frozen into the snapshot HERE — the worker
    and the GET only ever see that snapshot."""
    with db_session() as sess:
        scenario_session = get_authorized_session(sess, session_id, principal)

        # Full session row — the board load behind get_authorized_session deliberately omits
        # the AssetContextJSON/SubsystemsJSON blobs the snapshot needs.
        session_row = dal.load_session(sess, session_id)
        if session_row is None:  # unreachable (board load above 404'd; same PK, same txn) —
            raise dal.NotFoundError("session not found")  # but assert would vanish under -O

        scn = dal.scenario_row(sess, session_id, output_id)
        if scn is None:
            raise dal.NotFoundError("scenario not found in this session")
        if scn["Superseded"]:
            raise treatment.TreatmentConflict(
                "this scenario was superseded by a regeneration — request the current one",
                reason=TreatmentGateReason.scenario_superseded)
        if scn["Accepted"] != 1:
            raise treatment.TreatmentConflict(
                "treatment plans are generated for accepted scenarios only",
                reason=TreatmentGateReason.scenario_not_accepted)

        # The register's half of the context is the validated body — no external reads. The
        # session-entity check above (get_authorized_session) is THE authorization boundary.
        snapshot = treatment.build_treatment_input(
            sess, dict(session_row), dict(scn), body.model_dump(mode="json"))

        plan_id = dal.guid()
        stale_cutoff = treatment._stale_cutoff()
        dal.supersede_active_plan(sess, scn["OutputID"], stale_cutoff)
        try:
            dal.insert_row(sess, m.Risk_Treatment_Plan, {
                "PlanID": plan_id, "SessionID": session_id, "OutputID": scn["OutputID"],
                "TenantID": session_row["TenantID"], "EntityID": session_row["EntityID"],
                "UserID": principal.user_id,
                "CrmRiskIdentificationID": None,  # reserved — no register lookup in this design
                "TreatmentStrategy": str(TreatmentStrategy.mitigate),  # server stamp, not a body field
                "RiskLevel": str(body.risk_level),  # denormalized for the register's SQL filter
                "Status": str(StageStatus.RUNNING), "ActiveTaskID": None,
                "RiskIdentificationDate": body.risk_identification_date,
                "InputSnapshotJSON": json.dumps(snapshot, default=str),
                "Superseded": 0, "CreatedAt": dal.now(), "UpdatedAt": dal.now(),
            })
            # Force the filtered-unique check NOW, inside this try — left to the context
            # manager's commit, the IntegrityError would fire outside it.
            sess.flush()
        except IntegrityError:
            sess.rollback()
            raise treatment.TreatmentConflict(
                "a treatment plan is already being generated for this scenario",
                reason=TreatmentGateReason.generation_in_progress) from None
        dal.append_audit(
            sess, AuditID=dal.guid(), SessionID=session_id,
            TenantID=session_row["TenantID"], EntityID=session_row["EntityID"],
            SubsystemID=ASSET_UNIT_ID, EventType=AuditEventType.treatment_plan_requested,
            ActorUserID=principal.user_id,
            DetailJSON=json.dumps({"plan_id": plan_id, "output_id": scn["OutputID"],
                                   **({"note": treatment._clip(body.user_note)}
                                      if body.user_note else {})}))

    # Enqueue OUTSIDE the db_session block (Pattern A). A failed enqueue must not wedge the
    # OutputID behind the staleness window: park the committed RUNNING row in ERROR, re-raise
    # (surfaces as the standard 500) — SDD §6.1 step 8.
    try:
        enqueue_treatment_plan(plan_id)
    except Exception:
        with db_session() as sess:
            # task_id=None: nothing has claimed this row yet (inserted with ActiveTaskID=None
            # above), so only finish it if that's still true.
            dal.finish_plan(sess, plan_id, status=StageStatus.ERROR, task_id=None,
                            error_message="failed to queue generation — request it again",
                            error_reason=TreatmentOutcomeReason.enqueue_failed)
        log.error("treatment.enqueue_failed", plan_id=plan_id)
        raise
    return TreatmentPlanAccepted(plan_id=plan_id, session_id=session_id,
                                 output_id=scn["OutputID"], status=str(StageStatus.RUNNING))


@router.get("/sessions/{session_id}/scenarios/{output_id}/treatment-plan",
            response_model=TreatmentPlanStatus)
def get_treatment_plan(session_id: str, output_id: str,
                       principal: Principal = Depends(get_principal)) -> TreatmentPlanStatus:
    """The poll endpoint — the scenario's one active plan row. 404 when no plan has ever been
    requested for this scenario. A stale RUNNING row is PRESENTED as ERROR/timed-out; the
    stored Status is not rewritten (no reaper — the next POST supersedes it instead).

    POLLING IS THE CONTRACT. The worker also emits an advisory `treatment_plan_result` on the
    session's SSE stream (GET /v1/sessions/{id}/events) so a client can refetch immediately, but
    that is a HINT: three outcomes never publish — a dead worker (the row stays RUNNING and only
    the projection above calls it timed out), an LLM-capacity autoretry (which keeps bumping the
    progress clock, so the row never goes stale either), and cancel/review (written here, in the
    API process). Keep a slow backstop poll; the event only makes the common case feel instant."""
    with db_session() as sess:
        get_authorized_session(sess, session_id, principal)
        row = dal.active_plan_row(sess, session_id, output_id)
        if row is None:
            raise dal.NotFoundError("no treatment plan has been requested for this scenario")
        return _plan_status_from_row(row, treatment._stale_cutoff())


def _plan_status_from_row(row: RowMapping, stale_cutoff: datetime) -> TreatmentPlanStatus:
    """One active plan row -> the wire model. Shared by the single-plan GET and the Excel
    export, so the two can never disagree — the guarantee the export used to buy by re-entering
    the GET per scenario, now held by construction instead of by N extra authorization+fetch
    round trips. `stale_cutoff` is the CALLER's single instant (_present_status's contract):
    the Excel route passes one cutoff for every row of its response."""
    status, error_message, reason = _present_status(
        row["Status"], row["ErrorMessage"], row["UpdatedAt"], stale_cutoff, row["ErrorReason"])

    plan = _normalize_plan_shape(_safe_json_dict(row["PlanJSON"], row["PlanID"]))
    if plan is not None:
        plan = {k: plan[k] for k in _VISIBLE_PLAN_KEYS if k in plan}
    scenario_json = _safe_json_dict(row["ScenarioJSON"], row["PlanID"])
    scenario = ({k: scenario_json.get(k) for k in
                 ("scenario_title", "scenario_statement", "risk_statement")}
                if scenario_json else None)
    if scenario is not None:
        # The threat's identity comes from the joined Identified_Threat row, not the LLM's
        # scenario JSON — same source split as sessions._build_scenario.
        scenario["threat_category"] = row["ThreatCategory"]
        scenario["threat_type"] = row["ThreatType"]
        scenario["threat_name"] = row["ThreatName"]
        scenario["threat_actors"] = stored_actors(row["ThreatActorsJSON"])
    validation = _safe_json_dict(row["ValidationJSON"], row["PlanID"]) or {}
    moderation = validation.get("moderation") or {}
    return TreatmentPlanStatus(
        plan_id=row["PlanID"], session_id=row["SessionID"], output_id=row["OutputID"],
        status=status, treatment_strategy=row["TreatmentStrategy"],
        scenario=scenario,
        risk_level=row["RiskLevel"], review_status=row["ReviewStatus"],
        review_comment=row["ReviewComment"], reviewed_by=row["ReviewedBy"],
        reviewed_at=row["ReviewedAt"],
        risk_identification_date=row["RiskIdentificationDate"],
        plan=plan,
        warnings=[w for w in validation.get("warnings") or [] if isinstance(w, str)],
        moderation_flagged=bool(moderation.get("flagged")),
        error_message=error_message, reason=reason,
        created_at=row["CreatedAt"], completed_at=row["CompletedAt"])


def _safe_json_dict(blob: str | None, plan_id: str) -> dict | None:
    """Defensive PlanJSON/ValidationJSON parse — one corrupt blob must degrade to None with a
    log line, never 500 the poll (same posture as sessions._safe_scenario_json)."""
    if not blob:
        return None
    try:
        parsed = json.loads(blob)
    except (TypeError, ValueError):
        log.warning("treatment.stored_json_unparseable", plan_id=plan_id)
        return None
    return parsed if isinstance(parsed, dict) else None


def _normalize_plan_shape(plan: dict | None) -> dict | None:
    """Read-time projection for pre-v0.12 PlanJSON rows — stored rows are never rewritten (same
    posture as _present_status). The old contract stored controls_to_be_implemented as a bare
    array with control_coverage as a top-level sibling; the current contract nests both as
    {control_coverage, controls[]}. Lifting old rows here — the ONE place PlanJSON is served
    (the board and register never select the column; the Excel export consumes this GET) —
    means every consumer sees one shape regardless of when the plan was generated.

    ANY non-dict value is coerced (list rows kept, junk dropped), so a corrupt or hand-edited
    blob can never 500 the poll or the workbook — same defensive posture as _safe_json_dict.
    Rows from the short-lived pre-v0.5 shape (AI table under `recommended_controls`) coerce to
    an empty controls list rather than being recovered; the evidence endpoint still serves
    their raw snapshot if that history is ever needed."""
    if plan is None:
        return None
    cti = plan.get("controls_to_be_implemented")
    if not isinstance(cti, dict):
        plan["controls_to_be_implemented"] = {
            "control_coverage": plan.get("control_coverage"),
            "controls": [c for c in cti if isinstance(c, dict)] if isinstance(cti, list) else [],
        }
    return plan


def _naive_utc(dt: datetime) -> datetime:
    """Normalize to naive UTC. MSSQL datetime2 stores naive-UTC wall time and pyodbc silently
    drops tzinfo on bind (the documented reason TreatmentPlanBody._utc_naive exists), so an
    aware value must be CONVERTED to UTC before the offset is stripped — a bare
    replace(tzinfo=None) on a +05:30 timestamp would shift every comparison by 5.5 hours.
    Naive input is trusted as UTC already (that is what the DB hands back)."""
    return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt


def _present_status(status: str, error_message: str | None, updated_at: datetime | None,
                    stale_cutoff: datetime,
                    error_reason: str | None = None) -> tuple[str, str | None, str | None]:
    """Read-time staleness projection shared by the single-plan GET, the board and the
    register: a RUNNING row whose progress clock stopped past treatment_stale_seconds
    presents as ERROR/timed-out; the stored row is never rewritten (D10 — the next POST
    supersedes it, and a late finish still lands).

    Returns (status, message, reason). The reason is the projection's whole point on this path:
    `timed_out` has NO writer — it exists only here — so a client can distinguish a timeout from a
    real failure without matching the English sentence. For a stored ERROR the row's own
    ErrorReason passes through; NULL (a row that failed before the column existed) reads as
    generation_failed, the historical catch-all.

    `stale_cutoff` is the CALLER's instant, not recomputed here — `treatment._stale_cutoff()`
    returns `now() - treatment_stale_seconds` at call time, so calling it fresh per row (the
    board loops over several) or a second time after an earlier SQL-side filter already used one
    (the register) drifts the two apart by however long the round trip took. A row can then pass
    one check and fail the other on the exact same request."""
    if status == str(StageStatus.RUNNING) and updated_at is not None \
            and _naive_utc(updated_at) < _naive_utc(stale_cutoff):
        return str(StageStatus.ERROR), _TIMED_OUT_MESSAGE, str(TreatmentOutcomeReason.timed_out)
    if status == str(StageStatus.ERROR):
        return status, error_message, error_reason or str(TreatmentOutcomeReason.generation_failed)
    return status, error_message, None  # RUNNING / COMPLETE carry no reason


def _scenario_title(scenario_json: str | None) -> str | None:
    """Display title from a ScenarioJSON blob — defensive, a corrupt blob yields None."""
    return (_safe_json_dict(scenario_json, "-") or {}).get("scenario_title")


_CANCELLED_MESSAGE = "cancelled by user"

#: Wire labels for the audit feeds — short verbs, not internal enum names.
_EVENT_LABELS = {
    str(AuditEventType.treatment_plan_requested): "requested",
    str(AuditEventType.treatment_plan_outcome): "outcome",
    str(AuditEventType.treatment_plan_cancelled): "cancelled",
    str(AuditEventType.treatment_plan_reviewed): "reviewed",
}


@router.get("/sessions/{session_id}/treatment-plans", response_model=TreatmentBoard)
def get_treatment_board(session_id: str,
                        principal: Principal = Depends(get_principal)) -> TreatmentBoard:
    """The session plan board — every ACCEPTED scenario's plan state in one call (replaces N
    per-scenario polls). Null plan fields = never requested (UI shows Generate)."""
    with db_session() as sess:
        get_authorized_session(sess, session_id, principal)
        rows = dal.session_plan_board(sess, session_id)
        # ONE cutoff for the whole board, not one per row (see _present_status) — a board with
        # several plans must not judge the last row against a later instant than the first.
        stale_cutoff = treatment._stale_cutoff()
        plans = []
        for r in rows:
            # All three default to None together: a scenario with no plan yet leaves every one
            # of them unset, and initializing only some of them makes the never-requested row
            # raise UnboundLocalError instead of rendering the UI's "Generate" state.
            status: str | None = None
            err: str | None = None
            reason: str | None = None
            if r["PlanID"] is not None:
                status, err, reason = _present_status(r["Status"], r["ErrorMessage"],
                                                      r["PlanUpdatedAt"], stale_cutoff,
                                                      r["ErrorReason"])
            plans.append(TreatmentBoardRow(
                output_id=r["OutputID"], scenario_title=_scenario_title(r["ScenarioJSON"]),
                plan_id=r["PlanID"], status=status, risk_level=r["RiskLevel"],
                review_status=r["ReviewStatus"], error_message=err, reason=reason,
                created_at=r["PlanCreatedAt"], completed_at=r["PlanCompletedAt"]))
    return TreatmentBoard(session_id=session_id, accepted_scenarios=len(rows), plans=plans)


@router.get("/sessions/{session_id}/treatment-plans.xlsx")
def get_treatment_plans_excel(session_id: str,
                              principal: Principal = Depends(get_principal)) -> Response:
    """The session's treatment-plan board, as a single-sheet Excel workbook — one row per
    accepted scenario that has a generated plan.

    Renders through _plan_status_from_row — the SAME presenter the JSON poll uses — so this
    can never drift from its staleness projection, trimming, or field rendering. One batched
    dal.active_plan_rows read replaces the former per-scenario GET reentry (1+2N round trips
    → 3): one authorization, the board query (whose ORDER BY drives row order), one plan
    fetch. A single stale cutoff serves every row, per _present_status's own contract."""
    with db_session() as sess:
        get_authorized_session(sess, session_id, principal)
        rows = dal.session_plan_board(sess, session_id)
        plan_rows = {r["OutputID"]: r for r in dal.active_plan_rows(sess, session_id)}
    stale_cutoff = treatment._stale_cutoff()
    plans = [_plan_status_from_row(plan_rows[r["OutputID"]], stale_cutoff)
             for r in rows if r["PlanID"] is not None and r["OutputID"] in plan_rows]
    workbook = build_treatment_plans_workbook(session_id, plans)
    buffer = io.BytesIO()
    workbook.save(buffer)
    return Response(
        content=buffer.getvalue(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="session_{session_id}_treatment_plans.xlsx"'},
    )


@router.post("/sessions/{session_id}/scenarios/{output_id}/treatment-plan/cancel",
             response_model=TreatmentCancelResponse, responses=_CONFLICT_RESPONSES)
def post_cancel_treatment_plan(session_id: str, output_id: str,
                               principal: Principal = Depends(get_principal)) -> TreatmentCancelResponse:
    """The stop button: flip a RUNNING generation to ERROR right now, instead of waiting out
    the staleness window after a mistaken click. Fenced by finish_plan's CAS — if the worker
    finished first (or nothing is running), 409 not_in_progress and nothing changes."""
    with db_session() as sess:
        get_authorized_session(sess, session_id, principal)
        row = dal.active_plan_row(sess, session_id, output_id)
        if row is None:
            raise dal.NotFoundError("no treatment plan has been requested for this scenario")
        # task_id=row["ActiveTaskID"]: whoever currently holds it, whatever that is — closes a
        # TOCTOU window where a worker reclaims the row between this SELECT and the UPDATE below.
        if row["Status"] != str(StageStatus.RUNNING) or not dal.finish_plan(
                sess, row["PlanID"], status=StageStatus.ERROR, task_id=row["ActiveTaskID"],
                error_message=_CANCELLED_MESSAGE,
                error_reason=TreatmentOutcomeReason.cancelled):
            raise treatment.TreatmentConflict(
                "no generation is in progress for this scenario",
                reason=TreatmentGateReason.not_in_progress)
        dal.append_audit(
            sess, AuditID=dal.guid(), SessionID=session_id, TenantID=row["TenantID"],
            EntityID=row["EntityID"], SubsystemID=ASSET_UNIT_ID,
            EventType=AuditEventType.treatment_plan_cancelled, ActorUserID=principal.user_id,
            DetailJSON=json.dumps({"plan_id": row["PlanID"],
                                   "reason": str(TreatmentOutcomeReason.cancelled)}))
    log.info("treatment.cancelled", plan_id=row["PlanID"], user=principal.user_id)
    return TreatmentCancelResponse(plan_id=row["PlanID"], status=str(StageStatus.ERROR),
                                   error_message=_CANCELLED_MESSAGE)


@router.post("/sessions/{session_id}/scenarios/{output_id}/treatment-plan/review",
             response_model=TreatmentReviewResponse, responses=_CONFLICT_RESPONSES)
def post_review_treatment_plan(session_id: str, output_id: str, body: TreatmentReviewBody,
                               principal: Principal = Depends(get_principal)) -> TreatmentReviewResponse:
    """Record the human adoption decision on the ACTIVE, COMPLETE plan. The reviewer's
    identity comes from the login token (never the body); a re-review overwrites (latest
    wins); regenerating supersedes the row, so a new version always starts unreviewed."""
    # Reviewer free text is redacted+capped like every other client string that lands in a
    # persistent store (user_note precedent) — a pasted secret must not reach ReviewComment
    # or the compliance feed's DetailJSON. One timestamp, naive UTC: stored AND echoed, so
    # the POST receipt matches the next GET byte-for-byte (wire convention: no offset).
    comment = treatment._clip(body.comment)
    reviewed_at = _naive_utc(dal.now())
    with db_session() as sess:
        get_authorized_session(sess, session_id, principal)
        row = dal.active_plan_row(sess, session_id, output_id)
        if row is None:
            raise dal.NotFoundError("no treatment plan has been requested for this scenario")
        if not dal.review_plan(sess, row["PlanID"], status=str(body.decision),
                               comment=comment, reviewer=principal.user_id,
                               reviewed_at=reviewed_at):
            raise treatment.TreatmentConflict(
                "only a COMPLETE plan can be reviewed — wait for generation to finish, or "
                "regenerate first", reason=TreatmentGateReason.not_complete)
        dal.append_audit(
            sess, AuditID=dal.guid(), SessionID=session_id, TenantID=row["TenantID"],
            EntityID=row["EntityID"], SubsystemID=ASSET_UNIT_ID,
            EventType=AuditEventType.treatment_plan_reviewed, ActorUserID=principal.user_id,
            DetailJSON=json.dumps({"plan_id": row["PlanID"], "decision": str(body.decision),
                                   **({"comment": comment} if comment else {})}))
    log.info("treatment.reviewed", plan_id=row["PlanID"], decision=str(body.decision),
             user=principal.user_id)
    return TreatmentReviewResponse(plan_id=row["PlanID"], review_status=str(body.decision),
                                   reviewed_by=principal.user_id, reviewed_at=reviewed_at)


@router.get("/entities/{entity_id}/treatment-plans", response_model=TreatmentRegisterPage)
def list_entity_treatment_plans(entity_id: str,
                                # Enum-typed, not str: an unrecognized value used to bind straight
                                # into the WHERE and return an empty page, which reads as "no such
                                # plans" rather than "you typed it wrong". Now a clean 422.
                                status: Literal[StageStatus.RUNNING, StageStatus.COMPLETE,
                                                StageStatus.ERROR] | None = Query(
                                    None, description="Filter by presented status (a timed-out "
                                                      "RUNNING plan counts as ERROR)."),
                                review_status: TreatmentReviewStatus | None = Query(None),
                                risk_level: RiskLevel | None = Query(None),
                                limit: int = Query(100, ge=1, le=500),
                                offset: int = Query(0, ge=0),
                                principal: Principal = Depends(get_principal)) -> TreatmentRegisterPage:
    """The entity-wide remediation register: every active plan across all the entity's
    assets, newest first, filterable. THE page for 'which Critical risks still have no
    approved plan?'."""
    principal.require_entity(entity_id)
    with db_session() as sess:
        # Same cutoff instant for the SQL filter and the row presentation — the filter must
        # match what _present_status will show (a timed-out plan IS an ERROR to the operator).
        # ONE value, passed to both — previously each called treatment._stale_cutoff()
        # independently, so a row landing between the two instants could pass the SQL filter as
        # RUNNING while _present_status rendered it ERROR on the same response.
        stale_cutoff = treatment._stale_cutoff()
        rows = dal.entity_plan_rows(sess, entity_id, stale_cutoff=stale_cutoff,
                                    status=status, review_status=review_status,
                                    risk_level=risk_level, limit=limit, offset=offset)
        items = []
        for r in rows:
            st, err, reason = _present_status(r["Status"], r["ErrorMessage"], r["UpdatedAt"],
                                              stale_cutoff, r["ErrorReason"])
            items.append(TreatmentRegisterRow(
                plan_id=r["PlanID"], session_id=r["SessionID"], output_id=r["OutputID"],
                asset_name=r["AssetName"], scenario_title=r["ScenarioTitle"],
                status=st, risk_level=r["RiskLevel"], review_status=r["ReviewStatus"],
                reviewed_by=r["ReviewedBy"], error_message=err, reason=reason,
                created_at=r["CreatedAt"], completed_at=r["CompletedAt"]))
    return TreatmentRegisterPage(entity_id=entity_id, limit=limit, offset=offset, plans=items)


@router.get("/sessions/{session_id}/scenarios/{output_id}/treatment-plan/audit",
            response_model=TreatmentAuditTrail)
def get_treatment_plan_audit(session_id: str, output_id: str,
                             principal: Principal = Depends(get_principal)) -> TreatmentAuditTrail:
    """One scenario's plan life story across ALL versions, oldest first: requested (by whom),
    each attempt's outcome, cancels, reviews — plus synthesized 'superseded' entries from the
    never-deleted version chain."""
    with db_session() as sess:
        get_authorized_session(sess, session_id, principal)
        history = dal.plan_history_rows(sess, session_id, output_id)
        if not history:
            raise dal.NotFoundError("no treatment plan has been requested for this scenario")
        plan_ids = {r["PlanID"] for r in history}
        events = []
        for a in dal.treatment_audit_rows(sess, session_id):
            detail = _safe_json_dict(a["DetailJSON"], "-") or {}
            if detail.get("plan_id") in plan_ids:
                events.append(TreatmentAuditEvent(
                    at=a["CreatedAt"], event=_EVENT_LABELS.get(a["EventType"], a["EventType"]),
                    actor=a["ActorUserID"], actor_type=a["ActorType"], detail=detail))
        for r in history:
            if r["Superseded"]:
                events.append(TreatmentAuditEvent(
                    at=r["UpdatedAt"], event="superseded", detail={"plan_id": r["PlanID"]}))
        events.sort(key=lambda e: (e.at is None, e.at))
    return TreatmentAuditTrail(session_id=session_id, output_id=output_id, events=events)


@router.get("/entities/{entity_id}/treatment-plans/audit",
            response_model=TreatmentEntityAuditPage)
def list_entity_treatment_audit(entity_id: str,
                                since: datetime | None = Query(None, alias="from"),
                                until: datetime | None = Query(None, alias="to"),
                                user_id: str | None = Query(None, description="Filter to one actor"),
                                limit: int = Query(200, ge=1, le=1000),
                                offset: int = Query(0, ge=0),
                                principal: Principal = Depends(get_principal)) -> TreatmentEntityAuditPage:
    """The compliance feed: every treatment-plan action across the entity, newest first —
    'all treatment-plan activity in July' as one request instead of a database ticket."""
    principal.require_entity(entity_id)
    with db_session() as sess:
        # from/to may arrive with any UTC offset — normalize to naive UTC before binding
        # against the naive-UTC CreatedAt column (same rule as the body's date validator).
        rows = dal.entity_treatment_audit_rows(
            sess, entity_id, since=_naive_utc(since) if since else None,
            until=_naive_utc(until) if until else None,
            actor=user_id, limit=limit, offset=offset)
        events = [TreatmentAuditEvent(
            at=r["CreatedAt"], event=_EVENT_LABELS.get(r["EventType"], r["EventType"]),
            actor=r["ActorUserID"], actor_type=r["ActorType"], session_id=r["SessionID"],
            detail=_safe_json_dict(r["DetailJSON"], "-") or {}) for r in rows]
    return TreatmentEntityAuditPage(entity_id=entity_id, limit=limit, offset=offset,
                                    events=events)


@router.get("/sessions/{session_id}/scenarios/{output_id}/treatment-plan/evidence",
            response_model=TreatmentEvidence)
def get_treatment_plan_evidence(session_id: str, output_id: str,
                                version: str = Query(..., description="The plan_id of the version to inspect (superseded versions allowed)."),
                                principal: Principal = Depends(get_principal)) -> TreatmentEvidence:
    """The reproducibility bundle for ONE plan version: the frozen input snapshot (exactly
    what the AI was given), the validation/moderation record, and every AI-call receipt —
    joined by Prompt_Log.CorrelationID, byte-for-byte, even for versions replaced long ago.

    `status` is the STORED value, deliberately unprojected (no staleness rewrite): evidence
    reports the record as written — a stale RUNNING plan reads RUNNING here even while the
    poll GET presents it as timed out."""
    with db_session() as sess:
        get_authorized_session(sess, session_id, principal)
        row = dal.plan_row_by_id(sess, session_id, output_id, version)
        if row is None:
            raise dal.NotFoundError("no such plan version for this scenario")
        attempts = [TreatmentEvidenceAttempt(
            at=r["CreatedAt"], prompt=r["Prompt"], response=r["ResponseText"],
            model_name=r["Model"], model_version=r["ModelVersion"],
            prompt_version=r["PromptVersion"], parse_succeeded=r["ParseSucceeded"])
            for r in dal.prompt_logs_for_plan(sess, row["PlanID"])]
    return TreatmentEvidence(
        plan_id=row["PlanID"], status=row["Status"],
        input_snapshot=_safe_json_dict(row["InputSnapshotJSON"], row["PlanID"]),
        validation=_safe_json_dict(row["ValidationJSON"], row["PlanID"]),
        attempts=attempts)
