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
    TreatmentPlanRegenerateBody,
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

_TIMED_OUT_MESSAGE = "generation timed out — regenerate it (POST .../treatment-plan/regenerate)"

#: The ONE wording source for every treatment-route 409 (accept.py::_REASON_TEXT's analog):
#: raise sites carry no prose of their own, so a reason can never ship two spellings. A test
#: pins every raisable TreatmentGateReason member to an entry (scenario_superseded is
#: HISTORICAL — never raised — and deliberately absent).
_GATE_TEXT: dict[TreatmentGateReason, str] = {
    TreatmentGateReason.scenario_not_accepted:
        "treatment plans are generated for accepted scenarios only",
    TreatmentGateReason.generation_in_progress:
        "a treatment plan is already being generated for this scenario",
    TreatmentGateReason.not_in_progress:
        "no generation is in progress for this scenario",
    TreatmentGateReason.not_complete:
        "only a COMPLETE plan can be reviewed or adopted — wait for generation to finish, "
        "or regenerate first",
    TreatmentGateReason.plan_already_exists:
        "a treatment plan already exists for this scenario — use "
        "POST .../treatment-plan/regenerate to create a new version",
    TreatmentGateReason.version_not_active:
        "this plan version is not the current one — approving it would make it current, "
        "but rejecting a historical version changes nothing",
}


def _conflict(reason: TreatmentGateReason) -> treatment.TreatmentConflict:
    """The only way this module builds a 409 — wording resolved from _GATE_TEXT, never inline."""
    return treatment.TreatmentConflict(_GATE_TEXT[reason], reason=reason)

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
    """FIRST generation of the Mitigate treatment plan for one ACCEPTED scenario. The register's
    risk data arrives IN the body (TSG reads no risk-module tables); everything is frozen into
    the snapshot at insert — the worker and the GET only ever see that snapshot.

    If ANY plan already exists for the scenario (whatever its status) → 409 plan_already_exists:
    every later version is minted by POST .../treatment-plan/regenerate, which reuses the frozen
    register data and takes only a user_note. (BREAKING wire change from the old re-POST
    semantics — see docs/TSG_UI_API_INTEGRATION.md.) Two concurrent first-creates both pass the
    read below; UX_TreatmentPlan_ActiveOutput arbitrates the insert race (loser → 409, same as
    always)."""
    return _launch_generation(
        session_id, output_id, principal,
        risk_input=body.model_dump(mode="json"),
        risk_level=str(body.risk_level), risk_identification_date=body.risk_identification_date,
        user_note=body.user_note, first_generation=True, fence_plan_id=None)


@router.post("/sessions/{session_id}/scenarios/{output_id}/treatment-plan/regenerate",
             status_code=202, response_model=TreatmentPlanAccepted, responses=_CONFLICT_RESPONSES)
def post_regenerate_treatment_plan(session_id: str, output_id: str, body: TreatmentPlanRegenerateBody,
                                   principal: Principal = Depends(get_principal)) -> TreatmentPlanAccepted:
    """Regenerate the plan: retire the ACTIVE version, generate a new one. Body is ONLY an
    optional user_note — the register risk data is reused from the active version's frozen
    snapshot (the client never resends it; if the register itself changed, that is a documented
    limitation of this shape). Baseline is the ACTIVE row, never newest-by-CreatedAt, so a
    version switched back in by an approve is what a later regenerate builds on. Fresh RUNNING →
    409 generation_in_progress; no plan ever generated → 404."""
    with db_session() as sess:
        get_authorized_session(sess, session_id, principal)
        # One narrow read: id + the two column stamps + the snapshot. The fence_plan_id below
        # makes a stale read harmless — a racing switch/regenerate between this read and the
        # retire misses the CAS instead of using the wrong version's data.
        row = dal.active_plan_baseline(sess, session_id, output_id)
        if row is None:
            raise dal.NotFoundError("no treatment plan has been requested for this scenario")
        snapshot = treatment._loads(row["InputSnapshotJSON"], {})
        risk_input = treatment.regen_risk_input_from_snapshot(snapshot, body.user_note)
        risk_level, risk_date = row["RiskLevel"], row["RiskIdentificationDate"]
        fence_plan_id = str(row["PlanID"])
    return _launch_generation(
        session_id, output_id, principal, risk_input=risk_input,
        risk_level=risk_level, risk_identification_date=risk_date,
        user_note=body.user_note, first_generation=False, fence_plan_id=fence_plan_id)


def _launch_generation(session_id: str, output_id: str, principal: Principal, *,
                       risk_input: dict, risk_level: str | None, risk_identification_date,
                       user_note: str | None, first_generation: bool,
                       fence_plan_id: str | None) -> TreatmentPlanAccepted:
    """Shared create/regenerate implementation — the split is at the route layer only.

    `first_generation` gates on "no plan rows exist" (the exactly-one-active invariant makes
    the active-row read a complete existence check); `fence_plan_id` is regenerate's TOCTOU
    fence: the retire targets exactly the row whose snapshot was read, or fails the CAS."""
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
        # No Superseded gate: the accepted version may be an older, superseded one (Accepted is
        # decoupled from generation recency). TreatmentGateReason.scenario_superseded is retired
        # — kept in the enum for wire-compat, never raised.
        if scn["Accepted"] != 1:
            raise _conflict(TreatmentGateReason.scenario_not_accepted)

        if first_generation and dal.active_plan_row(sess, session_id, output_id) is not None:
            raise _conflict(TreatmentGateReason.plan_already_exists)

        # The register's half of the context is `risk_input` (the validated body on create; the
        # active version's frozen snapshot on regenerate) — no external reads. The
        # session-entity check above (get_authorized_session) is THE authorization boundary.
        snapshot = treatment.build_treatment_input(
            sess, dict(session_row), dict(scn), risk_input)

        plan_id = dal.guid()
        stale_cutoff = treatment._stale_cutoff()
        if not first_generation:
            # First generation skips the retire entirely — the gate above just proved no rows
            # exist, so the UPDATE would be a guaranteed no-op round trip.
            if dal.supersede_active_plan(sess, scn["OutputID"], stale_cutoff,
                                         plan_id=fence_plan_id) == 0:
                # Fresh RUNNING generation, or the active row changed since the route read it
                # (fence miss) — either way, generation state moved; this request must not act.
                raise _conflict(TreatmentGateReason.generation_in_progress)
        try:
            dal.insert_row(sess, m.Risk_Treatment_Plan, {
                "PlanID": plan_id, "SessionID": session_id, "OutputID": scn["OutputID"],
                "TenantID": session_row["TenantID"], "EntityID": session_row["EntityID"],
                "UserID": principal.user_id,
                "CrmRiskIdentificationID": None,  # reserved — no register lookup in this design
                "TreatmentStrategy": str(TreatmentStrategy.mitigate),  # server stamp, not a body field
                "RiskLevel": risk_level,  # denormalized for the register's SQL filter
                "Status": str(StageStatus.RUNNING), "ActiveTaskID": None,
                "RiskIdentificationDate": risk_identification_date,
                "InputSnapshotJSON": json.dumps(snapshot, default=str),
                "Superseded": 0, "CreatedAt": dal.now(), "UpdatedAt": dal.now(),
            })
            # Force the filtered-unique check NOW, inside this try — left to the context
            # manager's commit, the IntegrityError would fire outside it.
            sess.flush()
        except IntegrityError:
            sess.rollback()
            raise _conflict(TreatmentGateReason.generation_in_progress) from None
        dal.append_audit(
            sess, AuditID=dal.guid(), SessionID=session_id,
            TenantID=session_row["TenantID"], EntityID=session_row["EntityID"],
            SubsystemID=ASSET_UNIT_ID, EventType=AuditEventType.treatment_plan_requested,
            ActorUserID=principal.user_id,
            DetailJSON=json.dumps({"plan_id": plan_id, "output_id": scn["OutputID"],
                                   **({"note": treatment._clip(user_note)}
                                      if user_note else {})}))

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
                            error_message="failed to queue generation — regenerate it "
                                          "(POST .../treatment-plan/regenerate)",
                            error_reason=TreatmentOutcomeReason.enqueue_failed)
        log.error("treatment.enqueue_failed", plan_id=plan_id)
        raise
    return TreatmentPlanAccepted(plan_id=plan_id, session_id=session_id,
                                 output_id=scn["OutputID"], status=str(StageStatus.RUNNING))


@router.get("/sessions/{session_id}/scenarios/{output_id}/treatment-plan",
            response_model=TreatmentPlanStatus)
def get_treatment_plan(session_id: str, output_id: str,
                       include_superseded: bool = Query(
                           False, description="Also return every regenerated-away version of "
                                              "this plan under `superseded`, newest first."),
                       principal: Principal = Depends(get_principal)) -> TreatmentPlanStatus:
    """The poll endpoint — the scenario's one active plan row. 404 when no plan has ever been
    requested for this scenario. A stale RUNNING row is PRESENTED as ERROR/timed-out; the
    stored Status is not rewritten (no reaper — the next POST supersedes it instead).

    ?include_superseded=true additionally serves the regeneration history: the same top-level
    response (the current plan) plus `superseded` — every replaced version, newest first,
    rendered by the same presenter (same trim, same staleness projection). History items carry
    scenario=null: the scenario hangs off the OutputID, identical for every version, so it is
    served once on the top level instead of N+1 times. Default off keeps the hot polling
    path's single-row query untouched.

    POLLING IS THE CONTRACT. The worker also emits an advisory `treatment_plan_result` on the
    session's SSE stream (GET /v1/sessions/{id}/events) so a client can refetch immediately, but
    that is a HINT: three outcomes never publish — a dead worker (the row stays RUNNING and only
    the projection above calls it timed out), an LLM-capacity autoretry (which keeps bumping the
    progress clock, so the row never goes stale either), and cancel plus a plain review verdict
    (written here, in the API process). One API-side action DOES publish: an approve that
    switches the active version emits the same event after its commit. Keep a slow backstop
    poll; the event only makes the common case feel instant."""
    with db_session() as sess:
        get_authorized_session(sess, session_id, principal)
        row = dal.active_plan_row(sess, session_id, output_id)
        if row is None:
            raise dal.NotFoundError("no treatment plan has been requested for this scenario")
        # ONE cutoff for the current row and every history row (see _present_status).
        stale_cutoff = treatment._stale_cutoff()
        older = None
        if include_superseded:
            # PlanID guard: two SELECTs under READ COMMITTED — a regeneration committing
            # between them would supersede the row just read as current, making it show up in
            # BOTH places on one response. Dropping it here keeps the reply self-consistent.
            older = [_plan_status_from_row(r, stale_cutoff)
                     for r in dal.superseded_plan_rows(sess, session_id, output_id)
                     if r["PlanID"] != row["PlanID"]]
        return _plan_status_from_row(row, stale_cutoff, superseded=older)


def _plan_status_from_row(row: RowMapping, stale_cutoff: datetime,
                          superseded: list[TreatmentPlanStatus] | None = None) -> TreatmentPlanStatus:
    """One plan row -> the wire model. Shared by the single-plan GET, the Excel export, the
    versions history (?include_superseded) and the detailed register (?include_plan), so no
    two views can ever disagree — the guarantee the export used to buy by re-entering the GET
    per scenario, now held by construction. `stale_cutoff` is the CALLER's single instant
    (_present_status's contract): batch routes pass one cutoff for every row of a response.
    Blob columns that feed only wire-hidden fields (ValidationJSON, ReviewComment — exclude=True
    on the model) are read with .get: every batch query deliberately omits them, and only the
    single-row active_plan_row still hauls them so the poll GET keeps its one-flag-unhide
    contract."""
    status, error_message, reason = _present_status(
        row["Status"], row["ErrorMessage"], row["UpdatedAt"], stale_cutoff, row["ErrorReason"])

    plan = _visible_plan(row["PlanJSON"], row["PlanID"])
    # .get, not []: history rows (dal.superseded_plan_rows) carry no scenario/threat join —
    # the scenario is version-independent, served once on the top-level object.
    scenario_json = _safe_json_dict(row.get("ScenarioJSON"), row["PlanID"])
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
    validation = _safe_json_dict(row.get("ValidationJSON"), row["PlanID"]) or {}
    moderation = validation.get("moderation") or {}
    return TreatmentPlanStatus(
        plan_id=row["PlanID"], session_id=row["SessionID"], output_id=row["OutputID"],
        status=status, treatment_strategy=row["TreatmentStrategy"],
        scenario=scenario,
        risk_level=row["RiskLevel"], review_status=row["ReviewStatus"],
        review_comment=row.get("ReviewComment"), reviewed_by=row["ReviewedBy"],
        reviewed_at=row["ReviewedAt"],
        risk_identification_date=row["RiskIdentificationDate"],
        plan=plan,
        warnings=[w for w in validation.get("warnings") or [] if isinstance(w, str)],
        moderation_flagged=bool(moderation.get("flagged")),
        error_message=error_message, reason=reason, superseded=superseded,
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


def _visible_plan(plan_json: str | None, plan_id: str) -> dict | None:
    """Stored PlanJSON -> the served plan object: defensive parse, legacy-shape lift, then the
    _VISIBLE_PLAN_KEYS trim. THE one projection — the poll GET (via _plan_status_from_row) and
    the register's ?include_plan=true both serve exactly this, so the two views can never
    disagree on what a plan looks like."""
    plan = _normalize_plan_shape(_safe_json_dict(plan_json, plan_id))
    if plan is not None:
        plan = {k: plan[k] for k in _VISIBLE_PLAN_KEYS if k in plan}
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


_CANCELLED_MESSAGE = "cancelled by user"

#: Wire labels for the audit feeds — short verbs, not internal enum names.
_EVENT_LABELS = {
    str(AuditEventType.treatment_plan_requested): "requested",
    str(AuditEventType.treatment_plan_outcome): "outcome",
    str(AuditEventType.treatment_plan_cancelled): "cancelled",
    str(AuditEventType.treatment_plan_reviewed): "reviewed",
    str(AuditEventType.treatment_plan_version_restored): "version restored",
}


@router.get("/sessions/{session_id}/treatment-plans", response_model=TreatmentBoard)
def get_treatment_board(session_id: str,
                        include_plan: bool = Query(
                            False, description="Also return each plan's content — the "
                                               "same trimmed object as the single-plan "
                                               "GET. Null on rows with no generated "
                                               "content (RUNNING/ERROR or never "
                                               "requested)."),
                        include_superseded: bool = Query(
                            False, description="Also return each scenario's regeneration "
                                               "history under `superseded` — every replaced "
                                               "version, newest first, rendered like the "
                                               "single-plan GET's history entries."),
                        principal: Principal = Depends(get_principal)) -> TreatmentBoard:
    """The session plan board — every ACCEPTED scenario's plan state in one call (replaces N
    per-scenario polls). Null plan fields = never requested (UI shows Generate).
    ?include_plan=true adds each COMPLETE plan's content, same projection as the register;
    ?include_superseded=true adds each scenario's regeneration history, same entries as the
    single-plan GET's (one session-wide query, not one per scenario)."""
    with db_session() as sess:
        get_authorized_session(sess, session_id, principal)
        rows = dal.session_plan_board(sess, session_id, include_plan=include_plan)
        # ONE cutoff for the whole board, not one per row (see _present_status) — a board with
        # several plans must not judge the last row against a later instant than the first.
        stale_cutoff = treatment._stale_cutoff()
        # Whole-session history in ONE round trip, bucketed by scenario — the query's global
        # newest-first order keeps every bucket newest-first.
        history: dict[str, list[TreatmentPlanStatus]] = {}
        if include_superseded:
            for h in dal.superseded_plan_rows(sess, session_id):
                history.setdefault(h["OutputID"], []).append(
                    _plan_status_from_row(h, stale_cutoff))
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
                output_id=r["OutputID"], scenario_title=r["ScenarioTitle"],
                plan_id=r["PlanID"], status=status, risk_level=r["RiskLevel"],
                review_status=r["ReviewStatus"], error_message=err, reason=reason,
                # PlanID guard: never-requested rows have NULL plan columns (and without the
                # flag the row carries no PlanJSON key at all).
                plan=(_visible_plan(r["PlanJSON"], r["PlanID"])
                      if include_plan and r["PlanID"] is not None else None),
                # Same READ-COMMITTED guard as the single GET: a regeneration committing
                # between the two SELECTs must not list one PlanID as both current and history.
                superseded=([e for e in history.get(r["OutputID"], [])
                             if e.plan_id != r["PlanID"]]
                            if include_superseded else None),
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
            raise _conflict(TreatmentGateReason.not_in_progress)
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
    """Record the human adoption decision. Default (no plan_id, or the active plan's id): the
    verdict lands on the ACTIVE, COMPLETE plan — a re-review overwrites (latest wins), and a
    regenerated plan always starts unreviewed. With a HISTORICAL plan_id and decision=approved:
    the atomic version switch — retire the active row, reactivate the target, stamp the verdict,
    all-or-nothing — approving an older version IS making it the plan (last human decision
    wins; the displaced version keeps its own verdict in history). Rejecting a historical
    version is refused (version_not_active): it is already not the plan. The reviewer's
    identity comes from the login token, never the body."""
    # Reviewer free text is redacted+capped like every other client string that lands in a
    # persistent store (user_note precedent) — a pasted secret must not reach ReviewComment
    # or the compliance feed's DetailJSON. One timestamp, naive UTC: stored AND echoed, so
    # the POST receipt matches the next GET byte-for-byte (wire convention: no offset).
    comment = treatment._clip(body.comment)
    reviewed_at = _naive_utc(dal.now())
    swapped = False
    with db_session() as sess:
        get_authorized_session(sess, session_id, principal)
        row = dal.active_plan_row(sess, session_id, output_id)
        if row is None:
            raise dal.NotFoundError("no treatment plan has been requested for this scenario")

        target_id = body.plan_id  # canonicalized at the schema boundary; row ids canonical too
        if target_id is not None and target_id != str(row["PlanID"]):
            # --- Version-switch branch: verdict targets a historical version ---
            if not dal.plan_version_exists(sess, session_id, output_id, target_id):
                raise dal.NotFoundError("no such plan version for this scenario")
            if body.decision != TreatmentReviewStatus.approved:
                raise _conflict(TreatmentGateReason.version_not_active)
            # Retire the active row, fenced to the exact row read above — a racing
            # regenerate/switch misses the CAS; a fresh RUNNING generation matches nothing.
            if not dal.supersede_active_plan(sess, output_id, treatment._stale_cutoff(),
                                             plan_id=str(row["PlanID"])):
                raise _conflict(TreatmentGateReason.generation_in_progress)
            # Reactivate the target (CAS: Superseded=1 AND COMPLETE). A miss rolls the retire
            # back too — this pair is the only writer that could otherwise leave the scenario
            # with ZERO active rows. The UPDATE executes immediately (execute_dml), so a
            # filtered-unique violation would raise HERE, not at a later flush — though the
            # plan_id-fenced retire above already precludes it (any concurrent activator must
            # first win that same retire), so the except is belt-and-braces, not the guard.
            try:
                reactivated = dal.reactivate_plan_version(sess, session_id, output_id, target_id)
            except IntegrityError:
                sess.rollback()
                raise _conflict(TreatmentGateReason.generation_in_progress) from None
            if not reactivated:
                sess.rollback()
                raise _conflict(TreatmentGateReason.not_complete)
            plan_id = target_id
            dal.append_audit(
                sess, AuditID=dal.guid(), SessionID=session_id, TenantID=row["TenantID"],
                EntityID=row["EntityID"], SubsystemID=ASSET_UNIT_ID,
                EventType=AuditEventType.treatment_plan_version_restored,
                ActorUserID=principal.user_id,
                # `plan_id` key REQUIRED: the per-scenario trail filters on it.
                DetailJSON=json.dumps({"plan_id": plan_id,
                                       "retired_plan_id": str(row["PlanID"]),
                                       "output_id": output_id}))
            swapped = True
        else:
            plan_id = str(row["PlanID"])

        if not dal.review_plan(sess, plan_id, status=str(body.decision),
                               comment=comment, reviewer=principal.user_id,
                               reviewed_at=reviewed_at):
            sess.rollback()  # on the swap branch this also undoes the swap — all-or-nothing
            raise _conflict(TreatmentGateReason.not_complete)
        dal.append_audit(
            sess, AuditID=dal.guid(), SessionID=session_id, TenantID=row["TenantID"],
            EntityID=row["EntityID"], SubsystemID=ASSET_UNIT_ID,
            EventType=AuditEventType.treatment_plan_reviewed, ActorUserID=principal.user_id,
            DetailJSON=json.dumps({"plan_id": plan_id, "decision": str(body.decision),
                                   **({"comment": comment} if comment else {})}))
    if swapped:
        # After the commit, never before (the bus has no replay log): tell watching clients the
        # operative plan changed so they refetch the swapped-in version. Same advisory shape the
        # worker publishes; _publish_plan_result never raises.
        treatment._publish_plan_result({"SessionID": session_id, "OutputID": output_id},
                                       plan_id, StageStatus.COMPLETE)
    log.info("treatment.reviewed", plan_id=plan_id, decision=str(body.decision),
             swapped=swapped, user=principal.user_id)
    return TreatmentReviewResponse(plan_id=plan_id, review_status=str(body.decision),
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
                                include_plan: bool = Query(
                                    False, description="Also return each plan's content — the "
                                                       "same trimmed object as the single-plan "
                                                       "GET. Null on rows with no generated "
                                                       "content (RUNNING/ERROR)."),
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
                                    risk_level=risk_level, include_plan=include_plan,
                                    limit=limit, offset=offset)
        items = []
        for r in rows:
            if include_plan:
                # The poll GET's own presenter renders the detail — one projection, two pages,
                # so the register can never disagree with GET .../treatment-plan.
                ps = _plan_status_from_row(r, stale_cutoff)
                items.append(TreatmentRegisterRow(
                    plan_id=ps.plan_id, session_id=ps.session_id, output_id=ps.output_id,
                    asset_name=r["AssetName"], scenario_title=r["ScenarioTitle"],
                    status=ps.status, risk_level=ps.risk_level,
                    review_status=ps.review_status, reviewed_by=ps.reviewed_by,
                    error_message=ps.error_message, reason=ps.reason,
                    scenario=ps.scenario, treatment_strategy=ps.treatment_strategy,
                    risk_identification_date=ps.risk_identification_date, plan=ps.plan,
                    created_at=ps.created_at, completed_at=ps.completed_at))
                continue
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
