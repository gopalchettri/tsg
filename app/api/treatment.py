"""Risk Treatment Plan routes — docs/RISK_TREATMENT_PLAN_SDD.md §5/§6.1.

Mounted by app/main.py ONLY when settings.risk_module_enabled (flag off → these paths 404 by
absence, zero handler code; the flag arms nothing else — no external tables are required).
Both routes are registered in app/api/route_audit.py::_ENTITY_SCOPED_ROUTES — registry entries
for an unmounted router are inert, but a mounted route missing from the registry fails boot.

POST takes the register's risk data IN the request body (TSG reads NO risk-module tables),
freezes it with TSG's own scenario/asset context into InputSnapshotJSON, inserts the RUNNING
plan row and enqueues; the GET on the same path is the poll endpoint (no separate job-status
route). The filtered unique index UX_TreatmentPlan_ActiveScenario — not any SELECT — is the
concurrent-POST arbiter.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.exc import IntegrityError

from app.api.deps import Principal, get_principal
from app.api.schemas import (
    UNAVAILABLE_RESPONSES,
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
    TreatmentPlanStatusSummary,
    TreatmentRegisterPage,
    TreatmentRegisterRow,
    TreatmentReviewBody,
    TreatmentReviewResponse,
)
from app.api.sessions import (
    _actor_ids_from_blobs,
    _controls_by_output,
    get_authorized_session,
)

# The presenter (row -> wire model) and its folds live in treatment_presenter.py. Imported by
# NAME and re-exported on purpose (noqa: F401): tests and the export consume several of these
# through this module, and the presenter never imports treatment.py back.
from app.api.treatment_presenter import (  # noqa: F401
    _SCENARIO_ECHO_KEYS,
    _TIMED_OUT_MESSAGE,
    _VISIBLE_PLAN_KEYS,
    _board_progress,
    _naive_utc,
    _normalize_plan_shape,
    _plan_status_from_row,
    _present_status,
    _progress_of,
    _safe_json_dict,
    _scenario_echo,
    _visible_plan,
)
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
from app.pipeline.tasks import ASSET_UNIT_ID

log = get_logger(__name__)

router = APIRouter(prefix="/v1", tags=["Remediation Plans"])

# Same declaration idea as sessions._CONFLICT_RESPONSES: typing the 409 puts
# TreatmentGateReason into /openapi.json so the UI can generate the reason codes.
_CONFLICT_RESPONSES: dict[int | str, dict] = {
    409: {"model": ErrorResponse, "description": "Conflict — see details.reason."}}


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


def enqueue_treatment_plan(plan_id: str, entity_id: str, user_id: str | None) -> None:
    """Indirection so tests can run the generation synchronously instead of via a broker."""
    generate_treatment_plan_task.apply_async(args=(plan_id,), shadow=(
        f"treatment-plan: {plan_id} · entity {entity_id} · by {user_id} · "
        f"{dal.now():%Y-%m-%d %H:%M} UTC"))


@router.post("/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan", status_code=202,
            response_model=TreatmentPlanAccepted,
            responses=_CONFLICT_RESPONSES | UNAVAILABLE_RESPONSES,
            summary="Request a remediation plan",
            description=(
                "Asks the AI to write the FIRST remediation plan for one accepted scenario.\n\n"
                "**Before you call:** the scenario must be accepted. This endpoint is first-generation only — "
                "if any plan already exists for the scenario, whatever its state, this fails with "
                "`plan_already_exists` and you must use the regenerate endpoint instead.\n\n"
                "**What to send:** your risk register's own scoring data. TSG stores none of it, so it "
                "travels in this body and is frozen into the plan. Five fields are required: "
                "`existing_controls` (may be an empty list, but the key must be present), "
                "`likelihood_rating`, `impact_rating`, `final_risk_rating` and `risk_level`.\n\n"
                "**What you get:** `202` with a `plan_id`. Queued, not written — poll the status endpoint "
                "until `progress.overall` leaves `generating`.\n\n"
                "**If the queue is unreachable you get `503`, and a plan row has ALREADY been created** and "
                "parked in error. Retrying this endpoint then fails with `plan_already_exists`; the way back "
                "is the regenerate endpoint.\n\n"
                "Other limits worth knowing: `existing_controls` takes at most 50 entries of at most 500 "
                "characters each, and the two mitigation dates must be sent together, end on or after start."
            ))
def post_treatment_plan(session_id: str, scenario_id: str, body: TreatmentPlanBody,
                        principal: Principal = Depends(get_principal)) -> TreatmentPlanAccepted:
    """FIRST generation of the Mitigate treatment plan for one ACCEPTED scenario. The register's
    risk data arrives IN the body (TSG reads no risk-module tables); everything is frozen into
    the snapshot at insert — the worker and the GET only ever see that snapshot.

    If ANY plan already exists for the scenario (whatever its status) → 409 plan_already_exists:
    every later version is minted by POST .../treatment-plan/regenerate, which reuses the frozen
    register data and takes an empty body. (BREAKING wire change from the old re-POST
    semantics — see docs/TSG_UI_API_INTEGRATION.md.) Two concurrent first-creates both pass the
    read below; UX_TreatmentPlan_ActiveScenario arbitrates the insert race (loser → 409, same as
    always)."""
    return _launch_generation(
        session_id, scenario_id, principal,
        risk_input=body.model_dump(mode="json"),
        risk_level=str(body.risk_level), risk_identification_date=body.risk_identification_date,
        first_generation=True)


@router.post("/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/regenerate",
            status_code=202, response_model=TreatmentPlanAccepted,
            responses=_CONFLICT_RESPONSES | UNAVAILABLE_RESPONSES,
            summary="Regenerate a remediation plan",
            description=(
                "Creates a new version of a plan that already exists. Every version after the first is minted "
                "here — the request endpoint refuses once any plan exists.\n\n"
                "**Before you call:** a plan must already have been requested for this scenario, and the "
                "scenario must still be accepted. Send a literal empty object `{}` as the body; any key at "
                "all is rejected.\n\n"
                "**You do not resend your risk data.** It is reused from the snapshot frozen at the first "
                "request. Only the scenario and control half is rebuilt against whatever they are now.\n\n"
                "**What you get:** `202` with a NEW `plan_id`. The previous version is retired, not deleted, "
                "and remains readable. Calling again while a regeneration is still running fails with "
                "`generation_in_progress`. A `503` means the queue was unreachable and the new version is "
                "parked in error — another regenerate is the way back."
            ))
def post_regenerate_treatment_plan(session_id: str, scenario_id: str, body: TreatmentPlanRegenerateBody,
                                principal: Principal = Depends(get_principal)) -> TreatmentPlanAccepted:
    """Regenerate the plan: retire the ACTIVE version, generate a new one. The register risk data
    is reused from the active version's frozen snapshot (the client never resends it; if the
    register itself changed, that is a documented
    limitation of this shape). Baseline is the ACTIVE row, never newest-by-CreatedAt, so a
    version switched back in by an approve is what a later regenerate builds on. Fresh RUNNING →
    409 generation_in_progress; no plan ever generated → 404.

    The body is empty (`{}`) — see TreatmentPlanRegenerateBody. With nothing to steer on, a
    regeneration is a REFRESH against the current scenario/controls, which build_treatment_input
    rebuilds every time."""
    return _launch_generation(session_id, scenario_id, principal, first_generation=False)


def _launch_generation(session_id: str, scenario_id: str, principal: Principal, *,
                    first_generation: bool,
                    risk_input: dict | None = None, risk_level: str | None = None,
                    risk_identification_date=None) -> TreatmentPlanAccepted:
    """Shared create/regenerate implementation — the split is at the route layer only.

    `first_generation` gates on "no plan rows exist" (the exactly-one-active invariant makes
    the active-row read a complete existence check). REGENERATE passes none of the risk_* args:
    it reads them from the active version's frozen snapshot below, inside THIS transaction. That
    read used to sit in a second, earlier transaction in the route, which re-ran
    get_authorized_session and paid an extra round trip for one logical action; folding it in also
    narrows the window between reading the baseline and superseding it. The fence (the baseline's
    own PlanID) still arbitrates: the retire targets exactly the row whose snapshot was read, or
    fails the CAS."""
    with db_session() as sess:
        # Called for its SIDE EFFECT — this raises on an unauthorized caller and IS the
        # authorization boundary. The return value is unused: the board load behind it omits
        # the JSON blobs, so the full row is re-read via dal.load_session just below.
        get_authorized_session(sess, session_id, principal)

        fence_plan_id: str | None = None
        if not first_generation:
            # ORDER MATTERS: this runs BEFORE the accept gate below, matching what the old
            # two-transaction split enforced — a scenario with no plan at all 404s even when it is
            # also not accepted. Moving it after that gate would silently turn those 404s into
            # 409s. One narrow read: id + the two column stamps + the snapshot.
            base = dal.active_plan_baseline(sess, session_id, scenario_id)
            if base is None:
                raise dal.NotFoundError("no treatment plan has been requested for this scenario")
            risk_input = treatment.regen_risk_input_from_snapshot(
                treatment._loads(base["InputSnapshotJSON"], {}))
            risk_level = base["RiskLevel"]
            risk_identification_date = base["RiskIdentificationDate"]
            fence_plan_id = str(base["PlanID"])

        # Full session row — the board load behind get_authorized_session deliberately omits
        # the AssetContextJSON/SubsystemsJSON blobs the snapshot needs.
        session_row = dal.load_session(sess, session_id)
        if session_row is None:  # unreachable (board load above 404'd; same PK, same txn) —
            raise dal.NotFoundError("session not found")  # but assert would vanish under -O

        scn = dal.scenario_row(sess, session_id, scenario_id)
        if scn is None:
            raise dal.NotFoundError("scenario not found in this session")
        # No Superseded gate: the accepted version may be an older, superseded one (Accepted is
        # decoupled from generation recency). TreatmentGateReason.scenario_superseded is retired
        # — kept in the enum for wire-compat, never raised.
        if scn["Accepted"] != 1:
            raise _conflict(TreatmentGateReason.scenario_not_accepted)

        if first_generation and dal.active_plan_row(sess, session_id, scenario_id) is not None:
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
            if dal.supersede_active_plan(sess, scn["ScenarioID"], stale_cutoff,
                                        plan_id=fence_plan_id) == 0:
                # Fresh RUNNING generation, or the active row changed since the route read it
                # (fence miss) — either way, generation state moved; this request must not act.
                raise _conflict(TreatmentGateReason.generation_in_progress)
        try:
            dal.insert_row(sess, m.Risk_Treatment_Plan, {
                "PlanID": plan_id, "SessionID": session_id, "ScenarioID": scn["ScenarioID"],
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
            # scenario_id on the COLUMN, not only inside DetailJSON. IX_ScenarioAudit_Scenario is a
            # FILTERED index (WHERE scenario_id IS NOT NULL), so leaving it null excluded these rows
            # from it entirely — which is why the per-scenario trail had to fetch the whole
            # session and narrow in Python ("DetailJSON is opaque to SQL here").
            ScenarioID=scn["ScenarioID"], PlanID=plan_id,
            DetailJSON=json.dumps({"plan_id": plan_id, "scenario_id": scn["ScenarioID"]}))

    # Enqueue OUTSIDE the db_session block (Pattern A). A failed enqueue must not wedge the
    # scenario_id behind the staleness window: park the committed RUNNING row in ERROR, then answer
    # 503 — SDD §6.1 step 8.
    #
    # 503, not a bare re-raise: the broker being briefly unreachable is not a bug in this service,
    # and a 500 tells the client "our code is broken, don't retry" for a condition that is
    # transient and retryable. The three sibling sites for this exact failure already answer 503
    # (create_session above, and _recover_from_enqueue_failure for regenerate/next-set), and
    # sessions.py's comment there names THIS function as the pattern it copied — so the bare
    # re-raise was the outlier, not the convention. No Retry-After: none of the siblings set one
    # (only the capacity handlers in errors.py do), and adding it here alone would just move the
    # inconsistency rather than remove it.
    try:
        enqueue_treatment_plan(plan_id, str(session_row["EntityID"]), principal.user_id)
    except Exception as exc:
        with db_session() as sess:
            # task_id=None: nothing has claimed this row yet (inserted with ActiveTaskID=None
            # above), so only finish it if that's still true.
            dal.finish_plan(sess, plan_id, status=StageStatus.ERROR, task_id=None,
                            error_message="failed to queue generation — regenerate it "
                                        "(POST .../treatment-plan/regenerate)",
                            error_reason=TreatmentOutcomeReason.enqueue_failed)
        # .exception, not .error(exc_info=True): same traceback, and the form ruff's G201 wants.
        # The traceback is the ONLY record of why the broker refused — the 503 detail is a fixed
        # string, so nothing about the cause reaches the client.
        log.exception("treatment.enqueue_failed", plan_id=plan_id)
        raise HTTPException(
            status_code=503,
            detail=f"treatment plan {plan_id} could not be queued for processing — regenerate it "
                "(POST .../treatment-plan/regenerate)",
        ) from exc
    return TreatmentPlanAccepted(plan_id=plan_id, session_id=session_id,
                                scenario_id=scn["ScenarioID"], status=str(StageStatus.RUNNING))


@router.get("/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/status",
            response_model=TreatmentPlanStatusSummary,
            summary="Check a remediation plan's status",
            description=(
                "The cheap poll: lifecycle and review state only, with no plan content, scenario or threat "
                "attached.\n\n"
                "**Call it:** on a timer after requesting or regenerating a plan, until `progress.overall` "
                "leaves `generating`. Switch to the full plan endpoint once you actually need the content — "
                "polling that one instead re-downloads the whole document every tick.\n\n"
                "**Switch your UI on `progress.overall`:** `generating` shows a spinner, `awaiting_review` "
                "offers Review, `rejected` offers Regenerate, `approved` is done, `error` offers Retry.\n\n"
                "**Watch out:** a `404` here is not an error. It means no plan was ever requested for this "
                "scenario, which is the 'pending' state — show a Generate button."
            ))
def get_treatment_plan_status(session_id: str, scenario_id: str,
                            principal: Principal = Depends(get_principal)
                            ) -> TreatmentPlanStatusSummary:
    """One scenario's remediation lifecycle — the plan-side counterpart of
    GET /v1/sessions/{session_id}.

    Answers "where is this plan" and nothing else: no plan content, no scenario, no threat. Poll
    this on a timer while a plan generates; call GET .../treatment-plan once it is COMPLETE to
    fetch the plan itself. The split is the point — that endpoint returns the whole PlanJSON,
    which is tens of KB a poller re-downloads on every tick for three strings it actually reads.

    Switch on `progress.overall`: pending -> Generate, generating -> spinner, awaiting_review ->
    Review, rejected -> Regenerate, approved -> done, error -> Retry. It is folded by the SAME
    function the session board uses, so this and GET /v1/sessions/{id}/treatment-plans can never
    disagree about one plan.

    404 when no plan has ever been requested for this scenario — that is the `pending` state,
    and it is why `pending` never appears in a 200 here. A stale RUNNING row is PRESENTED as
    ERROR/timed-out exactly as the full GET does; the stored Status is not rewritten.
    """
    with db_session() as sess:
        get_authorized_session(sess, session_id, principal)
        row = dal.plan_status_row(sess, session_id, scenario_id)
        if row is None:
            raise dal.NotFoundError("no treatment plan has been requested for this scenario")
        status, err, reason = _present_status(row["Status"], row["ErrorMessage"],
                                            row["UpdatedAt"], treatment._stale_cutoff(),
                                            row["ErrorReason"])
        return TreatmentPlanStatusSummary(
            session_id=row["SessionID"], scenario_id=row["ScenarioID"], plan_id=row["PlanID"],
            progress=_progress_of([(row["PlanID"], status, row["ReviewStatus"])]),
            status=status, review_status=row["ReviewStatus"], reviewed_by=row["ReviewedBy"],
            reviewed_at=row["ReviewedAt"], created_by=row["UserID"],
            error_message=err, reason=reason,
            created_at=row["CreatedAt"], updated_at=row["UpdatedAt"],
            completed_at=row["CompletedAt"])


@router.get("/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan",
            response_model=TreatmentPlanStatus,
            summary="Read a remediation plan",
            description=(
                "The plan itself: the recommended controls, the numbered action list with owners and target "
                "dates, and the timeline — plus the scenario, threat, adversaries and mapped controls, so a "
                "reviewer never has to cross-reference another screen.\n\n"
                "**Call it:** once the status reads `COMPLETE`. It also works while running or after a "
                "failure, where `plan` is simply null.\n\n"
                "**History:** add `?include_superseded=true` to also get every version you regenerated away, "
                "newest first. Each is a full entry with its own plan and review verdict.\n\n"
                "**Watch out:** check `warnings` before treating a completed plan as ready to act on. A plan "
                "can complete with an empty action list and a warning saying so."
            ))
def get_treatment_plan(session_id: str, scenario_id: str,
                    include_superseded: bool = Query(
                        False, description="Also return every regenerated-away version of "
                                            "this plan under `superseded`, newest first."),
                    principal: Principal = Depends(get_principal)) -> TreatmentPlanStatus:
    """The poll endpoint — the scenario's one active plan row. 404 when no plan has ever been
    requested for this scenario. A stale RUNNING row is PRESENTED as ERROR/timed-out; the
    stored Status is not rewritten (no reaper — the next POST supersedes it instead).

    ?include_superseded=true additionally serves the regeneration history: the same top-level
    response (the current plan) plus `superseded` — every replaced version, newest first,
    rendered by the same presenter (same trim, same staleness projection). Every history item is
    a FULL entry: its own plan, review verdict, created_by, cancelled_*, warnings and
    moderation_flagged, plus the scenario/threat/actors/controls blocks — those four are
    version-independent, so they are read ONCE for the active row and overlaid onto each history
    item rather than re-queried per version. Only `progress` is null on them: a retired version
    is history, not a live lifecycle. Default off keeps the hot polling path's single-row
    query untouched.

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
        row = dal.active_plan_row(sess, session_id, scenario_id)
        if row is None:
            raise dal.NotFoundError("no treatment plan has been requested for this scenario")
        # ONE cutoff for the current row and every history row (see _present_status).
        stale_cutoff = treatment._stale_cutoff()
        # ONE batched resolve for this response. _actor_ids_from_blobs prefers the ids Stage 1
        # STORED in the blob (zero queries) and only falls back to a name lookup for legacy rows.
        actor_ids = _actor_ids_from_blobs(sess, [row.get("ThreatActorsJSON")])
        # One batched read for this scenario's controls — the same source /results uses, so the
        # two screens cannot disagree about which controls the scenario has.
        # The WHOLE read goes to the presenter — the list AND whether the read happened — and the
        # presenter keys the lookup by the ROW's ScenarioID, not this URL parameter (which nothing
        # canonicalises: an upper-case id used to render every block except an empty `controls`).
        controls = _controls_by_output(sess, [scenario_id])
        older = None
        if include_superseded:
            # History rows carry no scenario/threat join — the scenario is version-independent,
            # so overlay the ACTIVE row's single copy rather than re-selecting the same multi-KB
            # blob once per version. The history row's own keys win (`{**echo, **r}`), so its
            # per-version fields — created_by, cancelled_*, warnings, moderation_flagged — are
            # never clobbered by the current version's. `controls` is the list already read
            # above: same scenario, so the same controls, at no extra query.
            echo = _scenario_echo(row)
            # PlanID guard: two SELECTs under READ COMMITTED — a regeneration committing
            # between them would supersede the row just read as current, making it show up in
            # BOTH places on one response. Dropping it here keeps the reply self-consistent.
            older = [_plan_status_from_row({**echo, **r}, stale_cutoff, actor_ids, controls,
                                           superseded_row=True)
                    for r in dal.superseded_plan_rows(sess, session_id, scenario_id)
                    if r["PlanID"] != row["PlanID"]]
        return _plan_status_from_row(row, stale_cutoff, actor_ids, controls, superseded=older)


_CANCELLED_MESSAGE = "cancelled by user"

#: Wire labels for the audit feeds — short verbs, not internal enum names.
_EVENT_LABELS = {
    str(AuditEventType.treatment_plan_requested): "requested",
    str(AuditEventType.treatment_plan_outcome): "outcome",
    str(AuditEventType.treatment_plan_cancelled): "cancelled",
    str(AuditEventType.treatment_plan_reviewed): "reviewed",
    str(AuditEventType.treatment_plan_version_restored): "version restored",
}


@router.get("/sessions/{session_id}/treatment-plans", response_model=TreatmentBoard,
            summary="List a session's remediation plans",
            description=(
                "Every accepted scenario in the session with its plan state, in one call. This replaces "
                "polling each scenario separately.\n\n"
                "**Call it:** any time, including on a session with nothing accepted — that returns `200` "
                "with an empty list, never a `404`.\n\n"
                "**Reading the result:** a scenario with no plan yet has `plan_id`, `status` and the rest all "
                "null together, which is your Generate state. They are never partially filled.\n\n"
                "**Watch out:** the session-level `progress` can read `generating` even when every plan you "
                "can see is finished and approved. An accepted scenario with no plan requested at all counts "
                "as generation still outstanding, which is correct — otherwise your UI would stop offering "
                "Generate while a risk had no plan.\n\n"
                "Add `?include_plan=true` for each plan's content and `?include_superseded=true` for version "
                "history."
            ))
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
            hist_rows = dal.superseded_plan_rows(sess, session_id)
            # Only regenerated scenarios have history — typically a few of many — so the scenario
            # echo, the actor resolve and the controls read are TARGETED at those ids rather than
            # widened across the whole board: bytes scale with regenerations, not with the
            # session. scenario_echo_rows is the canonical scenario select, so each history row
            # gets the same `{**echo, **row}` overlay the single-plan GET applies and the two
            # surfaces serve identical entries. All three helpers are no-query on an empty list.
            ids = sorted({str(h["ScenarioID"]) for h in hist_rows})
            echo_rows = dal.scenario_echo_rows(sess, session_id, ids)
            echo = {str(e["ScenarioID"]): _scenario_echo(e) for e in echo_rows}
            actor_ids = _actor_ids_from_blobs(sess, [e.get("ThreatActorsJSON") for e in echo_rows])
            ctl = _controls_by_output(sess, ids)
            for h in hist_rows:
                history.setdefault(h["ScenarioID"], []).append(
                    _plan_status_from_row({**echo.get(str(h["ScenarioID"]), {}), **h}, stale_cutoff,
                                          actor_ids, ctl, superseded_row=True))
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
                scenario_id=r["ScenarioID"], scenario_title=r["ScenarioTitle"],
                plan_id=r["PlanID"], status=status, risk_level=r["RiskLevel"],
                review_status=r["ReviewStatus"], error_message=err, reason=reason,
                # PlanID guard: never-requested rows have NULL plan columns (and without the
                # flag the row carries no PlanJSON key at all).
                plan=(_visible_plan(r["PlanJSON"], r["PlanID"])
                    if include_plan and r["PlanID"] is not None else None),
                # Same READ-COMMITTED guard as the single GET: a regeneration committing
                # between the two SELECTs must not list one PlanID as both current and history.
                superseded=([e for e in history.get(r["ScenarioID"], [])
                            if e.plan_id != r["PlanID"]]
                            if include_superseded else None),
                created_at=r["PlanCreatedAt"], completed_at=r["PlanCompletedAt"]))
    return TreatmentBoard(session_id=session_id, accepted_scenarios=len(rows),
                          progress=_board_progress(plans), plans=plans)


@router.post("/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/cancel",
            response_model=TreatmentCancelResponse, responses=_CONFLICT_RESPONSES,
            summary="Cancel a running plan generation",
            description=(
                "The stop button: immediately marks a generation that is still running as failed, instead of "
                "waiting out the staleness timeout after a mistaken click.\n\n"
                "**Before you call:** the plan must genuinely still be running. If it already finished, or "
                "the worker's own completion beat you by a moment, you get a conflict rather than a silent "
                "no-op.\n\n"
                "**What happens:** the plan row is never deleted. Cancelling marks it failed but does NOT "
                "abort the AI call already in flight — that call runs to completion and is still billed, its "
                "result simply discarded. Recover by regenerating."
            ))
def post_cancel_treatment_plan(session_id: str, scenario_id: str,
                            principal: Principal = Depends(get_principal)) -> TreatmentCancelResponse:
    """The stop button: flip a RUNNING generation to ERROR right now, instead of waiting out
    the staleness window after a mistaken click. Fenced by finish_plan's CAS — if the worker
    finished first (or nothing is running), 409 not_in_progress and nothing changes."""
    with db_session() as sess:
        get_authorized_session(sess, session_id, principal)
        row = dal.active_plan_row(sess, session_id, scenario_id)
        if row is None:
            raise dal.NotFoundError("no treatment plan has been requested for this scenario")
        # task_id=row["ActiveTaskID"]: whoever currently holds it, whatever that is — closes a
        # TOCTOU window where a worker reclaims the row between this SELECT and the UPDATE below.
        if row["Status"] != str(StageStatus.RUNNING) or not dal.finish_plan(
                sess, row["PlanID"], status=StageStatus.ERROR, task_id=row["ActiveTaskID"],
                error_message=_CANCELLED_MESSAGE,
                error_reason=TreatmentOutcomeReason.cancelled,
                # Marks this as a CANCELLATION rather than an ordinary ERROR: finish_plan only
                # stamps CancelledAt/CancelledBy when this is passed, so the generic failure
                # paths through the same function stay untouched.
                cancelled_by=principal.user_id):
            raise _conflict(TreatmentGateReason.not_in_progress)
        dal.append_audit(
            sess, AuditID=dal.guid(), SessionID=session_id, TenantID=row["TenantID"],
            EntityID=row["EntityID"], SubsystemID=ASSET_UNIT_ID,
            EventType=AuditEventType.treatment_plan_cancelled, ActorUserID=principal.user_id,
            ScenarioID=scenario_id, PlanID=row["PlanID"],
            DetailJSON=json.dumps({"plan_id": row["PlanID"],
                                "reason": str(TreatmentOutcomeReason.cancelled)}))
    log.info("treatment.cancelled", plan_id=row["PlanID"], user=principal.user_id)
    return TreatmentCancelResponse(plan_id=row["PlanID"], status=str(StageStatus.ERROR),
                                error_message=_CANCELLED_MESSAGE)


@router.post("/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/review",
            response_model=TreatmentReviewResponse, responses=_CONFLICT_RESPONSES,
            summary="Approve or decline a remediation plan",
            description=(
                "Records a human's verdict on a plan. This is the decision a regulator would ask to see.\n\n"
                "**Before you call:** the plan version you are deciding on must be complete.\n\n"
                "**`plan_id` is required and names the version you actually read.** This is deliberate: "
                "without it, a regeneration landing between your read and this call could move your verdict "
                "onto a plan nobody looked at. Omitting it is a `422`.\n\n"
                "**Switching versions:** passing an OLD version's `plan_id` with `approved` makes that "
                "version current again and approves it, in one step. Passing an old id with `rejected` is "
                "refused — it is already not the active plan, and doing it while a fresh regeneration is "
                "still running is refused with `generation_in_progress`. A `plan_id` that is not a version of "
                "this scenario at all is a `404`.\n\n"
                "`reviewed_by` always comes from your `X-User-Id` header; there is no reviewer field in the "
                "body, so nobody can review as someone else. Re-reviewing overwrites the previous verdict."
            ))
def post_review_treatment_plan(session_id: str, scenario_id: str, body: TreatmentReviewBody,
                            principal: Principal = Depends(get_principal)) -> TreatmentReviewResponse:
    """Record the human adoption decision. `plan_id` is REQUIRED — a verdict always names the
    version it applies to, so a regeneration landing between the reviewer's GET and this POST
    can never redirect it onto a plan nobody read. With the ACTIVE plan's id: the verdict lands
    on it — a re-review overwrites (latest wins), and a regenerated plan always starts
    unreviewed. With a HISTORICAL plan_id and decision=approved:
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
        row = dal.active_plan_row(sess, session_id, scenario_id)
        if row is None:
            raise dal.NotFoundError("no treatment plan has been requested for this scenario")

        target_id = body.plan_id  # canonicalized at the schema boundary; row ids canonical too
        if target_id != str(row["PlanID"]):
            # --- Version-switch branch: verdict targets a historical version ---
            if not dal.plan_version_exists(sess, session_id, scenario_id, target_id):
                raise dal.NotFoundError("no such plan version for this scenario")
            if body.decision != TreatmentReviewStatus.approved:
                raise _conflict(TreatmentGateReason.version_not_active)
            # Retire the active row, fenced to the exact row read above — a racing
            # regenerate/switch misses the CAS; a fresh RUNNING generation matches nothing.
            if not dal.supersede_active_plan(sess, scenario_id, treatment._stale_cutoff(),
                                            plan_id=str(row["PlanID"])):
                raise _conflict(TreatmentGateReason.generation_in_progress)
            # Reactivate the target (CAS: Superseded=1 AND COMPLETE). A miss rolls the retire
            # back too — this pair is the only writer that could otherwise leave the scenario
            # with ZERO active rows. The UPDATE executes immediately (execute_dml), so a
            # filtered-unique violation would raise HERE, not at a later flush — though the
            # plan_id-fenced retire above already precludes it (any concurrent activator must
            # first win that same retire), so the except is belt-and-braces, not the guard.
            try:
                reactivated = dal.reactivate_plan_version(sess, session_id, scenario_id, target_id)
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
                ScenarioID=scenario_id, PlanID=plan_id,
                # `plan_id` key REQUIRED: the per-scenario trail filters on it.
                DetailJSON=json.dumps({"plan_id": plan_id,
                                    "retired_plan_id": str(row["PlanID"]),
                                    "scenario_id": scenario_id}))
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
            ScenarioID=scenario_id, PlanID=plan_id,
            DetailJSON=json.dumps({"plan_id": plan_id, "decision": str(body.decision),
                                   **({"comment": comment} if comment else {})}))
    if swapped:
        # After the commit, never before (the bus has no replay log): tell watching clients the
        # operative plan changed so they refetch the swapped-in version. Same advisory shape the
        # worker publishes; _publish_plan_result never raises.
        treatment._publish_plan_result({"SessionID": session_id, "ScenarioID": scenario_id},
                                    plan_id, StageStatus.COMPLETE)
    log.info("treatment.reviewed", plan_id=plan_id, decision=str(body.decision),
            swapped=swapped, user=principal.user_id)
    return TreatmentReviewResponse(plan_id=plan_id, review_status=str(body.decision),
                                reviewed_by=principal.user_id, reviewed_at=reviewed_at)


@router.get("/entities/{entity_id}/treatment-plans", response_model=TreatmentRegisterPage,
            summary="List an entity's remediation plans",
            description=(
                "Each scenario's CURRENT plan version across every session and asset for one entity, newest "
                "first. This is the page that answers 'which Critical risks still have no approved plan?'. "
                "Versions you regenerated away are not listed here — read those per scenario with "
                "`?include_superseded=true`.\n\n"
                "**Before you call:** the `entity_id` in the path must match your `X-Entity-Id` header.\n\n"
                "**Filters:** `status` (`RUNNING`, `COMPLETE`, `ERROR`), `review_status` (`approved`, "
                "`rejected`), `risk_level` (`Low`, `Medium`, `High`, `Critical`), plus `limit` (max 500) and "
                "`offset`.\n\n"
                "By default each row carries lifecycle fields only. Add `?include_plan=true` to also get the "
                "plan content and the scenario and threat behind it."
            ))
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
        # Only the include_plan branch renders a scenario/actors block, so resolve for it only.
        actor_ids = (_actor_ids_from_blobs(sess, [r.get("ThreatActorsJSON") for r in rows])
                     if include_plan else {})
        # ONE controls read for the whole page, never one per row — _controls_by_output takes a
        # list precisely so this cannot become an N+1 as the register grows.
        page_controls = (_controls_by_output(sess, [str(r["ScenarioID"]) for r in rows])
                         if include_plan else None)
        items = []
        for r in rows:
            if include_plan:
                # The poll GET's own presenter renders the detail — one projection, two pages,
                # so the register can never disagree with GET .../treatment-plan.
                ps = _plan_status_from_row(r, stale_cutoff, actor_ids, page_controls)
                items.append(TreatmentRegisterRow(
                    plan_id=ps.plan_id, session_id=ps.session_id, scenario_id=ps.scenario_id,
                    asset_name=r["AssetName"], scenario_title=r["ScenarioTitle"],
                    status=ps.status, risk_level=ps.risk_level,
                    review_status=ps.review_status, reviewed_by=ps.reviewed_by,
                    error_message=ps.error_message, reason=ps.reason,
                    scenario=ps.scenario, threat=ps.threat, actors=ps.actors,
                    controls=ps.controls, controls_unavailable=ps.controls_unavailable,
                    treatment_strategy=ps.treatment_strategy,
                    risk_identification_date=ps.risk_identification_date, plan=ps.plan,
                    created_at=ps.created_at, completed_at=ps.completed_at))
                continue
            st, err, reason = _present_status(r["Status"], r["ErrorMessage"], r["UpdatedAt"],
                                            stale_cutoff, r["ErrorReason"])
            items.append(TreatmentRegisterRow(
                plan_id=r["PlanID"], session_id=r["SessionID"], scenario_id=r["ScenarioID"],
                asset_name=r["AssetName"], scenario_title=r["ScenarioTitle"],
                status=st, risk_level=r["RiskLevel"], review_status=r["ReviewStatus"],
                reviewed_by=r["ReviewedBy"], error_message=err, reason=reason,
                created_at=r["CreatedAt"], completed_at=r["CompletedAt"]))
    return TreatmentRegisterPage(entity_id=entity_id, limit=limit, offset=offset, plans=items)


@router.get("/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/audit",
            response_model=TreatmentAuditTrail,
            summary="Read one scenario's plan history",
            description=(
                "Every remediation-plan event for one scenario, across all its versions, oldest first: who "
                "requested each plan, how each generation ended, cancellations, review verdicts and version "
                "switches.\n\n"
                "**Call it:** when investigating a declined plan, answering an audit request, or working out "
                "why a plan looks the way it does.\n\n"
                "**Watch out:** a `404` means no plan was ever requested for this scenario. Events recorded "
                "before per-scenario stamping shipped carry no scenario id and do not appear here — the "
                "entity-wide feed still returns them."
            ))
def get_treatment_plan_audit(session_id: str, scenario_id: str,
                            principal: Principal = Depends(get_principal)) -> TreatmentAuditTrail:
    """One scenario's plan life story across ALL versions, oldest first: requested (by whom),
    each attempt's outcome, cancels, reviews — plus synthesized 'superseded' entries from the
    never-deleted version chain."""
    with db_session() as sess:
        get_authorized_session(sess, session_id, principal)
        history = dal.plan_history_rows(sess, session_id, scenario_id)
        if not history:
            raise dal.NotFoundError("no treatment plan has been requested for this scenario")
        events = []
        # Narrowed in SQL on the indexed ScenarioID column, not in Python on a DetailJSON key.
        # This used to fetch EVERY treatment event of the whole session and discard the other
        # scenarios' rows here — unbounded, and only necessary because the writers left ScenarioID
        # NULL so SQL had nothing to filter on. They stamp it now, so this is a seek.
        # Equivalent by construction: the rows for this scenario are exactly the rows whose plan
        # versions are in `history`, which is itself keyed by (session_id, scenario_id).
        for a in dal.treatment_audit_rows(sess, session_id, scenario_id):
            detail = _safe_json_dict(a["DetailJSON"], "-") or {}
            events.append(TreatmentAuditEvent(
                at=a["CreatedAt"], event=_EVENT_LABELS.get(a["EventType"], a["EventType"]),
                actor=a["ActorUserID"], actor_type=a["ActorType"], detail=detail))
        for r in history:
            if r["Superseded"]:
                events.append(TreatmentAuditEvent(
                    at=r["UpdatedAt"], event="superseded", detail={"plan_id": r["PlanID"]}))
        events.sort(key=lambda e: (e.at is None, e.at))
    return TreatmentAuditTrail(session_id=session_id, scenario_id=scenario_id, events=events)


@router.get("/entities/{entity_id}/treatment-plans/audit",
            response_model=TreatmentEntityAuditPage,
            summary="Read an entity's plan activity",
            description=(
                "Every remediation-plan action across the whole entity, newest first. This is the compliance "
                "export.\n\n"
                "**Before you call:** the `entity_id` in the path must match your `X-Entity-Id` header.\n\n"
                "**Filters:** `from` and `to` bound the time window and accept any UTC offset, `user_id` "
                "narrows to one person, and `limit` (max 1000) with `offset` pages the result.\n\n"
                "Unlike the per-scenario trail, every event here carries its `session_id`, because one page "
                "mixes events from many sessions."
            ))
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


@router.get("/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/evidence",
            response_model=TreatmentEvidence,
            summary="Get a plan version's evidence bundle",
            description=(
                "The receipt for one plan version: the exact frozen input the AI was given, the validation "
                "and moderation record, and every raw AI prompt and response.\n\n"
                "**Required:** the `version` query parameter, naming the exact `plan_id` to inspect. A "
                "version you replaced long ago is fine — evidence survives regeneration.\n\n"
                "**Call it:** when a plan is challenged, or to work out why one generation produced a "
                "different answer from another.\n\n"
                "**Watch out:** `status` here is the raw stored value, deliberately not reinterpreted. A plan "
                "the status endpoint presents as timed-out may still read `RUNNING` here, because an audit "
                "record must not be rewritten at read time. An old plan can legitimately return an empty "
                "attempt list if it predates prompt linking."
            ))
def get_treatment_plan_evidence(session_id: str, scenario_id: str,
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
        row = dal.plan_row_by_id(sess, session_id, scenario_id, version)
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
