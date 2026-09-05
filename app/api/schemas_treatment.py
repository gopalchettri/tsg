"""Wire models of the treatment-plan (remediation) surface. Split out of schemas.py in 2026-09 as
a PURE move: every model keeps its name, so the OpenAPI document is byte-identical, and every
existing `from app.api.schemas import Treatment…` keeps working (schemas.py resolves this slice
lazily). TreatmentPlanResultEvent is NOT here — it is part of the SSE event union and stays with
the other event models; the shared building blocks (ApiModel, MappedControl, ScenarioNarrative,
ThreatResult, ThreatActorRef, _canonical_guid) stay in schemas.py and are imported.
"""
from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any, Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from app.api.schemas import (  # shared helpers stay in the parent
    _MAX_BATCH,
    ApiModel,
    MappedControl,
    ScenarioNarrative,
    ThreatActorRef,
    ThreatResult,
    _canonical_guid,
)
from app.core.enums import (
    RiskLevel,
    StageStatus,
    TreatmentOutcomeReason,
    TreatmentProgress,
    TreatmentReviewStatus,
    TreatmentStageStatus,
    YesNo,
)


class TreatmentPlanDocument(ApiModel):
    """The AI-authored treatment plan, as served.

    Every field Optional and `extra="allow"` — the SAME posture as ScenarioNarrative, and for the
    same reason: this content is model-authored, it is read back from rows written by older builds,
    and a strict declaration would turn one odd stored value into a 500 on the poll endpoint rather
    than a slightly-wrong field. The model exists to NAME the shape on the wire, not to police it.

    It is also the single source of `treatment._VISIBLE_PLAN_KEYS`: that projection used to restate
    these ten names in a tuple beside the model that defines them, so a prompt change could add a
    key the API silently dropped. Declaring them once and deriving the projection removes the copy.
    """
    model_config = ConfigDict(extra="allow")

    title: Any | None = None
    treatment_plan: Any | None = None
    action_plan: Any | None = None
    applicable_to_all_subsystems: Any | None = None
    controls_to_be_implemented: Any | None = None
    remediation_action_plan: Any | None = None
    mitigation_timeline: Any | None = None
    mitigation_owner: Any | None = None
    risk_owner: Any | None = None
    impacted_business_division: Any | None = None


# --- Risk Treatment Plan generation (app/api/treatment.py, docs/RISK_TREATMENT_PLAN_SDD.md §5) ---
class TreatmentPlanBody(ApiModel):
    """POST .../scenarios/{scenario_id}/treatment-plan — the register's risk data, sent by the
    UI (TSG reads NO risk-module tables; the body is the single source). TSG extracts the
    asset/threat/scenario/mapped-controls half itself via the path's session_id + scenario_id.

    The endpoint IS the Mitigate generator — there is no strategy field; TreatmentStrategy is
    stamped server-side (TreatmentStrategy.mitigate). Register facts the AI must never invent
    (risk_identification_date, risk_owner, impacted_business_division) are optional: absent →
    the output shows null, the model is never asked to fill the gap. `user_id` is deliberately
    NOT a field — the acting user comes from the authenticated principal (see
    CreateSessionBody's rationale)."""
    # extra="forbid": an unrecognised key is a 422 naming it, never a silent drop. This is the
    # FIRST forbid model in this file (the rest take pydantic's ignore default, and ScenarioResult
    # sets allow on purpose) — deliberate here, because silent-drop is exactly how the
    # mitigation_*/timeline_* field-name mismatch stayed invisible while every request returned
    # 200 and lost its assessment window. Keys accepted-and-dropped before this flag, which now
    # 422: user_id, strategy, treatment_strategy, user_note, timeline_start_date/_end_date.
    # Rejection renders as the standard 422 envelope with errors[].type == "extra_forbidden".
    model_config = ConfigDict(extra="forbid", json_schema_extra={"example": {
        "existing_controls": ["annual patching", "network firewall"],
        "likelihood_rating": 4, "impact_rating": 5,
        "final_risk_rating": 20, "risk_level": "Critical",
        "risk_identification_date": "2026-06-14T08:31:00Z",
        "risk_owner": "Head of OT Operations",
        "impacted_business_division": "Water Treatment Operations",
        "existing_controls_all_subsystems": "No",
        "existing_controls_all_subsystems_justification": "Controls deployed on IT systems only.",
        "mitigation_start_date": "2026-07-01", "mitigation_end_date": "2026-09-30"}})

    existing_controls: list[str] = Field(
        max_length=_MAX_BATCH,
        description=("The register's controls already applied to this risk, as plain text — may "
                     "be [] (a risk with no controls), but the key must be present. The AI's "
                     "recommended controls are the scenario-identified controls NOT covered by "
                     "this list."))
    likelihood_rating: int = Field(ge=1, le=5, description="Register likelihood, 1-5.")
    impact_rating: int = Field(ge=1, le=5, description="Register impact, 1-5.")
    final_risk_rating: int = Field(
        ge=1, le=25,
        description="Register final risk rating, 1-25 (5x5 matrix). Taken as-is; never re-derived.")
    risk_level: RiskLevel = Field(description="Register risk level: Low | Medium | High | Critical.")
    risk_identification_date: datetime | None = Field(
        default=None,
        description=("When the risk was recorded in the register — echoed into the output, never "
                     "AI-generated. Normalized to UTC (naive input treated as UTC)."))
    risk_owner: str | None = Field(
        default=None, max_length=200,
        description=("Register risk owner — echoed into the output; deliberately NOT shown to "
                     "the AI (a person's name; the model must only ever name roles)."))
    impacted_business_division: str | None = Field(
        default=None, max_length=200,
        description="Impacted business division within the entity — echoed into the output.")
    existing_controls_all_subsystems: YesNo | None = Field(
        default=None,
        description=("Are the existing controls applied to ALL sub-systems? Steers the AI's own "
                     "applicable_to_all_subsystems answer and per-sub-system extension actions."))
    existing_controls_all_subsystems_justification: str | None = Field(
        default=None, max_length=1000,
        description="Free-text justification for the Yes/No above (redacted before reaching the AI).")
    mitigation_start_date: date | None = Field(
        default=None,
        description="Start of the window the ENTIRE risk assessment must complete within. "
                    "Provide together with mitigation_end_date, or neither.")
    mitigation_end_date: date | None = Field(
        default=None,
        description="End of that window. Every action's `timeline` and the overall "
                    "`mitigation_timeline` are ISO YYYY-MM-DD dates inside [start, end] — these "
                    "two dates ARE the schedule's bounds, and the plan schedules inside them "
                    "even when part of the window has already passed.")

    @field_validator("risk_identification_date", "risk_owner", "impacted_business_division",
                     "existing_controls_all_subsystems",
                     "existing_controls_all_subsystems_justification",
                     "mitigation_start_date", "mitigation_end_date", mode="before")
    @classmethod
    def _blank_is_absent(cls, v):
        """An empty string means "not provided" on every OPTIONAL field, not a validation failure.

        The UI sends "" for an unfilled control. Without this, the TYPED ones (the two dates, the
        datetime, and the YesNo enum) each 422 the ENTIRE request — the caller gets no plan at all
        rather than a plan without that value, which contradicts this model's own "absent -> the
        output shows null" contract. The two str fields are included deliberately: they ACCEPT ""
        happily, and it then survives redact() into the snapshot and back out through
        _VISIBLE_PLAN_KEYS as "" where that same contract promises null.

        `risk_level` is deliberately NOT here — it is REQUIRED, so "" there is a genuinely
        unfilled mandatory field and its 422 is the correct answer.
        mode="before" so this runs ahead of both type coercion and _validate_mitigation_window.
        """
        return None if isinstance(v, str) and not v.strip() else v

    @model_validator(mode="after")
    def _validate_mitigation_window(self):
        if (self.mitigation_start_date is None) != (self.mitigation_end_date is None):
            raise ValueError("mitigation_start_date and mitigation_end_date must be provided together")
        if self.mitigation_start_date and self.mitigation_end_date < self.mitigation_start_date:
            raise ValueError("mitigation_end_date must be on or after mitigation_start_date")
        return self

    @field_validator("existing_controls")
    @classmethod
    def _cap_control_text(cls, v: list[str]) -> list[str]:
        for item in v:
            if len(item) > 500:
                raise ValueError("each existing_controls entry must be 500 characters or fewer")
        # Blank/whitespace entries and duplicates are dropped, order preserved: this list is the
        # gap-analysis BASELINE the model matches library controls against, and a "" can cover
        # nothing — the documented "[] means a risk with no controls" semantics must hold even
        # when a UI sends ["",""] (the shipped sample did exactly that).
        seen: set[str] = set()
        cleaned: list[str] = []
        for item in v:
            s = item.strip()
            if s and s not in seen:
                seen.add(s)
                cleaned.append(s)
        return cleaned

    @field_validator("risk_identification_date")
    @classmethod
    def _utc_naive(cls, v: datetime | None) -> datetime | None:
        # pyodbc silently drops tzinfo binding into datetime2 (UTC-by-convention everywhere in
        # this schema) — normalize here so a "+05:30" timestamp can't store the wrong wall time.
        if v is None or v.tzinfo is None:
            return v
        return v.astimezone(UTC).replace(tzinfo=None)


class TreatmentPlanRegenerateBody(ApiModel):
    """POST .../treatment-plan/regenerate — mint a new plan version. NOTHING travels: send `{}`.

    The register risk data was frozen into the active version's InputSnapshotJSON at first
    generation and is reused from there (the client never resends it; changed register data
    cannot be resubmitted after first generation — a documented limitation of this shape).
    The baseline is the ACTIVE version — the one a human last chose — never simply the
    newest, so regenerating after a version switch builds on the switched-to plan.

    The body is now EMPTY (the `user_note` steering field was removed 2026-08). What a
    regeneration therefore does is REFRESH the plan against the CURRENT scenario and its mapped
    controls: build_treatment_input rebuilds the TSG-derived half every time, so a scenario that
    changed since the last version yields a different plan. With nothing changed and
    TREATMENT_TEMPERATURE at 0.0 the model is deterministic, so the result is the previous plan
    again — the call still costs an LLM round trip. The model is kept (rather than dropping the
    body parameter) so a client still POSTing the removed field gets a loud 422 instead of having
    its body silently ignored."""
    model_config = ConfigDict(extra="forbid", json_schema_extra={"example": {}})


class TreatmentPlanAccepted(ApiModel):
    """202 body for the POST — the GET on the same path is the poll endpoint."""
    model_config = ConfigDict(json_schema_extra={"example": {
        "plan_id": "0f0e0d0c-0b0a-8988-8786-858483828180",
        "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e",
        "scenario_id": "1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90",
        "status": "RUNNING"}})

    plan_id: str = Field(description="The new Risk_Treatment_Plan row's id.")
    session_id: str = Field(description="Echo of the session in the path.")
    scenario_id: str = Field(description="Echo of the scenario in the path.")
    # Narrowed because the ROUTE constructs this from an enum member — safe. The GET/board/register
    # status fields are deliberately NOT narrowed: those come back from the database as free text,
    # and one out-of-vocabulary row would 500 the whole page rather than degrade.
    status: Literal[StageStatus.RUNNING] = Field(
        description="Always RUNNING at accept time. Poll GET .../treatment-plan until it becomes "
                    "COMPLETE or ERROR; that GET also serves the finished plan. For an instant "
                    "hand-off the worker additionally publishes an advisory `treatment_plan_result` "
                    "on GET /v1/sessions/{session_id}/events — listen with "
                    "addEventListener('treatment_plan_result'), match on scenario_id (a regenerate "
                    "mints a new plan_id), and KEEP the poll: several outcomes never publish.")


class TreatmentPlanStatus(ApiModel):
    """GET .../treatment-plan — the active plan row. `status` is the poll signal; `plan` is the
    parsed PlanJSON contract (null until COMPLETE, or when the stored blob is corrupt). A
    RUNNING row whose progress clock stopped for longer than treatment_stale_seconds is
    presented as ERROR with a timed-out message — a read-time projection, the stored row is
    not rewritten.

    PRESENTATION TRIM (user request, 06 Aug 2026): the fields marked exclude=True below are
    HIDDEN from the response for now, not deleted — they are still populated and stored;
    remove the exclude flag to unhide. The `plan` document is trimmed the same way by
    api.treatment._VISIBLE_PLAN_KEYS — since the AI's own schema was narrowed to match (7
    fields; see prompts.treatment_prompt), that filter now does no real trimming except for
    risk_identification_date, which is surfaced once already as the sibling field above rather
    than duplicated inside `plan`."""
    model_config = ConfigDict(json_schema_extra={"example": {
        "plan_id": "0f0e0d0c-0b0a-8988-8786-858483828180",
        "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e",
        "scenario_id": "1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90",
        "status": "COMPLETE", "treatment_strategy": "Mitigate",
        "scenario": {"threat_category": "Elevation of Privilege",
                     "threat_type": "Credential Abuse",
                     "threat_name": "Stolen RDP credentials",
                     "scenario_title": "Ransomware via exposed RDP",
                     "scenario_statement": "A ransomware operator gains access through…",
                     "risk_statement": "Loss of treatment-plant availability…"},
        # Adversaries are a SIBLING of `scenario`, never inside it — this example must keep
        # showing that, since json_schema_extra is a separate expression that survives a field
        # change and is exactly how a published example ends up contradicting its own schema.
        "actors": [{"actor_id": 12, "actor_name": "Nation-state/APT"},
                   {"actor_id": 31, "actor_name": "Malicious insider"}],
        "risk_level": "Critical", "review_status": None,
        # No 'Z' suffix on purpose: values round-trip as NAIVE datetimes (UTC by convention —
        # the body validator normalizes, datetime2 stores naive), so the wire has no offset.
        "risk_identification_date": "2026-06-14T08:31:00",
        "error_message": None,
        "plan": {"title": "Remote Access Hardening", "treatment_plan": "Mitigate",
                 "action_plan": "Harden remote access in three phases…",
                 "applicable_to_all_subsystems": "No",
                 "controls_to_be_implemented": {
                     "control_coverage": "gaps",
                     "controls": [
                         {"control_type": "preventive",
                          "control_name": "Access Restriction For Change",
                          "description": "Enforce role-based access control and least-privilege…",
                          "priority": "Critical",
                          "control_code": "CII-CID-070",
                          "control_library_id": 70,
                          "domain": "Configuration Management"}]},
                 "mitigation_timeline": "2026-09-28",
                 "mitigation_owner": "OT Security Team",
                 "risk_owner": "Head of OT Operations",
                 "impacted_business_division": "Water Treatment Operations"}}})

    plan_id: str = Field(description="Risk_Treatment_Plan row id.")
    progress: TreatmentPlanProgress | None = Field(
        default=None,
        description="THIS plan's lifecycle position — the same block the session board publishes "
                    "(GET /v1/sessions/{id}/treatment-plans), folded over one scenario instead "
                    "of all of them, so a per-scenario screen and the board can never disagree "
                    "about the same plan. `overall` is the field to switch on: awaiting_review "
                    "-> show Review, rejected -> show Regenerate, error -> show Retry. Null on a "
                    "superseded-version row, which is history and has no live lifecycle.")
    session_id: str = Field(description="Owning session.")
    scenario_id: str = Field(description="The accepted scenario this plan treats.")
    status: str = Field(description="RUNNING | COMPLETE | ERROR — the poll signal (stale RUNNING projects as ERROR).")
    treatment_strategy: str = Field(description="The strategy this plan was generated for — server-stamped 'Mitigate'.")
    scenario: ScenarioNarrative | None = Field(
        default=None,
        description="The accepted scenario this plan treats — IDENTICAL shape to "
                    "ScenarioResult.scenario, built by the same builder, so the plan screen and "
                    "the results screen cannot show different detail for one scenario. Present "
                    "on superseded-version entries too (the scenario is version-independent, so "
                    "the active row's copy is overlaid onto each). Null if the scenario row is "
                    "unreadable (defensive parse), or on the session board's history entries, "
                    "whose own rows carry no scenario either.")
    threat: ThreatResult | None = Field(
        default=None,
        description="The threat this scenario was generated from, with every database key — "
                    "identical shape and rules to ScenarioResult.threat. Null when no "
                    "Identified_Threat row joined, or on the session board's history entries.")
    actors: list[ThreatActorRef] = Field(
        default_factory=list,
        description="Adversaries for this plan's underlying threat, each with its Threat_Actor "
                    "database key. A SIBLING of `scenario`, never inside it — the same rule as "
                    "ScenarioResult.actors, so the plan screen and the results screen report "
                    "adversaries in one identical shape. Empty when the threat linkage is "
                    "broken, when the threat names none, or on a superseded-version row (which "
                    "carries no threat join at all).")
    controls: list[MappedControl] = Field(
        default_factory=list,
        description="Step-4 controls mapped to this scenario — identical shape and source to "
                    "ScenarioResult.controls. These are the controls the plan's gap analysis "
                    "reasons about, so showing them beside the plan is what lets a reviewer "
                    "check the analysis rather than take it on trust.")
    controls_unavailable: bool = Field(
        default=False,
        description="true = the control mapping could NOT be read for this response (a transient "
                    "database error), so `controls` is empty because we did not get to look — "
                    "NOT because the library has nothing. Treat the list as unknown and retry; "
                    "do not act on it as a library gap. Always false on a healthy response, so a "
                    "client that ignores this field behaves exactly as before. Same flag and "
                    "meaning as ScenarioResult.controls_unavailable.")
    risk_level: str | None = Field(
        default=None, description="The register risk level this plan was generated against (from the request).")
    review_status: str | None = Field(
        default=None, description="TreatmentReviewStatus (approved / rejected) — null until a human reviews.")
    review_comment: str | None = Field(default=None, exclude=True, description="The reviewer's comment, if any.")
    # UNHIDDEN (was exclude=True under the 06 Aug 2026 presentation trim): the requirement
    # "user_id who created the remediation plan, user_id who accepted the plan — everything is
    # required" supersedes that trim for the two ATTRIBUTION fields. review_comment stays hidden;
    # it was not asked for and is not an attribution.
    reviewed_by: str | None = Field(default=None, description="Who recorded the review decision (from their login token).")
    reviewed_at: datetime | None = Field(default=None, description="When the review decision was recorded.")
    created_by: str | None = Field(
        default=None,
        description="User id of whoever REQUESTED this plan. Distinct from reviewed_by: the "
                    "generator and the reviewer are routinely different people, which is the "
                    "point of the review step.")
    cancelled_by: str | None = Field(
        default=None, description="User id of whoever cancelled this plan. Null unless cancelled.")
    cancelled_at: datetime | None = Field(
        default=None, description="When it was cancelled (naive UTC). Null unless cancelled.")
    risk_identification_date: datetime | None = Field(
        default=None,
        description="Echo of the request's register date — record data, never AI-generated (spec). Null when not sent.")
    plan: dict[str, Any] | None = Field(
        default=None,
        description=("The generated plan (SDD §7.3 contract): AI fields (title, "
                     "controls_to_be_implemented — {control_coverage, controls[]}, the "
                     "gap-analysis object, remediation_action_plan[], action_plan, "
                     "applicable_to_all_subsystems, mitigation_timeline, mitigation_owner), "
                     "the server stamp (treatment_plan), and register echoes (risk_owner, "
                     "impacted_business_division). JSON is the wire contract; markdown "
                     "rendering is the client's job."))
    # UNHIDDEN 2026-08-30 (was exclude=True since the 06-Aug presentation trim): these are the
    # ONLY surface where the risk-calibration, window-overrun, dropped-control and vocabulary
    # advisories reach the human who signs off the plan — hidden, the whole advisory layer was
    # decorative. Additive wire change; same reversal already applied to reviewed_by/created_by.
    warnings: list[str] = Field(
        default_factory=list,
        description="Advisory validation warnings (risk-urgency alignment, window overruns, "
                    "dropped unresolvable controls, vocabulary clamps, ...). Never blocking — "
                    "review before implementing the plan.")
    moderation_flagged: bool = Field(
        default=False,
        description="Advisory content-moderation flag for a human reviewer, when moderation ran.")
    error_message: str | None = Field(
        default=None, description="Client-safe failure reason when status is ERROR.")
    reason: TreatmentOutcomeReason | None = Field(
        default=None,
        description="WHY it ended this way — switch on THIS, never on error_message. Set only when "
                    "status is ERROR: cancelled (a human stopped it), timed_out (no progress; "
                    "regenerate), enqueue_failed (broker was down; retry now), content_blocked "
                    "(a safety guardrail refused it — do NOT auto-retry unchanged), invalid_plan / "
                    "generation_failed (retryable). Null on RUNNING and COMPLETE.")
    superseded: list[TreatmentPlanStatus] | None = Field(
        default=None,
        description="Regeneration history — every replaced version, newest first, each with its "
                    "own plan_id, status, review verdict, plan content, created_by, "
                    "cancelled_*, warnings and moderation_flagged — so one version can be told "
                    "from another before adopting it via POST .../review with its plan_id. "
                    "Populated only on GET .../treatment-plan?include_superseded=true: null when "
                    "not requested, [] when requested and the plan was never regenerated. The "
                    "scenario/threat/actors/controls blocks are version-independent and repeat "
                    "the top-level values. `progress` is null on every entry (history has no "
                    "live lifecycle), and entries never nest their own history (one level "
                    "deep).")
    created_at: datetime | None = Field(default=None, exclude=True, description="When this attempt was requested.")
    completed_at: datetime | None = Field(default=None, exclude=True, description="When it reached COMPLETE/ERROR.")


class TreatmentBoardRow(ApiModel):
    """One accepted scenario's line on the session plan board. Null plan fields = no plan has
    ever been requested for it (the UI shows a Generate button)."""
    scenario_id: str = Field(description="The accepted scenario.")
    scenario_title: str | None = Field(default=None, description="From the scenario, for display.")
    plan_id: str | None = Field(default=None, description="Active plan id; null = never requested.")
    status: str | None = Field(default=None, description="RUNNING | COMPLETE | ERROR (stale RUNNING projects as ERROR).")
    risk_level: str | None = Field(default=None)
    review_status: str | None = Field(default=None, description="approved / rejected / null.")
    error_message: str | None = Field(default=None)
    reason: TreatmentOutcomeReason | None = Field(
        default=None, description="Why it ended this way when status is ERROR — see "
                                  "TreatmentPlanStatus.reason. Null otherwise.")
    plan: dict[str, Any] | None = Field(
        default=None,
        description="The plan's content — the same trimmed object as TreatmentPlanStatus.plan. "
                    "Populated only with ?include_plan=true; null when not requested, and null "
                    "on rows with no generated content (RUNNING/ERROR or never requested).")
    superseded: list[TreatmentPlanStatus] | None = Field(
        default=None,
        description="Regeneration history — every replaced version of this scenario's plan, "
                    "newest first: the SAME full entries the single-plan GET serves under "
                    "?include_superseded=true (own plan content, status, review verdict, "
                    "created_by, cancelled_*, warnings, moderation_flagged, plus the "
                    "version-independent scenario/threat/actors/controls blocks, read once per "
                    "scenario and repeated). `progress` is null on every entry — history has no "
                    "live lifecycle. Populated only with ?include_superseded=true: null when not "
                    "requested, [] when requested and never regenerated.")
    created_at: datetime | None = Field(default=None)
    completed_at: datetime | None = Field(default=None)


class TreatmentPlanProgress(ApiModel):
    """The session's remediation-planning progress — the plan board's answer to
    SessionProgress, and deliberately the SAME SHAPE: one status string per named stage plus a
    derived overall, so a UI reads this board the way it already reads the generation board.

    Planning has two stages, and they are genuinely different questions: the machine writes the
    plans, then a human decides on them. Splitting them is what lets a client tell "still
    generating" from "generated, waiting on me" without inspecting a single row.
    """
    model_config = ConfigDict(json_schema_extra={"example": {
        "generation": "COMPLETE", "review": "PENDING", "overall": "awaiting_review"}})


    generation: TreatmentStageStatus = Field(
        description="Plan GENERATION across every accepted scenario. PENDING = none requested "
                    "yet (the UI shows Generate); RUNNING = at least one generating, or some "
                    "scenario still has no plan; COMPLETE = every accepted scenario has a "
                    "generated plan; ERROR = at least one failed. Mirrors "
                    "SessionProgress.scenarios.")
    review: TreatmentStageStatus = Field(
        description="The HUMAN half. PENDING while any generated plan still lacks an "
                    "approve/reject decision, COMPLETE once every one has been decided — a "
                    "REJECTED plan counts as decided. Stays PENDING while generation is still "
                    "running, because there is nothing to review yet. Never RUNNING: a person "
                    "either has decided or has not.")
    overall: TreatmentProgress = Field(
        description="One rolled-up status for the whole session's planning — the counterpart of "
                    "SessionProgress.overall, and the field a review queue filters on. See "
                    "TreatmentProgress for the priority order. Every value names a state of "
                    "the real flow AND the action it implies, so a UI can switch on this one "
                    "field: pending -> Generate, generating -> spinner, awaiting_review -> "
                    "Review, rejected -> Regenerate, approved -> done, error -> Retry. "
                    "`rejected` is deliberately NOT folded into `approved`: regenerate works on "
                    "a rejected plan, so it is work still outstanding.")


class TreatmentPlanStatusSummary(ApiModel):
    """GET .../treatment-plan/status — one scenario's remediation lifecycle, and nothing else.

    The remediation counterpart of GET /v1/sessions/{id}: a cheap poll a UI can hit on a timer
    while a plan generates. Deliberately carries NO plan content, no scenario and no threat —
    the full GET .../treatment-plan serves those, and a status poll that dragged tens of KB of
    PlanJSON along would make polling expensive exactly when it happens most.

    `progress` is folded by the same function the session board uses, so this endpoint and
    GET /v1/sessions/{id}/treatment-plans can never disagree about the same plan.
    """
    model_config = ConfigDict(json_schema_extra={"example": {
        "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e",
        "scenario_id": "1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90",
        "plan_id": "442b4bd2-98ab-8ac4-b589-01a054d68dbf",
        "progress": {"generation": "COMPLETE", "review": "PENDING",
                     "overall": "awaiting_review"},
        "status": "COMPLETE", "review_status": None, "reviewed_by": None,
        "error_message": None, "reason": None, "created_by": "dewa"}})

    session_id: str
    scenario_id: str = Field(description="The accepted scenario this plan treats.")
    plan_id: str = Field(description="Risk_Treatment_Plan row id — the ACTIVE version.")
    progress: TreatmentPlanProgress = Field(
        description="The lifecycle block. `overall` is the field to switch on: pending -> "
                    "Generate, generating -> spinner, awaiting_review -> Review, rejected -> "
                    "Regenerate, approved -> done, error -> Retry.")
    status: str = Field(
        description="RUNNING | COMPLETE | ERROR — the raw generation status a stale RUNNING is "
                    "already projected from. `progress.generation` says the same thing in the "
                    "board's vocabulary; this is kept for clients already reading it.")
    review_status: str | None = Field(
        default=None, description="approved / rejected / null (nobody has decided yet).")
    reviewed_by: str | None = Field(default=None, description="Who decided, if anyone has.")
    reviewed_at: datetime | None = Field(default=None, description="When (naive UTC).")
    created_by: str | None = Field(default=None, description="Who requested the plan.")
    error_message: str | None = Field(
        default=None, description="Client-safe failure reason when status is ERROR.")
    reason: TreatmentOutcomeReason | None = Field(
        default=None, description="Why it ended this way when status is ERROR. Null otherwise.")
    created_at: datetime | None = Field(default=None)
    updated_at: datetime | None = Field(default=None)
    completed_at: datetime | None = Field(default=None)


class TreatmentBoard(ApiModel):
    """GET /v1/sessions/{id}/treatment-plans — every accepted scenario's plan state in ONE
    call (the page the reviewer looks at daily; replaces N per-scenario polls)."""
    model_config = ConfigDict(json_schema_extra={"example": {
        "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e", "accepted_scenarios": 2,
        "plans": [{"scenario_id": "1a2b…", "scenario_title": "Ransomware via exposed RDP",
                   "plan_id": "b9fe…", "status": "COMPLETE", "risk_level": "Critical",
                   "review_status": "approved"},
                  {"scenario_id": "9f3c…", "scenario_title": "Insider tampering",
                   "plan_id": None, "status": None}]}})
    session_id: str
    accepted_scenarios: int = Field(description="How many accepted scenarios the session holds.")
    progress: TreatmentPlanProgress = Field(
        description="Rolled-up planning status for the whole session — read this to render a "
                    "status line or a progress bar without iterating `plans`.")
    plans: list[TreatmentBoardRow]


class TreatmentCancelResponse(ApiModel):
    """POST .../treatment-plan/cancel — the stop button's receipt."""
    plan_id: str
    status: Literal[StageStatus.ERROR] = Field(  # route-constructed from the enum — safe to narrow
        description="Always ERROR after a successful cancel.")
    error_message: str | None = Field(default=None, description="'cancelled by user'.")


class TreatmentReviewBody(ApiModel):
    """POST .../treatment-plan/review — record the human adoption decision on a COMPLETE
    plan. The reviewer's identity comes from the login token, never from this body."""
    # plan_id is in the example because it is REQUIRED — json_schema_extra is a separate
    # expression that survives a field change, and an example missing a required field is
    # exactly how a published example ends up contradicting its own schema.
    model_config = ConfigDict(json_schema_extra={"example": {
        "decision": "approved", "plan_id": "0f0e0d0c-0b0a-8988-8786-858483828180",
        "comment": "A3 timeline extended per operations."}})
    decision: TreatmentReviewStatus = Field(description="approved | rejected.")
    comment: str | None = Field(default=None, max_length=2000, description="Optional reviewer comment.")
    plan_id: str = Field(
        description=(
            "REQUIRED — which plan version this decision applies to. Deliberately not optional: "
            "'whatever is active right now' would let a regeneration committing between the GET "
            "and this POST redirect the verdict onto a version the reviewer never read, and this "
            "endpoint writes an audited adoption decision. Pass the ACTIVE version's id to "
            "review the current plan. Pass a HISTORICAL version's plan_id (from GET "
            ".../treatment-plan?include_superseded=true) with decision='approved' to make that "
            "version the current plan AND approve it, atomically — approving an older version IS "
            "choosing it. Only COMPLETE versions can be adopted (409 not_complete otherwise); "
            "rejecting a historical version is refused (409 version_not_active); a running "
            "regeneration blocks the switch (409 generation_in_progress). Last human decision "
            "wins: a later approval of another version displaces the operative plan; the "
            "displaced version keeps its own verdict in history and every switch is audited. "
            "Note: the entity register lists plans by original creation date, so a switched-to "
            "older version keeps its original position, not the top."
        ))

    _canonicalize_plan_id = field_validator("plan_id")(_canonical_guid)


class TreatmentReviewResponse(ApiModel):
    plan_id: str
    review_status: TreatmentReviewStatus  # echoes the validated request body — safe to type
    reviewed_by: str | None = Field(default=None, description="From the reviewer's login token.")
    reviewed_at: datetime | None = None


class TreatmentRegisterRow(ApiModel):
    """One plan in the entity-wide remediation register."""
    plan_id: str
    session_id: str
    scenario_id: str
    asset_name: str | None = None
    scenario_title: str | None = None
    status: str = Field(description="RUNNING | COMPLETE | ERROR (stale RUNNING projects as ERROR).")
    risk_level: str | None = None
    review_status: str | None = None
    reviewed_by: str | None = None
    error_message: str | None = None
    reason: TreatmentOutcomeReason | None = Field(
        default=None, description="Why it ended this way when status is ERROR — see "
                                  "TreatmentPlanStatus.reason. Null otherwise.")
    scenario: ScenarioNarrative | None = Field(
        default=None,
        description="Same block as TreatmentPlanStatus.scenario. Populated only with "
                    "?include_plan=true.")
    threat: ThreatResult | None = Field(
        default=None,
        description="Same block as TreatmentPlanStatus.threat. Populated only with "
                    "?include_plan=true.")
    actors: list[ThreatActorRef] = Field(
        default_factory=list,
        description="Same block as TreatmentPlanStatus.actors — adversaries with their "
                    "Threat_Actor keys. Populated only with ?include_plan=true.")
    controls: list[MappedControl] = Field(
        default_factory=list,
        description="Same block as TreatmentPlanStatus.controls. Populated only with "
                    "?include_plan=true.")
    controls_unavailable: bool = Field(
        default=False,
        description="Same flag as TreatmentPlanStatus.controls_unavailable: true = the control "
                    "mapping could not be read for this page, so `controls` is empty on every "
                    "row because we did not get to look. Only meaningful with ?include_plan=true.")
    treatment_strategy: str | None = Field(
        default=None,
        description="Server-stamped 'Mitigate' — see TreatmentPlanStatus. Populated only with "
                    "?include_plan=true.")
    risk_identification_date: datetime | None = Field(
        default=None,
        description="Register echo — see TreatmentPlanStatus. Populated only with "
                    "?include_plan=true.")
    plan: dict[str, Any] | None = Field(
        default=None,
        description="The plan's content — the same trimmed object as TreatmentPlanStatus.plan, "
                    "rendered by the same presenter: with ?include_plan=true a register row "
                    "mirrors the single-plan GET's response (minus `superseded`, plus "
                    "asset_name/scenario_title). Null when not requested, and null on rows "
                    "with no generated content (RUNNING/ERROR).")
    created_at: datetime | None = None
    completed_at: datetime | None = None


class TreatmentRegisterPage(ApiModel):
    """GET /v1/entities/{id}/treatment-plans — every plan across the entity, newest first,
    filterable by status / review_status / risk_level. This list IS the remediation register."""
    entity_id: str
    limit: int
    offset: int
    plans: list[TreatmentRegisterRow]


class TreatmentAuditEvent(ApiModel):
    """One entry in a treatment-plan audit trail. `detail` is the event's DetailJSON verbatim
    (plan_id, status, decision, note… depending on the event type)."""
    at: datetime | None = Field(default=None, description="When it happened (UTC).")
    event: str = Field(description="requested | outcome | cancelled | reviewed | version restored | superseded.")
    actor: str | None = Field(default=None, description="The person (null on system events).")
    actor_type: str | None = Field(default=None, description="user | system.")
    session_id: str | None = Field(default=None, description="Present on the entity-wide feed.")
    detail: dict[str, Any] = Field(default_factory=dict)


class TreatmentAuditTrail(ApiModel):
    """GET .../treatment-plan/audit — one scenario's plan life story across ALL versions:
    who requested, each attempt's outcome, cancels, reviews, and supersedes, oldest first."""
    session_id: str
    scenario_id: str
    events: list[TreatmentAuditEvent]


class TreatmentEntityAuditPage(ApiModel):
    """GET /v1/entities/{id}/treatment-plans/audit — the compliance feed: every treatment-plan
    action across the entity, newest first, filterable by date range and person."""
    entity_id: str
    limit: int
    offset: int
    events: list[TreatmentAuditEvent]


class TreatmentEvidenceAttempt(ApiModel):
    """One AI-call receipt (Prompt_Log row) for the plan version — the exact words exchanged."""
    at: datetime | None = None
    prompt: str | None = Field(default=None, description="The exact flattened prompt sent.")
    response: str | None = Field(default=None, description="The exact raw model reply.")
    model_name: str | None = None
    model_version: str | None = None
    prompt_version: str | None = None
    parse_succeeded: bool | None = None


class TreatmentEvidence(ApiModel):
    """GET .../treatment-plan/evidence?version={plan_id} — the reproducibility bundle for ONE
    version (superseded versions included — that is what an auditor asks for): the frozen
    input snapshot, the validation/moderation record, and every AI-call receipt (linked by
    Prompt_Log.CorrelationID; attempts generated before that column exist as rows without
    linkage and return empty here)."""
    plan_id: str
    status: str = Field(description="The STORED status, deliberately unprojected — evidence "
                                    "reports the record as written, so a stale RUNNING plan "
                                    "reads RUNNING here while the poll GET presents it as "
                                    "timed out.")
    input_snapshot: dict[str, Any] | None = Field(default=None, description="Exactly what the AI was given.")
    validation: dict[str, Any] | None = Field(default=None, description="Warnings + moderation record.")
    attempts: list[TreatmentEvidenceAttempt]
