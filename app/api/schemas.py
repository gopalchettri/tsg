"""Request/response Pydantic models for the session API (`app/api/sessions.py`).

Split out from the routes themselves so the shape of every endpoint's body/response
can be found in one place without wading through route logic.
"""
from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator, model_validator
from pydantic.json_schema import JsonDict


class ApiModel(BaseModel):
    """Base for every request/response model. Its ONLY job is to stamp UTC on timestamps.

    Every datetime in this schema is UTC by convention — `dal.now()` returns aware UTC and
    `_utc_naive` strips tzinfo at the boundary because "pyodbc silently drops tzinfo binding into
    datetime2". The values were therefore correct but UNLABELLED: a naive datetime serializes with
    no offset, and every browser parses that as LOCAL time. For an IST client that is a 5.5-hour
    error on `accepted_at`, `reviewed_at` and every audit timestamp — on endpoints already shipping.

    A base class rather than a per-field annotated type, deliberately: an annotation is more
    explicit at the declaration, but the NEXT datetime field somebody adds would silently miss it
    and the bug would be back. Inheriting cannot be forgotten per-field, and
    `test_every_timestamped_model_inherits_ApiModel` fails loudly if a model skips the base
    entirely — which restores the explicitness the annotation would have bought.

    NOT switching the columns to `datetimeoffset`: the driver already drops tzinfo on the way IN
    (which is why `_utc_naive` exists), so storing offsets bets the fix on the exact behaviour this
    codebase wrote defensive code to avoid, and it fails silently. Labelling on the way out cannot.

    The `*` serializer is safe for non-datetime values — verified it leaves nested models,
    lists and scalars untouched, returning them unchanged for pydantic's normal handling.
    """

    @field_serializer("*", when_used="unless-none")
    def _stamp_utc(self, value):
        if isinstance(value, datetime) and value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value


# --- API client key-management (admin) schemas ---
class CreateApiClientBody(ApiModel):
    """Provision a new API key. The secret is generated server-side; the caller supplies only
    metadata."""
    client_id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=200)
    module: str = Field(min_length=1, max_length=50)


class ApiClientCreated(ApiModel):
    """Returned ONCE at creation. `secret` is never stored and never retrievable again."""
    client_id: str
    module: str
    secret: str


class ApiClientInfo(ApiModel):
    """One API client as listed — metadata only, never the hash or secret."""
    client_id: str
    name: str
    module: str
    active: bool
    created_at: datetime | None = None
    created_by: str | None = None
    revoked_at: datetime | None = None
    revoked_by: str | None = None


class ApiClientRevoked(ApiModel):
    """Confirmation that a key was deactivated. Exists so the route is not typed `-> dict`, which
    publishes an EMPTY object schema — a generated client then has no idea what comes back."""
    client_id: str
    status: str = "revoked"

# Typing the wire with these is what puts them in /openapi.json — the UI generates its own
# string-literal unions from the spec instead of hand-copying codes out of the API guide.
from app.core.config import CONTROL_DESCRIPTION_MAX_CHARS, CONTROL_NAME_MAX_CHARS
from app.core.enums import (
    CeleryJobState,
    ClickOutcomeReason,
    NextSetOutcome,
    ReviewGateReason,
    RiskLevel,
    SSEEventType,
    StageStatus,
    SubsystemLevel,
    TreatmentGateReason,
    TreatmentOutcomeReason,
    TreatmentProgress,
    TreatmentReviewStatus,
    YesNo,
)
from app.db.dal import canonical_guid

# Plan item 1b: bound every list-of-targets field so one HTTP request can't turn into an
# unbounded synchronous AI/DB workload inside a single Celery task (no chunking exists).
_MAX_BATCH = 50


def _canonical_scenario_ids(v: list[str] | None) -> list[str] | None:
    """Normalize client-supplied scenario_ids to the one canonical spelling AT THE TRUST BOUNDARY,
    so nothing downstream ever compares a raw client id against a DB-derived one.

    `uuid.UUID` accepts uppercase, dashless, braced and `urn:uuid:` forms and `models.GUID`
    normalizes them for SQL — so the row matches, but a Python-side set/count comparison on the
    raw string does not. That gap produced a false `regenerate_conflict` on a valid request and
    a spurious 404 (with full rollback) on accept. Normalizing here fixes every consumer at once
    — including future ones — instead of one call site at a time.

    A malformed id raises here, which FastAPI renders as a clean 422 `validation_error`; left
    to `GUID.bind_processor` it would instead surface as a 500."""
    if v is None:
        return None
    if len(v) > _MAX_BATCH:
        # Over the batch bound — hand it back untouched and let the size check reject it. On
        # AcceptBody that bound lives in the mode="after" model validator (deliberately, to keep
        # its context-aware message — see there), which pydantic runs AFTER this field validator:
        # without this guard a 200k-id body ran the per-item uuid parse to completion first,
        # ~0.4s of GIL-holding work stalling the whole event loop before the 422. An over-cap
        # list is rejected under EVERY mode, so a non-canonical value can never escape validation.
        return v
    out = []
    for raw in v:
        try:
            out.append(canonical_guid(raw))
        except (ValueError, AttributeError, TypeError):
            raise ValueError(f"not a valid GUID: {raw!r}") from None
    return out


def _canonical_guid_or_none(v: str | None) -> str | None:
    """Scalar sibling of _canonical_scenario_ids — same trust-boundary rule for single-id fields
    (TreatmentReviewBody.plan_id): MSSQL returns uppercase GUIDs, dal.guid() stores lowercase,
    Python compares case-sensitively — an un-canonicalized id would silently flip a branch
    decision (e.g. 'is this the active plan version?'). Malformed input dies here as a clean
    422, never a driver-level 500."""
    if v is None:
        return None
    try:
        return canonical_guid(v)
    except (ValueError, AttributeError, TypeError):
        raise ValueError(f"not a valid GUID: {v!r}") from None


class CreateSessionBody(ApiModel):
    """Ids only — asset/subsystem/sector descriptive context is resolved server-side,
    authoritatively, from the DB (`app.pipeline.context.gather_asset_details`), never
    accepted from the client. This is deliberate: the client can no longer inject
    arbitrary text into the LLM prompt just by having it happen to match the DB, because
    there's no client-supplied text to inject in the first place."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entity_id": "78",
                "service_id": 335,
                "sector_id": 95,
                "subsector_id": 111,
                "asset_id": 103,
                "supporting_system_id": [321, 322, 323, 324],
            }
        }
    )

    asset_id: int = Field(description="Primary key of the asset to generate threat scenarios for.")
    entity_id: str = Field(description="Tenant/business-unit code the asset belongs to; used for entity-scoped access control.")
    service_id: int | None = Field(default=None, description="Critical service the asset delivers (onboarding_services.id). With entity_id it resolves the sub-sector server-side.")
    # SECTOR vs SUB-SECTOR — the distinction that produced a silent, months-long defect.
    # In onboarding_sectors the PARENT row is the sector (95 Energy) and the CHILD is the
    # sub-sector (110 Electricity, 111 Water). The pipeline needs the CHILD: it derives the
    # parent itself via parent_id, and filters the threat library on both. Callers previously
    # sent the parent in `sector_id`, so sub-sector-scoped library entries were invisible and
    # grounding quietly matched against a smaller pool. Send `subsector_id`.
    subsector_id: int | None = Field(default=None, description="Sub-sector id (onboarding_sectors child row, e.g. 111 Water). Preferred; its parent sector is derived server-side.")
    sector_id: int | None = Field(default=None, description="Parent sector id (e.g. 95 Energy). Cross-check only — must be the parent of subsector_id. Not the source of truth.")
    # `user_id` deliberately REMOVED: the initiating user is taken from the authenticated
    # principal (X-User-Id, see docs/TSG_API_AUTHENTICATION_GUIDE.md), the same source cancel/accept already audit
    # against. As a body field it was unverified text — a caller could send "user_id": "ceo" and
    # Scenario_Audit.ActorUserID recorded ceo, so one column meant "verified identity" on some
    # rows and "whatever was typed" on others. Unknown keys are ignored by default, so a client
    # still sending it is not rejected; the value is simply never read.
    supporting_system_id: list[int] = Field(
        min_length=1,
        max_length=_MAX_BATCH,
        description="Ids of the asset's supporting systems (subsystems) to analyze. 1-50 ids, no duplicates.",
    )

    @field_validator("supporting_system_id")
    @classmethod
    def _no_duplicate_ids(cls, v: list[int]) -> list[int]:
        """Reject the request if the same supporting-system id appears more than once."""
        # A repeated id would corrupt the CAS-keyed Subsystem_Stage_State rows one-per-id
        # downstream — reject at the request boundary, before any DB work happens.
        if len(set(v)) != len(v):
            dupes = sorted({i for i in v if v.count(i) > 1})
            raise ValueError(f"supporting_system_id contains duplicates: {dupes}")
        return v


class AcceptBody(ApiModel):
    """Body for the "accept scenarios" endpoint. `mode` is REQUIRED (no default) so a
    caller can never silently accept-all by omitting a field — accept-all/none/subset
    are three separate, mutually-exclusive choices instead of shades of
    null-vs-omitted-vs-empty-list. [R8]"""
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"mode": "all"},
                {"mode": "none"},
                {"mode": "subset", "scenario_ids": ["3fa85f64-5717-4562-b3fc-2c963f66afa6"]},
            ]
        }
    )

    mode: Literal["all", "none", "subset"] = Field(
        description=(
            "Required. 'all' = accept every generated scenario; 'none' = accept nothing "
            "(the session still completes, terminally — [R8]); 'subset' = accept only the "
            "scenarios named in scenario_ids."
        )
    )
    scenario_ids: list[str] | None = Field(
        default=None,
        description=(
            f"Output ids to accept. Required (non-empty, max {_MAX_BATCH}) when mode='subset'; "
            "must be omitted otherwise. An id may name ANY version of a scenario — including an "
            "older one that a regeneration replaced (see replaced_scenarios in GET /results"
            "?include_replaced=true); the named version becomes the accepted one. Naming two "
            "versions of the same scenario is rejected (409, reason 'duplicate_identity')."
        ),
    )

    _canonicalize_scenario_ids = field_validator("scenario_ids")(_canonical_scenario_ids)

    @model_validator(mode="after")
    def _mode_and_scenario_ids_agree(self) -> AcceptBody:
        # Length bounds live HERE, not as Field constraints: Pydantic runs field-level
        # min_length/max_length BEFORE any mode="after" validator, so a field failure would
        # skip this validator entirely — {"mode": "all", "scenario_ids": []} would then be told
        # to ADD items ("at least 1 item") when the actual fix is to REMOVE the field. One
        # validation site keeps every mode/scenario_ids disagreement on one context-aware message.
        if self.mode == "subset":
            if not self.scenario_ids:
                raise ValueError("scenario_ids is required (non-empty) when mode='subset'")
            if len(self.scenario_ids) > _MAX_BATCH:
                raise ValueError(f"scenario_ids must have at most {_MAX_BATCH} items")
        elif self.scenario_ids is not None:
            raise ValueError(f"scenario_ids must not be provided when mode={self.mode!r}")
        return self


class RegenerateScenariosBody(ApiModel):
    """Body for asking the pipeline to regenerate scenarios for the session's asset. No asset/
    subsystem id is needed here — `session_id` (already in the URL) is the sole identifier, since
    a session is always exactly one asset (`UX_Session_ActiveAsset`); the target scenarios are
    identified by `scenario_ids` alone."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "scenario_ids": ["3fa85f64-5717-4562-b3fc-2c963f66afa6"],
            }
        }
    )

    scenario_ids: list[str] = Field(
        min_length=1, max_length=_MAX_BATCH, description="Output ids of the scenarios to regenerate. 1-50 ids."
    )
    # No `user_note`. It was accepted here for a year and NEVER reached the model: it appears
    # nowhere in prompts.py, and cascade.py only stamped it into a FAILURE audit record. A field
    # whose description promises steering it cannot do is worse than no field, so it is gone —
    # same call as the treatment-plan regenerate body, for the same reason.

    _canonicalize_scenario_ids = field_validator("scenario_ids")(_canonical_scenario_ids)


class NextSetSummary(ApiModel):
    """What the most recent "generate next set" click on this session achieved.

    THE DURABLE record, not a convenience copy. The `next_set_result` SSE event carries the same
    facts, but publishing is best-effort behind a circuit breaker with no replay log
    (app/sse/bus.py), so a client that polls instead of streaming — or whose stream dropped —
    would otherwise never learn why a click delivered fewer scenarios than it asked for.

    `epoch` is what makes this unambiguous. POST .../scenarios/next-set returns the epoch it
    reserved; poll this endpoint until `last_next_set.epoch` equals it and you are reading YOUR
    click's result rather than the previous one's. Without that comparison a client cannot tell a
    finished click from a stale summary — precisely how a mid-flight read looks complete."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "outcome": "partial_retryable", "requested": 5, "delivered": 3,
                "variants": 0, "reason": None, "epoch": 4,
            }
        }
    )

    outcome: NextSetOutcome = Field(
        description=(
            "What the click achieved. 'complete' = the full requested batch landed. "
            "'partial_retryable' = fewer, because generation(s) failed — those threats stay "
            "re-servable, so clicking 'generate next set' again RETRIES them. 'exhausted' = "
            "fewer (possibly zero) because nothing further exists for this asset; clicking "
            "again changes nothing. Switch on this rather than comparing counts: a short "
            "result is sometimes the correct final answer, not a failure."
        ),
    )
    requested: int = Field(description="Scenarios the click aimed to add (the configured next-set batch size).")
    delivered: int = Field(description="Scenarios actually added — fresh plus variants.")
    variants: int = Field(
        description="How many of `delivered` are alternate takes on already-covered threats "
                    "(ScenarioNumber > 1) rather than brand-new threats.",
    )
    reason: ClickOutcomeReason | None = Field(
        default=None,
        description="Why the click fell back to variants or came up empty; null when it simply succeeded.",
    )
    epoch: int = Field(
        description="Generation epoch this summary describes — compare against the `epoch` "
                    "returned by the POST that started the click.",
    )


class RegenSummary(ApiModel):
    """What the most recent scenario-regenerate request on this session did (plan item 3) — the
    DURABLE mirror of the SSE `regen_result` event, same rationale as `NextSetSummary` above:
    `regen_result` is best-effort behind a circuit breaker with no replay (app/sse/bus.py), so a
    polling client, or one whose stream dropped, needs this to learn what a regenerate actually
    changed. Built straight from the `regeneration_completed` audit row's DetailJSON
    (app/pipeline/cascade.py::_build_regen_audit_detail), so the field names match that shape
    exactly rather than the differently-named `regen_result` event fields."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "target_ids": ["b3fc2c96-3f66-4562-8fa6-5717afa63f66"],
                "requested_ids": ["6ba7b810-9dad-11d1-80b4-00c04fd430c8"],
                "replacements": [{"old": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
                                "new": "b3fc2c96-3f66-4562-8fa6-5717afa63f66"}],
                "failed_threat_ids": [], "rescored_threat_ids": [], "epoch": 4,
            }
        }
    )

    target_ids: list[str] | None = Field(
        default=None, description="ThreatIDs this regeneration actually resolved to and redid; "
                                "null if none resolved.")
    requested_ids: list[str] | None = Field(
        default=None, description="scenario_ids the client asked to regenerate (the request body's "
                                "`scenario_ids`); null for a request with no explicit targets.")
    replacements: list[dict[str, str]] = Field(
        default_factory=list, description="old->new scenario_id pairs this regen actually committed.")
    failed_threat_ids: list[str] = Field(
        default_factory=list, description="Targets whose generation call itself failed — "
                                        "transient, still worth retrying via the same request.")
    rescored_threat_ids: list[str] = Field(
        default_factory=list, description="Targets that no longer meet the current scoping "
                                        "cutoff — terminal, retrying will not change the outcome.")
    epoch: int = Field(
        description="Generation epoch this summary describes — compare against the `epoch` "
                    "returned by the POST that started the regenerate request.")


class CoverageCell(ApiModel):
    """One unanswered (supporting system x STRIDE category) question."""
    subsystem_id: int = Field(description="0 = the asset itself, >= 1 = a specific supporting system.")
    category: str = Field(description="STRIDE category with no threat recorded against that unit.")


class CoverageVerdict(ApiModel):
    """Did this assessment actually ANSWER every question it was supposed to ask?

    Threat modelling needs a set-level property that per-item relevance ranking is structurally
    blind to: an assessment that misses the one threat that matters looks IDENTICAL to a
    complete one — no error, no exception, the session reports success. So the threat space is
    treated as a matrix to fill, not a list to search: every (unit x STRIDE category) cell must
    hold a threat or a recorded justification, and an empty cell is reported here rather than
    passing silently.

    Units are the asset (0) plus every supporting system a threat was recorded against
    (pipeline/coverage.py). Null until threat identification has run.

    DELIBERATELY SEPARATE FROM `overall`. That field answers "did the pipeline finish"; this one
    answers "is the answer whole". Folding an uncovered cell into `overall` would make a
    coverage gap read as a crash and send a reviewer hunting an infrastructure fault that does
    not exist. Gate sign-off on `complete`, not on `overall`."""
    cells: int = Field(description="Questions this assessment had to answer: units x active STRIDE categories.")
    covered: int = Field(description="Cells holding at least one identified threat.")
    justified_na: int = Field(description="Cells closed by a recorded, reviewable not-applicable justification.")
    unexplained: int = Field(description="Cells holding NEITHER. Must be 0 before this assessment is complete.")
    complete: bool = Field(
        description="`unexplained == 0`. FALSE means threats were not identified for every "
                    "(supporting system x STRIDE) pair and the gaps below say which — the "
                    "assessment is usable but NOT whole, and should not be signed off as if it "
                    "were. This is the one flag a reviewer must not ignore."
    )
    units: list[int] = Field(default_factory=list, description="The grid's rows: 0 (the asset) plus each supporting system id.")
    gaps: list[CoverageCell] = Field(
        default_factory=list,
        description="The unexplained cells by name, capped for payload size — `unexplained` is "
                    "the true count and may exceed this list's length."
    )


class SessionProgress(ApiModel):
    """The session's asset-level progress: per-stage statuses plus a derived overall status. One
    flat object, not a list — the pipeline tracks the asset as a single unit of work (see
    sessions.py::build_board), so there is never more than one of these per session."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "threats": "COMPLETE", "scenarios": "COMPLETE", "controls": "COMPLETE",
                "overall": "awaiting_review", "error_message": {},
                "last_next_set": {
                    "outcome": "partial_retryable", "requested": 5, "delivered": 3,
                    "variants": 0, "reason": None, "epoch": 4,
                },
                "last_regen": None,
                "coverage": {
                    "cells": 18, "covered": 17, "justified_na": 0, "unexplained": 1,
                    "complete": False, "units": [0, 41, 42],
                    "gaps": [{"subsystem_id": 42, "category": "Tampering"}],
                },
            }
        }
    )

    threats: str = Field(description="THREATS stage status: IDLE, RUNNING, COMPLETE, ERROR, or CANCELLED.")
    scenarios: str = Field(
        description="SCENARIOS stage status: IDLE, RUNNING, COMPLETE, ERROR, or CANCELLED. "
                    "COMPLETE means GENERATION finished — scenarios written and their controls "
                    "mapped. It does NOT mean the session is finished: a human still has to "
                    "accept or reject, and `overall` reports `awaiting_review` until they do. "
                    "Internally the stage row still records the review barrier; this field "
                    "answers 'is generation done', `overall` answers 'does a human still owe a "
                    "decision'.")
    overall: str = Field(
        description="Computed overall status: pending, in_progress, awaiting_review, complete, "
                    "error, or cancelled. THE review-queue field — `awaiting_review` means "
                    "generation finished and a human still owes an accept/reject on at least one "
                    "scenario, `complete` means every scenario has been decided. It is derived "
                    "from the SCENARIO DECISIONS, not from the stage status: the stage parks at "
                    "the review barrier permanently (accept never moves it, so decisions stay "
                    "changeable), so a stage-only rollup reported the same value for an "
                    "untouched session and a fully reviewed one.")
    controls: str = Field(
        default="PENDING",
        description="Step-4 control mapping, rolled up for the session: PENDING (nothing mapped "
                    "yet), RUNNING (some scenarios mapped, some not), COMPLETE (every active "
                    "scenario mapped). DERIVED from ControlsMappedAt — control mapping is the "
                    "tail of scenario generation and owns no stage row. It is also the longest "
                    "step in the pipeline, and scenarios become visible BEFORE their controls "
                    "do, so poll this before rendering a finished card. The per-scenario twin is "
                    "ScenarioResult.controls_mapped.")
    # BREAKING REST API CHANGE (plan item 7, deliberately shipped last and separately from the
    # rest of this file's changes): was `str | None`, last-row-wins across stages, so two
    # simultaneous stage failures silently dropped one message. Now a dict keyed by stage
    # ("threats"/"scenarios"), each entry that stage's own message — nothing is dropped. This
    # reshapes SessionProgress on BOTH `GET /v1/sessions/{session_id}` (the polling endpoint) and
    # every SSE `reconcile` event (also built from sessions.py::build_board): any existing typed
    # consumer reading `error_message` as `Optional[str]` hard-fails to parse the response the
    # moment this ships. See docs/SSE_SESSION_PROGRESS_CONTRACT_GUIDE.md for the migration note.
    error_message: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Client-safe failure reason(s) for the most recent stage error(s), keyed by stage "
            "('threats'/'scenarios'). Empty on a clean board. A non-empty dict on an "
            "board whose scenarios await a decision means the run failed mid-batch after "
            "generating some "
            "scenarios — the review set may be PARTIAL, not a complete run. BREAKING CHANGE: "
            "this was a single `str | None` before — see the SSE contract guide."
        ),
    )
    last_next_set: NextSetSummary | None = Field(
        default=None,
        description=(
            "Outcome of the most recent 'generate next set' click, or null if none has run. "
            "Compare `last_next_set.epoch` against the `epoch` returned by the POST that "
            "started your click: while they differ, your click is still in flight and this "
            "summary describes an EARLIER one."
        ),
    )
    last_regen: RegenSummary | None = Field(
        default=None,
        description=(
            "Outcome of the most recent scenario-regenerate request, or null if none has run. "
            "Same epoch-comparison pattern as `last_next_set`: compare `last_regen.epoch` "
            "against the `epoch` RegenerateResponse returned for your request."
        ),
    )
    coverage: CoverageVerdict | None = Field(
        default=None,
        description=(
            "Whether every (supporting system x STRIDE category) question was answered. This is "
            "the per-supporting-system dimension of the board: stage status stays asset-level "
            "because generation IS asset-level (one scenario covers a threat across every "
            "system it reaches), but COVERAGE genuinely varies per system and is what a "
            "reviewer needs per system. Null until threat identification has run, AND null "
            "whenever TSG_COVERAGE_REPORTING_ENABLED is off (the default) — an advisory-only "
            "signal that never gates accept/reject/treatment-plan generation, disabled because "
            "it never found a shape that stayed both complete and easy to read on a polled "
            "endpoint. Nothing is computed or stored while it's off, not just hidden here."
        ),
    )


class SessionBoard(ApiModel):
    """Full status board for a session: session-level info plus the asset's progress."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "entity_id": "ENT-001",
                "asset_id": 12345, "asset_name": "SCADA Historian",
                "user_id": "qa-user",
                "session_status": "active",
                "current_stage": "SCENARIO_GENERATION",
                "stage_status": "COMPLETE",
                "progress": {
                    "threats": "COMPLETE", "scenarios": "AWAITING_DECISION",
                    "overall": "awaiting_review", "error_message": {},
                },
            }
        }
    )

    session_id: str = Field(description="Session's unique id (GUID).")
    entity_id: str = Field(description="Tenant/business-unit code the session belongs to.")
    asset_id: int = Field(description="Primary key of the asset this session belongs to.")
    asset_name: str = Field(description="Display name of the asset this session belongs to.")
    user_id: str | None = Field(description="The session's owning user (who created it). Null only if the principal had no identity to record.")
    session_status: str = Field(description="Lifecycle status: active, completed, or cancelled.")
    current_stage: str = Field(
        description="Current workflow stage: THREAT_IDENTIFICATION, SCENARIO_GENERATION, REVIEW, APPROVED, or CANCELLED."
    )
    stage_status: str = Field(
        description="Status of the current stage: IDLE, RUNNING, AWAITING_DECISION, COMPLETE, ERROR, or CANCELLED."
    )
    progress: SessionProgress = Field(description="The session's asset-level progress.")


class CreateSessionResponse(ApiModel):
    """Response returned after a new session is created."""
    model_config = ConfigDict(
        json_schema_extra={"example": {"session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "user_id": "qa-user"}}
    )

    session_id: str = Field(description="Id of the newly created session. Use it to poll status, fetch results, or stream events.")
    user_id: str | None = Field(
        description="The session's owning user (the authenticated caller who created it). "
                    "Null only if the principal had no identity to record."
    )


class ThreatActorRef(ApiModel):
    """One adversary WITH its database key. Actor names always come from the library (the model
    never invents one), so a name normally resolves to a real Threat_Actor row; ThreatActorID is
    null only when the stored name no longer matches an active row — visible, never silent."""
    actor_id: int | None = Field(
        default=None,
        description="Threat_Actor primary key. Null when the stored name no longer resolves to "
                    "an active Threat_Actor row (renamed/deactivated since this threat was written).")
    actor_name: str = Field(description="The adversary's name (Threat_Actor.ThreatActorName).")


class ThreatResult(ApiModel):
    """One threat identified for the session's asset, as returned to the client."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "threat_category": "Tampering",
                "grounding_status": "verified",
            }
        }
    )

    threat_id: str = Field(description="Identified threat's unique id (GUID). Matches the ThreatID on the scenario(s) generated from it.")
    threat_category: str | None = Field(
        default=None,
        description="STRIDE category this threat was placed in (Spoofing, Tampering, Repudiation, "
                    "Information Disclosure, Denial of Service, Elevation of Privilege) - the "
                    "coverage grid's column."
    )
    threat_category_id: int | None = Field(
        default=None,
        description="Threat_Category primary key for ThreatCategory, resolved at identification "
                    "time and stored — so this joins without matching the category TEXT. Null "
                    "when the proposed category matched no master row."
    )
    threat_type: str = Field(description="The threat's type AS PROPOSED. For a library-retrieved threat "
                                        "this equals LibraryThreatType; for a generated one it is the "
                                        "model's own wording, kept verbatim.")
    threat_name: str | None = Field(description="The threat's name AS PROPOSED - see ThreatType.")
    description: str | None = Field(
        default=None,
        description="The AI's one-sentence description of this threat, written at identification "
                    "time in asset-free language and copied into Threat_Catalogue.Description "
                    "when the threat is promoted. For a library-retrieved threat this carries "
                    "the catalogue's own description (clipped). Null when the model's wording "
                    "named the asset (dropped rather than leaked into a shared library)."
    )
    threat_type_id: int | None = Field(
        default=None,
        description="Id of the matched Threat_Type master row. Null when the type came back unverified."
    )
    library_threat_type: str | None = Field(
        default=None,
        description="The MATCHED library type's own name, straight off Threat_Type. Null when nothing "
                    "matched. Reported ALONGSIDE ThreatType rather than replacing it: the two differ "
                    "exactly when the model's wording and the curator's differ, and that difference is "
                    "the reviewer's signal about match quality."
    )
    library_threat_name: str | None = Field(
        default=None,
        description="The MATCHED library threat's own name, straight off Threat_Catalogue. Same "
                    "alongside-not-instead-of rule as LibraryThreatType."
    )
    grounding_status: str = Field(
        description=(
            "Whether this threat matched an approved threat-library entry: `verified` (it did) "
            "or `unverified` (no confident match — a novel candidate, still scenario-generated "
            "and eligible for library promotion on accept)."
        )
    )
    threat_catalogue_id: int | None = Field(
        default=None,
        description="Id of the matched Threat_Catalogue row, set only when the name match "
                    "itself cleared the cutoff. Null whenever it did not — a close-but-unconfirmed "
                    "candidate is deliberately not reported as a match."
    )
    is_threat_type_ai_generated: bool | None = Field(
        default=None,
        description="True when the threat's TYPE matched no Threat_Type library row at "
                    "identification time (the AI's own wording, threat_type_id null); False "
                    "when it matched (threat_type_id set, library_threat_type names the row). "
                    "Independent of is_threat_ai_generated below — a threat can invent a new "
                    "specific catalogue entry under an EXISTING, already-curated type."
    )
    is_threat_ai_generated: bool | None = Field(
        default=None,
        description="True when the threat was NOT in the threat catalogue at identification "
                    "time (invented by the AI); False for library threats -- retrieved, or "
                    "AI-proposed but verified to match a catalogue row. Immutable provenance: "
                    "promoting the threat later does NOT flip it. Null only for rows written "
                    "before this field existed."
    )
    # Actors are NOT here. They sit beside this block, as ScenarioResult.actors /
    # AcceptedScenario.actors — one flat list per scenario entry, next to `controls`. Keeping
    # them out of the threat object means neither list depends on a threat row having joined:
    # _threat_block returns None on an OUTER-join miss, which would otherwise take the actors
    # with it. See ScenarioResult.actors for why actors and controls are two lists, not one.
    grounding_score: float | None = Field(
        default=None,
        description="Library-match confidence (reranker score, 0-100) against the threat "
                    "catalogue. Null for rows written before this field existed."
    )
    score: float | None = Field(
        default=None,
        description="Relevance score from scoping (base + confidence + rule boosts). Higher = "
                    "more relevant to this asset; rank best-first on this."
    )
    scope_rank: int | None = Field(
        default=None,
        description="1-based rank the scoping pass assigned within its round (1 = strongest)."
    )


class StandardRef(ApiModel):
    """One referred standard WITH its database key. A control can refer to several standards
    (Control_Library_Standard_Map is many-to-many), and a bare name list cannot say which
    Control_Standard row each came from — the same keys-alongside-names rule as
    ThreatCatalogueID/ControlLibraryID."""
    standard_id: int = Field(description="Control_Standard primary key.")
    standard_name: str = Field(description="The standard's name (Control_Standard.StandardName).")


#: One `controls` entry, for the OpenAPI examples below.
_MAPPED_CONTROL_EXAMPLE: JsonDict = {
    "control_id": 201,
    "control_code": "CII-CID-201",
    "domain": "Identification & Authentication",
    "control_name": "Multi-Factor Authentication",
    "map_rank": 1,
    "score": 93.0,
    "standards": [
        {"standard_id": 3, "standard_name": "NIST SP 800-53 Rev. 5"},
        {"standard_id": 7, "standard_name": "ISO 27001:2022"},
    ],
}

#: The scenario narrative exactly as the pipeline produces it (prompts.py::scenario_prompt): these
#: are the LLM's own keys, passed through verbatim by sessions.py (via dal.safe_json_dict), with
#: `controls` swapped for the grounded library matches. ONE constant shared by every example that
#: shows a scenario — the four hand-copied literals this replaces had all drifted to a
#: `title`/`narrative` shape the API has never actually returned.
_SCENARIO_EXAMPLE: JsonDict = {
    "threat_category": "Tampering",
    "threat_type": "unauthorized modification of firmware",
    "threat_name": "Unauthorized firmware update of Remote Terminal Unit (RTU)",
    "scenario_title": "Remote Terminal Unit (RTU) — Unauthorized firmware push",
    "scenario_statement": (
        "An attacker with OT network access pushes unsigned firmware to the RTU, "
        "compromising the integrity of its control logic."
    ),
    "risk_statement": (
        "The RTU provides the Substation Control critical service; corrupted firmware "
        "could cause a sustained outage."
    ),
    "supporting_systems_involved": [
        {"supporting_system_id": 306, "supporting_system": "OT Telecom Network",
         "is_entry_point": True,
         "justification": "The firmware push travels over this network to reach the RTU."},
    ],
}

#: Actors and controls are ENVELOPE siblings, so the examples live here rather than inside
#: _SCENARIO_EXAMPLE — reused by _SCENARIO_RESULT_EXAMPLE and _ACCEPTED_SCENARIO_EXAMPLE so the
#: two envelopes cannot drift apart the way hand-copied examples already have once (§7b G2).
_ACTORS_EXAMPLE: list[JsonDict] = [
    {"actor_id": 12, "actor_name": "Nation-state/APT"},
    {"actor_id": 31, "actor_name": "Malicious insider"},
]


class MappedControl(ApiModel):
    """One Control_Library row mapped to a scenario by Step-4 control mapping
    (control_mapping.map_controls): the scenario's own text was grounded against the control
    library and this real library control matched. Ordered by rank (1 = best). The LLM never
    proposes controls (library-first redesign).

    Delivered as an ENVELOPE sibling — `ScenarioResult.controls` / `AcceptedScenario.controls` —
    NOT inside `scenario` and NOT inside `threat`. Both placements were wrong for the same
    reason: mapping is keyed by Threat_Scenario_Control_Map.ScenarioID, so controls belong to the
    SCENARIO, while a threat can father several scenarios that each map different controls.
    Nesting them under `threat` invited exactly the de-duplication that would cross-wire them.

    A legacy scenario's raw JSON may still carry a model-authored `{name, why}` list under a
    `controls` key; sessions.py::_scenario_narrative POPS it, so it can never reach the wire
    through ScenarioNarrative's `extra="allow"`.

    An empty list means nothing in the library matched well enough — a library-gap signal, not an
    error, but only once `controls_mapped` is true (see ScenarioResult)."""
    model_config = ConfigDict(json_schema_extra={"example": _MAPPED_CONTROL_EXAMPLE})

    control_id: int = Field(description="Control_Library primary key.")
    control_code: str = Field(description="Stable control code, e.g. 'CII-CID-201'.")
    domain: str = Field(description="The control's domain as recorded in the library (reported as-is).")
    control_name: str = Field(description="The library control's official name.")
    map_rank: int = Field(description="1 = best match for this scenario. Spelled as the "
                                    "Threat_Scenario_Control_Map column it is read from.")
    score: float | None = Field(description="Raw match confidence 0-100 at mapping time.")
    # No bare `StandardNames: list[str]`. Standards below carries the same names WITH their
    # Control_Standard keys; a control routinely refers to three or more standards, which is
    # exactly where an un-keyed name list stops being usable and starts being ambiguous.
    standards: list[StandardRef] = Field(
        default_factory=list,
        description="Referred standards for this control, each with its Control_Standard "
                    "database key (Control_Library_Standard_Map is many-to-many, so a control "
                    "commonly refers to several).")


class SupportingSystemInvolved(ApiModel):
    """One supporting system this scenario's own narrative is actually about — its entry point,
    or a system whose data/availability/integrity the scenario's consequences affect. Resolved
    and id-stamped by tasks.py::_ground_entry_points; a system the scenario doesn't involve at
    all simply has no entry here, never a `false`-flavoured row. Replaces the five-field spread
    this used to be split across (entry_point/entry_point_id/other_plausible_entry_points/
    plausible_entry_point_ids/supporting_system_applicability) — one list, id and name always
    together, nothing to zip against a second array by position."""
    supporting_system_id: int = Field(description="onboarding_supporting_systems primary key.")
    supporting_system: str = Field(description="Supporting system name, copied exactly from the session's scope.")
    is_entry_point: bool = Field(
        description="True for the ONE system through which this scenario's threat reaches the "
                    "asset (at most one true per scenario). False means affected but not the "
                    "entry path.")
    # default="", not required: a missing justification must degrade, never crash the whole
    # results page for every OTHER scenario in the session — same fail-open posture as every
    # other model-authored prose field in this file. Verified: without this default, a single
    # scenario whose repair turn omitted the field 500s every read of the session's results.
    justification: str = Field(default="", description="One-sentence rationale, grounded in the context.")

    @field_validator("justification", mode="before")
    @classmethod
    def _null_is_absent(cls, v):
        """default="" alone only covers a MISSING key — a stored row carrying an explicit
        `null` (any row written before tasks.py's write-time normalization, or any future
        write path that misses it) still needs to degrade rather than 500. Verified: without
        this, ScenarioNarrative(justification=None) still raises."""
        return "" if v is None else v


class ScenarioNarrative(ApiModel):
    """The LLM's scenario JSON passed through verbatim — the model's own prose, nothing else.

    `extra="allow"` is the point: scenario_title/scenario_statement/risk_statement — and anything
    else a future prompt adds — ride through unvalidated and unmodified, exactly as the bare dict
    this replaced did. Deliberately so: these are model-authored strings, and validating text the
    code doesn't control just converts an odd LLM response into a 500.
    `supporting_systems_involved` is declared because it's structured, not a bare string, and
    benefits from a typed OpenAPI component rather than a hand-copied prose description (a
    hand-copied one is exactly how the smoke guides ended up documenting `title`/`narrative`, keys
    the API has never returned).

    NEITHER `controls` NOR `threat_actors` live here any more. Both are ENVELOPE siblings now —
    ScenarioResult.controls / .actors — so each block answers exactly one question. Because
    `extra="allow"` passes through any key the builder writes, removing the declarations was not
    enough on its own: sessions.py::_scenario_narrative POPS both keys, which also stops a LEGACY
    row's model-authored `{name, why}` controls list from surfacing. Do not re-add either field
    here, and do not delete those pops.

    threat_category/threat_type/threat_name are NOT LLM output — they come from the
    Identified_Threat row this scenario was generated from, merged in at read time
    (sessions.py::_scenario_narrative) by every current caller. Default to None anyway: no
    enforced foreign key guarantees the join found a row (see _scenario_select's OUTER join),
    and a scenario written before this field existed carries none either.

    The FULL typed threat — with database keys — is NOT here. It is on the ENVELOPE, as
    ScenarioResult.threat / AcceptedScenario.threat, deliberately: a failed generation returns
    scenario=null, and the threat must survive that. Read it there, not through this model
    (extra="allow" means `scenario.threat` would silently read as absent rather than raise)."""
    model_config = ConfigDict(extra="allow", json_schema_extra={"example": _SCENARIO_EXAMPLE})

    threat_category: str | None = Field(default=None, description="This threat's STRIDE category, e.g. Spoofing, Tampering.")
    threat_type: str | None = Field(default=None, description="STRIDE threat type this scenario was generated from.")
    threat_name: str | None = Field(default=None, description="Human-readable threat name this scenario was generated from.")
    supporting_systems_involved: list[SupportingSystemInvolved] = Field(
        default_factory=list,
        description=(
            "Only the supporting systems this scenario's own narrative is actually about — its "
            "entry point plus any system it meaningfully affects. A system not listed here has "
            "no involvement in this scenario. Empty for scenarios written before this field "
            "existed, or when the session has no supporting systems in scope."
        ),
    )
    plausible_entry_point_ids: list[int] = Field(
        default_factory=list, exclude=True,
        description="INTERNAL — never serialized. Coverage target for "
                    "dal.variant_eligible_primaries: every system this same underlying threat "
                    "could ALSO credibly enter through, not just the one this scenario is about. "
                    "Kept off the wire because it describes a future scenario, not this one.",
    )


#: Shared by ScenarioResult and by the SessionResults example that embeds one.
_SCENARIO_RESULT_EXAMPLE: JsonDict = {
    "scenario_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    "scenario": _SCENARIO_EXAMPLE,
    "threat": {
        "threat_category": "Tampering",
        "grounding_status": "verified",
        "grounding_score": 100.0,
        "score": 70.0,
        "scope_rank": 3,
    },
    "actors": _ACTORS_EXAMPLE,
    "controls": [_MAPPED_CONTROL_EXAMPLE],
    "accepted": False,
    "moderation_checked": False,
    "moderation_flagged": None,
    "moderation_categories": [],
    "validation_status": "ok",
    "validation_errors": [],
    "generation_epoch": 1,
    "scenario_number": 1,
    "controls_mapped": True,
    "scenario_source": "generated",
    "replaced_scenarios": [],
}


class ScenarioResult(ApiModel):
    """One generated scenario for the session's asset, plus whether it has been accepted."""
    model_config = ConfigDict(json_schema_extra={"example": _SCENARIO_RESULT_EXAMPLE})

    scenario_id: str = Field(description="Generated scenario's unique id (GUID). Used to accept/regenerate this scenario.")
    scenario: ScenarioNarrative | None = Field(
        description=(
            "Generated scenario narrative — the model's own prose only: scenario_title, "
            "scenario_statement, risk_statement, supporting_systems_involved. Null if generation "
            "failed. Actors and controls are NOT in here; they are the sibling `actors` and "
            "`controls` blocks below."
        )
    )
    threat: ThreatResult | None = Field(
        default=None,
        description=(
            "The FULL threat this scenario was generated from, with every database key "
            "(ThreatCatalogueID, ThreatTypeID). Declared HERE, on the envelope, and deliberately "
            "NOT inside `scenario`: a failed generation returns scenario=null, and a reviewer "
            "must still be able to see WHICH threat failed. "
            "GroundingStatus `verified` = a real library row backs this threat (keys set); "
            "`unverified` = model-proposed with no confident library match (keys null). Null "
            "only when no Identified_Threat row joined at all (the OUTER join in "
            "sessions.py::_scenario_select) — note `actors` and `controls` are siblings, so they "
            "survive that miss rather than disappearing with the threat object."
        )
    )
    actors: list[ThreatActorRef] = Field(
        default_factory=list,
        description=(
            "Adversaries for this scenario's threat, each with its Threat_Actor database key. "
            "Taken from the LIBRARY only — the actors curated on the matched threat's TYPE "
            "(ThreatType_ThreatActor_Map), or the nearest active library actors when none are "
            "linked. The model never names an adversary, so a name here always corresponds to a "
            "real Threat_Actor row. Empty when the table holds none. "
            "A property of the THREAT: two scenarios generated from the same threat carry "
            "IDENTICAL actors — unlike `controls`, which are mapped per scenario. That asymmetry "
            "is why these are two separate lists and not one nested block."
        ),
    )
    controls: list[MappedControl] = Field(
        default_factory=list,
        description=(
            "Step-4 mitigating controls mapped from the control library, best first. A property "
            "of the SCENARIO — keyed by Threat_Scenario_Control_Map.ScenarioID, so two scenarios "
            "from the same threat routinely carry DIFFERENT controls. Empty means nothing matched "
            "well enough, but that only reads as a library gap once `controls_mapped` is true — "
            "check `controls_mapped` and `controls_unavailable` before concluding anything."
        ),
    )
    accepted: bool = Field(description="Whether a human reviewer has accepted this scenario.")
    # WHO decided, beside the flag that says a decision happened. `Accepted: true` with no
    # accepted_by used to be the only thing this endpoint could say. Named snake_case because
    # that is the convention the whole response surface is moving to — new fields land in the
    # target spelling rather than being renamed a second time.
    accepted_by: str | None = Field(
        default=None,
        description="User id of whoever accepted this scenario. Null if it has not been accepted, "
                    "or was accepted before this was recorded.")
    accepted_at: datetime | None = Field(
        default=None, description="When it was accepted (naive UTC). Null if not accepted.")
    rejected_by: str | None = Field(
        default=None,
        description="User id of whoever rejected this scenario. Null if it has not been rejected. "
                    "A scenario can never carry both an acceptor and a rejecter — "
                    "CK_Scenario_DecisionExclusive forbids it in the database.")
    rejected_at: datetime | None = Field(
        default=None, description="When it was rejected (naive UTC). Null if not rejected.")
    moderation_checked: bool = Field(
        description="Whether content moderation actually ran for this scenario. False means moderation_flagged is meaningless (never checked, not checked-and-clean) — off by default, or the moderation service was unavailable.",
    )
    # [REVIEW-FIX] previously ValidationJSON (where llm.moderate's result lands, via
    # tasks.py::_moderation_report) was never selected here at all — a flagged scenario was
    # written to the DB but invisible to any human reviewer through this API. None means
    # moderation was never checked (off by default, or the moderation service was
    # unavailable) — distinct from checked-and-clean (False).
    moderation_flagged: bool | None = Field(
        default=None,
        description="true if flagged by content moderation, false if checked and clean, null if moderation was never run (see moderation_checked).",
    )
    moderation_categories: list[str] = Field(
        default=[], description="Moderation categories that were flagged, e.g. violence. Empty unless moderation_flagged is true."
    )
    # [REVIEW-FIX] same gap as moderation above, for validate_scenario's own structural/
    # consistency report (missing fields, statement not referencing the threat, risk_statement
    # not referencing the asset/critical service) — also landed in ValidationJSON but was never
    # selected here either, so a warning-status scenario looked identical to a clean one through
    # this API. None means the field is missing/malformed, not "checked and clean" (that's "ok").
    validation_status: str | None = Field(
        default=None, description="Structural/consistency validation result: ok, warning, or null if not checked."
    )
    validation_errors: list[str] = Field(
        default=[],
        description=(
            "Validation warnings, e.g. 'scenario does not reference the identified threat'. "
            "Empty unless validation_status is warning."
        ),
    )
    generation_epoch: int = Field(
        description=(
            "Generation round that produced this scenario: 1 = the initial run; each "
            "regenerate/next-set round increments it. The highest epoch is the newest batch — "
            "clients use this to spot fresh scenarios without diffing output ids."
        ),
    )
    scenario_number: int = Field(
        default=1,
        description=(
            "Which of its threat's coexisting scenarios this is: 1 = the original, 2+ = alternate "
            "takes added by 'generate next set' when no brand-new threat could be found. How many "
            "a threat accumulates is not a fixed setting — it is one per supporting system that "
            "could credibly carry that threat to the asset, so it varies by threat and by asset. "
            "Group cards by ThreatID and label them with this number; do NOT render a "
            "'Scenario 1 of N' total, because N is not known until that threat's coverage is "
            "complete. Without this number, two scenarios of one threat look like unrelated "
            "entries."
        ),
    )
    # Step-4 mapping is a TAIL step of scenario generation (tasks.py::write_scenarios runs it once,
    # after every scenario in the batch is written), but scenario rows land incrementally — so a
    # caller polling /results mid-stage sees scenarios whose controls simply aren't computed yet.
    # Without this flag that state is indistinguishable from "mapped, nothing matched", and the
    # smoke guide's "an empty controls list is normal" then reads as reassurance in BOTH cases.
    # Mirrors Threat_Scenario.ControlsMappedAt, so false ALSO covers the unseeded-library
    # case: control_mapping bails at `controls.no_candidates` without stamping, deliberately, so
    # those outputs are picked up by a later run once Seed_to_Control_library.sql has been applied.
    scenario_source: str = Field(
        default="generated",
        description=(
            "Where this scenario's TEXT came from. `generated` = written for this asset. "
            "`library` = written for a DIFFERENT asset with an identical profile (same sector "
            "scope, asset type, sub-sector, and the same technology on each supporting system, "
            "in the same order) and reused here with the supporting-system names swapped to "
            "this asset's. Reused text is re-validated and its entry points re-resolved against "
            "this asset, and the swap is refused outright unless every name maps cleanly - but "
            "a reviewer signing a risk register is entitled to know the prose was not authored "
            "about the system in front of them. Ask for a bespoke version with "
            "POST /regenerate/scenarios, which never serves from the library."
        ),
    )
    controls_unavailable: bool = Field(
        default=False,
        description=(
            "true = this response could NOT read the control mapping (a transient database "
            "error), so `controls` is empty because we did not get to look — NOT because "
            "the library has nothing. Treat the list as unknown and retry; do not read it as a "
            "library gap. Always false on a healthy response, so an existing client that ignores "
            "this field behaves exactly as before. It exists because `ControlsMapped: true` with "
            "an empty list is documented as a genuine library-gap signal, and a failed read used "
            "to be indistinguishable from one — the same overloaded-empty defect that "
            "grounding.ControlMatches.answered was introduced to kill on the write side."
        ),
    )
    controls_mapped: bool = Field(
        description=(
            "Whether Step-4 control mapping has been attempted for this scenario. true with an "
            "empty `controls` = mapping ran and nothing in the library matched, a genuine "
            "library-gap signal. false = not attempted, for one of two reasons: SCENARIO_GENERATION "
            "is still running (mapping is its tail step, so controls appear once the session's "
            "status reaches REVIEW), or the control library was empty/unreachable when the stage "
            "ran — check the worker log for `controls.no_candidates` and confirm the control "
            "library is seeded."
        ),
    )
    # Declared LAST on purpose: Pydantic serializes in declaration order, and a nested array of
    # whole scenarios ahead of the scalars would bury GenerationEpoch/ScenarioNumber/
    # ControlsMapped under it. Self-referential — the only recursive model in this schema —
    # which resolves as a forward ref because of `from __future__ import annotations` above.
    replaced_scenarios: list[ScenarioResult] = Field(
        default=[],
        description=(
            "The older versions this scenario replaced, NEWEST FIRST: [0] is the version it "
            "directly replaced, then that one's predecessor, back to the first generation. "
            "Returned ONLY when the request passes ?include_replaced=true; otherwise always "
            "empty, so the default response is unchanged. Each entry carries its full scenario "
            "text and the controls it had mapped, so a reviewer can compare against the version "
            "that superseded it. The list is FLAT — the whole history is here and these entries' "
            "own `replaced_scenarios` are always empty, so never recurse. len() is how many "
            "times this scenario has been regenerated: 2 entries means it is version 3. "
            "NOT disjoint from the top-level cards: an accepted-but-superseded version appears "
            "BOTH as its own top-level card (flagged accepted) and inside its successor's "
            "history — the history is complete, deliberately; dedupe by scenario_id if rendering "
            "both."
        ),
    )


class SessionResults(ApiModel):
    """The scenarios produced so far for a session, each carrying its own threat."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "entity_id": "ENT-001",
                "asset_id": 12345,
                "asset_name": "SCADA Historian",
                "user_id": "qa-user",
                "scenarios": [_SCENARIO_RESULT_EXAMPLE],
            }
        }
    )

    session_id: str = Field(description="Session's unique id (GUID).")
    entity_id: str = Field(description="Tenant/business-unit code the session belongs to.")
    asset_id: int = Field(description="Primary key of the asset this session belongs to.")
    asset_name: str = Field(description="Display name of the asset this session belongs to.")
    user_id: str | None = Field(description="The session's owning user (who created it). Null only if the principal had no identity to record.")
    progress: SessionProgress | None = Field(
        default=None,
        description=(
            "Readiness snapshot, so this response can be told apart from a FINISHED one. The "
            "scenario list below is whatever exists right now: while a run or a 'generate next "
            "set' click is still working it is a partial view that looks exactly like a "
            "completed one. Check `progress.overall` before treating it as final, and "
            "`progress.last_next_set.epoch` to confirm your own click has landed."
        ),
    )
    # No top-level `threats` list. It was REMOVED, not relocated: it only ever contained
    # threats that already had an active scenario row (get_results' own EXISTS predicate), so
    # every entry was a duplicate of some card's own threat — and keeping the two in sync was
    # the reason for the missing_tids backfill query that used to live here. Each card now
    # carries its threat on ScenarioResult.threat, which cannot drift from the card it
    # describes because it is read from the same row.
    scenarios: list[ScenarioResult] = Field(
        description="All scenarios generated so far for this session. Versions that regeneration "
                    "replaced are nested inside the scenario that replaced them, in its "
                    "`replaced_scenarios`, and only when ?include_replaced=true."
    )


class AcceptResponse(ApiModel):
    """Response confirming an accept request was processed."""
    model_config = ConfigDict(
        json_schema_extra={"example": {"session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "user_id": "qa-user", "status": "completed", "accepted_count": 3}}
    )

    session_id: str = Field(description="Session's unique id (GUID).")
    user_id: str | None = Field(description="The session's owning user (who created it). Null only if the principal had no identity to record.")
    status: str = Field(description="Result of the accept request. Always 'completed' on success.")
    accepted_count: int = Field(description="Number of scenarios actually marked accepted by this request (0 for mode='none').")


class PromotedRef(ApiModel):
    """One master-library row this promotion touched, with every key the UI needs to join on.

    No bare names anywhere — same reasoning as MappedControl.Standards: an un-keyed name list
    "stops being usable and starts being ambiguous". `status` is the field to branch on."""
    id: int | None = Field(description="The master row's primary key. Null only when status is "
                                       "'failed' and no row could be resolved.")
    name: str = Field(description="Display name of the master row.")
    status: Literal["inserted", "existing", "failed"] = Field(
        description="'inserted' — a NEW master row exists because of this call. 'existing' — one "
                    "was already there and was reused (the normal case; nothing was duplicated). "
                    "'failed' — see `error`.")
    error: str | None = Field(default=None, description="Why this item failed. Null otherwise.")
    type_id: int | None = Field(default=None, description="Threat_Type key this row hangs off — "
                                                          "set on the threat and on every actor.")
    category_id: int | None = Field(default=None, description="Threat_Category key. Null when the "
                                                              "AI's category text matched no master row.")
    linked: bool | None = Field(default=None, description="Actors only: true when THIS call wrote "
                                "a new ThreatType_ThreatActor_Map row (actors attach per TYPE in "
                                "this model). Always false on an EXISTING catalogue threat — its "
                                "curation belongs to the curators and is never touched.")


class LibraryPromotionResponse(ApiModel):
    """Result of promoting one accepted scenario's threat data into the shared master library.

    Every entity carries its database id and the id of what it links to. Controls are REPORTED,
    never written: they are selected from the curated Control_Library during generation, so a
    mapped control is already master data and there is never a new one to create."""
    model_config = ConfigDict(json_schema_extra={"example": {
        "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        "scenario_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
        "success": True, "created_count": 1,
        "threat_type": {"id": 42, "name": "Ransomware", "category_id": 2, "status": "existing"},
        "threat": {"id": 187,
                   "name": "Ransomware encrypts historian data at rest",
                   "type_id": 42, "category_id": 2,
                   "status": "inserted"},
        "threat_actors": [{"id": 9, "name": "APT-Nova", "type_id": 42,
                           "status": "existing", "linked": True}],
        "controls": [{"control_id": 771, "control_code": "CII-CID-201", "domain": "Access Control",
                      "control_name": "Privileged access review", "map_rank": 1, "score": 82.4}],
        "controls_mapped": True}})

    session_id: str = Field(description="Session's unique id (GUID).")
    scenario_id: str = Field(description="The promoted scenario's unique id (GUID).")
    success: bool = Field(description="False when any item reports status 'failed'. The rest of "
                                      "the promotion still stands — check each item's status.")
    created_count: int = Field(description="How many NEW master rows this call created. 0 on a "
                                           "repeat call, which is the expected idempotent result.")
    threat_type: PromotedRef = Field(description="The Threat_Type row.")
    threat: PromotedRef = Field(description="The Threat_Catalogue row.")
    threat_actors: list[PromotedRef] = Field(
        default_factory=list,
        description="Threat_Actor rows linked to the type. Always 'existing' in practice — the AI "
                    "never invents an adversary, so this endpoint links but never creates actors.")
    controls: list[MappedControl] = Field(
        default_factory=list,
        description="Controls already mapped to this scenario at generation time. Read-only.")
    controls_mapped: bool = Field(description="False when Step-4 control mapping has not produced "
                                              "rows for this scenario yet.")


class RejectBody(ApiModel):
    """Body for the "reject scenarios" endpoint — an explicit, recorded decline.

    Always an explicit list. There is deliberately no `mode` and no reject-all: accept has three
    modes because "accept everything" is the common case, while declining every scenario is not a
    click a reviewer should be one mis-tap away from. Leaving scenarios pending is already a valid
    resting state, so the destructive-looking shortcut buys nothing."""
    model_config = ConfigDict(
        json_schema_extra={"examples": [{"scenario_ids": ["3fa85f64-5717-4562-b3fc-2c963f66afa6"]}]}
    )

    scenario_ids: list[str] = Field(
        description=(
            f"Output ids to reject (non-empty, max {_MAX_BATCH}). Rejecting records WHO declined "
            "the scenario and WHEN; it does not delete it, and the scenario stays visible in "
            "GET /results. An id already accepted comes back 404 with reason 'already_accepted' "
            "— the two decisions are mutually exclusive. Rejecting the same id twice is a no-op "
            "that preserves the original decision, not a rewrite of it."
        ),
    )

    _canonicalize_scenario_ids = field_validator("scenario_ids")(_canonical_scenario_ids)

    @model_validator(mode="after")
    def _scenario_ids_within_bounds(self) -> RejectBody:
        # Same reasoning as AcceptBody: bounds live here, not as Field constraints, so the
        # message is written for the caller rather than by Pydantic's generic length check.
        if not self.scenario_ids:
            raise ValueError("scenario_ids is required (non-empty)")
        if len(self.scenario_ids) > _MAX_BATCH:
            raise ValueError(f"scenario_ids must have at most {_MAX_BATCH} items")
        return self


class RejectResponse(ApiModel):
    """Response confirming a reject request was processed."""
    model_config = ConfigDict(
        json_schema_extra={"example": {"session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "user_id": "qa-user", "rejected_count": 2}}
    )

    session_id: str = Field(description="Session's unique id (GUID).")
    user_id: str | None = Field(description="The session's owning user (who created it). Null only if the principal had no identity to record.")
    rejected_count: int = Field(description="Number of scenarios actually marked rejected by this request.")


class RegenerateResponse(ApiModel):
    """Response confirming a regenerate/next-set request was ACCEPTED — not that it finished.

    The work runs on a Celery worker and can take minutes; this returns in milliseconds. `epoch`
    is how you find out when it is done (see its description) — without it a client has no way to
    distinguish "my click is still running" from "my click finished", which is exactly how a
    mid-flight read of /results looks like a completed one."""
    model_config = ConfigDict(
        json_schema_extra={"example": {"session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "user_id": "qa-user", "status": "regenerating", "epoch": 4}}
    )

    session_id: str = Field(description="Session's unique id (GUID).")
    user_id: str | None = Field(description="The session's owning user (who created it). Null only if the principal had no identity to record.")
    status: str = Field(
        description="Result of the request: 'regenerating' for a scenario regenerate request, 'generating' for a next-set request."
    )
    epoch: int = Field(
        description=(
            "Generation epoch reserved for THIS request. Poll GET /v1/sessions/{session_id} "
            "until the MATCHING progress field's epoch equals this value — that, not the stage "
            "status, is the exact signal that your click landed. For a regenerate request "
            "(status='regenerating') that field is `progress.last_regen.epoch`; for a next-set "
            "request (status='generating') it is `progress.last_next_set.epoch` — the two never "
            "share one field, since each is written from a different audit event. Plan item 3: "
            "earlier this description pointed a regenerate caller at `last_next_set`, a field "
            "regen never writes, so that poll could never observe a regen finishing. It stays "
            "correct when another tab clicks concurrently (each waits for its own epoch) and it "
            "turns a stalled worker into a diagnosable 'my epoch never arrived' rather than an "
            "endless wait."
        ),
    )


class CancelResponse(ApiModel):
    """Response confirming a session was cancelled."""
    model_config = ConfigDict(
        json_schema_extra={"example": {"session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "user_id": "qa-user", "status": "cancelled"}}
    )

    session_id: str = Field(description="Session's unique id (GUID).")
    user_id: str | None = Field(description="The session's owning user (who created it). Null only if the principal had no identity to record.")
    status: str = Field(description="Always 'cancelled' on success.")


# --- Error envelope -----------------------------------------------------------------------------
# errors.py builds these bodies by hand; these models exist to DESCRIBE that shape in the OpenAPI
# spec, not to construct it. Without them ReviewGateReason reaches no route and never appears in
# /openapi.json — leaving the UI to hand-copy exactly the codes it most needs, since they decide
# whether a blocked action shows a dead end or a spinner.
class ErrorDetails(ApiModel):
    """`details` on a 4xx envelope. Open-ended by design: handlers attach cause-specific keys
    (`existing_id`, `active_session_id`, …) alongside the common ones below."""
    model_config = ConfigDict(extra="allow")

    reason: ReviewGateReason | ClickOutcomeReason | TreatmentGateReason | None = Field(
        default=None,
        description=(
            "Machine-readable cause, when the raise site gave one. A ReviewGateReason means the "
            "request never ran (wrong session state); a ClickOutcomeReason means it ran and "
            "resolved to nothing; a TreatmentGateReason means a treatment-plan request was "
            "refused. Absent on raise sites with no stable cause, e.g. the "
            "target-went-stale race. "
            "RETRY SEMANTICS, for a client deciding between a spinner and a dead end: "
            "`generation_in_progress` is the ONLY one worth waiting on — a worker is provably "
            "alive (it holds an unexpired lease), so polling will clear it. "
            "`generation_abandoned` is its opposite and is NOT retryable: the previous run died "
            "or hung and automatic recovery could not return the session to REVIEW, so waiting "
            "changes nothing — start a new session for the asset."
        ),
    )
    detail: str | None = Field(default=None, description="Developer-facing explanation. Never show this to an end user.")
    message: str | None = Field(default=None, description="End-user-safe sentence for this reason, when one is defined.")


class ErrorResponse(ApiModel):
    """The envelope every 4xx/5xx body uses (see errors.py::_env)."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "error_code": "regenerate_conflict",
                "message": "session not at REVIEW yet (stage=SCENARIO_GENERATION, status=RUNNING) — generation still in progress",
                "details": {"reason": "generation_in_progress"},
            }
        }
    )

    error_code: str = Field(description="Stable machine-readable error class, e.g. 'regenerate_conflict'.")
    message: str = Field(description="Human-readable summary of what went wrong.")
    details: ErrorDetails | None = Field(default=None, description="Cause-specific extras; omitted when there are none.")


class LivenessReport(ApiModel):
    """`GET /health` — the liveness probe's body. Trivial, but untyped it published an EMPTY object,
    so a generated client could not see even this one field."""
    status: Literal["ok"] = Field(description="Always 'ok'; the route returns 200 unconditionally.")


class ReadinessReport(ApiModel):
    """`GET /ready` — per-dependency readiness.

    `checks` is deliberately a mapping rather than named fields: the dependency set is
    configuration-dependent (Mongo is skipped when unused), so a fixed shape would publish
    dependencies a given deployment does not have. The VALUES are closed, which is the part worth
    typing — 'skipped' is distinct from 'ok' and means the dependency is not in use here.

    Note the route returns its 503 with a plain `JSONResponse` rather than raising, so that body is
    THIS shape, not the ErrorResponse envelope — which is why /ready must NOT take the shared
    UNAVAILABLE_RESPONSES fragment. Attaching it would publish a lie."""
    status: Literal["ready", "not_ready"] = Field(
        description="'not_ready' is returned with HTTP 503 so an orchestrator pulls the pod.")
    checks: dict[str, Literal["ok", "error", "skipped"]] = Field(
        description="Per-dependency outcome. 'skipped' = not used by this deployment.")


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


#: Attach to any route that can answer 503 — `responses=UNAVAILABLE_RESPONSES` on its decorator.
#:
#: Same idea as treatment._CONFLICT_RESPONSES: the ROUTE declares what it can return, because the
#: route is what knows. This replaced a central set of route PATHS in main.py, which had exactly
#: the failure a central list invites — the {output_id} -> {scenario_id} rename silently orphaned
#: two of its six entries, so those routes stopped declaring 503 with no boot error and no failing
#: test. A path list nothing validates goes stale in silence; a decorator argument moves with the
#: route it is attached to.
UNAVAILABLE_RESPONSES: dict[int | str, dict] = {
    503: {"model": ErrorResponse,
        "description": "Temporarily unavailable — retry. Capacity and stream-ceiling responses "
                        "also carry Retry-After."}}


# --- SSE event payloads -------------------------------------------------------------------------
# Same rationale: cascade.py publishes these dicts, and the /events route streams them, so nothing
# would otherwise describe them in the spec. Publishing through these models keeps the wire and the
# documented schema from drifting.
class NextSetResultEvent(ApiModel):
    """`next_set_result` — one "generate next set" click finished.

    ADVISORY. Best-effort, behind a circuit breaker, never replayed (app/sse/bus.py), so treat it
    as a prompt to refresh rather than as the record. `SessionProgress.last_next_set` on the status
    board carries the same facts durably and is what a reconnecting client should trust."""
    # Literal, NOT the bare enum: these models are served as a UNION, and a field typed as the whole
    # SSEEventType gives the union no discriminator — a generated client would validate ANY event
    # type as a NextSetResultEvent. The Literal emits {"const": "next_set_result"} per member.
    type: Literal[SSEEventType.next_set_result] = Field(description="Always 'next_set_result'.")
    session_id: str = Field(description="Session the click belonged to.")
    subsystem_id: int = Field(description="Unit of work; always 0 (the asset itself).")
    outcome: NextSetOutcome = Field(description="What the click achieved — see NextSetSummary.outcome.")
    requested: int = Field(description="Scenarios the click aimed to add.")
    new_scenarios: int = Field(description="Scenarios actually added — fresh plus variants (i.e. `delivered`).")
    new_variants: int = Field(description="How many of `new_scenarios` are alternate takes on already-covered threats.")
    no_new: bool = Field(description="True when the click added nothing at all.")
    epoch: int = Field(description="Generation epoch this click ran at; matches the POST's `epoch`.")
    reason: ClickOutcomeReason | None = Field(default=None, description="Why the click fell back or came up empty.")
    detail: str | None = Field(default=None, description="Developer-facing explanation; populated only on a fruitless click.")
    message: str | None = Field(
        default=None,
        description="End-user sentence; populated only on a fruitless click, because the wording "
                    "says nothing was added and would contradict a payload reporting new scenarios.",
    )
    ts: datetime = Field(description="When the event was published (UTC, ISO-8601).")


class RegenResultEvent(ApiModel):
    """`regen_result` — one regenerate click finished.

    Deliberately carries NO outcome/requested fields: regenerate REPLACES rather than adds, so its
    scenario count never changes and a batch-size notion would be meaningless here."""
    type: Literal[SSEEventType.regen_result] = Field(description="Always 'regen_result'.")  # see NextSetResultEvent.type
    session_id: str = Field(description="Session the click belonged to.")
    subsystem_id: int = Field(description="Unit of work; always 0 (the asset itself).")
    requested_scenario_ids: list[str] = Field(description="scenario_ids the client asked to regenerate.")
    new_scenario_ids: list[str] = Field(description="Replacement scenario_ids. Empty means the click was fruitless.")
    replacements: list[dict[str, str]] = Field(
        default_factory=list,
        description="old→new pairs. The two flat lists above cannot express the mapping when "
                    "several targets are regenerated at once; these can.",
    )
    failed_threat_ids: list[str] = Field(
        default_factory=list,
        description="Threats in this batch whose generation call itself failed — transient, "
                    "still Selected and re-servable; retrying the same regenerate is worth it.",
    )
    rescored_threat_ids: list[str] = Field(
        default_factory=list,
        description="Threats in this batch that no longer meet the current scoping cutoff — "
                    "terminal; retrying will not change the outcome.",
    )
    reason: ClickOutcomeReason | None = Field(default=None, description="Why the click was fruitless; null for the target-went-stale race.")
    detail: str | None = Field(default=None, description="Developer-facing explanation.")
    message: str | None = Field(default=None, description="End-user-safe sentence.")
    ts: datetime = Field(description="When the event was published (UTC, ISO-8601).")


class TreatmentPlanResultEvent(ApiModel):
    """`treatment_plan_result` — one treatment plan reached a committed COMPLETE or ERROR.

    ADVISORY, and weaker than the two above: it is a prompt to REFETCH, never a completion
    contract. It is published only when the worker's finish CAS actually rewrote the row, so three
    outcomes never emit one — a dead worker (the row stays RUNNING and only the GET's read-time
    projection calls it timed out; there is no reaper), an LLMSlotUnavailable autoretry (which
    keeps bumping the progress clock, so the row never even goes stale), and cancel plus a plain
    review verdict (written in the API process, not the worker). One API-side action DOES emit it:
    an approve that switches the active plan version publishes after its commit, so a watching
    client refetches the swapped-in plan. A publish failure additionally silences every event in
    that worker process for a cooldown window. **A client MUST therefore keep a slow backstop poll**
    — this event only makes the common case feel instant.

    Match on `scenario_id`: a regeneration mints a NEW plan_id, so a client keyed on plan_id would
    discard the very event it is waiting for."""
    type: Literal[SSEEventType.treatment_plan_result] = Field(
        description="Always 'treatment_plan_result'.")  # see NextSetResultEvent.type
    session_id: str = Field(description="Session the plan belongs to.")
    scenario_id: str = Field(
        description="The accepted scenario this plan treats. MATCH ON THIS — it is stable across "
                    "regenerations, unlike plan_id.")
    plan_id: str = Field(
        description="Informational: the Risk_Treatment_Plan row that finished. A regeneration "
                    "produces a different one for the same scenario_id.")
    status: Literal[StageStatus.COMPLETE, StageStatus.ERROR] = Field(
        description="The committed status. Refetch for the detail.")
    reason: TreatmentOutcomeReason | None = Field(
        default=None,
        description="Why, when status is ERROR — see TreatmentPlanStatus.reason. Null on COMPLETE.")
    ts: datetime = Field(description="When the event was published (UTC, ISO-8601).")


# Plan item 25: typed models for the 6 event kinds that previously reached the wire with no
# schema at all (only NextSetResultEvent/RegenResultEvent/TreatmentPlanResultEvent existed).
# Field shapes are taken directly from their publish call sites — tasks.py::_send_live_update for
# the two stage events, and the three bus.publish() calls below it for subsystem_started/
# session_entered_review/error (app/pipeline/tasks.py).
class StageStartedEvent(ApiModel):
    """`stage_started` — one (subsystem, level) work cell was just claimed and began running."""
    type: Literal[SSEEventType.stage_started] = Field(description="Always 'stage_started'.")  # see NextSetResultEvent.type
    session_id: str = Field(description="Session the stage belongs to.")
    subsystem_id: int = Field(description="Unit of work; always 0 (the asset itself).")
    stage: SubsystemLevel = Field(description="Which work cell started: THREATS or SCENARIOS.")
    status: Literal[StageStatus.RUNNING] = Field(
        description="Always 'RUNNING' — this event fires only at claim time, from the one call "
                    "site that publishes it.")
    generation_epoch: int = Field(description="Generation epoch this run is claimed at.")
    ts: datetime = Field(description="When the event was published (UTC, ISO-8601).")


class StageCompletedEvent(ApiModel):
    """`stage_completed` — one (subsystem, level) work cell finished successfully; a failure
    routes to `error` instead and never reaches this event.

    TWO real values for `status`, not one, both published from the SAME call site
    (tasks.py::_send_live_update): THREATS finishes `StageStatus.COMPLETE`; SCENARIOS finishes
    `StageStatus.AWAITING_DECISION` — SCENARIOS reaching AWAITING_DECISION *is* the review
    barrier, not an unfinished state. A single-value Literal (this file's usual convention for
    every other event's discriminator-adjacent field) would reject half this event's real
    traffic, so both values are declared here deliberately."""
    type: Literal[SSEEventType.stage_completed] = Field(description="Always 'stage_completed'.")  # see NextSetResultEvent.type
    session_id: str = Field(description="Session the stage belongs to.")
    subsystem_id: int = Field(description="Unit of work; always 0 (the asset itself).")
    stage: SubsystemLevel = Field(description="Which work cell finished: THREATS or SCENARIOS.")
    status: Literal[StageStatus.COMPLETE, StageStatus.AWAITING_DECISION] = Field(
        description="THREATS finishes COMPLETE; SCENARIOS finishes AWAITING_DECISION (the "
                    "review barrier). Never any other value — a failure publishes `error`.")
    generation_epoch: int = Field(description="Generation epoch this run finished at.")
    ts: datetime = Field(description="When the event was published (UTC, ISO-8601).")


class SubsystemStartedEvent(ApiModel):
    """`subsystem_started` — fires BEFORE this subsystem's stages run. Subsystem-scoped, no
    `stage` field: it precedes both THREATS and SCENARIOS for this subsystem."""
    type: Literal[SSEEventType.subsystem_started] = Field(description="Always 'subsystem_started'.")  # see NextSetResultEvent.type
    session_id: str = Field(description="Session the subsystem belongs to.")
    subsystem_id: int = Field(description="Unit of work about to start; always 0 (the asset itself).")
    generation_epoch: int = Field(description="Generation epoch this run starts at.")
    ts: datetime = Field(description="When the event was published (UTC, ISO-8601).")


class SessionEnteredReviewEvent(ApiModel):
    """`session_entered_review` — every subsystem hit its review barrier; the session is now
    parked at REVIEW waiting on a human decision. Session-wide: never carries subsystem_id."""
    type: Literal[SSEEventType.session_entered_review] = Field(
        description="Always 'session_entered_review'.")  # see NextSetResultEvent.type
    session_id: str = Field(description="Session that entered review.")
    status: Literal[StageStatus.AWAITING_DECISION] = Field(
        description="Always 'SCENARIOS_AWAITING_DECISION' — the review-barrier value.")
    generation_epoch: int = Field(description="Generation epoch active when the session entered review.")
    ts: datetime = Field(description="When the event was published (UTC, ISO-8601).")


class ErrorEvent(ApiModel):
    """`error` — a stage failed, or the whole session failed. DUAL-scope by design (plan item
    27); `scope` says which instead of leaving a client to infer it from whether `subsystem_id`
    happens to be present:

    - `scope="stage"` (tasks.py::_record_failure): one subsystem's stage errored.
      `subsystem_id`/`generation_epoch` are present; the session may still recover (a live retry,
      or the reviewer regenerating/next-setting once at REVIEW).
    - `scope="session"` (tasks.py::_mark_session_failed): every subsystem errored and the session
      was marked cancelled server-side. `subsystem_id`/`generation_epoch` are absent — there is
      no single stage left to name, and no epoch to compare against.

    KNOWN GAP, not closed by item 27: `error` also has THREE other publish sites, all in
    app/pipeline/reaper.py (item 5's dead-worker sweep — a different, earlier phase), and none of
    them set `scope` yet — two are stage-scoped (subsystem_id present) and one is session-scoped
    (rowcount-gated, no subsystem_id), but the field itself is simply absent on the wire for all
    three. `scope` is therefore OPTIONAL here rather than required: a client that only switches on
    `scope` will silently miss a reaper-originated error. Until reaper.py is updated to match, a
    robust client falls back to "subsystem_id present" (the pre-item-27 rule) whenever `scope` is
    null. See docs/SSE_SESSION_PROGRESS_CONTRACT_GUIDE.md for the full gap list.

    Plan item 28 — READ BEFORE WIRING UI TEARDOWN: a stage-scoped `error` is NOT necessarily
    terminal for the session (the pipeline can still finish other subsystems, or a human can
    regenerate). Clients MUST NOT tear down UI on `error` alone — wait for
    `session_entered_review`, or a terminal `session_status` (`completed`/`cancelled`) from a
    `reconcile` event or a `GET /v1/sessions/{session_id}` poll, before treating the session as
    finished."""
    type: Literal[SSEEventType.error] = Field(description="Always 'error'.")  # see NextSetResultEvent.type
    session_id: str = Field(description="Session the error belongs to.")
    scope: Literal["stage", "session"] | None = Field(
        default=None,
        description="'stage' = one subsystem's stage failed (subsystem_id/generation_epoch "
                    "present, session not necessarily done); 'session' = every subsystem failed "
                    "and the session was cancelled (subsystem_id/generation_epoch absent, "
                    "terminal); null = published by the reaper's dead-worker sweep, which does "
                    "not set this field yet (known gap) — fall back to whether subsystem_id is "
                    "present.")
    subsystem_id: int | None = Field(
        default=None, description="Unit of work that failed; null when scope='session' (or when "
                                "scope is null and no single stage applies).")
    message: str = Field(description="Client-safe failure reason.")
    generation_epoch: int | None = Field(
        default=None, description="Epoch the failed stage was running at; null when scope='session' "
                                "or not applicable.")
    ts: datetime = Field(description="When the event was published (UTC, ISO-8601).")


class HeartbeatEvent(ApiModel):
    """`heartbeat` — keep-alive so proxies don't drop an idle SSE connection (sse_starlette's
    `ping`, on `sse_ping_seconds`). Carries no progress information; a client should ignore its
    content and only use its arrival to reset its own idle/liveness timer."""
    type: Literal[SSEEventType.heartbeat] = Field(description="Always 'heartbeat'.")  # see NextSetResultEvent.type
    session_id: str = Field(description="Session this heartbeat keeps alive.")
    ts: datetime = Field(description="When the heartbeat was sent (UTC, ISO-8601).")


#: Shared by AcceptedScenario and by the AcceptedScenariosResponse example that embeds one.
_ACCEPTED_SCENARIO_EXAMPLE: JsonDict = {
    "scenario_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    "subsystem_id": 101,
    "scenario": _SCENARIO_EXAMPLE,
    "actors": _ACTORS_EXAMPLE,
    "controls": [_MAPPED_CONTROL_EXAMPLE],
}


class AcceptedScenario(ApiModel):
    """One accepted scenario row — joinable on ids."""
    model_config = ConfigDict(json_schema_extra={"example": _ACCEPTED_SCENARIO_EXAMPLE})

    scenario_id: str = Field(description="Accepted scenario's unique id (GUID).")
    # Same four as ScenarioResult. Declared on THIS base so ScenarioListItem and every route that
    # returns it inherit them — one declaration, not one per response model, which is the drift
    # that dal.scenario_threat_columns() exists to prevent one layer down.
    accepted_by: str | None = Field(
        default=None,
        description="User id of whoever accepted this scenario. Null if accepted before this was "
                    "recorded.")
    accepted_at: datetime | None = Field(
        default=None, description="When it was accepted (naive UTC).")
    rejected_by: str | None = Field(
        default=None,
        description="User id of whoever rejected this scenario. Null unless rejected — mutually "
                    "exclusive with accepted_by.")
    rejected_at: datetime | None = Field(
        default=None, description="When it was rejected (naive UTC).")
    controls_unavailable: bool = Field(
        default=False,
        description=(
            "true = the control mapping could not be read for this response, so "
            "`controls` is empty because we did not get to look. See "
            "ScenarioResult.ControlsUnavailable."
        ),
    )
    subsystem_id: int = Field(
        description="Unit of work this scenario belongs to: 0 = the asset itself, >= 1 = a specific "
                    "supporting system. Scenarios are written at the asset unit; a threat's reach "
                    "across supporting systems is reported per scenario in "
                    "`scenario.supporting_systems_involved`."
    )
    scenario: ScenarioNarrative | None = Field(
        description=(
            "Accepted scenario narrative — the model's own prose only: scenario_title, "
            "scenario_statement, risk_statement, supporting_systems_involved. Identical shape to "
            "ScenarioResult.scenario. Actors and controls are the sibling blocks below."
        )
    )
    threat: ThreatResult | None = Field(
        default=None,
        description="The FULL threat this scenario was generated from, identical shape and rules "
                    "to ScenarioResult.threat — every database key. "
                    "The flat ThreatTypeID/ThreatCatalogueID/ThreatType/ThreatName/Library* "
                    "fields above remain for existing clients and report the same values."
    )
    actors: list[ThreatActorRef] = Field(
        default_factory=list,
        description="Adversaries for this scenario's threat, each with its Threat_Actor database "
                    "key. Identical shape and rules to ScenarioResult.actors — a property of the "
                    "THREAT, so scenarios sharing a threat carry identical actors.",
    )
    controls: list[MappedControl] = Field(
        default_factory=list,
        description="Step-4 mitigating controls mapped from the control library, best first. "
                    "Identical shape and rules to ScenarioResult.controls — a property of the "
                    "SCENARIO, so scenarios sharing a threat routinely carry different controls.",
    )


class AcceptedScenariosResponse(ApiModel):
    """The accepted scenarios for one session (whichever version was accepted — possibly one
    a regeneration superseded), identified solely by the session_id in the URL path. asset_id
    and entity_id are read off that session (not separate inputs) and returned here so a
    caller with only a session_id can still learn which asset/entity it belongs to."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "asset_id": 12345,
                "entity_id": "ENT-001",
                "user_id": "qa-user",
                "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "completed_at": "2026-07-20T14:32:11.123Z",
                "scenarios": [_ACCEPTED_SCENARIO_EXAMPLE],
            }
        }
    )

    asset_id: int = Field(description="Primary key of the asset this session belongs to.")
    entity_id: str = Field(description="Tenant/business-unit code this session belongs to.")
    user_id: str | None = Field(description="The session's owning user (who created it). Null only if the principal had no identity to record.")
    session_id: str = Field(description="The session id from the URL path (echoed back).")
    completed_at: datetime | None = Field(
        description="UTC timestamp the session was completed. Null if the session hasn't completed yet "
                    "(scenarios == [] in that case, since acceptance only happens at completion)."
    )
    scenarios: list[AcceptedScenario] = Field(description="Accepted scenarios for this session (whichever version was accepted — possibly one a regeneration superseded).")


#: ScenarioListItem's example — the shared AcceptedScenario example plus the cross-session
#: context fields (built by spreading, never hand-copied — see the comment on _SCENARIO_EXAMPLE).
_SCENARIO_LIST_ITEM_EXAMPLE: JsonDict = {
    **_ACCEPTED_SCENARIO_EXAMPLE,
    "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "entity_id": "ENT-001",
    "user_id": "qa-user",
    "session_status": "completed",
    "scenario_number": 1,
    "accepted": True,
    "superseded": False,
    "created_at": "2026-07-20T14:32:11.123Z",
}


class ScenarioListItem(AcceptedScenario):
    """One scenario row with its session context — the cross-session reads
    (GET /v1/users/{user_id}/scenarios, GET /v1/entities/{entity_id}/scenarios,
    GET /v1/sessions/{session_id}/scenarios/{scenario_id}) all return this shape."""
    model_config = ConfigDict(json_schema_extra={"example": _SCENARIO_LIST_ITEM_EXAMPLE})

    # RENAME BOUNDARY (Phase 4): columns of the THREAT / SCENARIO / CONTROL tables carry their
    # DB spelling above; the four session-envelope fields below deliberately keep their wire
    # spelling, because AcceptedScenariosResponse returns the same four at its top level and
    # splitting the two would leave one payload disagreeing with itself.
    session_id: str = Field(description="Owning session's unique id (GUID).")
    entity_id: str = Field(description="Tenant/business-unit code the owning session belongs to.")
    user_id: str | None = Field(
        description="The session's owning user (who created it). Null only if the principal had no identity to record."
    )
    session_status: str = Field(description="Owning session's status: active | completed | cancelled.")
    scenario_number: int = Field(description="1 = original scenario, 2+ = coexisting 'next set' alternates.")
    accepted: bool = Field(description="True once the user accepted this scenario.")
    superseded: bool = Field(
        description="True if a regeneration replaced this row. Only reachable in lists with "
                    "include_superseded=true, or on a direct fetch by scenario_id."
    )
    created_at: datetime | None = Field(description="UTC timestamp the scenario row was created.")


class SessionAuditEvent(ApiModel):
    """One step in a session's history.

    EVERY row names what it acted on. Without that, the trail reads as an unexplained hop between
    people — user1, then system, then user2 — because the SUBJECT is changing and nothing says so.
    With it, the same sequence reads plainly: user1 started the session, the system generated
    scenarios, user2 accepted scenario A, user2 approved the plan for scenario A.

    `actor_user_id` is WHO ACTUALLY DID IT and is null for pipeline steps — that is information,
    not missing data. It used to be back-filled with the session owner, which is what made the
    timeline unreadable. `actor_type` states it outright so nothing has to be inferred."""
    audit_id: str = Field(description="This entry's unique id (GUID).")
    at: datetime | None = Field(description="When it happened (UTC).")
    event: str = Field(
        description="What happened — an AuditEventType value. Typed as a string ON PURPOSE: the "
                    "column carries no database constraint, so one unrecognised historical value "
                    "would otherwise fail the whole page rather than the single row.")
    subject_type: Literal["session", "scenario", "plan"] = Field(
        description="What this step acted on. Derived: a plan id means the plan, else a scenario "
                    "id means that scenario, else the session as a whole.")
    scenario_id: str | None = Field(
        default=None, description="The scenario this step concerns, when it concerns one.")
    plan_id: str | None = Field(
        default=None, description="The treatment plan this step concerns, when it concerns one.")
    actor_user_id: str | None = Field(
        default=None,
        description="Who performed it. NULL means the pipeline did — read with actor_type.")
    actor_type: str | None = Field(
        default=None, description="'user' or 'system'. NULL only on rows predating the column.")
    stage: str | None = Field(default=None, description="Workflow stage, when the step has one.")
    subsystem_id: int | None = Field(
        default=None, description="0 = the asset itself; >= 1 = a specific supporting system.")
    decision: str | None = Field(default=None, description="Set on accept/reject rows only.")
    detail: dict[str, Any] = Field(
        default_factory=dict,
        description="Event-specific payload; the keys differ per event type. Left open rather "
                    "than modelled: a union across every event's shape would be more machinery "
                    "than the dict it replaced.")


class SessionAuditPage(ApiModel):
    """A page of a session's step trail, oldest first — same envelope shape as the entity-wide
    treatment audit feed, so both audit reads page identically."""
    model_config = ConfigDict(json_schema_extra={"example": {
        "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "limit": 100, "offset": 0,
        "events": [{
            "audit_id": "1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90",
            "at": "2026-08-30T09:00:00Z", "event": "session_started", "subject_type": "session",
            "scenario_id": None, "plan_id": None, "actor_user_id": "u1", "actor_type": "user",
            "stage": None, "subsystem_id": None, "decision": None, "detail": {},
        }],
    }})

    session_id: str = Field(description="The session this trail belongs to.")
    limit: int = Field(description="Page size that was applied.")
    offset: int = Field(description="Rows skipped.")
    events: list[SessionAuditEvent] = Field(
        default_factory=list, description="The steps, oldest first.")


class EmbeddingActionBody(ApiModel):
    """Shared request shape for all four admin embedding actions (app/api/admin.py).
    `group=None` means "every group"; `names`, when given, scopes to just those items and
    REQUIRES an explicit (non-null) `group` (a name alone doesn't say which table it's in)."""
    model_config = ConfigDict(
        json_schema_extra={"example": {"group": "threat_type", "names": ["Spoofing", "Denial of Service"]}}
    )

    group: Literal["threat_type", "threat_catalogue", "control_library", "threat_actor"] | None = Field(
        default=None,
        description="Which table to act on: threat_type, threat_catalogue, control_library or threat_actor. Omit for every group.",
    )
    names: list[str] | None = Field(
        default=None,
        max_length=_MAX_BATCH,
        description="Names to scope the action to. Requires group to be set. Omit for all names in the group.",
    )


class EmbeddingActionResponse(ApiModel):
    """[REVIEW-FIX] create/update/recreate report ROW-count semantics (active master rows
    processed); delete reports a DIFFERENT quantity (Mongo vectors actually deleted, which can
    include stale docs from a retired model) — distinct field names instead of one ambiguous
    shared key, so the same number never silently means two different things. Only the field
    the calling route actually populates is non-null. Also the base shape `EmbeddingJobStatus`
    below extends with `state`/`error` — the eventual RESULT of a queued action, not what a
    route returns directly (see app/api/admin.py: actions now run via a Celery task)."""
    # `int | str` is kept DELIBERATELY even though new writes can only produce ints: a failed
    # group used to ride along as "error: ..." inside an otherwise-SUCCESS payload, and
    # embeddings._for_each_group now raises EmbeddingGroupsFailed instead (state=FAILURE, detail
    # in `error`). But admin.py builds this model in the route body from a Celery result that may
    # PREDATE the deploy and still be inside the backend's TTL — narrowing to dict[str, int] turns
    # every such poll into a pydantic ValidationError, i.e. a 500 for a job that actually
    # succeeded. Tolerating the legacy shape on read costs one union member in the OpenAPI doc;
    # rejecting it costs real 500s for the length of the result TTL after every deploy.
    rows_processed: dict[str, int | str] | None = Field(
        default=None,
        description="Master rows processed, by group (create/update/recreate only). Present only "
                    "when state is SUCCESS; on FAILURE see `error`. A string value is a legacy "
                    "per-group error from a job queued before the FAILURE-reporting change."
    )
    vectors_deleted: dict[str, int | str] | None = Field(
        default=None,
        description="Mongo vectors deleted, by group (delete only). Present only when state is "
                    "SUCCESS; on FAILURE see `error`. A string value is a legacy per-group error "
                    "from a job queued before the FAILURE-reporting change."
    )


class IntelFeedStatus(ApiModel):
    """One live-intel feed's operational state (GET /v1/tsg/threat-intel/feeds).

    Reports three distinguishable conditions that used to look identical: `enabled=false`
    (switched off), `enabled=true` with no `last_success_at` (never ran), and a populated
    `last_error` (ran and failed). A `last_success_at` with `item_count` unchanged is also
    normal — some feeds are incremental and legitimately fetch nothing new."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "feed": "cisa_kev", "enabled": True, "item_count": 1653,
                "kinds": {"cve": 1653}, "prompted": True,
                "last_fetched_at": "2026-07-27T03:00:00Z",
                "last_attempt_at": "2026-07-27T03:00:00Z",
                "last_success_at": "2026-07-27T03:00:00Z", "last_error": None,
            }
        }
    )

    feed: str = Field(description="Feed name, e.g. 'cisa_kev' — the value used in the refresh URL.")
    enabled: bool = Field(description="Whether this feed is switched on by configuration right now.")
    item_count: int = Field(description="Cached items currently held for this feed.")
    kinds: dict[str, int] = Field(default_factory=dict, description="Cached item counts by kind (cve, ics_advisory, pulse, ioc_url).")
    prompted: bool = Field(description="Whether this feed's items can reach the LLM. IOC feeds are cached but never prompted.")
    last_fetched_at: datetime | None = Field(default=None, description="Newest fetched_at across this feed's cached items.")
    last_attempt_at: datetime | None = Field(default=None, description="When a refresh of this feed last ran, successful or not.")
    last_success_at: datetime | None = Field(default=None, description="When this feed last refreshed successfully.")
    last_error: str | None = Field(default=None, description="Error from the last attempt, or null if it succeeded.")


class IntelFeedsResponse(ApiModel):
    """Every known feed, enabled or not."""
    feeds: list[IntelFeedStatus]


class IntelRefreshAccepted(ApiModel):
    """Queued refresh jobs. The all-feeds route fans out, so `jobs` carries one entry per
    feed dispatched — a single feed's refresh returns exactly one."""
    model_config = ConfigDict(
        json_schema_extra={"example": {"jobs": {"cisa_kev": "6ba7b810-9dad-11d1-80b4-00c04fd430c8"}}}
    )

    jobs: dict[str, str] = Field(description="feed name -> Celery job id for the refresh queued for it.")


class IntelJobEvent(ApiModel):
    """One `data:` line on GET .../threat-intel/feeds/events/{job_id} (event type
    intel_job_update). Envelope fields are guaranteed on every event; `feed`/`item_count` are
    verified against celery_app.py's `_publish_intel_job_event` call sites."""
    model_config = ConfigDict(json_schema_extra={"example": {
        "type": "intel_job_update", "job_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        "state": "SUCCESS", "feed": "otx", "item_count": 42, "error": None}})

    type: Literal["intel_job_update"]
    job_id: str
    state: str = Field(description="Celery state name: PENDING/STARTED/SUCCESS/FAILURE/RETRY.")
    feed: str = Field(description="Which feed this event is about — always present.")
    item_count: int | None = Field(default=None, description="Present only on the SUCCESS event.")
    error: str | None = Field(default=None, description="Present only on FAILURE/RETRY.")


class IntelItem(ApiModel):
    """One cached intel item (GET /v1/tsg/threat-intel/items) — a KEV CVE, an ICS
    advisory, or an OTX pulse, in the store's normalized shape."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "source": "otx", "kind": "pulse", "external_id": "6a6c1a2b3c4d5e6f7a8b9c0d",
                "title": "[Armored Likho] Armored Likho's new weapon: BusySnake Stealer",
                "adversary": "Armored Likho",
                "description": "BusySnake is a new stealer attributed to ...",
                "url": "https://otx.alienvault.com/pulse/6a6c1a2b3c4d5e6f7a8b9c0d",
                "tags": ["armored likho", "stealer"],
                "fetched_at": "2026-08-03T07:44:27Z",
            }
        }
    )

    source: str = Field(description="Feed this item came from (cisa_kev, cisa_ics, otx, urlhaus, taxii).")
    kind: str = Field(description="Item kind (cve, ics_advisory, pulse, ioc_url, stix).")
    external_id: str = Field(description="The item's id in its source — CVE id, advisory code, or pulse id.")
    title: str = Field(description="Normalized title; OTX pulses carry their adversary as a [Group] prefix.")
    adversary: str | None = Field(default=None, description="Attributed threat actor, when the source names one (OTX pulses only). Null for feeds without attribution and for items cached before the field existed.")
    # Read-tolerant defaults: this model validates whatever is IN the collection, not what
    # our writers produce — one legacy/foreign doc missing a field must render as a sparse
    # row, never fail validation and 500 the whole page.
    description: str = Field(default="", description="Truncated source description.")
    url: str = Field(default="", description="Link back to the item at its source.")
    tags: list[str] = Field(default_factory=list, description="Source tags; for attributed OTX pulses the adversary is the first tag.")
    fetched_at: datetime | None = Field(default=None, description="UTC time this item was last written by a refresh (also its TTL clock). Null only on a malformed legacy doc.")
    published_at: datetime | None = Field(default=None, description="The item's own date at its source (an OTX pulse's last-modified time); falls back to sync time for feeds that publish none. This is the ordering key — newest threat first.")


class IntelItemsResponse(ApiModel):
    """One page of cached intel items, newest first."""
    items: list[IntelItem]
    total: int = Field(description="Total items matching the filter, across all pages.")
    limit: int = Field(description="Page size used for this response.")
    offset: int = Field(description="Offset used for this response.")


class EmbeddingJobAccepted(ApiModel):
    """Returned immediately (202) when an admin embedding action is queued — poll
    GET .../status/{job_id} for the eventual outcome."""
    model_config = ConfigDict(json_schema_extra={"example": {"job_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8"}})

    job_id: str = Field(description="Celery task id for the queued action. Poll GET status/{job_id} for the outcome.")


class EmbeddingJobStatus(EmbeddingActionResponse):
    """Polled result of a queued admin embedding action. `state` mirrors Celery's own
    AsyncResult.state (PENDING/STARTED/SUCCESS/FAILURE/RETRY/...); rows_processed/
    vectors_deleted (inherited) are populated only once `state == "SUCCESS"`, `error` only
    once `state == "FAILURE"` (e.g. a genuine per-group lock conflict — EmbeddingBusy — surfaces
    here now, not as an HTTP 409 on the original POST, since that request already returned
    before the task ran)."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "state": "SUCCESS",
                "rows_processed": {"threat_type": 12, "threat_catalogue": 8},
                "vectors_deleted": None,
                "error": None,
            }
        }
    )

    state: CeleryJobState = Field(
        description="Job's current state, mirrors Celery's AsyncResult.state — see CeleryJobState (app/core/enums.py)."
    )
    error: str | None = Field(default=None, description="Error message when state is FAILURE. Null otherwise.")


class EmbeddingJobEvent(ApiModel):
    """One `data:` line on GET .../embeddings/events/{job_id} (event type
    embedding_job_update). Envelope + confirmed per-state fields are typed; `extra="allow"`
    because a multi-group sweep's per-group progress ticks are not exhaustively enumerated here."""
    model_config = ConfigDict(extra="allow", json_schema_extra={"example": {
        "type": "embedding_job_update", "job_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        "state": "SUCCESS", "action": "recreate",
        "rows_processed": {"threat_type": 12, "threat_catalogue": 8},
        "vectors_deleted": None, "error": None}})

    type: Literal["embedding_job_update"]
    job_id: str
    state: str = Field(description="Celery state name: PENDING/STARTED/SUCCESS/FAILURE/RETRY.")
    action: str | None = Field(default=None, description="create|update|recreate|delete — present from STARTED onward.")
    group: str | None = Field(default=None, description="Present on a per-group progress tick during a multi-group sweep.")
    rows: int | None = Field(default=None, description="Rows processed for `group`, on that same progress tick.")
    rows_processed: dict[str, int] | None = Field(default=None, description="Present only on the terminal SUCCESS event.")
    vectors_deleted: int | str | None = Field(default=None, description="Present only on a SUCCESS delete action.")
    error: str | None = Field(default=None, description="Present only on FAILURE/RETRY.")


# ---------------------------------------------------------------------------
# Session-promotion admin (app/api/admin.py) — GET/retry/dismiss for sessions whose library
# promotion (accept.py's isolated Phase 2) failed and is pending automatic or manual retry.
# ---------------------------------------------------------------------------
class LibraryRowAudit(ApiModel):
    """Provenance every master row carries. `source` records WHERE the row came from
    ('functional_team_excel' seed, an import tag, 'ai_auto_promoted', 'manual' via this API);
    created_by/updated_by record WHO, as the caller's user id.

    `updated_at`/`updated_by` stay null until someone edits the row through this API — the
    importer and promote-on-accept paths deliberately leave existing rows untouched. A soft
    delete IS an edit, so on a deleted row `updated_by` is whoever deleted it."""
    is_active: bool = Field(description="Curator's enable/disable flag. Inactive rows are excluded from AI matching.")
    is_deleted: bool = Field(description="Soft-delete flag. Deleted rows are hidden from the list endpoints and from grounding.")
    source: str | None = Field(default=None, description="Provenance tag. Null on rows created before the column existed.")
    created_at: datetime | None = Field(default=None, description="UTC insert time. Null on rows predating the audit columns.")
    created_by: str | None = Field(default=None, description="User id that created the row, or an 'auto:<source>'/'cli:<user>' literal for background imports.")
    updated_at: datetime | None = Field(default=None, description="UTC time of the last edit through this API. Null if never edited.")
    updated_by: str | None = Field(default=None, description="User id of the last edit, including a soft delete. Null if never edited.")
    # Declared on the shared row model rather than in a separate write-response wrapper so a
    # client parses one shape whether it listed the row or just wrote it. Always null on GET.
    embeddings_job_id: str | None = Field(
        default=None,
        description=(
            "Set only on create/update/delete of a threat type or catalogue entry whose NAME "
            "changed — poll it on GET /v1/tsg/threat-library/embeddings/status/{job_id} to know "
            "when the AI can match the new text. Null when nothing needed re-embedding (a "
            "description-only edit, or an actor/category, which back no embedding group), and "
            "null with a logged warning if the queue was unreachable — the row is still saved, "
            "and the fix is to run POST /v1/tsg/threat-library/embeddings/update."
        ),
    )


class ThreatCategoryCreate(ApiModel):
    """New Threat_Category row. `threat_category_id` is REQUIRED and caller-supplied because
    this table's PK is a plain int, not IDENTITY (TSG_Core.sql section 2) — the STRIDE set is
    fixed and externally numbered. Deriving MAX+1 server-side would race two concurrent creates
    onto the same id, so the caller owns the choice."""
    model_config = ConfigDict(json_schema_extra={"example": {
        "threat_category_id": 7, "threat_category_name": "Elevation of Privilege",
        "threat_category_code": "EOP"}})

    threat_category_id: int = Field(ge=1, description="Primary key. Required — this table's PK is not auto-generated.")
    threat_category_name: str = Field(min_length=1, max_length=200, description="Display name, e.g. 'Elevation of Privilege'.")
    threat_category_code: str | None = Field(default=None, max_length=20, description="Short code, e.g. 'EOP'.")
    is_active: bool = Field(default=True, description="Set false to create the row already disabled.")


class ThreatCategoryUpdate(ApiModel):
    """Partial update — send only what changes. At least one field is required."""
    model_config = ConfigDict(json_schema_extra={"example": {"threat_category_code": "EOP"}})

    threat_category_name: str | None = Field(default=None, min_length=1, max_length=200)
    threat_category_code: str | None = Field(default=None, max_length=20)
    is_active: bool | None = Field(default=None, description="Disable without deleting. Re-enabling can 409 on a name clash.")


class ThreatCategoryRow(LibraryRowAudit):
    """One Threat_Category row as returned by the CRUD endpoints."""
    threat_category_id: int = Field(description="Primary key.")
    threat_category_name: str = Field(description="Display name.")
    threat_category_code: str | None = Field(default=None, description="Short code.")


class ThreatTypeCreate(ApiModel):
    """New Threat_Type row (a threat FAMILY). Unique on NAME alone among live rows — a name
    freed by a soft delete can be reused."""
    model_config = ConfigDict(json_schema_extra={"example": {
        "threat_type_name": "Credential Abuse", "threat_category_id": 4}})

    threat_type_name: str = Field(min_length=1, max_length=300, description="Family name. Also the text the AI matches against — keep it descriptive.")
    threat_category_id: int | None = Field(default=None, ge=1, description="Owning STRIDE category. Must reference a live Threat_Category row.")
    is_active: bool = Field(default=True, description="Set false to create the row already disabled.")


class ThreatTypeUpdate(ApiModel):
    """Partial update — send only what changes. At least one field is required.

    Renaming re-embeds this row for AI matching — see the endpoint's `embeddings_job_id`."""
    model_config = ConfigDict(json_schema_extra={"example": {"threat_type_name": "Credential Abuse & Session Theft"}})

    threat_type_name: str | None = Field(default=None, min_length=1, max_length=300)
    threat_category_id: int | None = Field(default=None, ge=1)
    is_active: bool | None = Field(default=None, description="Disable without deleting. Re-enabling can 409 on a natural-key clash.")


class ThreatTypeRow(LibraryRowAudit):
    """One Threat_Type row as returned by the CRUD endpoints."""
    threat_type_id: int = Field(description="Primary key.")
    threat_type_name: str = Field(description="Family name.")
    threat_category_id: int | None = Field(default=None)


class ThreatCatalogueCreate(ApiModel):
    """New Threat_Catalogue row (one EXACT threat under a family). Name-unique among live rows
    (UX_ThreatCatalogue_NaturalKey); the app also dedups by normalized name."""
    model_config = ConfigDict(json_schema_extra={"example": {
        "threat_type_id": 12, "threat_name": "Credential phishing and MFA session theft"}})

    threat_type_id: int = Field(ge=1, description="Owning family. Must reference a live Threat_Type row.")
    threat_name: str = Field(min_length=1, max_length=500, description="Exact threat name. This IS the text the AI matches against.")
    is_active: bool = Field(default=True, description="Set false to create the row already disabled.")


class ThreatCatalogueUpdate(ApiModel):
    """Partial update — send only what changes. At least one field is required.

    Renaming re-embeds this row for AI matching — see the endpoint's `embeddings_job_id`.
    Description was removed as unused, so the name is now the whole embedded passage."""
    model_config = ConfigDict(json_schema_extra={"example": {
        "threat_name": "Credential phishing and MFA session theft"}})

    threat_type_id: int | None = Field(default=None, ge=1)
    threat_name: str | None = Field(default=None, min_length=1, max_length=500)
    is_active: bool | None = Field(default=None, description="Disable without deleting. Re-enabling can 409 on a natural-key clash.")


class ThreatCatalogueRow(LibraryRowAudit):
    """One Threat_Catalogue row as returned by the CRUD endpoints."""
    threat_catalogue_id: int = Field(description="Primary key.")
    threat_type_id: int = Field(description="Owning family.")
    threat_name: str = Field(description="Exact threat name.")


class ThreatActorCreate(ApiModel):
    """New Threat_Actor row. Unique on name alone among live rows — actors are global, with no
    sector or category dimension."""
    model_config = ConfigDict(json_schema_extra={"example": {"threat_actor_name": "Hacktivist", "is_capable": 1}})

    threat_actor_name: str = Field(min_length=1, max_length=200, description="Actor name, e.g. 'Nation State'.")
    is_capable: int = Field(default=1, description="Capability weight fed to the threats-prompt hint.")
    is_active: bool = Field(default=True, description="Set false to create the row already disabled.")


class ThreatActorUpdate(ApiModel):
    """Partial update — send only what changes. At least one field is required."""
    model_config = ConfigDict(json_schema_extra={"example": {"is_capable": 0}})

    threat_actor_name: str | None = Field(default=None, min_length=1, max_length=200)
    is_capable: int | None = Field(default=None)
    is_active: bool | None = Field(default=None, description="Disable without deleting. Re-enabling can 409 on a name clash.")


class ThreatActorRow(LibraryRowAudit):
    """One Threat_Actor row as returned by the CRUD endpoints."""
    threat_actor_id: int = Field(description="Primary key.")
    threat_actor_name: str = Field(description="Actor name.")
    is_capable: int = Field(description="Capability weight.")


# --- Control library (/v1/tsg/control-library) -------------------------------------------
# Same three-model-per-table shape as the threat masters above. The one behavioural difference
# worth knowing: a control's embedded text is `control_name + ": " + control_description`, so
# editing EITHER re-embeds the row — unlike the threat tables, where only the name counts.
class ControlStandardCreate(ApiModel):
    """New Control_Standard row (a named standard, e.g. 'NIST SP 800-53 Rev. 5'). Unique on name
    among live rows."""
    model_config = ConfigDict(json_schema_extra={"example": {"standard_name": "NIST SP 800-53 Rev. 5"}})

    standard_name: str = Field(min_length=1, max_length=200, description="Standard's full name as it should be reported.")
    is_active: bool = Field(default=True, description="Set false to create the row already disabled.")


class ControlStandardUpdate(ApiModel):
    """Partial update — send only what changes. At least one field is required."""
    model_config = ConfigDict(json_schema_extra={"example": {"standard_name": "ISO 27001:2022", "is_active": True}})

    standard_name: str | None = Field(default=None, min_length=1, max_length=200)
    is_active: bool | None = Field(default=None, description="Disable without deleting. Re-enabling can 409 on a name clash.")


class ControlStandardRow(LibraryRowAudit):
    """One Control_Standard row as returned by the CRUD endpoints."""
    standard_id: int = Field(description="Primary key.")
    standard_name: str = Field(description="Standard's full name.")


class ControlCreate(ApiModel):
    """New Control_Library row. Unique on `control_code` among live rows — the code, not the
    name, is the natural key, because two controls can legitimately share a name across domains."""
    model_config = ConfigDict(json_schema_extra={"example": {
        "control_code": "CII-CID-1289", "itot": "IT", "domain": "Identification & Authentication",
        "control_name": "Phishing-Resistant MFA",
        "control_description": "Mechanisms exist to require phishing-resistant multi-factor authentication for privileged accounts.",
        "sample_evidence": "Screenshot of the MFA policy showing FIDO2 enforcement."}})

    control_code: str = Field(min_length=1, max_length=20, description="Stable code, e.g. 'CII-CID-1289'. The natural key.")
    itot: str = Field(min_length=1, max_length=10, description="'IT' or 'OT' — drives grounding's asset-type pre-filter.")
    domain: str = Field(min_length=1, max_length=200, description="Control domain, reported as-is (free vocabulary, never joined on).")
    control_name: str = Field(min_length=1, max_length=CONTROL_NAME_MAX_CHARS,
                            description="Official control name. Part of the text the AI matches against.")
    # CAPPED, and the cap is load-bearing. A control is embedded as name + ": " + description, and
    # llm.embed REJECTS anything over max_embed_chars rather than truncating — in a BATCH call, so
    # ONE over-long control fails the entire library embedding and stops control mapping for every
    # asset and every session until someone finds that row. embeddings._active_names contains any
    # row that still exceeds the limit (the seed SQL bypasses this schema entirely).
    control_description: str = Field(min_length=1, max_length=CONTROL_DESCRIPTION_MAX_CHARS,
                                    description="Full control text. ALSO part of the matched text — "
                                                "editing it re-embeds the row.")
    sample_evidence: str | None = Field(default=None, description="Example evidence an assessor would accept. Not embedded.")
    is_active: bool = Field(default=True, description="Set false to create the row already disabled.")


class ControlUpdate(ApiModel):
    """Partial update — send only what changes. At least one field is required.

    Changing `control_name` OR `control_description` re-embeds the control (see the endpoint's
    `embeddings_job_id`); the other fields do not."""
    model_config = ConfigDict(json_schema_extra={"example": {
        "control_code": "CII-CID-1289", "itot": "IT", "domain": "Identification & Authentication",
        "control_name": "Phishing-Resistant MFA", "control_description": "Updated control text.",
        "sample_evidence": "Screenshot of the MFA policy.", "is_active": True}})

    control_code: str | None = Field(default=None, min_length=1, max_length=20)
    itot: str | None = Field(default=None, min_length=1, max_length=10)
    domain: str | None = Field(default=None, min_length=1, max_length=200)
    control_name: str | None = Field(default=None, min_length=1, max_length=CONTROL_NAME_MAX_CHARS)
    control_description: str | None = Field(default=None, min_length=1,
                                            max_length=CONTROL_DESCRIPTION_MAX_CHARS)
    sample_evidence: str | None = Field(default=None)
    is_active: bool | None = Field(default=None, description="Disable without deleting. Re-enabling can 409 on a code clash.")


class ControlRow(LibraryRowAudit):
    """One Control_Library row as returned by the CRUD endpoints."""
    control_library_id: int = Field(description="Primary key.")
    control_code: str = Field(description="Stable control code.")
    itot: str = Field(description="'IT' or 'OT'.")
    domain: str = Field(description="Control domain.")
    control_name: str = Field(description="Official control name.")
    control_description: str = Field(description="Full control text.")
    sample_evidence: str | None = Field(default=None, description="Example evidence.")


class ControlStandardsResponse(ApiModel):
    """The standards currently linked to one control — what fills `standards[]` on a scenario's
    mapped controls. Returned by the attach/detach endpoints so the caller sees the result of
    the change without a second call."""
    model_config = ConfigDict(json_schema_extra={"example": {
        "control_library_id": 201, "standard_ids": [1, 4],
        "standards": ["ISO 27001:2022", "NIST SP 800-53 Rev. 5"]}})

    control_library_id: int = Field(description="The control these standards belong to.")
    standard_ids: list[int] = Field(description="Linked Control_Standard primary keys.")
    standards: list[str] = Field(description="Their names, alphabetically — the same list a scenario's control shows.")


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
    session_id: str = Field(description="Owning session.")
    scenario_id: str = Field(description="The accepted scenario this plan treats.")
    status: str = Field(description="RUNNING | COMPLETE | ERROR — the poll signal (stale RUNNING projects as ERROR).")
    treatment_strategy: str = Field(description="The strategy this plan was generated for — server-stamped 'Mitigate'.")
    scenario: ScenarioNarrative | None = Field(
        default=None,
        description="The accepted scenario this plan treats — IDENTICAL shape to "
                    "ScenarioResult.scenario, built by the same builder, so the plan screen and "
                    "the results screen cannot show different detail for one scenario. Null "
                    "only if the scenario row is unreadable (defensive parse), or on a "
                    "superseded-version row, which carries no scenario join: the scenario is "
                    "version-independent and served once on the top-level object.")
    threat: ThreatResult | None = Field(
        default=None,
        description="The threat this scenario was generated from, with every database key — "
                    "identical shape and rules to ScenarioResult.threat. Null when no "
                    "Identified_Threat row joined, or on a superseded-version row.")
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
                    "own plan_id, status, review verdict and plan content. Populated only on "
                    "GET .../treatment-plan?include_superseded=true: null when not requested, "
                    "[] when requested and the plan was never regenerated. History items carry "
                    "scenario=null (the scenario is version-independent — read it once from the "
                    "top level) and never nest their own history (one level deep).")
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
                    "newest first, the same entries the single-plan GET serves under "
                    "?include_superseded=true (full plan content, own status/review verdict; "
                    "scenario=null — read the title from this row). Populated only with "
                    "?include_superseded=true: null when not requested, [] when requested "
                    "and never regenerated.")
    created_at: datetime | None = Field(default=None)
    completed_at: datetime | None = Field(default=None)


class TreatmentPlanProgress(ApiModel):
    """The session's remediation-planning progress — the plan board's answer to
    SessionProgress, so a UI can render one status line without folding the rows itself.

    Every count is over the session's ACCEPTED scenarios, and they sum to accepted_scenarios:
    each scenario lands in exactly one bucket. Derived from the same rows the board already
    returns, so this costs no extra query.
    """
    model_config = ConfigDict(json_schema_extra={"example": {
        "not_requested": 3, "running": 1, "complete": 3, "error": 1,
        "awaiting_review": 2, "approved": 1, "rejected": 0, "overall": "in_progress"}})

    not_requested: int = Field(
        description="Accepted scenarios with no plan yet — what the UI's Generate button "
                    "counts.")
    running: int = Field(description="Plans currently generating.")
    complete: int = Field(
        description="Plans that finished generating, REVIEWED OR NOT — the generation total. "
                    "It therefore OVERLAPS awaiting_review/approved/rejected, which split this "
                    "same set by review verdict; only the four buckets not_requested + running "
                    "+ complete + error sum to accepted_scenarios.")
    error: int = Field(description="Plans that failed (a stale RUNNING projects as ERROR).")
    awaiting_review: int = Field(
        description="COMPLETE plans with no approve/reject decision yet — THE review-queue "
                    "count, and the reason `overall` is not simply 'complete' once generation "
                    "finishes.")
    approved: int = Field(description="COMPLETE plans a reviewer approved.")
    rejected: int = Field(description="COMPLETE plans a reviewer rejected.")
    overall: TreatmentProgress = Field(
        description="One rolled-up status for the whole session's planning — the plan-board "
                    "counterpart of SessionProgress.overall. See TreatmentProgress for the "
                    "priority order; an ERROR outranks work still running, and a session whose "
                    "plans are all generated but unreviewed reports `awaiting_review`, never "
                    "`complete`.")


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
    model_config = ConfigDict(json_schema_extra={"example": {
        "decision": "approved", "comment": "A3 timeline extended per operations."}})
    decision: TreatmentReviewStatus = Field(description="approved | rejected.")
    comment: str | None = Field(default=None, max_length=2000, description="Optional reviewer comment.")
    plan_id: str | None = Field(
        default=None,
        description=(
            "Which plan version the decision targets. Omit (or pass the active version's id) to "
            "review the current plan — today's behavior. Pass a HISTORICAL version's plan_id "
            "(from GET .../treatment-plan?include_superseded=true) with decision='approved' to "
            "make that version the current plan AND approve it, atomically — approving an older "
            "version IS choosing it. Only COMPLETE versions can be adopted (409 not_complete "
            "otherwise); rejecting a historical version is refused (409 version_not_active); a "
            "running regeneration blocks the switch (409 generation_in_progress). Last human "
            "decision wins: a later approval of another version displaces the operative plan; "
            "the displaced version keeps its own verdict in history and every switch is audited. "
            "Note: the entity register lists plans by original creation date, so a switched-to "
            "older version keeps its original position, not the top."
        ))

    _canonicalize_plan_id = field_validator("plan_id")(_canonical_guid_or_none)


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


# ---------------------------------------------------------------------------
# Grounding-threshold calibration (app/api/admin.py::grounding_router)
# ---------------------------------------------------------------------------

class GroundingCalibrationBody(ApiModel):
    """POST body for /v1/tsg/grounding/calibrate."""
    model_config = ConfigDict(json_schema_extra={"example": {"force": False}})

    force: bool = Field(
        default=False,
        description="Re-measure and OVERWRITE an existing stored calibration for this "
                    "embedding+reranker pair. Without it a pair that already has one is a no-op "
                    "(the job returns skipped=already_calibrated), because a sweep costs minutes "
                    "of wall-clock and real LLM spend. Set it after curating the threat library.",
    )


class GroundingCalibrationAccepted(ApiModel):
    """Returned immediately (202) when a calibration sweep is started — poll
    GET .../calibrate/status/{job_id} for the eventual outcome."""
    model_config = ConfigDict(json_schema_extra={"example": {
        "job_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        "run_id": "0f8fad5b-d9cb-469f-a165-70867728950e"}})

    job_id: str = Field(description="Celery task id for the queued sweep. Poll GET "
                                    "calibrate/status/{job_id} for the outcome.")
    run_id: str = Field(description="Ledger row id (Grounding_Calibration_Run.RunID). Unlike "
                                    "job_id, which expires with the Celery result after an hour, "
                                    "this identifies the run permanently — it is what "
                                    "GET /calibrations reports.")


class GroundingJobEvent(ApiModel):
    """One `data:` line on GET .../calibrate/events/{job_id} (event type grounding_job_update).
    Envelope + confirmed fields are typed; `extra="allow"` because the terminal SUCCESS event
    spreads a measurement namedtuple's fields verbatim (not exhaustively enumerated here) plus
    embedding_model/reranker_model/run_id."""
    model_config = ConfigDict(extra="allow", json_schema_extra={"example": {
        "type": "grounding_job_update", "job_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        "state": "STARTED", "run_id": "0f8fad5b-d9cb-469f-a165-70867728950e",
        "phase": "negatives", "done": 40, "total": 100, "force": False, "error": None}})

    type: Literal["grounding_job_update"]
    job_id: str
    state: str = Field(description="Celery state name: PENDING/STARTED/RETRY/SUCCESS/FAILURE.")
    run_id: str | None = Field(default=None, description="Grounding_Calibration_Run.RunID once known.")
    force: bool | None = Field(default=None, description="Present on the very first STARTED event.")
    phase: str | None = Field(default=None, description="'negatives' or 'positives' — present on progress ticks.")
    done: int | None = Field(default=None, description="Samples measured so far, on a progress tick.")
    total: int | None = Field(default=None, description="Samples planned for this phase, on a progress tick.")
    error: str | None = Field(default=None, description="Present only on FAILURE.")


class GroundingCalibrationStatus(ApiModel):
    """Polled result of a queued calibration sweep. `state` mirrors Celery's AsyncResult.state;
    every measurement field is populated only once `state == "SUCCESS"`, `error` only on FAILURE.

    NOTE `state == "SUCCESS"` with `match_th == null` is a real, meaningful outcome, not a bug:
    the sweep ran and found that NO cutoff separates genuine matches from impostors better than
    chance under this model pair. That is a finding about the models/library, so it is reported
    as a successful measurement rather than a task failure — see `quality`."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "state": "SUCCESS",
                "match_th": 86.25,
                "quality": 0.94,
                "negatives": 100,
                "positives": 200,
                "highest_negative": 99.5,
                "lowest_positive": 71.2,
                "near_duplicates": ["'Mobile, QR or collaboration-channel compromise' ~ "
                                    "'Removable media or portable device compromise' @ 99.5"],
                "embedding_model": "multilingual-e5-large",
                "reranker_model": "bge-reranker-v2-m3",
                "skipped": None,
                "error": None,
            }
        }
    )

    state: CeleryJobState = Field(
        description="Job's current state, mirrors Celery's AsyncResult.state — see CeleryJobState."
    )
    match_th: float | None = Field(
        default=None,
        description="The measured cutoff. null means no cutoff beat chance (see the class note).")
    quality: float | None = Field(
        default=None,
        description="Youden's J at `match_th`: 1.0 separates the two classes perfectly, 0.0 is "
                    "chance. THE FIELD THAT SAYS WHETHER TO TRUST `match_th` — a cutoff scraped "
                    "out of heavy overlap and one measured on cleanly separated scores are the "
                    "same float otherwise. null when the sweep was skipped.")
    negatives: int | None = Field(
        default=None, description="Impostor scores measured (library entries vs the library "
                                "with themselves removed).")
    positives: int | None = Field(
        default=None, description="Genuine-match scores measured (LLM paraphrases vs the full library).")
    highest_negative: float | None = Field(
        default=None, description="Best score any impostor achieved — the ceiling the cutoff fights.")
    lowest_positive: float | None = Field(
        default=None, description="Worst score any genuine paraphrase achieved.")
    near_duplicates: list[str] = Field(
        default_factory=list,
        description="Catalogue pairs naming the same threat (scored >= TSG_NEAR_DUPLICATE_SCORE "
                    "against each other). Each is scored as an impostor against its own twin, so "
                    "it drags the measured cutoff down. CURATION WORK, not an error — calibration "
                    "no longer aborts on these; dedupe them and re-run with force=true for a "
                    "tighter threshold.")
    run_id: str | None = Field(
        default=None,
        description="Ledger row id. This route answers from the permanent row once the Celery "
                    "result has expired, so a late poll still gets the real outcome.")
    embedding_model: str | None = Field(default=None, description="Embedding model this calibration is for.")
    reranker_model: str | None = Field(default=None, description="Reranker model this calibration is for.")
    skipped: str | None = Field(
        default=None,
        description="Set when the sweep did not run: 'already_calibrated' means this pair had a "
                    "successful run and force was not set.")
    error: str | None = Field(default=None, description="Populated only when state is FAILURE.")


class GroundingCalibrationRun(ApiModel):
    """One row of calibration history — who ran it, when, and how it ended."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "run_id": "0f8fad5b-d9cb-469f-a165-70867728950e",
                "job_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
                "status": "success",
                "started_by": "gopal",
                "started_by_client": "tsg-web",
                "started_at": "2026-08-27T10:14:02Z",
                "finished_at": "2026-08-27T10:29:41Z",
                "embedding_model": "multilingual-e5-large",
                "reranker_model": "bge-reranker-v2-m3",
                "forced": False,
                "match_th": 86.25,
                "quality": 0.99,
                "negatives": 100,
                "positives": 200,
                "highest_negative": 99.5,
                "lowest_positive": 71.2,
                "near_duplicates": [],
                "error": None,
            }
        }
    )

    run_id: str = Field(description="Grounding_Calibration_Run.RunID — permanent.")
    job_id: str | None = Field(default=None, description="Celery task id, for cross-referencing "
                                                        "logs. Expires; run_id does not.")
    status: str = Field(
        description="running | success | no_signal | failed. `no_signal` is NOT a crash — the "
                    "sweep ran and found no cutoff that beats chance under this model pair, which "
                    "means curate the library or change models. `failed` means it raised. A "
                    "`running` row past the stale window is reported here as `failed`, since it "
                    "cannot still be running.")
    started_by: str | None = Field(
        default=None,
        description="The X-User-Id that asked. CLAIMED, not proven: admin routes are gated by a "
                    "shared X-Admin-Key and this header is trusted, never verified. See "
                    "`started_by_client` for the half that is authenticated.")
    started_by_client: str | None = Field(
        default=None,
        description="The API_Client the request authenticated as (X-API-Key). Verified.")
    started_at: datetime | None = Field(default=None)
    finished_at: datetime | None = Field(default=None)
    embedding_model: str | None = Field(default=None)
    reranker_model: str | None = Field(default=None)
    forced: bool = Field(default=False, description="Re-measured over an existing successful run.")
    match_th: float | None = Field(default=None, description="The measured cutoff. This value IS "
                                                            "the threshold the pipeline reads.")
    quality: float | None = Field(
        default=None,
        description="Youden's J at match_th: 1.0 separates the classes perfectly, 0.0 is chance. "
                    "The field that says whether to trust match_th.")
    negatives: int | None = Field(default=None)
    positives: int | None = Field(default=None)
    highest_negative: float | None = Field(default=None)
    lowest_positive: float | None = Field(default=None)
    near_duplicates: list[str] = Field(
        default_factory=list,
        description="Catalogue pairs naming the same threat. Curation work, not an error — each "
                    "is scored as an impostor against its own twin and drags the cutoff down.")
    error: str | None = Field(default=None, description="Why it failed, when it did.")


class GroundingCalibrationHistory(ApiModel):
    """Calibration runs, newest first.

    Exists because Celery's result backend expires after an hour, so the per-job status route
    cannot answer "did last Tuesday's calibration pass, and who ran it?" — and a failed sweep used
    to write nothing anywhere. These rows are permanent."""
    model_config = ConfigDict(json_schema_extra={"example": {"runs": []}})

    runs: list[GroundingCalibrationRun]


class GroundingThresholdResponse(ApiModel):
    """The cutoff this deployment is CURRENTLY grounding with, and where it came from."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {"value": 86.25, "origin": "calibrated",
                        "embedding_model": "multilingual-e5-large",
                        "reranker_model": "bge-reranker-v2-m3"}
        }
    )

    value: float = Field(description="The match cutoff in force right now.")
    origin: str = Field(
        description="Where it came from — the field that makes `value` interpretable: "
                    "'calibrated' (measured for this exact model pair — always wins when one "
                    "is stored), 'env_pinned' (TSG_GROUNDING_MATCH_THRESHOLD is bootstrapping "
                    "because no calibration is stored for this pair yet), or "
                    "'static_default' (the built-in default, tuned for a DIFFERENT model pair — "
                    "provisional, and a calibration is worth running).")
    embedding_model: str = Field(description="Embedding model the threshold applies to.")
    reranker_model: str = Field(description="Reranker model the threshold applies to.")
