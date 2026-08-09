"""Request/response Pydantic models for the session API (`app/api/sessions.py`).

Split out from the routes themselves so the shape of every endpoint's body/response
can be found in one place without wading through route logic.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic.json_schema import JsonDict

# Typing the wire with these is what puts them in /openapi.json — the UI generates its own
# string-literal unions from the spec instead of hand-copying codes out of the API guide.
from app.core.enums import (ClickOutcomeReason, NextSetOutcome, ReviewGateReason, RiskLevel,
                            SSEEventType, TreatmentGateReason, TreatmentReviewStatus, YesNo)
from app.db.dal import canonical_guid

# Plan item 1b: bound every list-of-targets field so one HTTP request can't turn into an
# unbounded synchronous AI/DB workload inside a single Celery task (no chunking exists).
_MAX_BATCH = 50


def _canonical_output_ids(v: list[str] | None) -> list[str] | None:
    """Normalize client-supplied OutputIDs to the one canonical spelling AT THE TRUST BOUNDARY,
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


class CreateSessionBody(BaseModel):
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
    # principal (JWT `sub`, or X-Dev-User in dev), the same source cancel/accept already audit
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


class AcceptBody(BaseModel):
    """Body for the "accept scenarios" endpoint. `mode` is REQUIRED (no default) so a
    caller can never silently accept-all by omitting a field — accept-all/none/subset
    are three separate, mutually-exclusive choices instead of shades of
    null-vs-omitted-vs-empty-list. [R8]"""
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"mode": "all"},
                {"mode": "none"},
                {"mode": "subset", "output_ids": ["3fa85f64-5717-4562-b3fc-2c963f66afa6"]},
            ]
        }
    )

    mode: Literal["all", "none", "subset"] = Field(
        description=(
            "Required. 'all' = accept every generated scenario; 'none' = accept nothing "
            "(the session still completes, terminally — [R8]); 'subset' = accept only the "
            "scenarios named in output_ids."
        )
    )
    output_ids: list[str] | None = Field(
        default=None,
        description=f"Output ids to accept. Required (non-empty, max {_MAX_BATCH}) when mode='subset'; must be omitted otherwise.",
    )

    _canonicalize_output_ids = field_validator("output_ids")(_canonical_output_ids)

    @model_validator(mode="after")
    def _mode_and_output_ids_agree(self) -> AcceptBody:
        # Length bounds live HERE, not as Field constraints: Pydantic runs field-level
        # min_length/max_length BEFORE any mode="after" validator, so a field failure would
        # skip this validator entirely — {"mode": "all", "output_ids": []} would then be told
        # to ADD items ("at least 1 item") when the actual fix is to REMOVE the field. One
        # validation site keeps every mode/output_ids disagreement on one context-aware message.
        if self.mode == "subset":
            if not self.output_ids:
                raise ValueError("output_ids is required (non-empty) when mode='subset'")
            if len(self.output_ids) > _MAX_BATCH:
                raise ValueError(f"output_ids must have at most {_MAX_BATCH} items")
        elif self.output_ids is not None:
            raise ValueError(f"output_ids must not be provided when mode={self.mode!r}")
        return self


class RegenerateScenariosBody(BaseModel):
    """Body for asking the pipeline to regenerate scenarios for the session's asset. No asset/
    subsystem id is needed here — `session_id` (already in the URL) is the sole identifier, since
    a session is always exactly one asset (`UX_Session_ActiveAsset`); the target scenarios are
    identified by `output_ids` alone."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "output_ids": ["3fa85f64-5717-4562-b3fc-2c963f66afa6"],
                "user_note": "Please emphasize the insider-threat vector.",
            }
        }
    )

    output_ids: list[str] = Field(
        min_length=1, max_length=_MAX_BATCH, description="Output ids of the scenarios to regenerate. 1-50 ids."
    )
    user_note: str | None = Field(
        default=None, description="Optional free-text note from the reviewer guiding the regeneration (e.g. what to change)."
    )

    _canonicalize_output_ids = field_validator("output_ids")(_canonical_output_ids)


class NextSetSummary(BaseModel):
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


class SessionProgress(BaseModel):
    """The session's asset-level progress: per-stage statuses plus a derived overall status. One
    flat object, not a list — the pipeline tracks the asset as a single unit of work (see
    sessions.py::build_board), so there is never more than one of these per session."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "threats": "COMPLETE", "scenarios": "AWAITING_DECISION",
                "overall": "awaiting_review", "error_message": None,
                "last_next_set": {
                    "outcome": "partial_retryable", "requested": 5, "delivered": 3,
                    "variants": 0, "reason": None, "epoch": 4,
                },
            }
        }
    )

    threats: str = Field(description="THREATS stage status: IDLE, RUNNING, AWAITING_DECISION, COMPLETE, ERROR, or CANCELLED.")
    scenarios: str = Field(description="SCENARIOS stage status: IDLE, RUNNING, AWAITING_DECISION, COMPLETE, ERROR, or CANCELLED.")
    overall: str = Field(description="Computed overall status: pending, in_progress, awaiting_review, complete, error, or cancelled.")
    error_message: str | None = Field(
        default=None,
        description=(
            "Client-safe failure reason for the most recent stage error, if any. Non-null "
            "on an awaiting_review board means the run failed mid-batch after generating "
            "some scenarios — the review set may be PARTIAL, not a complete run."
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


class SessionBoard(BaseModel):
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
                "stage_status": "AWAITING_DECISION",
                "progress": {
                    "threats": "COMPLETE", "scenarios": "AWAITING_DECISION",
                    "overall": "awaiting_review", "error_message": None,
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


class CreateSessionResponse(BaseModel):
    """Response returned after a new session is created."""
    model_config = ConfigDict(
        json_schema_extra={"example": {"session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "user_id": "qa-user"}}
    )

    session_id: str = Field(description="Id of the newly created session. Use it to poll status, fetch results, or stream events.")
    user_id: str | None = Field(
        description="The session's owning user (the authenticated caller who created it). "
                    "Null only if the principal had no identity to record."
    )


class ThreatResult(BaseModel):
    """One threat identified for the session's asset, as returned to the client."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "threat_id": "b3fc2c96-3f66-4562-8fa6-5717afa63f66",
                "threat_type": "Spoofing",
                "threat_name": "Unauthorized RTU firmware update",
                "grounding_status": "verified",
                "threat_catalogue_id": 42,
            }
        }
    )

    threat_id: str = Field(description="Identified threat's unique id (GUID). Matches the threat_id on the scenario(s) generated from it.")
    threat_type: str = Field(description="STRIDE threat category, e.g. Spoofing, Tampering, Denial of Service.")
    threat_name: str | None = Field(description="Human-readable threat name.")
    grounding_status: str = Field(
        description=(
            "Whether this threat matched an approved threat-library entry: `verified` (it did) "
            "or `unverified` (no confident match — a novel candidate, still scenario-generated "
            "and eligible for library promotion on accept)."
        )
    )
    threat_catalogue_id: int | None = Field(
        description="Id of the matched threat-catalogue master row, set only when the name match "
                    "itself cleared the cutoff. Null whenever it did not — a close-but-unconfirmed "
                    "candidate is deliberately not reported as a match."
    )
    threat_actors: list[str] = Field(
        default=[],
        description="Adversary types proposed for this threat (raw Stage-1 list, drawn from the "
                    "closed Threat_Actor vocabulary shown to the model). Empty when none were "
                    "proposed."
    )
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


#: One `scenario.controls` entry, for the OpenAPI examples below.
_MAPPED_CONTROL_EXAMPLE: JsonDict = {
    "control_library_id": 201,
    "control_code": "CII-CID-201",
    "domain": "Identification & Authentication",
    "control_name": "Multi-Factor Authentication",
    "rank": 1,
    "score": 93.0,
    "suggested_control": "Multi-factor authentication for privileged accounts",
    "suggested_why": "Mitigates the risk of credential theft being used to reach the asset.",
    "standards": ["NIST SP 800-53 Rev. 5", "ISO 27001:2022"],
}

#: The scenario narrative exactly as the pipeline produces it (prompts.py::scenario_prompt): these
#: are the LLM's own keys, passed through verbatim by sessions.py::_safe_scenario_json, with
#: `controls` swapped for the grounded library matches. ONE constant shared by every example that
#: shows a scenario — the four hand-copied literals this replaces had all drifted to a
#: `title`/`narrative` shape the API has never actually returned.
_SCENARIO_EXAMPLE: JsonDict = {
    "scenario_title": "Remote Terminal Unit (RTU) — Unauthorized firmware push",
    "scenario_statement": (
        "An attacker with OT network access pushes unsigned firmware to the RTU, "
        "compromising the integrity of its control logic."
    ),
    "risk_statement": (
        "The RTU provides the Substation Control critical service; corrupted firmware "
        "could cause a sustained outage."
    ),
    "controls": [_MAPPED_CONTROL_EXAMPLE],
    # Two suggestions, only the first of which grounded — the second has no counterpart in
    # `controls` above, which is exactly the library-gap signal this field exists to show.
    "suggested_controls": [
        {"name": "Multi-factor authentication for privileged accounts",
         "why": "Mitigates the risk of credential theft being used to reach the asset."},
        {"name": "Vendor firmware attestation at the RTU boot loader",
         "why": "Blocks unsigned images from ever loading on the device."},
    ],
    # unmatched_suggestions precomputes exactly this diff: the one suggestion above with no
    # counterpart in `controls`.
    "unmatched_suggestions": [
        {"name": "Vendor firmware attestation at the RTU boot loader",
         "why": "Blocks unsigned images from ever loading on the device."},
    ],
}


class MappedControl(BaseModel):
    """One Control_Library row mapped to a scenario by Step-4 control mapping
    (control_mapping.map_controls): the LLM suggested a mitigating control in free text and grounding
    matched it to this real library control. Ordered by rank (1 = best).

    Delivered nested, as `scenario.controls` — it REPLACES the LLM's raw `{name, why}` suggestions
    there (sessions.py::_scenario_with_controls), so a scenario carries one control list, not two.
    Each entry keeps the suggestion it grounded from in `suggested_control`/`suggested_why`.
    An empty `scenario.controls` means nothing in the library matched well enough — a library-gap
    signal, not an error, but only once `controls_mapped` is true (see ScenarioResult)."""
    model_config = ConfigDict(json_schema_extra={"example": _MAPPED_CONTROL_EXAMPLE})

    control_library_id: int = Field(description="Control_Library primary key.")
    control_code: str = Field(description="Stable control code, e.g. 'CII-CID-201'.")
    domain: str = Field(description="The control's domain as recorded in the library (reported as-is).")
    control_name: str = Field(description="The library control's official name.")
    rank: int = Field(description="1 = best match for this scenario.")
    score: float | None = Field(description="Raw rerank confidence 0-100 at mapping time.")
    suggested_control: str | None = Field(
        description="The LLM's original free-text suggestion this control grounded from; null when the mapping fell back to the scenario text.")
    # The map row stores only the suggestion's NAME (control_mapping.collect_control_queries keeps
    # `name[:500]`), so the LLM's rationale is recovered at read time from the scenario's own raw
    # suggestions — which is why it also works for sessions mapped before this field existed.
    # Defaults to None so _query_controls can keep building MappedControl straight from DB rows.
    suggested_why: str | None = Field(
        default=None,
        description="The LLM's one-line rationale for the suggestion this control grounded from; null when the mapping fell back to the scenario text.")
    standards: list[str] = Field(default_factory=list, description="Referred standard names for this control.")


class SuggestedControl(BaseModel):
    """One raw control suggestion exactly as the LLM wrote it (prompt v1.3), before grounding.

    Reported ALONGSIDE the grounded `controls` rather than replaced by them, for two reasons. A
    suggestion that matched no library control appears only here — that difference IS the
    library-gap signal, and it was previously invisible. And between a scenario being written and
    Step-4 running (a tail step of the same stage, so minutes later), this is the only control
    content that exists at all; blanking it made a normal in-progress read look like the model
    had proposed nothing."""
    name: str = Field(description="The control the LLM named, in its own words.")
    why: str | None = Field(default=None, description="The LLM's one-line rationale for it.")


class ScenarioNarrative(BaseModel):
    """The LLM's scenario JSON passed through verbatim, with `controls` replaced by the Step-4
    grounded library matches (sessions.py::_scenario_with_controls).

    `extra="allow"` is the point: scenario_title/scenario_statement/risk_statement — and anything
    else a future prompt adds — ride through unvalidated and unmodified, exactly as the bare dict
    this replaced did. Deliberately so: these are model-authored strings, and validating text the
    code doesn't control just converts an odd LLM response into a 500. ONLY `controls` is declared,
    which is what keeps MappedControl in the OpenAPI components so its fields are generated rather
    than hand-copied into a prose description (a hand-copied one is exactly how the smoke guides
    ended up documenting `title`/`narrative`, keys the API has never returned)."""
    model_config = ConfigDict(extra="allow", json_schema_extra={"example": _SCENARIO_EXAMPLE})

    controls: list[MappedControl] = Field(
        default_factory=list,
        description=(
            "Step-4 mitigating controls mapped from the control library, best first. Empty means "
            "nothing matched well enough — but only once `controls_mapped` is true; see there."
        ),
    )
    suggested_controls: list[SuggestedControl] = Field(
        default_factory=list,
        description=(
            "The LLM's own control suggestions, present from the moment the scenario is written "
            "and independent of mapping state. Compare against `controls`: a suggestion here with "
            "no entry there naming it in `suggested_control` found no good library counterpart — "
            "a gap in the control library. Empty for pre-v1.3 scenarios, which produced none."
        ),
    )
    unmatched_suggestions: list[SuggestedControl] | None = Field(
        default=None,
        description=(
            "The subset of suggested_controls with no counterpart in controls — the library-gap "
            "signal precomputed for you, instead of diffing the two lists yourself. Null (not an "
            "empty list) when control mapping hasn't been attempted yet — see controls_mapped on "
            "the enclosing result; suggested_controls itself is still populated either way."
        ),
    )


#: Shared by ScenarioResult and by the SessionResults example that embeds one.
_SCENARIO_RESULT_EXAMPLE: JsonDict = {
    "output_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    "threat_id": "b3fc2c96-3f66-4562-8fa6-5717afa63f66",
    "scenario": _SCENARIO_EXAMPLE,
    "accepted": False,
    "moderation_checked": False,
    "moderation_flagged": None,
    "moderation_categories": [],
    "validation_status": "ok",
    "validation_errors": [],
    "generation_epoch": 1,
    "scenario_number": 1,
    "controls_mapped": True,
    "replaced_scenarios": [],
}


class ScenarioResult(BaseModel):
    """One generated scenario for the session's asset, plus whether it has been accepted."""
    model_config = ConfigDict(json_schema_extra={"example": _SCENARIO_RESULT_EXAMPLE})

    output_id: str = Field(description="Generated scenario's unique id (GUID). Used to accept/regenerate this scenario.")
    threat_id: str | None = Field(
        description="Id of the threat this scenario was generated from. Matches a threat_id in the "
                    "session's threats list. Null only if the underlying threat/scoping link is "
                    "missing (this schema has no enforced foreign keys) — the scenario itself is "
                    "still shown, never dropped, so it remains visible for review and accept."
    )
    scenario: ScenarioNarrative | None = Field(
        description=(
            "Generated scenario narrative — scenario_title, scenario_statement, risk_statement, "
            "plus the Step-4 `controls` mapped from the control library. Null if generation failed."
        )
    )
    accepted: bool = Field(description="Whether a human reviewer has accepted this scenario.")
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
            "Group cards by threat_id and label them with this number; do NOT render a "
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
    # Mirrors Threat_Scenario_Output.ControlsMappedAt, so false ALSO covers the unseeded-library
    # case: control_mapping bails at `controls.no_candidates` without stamping, deliberately, so
    # those outputs are picked up by a later run once Seed_to_Control_library.sql has been applied.
    controls_mapped: bool = Field(
        description=(
            "Whether Step-4 control mapping has been attempted for this scenario. true with an "
            "empty `scenario.controls` = mapping ran and nothing in the library matched, a genuine "
            "library-gap signal. false = not attempted, for one of two reasons: SCENARIO_GENERATION "
            "is still running (mapping is its tail step, so controls appear once the session's "
            "status reaches REVIEW), or the control library was empty/unreachable when the stage "
            "ran — check the worker log for `controls.no_candidates` and confirm the control "
            "library is seeded."
        ),
    )
    # Declared LAST on purpose: Pydantic serializes in declaration order, and a nested array of
    # whole scenarios ahead of the scalars would bury generation_epoch/scenario_number/
    # controls_mapped under it. Self-referential — the only recursive model in this schema —
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
            "times this scenario has been regenerated: 2 entries means it is version 3."
        ),
    )


class SessionResults(BaseModel):
    """All threats and scenarios produced so far for a session."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "entity_id": "ENT-001",
                "asset_id": 12345,
                "asset_name": "SCADA Historian",
                "user_id": "qa-user",
                "threats": [
                    {
                        "threat_id": "b3fc2c96-3f66-4562-8fa6-5717afa63f66",
                        "threat_type": "Spoofing",
                        "threat_name": "Unauthorized RTU firmware update",
                        "grounding_status": "verified",
                        "threat_catalogue_id": 42,
                    }
                ],
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
    threats: list[ThreatResult] = Field(description="All threats identified so far for this session.")
    scenarios: list[ScenarioResult] = Field(
        description="All scenarios generated so far for this session. Versions that regeneration "
                    "replaced are nested inside the scenario that replaced them, in its "
                    "`replaced_scenarios`, and only when ?include_replaced=true."
    )


class AcceptResponse(BaseModel):
    """Response confirming an accept request was processed."""
    model_config = ConfigDict(
        json_schema_extra={"example": {"session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "user_id": "qa-user", "status": "completed", "accepted_count": 3}}
    )

    session_id: str = Field(description="Session's unique id (GUID).")
    user_id: str | None = Field(description="The session's owning user (who created it). Null only if the principal had no identity to record.")
    status: str = Field(description="Result of the accept request. Always 'completed' on success.")
    accepted_count: int = Field(description="Number of scenarios actually marked accepted by this request (0 for mode='none').")


class RegenerateResponse(BaseModel):
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
            "until `progress.last_next_set.epoch` equals this value — that, not the stage "
            "status, is the exact signal that your click landed. It stays correct when another "
            "tab clicks concurrently (each waits for its own epoch) and it turns a stalled "
            "worker into a diagnosable 'my epoch never arrived' rather than an endless wait."
        ),
    )


class CancelResponse(BaseModel):
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
class ErrorDetails(BaseModel):
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
            "target-went-stale race."
        ),
    )
    detail: str | None = Field(default=None, description="Developer-facing explanation. Never show this to an end user.")
    message: str | None = Field(default=None, description="End-user-safe sentence for this reason, when one is defined.")


class ErrorResponse(BaseModel):
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


# --- SSE event payloads -------------------------------------------------------------------------
# Same rationale: cascade.py publishes these dicts, and the /events route streams them, so nothing
# would otherwise describe them in the spec. Publishing through these models keeps the wire and the
# documented schema from drifting.
class NextSetResultEvent(BaseModel):
    """`next_set_result` — one "generate next set" click finished.

    ADVISORY. Best-effort, behind a circuit breaker, never replayed (app/sse/bus.py), so treat it
    as a prompt to refresh rather than as the record. `SessionProgress.last_next_set` on the status
    board carries the same facts durably and is what a reconnecting client should trust."""
    type: SSEEventType = Field(description="Always 'next_set_result'.")
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


class RegenResultEvent(BaseModel):
    """`regen_result` — one regenerate click finished.

    Deliberately carries NO outcome/requested fields: regenerate REPLACES rather than adds, so its
    scenario count never changes and a batch-size notion would be meaningless here."""
    type: SSEEventType = Field(description="Always 'regen_result'.")
    session_id: str = Field(description="Session the click belonged to.")
    subsystem_id: int = Field(description="Unit of work; always 0 (the asset itself).")
    requested_output_ids: list[str] = Field(description="OutputIDs the client asked to regenerate.")
    new_output_ids: list[str] = Field(description="Replacement OutputIDs. Empty means the click was fruitless.")
    replacements: list[dict[str, str]] = Field(
        default_factory=list,
        description="old→new pairs. The two flat lists above cannot express the mapping when "
                    "several targets are regenerated at once; these can.",
    )
    reason: ClickOutcomeReason | None = Field(default=None, description="Why the click was fruitless; null for the target-went-stale race.")
    detail: str | None = Field(default=None, description="Developer-facing explanation.")
    message: str | None = Field(default=None, description="End-user-safe sentence.")
    ts: datetime = Field(description="When the event was published (UTC, ISO-8601).")


#: Shared by AcceptedScenario and by the AcceptedScenariosResponse example that embeds one.
_ACCEPTED_SCENARIO_EXAMPLE: JsonDict = {
    "output_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    "supporting_system_id": 101,
    "threat_type_id": 3,
    "threat_catalogue_id": 42,
    "threat_type": "Spoofing",
    "threat_name": "Unauthorized RTU firmware update",
    "scenario": _SCENARIO_EXAMPLE,
}


class AcceptedScenario(BaseModel):
    """One accepted scenario row — joinable on ids."""
    model_config = ConfigDict(json_schema_extra={"example": _ACCEPTED_SCENARIO_EXAMPLE})

    output_id: str = Field(description="Accepted scenario's unique id (GUID).")
    supporting_system_id: int = Field(description="Supporting system this scenario applies to.")
    threat_type_id: int | None = Field(
        description="Id of the matched threat-type master row. Null when the type came back unverified."
    )
    threat_catalogue_id: int | None = Field(
        description="Id of the matched threat-catalogue master row. Null when no catalogue candidate matched."
    )
    threat_type: str | None = Field(description="STRIDE threat category the scenario was generated from.")
    threat_name: str | None = Field(description="Human-readable name of the threat the scenario was generated from.")
    scenario: ScenarioNarrative | None = Field(
        description=(
            "Accepted scenario narrative — scenario_title, scenario_statement, risk_statement, plus "
            "the Step-4 `controls` mapped from the control library. Identical shape to "
            "ScenarioResult.scenario."
        )
    )
    threat_actors: list[str] = Field(
        default=[],
        description="Adversary types of the threat this scenario was generated from (raw Stage-1 "
                    "list). Empty when none were proposed."
    )


class AcceptedScenariosResponse(BaseModel):
    """The accepted, non-superseded scenarios for one session, identified solely by the
    session_id in the URL path. asset_id and entity_id are read off that session (not
    separate inputs) and returned here so a caller with only a session_id can still learn
    which asset/entity it belongs to."""
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
    scenarios: list[AcceptedScenario] = Field(description="Accepted, non-superseded scenarios for this session.")


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
    GET /v1/sessions/{session_id}/scenarios/{output_id}) all return this shape."""
    model_config = ConfigDict(json_schema_extra={"example": _SCENARIO_LIST_ITEM_EXAMPLE})

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
                    "include_superseded=true, or on a direct fetch by output_id."
    )
    created_at: datetime | None = Field(description="UTC timestamp the scenario row was created.")


class EmbeddingActionBody(BaseModel):
    """Shared request shape for all four admin embedding actions (app/api/admin.py).
    `group=None` means "every group"; `names`, when given, scopes to just those items and
    REQUIRES an explicit (non-null) `group` (a name alone doesn't say which table it's in)."""
    model_config = ConfigDict(
        json_schema_extra={"example": {"group": "threat_type", "names": ["Spoofing", "Denial of Service"]}}
    )

    group: Literal["threat_type", "threat_catalogue", "control_library"] | None = Field(
        default=None,
        description="Which table to act on: threat_type, threat_catalogue or control_library. Omit for every group.",
    )
    names: list[str] | None = Field(
        default=None,
        max_length=_MAX_BATCH,
        description="Names to scope the action to. Requires group to be set. Omit for all names in the group.",
    )


class EmbeddingActionResponse(BaseModel):
    """[REVIEW-FIX] create/update/recreate report ROW-count semantics (active master rows
    processed); delete reports a DIFFERENT quantity (Mongo vectors actually deleted, which can
    include stale docs from a retired model) — distinct field names instead of one ambiguous
    shared key, so the same number never silently means two different things. Only the field
    the calling route actually populates is non-null. Also the base shape `EmbeddingJobStatus`
    below extends with `state`/`error` — the eventual RESULT of a queued action, not what a
    route returns directly (see app/api/admin.py: actions now run via a Celery task)."""
    rows_processed: dict[str, int | str] | None = Field(
        default=None, description="Master rows processed, by group (create/update/recreate only)."
    )
    vectors_deleted: dict[str, int | str] | None = Field(
        default=None, description="Mongo vectors deleted, by group (delete only)."
    )


class ThreatLibraryImportBody(BaseModel):
    """Request for POST /v1/tsg/threat-library/sources/{source}/import — trigger one
    threat-library import (the same job scripts/import_threat_libraries.py runs). Plain
    JSON body, deliberately not multipart: the uploaded "file" is itself JSON text, so
    `file_content` carries it with no extra upload machinery.

    EVERY field below is optional, and `{}` is a valid body — it means "really import the
    source named in the path, downloading it from upstream". Two fields apply to SOME
    SOURCES ONLY: `via_taxii` to attack/attack_ics, `max_actors` to misp_actors. Those
    rules are enforced BEFORE dispatch, so a wrong combination returns 422 and never
    reaches the queue."""
    model_config = ConfigDict(
        json_schema_extra={"example": {"dry_run": True}}
    )

    # `source` is NOT a body field: it is the addressed resource in the path
    # (POST /v1/tsg/threat-library/sources/{source}/import), so an unknown library is a
    # 404 on that resource rather than a 422 on a body value.
    dry_run: bool = Field(default=False, description=(
        "Preview only — parse and report what WOULD be imported; nothing is written."))
    via_taxii: bool = Field(default=False, description=(
        "Fetch ATT&CK live via TAXII instead of GitHub (attack/attack_ics only; "
        "incompatible with file_content)."))
    max_actors: int = Field(default=40, ge=1, description=(
        "misp_actors only: cap on imported actors (they feed the threats-prompt hint)."))
    file_content: str | None = Field(default=None, description=(
        "ANY SOURCE. The library file's JSON text, supplied directly instead of downloading. "
        "Size-capped by settings.threat_library_import_max_upload_mb (422 if over). Must be "
        "valid JSON of the shape this source's adapter expects (422 otherwise). Mutually "
        "exclusive with via_taxii."))


class SourceInventoryItem(BaseModel):
    """One threat-library source's current state — the per-source row of
    GET /v1/tsg/threat-library/sources. `loaded=false` with a null `last_run` means the
    source was never imported; `loaded=false` with a failed `last_run` means it was tried
    and did not succeed. Those are different problems, so they read differently."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "source": "attack_ics", "source_tag": "mitre_attack_ics", "loaded": True,
                "type_count": 12, "threat_count": 95, "actor_count": None,
                "last_run": {"status": "success", "dry_run": False,
                             "started_at": "2026-07-27T09:14:00Z",
                             "finished_at": "2026-07-27T09:16:12Z", "error": None,
                             "types_imported": 12, "threats_imported": 95, "actors_upserted": None,
                             "started_by": "qa-tester"},
            }
        }
    )

    source: str = Field(description="API source name, e.g. 'attack_ics' — the value used in the import URL.")
    source_tag: str | None = Field(description="Provenance tag stamped on this source's imported rows (Threat_Type.Source).")
    loaded: bool = Field(description="True when this source has contributed rows to the library.")
    type_count: int = Field(description="Threat_Type (family) rows attributed to this source.")
    threat_count: int = Field(description="Threat_Catalogue (exact threat) rows attributed to this source.")
    actor_count: int | None = Field(
        default=None,
        description=(
            "Threat_Actor rows stamped with this source — misp_actors only; null for every other "
            "source. Counts only actors whose Source matches: rows created before Threat_Actor "
            "gained that column (seeded actors, anything promoted on accept) have Source=NULL and "
            "are excluded. Until 2026-07-27 this was an unfiltered count of the whole table, so it "
            "over-reported."
        ),
    )
    last_run: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Most recent import attempt for this source, or null if never attempted. Keys: status, "
            "dry_run, started_at, finished_at, error, types_imported, threats_imported, "
            "actors_upserted, started_by (the user who triggered it — null for CLI-driven runs and "
            "for any run recorded before the API forwarded its caller to the worker)."
        ),
    )


class SourcesInventoryResponse(BaseModel):
    """Every known source, imported or not — so 'pending' is visible rather than absent."""
    sources: list[SourceInventoryItem]


class IntelFeedStatus(BaseModel):
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


class IntelFeedsResponse(BaseModel):
    """Every known feed, enabled or not."""
    feeds: list[IntelFeedStatus]


class IntelRefreshAccepted(BaseModel):
    """Queued refresh jobs. The all-feeds route fans out, so `jobs` carries one entry per
    feed dispatched — a single feed's refresh returns exactly one."""
    model_config = ConfigDict(
        json_schema_extra={"example": {"jobs": {"cisa_kev": "6ba7b810-9dad-11d1-80b4-00c04fd430c8"}}}
    )

    jobs: dict[str, str] = Field(description="feed name -> Celery job id for the refresh queued for it.")


class IntelItem(BaseModel):
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


class IntelItemsResponse(BaseModel):
    """One page of cached intel items, newest first."""
    items: list[IntelItem]
    total: int = Field(description="Total items matching the filter, across all pages.")
    limit: int = Field(description="Page size used for this response.")
    offset: int = Field(description="Offset used for this response.")


class ThreatLibraryImportAccepted(BaseModel):
    """Returned immediately (202) when an import is queued — poll
    GET /v1/tsg/threat-library/imports/{job_id} for the eventual outcome."""
    model_config = ConfigDict(json_schema_extra={"example": {"job_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8"}})

    job_id: str = Field(description=(
        "Celery task id for the queued import. Poll GET /v1/tsg/threat-library/imports/{job_id} — "
        "NOT the embeddings status route, which is a different job family and 404s on this id."))


class ImportJobStatus(BaseModel):
    """Polled result of a queued threat-library import. `state` mirrors Celery's own
    AsyncResult.state; `result` (populated once state == "SUCCESS") is run_import's
    documented stats dict — including `ot_rules` (the auto-written boost-only scoring
    rules, the one permanent side effect an admin must be able to see) and
    `embeddings_job_id` (the follow-up refresh job, pollable on the embeddings status
    route). `error` is populated only once state == "FAILURE". Deliberately NOT
    EmbeddingJobStatus — an import result shares none of its fields."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "state": "SUCCESS",
                "result": {"source": "attack_ics", "dry_run": False, "types": 11, "threats": 83,
                        "new_category_links": 96, "before_count": 0, "after_count": 83,
                        "ot_rules": [{"threat_type_id": 87, "threat_type_name": "ICS ATT&CK - Impact",
                                        "rule_key": "asset_type", "threat_rule_id": 22}],
                        "skipped_count": 4, "skipped": [], "embeddings_job_id": "6ba7b810-..."},
                "error": None,
            }
        }
    )

    state: str = Field(description="Celery AsyncResult state: PENDING/STARTED/SUCCESS/FAILURE/RETRY/...")
    result: dict | None = Field(default=None, description="run_import's stats dict, once SUCCESS.")
    error: str | None = Field(default=None, description="Bounded error message, once FAILURE.")


class EmbeddingJobAccepted(BaseModel):
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

    state: str = Field(
        description="Job's current state, mirrors Celery's AsyncResult.state: PENDING, STARTED, SUCCESS, FAILURE, or RETRY."
    )
    error: str | None = Field(default=None, description="Error message when state is FAILURE. Null otherwise.")


# ---------------------------------------------------------------------------
# Threat-library master CRUD (app/api/library_crud.py)
#
# Three models per table — Create, Update (every field optional), Row (the response). They do
# not collapse into one generic pair: the four tables genuinely differ (a category has a
# SecurityObjective, an actor has IsCapable, a catalogue row has a parent type), and one loose
# model would accept fields the target table has no column for.
#
# Update models: every field defaults to None and the handler sends only what was actually set,
# so an omitted field keeps its current value instead of being nulled. An empty body is rejected
# — far more likely a mistake than a request to stamp UpdatedBy and change nothing.
# ---------------------------------------------------------------------------
class LibraryRowAudit(BaseModel):
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


class ThreatCategoryCreate(BaseModel):
    """New Threat_Category row. `threat_category_id` is REQUIRED and caller-supplied because
    this table's PK is a plain int, not IDENTITY (TSG_Core.sql section 2) — the STRIDE set is
    fixed and externally numbered. Deriving MAX+1 server-side would race two concurrent creates
    onto the same id, so the caller owns the choice."""
    model_config = ConfigDict(json_schema_extra={"example": {
        "threat_category_id": 7, "threat_category_name": "Elevation of Privilege",
        "threat_category_code": "EOP", "security_objective": "Authorization"}})

    threat_category_id: int = Field(ge=1, description="Primary key. Required — this table's PK is not auto-generated.")
    threat_category_name: str = Field(min_length=1, max_length=200, description="Display name, e.g. 'Elevation of Privilege'.")
    threat_category_code: str | None = Field(default=None, max_length=20, description="Short code, e.g. 'EOP'.")
    security_objective: str | None = Field(default=None, max_length=200, description="CIA objective this category maps to.")
    is_active: bool = Field(default=True, description="Set false to create the row already disabled.")


class ThreatCategoryUpdate(BaseModel):
    """Partial update — send only what changes. At least one field is required."""
    model_config = ConfigDict(json_schema_extra={"example": {"security_objective": "Authorization"}})

    threat_category_name: str | None = Field(default=None, min_length=1, max_length=200)
    threat_category_code: str | None = Field(default=None, max_length=20)
    security_objective: str | None = Field(default=None, max_length=200)
    is_active: bool | None = Field(default=None, description="Disable without deleting. Re-enabling can 409 on a name clash.")


class ThreatCategoryRow(LibraryRowAudit):
    """One Threat_Category row as returned by the CRUD endpoints."""
    threat_category_id: int = Field(description="Primary key.")
    threat_category_name: str = Field(description="Display name.")
    threat_category_code: str | None = Field(default=None, description="Short code.")
    security_objective: str | None = Field(default=None, description="CIA objective.")


class ThreatTypeCreate(BaseModel):
    """New Threat_Type row (a threat FAMILY). Unique on (name, category, sector) among live
    rows, so the same name under a different category or sector is allowed — and a name freed
    by a soft delete can be reused."""
    model_config = ConfigDict(json_schema_extra={"example": {
        "threat_type_name": "Credential Abuse", "description": "Attacks that misuse valid credentials.",
        "threat_category_id": 4}})

    threat_type_name: str = Field(min_length=1, max_length=300, description="Family name. Also the text the AI matches against — keep it descriptive.")
    description: str | None = Field(default=None, description="Free text. Not embedded; only the name is matched.")
    sector_id: int | None = Field(default=None, ge=1, description="Scope to one sector, or null for every sector.")
    threat_category_id: int | None = Field(default=None, ge=1, description="Owning STRIDE category. Must reference a live Threat_Category row.")
    is_active: bool = Field(default=True, description="Set false to create the row already disabled.")
    actor_names: list[str] = Field(
        default=[],
        description="Adversary types for this family, linked on create. Existing names "
                    "(case-insensitive) are reused; genuinely new ones are created — admin "
                    "supply is the deliberate way the actor vocabulary grows."
    )


class ThreatTypeUpdate(BaseModel):
    """Partial update — send only what changes. At least one field is required.

    Renaming re-embeds this row for AI matching — see the endpoint's `embeddings_job_id`."""
    model_config = ConfigDict(json_schema_extra={"example": {"threat_type_name": "Credential Abuse & Session Theft"}})

    threat_type_name: str | None = Field(default=None, min_length=1, max_length=300)
    description: str | None = Field(default=None)
    sector_id: int | None = Field(default=None, ge=1)
    threat_category_id: int | None = Field(default=None, ge=1)
    is_active: bool | None = Field(default=None, description="Disable without deleting. Re-enabling can 409 on a natural-key clash.")
    actor_names: list[str] | None = Field(
        default=None,
        description="Adversary types to link to this family — ADDITIVE and idempotent "
                    "(existing links are never removed). Also the repair path when a create's "
                    "actor linking failed after the family was committed."
    )


class ThreatTypeRow(LibraryRowAudit):
    """One Threat_Type row as returned by the CRUD endpoints."""
    threat_type_id: int = Field(description="Primary key.")
    threat_type_name: str = Field(description="Family name.")
    description: str | None = Field(default=None)
    sector_id: int | None = Field(default=None)
    threat_category_id: int | None = Field(default=None)


class ThreatCatalogueCreate(BaseModel):
    """New Threat_Catalogue row (one EXACT threat under a family). Unique on
    (threat_type_id, name, sector) among live rows."""
    model_config = ConfigDict(json_schema_extra={"example": {
        "threat_type_id": 12, "threat_name": "Credential phishing and MFA session theft",
        "description": "Adversary-in-the-middle phishing that replays the session cookie."}})

    threat_type_id: int = Field(ge=1, description="Owning family. Must reference a live Threat_Type row.")
    threat_name: str = Field(min_length=1, max_length=500, description="Exact threat name. Also the text the AI matches against.")
    description: str | None = Field(default=None, description="Free text. Not embedded; only the name is matched.")
    sector_id: int | None = Field(default=None, ge=1, description="Scope to one sector, or null for every sector.")
    is_active: bool = Field(default=True, description="Set false to create the row already disabled.")


class ThreatCatalogueUpdate(BaseModel):
    """Partial update — send only what changes. At least one field is required.

    Renaming re-embeds this row for AI matching — see the endpoint's `embeddings_job_id`."""
    model_config = ConfigDict(json_schema_extra={"example": {"description": "Updated wording."}})

    threat_type_id: int | None = Field(default=None, ge=1)
    threat_name: str | None = Field(default=None, min_length=1, max_length=500)
    description: str | None = Field(default=None)
    sector_id: int | None = Field(default=None, ge=1)
    is_active: bool | None = Field(default=None, description="Disable without deleting. Re-enabling can 409 on a natural-key clash.")


class ThreatCatalogueRow(LibraryRowAudit):
    """One Threat_Catalogue row as returned by the CRUD endpoints."""
    threat_catalogue_id: int = Field(description="Primary key.")
    threat_type_id: int = Field(description="Owning family.")
    threat_name: str = Field(description="Exact threat name.")
    description: str | None = Field(default=None)
    sector_id: int | None = Field(default=None)


class ThreatActorCreate(BaseModel):
    """New Threat_Actor row. Unique on name alone among live rows — actors are global, with no
    sector or category dimension."""
    model_config = ConfigDict(json_schema_extra={"example": {"threat_actor_name": "Hacktivist", "is_capable": 1}})

    threat_actor_name: str = Field(min_length=1, max_length=200, description="Actor name, e.g. 'Nation State'.")
    is_capable: int = Field(default=1, description="Capability weight fed to the threats-prompt hint.")
    is_active: bool = Field(default=True, description="Set false to create the row already disabled.")


class ThreatActorUpdate(BaseModel):
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


class ThreatRuleCreate(BaseModel):
    """New Config_Threat_Rule row — a scoping rule (tech_gate hard include/exclude, or a
    relevance_* score weight) keyed to one threat family. Unique on the live
    (threat_type_id, rule_type, rule_key, rule_value) quadruple.

    `weight` is stored server-side as Metadata {"weight": N} — callers never write raw Metadata
    JSON, because a malformed blob makes scoping skip the rule silently (_rule_weight's contract).
    tech_gate rules take NO weight (they are a hard door; scoping records delta 0.0)."""
    model_config = ConfigDict(json_schema_extra={"example": {
        "rule_type": "relevance_flag", "threat_type_id": 12, "rule_key": "asset_type",
        "rule_value": "Operational Technology (OT)", "weight": 10.0}})

    rule_type: str = Field(description="One of: tech_gate, relevance_flag, relevance_context_value.")
    threat_type_id: int = Field(ge=1, description="The Threat_Type this rule scopes — must name a live family.")
    rule_key: str = Field(min_length=1, max_length=200,
                        description="Context field the rule reads. Must be in scoping's allowlist "
                                    "(currently: criticality, subsystem_name, asset_type, past_incidents) "
                                    "— an unknown key would create a rule that silently never fires.")
    rule_value: str | None = Field(default=None, max_length=450,
                                description="Expected value. Omit for the key's default/truthy check; "
                                            "an explicit empty string means 'match a blank field'.")
    weight: float | None = Field(default=None,
                                description="relevance_* score delta. Omit to use the configured "
                                            "default_rule_weight. Forbidden on tech_gate.")
    is_active: bool = Field(default=True, description="Set false to create the rule already disabled.")


class ThreatRuleUpdate(BaseModel):
    """Partial update — send only what changes. `rule_type`/`rule_key`/`threat_type_id` are
    deliberately immutable (retire the rule and create a new one; keeps the audit trail honest).
    Sending `weight: null` explicitly CLEARS the override back to the configured default."""
    model_config = ConfigDict(json_schema_extra={"example": {"weight": 15.0}})

    rule_value: str | None = Field(default=None, max_length=450)
    weight: float | None = Field(default=None)
    is_active: bool | None = Field(default=None, description="Disable without deleting. Re-enabling can 409 on a natural-key clash.")


class ThreatRuleRow(BaseModel):
    """One Config_Threat_Rule row as returned by the CRUD endpoints."""
    threat_rule_id: int = Field(description="Primary key.")
    rule_type: str = Field(description="tech_gate | relevance_flag | relevance_context_value.")
    threat_type_id: int = Field(description="The Threat_Type this rule scopes.")
    rule_key: str = Field(description="Context field the rule reads.")
    rule_value: str | None = Field(description="Expected value; null = default/truthy check.")
    weight: float | None = Field(description="Metadata weight override; null = configured default (or n/a for tech_gate).")
    is_active: bool
    is_deleted: bool
    created_at: datetime | None = None
    created_by: str | None = None
    updated_at: datetime | None = None
    updated_by: str | None = None


# --- Control library (/v1/tsg/control-library) -------------------------------------------
# Same three-model-per-table shape as the threat masters above. The one behavioural difference
# worth knowing: a control's embedded text is `control_name + ": " + control_description`, so
# editing EITHER re-embeds the row — unlike the threat tables, where only the name counts.
class ControlStandardCreate(BaseModel):
    """New Control_Standard row (a named standard, e.g. 'NIST SP 800-53 Rev. 5'). Unique on name
    among live rows."""
    model_config = ConfigDict(json_schema_extra={"example": {"standard_name": "NIST SP 800-53 Rev. 5"}})

    standard_name: str = Field(min_length=1, max_length=200, description="Standard's full name as it should be reported.")
    is_active: bool = Field(default=True, description="Set false to create the row already disabled.")


class ControlStandardUpdate(BaseModel):
    """Partial update — send only what changes. At least one field is required."""
    model_config = ConfigDict(json_schema_extra={"example": {"standard_name": "ISO 27001:2022", "is_active": True}})

    standard_name: str | None = Field(default=None, min_length=1, max_length=200)
    is_active: bool | None = Field(default=None, description="Disable without deleting. Re-enabling can 409 on a name clash.")


class ControlStandardRow(LibraryRowAudit):
    """One Control_Standard row as returned by the CRUD endpoints."""
    standard_id: int = Field(description="Primary key.")
    standard_name: str = Field(description="Standard's full name.")


class ControlCreate(BaseModel):
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
    control_name: str = Field(min_length=1, max_length=500, description="Official control name. Part of the text the AI matches against.")
    control_description: str = Field(min_length=1, description="Full control text. ALSO part of the matched text — editing it re-embeds the row.")
    sample_evidence: str | None = Field(default=None, description="Example evidence an assessor would accept. Not embedded.")
    is_active: bool = Field(default=True, description="Set false to create the row already disabled.")


class ControlUpdate(BaseModel):
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
    control_name: str | None = Field(default=None, min_length=1, max_length=500)
    control_description: str | None = Field(default=None, min_length=1)
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


class ControlStandardsResponse(BaseModel):
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
class TreatmentPlanBody(BaseModel):
    """POST .../scenarios/{output_id}/treatment-plan — the register's risk data, sent by the
    UI (TSG reads NO risk-module tables; the body is the single source). TSG extracts the
    asset/threat/scenario/mapped-controls half itself via the path's session_id + output_id.

    The endpoint IS the Mitigate generator — there is no strategy field; TreatmentStrategy is
    stamped server-side (TreatmentStrategy.mitigate). Register facts the AI must never invent
    (risk_identification_date, risk_owner, impacted_business_division) are optional: absent →
    the output shows null, the model is never asked to fill the gap. `user_id` is deliberately
    NOT a field — the acting user comes from the authenticated principal (see
    CreateSessionBody's rationale)."""
    model_config = ConfigDict(json_schema_extra={"example": {
        "existing_controls": ["annual patching", "network firewall"],
        "likelihood_rating": 4, "impact_rating": 5,
        "final_risk_rating": 20, "risk_level": "Critical",
        "risk_identification_date": "2026-06-14T08:31:00Z",
        "risk_owner": "Head of OT Operations",
        "impacted_business_division": "Water Treatment Operations",
        "existing_controls_all_subsystems": "No",
        "existing_controls_all_subsystems_justification": "Controls deployed on IT systems only."}})

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
    user_note: str | None = Field(
        default=None, max_length=1000,
        description=("Steering for a regenerate — e.g. 'vendor owns the network; prefer "
                     "host-level controls'. Redacted, then shown to the AI as reviewer_note "
                     "(prompt RULE 6). Omit on a first generation unless you want to steer it."))

    @field_validator("existing_controls")
    @classmethod
    def _cap_control_text(cls, v: list[str]) -> list[str]:
        for item in v:
            if len(item) > 500:
                raise ValueError("each existing_controls entry must be 500 characters or fewer")
        return v

    @field_validator("risk_identification_date")
    @classmethod
    def _utc_naive(cls, v: datetime | None) -> datetime | None:
        # pyodbc silently drops tzinfo binding into datetime2 (UTC-by-convention everywhere in
        # this schema) — normalize here so a "+05:30" timestamp can't store the wrong wall time.
        if v is None or v.tzinfo is None:
            return v
        return v.astimezone(timezone.utc).replace(tzinfo=None)


class TreatmentPlanAccepted(BaseModel):
    """202 body for the POST — the GET on the same path is the poll endpoint."""
    model_config = ConfigDict(json_schema_extra={"example": {
        "plan_id": "0f0e0d0c-0b0a-8988-8786-858483828180",
        "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e",
        "output_id": "1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90",
        "status": "RUNNING"}})

    plan_id: str = Field(description="The new Risk_Treatment_Plan row's id.")
    session_id: str = Field(description="Echo of the session in the path.")
    output_id: str = Field(description="Echo of the scenario in the path.")
    status: str = Field(description="Always RUNNING at accept time — poll the GET until COMPLETE or ERROR.")


class TreatmentPlanStatus(BaseModel):
    """GET .../treatment-plan — the active plan row. `status` is the poll signal; `plan` is the
    parsed PlanJSON contract (null until COMPLETE, or when the stored blob is corrupt). A
    RUNNING row whose progress clock stopped for longer than treatment_stale_seconds is
    presented as ERROR with a timed-out message — a read-time projection, the stored row is
    not rewritten.

    PRESENTATION TRIM (user request, 06 Aug 2026): the fields marked exclude=True below are
    HIDDEN from the response for now, not deleted — they are still populated and stored;
    remove the exclude flag to unhide. The `plan` document is trimmed the same way by
    api.treatment._VISIBLE_PLAN_KEYS (the full document stays in PlanJSON)."""
    model_config = ConfigDict(json_schema_extra={"example": {
        "plan_id": "0f0e0d0c-0b0a-8988-8786-858483828180",
        "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e",
        "output_id": "1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90",
        "status": "COMPLETE", "treatment_strategy": "Mitigate",
        "scenario": {"scenario_title": "Ransomware via exposed RDP",
                     "scenario_statement": "A ransomware operator gains access through…",
                     "risk_statement": "Loss of treatment-plant availability…"},
        "risk_level": "Critical", "review_status": None,
        # No 'Z' suffix on purpose: values round-trip as NAIVE datetimes (UTC by convention —
        # the body validator normalizes, datetime2 stores naive), so the wire has no offset.
        "risk_identification_date": "2026-06-14T08:31:00",
        "error_message": None,
        "plan": {"title": "Remote Access Hardening", "treatment_plan": "Mitigate",
                 "action_plan": "Harden remote access in three phases…",
                 "applicable_to_all_subsystems": "No",
                 "controls_to_be_implemented": [],
                 "mitigation_timeline": "90 days overall; critical actions within 30 days",
                 "mitigation_owner": "OT Security Team",
                 "risk_owner": "Head of OT Operations",
                 "impacted_business_division": "Water Treatment Operations"}}})

    plan_id: str = Field(description="Risk_Treatment_Plan row id.")
    session_id: str = Field(description="Owning session.")
    output_id: str = Field(description="The accepted scenario this plan treats.")
    status: str = Field(description="RUNNING | COMPLETE | ERROR — the poll signal (stale RUNNING projects as ERROR).")
    treatment_strategy: str = Field(description="The strategy this plan was generated for — server-stamped 'Mitigate'.")
    scenario: dict[str, Any] | None = Field(
        default=None,
        description=("The accepted scenario this plan treats: scenario_title, "
                     "scenario_statement, risk_statement. Null only if the scenario row is "
                     "unreadable (defensive parse)."))
    risk_level: str | None = Field(
        default=None, description="The register risk level this plan was generated against (from the request).")
    review_status: str | None = Field(
        default=None, description="TreatmentReviewStatus (approved / changes_requested) — null until a human reviews.")
    review_comment: str | None = Field(default=None, exclude=True, description="The reviewer's comment, if any.")
    reviewed_by: str | None = Field(default=None, exclude=True, description="Who recorded the decision (from their login token).")
    reviewed_at: datetime | None = Field(default=None, exclude=True, description="When the decision was recorded.")
    risk_identification_date: datetime | None = Field(
        default=None,
        description="Echo of the request's register date — record data, never AI-generated (spec). Null when not sent.")
    plan: dict[str, Any] | None = Field(
        default=None,
        description=("The generated plan (SDD §7.3 contract): AI fields (title, objective, "
                     "recommendation, justification, controls_to_be_implemented[] — the "
                     "gap-analysis table, remediation_action_plan[], action_plan, "
                     "mitigation_owner, control_coverage, ...), the server stamp "
                     "(treatment_plan), and register echoes (risk_identification_date, "
                     "risk_owner, impacted_business_division). JSON is the wire contract; "
                     "markdown rendering is the client's job."))
    warnings: list[str] = Field(
        default_factory=list, exclude=True,
        description="Advisory validation warnings (vocabulary clamps, empty control map, ...). Never blocking.")
    moderation_flagged: bool = Field(
        default=False, exclude=True,
        description="Advisory content-moderation flag for a human reviewer, when moderation ran.")
    error_message: str | None = Field(
        default=None, description="Client-safe failure reason when status is ERROR.")
    created_at: datetime | None = Field(default=None, exclude=True, description="When this attempt was requested.")
    completed_at: datetime | None = Field(default=None, exclude=True, description="When it reached COMPLETE/ERROR.")


class TreatmentBoardRow(BaseModel):
    """One accepted scenario's line on the session plan board. Null plan fields = no plan has
    ever been requested for it (the UI shows a Generate button)."""
    output_id: str = Field(description="The accepted scenario.")
    scenario_title: str | None = Field(default=None, description="From the scenario, for display.")
    plan_id: str | None = Field(default=None, description="Active plan id; null = never requested.")
    status: str | None = Field(default=None, description="RUNNING | COMPLETE | ERROR (stale RUNNING projects as ERROR).")
    risk_level: str | None = Field(default=None)
    review_status: str | None = Field(default=None, description="approved / changes_requested / null.")
    error_message: str | None = Field(default=None)
    created_at: datetime | None = Field(default=None)
    completed_at: datetime | None = Field(default=None)


class TreatmentBoard(BaseModel):
    """GET /v1/sessions/{id}/treatment-plans — every accepted scenario's plan state in ONE
    call (the page the reviewer looks at daily; replaces N per-scenario polls)."""
    model_config = ConfigDict(json_schema_extra={"example": {
        "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e", "accepted_scenarios": 2,
        "plans": [{"output_id": "1a2b…", "scenario_title": "Ransomware via exposed RDP",
                   "plan_id": "b9fe…", "status": "COMPLETE", "risk_level": "Critical",
                   "review_status": "approved"},
                  {"output_id": "9f3c…", "scenario_title": "Insider tampering",
                   "plan_id": None, "status": None}]}})
    session_id: str
    accepted_scenarios: int = Field(description="How many accepted scenarios the session holds.")
    plans: list[TreatmentBoardRow]


class TreatmentCancelResponse(BaseModel):
    """POST .../treatment-plan/cancel — the stop button's receipt."""
    plan_id: str
    status: str = Field(description="Always ERROR after a successful cancel.")
    error_message: str | None = Field(default=None, description="'cancelled by user'.")


class TreatmentReviewBody(BaseModel):
    """POST .../treatment-plan/review — record the human adoption decision on a COMPLETE
    plan. The reviewer's identity comes from the login token, never from this body."""
    model_config = ConfigDict(json_schema_extra={"example": {
        "decision": "approved", "comment": "A3 timeline extended per operations."}})
    decision: TreatmentReviewStatus = Field(description="approved | changes_requested.")
    comment: str | None = Field(default=None, max_length=2000, description="Optional reviewer comment.")


class TreatmentReviewResponse(BaseModel):
    plan_id: str
    review_status: str
    reviewed_by: str | None = Field(default=None, description="From the reviewer's login token.")
    reviewed_at: datetime | None = None


class TreatmentRegisterRow(BaseModel):
    """One plan in the entity-wide remediation register."""
    plan_id: str
    session_id: str
    output_id: str
    asset_name: str | None = None
    scenario_title: str | None = None
    status: str = Field(description="RUNNING | COMPLETE | ERROR (stale RUNNING projects as ERROR).")
    risk_level: str | None = None
    review_status: str | None = None
    reviewed_by: str | None = None
    error_message: str | None = None
    created_at: datetime | None = None
    completed_at: datetime | None = None


class TreatmentRegisterPage(BaseModel):
    """GET /v1/entities/{id}/treatment-plans — every plan across the entity, newest first,
    filterable by status / review_status / risk_level. This list IS the remediation register."""
    entity_id: str
    limit: int
    offset: int
    plans: list[TreatmentRegisterRow]


class TreatmentAuditEvent(BaseModel):
    """One entry in a treatment-plan audit trail. `detail` is the event's DetailJSON verbatim
    (plan_id, status, decision, note… depending on the event type)."""
    at: datetime | None = Field(default=None, description="When it happened (UTC).")
    event: str = Field(description="requested | outcome | cancelled | reviewed | superseded.")
    actor: str | None = Field(default=None, description="The person (null on system events).")
    actor_type: str | None = Field(default=None, description="user | system.")
    session_id: str | None = Field(default=None, description="Present on the entity-wide feed.")
    detail: dict[str, Any] = Field(default_factory=dict)


class TreatmentAuditTrail(BaseModel):
    """GET .../treatment-plan/audit — one scenario's plan life story across ALL versions:
    who requested, each attempt's outcome, cancels, reviews, and supersedes, oldest first."""
    session_id: str
    output_id: str
    events: list[TreatmentAuditEvent]


class TreatmentEntityAuditPage(BaseModel):
    """GET /v1/entities/{id}/treatment-plans/audit — the compliance feed: every treatment-plan
    action across the entity, newest first, filterable by date range and person."""
    entity_id: str
    limit: int
    offset: int
    events: list[TreatmentAuditEvent]


class TreatmentEvidenceAttempt(BaseModel):
    """One AI-call receipt (Prompt_Log row) for the plan version — the exact words exchanged."""
    at: datetime | None = None
    prompt: str | None = Field(default=None, description="The exact flattened prompt sent.")
    response: str | None = Field(default=None, description="The exact raw model reply.")
    model_name: str | None = None
    model_version: str | None = None
    prompt_version: str | None = None
    parse_succeeded: bool | None = None


class TreatmentEvidence(BaseModel):
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
