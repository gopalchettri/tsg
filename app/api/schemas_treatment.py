"""Wire models of the treatment-plan (remediation) surface. Split out of schemas.py in 2026-09 as
a PURE move: every model keeps its name, so the OpenAPI document is byte-identical, and every
existing `from app.api.schemas import Treatment…` keeps working (schemas.py resolves this slice
lazily). TreatmentPlanResultEvent is NOT here — it is part of the SSE event union and stays with
the other event models; the shared building blocks (ApiModel, MappedControl, ScenarioNarrative,
ThreatResult, ThreatActorRef, _canonical_guid) stay in schemas.py and are imported.
"""
from __future__ import annotations

from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Annotated, Any, Literal

from pydantic import ConfigDict, Field, WithJsonSchema, field_validator, model_validator

from app.api.schemas import (  # shared helpers stay in the parent
    LIBRARY_BLOCK_DOC,
    SCENARIO_SOURCE_DOC,
    ApiModel,
    CreateSessionBody,
    LibraryOutcomeBlock,
    MappedControl,
    ScenarioNarrative,
    ThreatActorRef,
    ThreatResult,
    _canonical_guid,
)
from app.api.schemas_references import (
    ManualThreatIdentity,
    RegisterControlReferenceList,
    ScenarioControlReferenceList,
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
    # Computed by the server from each action's duration_days + depends_on (never AI-written):
    # the critical-path length, and its end date when the register sent a mitigation window.
    mitigation_timeline_days: Any | None = None
    mitigation_end_date_planned: Any | None = None
    mitigation_owner: Any | None = None
    risk_owner: Any | None = None
    impacted_business_division: Any | None = None


# The register's three scores. Decimal, never float: pipeline.treatment multiplies these for the
# consistency advisory, and in binary float 3.3 * 3.3 is 10.889999999999999 — a warning against a
# register that is exact. The register has no upper value (0 and up; the old 5x5 and 0-100 caps
# are retired). max_digits=15 is not a domain limit, it is the EXACTNESS limit: the snapshot stores
# a decimal as a JSON float (pipeline.treatment_input._num), and the model is told to cite it verbatim —
# a float holds 15 significant digits exactly and no more (a JS client's number likewise), so a
# 16th digit could be stored as a different number. With decimal_places=4 that leaves 11 digits
# before the point: the largest score is 99,999,999,999.9999. Beyond that is a 422 naming the
# rule, never a silent change. decimal_places is a CEILING, so whole numbers and 1-3 places still
# validate. The route reads the literal digits (app/api/exact_json.py) — without that, json.loads
# rounded to a float BEFORE this rule ran, and it judged a number the client never sent.
#
# WithJsonSchema is load-bearing, not cosmetic: a bare Decimal publishes as
# anyOf[{number}, {string, pattern:…}], which generates a `number | string` union in every client.
# We publish the plain number. Deliberately NO multipleOf: 0.0001 — the standards-correct spelling
# of "4 places", but JS validators compute 20.25 % 0.0001 as 9.99e-05 and would reject valid
# 2-place input; the ceiling is enforced server-side (422 decimal_max_places) and documented below.
_RATING = Annotated[Decimal, Field(ge=0, max_digits=15, decimal_places=4),
                    WithJsonSchema({"type": "number", "minimum": 0, "maximum": 99999999999.9999,
                                    "examples": [0, 4, 4.25, 87.5, 4000]})]
_RATING_RULE = ("an int or a decimal, 0 or more, up to 4 decimal places and 15 digits in total "
                "(largest 99999999999.9999). Optional: omitted, null or \"\" all mean the register "
                "has no value, and the plan shows null rather than a number the AI invented")

#: The register half of the approved remediation payload, verbatim — real values from the owner's
#: library (the three control ids/codes/names are live Control Library rows). Published as the
#: example of BOTH register-data bodies: nothing in this half is specific to which kind of scenario
#: the plan is for, and one shared literal cannot drift from the other.
#:
#: Decimals on purpose, and this is the only place an integrator sees them: the field takes an int
#: or a decimal, and the published example is where that gets learned. 3 x 2.46 = 7.38 exactly, so
#: the example also passes the register-consistency advisory instead of teaching a warning.
#: Dates carry a TIME on purpose too — that is the form the register actually sends, and the pair
#: that used to be a 422 (see _keep_the_calendar_date_as_written).
_REGISTER_EXAMPLE: dict[str, Any] = {
    "existing_controls": [
        {"control_id": 1490, "control_code": "CII-CID-202",
         "control_name": "Malicious Link & File Protections"},
        {"control_id": 1501, "control_code": "CII-CID-213",
         "control_name": "Phishing & Spam Protection"},
        {"control_id": 1486, "control_code": "CII-CID-198", "control_name": "Mobile Code"}],
    "likelihood_rating": 3, "impact_rating": 2.46, "final_risk_rating": 7.38,
    "risk_level": "Medium",
    "risk_identification_date": "2026-09-18T15:38:19.853",
    "risk_owner": "Head of Traffic Operations",
    "impacted_business_division": "Traffic Management",
    "existing_controls_all_subsystems": "No",
    "existing_controls_all_subsystems_justification":
        "Intelligent Traffic Systems Platform; Traffic Signal Control System",
    "mitigation_start_date": "2026-09-18T15:38:19.853",
    "mitigation_end_date": "2026-12-17T15:38:19.853",
}


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
    model_config = ConfigDict(extra="forbid", json_schema_extra={"example": _REGISTER_EXAMPLE})

    existing_controls: RegisterControlReferenceList | None = Field(
        default=None,
        description=("The register's controls already applied to this risk — the gap-analysis "
                     "BASELINE: the AI's recommended controls are the scenario's controls NOT "
                     "covered by this list. Each entry names a Control Library row by "
                     "control_id, control_code, control_name or any mix, or is a plain string "
                     "(a library code, or free text such as 'Quarterly phishing simulation' for a "
                     "control the library does not hold — free text is kept verbatim, never "
                     "rejected). Entries naming a library row are matched to the scenario's "
                     "controls by TSG (name, domain and description fetched from the library); "
                     "free text is judged by the AI. Optional: omitted, null, \"\" and [] all "
                     "mean a risk with no recorded controls. At most 50 entries; blank entries "
                     "are dropped, order is kept, and naming one control twice KEEPS THE FIRST "
                     "and drops the repeat — it is not an error. (The scenario's own "
                     "mapped_controls is the opposite: a duplicate there is a 422, because those "
                     "entries become rows.)"))
    likelihood_rating: _RATING | None = Field(
        default=None, description=f"Register likelihood — {_RATING_RULE}.")
    impact_rating: _RATING | None = Field(
        default=None, description=f"Register impact — {_RATING_RULE}.")
    final_risk_rating: _RATING | None = Field(
        default=None,
        description=f"Register final risk rating — {_RATING_RULE}. Taken as-is; never re-derived.")
    # RiskLevel is kept in the union rather than replaced by `str`, deliberately. The four toolkit
    # values are the ones every TSG surface shows and the ones the risk-urgency advisory reasons
    # about, and dropping the enum would drop them out of /openapi.json — a generated client would
    # offer a free-text box where a picker belongs. But the field can no longer REFUSE anything
    # else: the register this body speaks for is another system's, and a deployment whose register
    # says "Severe" or "Very High" was getting a 422 on the whole plan request over a label that
    # TSG only ever echoes. So: known value -> the enum member, anything else -> the string
    # verbatim, blank/null/absent -> null. Both branches are `str` at runtime (RiskLevel is a
    # StrEnum), so every consumer that stores or compares it is unaffected by which branch ran.
    risk_level: RiskLevel | str | None = Field(
        default=None,
        description=("Register risk level. Low | Medium | High | Critical are the toolkit's own "
                     "values and the ones TSG's advisories understand; any other non-empty label "
                     "your register uses is accepted and echoed back unchanged. Omitted, null or "
                     "\"\" mean the register has no level."))
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
        description="End of that window. The AI sizes each action in days and names what it waits "
                    "for; TSG then dates every action from mitigation_start_date and warns when "
                    "the plan ends after this date. Without the pair, actions carry durations "
                    "only and their start_date/end_date are null.")

    @field_validator("existing_controls", "likelihood_rating", "impact_rating",
                     "final_risk_rating", "risk_level",
                     "risk_identification_date", "risk_owner", "impacted_business_division",
                     "existing_controls_all_subsystems",
                     "existing_controls_all_subsystems_justification",
                     "mitigation_start_date", "mitigation_end_date", mode="before")
    @classmethod
    def _blank_is_absent(cls, v):
        """An empty string means "not provided" on every field of this body, not a failure.

        The UI sends "" for an unfilled control. Without this, the TYPED ones (the two dates, the
        datetime, the YesNo enum, the three Decimal ratings) each 422 the ENTIRE request — the
        caller gets no plan at all rather than a plan without that value, which contradicts this
        model's own "absent -> the output shows null" contract. The str fields are included
        deliberately: they ACCEPT "" happily, and it then survives redact() into the snapshot and
        back out through _VISIBLE_PLAN_KEYS as "" where that same contract promises null.

        `risk_level`, `existing_controls` and the three ratings joined this list in 2026-09, when
        the approved payload made them optional: the note that used to stand here ("risk_level is
        REQUIRED, so "" is a genuinely unfilled mandatory field and its 422 is correct") described
        five REQUIRED fields, and every one of them is now optional. Nothing on this body is
        mandatory any more, so nothing on it has a mandatory field's reason to refuse a blank.

        mode="before" so this runs ahead of type coercion, of the control-reference parsing, and of
        _validate_mitigation_window.
        """
        return None if isinstance(v, str) and not v.strip() else v

    @field_validator("mitigation_start_date", "mitigation_end_date", mode="before")
    @classmethod
    def _keep_the_calendar_date_as_written(cls, v):
        """Accept a date OR a date-with-time, and keep THE DATE THE CALLER WROTE.

        The register sends "2026-09-18T15:38:19.853" — a timestamp, for a field that is a calendar
        date. Pydantic refuses a non-midnight datetime for a `date` field (date_from_datetime_
        inexact), so the whole plan request was a 422 over a time nobody needed.

        Why the date part is taken here and NOT after normalizing the offset, which is what
        risk_identification_date does one field below: "2026-10-01T02:00:00+05:30" is 2026-09-30
        in UTC, so converting first would date the mitigation window a day EARLY — and the window
        is what every action's start_date/end_date is computed from, so one plan in the whole
        deployment would silently be a day out. A mitigation window is a business calendar, not an
        instant: the caller's 1 October is 1 October. `.date()` on the parsed value drops the
        offset without applying it, which is exactly that rule.

        A value that is not ISO-8601 is handed back untouched so pydantic renders its own
        date-parsing 422 — this validator never turns a malformed date into a silent None.
        """
        if isinstance(v, datetime):        # checked first: datetime IS a date subclass
            return v.date()
        if isinstance(v, str):
            try:
                return datetime.fromisoformat(v.strip()).date()
            except ValueError:
                return v
        return v

    @model_validator(mode="after")
    def _validate_mitigation_window(self):
        if (self.mitigation_start_date is None) != (self.mitigation_end_date is None):
            raise ValueError("mitigation_start_date and mitigation_end_date must be provided together")
        if self.mitigation_start_date and self.mitigation_end_date < self.mitigation_start_date:
            raise ValueError("mitigation_end_date must be on or after mitigation_start_date")
        return self

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



#: The published example of a manual scenario — the approved payload's `manual_scenario`, verbatim.
#: Every id, code and name is a real row in the owner's library: the category/type/threat are
#: threat-library rows (threat_id 126 is the LIBRARY threat's id, not a session's scenario uuid) and
#: the five controls are live Control Library rows. `entity_id` is published as an INT here, which
#: is the form the register sends; CreateSessionBody accepts that and the numeric string alike.
_MANUAL_SCENARIO_EXAMPLE: dict[str, Any] = {
    "entity_id": 142, "asset_id": 1200, "sector_id": 183, "subsector_id": 198, "service_id": 1707,
    "supporting_system_id": [1550, 1551],
    "threat_category_id": 5, "threat_category_name": "Tampering",
    "threat_type_id": 42, "threat_type_name": "Engineering Workstation Compromise",
    "threat_id": 126, "threat_name": "Engineering workstation compromise",
    "threat_scenario": (
        "Threat actors compromise an engineering workstation, programming laptop or project "
        "repository through phishing, malware, portable media, stolen laptop or weak endpoint "
        "controls. The workstation is then used to access controller projects, firmware files, "
        "recipes, network paths or privileged tools."),
    "risk_statement": (
        "Compromise of engineering workstations can expose controller logic and enable trusted "
        "changes to devices, making the attack difficult to distinguish from normal engineering "
        "activity."),
    "mapped_controls": [
        {"control_id": 1483, "control_code": "CII-CID-195",
         "control_name": "Malicious Code Protection (Anti-Malware)"},
        {"control_id": 1486, "control_code": "CII-CID-198", "control_name": "Mobile Code"},
        {"control_id": 1490, "control_code": "CII-CID-202",
         "control_name": "Malicious Link & File Protections"},
        {"control_id": 1501, "control_code": "CII-CID-213",
         "control_name": "Phishing & Spam Protection"},
        {"control_id": 1508, "control_code": "CII-CID-220", "control_name": "User Awareness"}],
}


class ManualScenarioIn(ManualThreatIdentity, CreateSessionBody):
    """A scenario a PERSON wrote, sent with its remediation request (RemediationPlanBody,
    is_manual=true). The asset half is CreateSessionBody's own — ids only, resolved server-side
    from the asset register exactly as a TSG run resolves them, so the AI plans against the same
    asset context either way and the client can never inject asset text. The threat half is
    ManualThreatIdentity's six fields, flat on the wire.

    The threat half names LIBRARY rows, by id or by name: an unknown category is a 422 (the six
    STRIDE categories are never minted); a type or threat not yet in the library is proposed to the
    curators as a PENDING row stamped Source='manual' with the caller as CreatedBy. The three must
    also be a combination the library holds: a threat already in the library must be sent with ITS
    type and one of ITS categories, and an existing type with a category the library files it under
    — otherwise a 422 on that field names the library's value. No value may be blank — whitespace
    or punctuation alone is a 422, never a nameless library row.

    NO `scenario_title`. It was required until 2026-09 and is absent from the approved payload:
    the title was a second name for content the scenario already carries in `threat_scenario` and
    in the threat's own name, and it is the one field of a manual scenario TSG never read back for
    anything but display. Removing a REQUIRED request field cannot break a caller that still sends
    one — except that this model forbids extras, so a stale client's `scenario_title` is a 422
    naming it rather than a silent drop. That is the intended answer: it tells the caller the field
    is gone instead of letting them believe TSG stored their title.
    """
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True,
                              json_schema_extra={"example": _MANUAL_SCENARIO_EXAMPLE})

    threat_scenario: str = Field(
        min_length=1, max_length=4000,
        description="What happens — the attack narrative the plan is written against.")
    risk_statement: str = Field(
        min_length=1, max_length=4000,
        description="The business impact if it happens — the plan's urgency is tied to it.")
    mapped_controls: ScenarioControlReferenceList | None = Field(
        default=None,
        description="The ONLY controls this plan may recommend, in your order of relevance — each "
                    "entry a Control Library row named by control_id, control_code, control_name "
                    "or any mix, or a plain code string. Every entry must resolve to an ACTIVE "
                    "library row (unknown or retired is a 422, all named), and naming one control "
                    "twice is a 422. Controls you send are never re-mapped or replaced. Optional: "
                    "omitted, null, \"\" and [] all mean you chose none — TSG then maps 5..25 "
                    "library controls to the scenario before planning, the same matching an AI "
                    "scenario gets, recorded in a controls_mapped audit row.")

    @field_validator("mapped_controls", mode="before")
    @classmethod
    def _blank_mapped_controls_is_absent(cls, v):
        """"" means "no controls", not a 422 — the same rule TreatmentPlanBody applies to every
        optional field of the register half, and for the same reason: a UI that leaves the control
        picker untouched must not lose the whole scenario over it.

        NOT named `_blank_is_absent`, deliberately: that is the name ManualThreatIdentity gives the
        same rule for the six threat fields, and a subclass attribute of that name SILENTLY REPLACES
        the inherited one — so a blank `threat_type_name` stopped meaning "absent" (it reached
        _names_a_real_row and complained about punctuation instead of naming the id/name pair the
        caller had to choose from). Validators are class attributes; two of them cannot share a
        name across a class and its base.
        """
        return None if isinstance(v, str) and not v.strip() else v


class RemediationPlanBody(TreatmentPlanBody):
    """POST /v1/remediation-plans — ONE request shape for both kinds of scenario.

    is_manual=false: the scenario is TSG's — send session_id + scenario_id (an accepted scenario),
    exactly what POST .../scenarios/{scenario_id}/treatment-plan takes in its path.
    is_manual=true: send manual_scenario instead (and an Idempotency-Key header); TSG saves it,
    accepts it and starts the plan in the same call. Mixing the two is a 422.
    Every other field is TreatmentPlanBody's register data, unchanged."""
    # BOTH approved payloads are published, because the two kinds of request differ in exactly the
    # part an example is for: one sends `manual_scenario` and no ids, the other sends the two ids
    # and no scenario, and _one_kind refuses a body that mixes them. A single example would leave
    # half the callers of this route guessing at the half they need — and guessing wrong is a 422.
    # Under "examples" (plural) rather than "example": Swagger renders a picker, and
    # test_every_documented_example_validates_against_its_own_model validates every entry.
    model_config = ConfigDict(json_schema_extra={"examples": [
        {"is_manual": True, "manual_scenario": _MANUAL_SCENARIO_EXAMPLE, **_REGISTER_EXAMPLE},
        # The smallest is_manual=false request also shows the second published register form: whole
        # numbers, a "Z"-suffixed identification date, and existing_controls naming three library
        # rows that the plan's gap analysis then works against.
        {"is_manual": False,
         "session_id": "8bd26529-2031-8428-9ed7-01a0d4840e23",
         "scenario_id": "0aed3720-ab97-83fa-ab43-01a0d4890bd4",
         "existing_controls": [
             {"control_id": 1490, "control_code": "CII-CID-202",
              "control_name": "Malicious Link & File Protections"},
             {"control_id": 1501, "control_code": "CII-CID-213",
              "control_name": "Phishing & Spam Protection"},
             {"control_id": 1508, "control_code": "CII-CID-220", "control_name": "User Awareness"}],
         "likelihood_rating": 4, "impact_rating": 5, "final_risk_rating": 20,
         "risk_level": "Critical", "risk_identification_date": "2026-09-15T09:30:00Z",
         "risk_owner": "Head of OT Operations",
         "impacted_business_division": "Power Generation Operations",
         "existing_controls_all_subsystems": "No",
         "existing_controls_all_subsystems_justification":
             "Controls are deployed on corporate IT systems only.",
         "mitigation_start_date": "2026-10-01T00:00:00",
         "mitigation_end_date": "2026-12-31T00:00:00"}]})

    is_manual: bool = Field(
        description="false: the scenario already exists in TSG (send session_id + scenario_id). "
                    "true: a person wrote it — send manual_scenario, TSG saves it.")
    session_id: str | None = Field(
        default=None, max_length=38,   # 38: a GUID in braces, which dal.canonical_guid accepts
        description="is_manual=false only: the TSG session that holds the scenario.")
    scenario_id: str | None = Field(
        default=None, max_length=38,   # see session_id
        description="is_manual=false only: the accepted scenario to plan for.")
    manual_scenario: ManualScenarioIn | None = Field(
        default=None, description="is_manual=true only: the scenario a person wrote.")

    @model_validator(mode="after")
    def _one_kind(self):
        if self.is_manual:
            if self.manual_scenario is None:
                raise ValueError("is_manual=true requires manual_scenario")
            if self.session_id is not None or self.scenario_id is not None:
                raise ValueError("is_manual=true must not send session_id or scenario_id — "
                                 "TSG creates them")
        else:
            if not self.session_id or not self.scenario_id:
                raise ValueError("is_manual=false requires session_id and scenario_id")
            if self.manual_scenario is not None:
                raise ValueError("is_manual=false must not send manual_scenario")
        return self


#: RemediationPlanBody's routing fields — everything else in it is the register's risk data.
REMEDIATION_ROUTING_FIELDS = frozenset({"is_manual", "session_id", "scenario_id", "manual_scenario"})


class RemediationPlanAccepted(ApiModel):
    """POST /v1/remediation-plans — the plan request's receipt, for either kind of scenario."""
    model_config = ConfigDict(json_schema_extra={"example": {
        "plan_id": "0f0e0d0c-0b0a-8988-8786-858483828180",
        "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e",
        "scenario_id": "1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90",
        "status": "RUNNING", "is_manual": True, "replayed": False}})

    plan_id: str = Field(description="The plan row's id.")
    session_id: str = Field(
        description="The session holding the scenario. For a manual scenario TSG created it — "
                    "KEEP it: status, plan, review and regenerate all take it in their path.")
    scenario_id: str = Field(description="The scenario the plan treats (created by TSG when manual).")
    status: str = Field(
        description="RUNNING on a new plan. On a replay, the existing plan's current status "
                    "(RUNNING | COMPLETE | ERROR — a stale RUNNING reads ERROR).")
    is_manual: bool = Field(
        description="The SCENARIO's provenance, read from the saved row — true when a person "
                    "wrote it. Not an echo of the request flag: sending is_manual=false with a "
                    "hand-written scenario's ids still answers true.")
    library: LibraryOutcomeBlock | None = Field(
        default=None,
        description=LIBRARY_BLOCK_DOC + " On a REPLAY this is the ORIGINAL save's outcome, "
                   "re-read rather than recomputed, so a retry never loses the warning the first "
                   "call gave you.")
    replayed: bool = Field(
        default=False,
        description="True when this Idempotency-Key had already saved this scenario, so nothing "
                    "new was saved. Normally this is the ORIGINAL request's plan (HTTP 200). If the "
                    "original never got as far as a plan, this request started it (HTTP 202).")


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
                 "mitigation_timeline": "2026-10-01 → 2026-11-09 (40 days, critical path "
                                        "A1 → A3 → A4)",
                 "mitigation_timeline_days": 40,
                 "mitigation_end_date_planned": "2026-11-09",
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
    scenario_source: str | None = Field(
        default=None,
        description=SCENARIO_SOURCE_DOC + " Null only where this response carries no scenario "
                                          "link at all — the plan's scenario row is missing (the "
                                          "joins are outer; there are no enforced foreign keys).")
    library: LibraryOutcomeBlock | None = Field(default=None, description=LIBRARY_BLOCK_DOC)
    scenario_replaced: bool = Field(
        default=False,
        description=(
            "True when the scenario this plan treats is NO LONGER the accepted version — someone "
            "adopted a regeneration of it (accept with `replace_accepted`). The plan is kept and "
            "still readable here, but it has left the plan board and the remediation register, "
            "and it can no longer be approved (409 `scenario_not_accepted`). Show it as historic: "
            "the risk's current answer is whatever the accepted version has.\n\n"
            "Always false on the board and the entity register, which list accepted versions only."))
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
                     "applicable_to_all_subsystems, mitigation_owner), the server-computed schedule "
                     "(each action's start_date/end_date/timeline, mitigation_timeline, "
                     "mitigation_timeline_days, mitigation_end_date_planned), "
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
    scenario_source: str | None = Field(default=None, description=SCENARIO_SOURCE_DOC)
    library: LibraryOutcomeBlock | None = Field(default=None, description=LIBRARY_BLOCK_DOC)
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
    """GET .../treatment-plan/evidence?plan_id={plan_id} — the reproducibility bundle for ONE
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
