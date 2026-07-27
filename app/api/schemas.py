"""Request/response Pydantic models for the session API (`app/api/sessions.py`).

Split out from the routes themselves so the shape of every endpoint's body/response
can be found in one place without wading through route logic.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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
                "asset_id": 12345,
                "entity_id": "ENT-001",
                "sector_id": 7,
                "supporting_system_id": [101, 102],
            }
        }
    )

    asset_id: int = Field(description="Primary key of the asset to generate threat scenarios for.")
    entity_id: str = Field(description="Tenant/business-unit code the asset belongs to; used for entity-scoped access control.")
    sector_id: int | None = Field(default=None, description="Optional sector id, used to bias threat-catalogue matching. Omit if unknown.")
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
    def _mode_and_output_ids_agree(self) -> "AcceptBody":
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


class SupportingSystemBoard(BaseModel):
    """One supporting system's row on the session status board: its per-stage statuses plus an overall status."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": 101,
                "name": "SCADA Historian",
                "stages": {"THREAT_IDENTIFICATION": "COMPLETE", "SCENARIO_GENERATION": "AWAITING_DECISION"},
                "overall": "awaiting_review",
            }
        }
    )

    id: int = Field(description="Supporting system's primary key.")
    name: str | None = Field(description="Supporting system's display name.")
    stages: dict[str, str] = Field(
        description="Per-stage status for this system, keyed by stage name (e.g. THREAT_IDENTIFICATION, SCENARIO_GENERATION)."
    )
    overall: str = Field(description="Computed overall status: pending, in_progress, awaiting_review, complete, error, or cancelled.")
    error_message: str | None = Field(
        default=None,
        description=(
            "Client-safe failure reason for this unit's most recent stage error, if any. "
            "Non-null on an awaiting_review board entry means the run failed mid-batch after "
            "generating some scenarios — the review set may be PARTIAL, not a complete run."
        ),
    )


class SessionBoard(BaseModel):
    """Full status board for a session: session-level info plus one row per supporting system."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "entity_id": "ENT-001",
                "session_status": "active",
                "current_stage": "SCENARIO_GENERATION",
                "stage_status": "AWAITING_DECISION",
                "supporting_systems": [
                    {
                        "id": 101,
                        "name": "SCADA Historian",
                        "stages": {"THREAT_IDENTIFICATION": "COMPLETE", "SCENARIO_GENERATION": "AWAITING_DECISION"},
                        "overall": "awaiting_review",
                    }
                ],
            }
        }
    )

    session_id: str = Field(description="Session's unique id (GUID).")
    entity_id: str = Field(description="Tenant/business-unit code the session belongs to.")
    session_status: str = Field(description="Lifecycle status: active, completed, or cancelled.")
    current_stage: str = Field(
        description="Current workflow stage: THREAT_IDENTIFICATION, SCENARIO_GENERATION, REVIEW, APPROVED, or CANCELLED."
    )
    stage_status: str = Field(
        description="Status of the current stage: IDLE, RUNNING, AWAITING_DECISION, COMPLETE, ERROR, or CANCELLED."
    )
    supporting_systems: list[SupportingSystemBoard] = Field(description="One status row per supporting system in this session.")


class CreateSessionResponse(BaseModel):
    """Response returned after a new session is created."""
    model_config = ConfigDict(json_schema_extra={"example": {"session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}})

    session_id: str = Field(description="Id of the newly created session. Use it to poll status, fetch results, or stream events.")


class ThreatResult(BaseModel):
    """One threat identified for a supporting system, as returned to the client."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "threat_id": "b3fc2c96-3f66-4562-8fa6-5717afa63f66",
                "supporting_system_id": 101,
                "threat_type": "Spoofing",
                "threat_name": "Unauthorized RTU firmware update",
                "grounding_status": "grounded",
                "threat_catalogue_id": 42,
            }
        }
    )

    threat_id: str = Field(description="Identified threat's unique id (GUID).")
    supporting_system_id: int = Field(description="Supporting system this threat applies to.")
    threat_type: str = Field(description="STRIDE threat category, e.g. Spoofing, Tampering, Denial of Service.")
    threat_name: str | None = Field(description="Human-readable threat name.")
    grounding_status: str = Field(
        description=(
            "Match confidence against the threat library: grounded (high confidence), "
            "confirm (moderate), or flagged (no confident match)."
        )
    )
    threat_catalogue_id: int | None = Field(
        description="Id of the matched threat-catalogue master row, when grounded/confirmed. Null when flagged."
    )


class MappedControl(BaseModel):
    """One Control_Library row mapped to a scenario by Step-4 control mapping
    (control_mapping.map_controls): the LLM suggested a mitigating control in free text and grounding
    matched it to this real library control. Ordered by rank (1 = best). An empty `controls`
    list on a scenario means nothing in the library matched well enough — a library-gap
    signal, not an error."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "control_library_id": 201,
                "control_code": "CII-CID-201",
                "domain": "Identification & Authentication",
                "control_name": "Multi-Factor Authentication",
                "rank": 1,
                "score": 93.0,
                "suggested_control": "Multi-factor authentication for privileged accounts",
                "standards": ["NIST SP 800-53 Rev. 5", "ISO 27001:2022"],
            }
        }
    )

    control_library_id: int = Field(description="Control_Library primary key.")
    control_code: str = Field(description="Stable control code, e.g. 'CII-CID-201'.")
    domain: str = Field(description="The control's domain as recorded in the library (reported as-is).")
    control_name: str = Field(description="The library control's official name.")
    rank: int = Field(description="1 = best match for this scenario.")
    score: float | None = Field(description="Raw rerank confidence 0-100 at mapping time.")
    suggested_control: str | None = Field(
        description="The LLM's original free-text suggestion this control grounded from; null when the mapping fell back to the scenario text.")
    standards: list[str] = Field(default_factory=list, description="Referred standard names for this control.")


class ScenarioResult(BaseModel):
    """One generated scenario for a supporting system, plus whether it has been accepted."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "output_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
                "supporting_system_id": 101,
                "scenario": {
                    "title": "Unauthorized Firmware Push",
                    "narrative": "An attacker with network access pushes unsigned firmware to the RTU, disrupting control.",
                    "risk_statement": "Could cause a sustained outage of the historian service.",
                },
                "accepted": False,
                "moderation_flagged": False,
                "moderation_categories": [],
                "validation_status": "ok",
                "validation_errors": [],
                "generation_epoch": 1,
            }
        }
    )

    output_id: str = Field(description="Generated scenario's unique id (GUID). Used to accept/regenerate this scenario.")
    supporting_system_id: int = Field(description="Supporting system this scenario applies to.")
    scenario: dict[str, Any] | None = Field(
        description="Generated scenario narrative (title, description, risk statement). Null if generation failed."
    )
    accepted: bool = Field(description="Whether a human reviewer has accepted this scenario.")
    # [REVIEW-FIX] previously ValidationJSON (where llm.moderate's result lands, via
    # tasks.py::_moderation_report) was never selected here at all — a flagged scenario was
    # written to the DB but invisible to any human reviewer through this API. None means
    # moderation was never checked (off by default, or the moderation service was
    # unavailable) — distinct from checked-and-clean (False).
    moderation_flagged: bool | None = Field(
        default=None,
        description="true if flagged by content moderation, false if checked and clean, null if moderation was never run.",
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
    controls: list[MappedControl] = Field(
        default_factory=list,
        description="Step-4 mapped mitigating controls from the control library, best first. Empty = no library control matched well enough.",
    )


class SessionResults(BaseModel):
    """All threats and scenarios produced so far for a session."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "entity_id": "ENT-001",
                "threats": [
                    {
                        "threat_id": "b3fc2c96-3f66-4562-8fa6-5717afa63f66",
                        "supporting_system_id": 101,
                        "threat_type": "Spoofing",
                        "threat_name": "Unauthorized RTU firmware update",
                        "grounding_status": "grounded",
                        "threat_catalogue_id": 42,
                    }
                ],
                "scenarios": [
                    {
                        "output_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
                        "supporting_system_id": 101,
                        "scenario": {
                            "title": "Unauthorized Firmware Push",
                            "narrative": "An attacker with network access pushes unsigned firmware to the RTU, disrupting control.",
                            "risk_statement": "Could cause a sustained outage of the historian service.",
                        },
                        "accepted": False,
                        "moderation_flagged": False,
                        "moderation_categories": [],
                        "validation_status": "ok",
                        "validation_errors": [],
                        "generation_epoch": 1,
                    }
                ],
            }
        }
    )

    session_id: str = Field(description="Session's unique id (GUID).")
    entity_id: str = Field(description="Tenant/business-unit code the session belongs to.")
    threats: list[ThreatResult] = Field(description="All threats identified so far for this session.")
    scenarios: list[ScenarioResult] = Field(description="All scenarios generated so far for this session.")


class AcceptResponse(BaseModel):
    """Response confirming an accept request was processed."""
    model_config = ConfigDict(
        json_schema_extra={"example": {"session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "status": "completed", "accepted_count": 3}}
    )

    session_id: str = Field(description="Session's unique id (GUID).")
    status: str = Field(description="Result of the accept request. Always 'completed' on success.")
    accepted_count: int = Field(description="Number of scenarios actually marked accepted by this request (0 for mode='none').")


class RegenerateResponse(BaseModel):
    """Response confirming a regenerate request was processed."""
    model_config = ConfigDict(
        json_schema_extra={"example": {"session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "status": "regenerating"}}
    )

    session_id: str = Field(description="Session's unique id (GUID).")
    status: str = Field(
        description="Result of the request: 'regenerating' for a scenario regenerate request, 'generating' for a next-set request."
    )


class CancelResponse(BaseModel):
    """Response confirming a session was cancelled."""
    model_config = ConfigDict(
        json_schema_extra={"example": {"session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "status": "cancelled"}}
    )

    session_id: str = Field(description="Session's unique id (GUID).")
    status: str = Field(description="Always 'cancelled' on success.")


class AcceptedScenario(BaseModel):
    """One accepted scenario row — joinable on ids."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "output_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
                "supporting_system_id": 101,
                "threat_type_id": 3,
                "threat_catalogue_id": 42,
                "threat_type": "Spoofing",
                "threat_name": "Unauthorized RTU firmware update",
                "scenario": {
                    "title": "Unauthorized Firmware Push",
                    "narrative": "An attacker with network access pushes unsigned firmware to the RTU, disrupting control.",
                    "risk_statement": "Could cause a sustained outage of the historian service.",
                },
            }
        }
    )

    output_id: str = Field(description="Accepted scenario's unique id (GUID).")
    supporting_system_id: int = Field(description="Supporting system this scenario applies to.")
    threat_type_id: int | None = Field(
        description="Id of the matched threat-type master row, when grounded/confirmed. Null when flagged."
    )
    threat_catalogue_id: int | None = Field(
        description="Id of the matched threat-catalogue master row, when grounded/confirmed. Null when flagged."
    )
    threat_type: str | None = Field(description="STRIDE threat category the scenario was generated from.")
    threat_name: str | None = Field(description="Human-readable name of the threat the scenario was generated from.")
    scenario: dict | None = Field(description="Accepted scenario narrative (title, description, risk statement).")
    controls: list[MappedControl] = Field(
        default_factory=list,
        description="Step-4 mapped mitigating controls from the control library, best first. Empty = no library control matched well enough.",
    )


class AcceptedScenariosResponse(BaseModel):
    """All scenarios ever accepted for an asset, across sessions, plus the latest completed session (if any)."""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "asset_id": 12345,
                "entity_id": "ENT-001",
                "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "completed_at": "2026-07-20T14:32:11.123Z",
                "scenarios": [
                    {
                        "output_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
                        "supporting_system_id": 101,
                        "threat_type_id": 3,
                        "threat_catalogue_id": 42,
                        "threat_type": "Spoofing",
                        "threat_name": "Unauthorized RTU firmware update",
                        "scenario": {
                            "title": "Unauthorized Firmware Push",
                            "narrative": "An attacker with network access pushes unsigned firmware to the RTU, disrupting control.",
                            "risk_statement": "Could cause a sustained outage of the historian service.",
                        },
                    }
                ],
            }
        }
    )

    asset_id: int = Field(description="Primary key of the asset these scenarios belong to.")
    entity_id: str = Field(description="Tenant/business-unit code the asset belongs to.")
    session_id: str | None = Field(
        description="Latest completed session's id, or null if the asset has no completed session yet (scenarios == [])."
    )
    completed_at: datetime | None = Field(description="UTC timestamp the latest session was completed. Null if none.")
    scenarios: list[AcceptedScenario] = Field(description="All scenarios ever accepted for this asset, across sessions.")


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
    """Request for POST /v1/tsg/threat-library/import — trigger one threat-library
    import (the same job scripts/import_threat_libraries.py runs). Plain JSON body,
    deliberately not multipart: the uploaded "file" is itself JSON text, so
    `file_content` carries it with no extra upload machinery."""
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
        "The library file's JSON text, supplied directly instead of downloading. "
        "Size-capped by settings.threat_library_import_max_upload_mb."))


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
                             "types_imported": 12, "threats_imported": 95, "actors_upserted": None},
            }
        }
    )

    source: str = Field(description="API source name, e.g. 'attack_ics' — the value used in the import URL.")
    source_tag: str | None = Field(description="Provenance tag stamped on this source's imported rows (Threat_Type.Source).")
    loaded: bool = Field(description="True when this source has contributed rows to the library.")
    type_count: int = Field(description="Threat_Type (family) rows attributed to this source.")
    threat_count: int = Field(description="Threat_Catalogue (exact threat) rows attributed to this source.")
    actor_count: int | None = Field(default=None, description="Threat_Actor rows — misp_actors only; null for every other source.")
    last_run: dict[str, Any] | None = Field(default=None, description="Most recent import attempt for this source, or null if never attempted.")


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


class ThreatLibraryImportAccepted(BaseModel):
    """Returned immediately (202) when an import is queued — poll
    GET .../import/status/{job_id} for the eventual outcome."""
    model_config = ConfigDict(json_schema_extra={"example": {"job_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8"}})

    job_id: str = Field(description="Celery task id for the queued import. Poll GET status/{job_id}.")


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
                           "ot_rules": [{"threat_type_id": 87, "threat_type_name": "ICS ATT&CK – Impact",
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
