"""Request/response Pydantic models for the session API (`app/api/sessions.py`).

Split out from the routes themselves so the shape of every endpoint's body/response
can be found in one place without wading through route logic.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

# Plan item 1b: bound every list-of-targets field so one HTTP request can't turn into an
# unbounded synchronous AI/DB workload inside a single Celery task (no chunking exists).
_MAX_BATCH = 50


class CreateSessionBody(BaseModel):
    """Ids only — asset/subsystem/sector descriptive context is resolved server-side,
    authoritatively, from the DB (`app.pipeline.context.gather_asset_details`), never
    accepted from the client. This is deliberate: the client can no longer inject
    arbitrary text into the LLM prompt just by having it happen to match the DB, because
    there's no client-supplied text to inject in the first place."""
    asset_id: int
    entity_id: str
    sector_id: int | None = None
    user_id: str | None = None
    supporting_system_id: list[int] = Field(min_length=1, max_length=_MAX_BATCH)

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
    """Body for the "accept scenarios" endpoint."""
    # No `min_length`: [R8] reads `subset=[]` as "accept none", distinct from `subset=None` = "accept all".
    subset: list[str] | None = Field(default=None, max_length=_MAX_BATCH)


class RegenerateScenariosBody(BaseModel):
    """Body for asking the pipeline to regenerate scenarios for one supporting system."""
    supporting_system_id: int
    output_ids: list[str] = Field(min_length=1, max_length=_MAX_BATCH)
    user_note: str | None = None


class SupportingSystemBoard(BaseModel):
    """One supporting system's row on the session status board: its per-stage statuses plus an overall status."""
    id: int
    name: str | None
    stages: dict[str, str]
    overall: str


class SessionBoard(BaseModel):
    """Full status board for a session: session-level info plus one row per supporting system."""
    session_id: str
    entity_id: str
    session_status: str
    current_stage: str
    stage_status: str
    supporting_systems: list[SupportingSystemBoard]


class CreateSessionResponse(BaseModel):
    """Response returned after a new session is created."""
    session_id: str


class ThreatResult(BaseModel):
    """One threat identified for a supporting system, as returned to the client."""
    threat_id: str
    supporting_system_id: int
    threat_type: str
    threat_name: str | None
    grounding_status: str
    threat_catalogue_id: int | None


class ScenarioResult(BaseModel):
    """One generated scenario for a supporting system, plus whether it has been accepted."""
    output_id: str
    supporting_system_id: int
    scenario: dict[str, Any] | None
    accepted: bool


class SessionResults(BaseModel):
    """All threats and scenarios produced so far for a session."""
    session_id: str
    entity_id: str
    threats: list[ThreatResult]
    scenarios: list[ScenarioResult]


class AcceptResponse(BaseModel):
    """Response confirming an accept request was processed."""
    session_id: str
    status: str


class RegenerateResponse(BaseModel):
    """Response confirming a regenerate request was processed."""
    session_id: str
    status: str


class CancelResponse(BaseModel):
    """Response confirming a session was cancelled."""
    session_id: str
    status: str


class AcceptedScenario(BaseModel):
    """One accepted scenario row — joinable on ids."""
    output_id: str
    supporting_system_id: int
    threat_type_id: int | None
    threat_catalogue_id: int | None
    threat_type: str | None
    threat_name: str | None
    scenario: dict | None


class AcceptedScenariosResponse(BaseModel):
    """All scenarios ever accepted for an asset, across sessions, plus the latest completed session (if any)."""
    asset_id: int
    entity_id: str
    session_id: str | None      # None - the asset has no completed session yet (scenarios == [])
    completed_at: datetime | None
    scenarios: list[AcceptedScenario]
