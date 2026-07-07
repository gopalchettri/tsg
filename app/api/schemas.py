"""Request/response Pydantic models for the session API (`app/api/sessions.py`).

Split out from the routes themselves so the shape of every endpoint's body/response
can be found in one place without wading through route logic.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

# Plan item 1b: bound every list-of-targets field so one HTTP request can't turn into an
# unbounded synchronous AI/DB workload inside a single Celery task (no chunking exists).
_MAX_BATCH = 50


class CreateSessionBody(BaseModel):
    asset_id: int
    entity_id: str
    sector_id: int | None = None
    user_id: str | None = None
    service_id: int | None = None


class AcceptBody(BaseModel):
    subset: list[str] | None = None


class RegenerateScenariosBody(BaseModel):
    supporting_system_id: int
    output_ids: list[str] = Field(min_length=1, max_length=_MAX_BATCH)
    user_note: str | None = None


class SupportingSystemBoard(BaseModel):
    id: int
    name: str | None
    stages: dict[str, str]
    overall: str


class SessionBoard(BaseModel):
    session_id: str
    entity_id: str
    session_status: str
    current_stage: str
    stage_status: str
    supporting_systems: list[SupportingSystemBoard]


class CreateSessionResponse(BaseModel):
    session_id: str


class ProfileResult(BaseModel):
    supporting_system_id: int
    profile: dict[str, Any]
    accepted: bool


class ThreatResult(BaseModel):
    threat_id: str
    supporting_system_id: int
    threat_type: str
    threat_name: str | None
    grounding_status: str
    threat_catalogue_id: int | None


class ScenarioResult(BaseModel):
    output_id: str
    supporting_system_id: int
    scenario: dict[str, Any] | None
    accepted: bool


class SessionResults(BaseModel):
    session_id: str
    profiles: list[ProfileResult]
    threats: list[ThreatResult]
    scenarios: list[ScenarioResult]


class AcceptResponse(BaseModel):
    session_id: str
    status: str


class RegenerateResponse(BaseModel):
    session_id: str
    status: str


class CancelResponse(BaseModel):
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
    asset_id: int
    entity_id: str
    session_id: str | None      # None - the asset has no completed session yet (scenarios == [])
    completed_at: datetime | None
    scenarios: list[AcceptedScenario]
