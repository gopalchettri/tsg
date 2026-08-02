"""Curator CRUD routes for the four threat-library master tables.

Thin route layer: every handler is a one-line delegation to app/api/library_crud.py, so the
shared behaviour (admin-key gate, CreatedBy/UpdatedBy stamping, 409 translation, embedding
refresh) cannot drift between the two libraries. Read that module for the semantics.

EVERY route below needs its own (METHOD, path) entry in app/api/route_audit.py — the app
refuses to boot otherwise.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Path, Request

from app.api.deps import Principal, get_principal, require_admin
from app.api.library_crud import _DELETED, _LIMIT, _OFFSET, _create, _delete, _list, _update
from app.api.schemas import (
    ThreatActorCreate, ThreatActorRow, ThreatActorUpdate,
    ThreatCatalogueCreate, ThreatCatalogueRow, ThreatCatalogueUpdate,
    ThreatCategoryCreate, ThreatCategoryRow, ThreatCategoryUpdate,
    ThreatTypeCreate, ThreatTypeRow, ThreatTypeUpdate,
)

router = APIRouter(
    prefix="/v1/tsg/threat-library",
    dependencies=[Depends(require_admin)],
)

@router.get("/threat-categories", response_model=list[ThreatCategoryRow], tags=["Threat Categories Admin"])
def list_threat_categories(limit: int = _LIMIT, offset: int = _OFFSET, include_deleted: bool = _DELETED,
                        _principal: Principal = Depends(get_principal)):
    """STRIDE categories. Read this first — nothing else in the API returns row ids, so this is
    where the id each resource's PATCH/DELETE routes need comes from: `threat_category_id` here,
    and `threat_type_id`/`threat_catalogue_id`/`threat_actor_id` on the other three list routes
    below."""
    return _list("threat-categories", limit, offset, include_deleted)


@router.post("/threat-categories", response_model=ThreatCategoryRow, status_code=201, tags=["Threat Categories Admin"])
def create_threat_category(body: ThreatCategoryCreate, request: Request,
                        principal: Principal = Depends(get_principal)):
    """Create a category. The id is caller-supplied — this table's PK is not IDENTITY."""
    return _create("threat-categories", body, principal, request)


@router.patch("/threat-categories/{threat_category_id}", response_model=ThreatCategoryRow, tags=["Threat Categories Admin"])
def update_threat_category(body: ThreatCategoryUpdate, request: Request, threat_category_id: int = Path(ge=1),
                        principal: Principal = Depends(get_principal)):
    """Partial update. Omitted fields keep their current value."""
    return _update("threat-categories", threat_category_id, body, principal, request)


@router.delete("/threat-categories/{threat_category_id}", response_model=ThreatCategoryRow, tags=["Threat Categories Admin"])
def delete_threat_category(request: Request, threat_category_id: int = Path(ge=1),
                        principal: Principal = Depends(get_principal)):
    """Soft delete (IsDeleted=1). Returns the deleted row so the caller can see the who/when."""
    return _delete("threat-categories", threat_category_id, principal, request)


@router.get("/threat-types", response_model=list[ThreatTypeRow], tags=["Threat Types Admin"])
def list_threat_types(limit: int = _LIMIT, offset: int = _OFFSET, include_deleted: bool = _DELETED,
                    _principal: Principal = Depends(get_principal)):
    """Threat families."""
    return _list("threat-types", limit, offset, include_deleted)


@router.post("/threat-types", response_model=ThreatTypeRow, status_code=201, tags=["Threat Types Admin"])
def create_threat_type(body: ThreatTypeCreate, request: Request,
                    principal: Principal = Depends(get_principal)):
    """Create a family. Returns `embeddings_job_id` — poll it on `/embeddings/status/{job_id}`
    to know when the AI can match the new name."""
    return _create("threat-types", body, principal, request)


@router.patch("/threat-types/{threat_type_id}", response_model=ThreatTypeRow, tags=["Threat Types Admin"])
def update_threat_type(body: ThreatTypeUpdate, request: Request, threat_type_id: int = Path(ge=1),
                    principal: Principal = Depends(get_principal)):
    """Partial update. A rename re-embeds the row and returns the new job's id."""
    return _update("threat-types", threat_type_id, body, principal, request)


@router.delete("/threat-types/{threat_type_id}", response_model=ThreatTypeRow, tags=["Threat Types Admin"])
def delete_threat_type(request: Request, threat_type_id: int = Path(ge=1),
                    principal: Principal = Depends(get_principal)):
    """Soft delete. Also drops the row's embedding so grounding stops matching it."""
    return _delete("threat-types", threat_type_id, principal, request)


@router.get("/threat-catalogue", response_model=list[ThreatCatalogueRow], tags=["Threat Catalogue Admin"])
def list_threat_catalogue(limit: int = _LIMIT, offset: int = _OFFSET, include_deleted: bool = _DELETED,
                        _principal: Principal = Depends(get_principal)):
    """Exact threats."""
    return _list("threat-catalogue", limit, offset, include_deleted)


@router.post("/threat-catalogue", response_model=ThreatCatalogueRow, status_code=201, tags=["Threat Catalogue Admin"])
def create_threat_catalogue(body: ThreatCatalogueCreate, request: Request,
                            principal: Principal = Depends(get_principal)):
    """Create an exact threat under a family. 404s if the family doesn't exist."""
    return _create("threat-catalogue", body, principal, request)


@router.patch("/threat-catalogue/{threat_catalogue_id}", response_model=ThreatCatalogueRow, tags=["Threat Catalogue Admin"])
def update_threat_catalogue(body: ThreatCatalogueUpdate, request: Request, threat_catalogue_id: int = Path(ge=1),
                            principal: Principal = Depends(get_principal)):
    """Partial update. A rename re-embeds the row and returns the new job's id."""
    return _update("threat-catalogue", threat_catalogue_id, body, principal, request)


@router.delete("/threat-catalogue/{threat_catalogue_id}", response_model=ThreatCatalogueRow, tags=["Threat Catalogue Admin"])
def delete_threat_catalogue(request: Request, threat_catalogue_id: int = Path(ge=1),
                            principal: Principal = Depends(get_principal)):
    """Soft delete. Also drops the row's embedding so grounding stops matching it."""
    return _delete("threat-catalogue", threat_catalogue_id, principal, request)


@router.get("/threat-actors", response_model=list[ThreatActorRow], tags=["Threat Actors Admin"])
def list_threat_actors(limit: int = _LIMIT, offset: int = _OFFSET, include_deleted: bool = _DELETED,
                    _principal: Principal = Depends(get_principal)):
    """Threat actors."""
    return _list("threat-actors", limit, offset, include_deleted)


@router.post("/threat-actors", response_model=ThreatActorRow, status_code=201, tags=["Threat Actors Admin"])
def create_threat_actor(body: ThreatActorCreate, request: Request,
                        principal: Principal = Depends(get_principal)):
    """Create an actor. Actors are not embedded, so no refresh job is returned."""
    return _create("threat-actors", body, principal, request)


@router.patch("/threat-actors/{threat_actor_id}", response_model=ThreatActorRow, tags=["Threat Actors Admin"])
def update_threat_actor(body: ThreatActorUpdate, request: Request, threat_actor_id: int = Path(ge=1),
                        principal: Principal = Depends(get_principal)):
    """Partial update. Omitted fields keep their current value."""
    return _update("threat-actors", threat_actor_id, body, principal, request)


@router.delete("/threat-actors/{threat_actor_id}", response_model=ThreatActorRow, tags=["Threat Actors Admin"])
def delete_threat_actor(request: Request, threat_actor_id: int = Path(ge=1),
                        principal: Principal = Depends(get_principal)):
    """Soft delete (IsDeleted=1). Returns the deleted row so the caller can see the who/when."""
    return _delete("threat-actors", threat_actor_id, principal, request)


