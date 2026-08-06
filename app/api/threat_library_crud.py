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
from app.api.library_crud import (
    _DELETED, _LIMIT, _OFFSET, _RESOURCES, _audit, _create, _delete, _list, _row_out, _update,
)
from app.core.logging import get_logger
from app.db import dal
from app.db.engine import db_session

log = get_logger(__name__)
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


def _link_actor_names(type_id: int, names: list[str], user_id: str | None) -> None:
    """Admin-supplied actor names for a threat type: reuse the existing row when the name
    already exists (case-insensitive, via the unique index's collation), create when genuinely
    new — admin supply is the DELIBERATE way the actor vocabulary grows, unlike the AI
    promotion path, which is resolve-only. Idempotent per name (upsert + race-safe link), so
    calling it again with the same names — including via the PATCH repair path below — never
    duplicates a row or a link. Runs in its own transaction after the CRUD commit: a link
    failure must not roll back an already-created family."""
    with db_session() as sess:
        for name in dict.fromkeys(n.strip() for n in names if n and n.strip()):
            dal.link_type_actor(sess, type_id,
                                dal.upsert_threat_actor(sess, name, created_by=user_id))


def _link_actor_names_best_effort(type_id: int, names: list[str], user_id: str | None) -> None:
    """The family row is already COMMITTED when this runs, so a transient link failure must
    degrade, not 500 the request — a 500 here left an actor-less family behind with no repair
    route. Logs type_id + the names so the failure is operable; repair = PATCH the same
    actor_names (additive, idempotent)."""
    try:
        _link_actor_names(type_id, names, user_id)
    except Exception:
        log.warning("threat_type.actor_link_failed", type_id=type_id, actor_names=names,
                    note="family committed; re-send the names via PATCH /threat-types/{id} "
                        "to repair the links", exc_info=True)


def _threat_type_row(type_id: int) -> dict:
    """One family row shaped like the CRUD responses — for the actors-only PATCH, which has
    no column update to return a row from."""
    res = _RESOURCES["threat-types"]
    with db_session() as sess:
        return _row_out("threat-types", dal.get_library_row(sess, res["model"], res["pk"], type_id))


@router.post("/threat-types", response_model=ThreatTypeRow, status_code=201, tags=["Threat Types Admin"])
def create_threat_type(body: ThreatTypeCreate, request: Request,
                    principal: Principal = Depends(get_principal)):
    """Create a family, linking any supplied `actor_names` to it. Returns
    `embeddings_job_id` — poll it on `/embeddings/status/{job_id}` to know when the AI can
    match the new name."""
    row = _create("threat-types", body, principal, request)
    if body.actor_names:
        _link_actor_names_best_effort(row["threat_type_id"], body.actor_names, principal.user_id)
    return row


@router.patch("/threat-types/{threat_type_id}", response_model=ThreatTypeRow, tags=["Threat Types Admin"])
def update_threat_type(body: ThreatTypeUpdate, request: Request, threat_type_id: int = Path(ge=1),
                    principal: Principal = Depends(get_principal)):
    """Partial update. A rename re-embeds the row and returns the new job's id.
    `actor_names` links ADDITIVELY (idempotent) — the repair path for a create whose actor
    linking failed after the family committed; existing links are never removed here."""
    sent = body.model_dump(exclude_unset=True)
    actor_names = sent.pop("actor_names", None)
    if sent:  # _to_columns drops actor_names, so column updates behave exactly as before
        row = _update("threat-types", threat_type_id, body, principal, request)
    else:  # actors-only PATCH: nothing to update — fetch the row (404s on a missing id)
        row = _threat_type_row(threat_type_id)
    if actor_names:
        _link_actor_names(threat_type_id, actor_names, principal.user_id)
        # Audited on BOTH paths, and as its own action: linking actors mutates the shared
        # library, so it owes the same forensic trail every other CRUD mutation writes —
        # _update's "update" record names no actors, and the actors-only path calls no _update
        # at all, so without this a library change would land with nothing in the trail.
        _audit(request, "threat-types", "link-actors", threat_type_id, principal)
    return row


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


