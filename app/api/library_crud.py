"""Shared machinery for the reference-library CRUD routers.

The routes live in threat_library_crud.py and control_library_crud.py; everything here is what
they must not each reinvent — the per-table registry, audit/provenance stamping, conflict
translation and embedding refresh. Six master tables behind two routers:

  /v1/tsg/threat-library   Threat_Category, Threat_Type, Threat_Catalogue, Threat_Actor
  /v1/tsg/control-library  Control_Library, Control_Standard (+ their many-to-many map)

Two checks, same split as app/api/admin.py: the router-level `X-Admin-Key` is the AUTHORIZATION
gate — shared cross-tenant library data, so not entity-scoped — and the per-route `principal`
supplies the identity that lands in CreatedBy/UpdatedBy.

Three behaviours worth knowing before editing this file:

* DELETE is a SOFT delete (IsDeleted=1 + the Updated* stamp). Threat_Type/Threat_Catalogue ids
are referenced by Identified_Threat rows in completed sessions, so a hard delete would orphan
historical scenarios. A delete IS an update — hence UpdatedBy, and no DeletedBy column.
* The natural-key indexes are FILTERED on `IsActive = 1 AND IsDeleted = 0` (TSG_Core.sql
section 4) and cover a TRIPLE, not just a name. So changing only the category or sector can
still collide; a soft-deleted name is free to reuse; and re-activating a row can collide. All
three surface as 409 rather than a 500 on IntegrityError.
* Creating, renaming or deleting a Threat_Type/Threat_Catalogue/Control_Library row makes the
stored embedding index stale, which would silently keep grounding matching text that no longer
exists. Each write dispatches the embeddings job AFTER its transaction commits. What counts as
"the text" differs per table and is NOT always the name: see `_embed_text`.
"""
from __future__ import annotations

from typing import Any

from fastapi import Query, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.api.admin import AdminValidationError
from app.api.admin_jobs import FAMILY_EMBEDDINGS, mark_admin_job
from app.api.deps import Principal
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.db.engine import db_session
from app.pipeline.celery_app import admin_embedding_action_task

log = get_logger(__name__)

#: Provenance stamped on rows born through this API — distinct from the seed and import tags.
#: Set server-side and never read from the body: provenance a caller can forge records nothing.
MANUAL_SOURCE = "manual"

_MAX_PAGE = 500


class LibraryConflict(Exception):
    """A write would violate a master table's natural-key index → 409.

    HTTP-shaped, so it lives here rather than in dal.py: the DAL lets IntegrityError escape
    because only the caller knows which key was violated and how to describe it."""

    def __init__(self, message: str, existing_id: int | None = None):
        super().__init__(message)
        self.existing_id = existing_id


# Per-table wiring: model, PK column + its API field name, embedding group, and the name column
# used to describe a collision. One table rather than four near-identical handler sets — the
# verbs are identical and only these facts differ. (No response class: each route declares its
# own response_model, so a copy here would be a second place to forget to update.)
_RESOURCES: dict[str, dict[str, Any]] = {
    "threat-categories": {
        "model": m.Threat_Category, "pk": m.Threat_Category.ThreatCategoryID,
        "pk_field": "threat_category_id", "group": None,
        "name_col": m.Threat_Category.ThreatCategoryName,
    },
    "threat-types": {
        "model": m.Threat_Type, "pk": m.Threat_Type.ThreatTypeID,
        "pk_field": "threat_type_id", "group": "threat_type",
        "name_col": m.Threat_Type.ThreatTypeName,
    },
    "threat-catalogue": {
        "model": m.Threat_Catalogue, "pk": m.Threat_Catalogue.ThreatCatalogueID,
        "pk_field": "threat_catalogue_id", "group": "threat_catalogue",
        "name_col": m.Threat_Catalogue.ThreatName,
    },
    "threat-actors": {
        "model": m.Threat_Actor, "pk": m.Threat_Actor.ThreatActorID,
        # group was None while actors had no embeddings; the nearest-match fallback
        # (library-first actors) now searches threat_actor vectors, so a rename must
        # re-embed exactly like types/catalogue rows do.
        "pk_field": "threat_actor_id", "group": "threat_actor",
        "name_col": m.Threat_Actor.ThreatActorName,
    },
    "controls": {
        "model": m.Control_Library, "pk": m.Control_Library.ControlLibraryID,
        "pk_field": "control_library_id", "group": "control_library",
        # The natural key is the CODE, not the name — two controls may share a name.
        "name_col": m.Control_Library.ControlCode,
    },
    "standards": {
        "model": m.Control_Standard, "pk": m.Control_Standard.StandardID,
        "pk_field": "standard_id", "group": None,
        "name_col": m.Control_Standard.StandardName,
    },
}


def _embed_text(resource: str, row) -> str | None:
    """The exact string embeddings.py stores a vector under for this row, or None when the table
    backs no embedding group.

    MUST stay byte-identical to embeddings._GROUPS' text expression for the same group: the cache
    key is sha256(model|group|kind|text), and `delete` resolves names against `_active_names`. A
    drift of one character means a delete quietly removes nothing and a stale vector keeps
    matching, reported as SUCCESS.

    Controls are NOT keyed on their name — the text is `ControlName + ": " + description — so
    editing only the DESCRIPTION still invalidates the vector."""
    group = _RESOURCES[resource]["group"]
    if not group:
        return None
    if group == "control_library":
        return f"{row.ControlName}: {row.ControlDescription or ''}"
    return getattr(row, _RESOURCES[resource]["name_col"].key)

# API field name -> DB column, per resource. Spelled out rather than derived by a casing rule:
# threat_type_id -> ThreatTypeID is regular, but SecurityObjective and IsCapable are not, and a
# convention with exceptions is worse than a table you can read.
_FIELD_MAP: dict[str, dict[str, str]] = {
    "threat-categories": {
        "threat_category_name": "ThreatCategoryName", "threat_category_code": "ThreatCategoryCode",
        "security_objective": "SecurityObjective", "is_active": "IsActive",
    },
    "threat-types": {
        "threat_type_name": "ThreatTypeName", "description": "Description",
        "sector_id": "SectorID", "threat_category_id": "ThreatCategoryID", "is_active": "IsActive",
    },
    "threat-catalogue": {
        "threat_type_id": "ThreatTypeID", "threat_name": "ThreatName",
        "description": "Description", "sector_id": "SectorID", "is_active": "IsActive",
    },
    "threat-actors": {
        "threat_actor_name": "ThreatActorName", "is_capable": "IsCapable", "is_active": "IsActive",
    },
    "controls": {
        "control_code": "ControlCode", "itot": "ITOT", "domain": "Domain",
        "control_name": "ControlName", "control_description": "ControlDescription",
        "sample_evidence": "SampleEvidence", "is_active": "IsActive",
    },
    "standards": {
        "standard_name": "StandardName", "is_active": "IsActive",
    },
}


def _to_columns(resource: str, body) -> dict:
    """Body -> DB column values, dropping fields the caller never sent.

    `exclude_unset` is load-bearing on the update path: without it every optional field would
    arrive as None and a PATCH of one field would null all the others."""
    fields = dict(_FIELD_MAP[resource])
    res = _RESOURCES[resource]
    fields[res["pk_field"]] = res["pk"].key  # only ThreatCategoryCreate actually sends a PK
    return {fields[k]: v for k, v in body.model_dump(exclude_unset=True).items() if k in fields}


def _row_out(resource: str, row) -> dict:
    """DB row -> response dict, including the audit block every table shares."""
    res = _RESOURCES[resource]
    out = {api: getattr(row, col) for api, col in _FIELD_MAP[resource].items()}
    out[res["pk_field"]] = getattr(row, res["pk"].key)
    out.update(
        is_active=bool(row.IsActive), is_deleted=bool(row.IsDeleted),
        source=getattr(row, "Source", None), created_at=row.CreatedAt,
        created_by=row.CreatedBy, updated_at=row.UpdatedAt, updated_by=row.UpdatedBy,
    )
    return out


def _conflict(sess, resource: str, name: str | None, pk_value=None) -> LibraryConflict:
    """Turn an IntegrityError into a 409 naming the row the caller collided with.

    Two DIFFERENT constraints reach here, and calling both "natural key" sends the caller to the
    wrong field. Threat_Category's PK is caller-supplied (not IDENTITY), so re-sending an existing
    id collides on PK_Threat_Category with a perfectly free name — reported as a name clash, that
    is flatly false. Check the name first (the common case), then the pk.

    Best-effort by design: the name lookup covers one column while the real index covers a triple
    (UX_ThreatType_NaturalKey is name+category+sector, UX_ThreatCatalogue_NaturalKey is
    type+name+sector), so a category/sector-only clash lands on the generic message. A 409 without
    an id beats a 500 — but a 409 with the WRONG id is worse than either, so when the name matches
    several live rows we report no id rather than whichever one the engine happened to return
    first. Only a unique match can be the row the caller actually collided with."""
    res = _RESOURCES[resource]
    table = res["model"].__tablename__
    if name is not None:
        hits = sess.execute(
            select(res["pk"]).where(res["name_col"] == name,
                                    res["model"].IsActive == True,
                                    res["model"].IsDeleted == False)
            .limit(2)                       # 2 is enough to tell "unique" from "ambiguous"
        ).scalars().all()
        if hits:
            return LibraryConflict(f"a live {table} row already matches this natural key",
                                hits[0] if len(hits) == 1 else None)
    if pk_value is not None and sess.execute(
            select(res["pk"]).where(res["pk"] == pk_value)).scalar() is not None:
        # Counts soft-deleted rows on purpose: the id is occupied either way, so "choose another
        # id" is the only useful advice — unlike the natural key, which a soft delete DOES free.
        return LibraryConflict(f"a {table} row with this id already exists", pk_value)
    return LibraryConflict(f"a live {table} row already matches this natural key", None)


def _refresh_embeddings(resource: str, action: str, names: list[str | None]) -> str | None:
    """Queue the embeddings refresh for one changed row, AFTER its transaction committed.

    A dispatch failure must never fail an already-committed write — the row IS saved, and a 5xx
    would invite a duplicate retry — so it degrades to a logged warning and a null job id.

    strict=False is load-bearing on the delete path: by the time the worker runs, the name
    belongs to a row that has been renamed away or soft-deleted, so it is no longer an ACTIVE
    master row and the strict check would raise UnknownEmbeddingNames — making a perfectly good
    edit report FAILURE. These names are read off the row itself and cannot be mistyped; the
    typo check exists for a human typing into the admin API."""
    group = _RESOURCES[resource]["group"]
    clean = [n for n in names if n]  # None = "table backs no embedding group" (_embed_text)
    if not group or not clean:
        return None
    try:
        job = admin_embedding_action_task.delay(action, group, clean, False)
        mark_admin_job(job.id, FAMILY_EMBEDDINGS)  # without the marker the id 404s on /status
        return job.id
    except Exception:
        log.warning("library_crud.embeddings_dispatch_failed", resource=resource,
                    action=action, names=clean, exc_info=True)
        return None


def _audit(request: Request, resource: str, action: str, row_id: int, principal: Principal) -> None:
    """Admin action trail, written AFTER the change lands (admin.py's ordering rationale)."""
    log.warning("admin.library_crud", resource=resource, action=action, row_id=row_id,
                user_id=principal.user_id,
                source_ip=request.client.host if request.client else None)


def _require_parent(sess, model, pk_col, value: int | None, label: str) -> None:
    """Reject a parent id naming no live row.

    These columns carry no DB foreign key, so nothing stops a caller inventing one — and an
    orphaned catalogue row is invisible until grounding silently fails to resolve its family."""
    if value is None:
        return
    found = sess.execute(
        select(pk_col).where(pk_col == value, model.IsActive == True,
                            model.IsDeleted == False)
    ).scalar()
    if found is None:
        raise dal.NotFoundError(f"{label} {value} not found")


def _check_parents(sess, resource: str, values: dict) -> None:
    """Whichever parent id this resource has, if the caller supplied one."""
    if resource == "threat-types" and "ThreatCategoryID" in values:
        _require_parent(sess, m.Threat_Category, m.Threat_Category.ThreatCategoryID,
                        values["ThreatCategoryID"], "Threat_Category")
    if resource == "threat-catalogue" and "ThreatTypeID" in values:
        _require_parent(sess, m.Threat_Type, m.Threat_Type.ThreatTypeID,
                        values["ThreatTypeID"], "Threat_Type")


def _list(resource: str, limit: int, offset: int, include_deleted: bool) -> list[dict]:
    res = _RESOURCES[resource]
    with db_session() as sess:
        stmt = select(res["model"])
        if not include_deleted:
            stmt = stmt.where(res["model"].IsDeleted == False)
        rows = sess.execute(stmt.order_by(res["pk"]).limit(limit).offset(offset)).scalars().all()
        return [_row_out(resource, r) for r in rows]


def _create(resource: str, body, principal: Principal, request: Request) -> dict:
    res = _RESOURCES[resource]
    values = _to_columns(resource, body)
    name = values.get(res["name_col"].key)
    with db_session() as sess:
        _check_parents(sess, resource, values)  # 404 before anything is written
        if "Source" in res["model"].__table__.columns:
            values["Source"] = MANUAL_SOURCE
        try:
            new_id = dal.create_library_row(sess, res["model"], values, principal.user_id)
            sess.commit()
        except IntegrityError:
            sess.rollback()
            # only _create can supply a PK — the Update schemas carry none
            raise _conflict(sess, resource, name, values.get(res["pk"].key)) from None
        orm = dal.get_library_row(sess, res["model"], res["pk"], new_id)
        row = _row_out(resource, orm)
        text = _embed_text(resource, orm)
    # Strictly after the session closes (commit done): a job dispatched inside the block could
    # read a snapshot without the new row and embed nothing.
    row["embeddings_job_id"] = _refresh_embeddings(resource, "create", [text])
    _audit(request, resource, "create", new_id, principal)
    return row


def _update(resource: str, row_id: int, body, principal: Principal, request: Request) -> dict:
    res = _RESOURCES[resource]
    values = _to_columns(resource, body)
    if not values:
        raise AdminValidationError("empty update body — send at least one field to change")
    name_col = res["name_col"].key
    with db_session() as sess:
        _check_parents(sess, resource, values)
        # Read as a plain string BEFORE the write — the ORM object is expired by the commit.
        old_text = _embed_text(resource, dal.get_library_row(sess, res["model"], res["pk"], row_id))
        try:
            dal.update_library_row(sess, res["model"], res["pk"], row_id, values, principal.user_id)
            sess.commit()
        except IntegrityError:
            sess.rollback()
            raise _conflict(sess, resource, values.get(name_col)) from None
        orm = dal.get_library_row(sess, res["model"], res["pk"], row_id)
        row = _row_out(resource, orm)
        new_text = _embed_text(resource, orm)
    job_id = None
    # Compare the EMBEDDED TEXT, not the name: for a control that text includes the description,
    # so a description-only edit must still re-embed (and a name-only comparison would miss it).
    if new_text and new_text != old_text:
        # Delete-then-create: 'create' alone would add the new vector and leave the old text
        # still matchable by grounding.
        _refresh_embeddings(resource, "delete", [old_text])
        job_id = _refresh_embeddings(resource, "create", [new_text])
    row["embeddings_job_id"] = job_id
    _audit(request, resource, "update", row_id, principal)
    return row


def _delete(resource: str, row_id: int, principal: Principal, request: Request) -> dict:
    res = _RESOURCES[resource]
    with db_session() as sess:
        text = _embed_text(resource, dal.get_library_row(sess, res["model"], res["pk"], row_id))
        dal.soft_delete_library_row(sess, res["model"], res["pk"], row_id, principal.user_id)
        sess.commit()
        # include_deleted: the row we just hid is exactly what the caller needs back, so they
        # can see the who/when stamp the delete wrote.
        out = _row_out(resource, dal.get_library_row(sess, res["model"], res["pk"], row_id,
                                                    include_deleted=True))
    out["embeddings_job_id"] = _refresh_embeddings(resource, "delete", [text])
    _audit(request, resource, "delete", row_id, principal)
    return out




# Paging knobs shared by every list route in both routers.
_LIMIT = Query(default=100, ge=1, le=_MAX_PAGE, description="Page size.")
_OFFSET = Query(default=0, ge=0, description="Rows to skip.")
_DELETED = Query(default=False, description="Include soft-deleted rows.")
