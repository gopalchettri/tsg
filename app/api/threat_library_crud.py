"""Curator CRUD routes for the four threat-library master tables.

Thin route layer: every handler is a one-line delegation to app/api/library_crud.py, so the
shared behaviour (admin-key gate, CreatedBy/UpdatedBy stamping, 409 translation, embedding
refresh) cannot drift between the two libraries. Read that module for the semantics.

EVERY route below needs its own (METHOD, path) entry in app/api/route_audit.py — the app
refuses to boot otherwise.
"""
from __future__ import annotations

import json as _json  # noqa: E402 — scoped alias; the module has no other json use

from fastapi import APIRouter, Depends, Path, Request
from fastapi import Query as _Query  # noqa: E402
from sqlalchemy import insert as _sa_insert  # noqa: E402
from sqlalchemy import select as _sa_select
from sqlalchemy import update as _sa_update
from sqlalchemy.exc import IntegrityError as _IntegrityError  # noqa: E402

from app.api.admin import AdminValidationError  # noqa: E402
from app.api.deps import Principal, get_admin_principal, require_admin
from app.api.library_crud import (  # noqa: E402
    _DELETED,  # noqa: E402
    _LIMIT,
    _OFFSET,
    _RESOURCES,
    LibraryConflict,
    _audit,
    _create,
    _delete,
    _list,
    _require_parent,
    _row_out,
    _update,
)
from app.api.library_crud import _DELETED as _RULE_DELETED
from app.api.schemas import (  # noqa: E402
    ThreatActorCreate,
    ThreatActorRow,
    ThreatActorUpdate,
    ThreatCatalogueCreate,
    ThreatCatalogueRow,
    ThreatCatalogueUpdate,
    ThreatCategoryCreate,
    ThreatCategoryRow,
    ThreatCategoryUpdate,
    ThreatRuleCreate,
    ThreatRuleRow,
    ThreatRuleUpdate,
    ThreatTypeCreate,
    ThreatTypeRow,
    ThreatTypeUpdate,
)
from app.core.enums import ThreatRuleType  # noqa: E402
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m  # noqa: E402
from app.db.dal import NotFoundError, now  # noqa: E402
from app.db.engine import db_session
from app.pipeline.scoping import _RULE_KEY_FIELDS

log = get_logger(__name__)


router = APIRouter(
    prefix="/v1/tsg/threat-library",
    dependencies=[Depends(require_admin)],
)

@router.get("/threat-categories", response_model=list[ThreatCategoryRow], tags=["Threat Categories Admin"])
def list_threat_categories(limit: int = _LIMIT, offset: int = _OFFSET, include_deleted: bool = _DELETED,
                        _principal: Principal = Depends(get_admin_principal)):
    """STRIDE categories. Read this first — nothing else in the API returns row ids, so this is
    where the id each resource's PATCH/DELETE routes need comes from: `threat_category_id` here,
    and `threat_type_id`/`threat_catalogue_id`/`threat_actor_id` on the other three list routes
    below."""
    return _list("threat-categories", limit, offset, include_deleted)


@router.post("/threat-categories", response_model=ThreatCategoryRow, status_code=201, tags=["Threat Categories Admin"])
def create_threat_category(body: ThreatCategoryCreate, request: Request,
                        principal: Principal = Depends(get_admin_principal)):
    """Create a category. The id is caller-supplied — this table's PK is not IDENTITY."""
    return _create("threat-categories", body, principal, request)


@router.patch("/threat-categories/{threat_category_id}", response_model=ThreatCategoryRow, tags=["Threat Categories Admin"])
def update_threat_category(body: ThreatCategoryUpdate, request: Request, threat_category_id: int = Path(ge=1),
                        principal: Principal = Depends(get_admin_principal)):
    """Partial update. Omitted fields keep their current value."""
    return _update("threat-categories", threat_category_id, body, principal, request)


@router.delete("/threat-categories/{threat_category_id}", response_model=ThreatCategoryRow, tags=["Threat Categories Admin"])
def delete_threat_category(request: Request, threat_category_id: int = Path(ge=1),
                        principal: Principal = Depends(get_admin_principal)):
    """Soft delete (IsDeleted=1). Returns the deleted row so the caller can see the who/when."""
    return _delete("threat-categories", threat_category_id, principal, request)


@router.get("/threat-types", response_model=list[ThreatTypeRow], tags=["Threat Types Admin"])
def list_threat_types(limit: int = _LIMIT, offset: int = _OFFSET, include_deleted: bool = _DELETED,
                    _principal: Principal = Depends(get_admin_principal)):
    """Threat families."""
    return _list("threat-types", limit, offset, include_deleted)


def _link_actor_names(type_id: int, names: list[str], user_id: str | None) -> None:
    """Admin-supplied actor names for a threat type: reuse the existing row when the name
    already exists — by NORMALIZED IDENTITY first ('APT Nova' reuses an existing 'APT-Nova'
    instead of minting a punctuation twin; same rule as accept-time triage and approval),
    then case-insensitively via the unique index's collation — and create when genuinely
    new: admin supply is the DELIBERATE way the actor vocabulary grows. Idempotent per name
    (identity lookup + upsert + race-safe link), so calling it again with the same names —
    including via the PATCH repair path below — never duplicates a row or a link. Runs in
    its own transaction after the CRUD commit: a link failure must not roll back an
    already-created family."""
    from app.pipeline.accept_actors import resolve_actor_id_by_identity
    with db_session() as sess:
        for name in dict.fromkeys(n.strip() for n in names if n and n.strip()):
            actor_id = resolve_actor_id_by_identity(sess, name)
            if actor_id is None:
                actor_id = dal.upsert_threat_actor(sess, name, created_by=user_id)
            dal.link_type_actor(sess, type_id, actor_id)


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
                    principal: Principal = Depends(get_admin_principal)):
    """Create a family, linking any supplied `actor_names` to it. Returns
    `embeddings_job_id` — poll it on `/embeddings/status/{job_id}` to know when the AI can
    match the new name."""
    row = _create("threat-types", body, principal, request)
    if body.actor_names:
        _link_actor_names_best_effort(row["threat_type_id"], body.actor_names, principal.user_id)
    return row


@router.patch("/threat-types/{threat_type_id}", response_model=ThreatTypeRow, tags=["Threat Types Admin"])
def update_threat_type(body: ThreatTypeUpdate, request: Request, threat_type_id: int = Path(ge=1),
                    principal: Principal = Depends(get_admin_principal)):
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
                    principal: Principal = Depends(get_admin_principal)):
    """Soft delete. Also drops the row's embedding so grounding stops matching it."""
    return _delete("threat-types", threat_type_id, principal, request)


@router.get("/threat-catalogue", response_model=list[ThreatCatalogueRow], tags=["Threat Catalogue Admin"])
def list_threat_catalogue(limit: int = _LIMIT, offset: int = _OFFSET, include_deleted: bool = _DELETED,
                        _principal: Principal = Depends(get_admin_principal)):
    """Exact threats."""
    return _list("threat-catalogue", limit, offset, include_deleted)


@router.post("/threat-catalogue", response_model=ThreatCatalogueRow, status_code=201, tags=["Threat Catalogue Admin"])
def create_threat_catalogue(body: ThreatCatalogueCreate, request: Request,
                            principal: Principal = Depends(get_admin_principal)):
    """Create an exact threat under a family. 404s if the family doesn't exist."""
    return _create("threat-catalogue", body, principal, request)


@router.patch("/threat-catalogue/{threat_catalogue_id}", response_model=ThreatCatalogueRow, tags=["Threat Catalogue Admin"])
def update_threat_catalogue(body: ThreatCatalogueUpdate, request: Request, threat_catalogue_id: int = Path(ge=1),
                            principal: Principal = Depends(get_admin_principal)):
    """Partial update. A rename re-embeds the row and returns the new job's id."""
    return _update("threat-catalogue", threat_catalogue_id, body, principal, request)


@router.delete("/threat-catalogue/{threat_catalogue_id}", response_model=ThreatCatalogueRow, tags=["Threat Catalogue Admin"])
def delete_threat_catalogue(request: Request, threat_catalogue_id: int = Path(ge=1),
                            principal: Principal = Depends(get_admin_principal)):
    """Soft delete. Also drops the row's embedding so grounding stops matching it."""
    return _delete("threat-catalogue", threat_catalogue_id, principal, request)


@router.get("/threat-actors", response_model=list[ThreatActorRow], tags=["Threat Actors Admin"])
def list_threat_actors(limit: int = _LIMIT, offset: int = _OFFSET, include_deleted: bool = _DELETED,
                    _principal: Principal = Depends(get_admin_principal)):
    """Threat actors."""
    return _list("threat-actors", limit, offset, include_deleted)


@router.post("/threat-actors", response_model=ThreatActorRow, status_code=201, tags=["Threat Actors Admin"])
def create_threat_actor(body: ThreatActorCreate, request: Request,
                        principal: Principal = Depends(get_admin_principal)):
    """Create an actor. Actors are not embedded, so no refresh job is returned."""
    return _create("threat-actors", body, principal, request)


@router.patch("/threat-actors/{threat_actor_id}", response_model=ThreatActorRow, tags=["Threat Actors Admin"])
def update_threat_actor(body: ThreatActorUpdate, request: Request, threat_actor_id: int = Path(ge=1),
                        principal: Principal = Depends(get_admin_principal)):
    """Partial update. Omitted fields keep their current value."""
    return _update("threat-actors", threat_actor_id, body, principal, request)


@router.delete("/threat-actors/{threat_actor_id}", response_model=ThreatActorRow, tags=["Threat Actors Admin"])
def delete_threat_actor(request: Request, threat_actor_id: int = Path(ge=1),
                        principal: Principal = Depends(get_admin_principal)):
    """Soft delete (IsDeleted=1). Returns the deleted row so the caller can see the who/when."""
    return _delete("threat-actors", threat_actor_id, principal, request)


# --- Scoping rules (Config_Threat_Rule) ----------------------------------------------------
# Not routed through library_crud's _RESOURCES registry: this table's audit columns are
# CreateDate/UpdateDate (not CreatedAt/UpdatedAt), it backs no embedding group, and its natural
# key is a QUADRUPLE behind a filtered unique index — three framework assumptions broken at
# once, so a small dedicated set of routes is less machinery than teaching the framework three
# exceptions. Until these routes existed, changing a scoping gate meant SQL against production.

def _validate_rule_fields(rule_type: str, rule_key: str, weight: float | None) -> None:
    """The three ways a rule row can be VALID SQL and still broken in production, all rejected
    at the door. scoping._apply_rules deliberately no-ops (with a log) on an unknown key or
    family — safe at runtime, but it means a typo here would create a rule that silently never
    fires; check_dead_threat_rules exists because that already happened once."""
    if rule_type not in {str(v) for v in ThreatRuleType}:
        raise AdminValidationError(
            f"rule_type {rule_type!r} is not one of {sorted(str(v) for v in ThreatRuleType)}")
    # lazy: keep api->pipeline import cold
    if rule_key not in _RULE_KEY_FIELDS:
        raise AdminValidationError(
            f"rule_key {rule_key!r} is not resolvable by scoping (allowlist: "
            f"{sorted(_RULE_KEY_FIELDS)}) — the rule would exist but never fire")
    if rule_type == str(ThreatRuleType.tech_gate) and weight is not None:
        raise AdminValidationError(
            "tech_gate rules take no weight — a gate is a hard include/exclude (delta 0.0); "
            "use relevance_flag/relevance_context_value for score weights")


def _rule_row_out(r) -> dict:
    """Row -> response dict. `weight` is unpacked from Metadata the same tolerant way
    scoping._rule_weight reads it — a legacy malformed blob reports null, never 500s the list."""
    weight = None
    if r.Metadata:
        try:
            w = _json.loads(r.Metadata).get("weight")
            weight = float(w) if w is not None and not isinstance(w, bool) else None
        except (ValueError, TypeError, AttributeError):
            weight = None
    return {"threat_rule_id": r.ThreatRuleID, "rule_type": r.RuleType,
            "threat_type_id": r.ThreatTypeID, "rule_key": r.RuleKey, "rule_value": r.RuleValue,
            "weight": weight, "is_active": bool(r.IsActive), "is_deleted": bool(r.IsDeleted),
            "created_at": r.CreateDate, "created_by": r.CreatedBy,
            "updated_at": r.UpdateDate, "updated_by": r.UpdatedBy}


def _get_rule(sess, rule_id: int):
    row = sess.execute(_sa_select(m.Config_Threat_Rule).where(
        m.Config_Threat_Rule.ThreatRuleID == rule_id)).scalar_one_or_none()
    if row is None:
        raise NotFoundError(f"Config_Threat_Rule {rule_id} not found")
    return row


@router.get("/threat-rules", response_model=list[ThreatRuleRow], tags=["Threat Rules Admin"])
def list_threat_rules(limit: int = _LIMIT, offset: int = _OFFSET,
                    include_deleted: bool = _RULE_DELETED,
                    threat_type_id: int | None = _Query(default=None, ge=1,
                                                        description="Only this family's rules."),
                    _principal: Principal = Depends(get_admin_principal)):
    """Scoping rules. tech_gate = hard include/exclude by asset context; relevance_* = score
    weights. A rule whose parent Threat_Type is soft-deleted still lists here but no longer
    fires (dal.active_threat_rules re-asserts the parent)."""
    with db_session() as sess:
        stmt = _sa_select(m.Config_Threat_Rule)
        if not include_deleted:
            stmt = stmt.where(m.Config_Threat_Rule.IsDeleted == False)  # noqa: E712
        if threat_type_id is not None:
            stmt = stmt.where(m.Config_Threat_Rule.ThreatTypeID == threat_type_id)
        rows = sess.execute(stmt.order_by(m.Config_Threat_Rule.ThreatRuleID)
                            .limit(limit).offset(offset)).scalars().all()
        return [_rule_row_out(r) for r in rows]


@router.post("/threat-rules", response_model=ThreatRuleRow, status_code=201, tags=["Threat Rules Admin"])
def create_threat_rule(body: ThreatRuleCreate, request: Request,
                    principal: Principal = Depends(get_admin_principal)):
    """Create a scoping rule. 404s if the family doesn't exist; 409s on the live
    (threat_type_id, rule_type, rule_key, rule_value) natural key."""
    _validate_rule_fields(body.rule_type, body.rule_key, body.weight)
    with db_session() as sess:
        _require_parent(sess, m.Threat_Type, m.Threat_Type.ThreatTypeID,
                        body.threat_type_id, "Threat_Type")
        try:
            res = sess.execute(_sa_insert(m.Config_Threat_Rule).values(
                RuleType=body.rule_type, ThreatTypeID=body.threat_type_id,
                RuleKey=body.rule_key, RuleValue=body.rule_value,
                Metadata=_json.dumps({"weight": body.weight}) if body.weight is not None else None,
                IsActive=body.is_active, IsDeleted=False,
                CreateDate=now(), CreatedBy=principal.user_id))
            sess.commit()
        except _IntegrityError:
            sess.rollback()
            raise LibraryConflict(
                "a live Config_Threat_Rule row already matches this "
                "(threat_type_id, rule_type, rule_key, rule_value) natural key") from None
        new_id = res.inserted_primary_key[0]
        out = _rule_row_out(_get_rule(sess, new_id))
    _audit(request, "threat-rules", "create", new_id, principal)
    return out


@router.patch("/threat-rules/{threat_rule_id}", response_model=ThreatRuleRow, tags=["Threat Rules Admin"])
def update_threat_rule(body: ThreatRuleUpdate, request: Request, threat_rule_id: int = Path(ge=1),
                    principal: Principal = Depends(get_admin_principal)):
    """Partial update of rule_value / weight / is_active. rule_type, rule_key and
    threat_type_id are immutable — retire and recreate instead, so the audit trail stays honest.
    An explicit `"weight": null` clears the override back to the configured default."""
    sent = body.model_dump(exclude_unset=True)
    if not sent:
        raise AdminValidationError("empty update body — send at least one field to change")
    with db_session() as sess:
        row = _get_rule(sess, threat_rule_id)
        if row.IsDeleted:
            raise NotFoundError(f"Config_Threat_Rule {threat_rule_id} is deleted")
        if "weight" in sent and sent["weight"] is not None and row.RuleType == str(ThreatRuleType.tech_gate):
            raise AdminValidationError("tech_gate rules take no weight — see POST /threat-rules")
        values: dict = {"UpdateDate": now(), "UpdatedBy": principal.user_id}
        if "rule_value" in sent:
            values["RuleValue"] = sent["rule_value"]
        if "weight" in sent:
            values["Metadata"] = (_json.dumps({"weight": sent["weight"]})
                                if sent["weight"] is not None else None)
        if "is_active" in sent:
            values["IsActive"] = sent["is_active"]
        try:
            sess.execute(_sa_update(m.Config_Threat_Rule)
                        .where(m.Config_Threat_Rule.ThreatRuleID == threat_rule_id)
                        .values(**values))
            sess.commit()
        except _IntegrityError:
            sess.rollback()
            raise LibraryConflict(
                "this change collides with a live Config_Threat_Rule natural key "
                "(re-enabling a rule whose quadruple was recreated?)") from None
        out = _rule_row_out(_get_rule(sess, threat_rule_id))
    _audit(request, "threat-rules", "update", threat_rule_id, principal)
    return out


@router.delete("/threat-rules/{threat_rule_id}", response_model=ThreatRuleRow, tags=["Threat Rules Admin"])
def delete_threat_rule(request: Request, threat_rule_id: int = Path(ge=1),
                    principal: Principal = Depends(get_admin_principal)):
    """Soft delete (IsDeleted=1) — same convention as every other library table: ids may be
    referenced by history, so nothing is ever hard-deleted. Returns the row with its who/when."""
    with db_session() as sess:
        row = _get_rule(sess, threat_rule_id)
        if not row.IsDeleted:
            sess.execute(_sa_update(m.Config_Threat_Rule)
                        .where(m.Config_Threat_Rule.ThreatRuleID == threat_rule_id)
                        .values(IsDeleted=True, UpdateDate=now(), UpdatedBy=principal.user_id))
            sess.commit()
        out = _rule_row_out(_get_rule(sess, threat_rule_id))
    _audit(request, "threat-rules", "delete", threat_rule_id, principal)
    return out


