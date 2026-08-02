"""Curator CRUD routes for the control library (controls, standards, and their link).

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
from sqlalchemy import delete, insert, select

from app.api.library_crud import _audit
from app.api.schemas import (
    ControlCreate, ControlRow, ControlStandardCreate, ControlStandardRow,
    ControlStandardsResponse, ControlStandardUpdate, ControlUpdate,
)
from app.db import dal
from app.db import models as m
from app.db.engine import db_session
from sqlalchemy.exc import IntegrityError

router = APIRouter(
    prefix="/v1/tsg/control-library",
    dependencies=[Depends(require_admin)],
)

# ---------------------------------------------------------------------------
# Control library. Same four verbs, plus two routes for the many-to-many link that fills
# `standards[]` on a scenario's mapped controls — without them a hand-created control would
# report an empty standards list forever.
# ---------------------------------------------------------------------------
@router.get("/standards", response_model=list[ControlStandardRow], tags=["Standards Admin"])
def list_standards(limit: int = _LIMIT, offset: int = _OFFSET, include_deleted: bool = _DELETED,
                _principal: Principal = Depends(get_principal)):
    """Named standards (ISO, NIST, DESC ISR, ...). Start here for the `standard_id` the link
    routes need."""
    return _list("standards", limit, offset, include_deleted)


@router.post("/standards", response_model=ControlStandardRow, status_code=201, tags=["Standards Admin"])
def create_standard(body: ControlStandardCreate, request: Request,
                    principal: Principal = Depends(get_principal)):
    """Create a standard. Standards are not embedded, so no refresh job is returned."""
    return _create("standards", body, principal, request)


@router.patch("/standards/{standard_id}", response_model=ControlStandardRow, tags=["Standards Admin"])
def update_standard(body: ControlStandardUpdate, request: Request, standard_id: int = Path(ge=1),
                    principal: Principal = Depends(get_principal)):
    """Partial update. Omitted fields keep their current value."""
    return _update("standards", standard_id, body, principal, request)


@router.delete("/standards/{standard_id}", response_model=ControlStandardRow, tags=["Standards Admin"])
def delete_standard(request: Request, standard_id: int = Path(ge=1),
                    principal: Principal = Depends(get_principal)):
    """Soft delete. Existing control-to-standard links are left in place; the standard simply
    stops being reported, so no scenario loses a control over it."""
    return _delete("standards", standard_id, principal, request)


@router.get("/controls", response_model=list[ControlRow], tags=["Controls Admin"])
def list_controls(limit: int = _LIMIT, offset: int = _OFFSET, include_deleted: bool = _DELETED,
                _principal: Principal = Depends(get_principal)):
    """The control library — 1,288 seeded rows plus anything curated here. Each row's
    `control_library_id` is the value the link routes' `{control_id}` (and `{control_id}` on
    the update/delete routes) expects — the field name and the URL segment name differ on
    purpose, only the URL was renamed for readability."""
    return _list("controls", limit, offset, include_deleted)


@router.post("/controls", response_model=ControlRow, status_code=201, tags=["Controls Admin"])
def create_control(body: ControlCreate, request: Request,
                principal: Principal = Depends(get_principal)):
    """Create a control. Returns `embeddings_job_id` — until it completes the new control cannot
    be matched to a scenario. Link its standards next, or `standards[]` stays empty."""
    return _create("controls", body, principal, request)


@router.patch("/controls/{control_id}", response_model=ControlRow, tags=["Controls Admin"])
def update_control(body: ControlUpdate, request: Request, control_id: int = Path(ge=1),
                principal: Principal = Depends(get_principal)):
    """Partial update. Changing `control_name` OR `control_description` re-embeds the row — both
    are part of the text grounding matches against."""
    return _update("controls", control_id, body, principal, request)


@router.delete("/controls/{control_id}", response_model=ControlRow, tags=["Controls Admin"])
def delete_control(request: Request, control_id: int = Path(ge=1),
                principal: Principal = Depends(get_principal)):
    """Soft delete. Also drops the control's embedding so it stops being mapped to scenarios.

    Threat_Scenario_Control_Map rows that already reference it are untouched, but the results
    endpoint filters on IsActive/IsDeleted, so it disappears from those payloads too."""
    return _delete("controls", control_id, principal, request)


def _standards_of(sess, control_id: int) -> ControlStandardsResponse:
    """The control's current links, ordered by name — the same list sessions.py reports."""
    rows = sess.execute(
        select(m.Control_Library_Standard_Map.StandardID, m.Control_Standard.StandardName)
        .join(m.Control_Standard,
            m.Control_Standard.StandardID == m.Control_Library_Standard_Map.StandardID)
        .where(m.Control_Library_Standard_Map.ControlLibraryID == control_id,
            m.Control_Standard.IsActive == True,  # noqa: E712
            m.Control_Standard.IsDeleted == False)  # noqa: E712
        .order_by(m.Control_Standard.StandardName)
    ).all()
    return ControlStandardsResponse(control_library_id=control_id,
                                    standard_ids=[r[0] for r in rows],
                                    standards=[r[1] for r in rows])


@router.post("/controls/{control_id}/standards/{standard_id}",
                    response_model=ControlStandardsResponse, status_code=201, tags=["Controls Admin"])
def attach_standard(request: Request, control_id: int = Path(ge=1), standard_id: int = Path(ge=1),
                    principal: Principal = Depends(get_principal)):
    """Link a control to a standard. Idempotent: re-linking an existing pair returns 201 with the
    unchanged list rather than 409 — the map's composite PK already guarantees one row per pair,
    and a client replaying a request should not have to tell the two apart."""
    with db_session() as sess:
        dal.get_library_row(sess, m.Control_Library, m.Control_Library.ControlLibraryID, control_id)
        dal.get_library_row(sess, m.Control_Standard, m.Control_Standard.StandardID, standard_id)
        # Insert-and-catch, not check-then-insert: the composite PK is the only thing that can
        # decide this race, and a pre-SELECT would leave a window where two concurrent identical
        # attaches both pass the check and the loser gets a PK violation — a 500 on a route
        # whose whole contract is idempotency. begin_nested so the failure rolls back only this
        # statement, matching dal's upsert_* pattern.
        try:
            with sess.begin_nested():
                dal.execute_dml(sess, insert(m.Control_Library_Standard_Map).values(
                    ControlLibraryID=control_id, StandardID=standard_id, CreatedAt=dal.now()))
            sess.commit()
        except IntegrityError:
            sess.rollback()  # already linked — the desired end state either way
        out = _standards_of(sess, control_id)
    # The map carries no audit columns (it is a pure link), so the trail lives in the log alone.
    _audit(request, "controls", f"attach_standard:{standard_id}", control_id, principal)
    return out


@router.delete("/controls/{control_id}/standards/{standard_id}",
                    response_model=ControlStandardsResponse, tags=["Controls Admin"])
def detach_standard(request: Request, control_id: int = Path(ge=1), standard_id: int = Path(ge=1),
                    principal: Principal = Depends(get_principal)):
    """Unlink a control from a standard — a HARD delete, unlike every other DELETE here. The map
    is a pure link: it has no audit columns to soft-delete into and nothing references it, so
    there is no history to preserve. 404s when the pair was not linked, so a caller can tell
    "removed it" apart from "there was nothing to remove"."""
    with db_session() as sess:
        dal.get_library_row(sess, m.Control_Library, m.Control_Library.ControlLibraryID, control_id)
        res = dal.execute_dml(sess, delete(m.Control_Library_Standard_Map).where(
            m.Control_Library_Standard_Map.ControlLibraryID == control_id,
            m.Control_Library_Standard_Map.StandardID == standard_id))
        if not res.rowcount:
            raise dal.NotFoundError(f"control {control_id} is not linked to standard {standard_id}")
        sess.commit()
        out = _standards_of(sess, control_id)
    _audit(request, "controls", f"detach_standard:{standard_id}", control_id, principal)
    return out
