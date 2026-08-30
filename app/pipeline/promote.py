"""Promote ONE accepted threat scenario's threat data into the shared library.

The ONLY write path into the library (accept-time auto-promotion was removed 2026-08): anyone
holding session_id + scenario_id may call it, the scenario must be ACCEPTED, and every promotion
is recorded in Scenario_Audit — who, when, and the per-item outcome.

This module is a **pure writer**. It performs no matching, no nearest-match search and no
discovery: every "is this the same as something we already have?" question was answered during
generation (grounding.find_threat_in_library for the type/threat/category, the type-actor map
for the actors), and every answer was persisted as an id on Identified_Threat. Here an id that
is present is used; an id that is absent means generation already searched and found nothing,
so the row is genuinely new.

What a NEW threat writes, in one transaction:
    Threat_Type                    (if the type itself is new — name-only dedup)
    Threat_Catalogue               (Description = the AI's threat description; name-only
                                    natural key, app-owned normalized-name dedup first)
    Threat_Catalogue_Category_Map  (the resolved category, when known)
    ThreatType_ThreatActor_Map     (the threat's stored actor ids — linked per TYPE, the
                                    model this library uses for actors)
An EXISTING catalogue threat is returned by id and nothing else is touched — curation stays
with the curators. Controls are REPORTED from the scenario's own mapping, never written to any
master table (the catalogue model has no threat→control curation).
"""
from __future__ import annotations

import json
from typing import Any, NamedTuple

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.enums import ActorType, AuditEventType, ScenarioDecisionReason, ScenarioStatus
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.db.dal import NotFoundError, guid
from app.pipeline import grounding
from app.pipeline.accept import AcceptConflict
from app.pipeline.tasks import asset_agnostic_name

log = get_logger(__name__)

# Response statuses the UI keys off. `inserted` means a NEW master row exists because of this
# call; `existing` means one was already there and was reused; `failed` carries a reason.
INSERTED, EXISTING, FAILED = "inserted", "existing", "failed"


class PromotionResult(NamedTuple):
    threat_type: dict[str, Any]
    threat: dict[str, Any] | None
    threat_actors: list[dict[str, Any]]
    controls: list[dict[str, Any]]
    controls_mapped: bool
    created_count: int
    success: bool


def _load_scenario_and_threat(sess: Session, session_id: str, scenario_id: str) -> tuple[Any, Any]:
    """The accepted scenario and the Identified_Threat behind it, or raise.

    Both ids must name the SAME row — passing another session's scenario_id must 404, not silently
    promote a scenario the caller never named.
    """
    out = sess.execute(
        select(m.Threat_Scenario).where(
            m.Threat_Scenario.ScenarioID == dal.canonical_guid(scenario_id),
            m.Threat_Scenario.SessionID == session_id)
    ).scalars().first()
    if out is None:
        raise NotFoundError(f"scenario {scenario_id} not found in session {session_id}")

    # The accept gate. `Accepted` is only ever READ here — scripts/test_pipeline_guards.py fails
    # the build if anything but dal.decide_scenarios assigns it.
    if out.Status != ScenarioStatus.complete:
        raise AcceptConflict("scenario is a failure card and cannot be promoted",
                            reason=ScenarioDecisionReason.failure_card)
    if out.Superseded:
        raise AcceptConflict("scenario was superseded by a regeneration — refresh and retry",
                            reason=ScenarioDecisionReason.duplicate_identity)
    if not out.Accepted:
        raise AcceptConflict(
            "scenario has not been accepted; only accepted scenarios promote to the library",
            reason=(ScenarioDecisionReason.already_rejected if out.RejectedAt
                    else ScenarioDecisionReason.unknown))

    threat = sess.execute(
        select(m.Identified_Threat)
        .join(m.Scoped_Threat, m.Scoped_Threat.ThreatID == m.Identified_Threat.ThreatID)
        .where(m.Scoped_Threat.ScopedThreatID == out.ScopedThreatID,
            m.Identified_Threat.Superseded == 0)
    ).scalars().first()
    if threat is None:
        raise AcceptConflict(
            "the threat behind this scenario was superseded by a regeneration — refresh and retry",
            reason=ScenarioDecisionReason.duplicate_identity)
    return out, threat


def _promote_type(sess: Session, threat: Any, category_id: int | None,
                user_id: str | None) -> tuple[int, dict[str, Any]]:
    """Reuse the grounded type id, or create the type. Never searches."""
    type_id = threat.ThreatTypeID
    # A curator can retire a type between identification and promotion. Treat a dead id exactly
    # as an absent one.
    if type_id is not None and dal.threat_type_active(sess, type_id):
        return type_id, {"id": type_id, "name": threat.ThreatType,
                        "category_id": category_id, "status": EXISTING}
    new_id, created = dal.upsert_threat_type(
        sess, threat.ThreatType, category_id, created_by=user_id)
    return new_id, {"id": new_id, "name": threat.ThreatType,
                    "category_id": category_id, "status": INSERTED if created else EXISTING}


def _promote_threat(sess: Session, threat: Any, type_id: int, category_id: int | None,
                    asset_name: str | None,
                    user_id: str | None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Reuse the identified catalogue row, or mint one. Never searches beyond the app-owned
    normalized-name dedup (type-scoped; UX_ThreatCatalogue_NaturalKey(ThreatName) is the
    concurrency backstop).

    Returns (threat entry, actor entries). The category map row and the type-actor links are
    written ONLY alongside a row minted HERE: an existing catalogue threat's curation belongs
    to the curators.
    """
    catalogue_id = threat.ThreatCatalogueID
    if catalogue_id is not None and dal.catalogue_active(sess, catalogue_id):
        row = sess.execute(
            select(m.Threat_Catalogue.ThreatName)
            .where(m.Threat_Catalogue.ThreatCatalogueID == catalogue_id)).first()
        return ({"id": catalogue_id,
                "name": row.ThreatName if row else threat.ThreatName,
                "type_id": type_id, "category_id": category_id,
                "status": EXISTING},
                _actor_entries(sess, threat, type_id, write=False))

    generic = threat.GenericName or asset_agnostic_name(threat.ThreatName, asset_name or "")
    generic = (generic or threat.ThreatName or "")[:500]

    # App-owned dedup FIRST: any live same-normalized-name row under this type means the
    # threat exists — ambiguity resolves deterministically (lowest id) and never mints a twin.
    existing = dal.find_catalogue_id_by_norm_name(sess, type_id, generic)
    if existing is not None:
        return ({"id": existing, "name": generic,
                "type_id": type_id, "category_id": category_id,
                "status": EXISTING},
                _actor_entries(sess, threat, type_id, write=False))

    new_id, created = dal.upsert_threat_catalogue(
        sess, generic, type_id, description=threat.Description, created_by=user_id)

    # Curation for the freshly minted row: the resolved category on the map, and the stored
    # actors on the TYPE map (actors attach per type in this model).
    if created and category_id is not None:
        try:
            dal.link_catalogue_category(sess, new_id, category_id)
        except Exception:
            log.warning("promote.category_link_failed", catalogue_id=new_id,
                        category_id=category_id, exc_info=True)
    actor_entries = _actor_entries(sess, threat, type_id, write=created)

    return ({"id": new_id, "name": generic,
            "type_id": type_id, "category_id": category_id,
            "status": INSERTED if created else EXISTING},
            actor_entries)


def _actor_entries(sess: Session, threat: Any, type_id: int | None,
                   *, write: bool) -> list[dict[str, Any]]:
    """The threat's stored actors as response entries; ThreatType_ThreatActor_Map rows written
    only when `write` (i.e. only alongside a catalogue row minted in this call — actors attach
    per TYPE in this model). LINK ONLY — never creates an actor: generation only ever stores
    ids of real Threat_Actor rows."""
    ids = grounding.stored_actor_ids(threat.ThreatActorsJSON)
    names = grounding.stored_actors(threat.ThreatActorsJSON)
    if not ids and names:
        # Legacy row with names but no ids; nothing trustworthy to link.
        log.info("promote.actor_ids_absent", threat_id=threat.ThreatID, n=len(names))
        return [{"id": None, "name": nm, "type_id": type_id, "linked": False,
                "status": FAILED, "error": "no stored actor id"} for nm in names]
    live = dal.active_actor_ids(sess, ids)
    out: list[dict[str, Any]] = []
    for actor_id, name in zip(ids, names):
        entry: dict[str, Any] = {"id": actor_id, "name": name, "type_id": type_id}
        if actor_id not in live:
            entry.update(status=FAILED, linked=False,
                        error="actor no longer exists in the library")
            log.warning("promote.actor_unresolved", threat_id=threat.ThreatID,
                        actor=name, actor_id=actor_id)
        elif write and type_id is not None:
            try:
                entry["linked"] = dal.link_type_actor(sess, type_id, actor_id)
                entry["status"] = EXISTING
            except Exception:
                # FIXED string, never str(exc): `error` rides the API response of a tenant-facing
                # route in EVERY app_env (errors.py's local/dev-only raw-text gate does not cover
                # a value the handler puts in the body itself), and a SQLAlchemy exception's str()
                # carries the full statement and its bound parameters. Same posture as the
                # "actor no longer exists in the library" branch above. The cause is not lost —
                # exc_info below records it server-side.
                entry.update(status=FAILED, linked=False,
                            error="could not link actor to threat type")
                log.warning("promote.actor_link_failed", threat_id=threat.ThreatID,
                            actor_id=actor_id, exc_info=True)
        else:
            # Existing catalogue threat: its curated links are the curators'; report, don't write.
            entry.update(status=EXISTING, linked=False)
        out.append(entry)
    return out


def _read_controls(sess: Session, scenario_id: str) -> list[dict[str, Any]]:
    """The controls Step-4 mapping already attached. READ from Control_Library ONLY — controls
    are never invented, and promotion never writes control curation (the catalogue model has
    no threat→control map); this is pure reporting.
    """
    cmap, lib = m.Threat_Scenario_Control_Map, m.Control_Library
    rows = sess.execute(
        select(lib.ControlLibraryID, lib.ControlCode, lib.Domain, lib.ControlName,
            cmap.MapRank, cmap.Score)
        .join(lib, lib.ControlLibraryID == cmap.ControlLibraryID)
        .where(cmap.ScenarioID == scenario_id)
        .order_by(cmap.MapRank)).all()
    return [{"ControlLibraryID": r.ControlLibraryID, "ControlCode": r.ControlCode,
            "Domain": r.Domain, "ControlName": r.ControlName,
            "MapRank": r.MapRank, "Score": r.Score} for r in rows]


def promote_scenario_to_library(sess: Session, scenario_session: dict, scenario_id: str,
                                user_id: str | None) -> PromotionResult:
    """Write one accepted scenario's threat data into the library. See module docstring."""
    session_id = scenario_session["SessionID"]
    out, threat = _load_scenario_and_threat(sess, session_id, scenario_id)

    # Read straight off the row — generation resolved this. No find_category call here.
    category_id = threat.ThreatCategoryID

    type_id, type_entry = _promote_type(sess, threat, category_id, user_id)

    # Threat_Catalogue.ThreatTypeID is NOT NULL, so the threat hard-depends on the type.
    # Fail with a clear message instead of letting a NULL reach the column and raise.
    if type_id is None:
        raise AcceptConflict("could not resolve or create the threat type; nothing was promoted")

    controls = _read_controls(sess, out.ScenarioID)
    threat_entry, actor_entries = _promote_threat(
        sess, threat, type_id, category_id, scenario_session.get("AssetName"), user_id)

    # Stamp the ids back, FENCED on Superseded = 0: a regeneration landing between the read
    # above and this write must not have ids stamped onto a row it already replaced.
    new_catalogue_id = threat_entry["id"]
    if new_catalogue_id is not None and (
            type_id != threat.ThreatTypeID or new_catalogue_id != threat.ThreatCatalogueID):
        res = sess.execute(
            update(m.Identified_Threat)
            .where(m.Identified_Threat.ThreatID == threat.ThreatID,
                m.Identified_Threat.Superseded == 0)
            .values(ThreatTypeID=type_id, ThreatCatalogueID=new_catalogue_id))
        if res.rowcount == 0:
            sess.rollback()
            raise AcceptConflict(
                "the threat was superseded while promoting — nothing was written, refresh and retry",
                reason=ScenarioDecisionReason.duplicate_identity)

    # The tracking record (user rule): who promoted, when, and the per-item outcome — the same
    # facts the API response carries, durably.
    dal.append_audit(
        sess, AuditID=guid(), SessionID=session_id, TenantID=scenario_session["TenantID"],
        EntityID=str(scenario_session["EntityID"]), EventType=AuditEventType.library_promoted,
        ActorUserID=user_id, ActorType=ActorType.user if user_id else ActorType.system,
        ThreatTypeRefID=type_id,
        DetailJSON=json.dumps({"scenario_id": str(scenario_id), "threat_id": str(threat.ThreatID),
                            "threat_type_id": type_id,
                            "catalogue_id": threat_entry["id"],
                            "category_id": category_id,
                            "statuses": {"threat_type": type_entry["status"],
                                            "threat": threat_entry["status"]},
                            "actor_ids": [a["id"] for a in actor_entries if a.get("id")],
                            "control_ids": [c["ControlLibraryID"] for c in controls],
                            "source": "promote-to-library"}))
    sess.commit()

    created = sum(1 for e in (type_entry, threat_entry) if e["status"] == INSERTED)
    failed = ([e for e in actor_entries if e["status"] == FAILED]
            + ([threat_entry] if threat_entry["status"] == FAILED else []))
    log.info("scenario.promoted_to_library", session_id=session_id, scenario_id=str(scenario_id),
            threat_type_id=type_id, catalogue_id=threat_entry["id"],
            created=created, failures=len(failed))
    return PromotionResult(
        threat_type=type_entry, threat=threat_entry, threat_actors=actor_entries,
        controls=controls, controls_mapped=bool(controls), created_count=created,
        success=not failed)
