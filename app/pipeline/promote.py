"""Promote ONE accepted threat scenario's threat data into the shared library.

The ONLY write path into the library (accept-time auto-promotion was removed 2026-08): anyone
holding session_id + scenario_id may call it, the scenario must be ACCEPTED, and every promotion
is recorded in Scenario_Audit — who, when, and the per-item outcome.

This module still performs no search of its own: every "is this the same as something we already
have?" question is answered elsewhere and arrives here as an id. An id present on
Identified_Threat is used; a `reuse` id decided by app/pipeline/library_match (before this
transaction opened, so a possibly-remote reranker never sits on the write path) is validated and
used; only when both are absent is a row minted.

It used to say an absent id "means generation already searched and found nothing, so the row is
genuinely new". That was FALSE, and it is the sentence that hid a year-long defect. An absent
catalogue id means grounding scored its best match BELOW the trust cutoff and discarded the row
(grounding.py:1445) — "found something at 70/100" and "found nothing" arrive here identically.
Worse, a minted row is born pending while grounding filters IsActive==True, so the next session
cannot see it and mints another wording: three phrasings of one threat reached the live library
that way. Hence the second rung. Types are deliberately NOT matched this way — measured, their
names are too short to separate synonyms from opposites (see library_match's module docstring).

What a NEW threat writes, in one transaction:
    Threat_Type                    (if the type itself is new — name-only dedup)
    Threat_Catalogue               (name only — Description was removed as unused; name-only
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


def load_scenario_and_threat(sess: Session, session_id: str, scenario_id: str) -> tuple[Any, Any]:
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


def _reuse_would_collide(sess: Session, threat: Any, catalogue_id: int) -> bool:
    """Would linking this threat to `catalogue_id` give two live threats in one (session,
    subsystem) the SAME catalogue id?

    That is not cosmetic. dal.identity_hash folds `cat:{ThreatCatalogueID}` as its first rung
    (pipeline_common._dedup_key), so two threats sharing a catalogue id fold to ONE IdentityHash —
    and supersede_by_identity_hashes then treats their scenarios as versions of each other and
    retires one, which can be a scenario a reviewer has already accepted.

    Reachable today through the exact-name rung, but rare; reuse-by-meaning makes it common enough
    to fence. Refusing here costs a duplicate row, which is visible and fixable — the collision is
    neither.
    """
    return sess.execute(
        select(m.Identified_Threat.ThreatID)
        .where(m.Identified_Threat.SessionID == threat.SessionID,
            m.Identified_Threat.SubsystemID == threat.SubsystemID,
            m.Identified_Threat.ThreatID != threat.ThreatID,
            m.Identified_Threat.ThreatCatalogueID == catalogue_id,
            m.Identified_Threat.Superseded == 0)
        .limit(1)).first() is not None


def _promote_threat(sess: Session, threat: Any, type_id: int, category_id: int | None,
                    asset_name: str | None, user_id: str | None,
                    reuse: tuple[int, float] | None = None,
                    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Reuse the identified catalogue row, or a caller-resolved near-match, or mint one.

    Three rungs, cheapest first: the stored id, the app-owned normalized-name dedup (type-scoped;
    UX_ThreatCatalogue_NaturalKey(ThreatName) is the concurrency backstop), then `reuse` — a
    same-meaning match the CALLER resolved, which this function validates but never computes.

    Returns (threat entry, actor entries). The category map row and the type-actor links are
    written ONLY alongside a row minted HERE: an existing catalogue threat's curation belongs
    to the curators.
    """
    catalogue_id = threat.ThreatCatalogueID
    if catalogue_id is not None and dal.catalogue_active(sess, catalogue_id):
        row = sess.execute(
            select(m.Threat_Catalogue.ThreatName, m.Threat_Catalogue.ThreatTypeID)
            .where(m.Threat_Catalogue.ThreatCatalogueID == catalogue_id)).first()
        if row is not None and row.ThreatTypeID != type_id:
            # The type this row pointed to was retired since generation and _promote_type just
            # minted a replacement — repoint the row so it can never disagree with the type this
            # promotion reports using. Name/category/standards are untouched: this is the one FK
            # the app itself must keep valid, not curator-owned content.
            sess.execute(
                update(m.Threat_Catalogue)
                .where(m.Threat_Catalogue.ThreatCatalogueID == catalogue_id)
                .values(ThreatTypeID=type_id))
            log.info("promote.catalogue_retyped", catalogue_id=catalogue_id,
                    old_type_id=row.ThreatTypeID, new_type_id=type_id)
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

    # SECOND rung: the same threat under different WORDS. normalize_name above folds CHARACTERS
    # (case, accents, punctuation), so "Impersonation of operator sessions" and "Impersonation of
    # authorized control sessions" are two distinct keys and both mint. The caller resolved this
    # one by MEANING, outside our transaction (app/pipeline/library_match.py); we only apply it,
    # and only once the cheap exact rung has missed.
    if reuse is not None:
        reuse_id, reuse_score = reuse
        if dal.catalogue_active(sess, reuse_id) and not _reuse_would_collide(sess, threat,
                                                                            reuse_id):
            log.info("promote.catalogue_reused_by_meaning", catalogue_id=reuse_id,
                    score=round(reuse_score, 2), proposed=generic, type_id=type_id)
            return ({"id": reuse_id, "name": generic,
                    "type_id": type_id, "category_id": category_id,
                    "status": EXISTING, "reused_catalogue_id": reuse_id,
                    "reuse_score": round(reuse_score, 2)},
                    _actor_entries(sess, threat, type_id, write=False))

    new_id, created = dal.upsert_threat_catalogue(
        sess, generic, type_id, created_by=user_id)

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
    return [{"control_id": r.ControlLibraryID, "control_code": r.ControlCode,
            "domain": r.Domain, "control_name": r.ControlName,
            "map_rank": r.MapRank, "score": r.Score} for r in rows]


def promote_scenario_to_library(sess: Session, scenario_session: dict, scenario_id: str,
                                user_id: str | None,
                                reuse: tuple[int, float] | None = None) -> PromotionResult:
    """Write one accepted scenario's threat data into the library. See module docstring.

    `reuse` is an ALREADY-DECIDED (catalogue_id, score) from app/pipeline/library_match, resolved
    by the caller before this transaction opened — this module does not search for it, which is
    what keeps a possibly-remote reranker off the write path. It is still validated here
    (liveness, same-session collision) before anything is linked to it."""
    session_id = scenario_session["SessionID"]
    out, threat = load_scenario_and_threat(sess, session_id, scenario_id)

    # Read straight off the row — generation resolved this. No find_category call here.
    category_id = threat.ThreatCategoryID

    type_id, type_entry = _promote_type(sess, threat, category_id, user_id)

    # Threat_Catalogue.ThreatTypeID is NOT NULL, so the threat hard-depends on the type.
    # Fail with a clear message instead of letting a NULL reach the column and raise.
    if type_id is None:
        raise AcceptConflict("could not resolve or create the threat type; nothing was promoted")

    controls = _read_controls(sess, out.ScenarioID)
    threat_entry, actor_entries = _promote_threat(
        sess, threat, type_id, category_id, scenario_session.get("AssetName"), user_id, reuse)

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
                            # Present ONLY when this promotion linked to an existing row by
                            # MEANING rather than by name. An automatic merge that left no trace
                            # would be unreviewable, and this is the durable one — the response
                            # is gone the moment the caller stops reading it.
                            **({"reused_catalogue_id": threat_entry["reused_catalogue_id"],
                                "reuse_score": threat_entry["reuse_score"]}
                                if "reused_catalogue_id" in threat_entry else {}),
                            "actor_ids": [a["id"] for a in actor_entries if a.get("id")],
                            "control_ids": [c["control_id"] for c in controls],
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
