"""promote.promote_scenario_to_library — the ONLY write path into Threat_Catalogue.

Properties this file pins, post 2026-08 catalogue reversal:

1. ONLY accepted scenarios promote: pending / rejected / superseded / failure-card all 409 with
   the right reason and write NOTHING — asserted on catalogue + junction + audit ROW COUNTS.
2. EXISTING is sacred: a live stored ThreatCatalogueID (or a normalized-name twin under the
   same type) is reused and the library's curated junction rows are NEVER touched — curation
   stays the curators'.
3. INSERTED copies the AI Description into Threat_Catalogue.Description and writes BOTH
   junction maps — the category membership row and the TYPE-actor links for the stored LIVE
   actor ids — so the next session receives the threat fully curated. Controls are REPORTED
   from the scenario's own mapping only, never written (the catalogue has no threat→control
   curation).
4. Actors are LINK-ONLY: a stored actor id that no longer resolves to a live Threat_Actor row
   is a FAILED entry, and a legacy names-without-ids blob fails every entry — promotion never
   invents an actor.
5. The stamp-back is fenced on Superseded = 0: a regeneration landing mid-promotion rolls the
   whole write back — including the freshly minted catalogue row — instead of stamping ids
   onto a dead threat.
6. UX_ThreatCatalogue_NaturalKey(ThreatName) is the simultaneous-mint backstop, and the
   app-owned dedup is TYPE-scoped, so a same-name row under another type is invisible to it:
   the resulting IntegrityError must recover to the existing row, not 500.

Real SQLite tables with the LIVE unique index on ThreatName mirrored, so the collision test
raises a real IntegrityError exactly as MSSQL would.
"""
from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import create_engine, event, select, update
from sqlalchemy.orm import sessionmaker

from app.core.enums import AuditEventType, ScenarioDecisionReason, ScenarioStatus
from app.db import dal
from app.db import models as m
from app.pipeline import promote
from app.pipeline.accept import AcceptConflict


def _guid() -> str:
    return str(uuid.uuid4())


# Master ids the fixture seeds once. OTHER_TYPE_ID exists only as a foreign ThreatTypeID on a
# seeded catalogue row — the cross-type name-collision test needs a row the type-scoped dedup
# cannot see.
TYPE_ID, OTHER_TYPE_ID, CAT_ID = 7, 8, 2
ACTORS_JSON = json.dumps({"actors": ["APT-Nova", "Insider"], "actor_ids": [9, 31],
                          "validated": True})

_TABLES = (m.Threat_Category, m.Threat_Type, m.Threat_Actor, m.Threat_Catalogue,
           m.ThreatType_ThreatActor_Map, m.Threat_Catalogue_Category_Map,
           m.Control_Library, m.Threat_Scenario_Control_Map,
           m.Identified_Threat, m.Scoped_Threat, m.Threat_Scenario, m.Scenario_Audit)


@pytest.fixture
def sf():
    engine = create_engine("sqlite://")

    # pysqlite workaround (same as the accept/admin suites): without it, RELEASE SAVEPOINT —
    # which dal.upsert_threat_catalogue emits via begin_nested — silently COMMITS the open
    # transaction, and the stamp-back fence's rollback assertion below would pass vacuously
    # while the minted row survived.
    @event.listens_for(engine, "connect")
    def _no_implicit_txn(dbapi_connection, connection_record):
        dbapi_connection.isolation_level = None

    @event.listens_for(engine, "begin")
    def _explicit_begin(conn):
        conn.exec_driver_sql("BEGIN")

    for t in _TABLES:
        t.__table__.create(engine, checkfirst=True)
    with engine.begin() as conn:
        # The LIVE name-uniqueness backstop, as raw DDL so no Index object pollutes the shared
        # table metadata for other test files. (SQLite ignores the production index's filtered
        # WHERE — fine for the backstop path this file exercises.)
        conn.exec_driver_sql(
            "CREATE UNIQUE INDEX UX_ThreatCatalogue_NaturalKey ON Threat_Catalogue(ThreatName)")

    sm = sessionmaker(bind=engine)
    with sm() as s:
        s.add(m.Threat_Category(ThreatCategoryID=CAT_ID, ThreatCategoryName="Tampering",
                                IsActive=True, IsDeleted=False))
        s.add(m.Threat_Type(ThreatTypeID=TYPE_ID, ThreatTypeName="Ransomware",
                            ThreatCategoryID=CAT_ID, IsActive=True, IsDeleted=False))
        s.add(m.Threat_Actor(ThreatActorID=9, ThreatActorName="APT-Nova",
                             IsActive=True, IsDeleted=False))
        s.add(m.Threat_Actor(ThreatActorID=31, ThreatActorName="Insider",
                             IsActive=True, IsDeleted=False))
        s.commit()
    return sm


def _seed_catalogue(sf, *, cid, name, type_id=TYPE_ID):
    with sf() as s:
        s.add(m.Threat_Catalogue(ThreatCatalogueID=cid, ThreatTypeID=type_id, ThreatName=name,
                                 IsActive=True, IsDeleted=False, CreatedBy="curator"))
        s.commit()


def _seed(sf, *, accepted=1, rejected_at=None, superseded_out=0, superseded_threat=0,
          status=ScenarioStatus.complete, actors_json=ACTORS_JSON, type_id=TYPE_ID,
          catalogue_id=None, generic_name="Ransomware encrypts historian data at rest",
          description="Encrypts stored data; demands payment."):
    """One session -> threat -> scoped threat -> scenario chain (legacy fixture shape,
    catalogue-era id columns). Returns (session dict, scenario_id, threat_id)."""
    sid, tid, oid, stid = _guid(), _guid(), _guid(), _guid()
    with sf() as s:
        s.add(m.Identified_Threat(
            ThreatID=tid, SessionID=sid, TenantID="t", EntityID="e", UserID="u", SubsystemID=0,
            ThreatCategory="Tampering", ThreatCategoryID=CAT_ID, ThreatType="Ransomware",
            ThreatName="Ransomware encrypts the ACME Historian", GenericName=generic_name,
            Description=description, ThreatTypeID=type_id, ThreatCatalogueID=catalogue_id,
            ThreatActorsJSON=actors_json, GroundingStatus="unverified",
            Superseded=superseded_threat))
        s.add(m.Scoped_Threat(ScopedThreatID=stid, SessionID=sid, TenantID="t", EntityID="e",
                              UserID="u", SubsystemID=0, ThreatID=tid, Score=1.0, ScopeRank=1,
                              Selected=1))
        s.add(m.Threat_Scenario(
            ScenarioID=oid, SessionID=sid, TenantID="t", EntityID="e", UserID="u", SubsystemID=0,
            ScopedThreatID=stid, Status=status, ScenarioJSON="{}", Accepted=accepted,
            RejectedAt=rejected_at, IdentityHash="h", ScenarioNumber=1,
            Superseded=superseded_out))
        s.commit()
    return {"SessionID": sid, "TenantID": "t", "EntityID": "e",
            "AssetName": "ACME Historian"}, oid, tid


def _counts(sf):
    """(catalogue, type-actor map, category map, audit) — what a refused call must not grow."""
    with sf() as s:
        return (s.query(m.Threat_Catalogue).count(),
                s.query(m.ThreatType_ThreatActor_Map).count(),
                s.query(m.Threat_Catalogue_Category_Map).count(),
                s.query(m.Scenario_Audit).count())


# --------------------------------------------------------------------------- the accept gate

@pytest.mark.parametrize("kwargs,want_reason", [
    ({"accepted": 0}, ScenarioDecisionReason.unknown),
    ({"accepted": 0, "rejected_at": "now"}, ScenarioDecisionReason.already_rejected),
    ({"superseded_out": 1}, ScenarioDecisionReason.duplicate_identity),
    ({"status": ScenarioStatus.error, "accepted": 0}, ScenarioDecisionReason.failure_card),
    ({"superseded_threat": 1}, ScenarioDecisionReason.duplicate_identity),
])
def test_only_accepted_scenarios_promote(sf, kwargs, want_reason):
    """Anyone with session_id + scenario_id can call this endpoint, so the accept gate is the
    only thing between an unreviewed AI threat and the shared cross-tenant library. Each
    refusal must also carry the machine-readable reason the UI keys its message off."""
    if kwargs.get("rejected_at") == "now":
        kwargs["rejected_at"] = dal.now()
    ss, oid, _ = _seed(sf, **kwargs)
    before = _counts(sf)
    with sf() as s, pytest.raises(AcceptConflict) as exc:
        promote.promote_scenario_to_library(s, ss, oid, "reviewer")
    assert exc.value.reason == want_reason
    assert _counts(sf) == before, f"{want_reason} wrote to the library"


# --------------------------------------------------------------------------- EXISTING reuse

def test_live_catalogue_id_is_reused_and_junctions_never_touched(sf):
    """A threat retrieved FROM the catalogue must round-trip to the same row, and the type's
    curated actor links belong to the curators — a promotion that 'helpfully' appended the
    session's actors would silently rewrite curation nobody reviewed."""
    _seed_catalogue(sf, cid=501, name="Credential Phishing")
    with sf() as s:
        # Curated junction state: ONE type-actor link. The threat stores TWO actor ids — if
        # promote writes for an EXISTING row, the count below becomes 2 and this test fails.
        s.add(m.ThreatType_ThreatActor_Map(ThreatTypeID=TYPE_ID, ThreatActorID=9))
        s.commit()
    ss, oid, _ = _seed(sf, catalogue_id=501)
    before = _counts(sf)

    with sf() as s:
        r = promote.promote_scenario_to_library(s, ss, oid, "reviewer")

    assert r.threat["status"] == promote.EXISTING
    assert r.threat["id"] == 501 and r.threat["name"] == "Credential Phishing"
    assert r.created_count == 0 and r.success is True
    assert all(a["linked"] is False for a in r.threat_actors)
    after = _counts(sf)
    assert after[:3] == before[:3], "an EXISTING catalogue threat's rows were modified"
    assert after[3] == before[3] + 1        # the promotion itself is still audited


def test_normalized_name_twin_is_reused_not_reminted(sf):
    """The app's TYPE-scoped normalized-name lookup is the first duplicate guard.
    'credential-phishing' and 'Credential Phishing' under one type are one identity; minting a
    twin here would fork the library exactly the way the old register forked."""
    _seed_catalogue(sf, cid=501, name="Credential Phishing")
    ss, oid, _ = _seed(sf, catalogue_id=None, generic_name="credential-phishing")

    with sf() as s:
        r = promote.promote_scenario_to_library(s, ss, oid, "reviewer")

    assert r.threat["status"] == promote.EXISTING and r.threat["id"] == 501
    counts = _counts(sf)
    assert counts[0] == 1, "a normalized-name twin was minted"
    assert counts[1] == 0 and counts[2] == 0, "junctions written for an EXISTING threat"


# --------------------------------------------------------------------------- INSERTED path

def test_new_threat_writes_row_and_both_junction_maps(sf):
    """The full INSERTED contract in one transaction: Threat_Catalogue carries the AI
    Description, the category map row and the type-actor links are written so the next session
    receives the threat fully curated, the ids are stamped back, the scenario's controls are
    REPORTED (never written to a master table), and the audit row records it all durably."""
    ss, oid, tid = _seed(sf)
    with sf() as s:
        s.add(m.Control_Library(ControlLibraryID=771, ControlCode="CII-CID-201", ITOT="OT",
                                Domain="Access Control", ControlName="Privileged access review",
                                ControlDescription="d", IsActive=True, IsDeleted=False))
        s.add(m.Threat_Scenario_Control_Map(ScenarioID=oid, ControlLibraryID=771,
                                            SessionID=ss["SessionID"], MapRank=1, Score=82.4))
        s.commit()

    with sf() as s:
        r = promote.promote_scenario_to_library(s, ss, oid, "reviewer")

    assert r.threat["status"] == promote.INSERTED
    assert r.threat_type["status"] == promote.EXISTING   # grounded live type id was reused
    assert r.created_count == 1 and r.success is True
    assert r.controls_mapped is True
    assert [c["ControlLibraryID"] for c in r.controls] == [771]
    assert all(a["linked"] is True for a in r.threat_actors)

    with sf() as s:
        row = s.get(m.Threat_Catalogue, r.threat["id"])
        assert row.Description == "Encrypts stored data; demands payment."
        assert row.ThreatName == "Ransomware encrypts historian data at rest"
        assert row.ThreatTypeID == TYPE_ID and row.IsActive and not row.IsDeleted

        actors = s.execute(
            select(m.ThreatType_ThreatActor_Map.ThreatActorID).where(
                m.ThreatType_ThreatActor_Map.ThreatTypeID == TYPE_ID)).scalars().all()
        assert sorted(actors) == [9, 31]             # the STORED live actor ids, nothing else
        cats = s.execute(
            select(m.Threat_Catalogue_Category_Map.ThreatCategoryID).where(
                m.Threat_Catalogue_Category_Map.ThreatCatalogueID
                == r.threat["id"])).scalars().all()
        assert cats == [CAT_ID]                      # the resolved category, on the map

        it = s.get(m.Identified_Threat, tid)
        assert it.ThreatCatalogueID == r.threat["id"]        # stamped back

        audit = s.execute(select(m.Scenario_Audit).where(
            m.Scenario_Audit.EventType == AuditEventType.library_promoted)).scalars().all()
        assert len(audit) == 1
        detail = json.loads(audit[0].DetailJSON)
        assert detail["catalogue_id"] == r.threat["id"]
        assert detail["category_id"] == CAT_ID
        assert detail["actor_ids"] == [9, 31] and detail["control_ids"] == [771]
        assert detail["source"] == "promote-to-library"
        assert detail["statuses"] == {"threat_type": "existing", "threat": "inserted"}


def test_dead_actor_id_fails_that_entry_but_never_links_it(sf):
    """LINK-ONLY: a stored actor id a curator has since retired (or that never existed) must
    become a FAILED entry — not a resurrected actor, not a dangling map row. The threat itself
    still promotes; success=False tells the caller to look at the per-item outcomes."""
    dead = json.dumps({"actors": ["APT-Nova", "Ghost Crew"], "actor_ids": [9, 99],
                       "validated": True})
    ss, oid, _ = _seed(sf, actors_json=dead)
    with sf() as s:
        r = promote.promote_scenario_to_library(s, ss, oid, "reviewer")

    assert r.threat["status"] == promote.INSERTED
    assert r.success is False
    by_id = {a["id"]: a for a in r.threat_actors}
    assert by_id[99]["status"] == promote.FAILED and by_id[99]["linked"] is False
    assert "no longer exists" in by_id[99]["error"]
    assert by_id[9]["linked"] is True
    with sf() as s:
        actors = s.execute(select(m.ThreatType_ThreatActor_Map.ThreatActorID)).scalars().all()
        assert actors == [9], "a dead actor id reached the type-actor map"


def test_names_without_ids_blob_fails_every_actor_entry(sf):
    """A legacy ThreatActorsJSON with names but no actor_ids has nothing trustworthy to link —
    pairing names to ids by guesswork here would write curation nobody resolved. Every entry
    FAILED, nothing written to the map."""
    legacy = json.dumps({"actors": ["APT-Nova"], "validated": False})
    ss, oid, _ = _seed(sf, actors_json=legacy)
    with sf() as s:
        r = promote.promote_scenario_to_library(s, ss, oid, "reviewer")

    assert r.threat["status"] == promote.INSERTED and r.success is False
    assert [a["status"] for a in r.threat_actors] == [promote.FAILED]
    assert r.threat_actors[0]["error"] == "no stored actor id"
    assert _counts(sf)[1] == 0, "an id-less actor name reached the type-actor map"


# --------------------------------------------------------------------------- concurrency

def test_supersede_mid_flight_rolls_back_the_minted_row(sf, monkeypatch):
    """The stamp-back is fenced on Superseded = 0. A regeneration landing between the threat
    read and the stamp must abort the WHOLE promotion — including the catalogue row and
    junction maps already minted in this transaction — or the library keeps a threat whose
    source row no longer exists and the dead row carries stamped ids."""
    ss, oid, tid = _seed(sf)
    before = _counts(sf)
    real = promote._read_controls

    def _supersede_then_read(sess, scenario_id):
        # Simulate the regeneration landing after _load_scenario_and_threat's read.
        sess.execute(update(m.Identified_Threat)
                     .where(m.Identified_Threat.ThreatID == tid).values(Superseded=1))
        return real(sess, scenario_id)

    monkeypatch.setattr(promote, "_read_controls", _supersede_then_read)
    with sf() as s, pytest.raises(AcceptConflict) as exc:
        promote.promote_scenario_to_library(s, ss, oid, "reviewer")
    assert exc.value.reason == ScenarioDecisionReason.duplicate_identity
    assert _counts(sf) == before, "rows survived the rollback of a superseded promotion"
    with sf() as s:
        assert s.get(m.Identified_Threat, tid).ThreatCatalogueID is None, "stamped anyway"


def test_cross_type_name_collision_recovers_to_existing_row(sf):
    """UX_ThreatCatalogue_NaturalKey(ThreatName) is the backstop the app-owned dedup cannot
    replace: the norm-name lookup is TYPE-scoped, so a live same-name row under a DIFFERENT
    type is invisible to it and the insert genuinely collides. The recovery must select by
    ThreatName ALONE and reuse that row — not 500, and never mint a twin."""
    _seed_catalogue(sf, cid=501, name="Ransomware encrypts historian data at rest",
                    type_id=OTHER_TYPE_ID)
    ss, oid, _ = _seed(sf)

    with sf() as s:
        r = promote.promote_scenario_to_library(s, ss, oid, "reviewer")

    assert r.threat["status"] == promote.EXISTING and r.threat["id"] == 501
    assert r.created_count == 0 and r.success is True
    counts = _counts(sf)
    assert counts[0] == 1, "the IntegrityError backstop minted a twin"
    # Recovery means created=False, so the curation writes are skipped exactly as they are for
    # any other EXISTING threat.
    assert counts[1] == 0 and counts[2] == 0, "junctions written for a recovered EXISTING row"
