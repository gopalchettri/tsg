"""Admin-gated library growth (plan eager-swimming-acorn, phase 3): with the master switch OFF
(default) the accept-time promotion phase writes NOTHING to the master library — novel types,
names, AND actors all queue as Threat_Candidate_Review cards (actors previously vanished);
switch ON restores full-auto (types + names + actors + links). Every test asserts MASTER-TABLE
ROW COUNTS, not just queue contents. Real SQLite tables; triage/LLM stubbed (no embeddings)."""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.core.enums import CandidateKind, CandidateStatus
from app.db import dal
from app.db import models as m
from app.pipeline import accept as accept_mod

SID = "5aa85f64-5717-4562-b3fc-2c963f66afa6"


def _engine():
    engine = create_engine("sqlite://")

    # pysqlite's legacy transaction control COMMITS the open transaction when it sees a
    # non-DML statement like RELEASE SAVEPOINT — which the dal upserts (begin_nested) emit —
    # silently breaking rollback-on-error tests. The documented SQLAlchemy workaround: take
    # over transaction control so SAVEPOINT/ROLLBACK behave like a real database (MSSQL).
    @event.listens_for(engine, "connect")
    def _no_implicit_txn(dbapi_connection, connection_record):
        dbapi_connection.isolation_level = None

    @event.listens_for(engine, "begin")
    def _explicit_begin(conn):
        conn.exec_driver_sql("BEGIN")

    for table in (m.Scenario_Session, m.Identified_Threat, m.Scoped_Threat,
                m.Threat_Scenario_Output, m.Threat_Candidate_Review, m.Threat_Type,
                m.Threat_Catalogue, m.Threat_Catalogue_Category_Map, m.Threat_Actor,
                m.ThreatType_ThreatActor_Map, m.Threat_Category, m.Scenario_Audit):
        table.__table__.create(engine)
    return engine


def _now():
    return datetime.now(UTC)


def _session_mapping(sid: str = SID) -> dict:
    return {"SessionID": sid, "TenantID": "t", "EntityID": "86", "UserID": "sara",
            "SectorIDsJSON": "[]", "ScoringRulesSnapshotJSON": None}


def _seed_threat(Session, sid: str, *, type_id=None, actors=("APT-X",),
                 threat_type="Firmware supply-chain tampering",
                 threat_name="Tampered firmware in smart meters",
                 grounding_score=None) -> str:
    """One threat with an ACCEPTED scenario. Default GroundingScore NULL = the classic
    promotion-candidate shape; pass a high score for the actor-only (GAP B) shape."""
    tid, scoped = str(uuid.uuid4()), str(uuid.uuid4())
    with Session() as s:
        s.execute(m.Identified_Threat.__table__.insert().values(
            ThreatID=tid, SessionID=sid, TenantID="t", EntityID="86", SubsystemID=0,
            ThreatCategory="Information Disclosure", ThreatType=threat_type,
            ThreatName=threat_name, GroundingStatus="unverified", GroundingScore=grounding_score,
            ThreatTypeID=type_id,
            ThreatActorsJSON=json.dumps({"actors": list(actors), "validated": False}),
            Superseded=0, CreatedAt=_now()))
        s.execute(m.Scoped_Threat.__table__.insert().values(
            ScopedThreatID=scoped, SessionID=sid, TenantID="t", EntityID="86", SubsystemID=0,
            ThreatID=tid, Score=90.0, ScopeRank=1, Selected=1, Superseded=0, CreatedAt=_now()))
        s.execute(m.Threat_Scenario_Output.__table__.insert().values(
            OutputID=str(uuid.uuid4()), SessionID=sid, TenantID="t", EntityID="86",
            SubsystemID=0, ScopedThreatID=scoped, Status="complete", ScenarioJSON="{}",
            Accepted=1, Superseded=0, IdentityHash=uuid.uuid4().hex + uuid.uuid4().hex,
            ScenarioNumber=1, GenerationEpoch=1, CreatedAt=_now()))
        s.commit()
    return tid


def _stub_triage(monkeypatch):
    """No embeddings/LLM: empty catalogue -> every candidate's verdict is `review`."""
    monkeypatch.setattr(accept_mod, "get_llm", lambda: None)
    monkeypatch.setattr(accept_mod, "_prepare_triage", lambda sess, llm, ss, rows: SimpleNamespace(
        entries=[], catalogue_vecs={}, query_vecs={},
        generic_by_tid={r["ThreatID"]: (r["ThreatName"] or "").replace("smart meters", "meters")
                        for r in rows},
        sector_ids=[]))


def _run_promotion(Session, monkeypatch, sid: str = SID) -> None:
    _stub_triage(monkeypatch)
    with Session() as s:
        accept_mod._add_unverified_threats_to_library(s, _session_mapping(sid), [0], "sara")
        s.commit()


def _counts(Session) -> dict:
    with Session() as s:
        return {
            "types": len(s.execute(select(m.Threat_Type.ThreatTypeID)).all()),
            "catalogue": len(s.execute(select(m.Threat_Catalogue.ThreatCatalogueID)).all()),
            "actors": len(s.execute(select(m.Threat_Actor.ThreatActorID)).all()),
            "links": len(s.execute(select(m.ThreatType_ThreatActor_Map.ThreatTypeID)).all()),
            "candidates": [dict(r) for r in s.execute(
                select(m.Threat_Candidate_Review.__table__)).mappings()],
        }


def test_switch_off_novel_everything_writes_nothing_to_master(monkeypatch):
    """The core policy: a novel type under switch OFF -> ZERO master rows and one 'threat'
    card (ThreatTypeID NULL) stamped CreatedBy=the accepting user. Actors are library-only
    now (grounding), so no actor card is filed and no actor row is ever minted here."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _seed_threat(Session, SID)
    _run_promotion(Session, monkeypatch)

    c = _counts(Session)
    assert c["types"] == 0 and c["catalogue"] == 0 and c["actors"] == 0 and c["links"] == 0
    kinds = sorted(r["CandidateKind"] for r in c["candidates"])
    assert kinds == [str(CandidateKind.threat)]           # threat only - actors never card now
    threat_card = next(r for r in c["candidates"] if r["CandidateKind"] == str(CandidateKind.threat))
    assert threat_card["ThreatTypeID"] is None            # novel type: NOT minted, mints on approval
    assert threat_card["CreatedBy"] == "sara"


def test_switch_off_matched_vocabulary_writes_and_queues_nothing_extra(monkeypatch):
    """'Already present -> do nothing': matched type id carried onto the card; known actor
    neither queued nor re-added."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    with Session() as s:
        s.execute(m.Threat_Type.__table__.insert().values(
            ThreatTypeID=1, ThreatTypeName="Firmware supply-chain tampering",
            IsActive=True, IsDeleted=False, Source="seed"))
        s.execute(m.Threat_Actor.__table__.insert().values(
            ThreatActorID=1, ThreatActorName="APT-X", IsCapable=1,
            IsActive=True, IsDeleted=False, Source="seed"))
        s.commit()
    _seed_threat(Session, SID, type_id=1)
    _run_promotion(Session, monkeypatch)

    c = _counts(Session)
    assert c["types"] == 1 and c["actors"] == 1 and c["links"] == 0  # nothing new, no links
    assert [r["CandidateKind"] for r in c["candidates"]] == [str(CandidateKind.threat)]
    assert c["candidates"][0]["ThreatTypeID"] == 1  # existing vocabulary carried, not re-minted


def test_cross_session_dedup_for_both_kinds(monkeypatch):
    """A SECOND session proposing the same threat name files ZERO new cards — the
    cross-session pending-dedup. Threat kind only: actors are library-only and never card."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _seed_threat(Session, SID)
    _run_promotion(Session, monkeypatch)
    n_before = len(_counts(Session)["candidates"])
    assert n_before == 1  # the threat card; actors are library-only and never card

    sid2 = str(uuid.uuid4())
    _seed_threat(Session, sid2)
    _run_promotion(Session, monkeypatch, sid=sid2)

    assert len(_counts(Session)["candidates"]) == n_before  # zero new cards


def test_switch_on_full_auto_mints_everything_with_provenance(monkeypatch):
    """ON: the type is minted and the session threat is back-filled — the master row carries
    Source/CreatedAt/CreatedBy=the accepting user. NO actor is minted or linked: actors are
    library-only (grounding), so accept never writes to Threat_Actor.
    (The empty stub catalogue keeps the NAME's verdict at `review`, so it still queues.)"""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    monkeypatch.setattr(get_settings(), "promotion_auto_approve_enabled", True)
    tid = _seed_threat(Session, SID)
    _run_promotion(Session, monkeypatch)

    c = _counts(Session)
    assert c["types"] == 1 and c["actors"] == 0 and c["links"] == 0  # no actor minting
    with Session() as s:
        trow = s.execute(select(m.Threat_Type.__table__)).mappings().one()
        backfilled = s.execute(select(m.Identified_Threat.ThreatTypeID)
                               .where(m.Identified_Threat.ThreatID == tid)).scalar()
    assert trow["Source"] == "ai_auto_promoted"
    assert trow["CreatedAt"] is not None
    assert trow["CreatedBy"] == "sara"         # the accepting user, stamped on auto-adds
    assert backfilled == trow["ThreatTypeID"]  # id back-fill happens in auto mode only


def test_resolve_actor_candidate_approve_and_reject(monkeypatch):
    """Approve an 'actor' card -> master row (CreatedBy = ORIGINAL proposer, not the admin)
    + link to the grounded type; reject -> nothing. The kind branch runs FIRST, so the NULL
    category/type can never reach the threat path's upserts."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    approve_id, reject_id = str(uuid.uuid4()), str(uuid.uuid4())
    with Session() as s:
        s.execute(m.Threat_Type.__table__.insert().values(
            ThreatTypeID=7, ThreatTypeName="Some type", IsActive=True, IsDeleted=False))
        for cid, name in ((approve_id, "APT-X"), (reject_id, "APT-Y")):
            s.execute(m.Threat_Candidate_Review.__table__.insert().values(
                CandidateID=cid, TenantID="t", EntityID="86", SessionID=SID,
                ProposedCategory=None, ProposedType=None, ProposedName=name,
                Status=CandidateStatus.pending, ThreatTypeID=7,
                CreatedAt=_now(), CandidateKind=str(CandidateKind.actor), CreatedBy="sara"))
        s.commit()
        res = accept_mod.resolve_candidate(s, dict(dal.get_candidate(s, approve_id)),
                                           "admin-bob", approve=True)
        assert res.won and res.type_id == 7
        res2 = accept_mod.resolve_candidate(s, dict(dal.get_candidate(s, reject_id)),
                                            "admin-bob", approve=False)
        assert res2.won
        s.commit()

    c = _counts(Session)
    assert c["actors"] == 1 and c["links"] == 1  # approve minted+linked; reject minted nothing
    with Session() as s:
        arow = s.execute(select(m.Threat_Actor.__table__)).mappings().one()
        approved_card = dal.get_candidate(s, approve_id)
    assert arow["ThreatActorName"] == "APT-X"
    assert arow["CreatedBy"] == "sara"                # ORIGINAL proposer credited on master
    assert approved_card["ReviewedBy"] == "admin-bob"  # admin credited on the card


def test_resolve_threat_candidate_credits_original_proposer(monkeypatch):
    """Approving a NULL-type 'threat' card mints type+catalogue with CreatedBy = the card's
    CreatedBy (sara), while ReviewedBy = the admin — the provenance split, pinned."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    cid = str(uuid.uuid4())
    with Session() as s:
        s.execute(m.Threat_Category.__table__.insert().values(  # STRIDE is always seeded in real DBs
            ThreatCategoryID=4, ThreatCategoryName="Information Disclosure",
            IsActive=True, IsDeleted=False))
        s.execute(m.Threat_Candidate_Review.__table__.insert().values(
            CandidateID=cid, TenantID="t", EntityID="86", SessionID=SID,
            ProposedCategory="Information Disclosure", ProposedType="Novel type",
            ProposedName="Novel threat of X", ProposedGenericName="Novel threat",
            Status=CandidateStatus.pending, ThreatTypeID=None,
            CreatedAt=_now(), CandidateKind=str(CandidateKind.threat), CreatedBy="sara"))
        s.commit()
        res = accept_mod.resolve_candidate(s, dict(dal.get_candidate(s, cid)), "admin-bob",
                                           approve=True)
        assert res.won and res.type_id is not None and res.catalogue_id is not None
        s.commit()
    with Session() as s:
        trow = s.execute(select(m.Threat_Type.__table__)).mappings().one()
        crow = s.execute(select(m.Threat_Catalogue.__table__)).mappings().one()
    assert trow["CreatedBy"] == "sara" and crow["CreatedBy"] == "sara"


def test_legacy_and_actor_rows_render_in_admin_serializer():
    """One NULL-field actor card + one legacy card (NULL kind/CreatedBy) must both serialize —
    previously a single NULL category row would 500 the whole candidates list."""
    from app.api.admin import _to_pending_candidate
    actor_row = {"CandidateID": "x", "SessionID": SID, "EntityID": "86",
                 "CandidateKind": str(CandidateKind.actor), "CreatedBy": "sara",
                 "ProposedCategory": None, "ProposedType": None, "ProposedName": "APT-X",
                 "ProposedGenericName": None, "ThreatTypeID": 7,
                 "Status": "pending", "CreatedAt": _now()}
    legacy_row = {**actor_row, "CandidateKind": None, "CreatedBy": None,
                  "ProposedCategory": "Spoofing", "ProposedType": "T", "ProposedName": "N"}
    del legacy_row["ThreatTypeID"]  # legacy shape may lack the key entirely
    rendered = _to_pending_candidate(actor_row)
    assert rendered.kind == CandidateKind.actor
    assert rendered.threat_type_id == 7  # the grounded link target is VISIBLE to the admin
    legacy = _to_pending_candidate(legacy_row)
    assert legacy.kind == CandidateKind.threat and legacy.created_by is None
    assert legacy.threat_type_id is None


def test_pending_identities_preload_folds_case_and_kind():
    """The batched dedup preload (ONE query, replacing per-row probes): identities are
    kind-scoped; actor rows fold by NORMALIZED spelling (so "APT X" suppresses "APT-X"), threat
    rows fold case-only to generic-or-name; NULL kind = threat; REJECTED rows count too — an
    admin's 'no' must stick."""
    from app.pipeline.accept_actors import pending_card_identities
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    with Session() as s:
        s.execute(m.Threat_Candidate_Review.__table__.insert().values(
            CandidateID=str(uuid.uuid4()), TenantID="t", EntityID="86", SessionID=SID,
            ProposedCategory=None, ProposedType="T", ProposedName="APT-X",
            Status=CandidateStatus.pending, CreatedAt=_now(),
            CandidateKind=str(CandidateKind.actor), CreatedBy="sara"))
        s.execute(m.Threat_Candidate_Review.__table__.insert().values(
            CandidateID=str(uuid.uuid4()), TenantID="t", EntityID="86", SessionID=SID,
            ProposedCategory=None, ProposedType="T", ProposedName="APT-Rejected",
            Status=CandidateStatus.rejected, CreatedAt=_now(),
            CandidateKind=str(CandidateKind.actor), CreatedBy="sara"))
        s.execute(m.Threat_Candidate_Review.__table__.insert().values(
            CandidateID=str(uuid.uuid4()), TenantID="t", EntityID="86", SessionID=SID,
            ProposedCategory="Spoofing", ProposedType="T", ProposedName="Threat of X",
            ProposedGenericName="Generic Threat",
            Status=CandidateStatus.pending, CreatedAt=_now(),
            CandidateKind=None, CreatedBy=None))  # legacy row: NULL kind reads as 'threat'
        s.commit()
        pending = pending_card_identities(s)
    assert (str(CandidateKind.actor), "apt x") in pending          # spelling-normalized
    assert (str(CandidateKind.actor), "apt rejected") in pending   # rejected suppresses too
    assert (str(CandidateKind.threat), "apt x") not in pending     # kind-scoped
    assert (str(CandidateKind.threat), "generic threat") in pending  # generic wins over name
    assert (str(CandidateKind.threat), "threat of x") not in pending


def test_actor_approve_links_by_name_after_threat_approve(monkeypatch):
    """Fully-novel proposal, approved in the natural order: the threat card mints the type,
    then the actor card's link resolves BY NAME onto that freshly minted type — the dead-end
    (ThreatTypeID NULL forever) is gone. The card records what it actually linked to."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    threat_cid, actor_cid = str(uuid.uuid4()), str(uuid.uuid4())
    with Session() as s:
        s.execute(m.Threat_Category.__table__.insert().values(
            ThreatCategoryID=4, ThreatCategoryName="Information Disclosure",
            IsActive=True, IsDeleted=False))
        s.execute(m.Threat_Candidate_Review.__table__.insert().values(
            CandidateID=threat_cid, TenantID="t", EntityID="86", SessionID=SID,
            ProposedCategory="Information Disclosure", ProposedType="Novel type",
            ProposedName="Novel threat of X", ProposedGenericName="Novel threat",
            Status=CandidateStatus.pending, ThreatTypeID=None,
            CreatedAt=_now(), CandidateKind=str(CandidateKind.threat), CreatedBy="sara"))
        s.execute(m.Threat_Candidate_Review.__table__.insert().values(
            CandidateID=actor_cid, TenantID="t", EntityID="86", SessionID=SID,
            ProposedCategory=None, ProposedType="Novel type", ProposedName="APT-N",
            Status=CandidateStatus.pending, ThreatTypeID=None,
            CreatedAt=_now(), CandidateKind=str(CandidateKind.actor), CreatedBy="sara"))
        s.commit()
        res_t = accept_mod.resolve_candidate(s, dict(dal.get_candidate(s, threat_cid)),
                                             "admin-bob", approve=True)
        assert res_t.won and res_t.type_id is not None
        res_a = accept_mod.resolve_candidate(s, dict(dal.get_candidate(s, actor_cid)),
                                             "admin-bob", approve=True)
        s.commit()
    assert res_a.won and res_a.type_id == res_t.type_id  # linked to the type approved first
    c = _counts(Session)
    assert c["actors"] == 1 and c["links"] == 1
    with Session() as s:
        link = s.execute(select(m.ThreatType_ThreatActor_Map.__table__)).mappings().one()
        card = dal.get_candidate(s, actor_cid)
    assert link["ThreatTypeID"] == res_t.type_id
    assert card["ThreatTypeID"] == res_t.type_id  # the card records the resolved link target


def test_actor_approve_never_guesses_a_link(monkeypatch):
    """Three no-link cases, one rule — save the actor, SKIP the link, never guess: the card's
    type was never approved (no match), TWO active types share the name (ambiguous), and a
    legacy card with no stored type text (pre-fix rows in a live queue)."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    ghost_cid, ambig_cid, legacy_cid = (str(uuid.uuid4()) for _ in range(3))
    with Session() as s:
        # Two ACTIVE types sharing one name (legal: the natural key includes category/sector).
        s.execute(m.Threat_Type.__table__.insert().values(
            ThreatTypeID=21, ThreatTypeName="Dup type", ThreatCategoryID=1,
            IsActive=True, IsDeleted=False))
        s.execute(m.Threat_Type.__table__.insert().values(
            ThreatTypeID=22, ThreatTypeName="Dup type", ThreatCategoryID=2,
            IsActive=True, IsDeleted=False))
        for cid, ptype, name in ((ghost_cid, "Ghost type", "APT-G"),
                                 (ambig_cid, "Dup type", "APT-D"),
                                 (legacy_cid, None, "APT-L")):
            s.execute(m.Threat_Candidate_Review.__table__.insert().values(
                CandidateID=cid, TenantID="t", EntityID="86", SessionID=SID,
                ProposedCategory=None, ProposedType=ptype, ProposedName=name,
                Status=CandidateStatus.pending, ThreatTypeID=None,
                CreatedAt=_now(), CandidateKind=str(CandidateKind.actor), CreatedBy="sara"))
        s.commit()
        for cid in (ghost_cid, ambig_cid, legacy_cid):
            res = accept_mod.resolve_candidate(s, dict(dal.get_candidate(s, cid)),
                                               "admin-bob", approve=True)
            assert res.won and res.type_id is None  # approved, but no link target claimed
        s.commit()
    c = _counts(Session)
    assert c["actors"] == 3 and c["links"] == 0  # all three created, none linked


def test_losing_approve_rolls_back_all_master_writes(monkeypatch):
    """The CAS-race fix: an approve that loses (the card was already resolved) raises its 409
    INSIDE the transaction, so the whole thing rolls back — the loser's actor mint and link
    must NOT survive alongside the rival's 'rejected' verdict."""
    from contextlib import contextmanager

    from app.api import admin as admin_mod

    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    cid = str(uuid.uuid4())
    with Session() as s:
        s.execute(m.Threat_Type.__table__.insert().values(
            ThreatTypeID=7, ThreatTypeName="Some type", IsActive=True, IsDeleted=False))
        s.execute(m.Threat_Candidate_Review.__table__.insert().values(
            CandidateID=cid, TenantID="t", EntityID="86", SessionID=SID,
            ProposedCategory=None, ProposedType="Some type", ProposedName="APT-X",
            Status=CandidateStatus.rejected,  # the rival's reject already landed — lost race
            ReviewedBy="rival-admin", ReviewedAt=_now(), ThreatTypeID=7,
            CreatedAt=_now(), CandidateKind=str(CandidateKind.actor), CreatedBy="sara"))
        s.commit()

    @contextmanager
    def _db_session():
        s = Session()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()

    monkeypatch.setattr(admin_mod, "db_session", _db_session)
    with pytest.raises(accept_mod.AcceptConflict):
        admin_mod._resolve_and_respond(cid, SimpleNamespace(user_id="admin-bob"), approve=True)

    c = _counts(Session)
    assert c["actors"] == 0 and c["links"] == 0  # the loser's mints were ERASED, not committed
    with Session() as s:
        card = dal.get_candidate(s, cid)
    assert card["Status"] == str(CandidateStatus.rejected)   # the rival's verdict stands
    assert card["ReviewedBy"] == "rival-admin"


def test_list_kind_filter_is_sql_side_not_post_limit():
    """An actor card behind older threat cards must still be listable: kind filters BEFORE the
    LIMIT. (The old Python filter after LIMIT returned zero actor rows forever here.)"""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    with Session() as s:
        for i in range(3):  # three OLDER threat cards (one a NULL-kind legacy row)
            s.execute(m.Threat_Candidate_Review.__table__.insert().values(
                CandidateID=str(uuid.uuid4()), TenantID="t", EntityID="86", SessionID=SID,
                ProposedCategory="Spoofing", ProposedType="T", ProposedName=f"Threat {i}",
                Status=CandidateStatus.pending,
                CreatedAt=datetime(2026, 8, 1, i, tzinfo=UTC),
                CandidateKind=None if i == 0 else str(CandidateKind.threat), CreatedBy="sara"))
        s.execute(m.Threat_Candidate_Review.__table__.insert().values(
            CandidateID=str(uuid.uuid4()), TenantID="t", EntityID="86", SessionID=SID,
            ProposedCategory=None, ProposedType="T", ProposedName="APT-X",
            Status=CandidateStatus.pending, CreatedAt=_now(),
            CandidateKind=str(CandidateKind.actor), CreatedBy="sara"))
        s.commit()
        actor_rows = dal.list_pending_candidates(s, limit=2, kind=CandidateKind.actor)
        threat_rows = dal.list_pending_candidates(s, limit=10, kind=CandidateKind.threat)
        all_rows = dal.list_pending_candidates(s, limit=10)
    assert [r["ProposedName"] for r in actor_rows] == ["APT-X"]  # visible despite limit=2
    assert len(threat_rows) == 3   # NULL-kind legacy row counts as 'threat'
    assert len(all_rows) == 4


def test_list_status_filter_is_sql_side_not_post_limit():
    """The rejected-identity blacklist is enumerable: status filters BEFORE the LIMIT, so a
    rejected card behind older pending cards is still listable. The filter is Status='rejected'
    exactly — an accepted card must not leak in — and the default stays pending-only."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    with Session() as s:
        for i in range(3):  # three OLDER pending threat cards
            s.execute(m.Threat_Candidate_Review.__table__.insert().values(
                CandidateID=str(uuid.uuid4()), TenantID="t", EntityID="86", SessionID=SID,
                ProposedCategory="Spoofing", ProposedType="T", ProposedName=f"Threat {i}",
                Status=CandidateStatus.pending,
                CreatedAt=datetime(2026, 8, 1, i, tzinfo=UTC),
                CandidateKind=str(CandidateKind.threat), CreatedBy="sara"))
        for status, name in ((CandidateStatus.accepted, "APT-Accepted"),
                             (CandidateStatus.rejected, "APT-Rejected")):
            s.execute(m.Threat_Candidate_Review.__table__.insert().values(
                CandidateID=str(uuid.uuid4()), TenantID="t", EntityID="86", SessionID=SID,
                ProposedCategory=None, ProposedType="T", ProposedName=name,
                Status=status, CreatedAt=_now(),
                CandidateKind=str(CandidateKind.actor), CreatedBy="sara"))
        s.commit()
        rejected_rows = dal.list_pending_candidates(s, limit=2, status=CandidateStatus.rejected)
        default_rows = dal.list_pending_candidates(s, limit=10)
    # visible despite limit=2; the accepted card never leaks into the blacklist view
    assert [r["ProposedName"] for r in rejected_rows] == ["APT-Rejected"]
    assert [r["ProposedName"] for r in default_rows] == ["Threat 0", "Threat 1", "Threat 2"]


def test_same_accept_paraphrases_queue_one_card(monkeypatch):
    """In-batch dedup keys on the SAME folded generic identity as the cross-session layer:
    two paraphrases grounding to one generic name queue ONE threat card, not two."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    # Both names fold to the generic "Tampered firmware in meters" under the stub triage.
    _seed_threat(Session, SID)
    _seed_threat(Session, SID, threat_type="Firmware tampering (variant)",
                 threat_name="Tampered firmware in meters")
    _run_promotion(Session, monkeypatch)

    c = _counts(Session)
    kinds = sorted(r["CandidateKind"] for r in c["candidates"])
    assert kinds == [str(CandidateKind.threat)]  # ONE threat card, not two


def test_actor_approve_falls_back_when_grounded_type_is_dead(monkeypatch):
    """A card grounded to a type that was soft-deleted AFTER queue time must not link to the
    corpse: the liveness check falls through to the by-name lookup — linking the name's active
    successor when one exists, else creating the actor unlinked."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    succ_cid, orphan_cid = str(uuid.uuid4()), str(uuid.uuid4())
    with Session() as s:
        s.execute(m.Threat_Type.__table__.insert().values(  # the retired original
            ThreatTypeID=7, ThreatTypeName="Some type", IsActive=True, IsDeleted=True))
        s.execute(m.Threat_Type.__table__.insert().values(  # its active same-name successor
            ThreatTypeID=9, ThreatTypeName="Some type", IsActive=True, IsDeleted=False))
        for cid, ptype in ((succ_cid, "Some type"), (orphan_cid, "Gone type")):
            s.execute(m.Threat_Candidate_Review.__table__.insert().values(
                CandidateID=cid, TenantID="t", EntityID="86", SessionID=SID,
                ProposedCategory=None, ProposedType=ptype, ProposedName=f"APT-{cid[:4]}",
                Status=CandidateStatus.pending, ThreatTypeID=7,  # both grounded to the corpse
                CreatedAt=_now(), CandidateKind=str(CandidateKind.actor), CreatedBy="sara"))
        s.commit()
        res_succ = accept_mod.resolve_candidate(s, dict(dal.get_candidate(s, succ_cid)),
                                                "admin-bob", approve=True)
        res_orphan = accept_mod.resolve_candidate(s, dict(dal.get_candidate(s, orphan_cid)),
                                                  "admin-bob", approve=True)
        s.commit()
    assert res_succ.won and res_succ.type_id == 9    # name resolution found the live successor
    assert res_orphan.won and res_orphan.type_id is None  # no live match anywhere -> unlinked
    with Session() as s:
        links = s.execute(select(m.ThreatType_ThreatActor_Map.__table__)).mappings().all()
        succ_card = dal.get_candidate(s, succ_cid)
        orphan_card = dal.get_candidate(s, orphan_cid)
    assert [lk["ThreatTypeID"] for lk in links] == [9]  # never the soft-deleted 7
    # The resolved CARD records the link OUTCOME, not the stale queue-time grounding: the
    # linked card shows its real target, the unlinked card shows NULL — never the dead id 7.
    assert succ_card["ThreatTypeID"] == 9
    assert orphan_card["ThreatTypeID"] is None


# ---------------------------------------------------------------------------
# Actor parity (plan eager-swimming-acorn, actor-generation phase): actors follow the same
# generate -> recognize -> gate approach threat types use.


def test_spelling_variant_resolves_to_existing_actor_no_card(monkeypatch):
    """Duplicate band: 'APT X' when 'APT-X' exists IS the same actor (normalized-identity tier
    of the banded triage) — no card, no second master row."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    with Session() as s:
        s.execute(m.Threat_Actor.__table__.insert().values(
            ThreatActorID=1, ThreatActorName="APT-X", IsCapable=1,
            IsActive=True, IsDeleted=False, Source="seed"))
        s.commit()
    _seed_threat(Session, SID, actors=("APT X",))
    _run_promotion(Session, monkeypatch)

    c = _counts(Session)
    assert c["actors"] == 1  # still just the seeded row — never a near-duplicate sibling
    assert [r["CandidateKind"] for r in c["candidates"]] == [str(CandidateKind.threat)]


def test_junk_actor_name_never_automints(monkeypatch):
    """Junk hygiene at the parse boundary, BOTH switch positions: filler ('Unknown') and
    letterless text ('###') are the model saying 'no actor identified' — dropped with a log
    at extraction (the same boundary where threat names pass clean_library_name), so they
    neither card nor mint, ever."""
    for auto in (False, True):
        engine = _engine()
        Session = sessionmaker(bind=engine, future=True)
        monkeypatch.setattr(get_settings(), "promotion_auto_approve_enabled", auto)
        _seed_threat(Session, SID, actors=("Unknown", "###"))
        _run_promotion(Session, monkeypatch)

        c = _counts(Session)
        assert c["actors"] == 0, f"auto={auto}"
        actor_cards = [r for r in c["candidates"]
                       if r["CandidateKind"] == str(CandidateKind.actor)]
        assert actor_cards == [], f"auto={auto}: filler must never reach the queue"


def test_actor_approve_strips_wrapping_junk(monkeypatch):
    """Approving a card queued as '\"APT-Nova\"' stores the spelling WITHOUT the wrapping
    quotes — the same rule the auto-mint path applies (clean_library_name's lesson)."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    cid = str(uuid.uuid4())
    with Session() as s:
        s.execute(m.Threat_Type.__table__.insert().values(
            ThreatTypeID=7, ThreatTypeName="Some type", IsActive=True, IsDeleted=False))
        s.execute(m.Threat_Candidate_Review.__table__.insert().values(
            CandidateID=cid, TenantID="t", EntityID="86", SessionID=SID,
            ProposedCategory=None, ProposedType=None, ProposedName='"APT-Nova"',
            Status=CandidateStatus.pending, ThreatTypeID=7,
            CreatedAt=_now(), CandidateKind=str(CandidateKind.actor), CreatedBy="sara"))
        s.commit()
        res = accept_mod.resolve_candidate(s, dict(dal.get_candidate(s, cid)),
                                           "admin-bob", approve=True)
        assert res.won
        s.commit()
    with Session() as s:
        stored = s.execute(select(m.Threat_Actor.ThreatActorName)).scalar()
    assert stored == "APT-Nova"  # wrapping quotes never become the stored spelling


def test_threat_approve_audit_carries_kind(monkeypatch):
    """The candidate_reconciled audit row for a THREAT approval names its kind, like the
    actor-approve and reject paths already did."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    cid = str(uuid.uuid4())
    with Session() as s:
        s.execute(m.Threat_Category.__table__.insert().values(
            ThreatCategoryID=4, ThreatCategoryName="Information Disclosure",
            IsActive=True, IsDeleted=False))
        s.execute(m.Threat_Candidate_Review.__table__.insert().values(
            CandidateID=cid, TenantID="t", EntityID="86", SessionID=SID,
            ProposedCategory="Information Disclosure", ProposedType="Novel type",
            ProposedName="Novel threat of X", ProposedGenericName="Novel threat",
            Status=CandidateStatus.pending, ThreatTypeID=None,
            CreatedAt=_now(), CandidateKind=str(CandidateKind.threat), CreatedBy="sara"))
        s.commit()
        res = accept_mod.resolve_candidate(s, dict(dal.get_candidate(s, cid)), "admin-bob",
                                           approve=True)
        assert res.won
        s.commit()
    with Session() as s:
        detail = json.loads(s.execute(select(m.Scenario_Audit.DetailJSON)).scalar())
    assert detail["kind"] == str(CandidateKind.threat)


def test_promotion_failure_persists_nothing_retry_files_once(monkeypatch):
    """Retry-parity pin: a crash at the END of the filing step (the audit insert, AFTER the
    candidate insert already executed) rolls back BOTH kinds' cards together; re-running the
    same unit — exactly what the retry clerk does — then files each kind exactly once."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _seed_threat(Session, SID)
    _stub_triage(monkeypatch)
    with Session() as s:
        real_execute = s.execute

        def exploding_audit(stmt, *a, **k):
            if getattr(stmt, "table", None) is not None \
                    and stmt.table.name == m.Scenario_Audit.__table__.name:
                raise RuntimeError("simulated crash during filing")
            return real_execute(stmt, *a, **k)

        monkeypatch.setattr(s, "execute", exploding_audit)
        with pytest.raises(RuntimeError):
            accept_mod._add_unverified_threats_to_library(s, _session_mapping(SID), [0], "sara")
        s.rollback()
    assert _counts(Session)["candidates"] == []  # nothing persisted — no partial filing
    _run_promotion(Session, monkeypatch)  # the clerk's retry = re-run the same unit
    kinds = sorted(r["CandidateKind"] for r in _counts(Session)["candidates"])
    assert kinds == [str(CandidateKind.threat)]


# ---------------------------------------------------------------------------
# Round-2 review pins: rejected-sticky under ON, Unicode identity, token-aware bands,
# identity-guarded writes, duplicate-resolve trace, ownerless-entry invariant.


def test_rejected_threat_identity_never_automints_under_switch_on(monkeypatch):
    """The threat twin: a rejected threat card's identity must not auto-mint a catalogue entry
    when the switch is ON — auto_approve is demoted to review, and the card dedup then
    suppresses a re-queue."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    with Session() as s:
        s.execute(m.Threat_Category.__table__.insert().values(
            ThreatCategoryID=4, ThreatCategoryName="Information Disclosure",
            IsActive=True, IsDeleted=False))
        s.commit()
    _seed_threat(Session, SID, actors=())
    _run_promotion(Session, monkeypatch)
    with Session() as s:
        card = next(r for r in _counts(Session)["candidates"]
                    if r["CandidateKind"] == str(CandidateKind.threat))
        assert accept_mod.resolve_candidate(s, dict(dal.get_candidate(s, card["CandidateID"])),
                                            "admin-bob", approve=False).won
        s.commit()

    monkeypatch.setattr(get_settings(), "promotion_auto_approve_enabled", True)
    # Force the auto_approve band (the stub's empty catalogue never reaches triage otherwise).
    monkeypatch.setattr(accept_mod, "_triage_generic_name",
                        lambda *a, **k: (accept_mod.TriageVerdict.auto_approve, None, 0.1))
    _stub_triage(monkeypatch)
    stub = accept_mod._prepare_triage
    monkeypatch.setattr(accept_mod, "_prepare_triage", lambda sess, llm, ss, rows: (
        lambda t: (t.entries.append({"id": 999, "name": "other", "type_id": 1,
                                     "sector_id": None, "cats": frozenset()}),
                   t.query_vecs.update({t.generic_by_tid[r["ThreatID"]]: [0.1] for r in rows}),
                   t)[-1])(stub(sess, llm, ss, rows)))
    sid2 = str(uuid.uuid4())
    _seed_threat(Session, sid2, actors=())
    with Session() as s:
        accept_mod._add_unverified_threats_to_library(s, _session_mapping(sid2), [0], "sara")
        s.commit()

    c = _counts(Session)
    assert c["catalogue"] == 0, "rejected identity must never auto-enter the catalogue"
    threat_cards = [r for r in c["candidates"] if r["CandidateKind"] == str(CandidateKind.threat)]
    assert len(threat_cards) == 1  # only the original, rejected card


def test_approve_reuses_existing_actor_by_identity(monkeypatch):
    """Identity-guarded approval: approving a card for 'APT NOVA' when master already holds
    'APT-Nova' reuses that row (and links it) — never a normalized twin."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    cid = str(uuid.uuid4())
    with Session() as s:
        s.execute(m.Threat_Type.__table__.insert().values(
            ThreatTypeID=7, ThreatTypeName="Some type", IsActive=True, IsDeleted=False))
        s.execute(m.Threat_Actor.__table__.insert().values(
            ThreatActorID=1, ThreatActorName="APT-Nova", IsCapable=1,
            IsActive=True, IsDeleted=False, Source="seed"))
        s.execute(m.Threat_Candidate_Review.__table__.insert().values(
            CandidateID=cid, TenantID="t", EntityID="86", SessionID=SID,
            ProposedCategory=None, ProposedType=None, ProposedName="APT NOVA",
            Status=CandidateStatus.pending, ThreatTypeID=7,
            CreatedAt=_now(), CandidateKind=str(CandidateKind.actor), CreatedBy="sara"))
        s.commit()
        res = accept_mod.resolve_candidate(s, dict(dal.get_candidate(s, cid)),
                                           "admin-bob", approve=True)
        assert res.won
        s.commit()
    c = _counts(Session)
    assert c["actors"] == 1, "must reuse the existing identity, never mint a twin"
    assert c["links"] == 1
    with Session() as s:
        link = s.execute(select(m.ThreatType_ThreatActor_Map.__table__)).mappings().one()
    assert (link["ThreatTypeID"], link["ThreatActorID"]) == (7, 1)


def test_ownerless_catalogue_match_off_never_writes_null_type_pair(monkeypatch):
    """Switch OFF + an auto_reject match onto an OWNERLESS legacy catalogue entry: the row
    must stay untouched (never a (ThreatTypeID NULL, ThreatCatalogueID real) pair) and the
    proposal fails toward the human as a review card."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    tid = _seed_threat(Session, SID, actors=())
    monkeypatch.setattr(accept_mod, "get_llm", lambda: None)
    monkeypatch.setattr(accept_mod, "_triage_generic_name",
                        lambda *a, **k: (accept_mod.TriageVerdict.auto_reject, 77, 0.99))
    monkeypatch.setattr(accept_mod, "_prepare_triage", lambda sess, llm, ss, rows: SimpleNamespace(
        entries=[{"id": 77, "name": "Ownerless entry", "type_id": None,
                  "sector_id": None, "cats": frozenset({4})}],
        catalogue_vecs={"Ownerless entry": [1.0]},
        query_vecs={(r["ThreatName"] or "").replace("smart meters", "meters"): [1.0]
                    for r in rows},
        generic_by_tid={r["ThreatID"]: (r["ThreatName"] or "").replace("smart meters", "meters")
                        for r in rows},
        sector_ids=[]))
    with Session() as s:
        accept_mod._add_unverified_threats_to_library(s, _session_mapping(SID), [0], "sara")
        s.commit()

    with Session() as s:
        row = s.execute(select(m.Identified_Threat.ThreatTypeID,
                               m.Identified_Threat.ThreatCatalogueID)
                        .where(m.Identified_Threat.ThreatID == tid)).one()
    assert tuple(row) == (None, None), "the forbidden (NULL type, real catalogue) pair"
    kinds = [r["CandidateKind"] for r in _counts(Session)["candidates"]]
    assert kinds == [str(CandidateKind.threat)]  # failed toward the human


# ---------------------------------------------------------------------------
# Scale optimization (10K-20K+ actors): capped/cached/relevance-ordered vocabulary hint
# (dal.active_actor_names) and the trigram-shortlisted accept-time triage
# (accept_actors._triage_actor_name). Each test pins a specific finding from the design
# review, not just "it still works" — the exact regressions a plausible-looking
# implementation could reintroduce.


def _index_table(actor_table):
    """Test helper: build both indices the way _preload_actor_memo does, so every
    _triage_actor_name test call exercises the real two-index shortlist, not just one."""
    from app.pipeline import accept_actors as aa
    return aa._build_trigram_index(actor_table), aa._build_token_index(actor_table)


if __name__ == "__main__":
    print("run via pytest")
