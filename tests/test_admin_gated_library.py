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
from app.core.enums import CandidateKind, CandidateStatus, TriageVerdict
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
            "SectorIDsJSON": "[]", "TuningJSON": None}


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
    """The core policy: novel type + novel actor, switch OFF -> ZERO master rows; one 'threat'
    card (ThreatTypeID NULL) + one 'actor' card, both stamped CreatedBy=the accepting user."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _seed_threat(Session, SID)
    _run_promotion(Session, monkeypatch)

    c = _counts(Session)
    assert c["types"] == 0 and c["catalogue"] == 0 and c["actors"] == 0 and c["links"] == 0
    kinds = sorted(r["CandidateKind"] for r in c["candidates"])
    assert kinds == [str(CandidateKind.actor), str(CandidateKind.threat)]
    threat_card = next(r for r in c["candidates"] if r["CandidateKind"] == str(CandidateKind.threat))
    actor_card = next(r for r in c["candidates"] if r["CandidateKind"] == str(CandidateKind.actor))
    assert threat_card["ThreatTypeID"] is None            # novel type: NOT minted, mints on approval
    assert threat_card["CreatedBy"] == "sara"
    assert actor_card["ProposedName"] == "APT-X"
    assert actor_card["ProposedCategory"] is None
    # The association is VISIBLE: the card names the type the actor was proposed for, so the
    # admin approves "APT-X for <type>", never a bare name with a hidden link behind it.
    assert actor_card["ProposedType"] == "Firmware supply-chain tampering"
    assert actor_card["CreatedBy"] == "sara"


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
    """A SECOND session proposing the same threat name AND the same actor files ZERO new
    cards — the cross-session pending-dedup (new; was memo-only before)."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _seed_threat(Session, SID)
    _run_promotion(Session, monkeypatch)
    n_before = len(_counts(Session)["candidates"])
    assert n_before == 2

    sid2 = str(uuid.uuid4())
    _seed_threat(Session, sid2)
    _run_promotion(Session, monkeypatch, sid=sid2)

    assert len(_counts(Session)["candidates"]) == n_before  # zero new cards, both kinds


def test_switch_on_full_auto_mints_everything_with_provenance(monkeypatch):
    """ON: the type is minted, the actor is AUTO-ADDED and linked, the session threat is
    back-filled — and every master row carries Source/CreatedAt/CreatedBy=the accepting user.
    (The empty stub catalogue keeps the NAME's verdict at `review`, so it still queues.)"""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    monkeypatch.setattr(get_settings(), "promotion_auto_approve_enabled", True)
    tid = _seed_threat(Session, SID)
    _run_promotion(Session, monkeypatch)

    c = _counts(Session)
    assert c["types"] == 1 and c["actors"] == 1 and c["links"] == 1
    with Session() as s:
        trow = s.execute(select(m.Threat_Type.__table__)).mappings().one()
        arow = s.execute(select(m.Threat_Actor.__table__)).mappings().one()
        backfilled = s.execute(select(m.Identified_Threat.ThreatTypeID)
                               .where(m.Identified_Threat.ThreatID == tid)).scalar()
    for row in (trow, arow):
        assert row["Source"] == "ai_auto_promoted"
        assert row["CreatedAt"] is not None
        assert row["CreatedBy"] == "sara"      # the accepting user, stamped on auto-adds
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
    assert kinds == [str(CandidateKind.actor), str(CandidateKind.threat)]  # one of each, not two


def test_actor_name_hygiene_at_the_parse_boundary(monkeypatch):
    """Dirty LLM actor strings are normalized ONCE where they're parsed: ' APT-X' (leading
    space) matches the existing master row instead of queueing a spurious card; blanks are
    dropped (an empty identity could never be deduped — it would re-queue every accept);
    ' New-Actor ' queues STRIPPED; a 600-char ramble is bounded to Threat_Actor's width so
    the batched card INSERT can never DataError on MSSQL."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    with Session() as s:
        s.execute(m.Threat_Actor.__table__.insert().values(
            ThreatActorID=1, ThreatActorName="APT-X", IsCapable=1,
            IsActive=True, IsDeleted=False, Source="seed"))
        s.commit()
    # The last fixture hits the slice boundary EXACTLY: strip is a no-op, [:200] ends on the
    # space at index 199 — only the trailing rstrip keeps the stored name canonical.
    _seed_threat(Session, SID, actors=(" APT-X", "", "   ", " New-Actor ", "R" * 600,
                                       "Q" * 199 + " " + "T" * 300))
    _run_promotion(Session, monkeypatch)

    c = _counts(Session)
    assert c["actors"] == 1  # switch OFF never mints — recognition is pinned by the card list below
    actor_cards = sorted(r["ProposedName"] for r in c["candidates"]
                         if r["CandidateKind"] == str(CandidateKind.actor))
    assert actor_cards == ["New-Actor", "Q" * 199, "R" * 200]  # stripped + bounded; blanks gone
    assert all(len(n) <= 200 and n == n.strip() for n in actor_cards)


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


def test_grounding_canonicalize_and_keep():
    """GAP A pin: a verified type's vocabulary corrects known spellings to the library's and
    KEEPS unknown names — grounding never silently drops a proposed actor anymore."""
    from app.pipeline import grounding
    out = grounding.canonicalize_actors(["nation state", "APT-Nova"], ["Nation State"])
    assert out == ["Nation State", "APT-Nova"]


def test_novel_actor_on_high_scoring_threat_still_queues(monkeypatch):
    """GAP B pin: a novel actor riding a WELL-MATCHED threat (score >= threshold) gets its
    review card even though the threat itself has no candidacy of its own."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    with Session() as s:
        s.execute(m.Threat_Type.__table__.insert().values(
            ThreatTypeID=1, ThreatTypeName="Firmware supply-chain tampering",
            IsActive=True, IsDeleted=False, Source="seed"))
        s.commit()
    _seed_threat(Session, SID, type_id=1, actors=("APT-Nova",), grounding_score=92.0)
    _run_promotion(Session, monkeypatch)

    c = _counts(Session)
    assert c["types"] == 1 and c["actors"] == 0 and c["links"] == 0  # nothing minted
    kinds = [r["CandidateKind"] for r in c["candidates"]]
    assert kinds == [str(CandidateKind.actor)]  # NO threat card — the score is above threshold
    card = c["candidates"][0]
    assert card["ProposedName"] == "APT-Nova"
    assert card["ThreatTypeID"] == 1  # the grounded id rides along for approve-time linking


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


def test_gray_zone_actor_queues_in_both_modes(monkeypatch):
    """Review band ('APTX' vs 'APT-X' ratio ~0.89, between the 0.80/0.95 knobs): a review card
    under BOTH switch positions — ON must not auto-mint gray-zone names, exactly as the threat
    path demotes them to review."""
    for auto in (False, True):
        engine = _engine()
        Session = sessionmaker(bind=engine, future=True)
        monkeypatch.setattr(get_settings(), "promotion_auto_approve_enabled", auto)
        with Session() as s:
            s.execute(m.Threat_Actor.__table__.insert().values(
                ThreatActorID=1, ThreatActorName="APT-X", IsCapable=1,
                IsActive=True, IsDeleted=False, Source="seed"))
            s.commit()
        _seed_threat(Session, SID, actors=("APTX",))
        _run_promotion(Session, monkeypatch)

        c = _counts(Session)
        assert c["actors"] == 1, f"auto={auto}: the gray zone must never mint"
        actor_cards = [r for r in c["candidates"]
                       if r["CandidateKind"] == str(CandidateKind.actor)]
        assert [r["ProposedName"] for r in actor_cards] == ["APTX"], f"auto={auto}"


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


def test_same_accept_spelling_variants_one_identity(monkeypatch):
    """'APT-Nova' and 'APT Nova' in ONE accept are ONE identity: switch OFF files one card;
    switch ON mints one master row (the second spelling resolves to the first's normalized
    identity — never a duplicate mint or a duplicate card)."""
    for auto, expect_actors, expect_cards in ((False, 0, 1), (True, 1, 0)):
        engine = _engine()
        Session = sessionmaker(bind=engine, future=True)
        monkeypatch.setattr(get_settings(), "promotion_auto_approve_enabled", auto)
        _seed_threat(Session, SID, actors=("APT-Nova",))
        _seed_threat(Session, SID, actors=("APT Nova",), threat_type="OT protocol abuse",
                     threat_name="Unauthenticated writes to PLC registers")
        _run_promotion(Session, monkeypatch)

        c = _counts(Session)
        assert c["actors"] == expect_actors, f"auto={auto}"
        actor_cards = [r for r in c["candidates"]
                       if r["CandidateKind"] == str(CandidateKind.actor)]
        assert len(actor_cards) == expect_cards, f"auto={auto}"


def test_near_opposite_actor_names_never_merge(monkeypatch):
    """Long labels one negation apart ('Insider with privileged access' vs 'Insider without
    privileged access', difflib ~0.95) must NEVER silently merge — similarity routes to a
    review card; only normalized spelling identity merges."""
    for auto in (False, True):
        engine = _engine()
        Session = sessionmaker(bind=engine, future=True)
        monkeypatch.setattr(get_settings(), "promotion_auto_approve_enabled", auto)
        with Session() as s:
            s.execute(m.Threat_Actor.__table__.insert().values(
                ThreatActorID=1, ThreatActorName="Insider with privileged access", IsCapable=1,
                IsActive=True, IsDeleted=False, Source="seed"))
            s.commit()
        _seed_threat(Session, SID, actors=("Insider without privileged access",))
        _run_promotion(Session, monkeypatch)

        c = _counts(Session)
        assert c["actors"] == 1, f"auto={auto}: never merged, never minted"
        actor_cards = [r for r in c["candidates"]
                       if r["CandidateKind"] == str(CandidateKind.actor)]
        assert [r["ProposedName"] for r in actor_cards] == \
            ["Insider without privileged access"], f"auto={auto}: must reach a human"


def test_switch_on_scored_row_mints_actor_only(monkeypatch):
    """ON + a well-matched (score 92) threat with a novel actor: the actor is minted (unlinked
    — a pre-existing type's actor set never grows at accept) and NOTHING threat-side happens:
    no new type, no catalogue entry, the threat row is not rewritten."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    monkeypatch.setattr(get_settings(), "promotion_auto_approve_enabled", True)
    with Session() as s:
        s.execute(m.Threat_Type.__table__.insert().values(
            ThreatTypeID=1, ThreatTypeName="Firmware supply-chain tampering",
            IsActive=True, IsDeleted=False, Source="seed"))
        s.commit()
    tid = _seed_threat(Session, SID, type_id=1, actors=("APT-Nova",), grounding_score=92.0)
    _run_promotion(Session, monkeypatch)

    c = _counts(Session)
    assert c["types"] == 1 and c["catalogue"] == 0, "scored row must not mint threat-side"
    assert c["actors"] == 1 and c["links"] == 0, "actor minted but never linked to a curated type"
    assert c["candidates"] == []
    with Session() as s:
        row = s.execute(select(m.Identified_Threat.ThreatTypeID, m.Identified_Threat.ThreatCatalogueID)
                        .where(m.Identified_Threat.ThreatID == tid)).one()
    assert tuple(row) == (1, None)  # the threat row itself is untouched


def test_rejected_actor_card_never_requeues(monkeypatch):
    """An admin's 'no' sticks: after rejecting the actor card, a later session proposing the
    same name (any spelling) files NO new card."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _seed_threat(Session, SID, actors=("APT-Nova",))
    _run_promotion(Session, monkeypatch)
    with Session() as s:
        card = next(r for r in _counts(Session)["candidates"]
                    if r["CandidateKind"] == str(CandidateKind.actor))
        res = accept_mod.resolve_candidate(s, dict(dal.get_candidate(s, card["CandidateID"])),
                                           "admin-bob", approve=False)
        assert res.won
        s.commit()

    sid2 = str(uuid.uuid4())
    _seed_threat(Session, sid2, actors=("APT NOVA",))  # spelling variant of the rejected name
    _run_promotion(Session, monkeypatch, sid=sid2)

    actor_cards = [r for r in _counts(Session)["candidates"]
                   if r["CandidateKind"] == str(CandidateKind.actor)]
    assert len(actor_cards) == 1  # still only the rejected one — no re-queue
    assert _counts(Session)["actors"] == 0


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


def test_second_type_same_actor_one_card(monkeypatch):
    """Association dedup: two threats (different type texts) proposing the same novel actor in
    ONE accept file exactly one card — the second (type, actor) association is deferred to the
    curator (logged), never double-carded and never silently lost."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _seed_threat(Session, SID, actors=("APT-Nova",))
    _seed_threat(Session, SID, actors=("APT-Nova",), threat_type="OT protocol abuse",
                 threat_name="Unauthenticated writes to PLC registers")
    _run_promotion(Session, monkeypatch)

    actor_cards = [r for r in _counts(Session)["candidates"]
                   if r["CandidateKind"] == str(CandidateKind.actor)]
    assert len(actor_cards) == 1


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
    assert kinds == [str(CandidateKind.actor), str(CandidateKind.threat)]


# ---------------------------------------------------------------------------
# Round-2 review pins: rejected-sticky under ON, Unicode identity, token-aware bands,
# identity-guarded writes, duplicate-resolve trace, ownerless-entry invariant.


def test_rejected_actor_never_automints_under_switch_on(monkeypatch):
    """THE round-2 headline: an admin's 'no' survives the master switch. After rejecting the
    actor card, a later accept under switch ON must NOT auto-mint the name (any spelling) —
    the suppression check runs BEFORE the mint branch."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _seed_threat(Session, SID, actors=("APT-Nova",))
    _run_promotion(Session, monkeypatch)
    with Session() as s:
        card = next(r for r in _counts(Session)["candidates"]
                    if r["CandidateKind"] == str(CandidateKind.actor))
        assert accept_mod.resolve_candidate(s, dict(dal.get_candidate(s, card["CandidateID"])),
                                            "admin-bob", approve=False).won
        s.commit()

    monkeypatch.setattr(get_settings(), "promotion_auto_approve_enabled", True)
    sid2 = str(uuid.uuid4())
    _seed_threat(Session, sid2, actors=("APT NOVA",))  # spelling variant of the rejected name
    _run_promotion(Session, monkeypatch, sid=sid2)

    c = _counts(Session)
    assert c["actors"] == 0, "switch ON must not override a recorded human rejection"
    actor_cards = [r for r in c["candidates"] if r["CandidateKind"] == str(CandidateKind.actor)]
    assert len(actor_cards) == 1  # still only the rejected card — no re-queue either


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


def test_non_latin_actor_name_reaches_the_queue(monkeypatch):
    """Unicode identity: a Cyrillic actor name is a NAME — it survives extraction, gets an
    identity, and queues as a card (the old ASCII-only key folded it to '' and dropped it)."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _seed_threat(Session, SID, actors=("Фэнси Бэр",))
    _run_promotion(Session, monkeypatch)

    actor_cards = [r for r in _counts(Session)["candidates"]
                   if r["CandidateKind"] == str(CandidateKind.actor)]
    assert [r["ProposedName"] for r in actor_cards] == ["Фэнси Бэр"]


def test_compound_seed_half_goes_to_review_not_novel(monkeypatch):
    """Token containment: 'Terrorist' against a library holding 'Terrorist/Extremist' is
    review, never novel — under ON it must card, not mint (character ratio alone read it as
    novel at 0.643 and would have auto-minted a near-duplicate of a seeded actor)."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    monkeypatch.setattr(get_settings(), "promotion_auto_approve_enabled", True)
    with Session() as s:
        s.execute(m.Threat_Actor.__table__.insert().values(
            ThreatActorID=1, ThreatActorName="Terrorist/Extremist", IsCapable=1,
            IsActive=True, IsDeleted=False, Source="seed"))
        s.commit()
    _seed_threat(Session, SID, actors=("Terrorist",))
    _run_promotion(Session, monkeypatch)

    c = _counts(Session)
    assert c["actors"] == 1, "never minted alongside its compound seed"
    actor_cards = [r for r in c["candidates"] if r["CandidateKind"] == str(CandidateKind.actor)]
    assert [r["ProposedName"] for r in actor_cards] == ["Terrorist"]


def test_numbered_group_spellings_one_identity_and_neighbor_goes_to_review(monkeypatch):
    """Letter↔digit boundary: 'APT41' IS 'APT-41' (identity — no card, no mint), while
    'APT28' against a library holding 'APT-29' is similar → review card, never a silent novel
    mint (the verdict no longer depends on an unrelated row's hyphen)."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    monkeypatch.setattr(get_settings(), "promotion_auto_approve_enabled", True)
    with Session() as s:
        s.execute(m.Threat_Actor.__table__.insert().values(
            ThreatActorID=1, ThreatActorName="APT-41", IsCapable=1,
            IsActive=True, IsDeleted=False, Source="seed"))
        s.execute(m.Threat_Actor.__table__.insert().values(
            ThreatActorID=2, ThreatActorName="APT-29", IsCapable=1,
            IsActive=True, IsDeleted=False, Source="seed"))
        s.commit()
    _seed_threat(Session, SID, actors=("APT41", "APT28"))
    _run_promotion(Session, monkeypatch)

    c = _counts(Session)
    assert c["actors"] == 2  # APT41 resolved to APT-41; APT28 carded, not minted
    actor_cards = [r for r in c["candidates"] if r["CandidateKind"] == str(CandidateKind.actor)]
    assert [r["ProposedName"] for r in actor_cards] == ["APT28"]


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


def test_duplicate_resolve_leaves_calibration_trace(monkeypatch):
    """A spelling variant resolved by normalized identity is the one decision that changes
    attribution — it must appear in the promotion_triage audit's actors array (verdict
    auto_reject, matched id), even though no card and no mint happen."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    with Session() as s:
        s.execute(m.Threat_Actor.__table__.insert().values(
            ThreatActorID=1, ThreatActorName="APT-Nova", IsCapable=1,
            IsActive=True, IsDeleted=False, Source="seed"))
        s.commit()
    _seed_threat(Session, SID, actors=("APT NOVA",))
    _run_promotion(Session, monkeypatch)

    with Session() as s:
        details = [json.loads(d) for d in
                   s.execute(select(m.Scenario_Audit.DetailJSON)).scalars() if d]
    triage = next(d for d in details if "actors" in d)
    assert triage["actors"] == [{"name": "APT NOVA", "verdict": "auto_reject", "ratio": 1.0,
                                 "matched_actor_id": 1, "matched_name": None}]


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


def _reset_actor_vocab_cache():
    dal._actor_vocab_cache = None


def test_active_actor_names_orders_by_relevance_with_deterministic_tiebreak(monkeypatch):
    """Most-linked-first, CreatedAt DESC, ThreatActorID as the FINAL deterministic tiebreak.
    Two actors tied on both link count (0) and CreatedAt must still resolve to the exact
    same top-N set on every call — the bug a plain 'order by count, created' (no ID
    tiebreak) would silently reintroduce once the cap boundary lands on a tie."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    monkeypatch.setattr(get_settings(), "actor_vocabulary_cap", 2)
    monkeypatch.setattr(get_settings(), "actor_vocabulary_cache_seconds", 0.0)  # force fresh query each call
    _reset_actor_vocab_cache()
    same_ts = _now()
    with Session() as s:
        s.execute(m.Threat_Type.__table__.insert().values(
            ThreatTypeID=1, ThreatTypeName="T1", IsActive=True, IsDeleted=False))
        s.execute(m.Threat_Type.__table__.insert().values(
            ThreatTypeID=2, ThreatTypeName="T2", IsActive=True, IsDeleted=False))
        s.execute(m.Threat_Actor.__table__.insert().values(
            ThreatActorID=1, ThreatActorName="Nation-state/APT", IsCapable=1, IsActive=True,
            IsDeleted=False, Source="seed", CreatedAt=same_ts))
        s.execute(m.ThreatType_ThreatActor_Map.__table__.insert().values(
            ThreatTypeID=1, ThreatActorID=1, CreatedAt=same_ts))
        s.execute(m.ThreatType_ThreatActor_Map.__table__.insert().values(
            ThreatTypeID=2, ThreatActorID=1, CreatedAt=same_ts))
        # B and C: TIED at 0 links, TIED at the same CreatedAt — only ThreatActorID can break it.
        s.execute(m.Threat_Actor.__table__.insert().values(
            ThreatActorID=2, ThreatActorName="Malicious insider", IsCapable=1, IsActive=True,
            IsDeleted=False, Source="seed", CreatedAt=same_ts))
        s.execute(m.Threat_Actor.__table__.insert().values(
            ThreatActorID=3, ThreatActorName="Hacktivist", IsCapable=1, IsActive=True,
            IsDeleted=False, Source="seed", CreatedAt=same_ts))
        s.commit()
        first = dal.active_actor_names(s)
        second = dal.active_actor_names(s)
    assert first == second, "identical inputs must yield the identical cap boundary every call"
    assert first[0] == "Nation-state/APT"          # most-linked wins the top slot
    assert first[1] == "Malicious insider"          # tie broken by ThreatActorID, not chance


def test_active_actor_names_cache_hit_issues_no_query(monkeypatch):
    """Within the TTL window, a second call must not re-run the underlying query."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _reset_actor_vocab_cache()
    monkeypatch.setattr(get_settings(), "actor_vocabulary_cache_seconds", 30.0)
    real_query = dal._query_active_actor_names
    calls = []
    monkeypatch.setattr(dal, "_query_active_actor_names",
                        lambda sess, cap: (calls.append(1), real_query(sess, cap))[1])
    with Session() as s:
        s.execute(m.Threat_Actor.__table__.insert().values(
            ThreatActorID=1, ThreatActorName="APT-X", IsCapable=1, IsActive=True,
            IsDeleted=False, Source="seed", CreatedAt=_now()))
        s.commit()
        dal.active_actor_names(s)
        dal.active_actor_names(s)
    assert len(calls) == 1


def test_active_actor_names_serves_stale_on_refresh_failure(monkeypatch):
    """A refresh that raises AFTER a successful cache fill serves the STALE list rather than
    propagate — a hint-list refresh hiccup must never fail an entire find_threats() call."""
    dal._actor_vocab_cache = (["APT-X"], 0.0)  # 0.0 forces the TTL to read as expired
    monkeypatch.setattr(get_settings(), "actor_vocabulary_cache_seconds", 30.0)
    monkeypatch.setattr(dal, "_query_active_actor_names",
                        lambda sess, cap: (_ for _ in ()).throw(RuntimeError("db hiccup")))
    engine2 = _engine()
    Session2 = sessionmaker(bind=engine2, future=True)
    with Session2() as s:
        assert dal.active_actor_names(s) == ["APT-X"]


def test_active_actor_names_cold_start_failure_returns_empty(monkeypatch):
    """A cold cache (never successfully populated) whose first read also fails must return
    [] rather than raise — the exact input prompts.py already treats as 'unseeded table'."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    _reset_actor_vocab_cache()
    monkeypatch.setattr(get_settings(), "actor_vocabulary_cache_seconds", 30.0)
    monkeypatch.setattr(dal, "_query_active_actor_names",
                        lambda sess, cap: (_ for _ in ()).throw(RuntimeError("db hiccup")))
    with Session() as s:
        assert dal.active_actor_names(s) == []


def _index_table(actor_table):
    """Test helper: build both indices the way _preload_actor_memo does, so every
    _triage_actor_name test call exercises the real two-index shortlist, not just one."""
    from app.pipeline import accept_actors as aa
    return aa._build_trigram_index(actor_table), aa._build_token_index(actor_table)


def test_trigram_index_short_circuits_unrelated_names(monkeypatch):
    """A proposed name sharing NO trigram AND NO whole token with any candidate is provably
    unrelated — _actor_similarity must never even be called for it."""
    from app.pipeline import accept_actors as aa
    norm = aa._norm("Nation-state/APT")
    actor_table = [(1, "Nation-state/APT", norm, set(norm.split()))]
    trigram_index, token_index = _index_table(actor_table)
    calls = []
    monkeypatch.setattr(aa, "_actor_similarity", lambda *a: calls.append(a) or 0.0)
    tn = SimpleNamespace(triage_auto_approve_cosine=0.80)
    fate = aa._triage_actor_name(aa._norm("Zzyxqw Corp"), actor_table, trigram_index,
                                token_index, tn)
    assert calls == []
    assert fate.verdict == TriageVerdict.auto_approve  # novel — nothing shares a trigram/token


def test_trigram_index_finds_true_near_duplicate():
    """A proposed name that fully CONTAINS an existing actor as a word ('Terrorist' inside
    'Terrorist/Extremist') must still be found and scored — never silently skipped to
    'novel' because the shortlist missed it. (This case shares many trigrams too — the
    adversarial short-token case below is what the trigram index alone cannot catch.)"""
    from app.pipeline import accept_actors as aa
    norm = aa._norm("Terrorist/Extremist")
    actor_table = [(1, "Terrorist/Extremist", norm, set(norm.split()))]
    trigram_index, token_index = _index_table(actor_table)
    tn = SimpleNamespace(triage_auto_approve_cosine=0.80)
    fate = aa._triage_actor_name(aa._norm("Terrorist"), actor_table, trigram_index,
                                token_index, tn)
    assert fate.verdict == TriageVerdict.review


def test_token_index_catches_what_trigrams_alone_would_miss():
    """THE regression a design review found by running the real code, not by inspection:
    'AQ PK' vs 'PK Brigade AQ' has token containment 1.0 (both 'aq' and 'pk' are shared
    whole words) but shares ZERO trigrams — a 1-2 character shared word's only trigrams
    cross into whichever word sits next to it, and that neighbor differs between the two
    strings ('aq ' / ' pk' vs ' aq' / 'pk '). Trigram-only shortlisting silently read this
    as 'novel'; the token index is the fix. Pins the exact case, not just the general idea."""
    from app.pipeline import accept_actors as aa
    norm = aa._norm("PK Brigade AQ")
    actor_table = [(1, "PK Brigade AQ", norm, set(norm.split()))]
    trigram_index, token_index = _index_table(actor_table)
    assert not (trigram_index.keys() & aa._trigrams(aa._norm("AQ PK"))), (
        "test assumption broken: this pair should share zero trigrams")
    tn = SimpleNamespace(triage_auto_approve_cosine=0.80)
    fate = aa._triage_actor_name(aa._norm("AQ PK"), actor_table, trigram_index, token_index, tn)
    assert fate.verdict == TriageVerdict.review, "must reach a human, not silently mint a duplicate"
    assert fate.matched_id == 1


def test_short_query_found_via_token_index_not_full_scan():
    """A normalized query under 3 characters ('AI') produces zero trigrams, but its single
    token IS indexed — it must resolve via the token index, not require a full-table scan."""
    from app.pipeline import accept_actors as aa
    norm = aa._norm("AI")
    actor_table = [(1, "AI", norm, set(norm.split()))]
    trigram_index, token_index = _index_table(actor_table)
    assert aa._trigrams(norm) == set(), "test assumption: 'ai' produces no trigrams"
    tn = SimpleNamespace(triage_auto_approve_cosine=0.80)
    fate = aa._triage_actor_name(aa._norm("AI"), actor_table, trigram_index, token_index, tn)
    assert fate.verdict == TriageVerdict.auto_reject
    assert fate.matched_id == 1


def test_degenerate_empty_query_falls_back_to_full_scan():
    """The true full-scan fallback: a query normalizing to '' (no trigrams AND no tokens)
    can't be shortlisted by either index at all — it must still degrade safely (defensive;
    the real pipeline already filters this out via the `if not aident: continue` guard in
    _queue_or_mint_row_actors before this function is ever called)."""
    from app.pipeline import accept_actors as aa
    norm = aa._norm("Hacktivist")
    actor_table = [(1, "Hacktivist", norm, set(norm.split()))]
    trigram_index, token_index = _index_table(actor_table)
    tn = SimpleNamespace(triage_auto_approve_cosine=0.80)
    fate = aa._triage_actor_name("", actor_table, trigram_index, token_index, tn)
    assert fate.verdict == TriageVerdict.auto_approve  # no crash, no false match


def test_mid_accept_mint_visible_to_trigram_index(monkeypatch):
    """A novel actor minted mid-accept must be found by a LATER, merely-similar proposal in
    the SAME accept via the trigram index — proving actor_table and trigram_index are kept
    in sync at the mint site, not just at preload. If the sync were broken, the second
    proposal would find zero shortlisted candidates and mint a SECOND, redundant actor."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    monkeypatch.setattr(get_settings(), "promotion_auto_approve_enabled", True)
    _seed_threat(Session, SID, actors=("Shadowfen",))
    _seed_threat(Session, SID, actors=("Shadowfen Group",), threat_type="OT protocol abuse",
                 threat_name="Unauthenticated writes to PLC registers")
    _run_promotion(Session, monkeypatch)

    c = _counts(Session)
    assert c["actors"] == 1, "the second proposal must resolve against the FIRST mint"
    with Session() as s:
        arow = s.execute(select(m.Threat_Actor.ThreatActorName)).scalar()
    assert arow == "Shadowfen"
    actor_cards = [r for r in c["candidates"] if r["CandidateKind"] == str(CandidateKind.actor)]
    assert [r["ProposedName"] for r in actor_cards] == ["Shadowfen Group"]


def test_rolled_back_mint_leaves_no_ghost_for_a_later_accept(monkeypatch):
    """The exact hazard _preload_actor_memo's docstring names as the reason the trigram/token
    indices are rebuilt fresh every accept, not cached across accepts: a mint that rolls back
    must be invisible to a LATER, independent accept — that accept's own
    _preload_actor_memo call re-reads the committed DB state, so it can never see a "ghost"
    actor the first accept's savepoint erased."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    monkeypatch.setattr(get_settings(), "promotion_auto_approve_enabled", True)
    _seed_threat(Session, SID, actors=("Rimefall",))
    _stub_triage(monkeypatch)
    with Session() as s:
        real_execute = s.execute

        def exploding_audit(stmt, *a, **k):
            if getattr(stmt, "table", None) is not None \
                    and stmt.table.name == m.Scenario_Audit.__table__.name:
                raise RuntimeError("simulated crash AFTER the mint already executed")
            return real_execute(stmt, *a, **k)

        monkeypatch.setattr(s, "execute", exploding_audit)
        with pytest.raises(RuntimeError):
            accept_mod._add_unverified_threats_to_library(s, _session_mapping(SID), [0], "sara")
        s.rollback()
    assert _counts(Session)["actors"] == 0, "the mint must be fully rolled back, not half-committed"

    sid2 = str(uuid.uuid4())
    _seed_threat(Session, sid2, actors=("Rimefall",))
    _run_promotion(Session, monkeypatch, sid=sid2)

    c = _counts(Session)
    assert c["actors"] == 1, "the second, independent accept must mint fresh — never treat " \
        "the rolled-back mint as an existing row to resolve against"
    with Session() as s:
        arow = s.execute(select(m.Threat_Actor.ThreatActorName)).scalar()
    assert arow == "Rimefall"


if __name__ == "__main__":
    print("run via pytest")
