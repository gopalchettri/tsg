"""Linking a promoted threat to the library row that already means the same thing.

promote-to-library dedups on exact spelling only, so three wordings of one threat minted three
rows — and because a minted row is born pending while grounding filters IsActive==True, the next
session cannot see it and mints another. Live damage: catalogue 647/648/649 under one type.

What this file pins:

1. A same-meaning row is REUSED, not re-minted — the whole point.
2. Reuse is bounded by the SAME calibrated bar grounding uses. Below it, promotion mints, because
   the measured alternative is merging "White-Box Optimization" into "Black-Box Optimization".
3. PENDING rows are candidates. That is the difference from grounding, whose IsActive filter is
   what created the ratchet in the first place.
4. Deleted rows are not candidates, and a stored catalogue id short-circuits the whole thing.
5. The reranker failing NEVER fails a promotion — it mints, exactly as before.
6. A reuse that would give two live threats in one session the same catalogue id is REFUSED: they
   would fold to one IdentityHash through the `cat:` rung and one scenario could retire the other.
7. TYPES are never matched this way. Measured, type names cannot separate synonyms from opposites
   ("Obtain Capabilities" vs "Develop Capabilities" reranks 99.8), so a novel type still mints.
"""
from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy.orm import sessionmaker
from test_accept_any_version import _engine, _now, _seed_session

from app.core.config import get_settings
from app.core.enums import ScenarioStatus
from app.db import dal
from app.db import models as m
from app.pipeline import library_match, promote

TYPE_ID = 28
ORIGINAL = 647


class _Reranker:
    """Scores by a lookup table keyed on the candidate name; everything else is noise-tier.

    The numbers are the REAL ones from scripts/measure_library_name_similarity.py against the live
    library, so the fixture cannot drift into a fantasy where separation is easier than it is.
    """

    def __init__(self, table: dict[str, float] | None = None, boom: bool = False):
        self.table = table or {}
        self.boom = boom
        self.calls = 0

    def rerank(self, query, docs, *, model=None):
        self.calls += 1
        if self.boom:
            raise RuntimeError("reranker down")
        return [self.table.get(d, 3.0) for d in docs]


@pytest.fixture
def db(monkeypatch):
    Session = sessionmaker(bind=_engine(), future=True)
    # The calibrated bar is a DB read; pin it so these tests assert the RULE, not the calibration.
    monkeypatch.setattr(library_match.grounding, "resolve_thresholds",
                        lambda sess, llm, s: type("T", (), {"value": 75.0})())
    return Session


def _seed_library(s, *, rows: list[tuple[int, str]], deleted: set[int] | None = None) -> None:
    s.execute(m.Threat_Type.__table__.insert().values(
        ThreatTypeID=TYPE_ID, ThreatTypeName="Identity Impersonation", ThreatCategoryID=None,
        IsActive=True, IsDeleted=False, Source="functional_team_excel", CreatedAt=_now()))
    for cid, name in rows:
        s.execute(m.Threat_Catalogue.__table__.insert().values(
            ThreatCatalogueID=cid, ThreatTypeID=TYPE_ID, ThreatName=name,
            # Pending on purpose: this is what grounding cannot see, and what promote must.
            IsActive=False, IsDeleted=cid in (deleted or set()),
            Source="promote-api", CreatedAt=_now()))
    s.commit()


def _seed_threat(Session, *, name: str, catalogue_id: int | None = None,
                type_id: int | None = TYPE_ID, session_id: str | None = None) -> tuple[str, str]:
    """An accepted scenario whose threat carries the given library ids -> (session, scenario)."""
    sid = session_id or _seed_session(Session)
    tid, scoped_id, oid = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    info = {"threat_id": tid, "catalogue_id": catalogue_id, "threat_type_id": type_id,
            "threat_type": "Identity Impersonation", "threat_name": name}
    with Session() as s:
        s.execute(m.Identified_Threat.__table__.insert().values(
            ThreatID=tid, SessionID=sid, SubsystemID=0, ThreatCategory="Spoofing",
            ThreatType="Identity Impersonation", ThreatName=name, GenericName=name,
            ThreatTypeID=type_id, ThreatCatalogueID=catalogue_id, ThreatCategoryID=None,
            GroundingStatus="unverified", Superseded=0, CreatedAt=_now()))
        s.execute(m.Scoped_Threat.__table__.insert().values(
            ScopedThreatID=scoped_id, SessionID=sid, TenantID="t", EntityID="86", SubsystemID=0,
            ThreatID=tid, Score=9.0, ScopeRank=1, Selected=1, Superseded=0, CreatedAt=_now()))
        s.execute(m.Threat_Scenario.__table__.insert().values(
            ScenarioID=oid, SessionID=sid, TenantID="t", EntityID="86", UserID="u1",
            SubsystemID=0, ScopedThreatID=scoped_id, Status=str(ScenarioStatus.complete),
            ScenarioJSON=json.dumps({"scenario_title": name, "scenario_statement": name}),
            Accepted=1, Superseded=0, IdentityHash=dal.identity_hash(sid, 0, info),
            ScenarioNumber=1, GenerationEpoch=1, CreatedAt=_now()))
        s.commit()
    return sid, oid


def _resolve(Session, sid: str, oid: str, llm) -> tuple[int, float] | None:
    """The route's two steps: probe inside a session, score outside it."""
    with Session() as s:
        row = dict(dal.load_session(s, sid))
        _out, threat = promote.load_scenario_and_threat(s, sid, oid)
        probe = library_match.probe(s, threat, asset_name=row.get("AssetName"),
                                    llm=llm, settings=get_settings())
    return library_match.pick(probe, llm)


def _promote(Session, sid: str, oid: str, reuse):
    with Session() as s:
        return promote.promote_scenario_to_library(s, dict(dal.load_session(s, sid)), oid,
                                                "curator", reuse)


def _catalogue_count(Session) -> int:
    with Session() as s:
        return s.query(m.Threat_Catalogue).count()


# ------------------------------------------------------------------ the one that matters

def test_a_differently_worded_duplicate_links_instead_of_minting(db):
    """647 vs 648 reranked 99.996 on the real library. The second wording must not become a row."""
    with db() as s:
        _seed_library(s, rows=[(ORIGINAL, "Impersonation of operator sessions")])
    sid, oid = _seed_threat(db, name="Impersonation of authorized control sessions")
    llm = _Reranker({"Impersonation of operator sessions": 99.996})

    reuse = _resolve(db, sid, oid, llm)
    assert reuse == (ORIGINAL, 99.996)

    result = _promote(db, sid, oid, reuse)
    assert result.threat["id"] == ORIGINAL
    assert result.threat["status"] == promote.EXISTING
    assert result.created_count == 0
    assert _catalogue_count(db) == 1, "the whole point: no twin was minted"


def test_the_pending_original_is_a_candidate(db):
    """The seeded row is IsActive=0. Grounding cannot see it — that blindness is what let the
    second wording look new — so promote looking at it IS the fix, not an oversight."""
    with db() as s:
        _seed_library(s, rows=[(ORIGINAL, "Impersonation of operator sessions")])
        assert not s.get(m.Threat_Catalogue, ORIGINAL).IsActive
    sid, oid = _seed_threat(db, name="Impersonation of authorized control sessions")
    assert _resolve(db, sid, oid, _Reranker({"Impersonation of operator sessions": 99.996}))


# ------------------------------------------------------------------ the bar

def test_a_below_bar_match_still_mints(db):
    """"White-Box Optimization" vs "Black-Box Optimization" reranked 0.613 on the real library:
    opposites, not synonyms. Anything under the calibrated bar must mint."""
    with db() as s:
        _seed_library(s, rows=[(ORIGINAL, "AML.T0043.000 White-Box Optimization")])
    sid, oid = _seed_threat(db, name="AML.T0043.001 Black-Box Optimization")
    llm = _Reranker({"AML.T0043.000 White-Box Optimization": 0.613})

    assert _resolve(db, sid, oid, llm) is None
    result = _promote(db, sid, oid, None)
    assert result.threat["status"] == promote.INSERTED
    assert _catalogue_count(db) == 2, "two genuinely different threats stay two rows"


def test_the_best_candidate_wins_not_the_first(db):
    with db() as s:
        _seed_library(s, rows=[(ORIGINAL, "Impersonation of operator sessions"),
                            (648, "Impersonation of authorized control sessions")])
    sid, oid = _seed_threat(db, name="Impersonation of authorized control or operator sessions")
    llm = _Reranker({"Impersonation of operator sessions": 84.2,
                    "Impersonation of authorized control sessions": 99.9})
    assert _resolve(db, sid, oid, llm) == (648, 99.9)


# ------------------------------------------------------------------ refusals

def test_a_stored_catalogue_id_short_circuits_the_probe(db):
    """Already a library threat: promote's stored-id branch owns this, and no reranker call
    should be paid for."""
    with db() as s:
        _seed_library(s, rows=[(ORIGINAL, "Impersonation of operator sessions")])
    sid, oid = _seed_threat(db, name="whatever", catalogue_id=ORIGINAL)
    llm = _Reranker()
    assert _resolve(db, sid, oid, llm) is None
    assert llm.calls == 0


def test_no_type_means_no_probe(db):
    """A threat with no type is about to MINT one, so there is no family to search. Types are
    deliberately out of scope — measured, their names cannot separate synonyms from opposites."""
    with db() as s:
        _seed_library(s, rows=[(ORIGINAL, "Impersonation of operator sessions")])
    sid, oid = _seed_threat(db, name="Something new", type_id=None)
    llm = _Reranker()
    assert _resolve(db, sid, oid, llm) is None
    assert llm.calls == 0


def test_a_deleted_row_is_not_a_candidate(db):
    with db() as s:
        _seed_library(s, rows=[(ORIGINAL, "Impersonation of operator sessions")],
                    deleted={ORIGINAL})
    sid, oid = _seed_threat(db, name="Impersonation of authorized control sessions")
    assert _resolve(db, sid, oid, _Reranker({"Impersonation of operator sessions": 99.9})) is None


def test_a_broken_reranker_mints_instead_of_failing_the_promotion(db):
    """Fail OPEN. A curator's click must not 5xx because a reranker is down; the cost is a
    duplicate row, which is visible and fixable."""
    with db() as s:
        _seed_library(s, rows=[(ORIGINAL, "Impersonation of operator sessions")])
    sid, oid = _seed_threat(db, name="Impersonation of authorized control sessions")
    assert _resolve(db, sid, oid, _Reranker(boom=True)) is None
    assert _promote(db, sid, oid, None).threat["status"] == promote.INSERTED


def test_a_reuse_that_would_collide_within_one_session_is_refused(db):
    """Two live threats in one (session, subsystem) sharing a catalogue id fold to ONE
    IdentityHash through the `cat:` rung, after which one scenario can retire the other — an
    accepted one included. Minting a duplicate is the lesser harm, so the fence prefers it."""
    with db() as s:
        _seed_library(s, rows=[(ORIGINAL, "Impersonation of operator sessions")])
    sid, _first = _seed_threat(db, name="Already linked", catalogue_id=ORIGINAL)
    _sid2, oid2 = _seed_threat(db, name="Impersonation of authorized control sessions",
                            session_id=sid)

    result = _promote(db, sid, oid2, (ORIGINAL, 99.9))
    assert result.threat["status"] == promote.INSERTED
    assert result.threat["id"] != ORIGINAL
    assert _catalogue_count(db) == 2


def test_a_reuse_is_recorded_in_the_audit_trail(db):
    """An automatic merge with no durable trace would be unreviewable. The response is gone once
    the caller stops reading it; Scenario_Audit is not."""
    with db() as s:
        _seed_library(s, rows=[(ORIGINAL, "Impersonation of operator sessions")])
    sid, oid = _seed_threat(db, name="Impersonation of authorized control sessions")
    _promote(db, sid, oid, (ORIGINAL, 99.996))
    with db() as s:
        row = s.query(m.Scenario_Audit).filter(
            m.Scenario_Audit.SessionID == sid).order_by(
            m.Scenario_Audit.CreatedAt.desc()).first()
    detail = json.loads(row.DetailJSON)
    assert detail["reused_catalogue_id"] == ORIGINAL
    assert detail["reuse_score"] == pytest.approx(100.0, abs=0.01)
