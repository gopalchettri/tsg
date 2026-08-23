"""P3 gate: a threat's actors are ALWAYS real library rows — the LLM never names an adversary.

Three branches, all of which must yield library names or nothing:
  1. the matched Threat_Type has LINKED actors      -> those, validated=True
  2. the matched type has NO linked actors          -> nearest library match, validated=False
  3. no actor rows exist at all                     -> [] (never an invented name)

Plus the prompt-side guarantee: the Stage-1 contract no longer asks for actors, so a model
that volunteers some is ignored rather than trusted.
"""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import models as m
from app.pipeline import embeddings, prompts
from app.pipeline.grounding import get_allowed_actor_names, nearest_library_actors


@pytest.fixture(autouse=True)
def _isolated_embeddings(monkeypatch):
    """In-memory embedding store: a real local Mongo would otherwise serve real-width vectors
    for names that exist in the live seed, and this test would write fakes into it."""
    monkeypatch.setenv("TSG_EMBEDDING_STORE", "memory")
    embeddings._L1.clear()
    embeddings._MATRIX.clear()
    yield
    embeddings._L1.clear()
    embeddings._MATRIX.clear()


class FakeLLM:
    def embed(self, texts, kind=None):
        return [[float(len(t) % 7), 1.0] for t in texts]


def _engine():
    engine = create_engine("sqlite://")
    for tbl in (m.Threat_Actor, m.ThreatType_ThreatActor_Map, m.Threat_Type):
        tbl.__table__.create(engine)
    return engine


def _seed_actors(s, *names):
    for i, n in enumerate(names, start=1):
        s.execute(m.Threat_Actor.__table__.insert().values(
            ThreatActorID=i, ThreatActorName=n, IsCapable=1, IsActive=True, IsDeleted=False))


def test_linked_actors_are_ordered_and_deterministic():
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    with Session() as s:
        _seed_actors(s, "APT33", "Malicious insider", "Hacktivist")
        for aid in (3, 1):  # inserted out of order on purpose
            s.execute(m.ThreatType_ThreatActor_Map.__table__.insert().values(
                ThreatTypeID=7, ThreatActorID=aid))
        s.commit()
        first = get_allowed_actor_names(s, 7)
        second = get_allowed_actor_names(s, 7)
    # ThreatActorID order, not insertion or set order — temp-0 reruns must store identical JSON
    assert first == ["APT33", "Hacktivist"] == second


def test_inactive_and_deleted_actors_are_never_returned():
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    with Session() as s:
        _seed_actors(s, "APT33")
        s.execute(m.Threat_Actor.__table__.insert().values(
            ThreatActorID=2, ThreatActorName="Retired Group", IsCapable=1,
            IsActive=False, IsDeleted=True))
        for aid in (1, 2):
            s.execute(m.ThreatType_ThreatActor_Map.__table__.insert().values(
                ThreatTypeID=7, ThreatActorID=aid))
        s.commit()
        assert get_allowed_actor_names(s, 7) == ["APT33"]


def test_nearest_fallback_returns_only_real_library_rows():
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    with Session() as s:
        _seed_actors(s, "APT33", "Malicious insider", "Ransomware affiliate")
        s.commit()
        out = nearest_library_actors(s, FakeLLM(), "insider misuse of privileged access")
    assert out, "the fallback must never return empty while actors exist"
    assert set(out) <= {"APT33", "Malicious insider", "Ransomware affiliate"}
    assert "Malicious insider" in out       # keyword leg carries the exact token


def test_nearest_fallback_is_empty_when_the_actor_table_is():
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    with Session() as s:
        assert nearest_library_actors(s, FakeLLM(), "anything at all") == []


def test_nearest_fallback_ignores_a_blank_query():
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    with Session() as s:
        _seed_actors(s, "APT33")
        s.commit()
        assert nearest_library_actors(s, FakeLLM(), "   ") == []


def test_stage1_prompt_never_asks_for_actors():
    """The contract itself: no actors field, and no adversary-naming instruction."""
    messages = prompts.threats_prompt(
        "Water Pumping Station", {"asset_type": "Pumping Station"},
        [{"id": 1, "name": "SCADA HMI", "asset_type": "OT"}], max_threats=5)
    system = messages[0]["content"]
    assert "actors:[]" not in system
    assert "actors:" not in system
    assert "name the adversary" not in system
