"""P3 gate: a threat's actors are ALWAYS real library rows — the LLM never names an adversary.

Post-2026-08 catalogue reversal the actor source of truth is `Threat_Actor`, and curated
links live on the TYPE (ThreatType_ThreatActor_Map) — every catalogue threat under one
type shares the actor list. Three branches, all of which must yield library rows or nothing:

  1. name-verified catalogue match WITH type-map rows -> those pairs, actors_validated=True
  2. verified match with NO map rows (or no catalogue match at all)
                                          -> nearest library actors, actors_validated=False
  3. no live actor rows exist             -> [] (never an invented name)

Plus the persistence round-trip: the (names, ids) pairs grounding produced must come back
intact from the stored ThreatActorsJSON blob — promotion links by id, so a silent pairing
drift would curate the wrong adversary into the shared library.
"""
from __future__ import annotations

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.enums import GroundingStatus
from app.db import models as m
from app.pipeline import embeddings
from app.pipeline.grounding import (
    find_threat_in_library,
    nearest_library_actors,
    stored_actor_ids,
    stored_actors,
)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    """In-memory embedding store (a real local Mongo would serve real-width vectors and this
    test would write fakes into it), and an env-pinned match threshold so resolve_thresholds
    never touches the Grounding_Calibration_Run table (absent from these SQLite fixtures)."""
    monkeypatch.setenv("TSG_EMBEDDING_STORE", "memory")
    monkeypatch.setenv("TSG_GROUNDING_MATCH_THRESHOLD", "75.0")
    embeddings._L1.clear()
    embeddings._MATRIX.clear()
    yield
    embeddings._L1.clear()
    embeddings._MATRIX.clear()


class FakeLLM:
    """Deterministic embed; rerank scores 100 only on an exact text match, so each test
    chooses its own verified/unverified branch by wording alone."""

    def embed(self, texts, kind=None):
        return [[float(len(t) % 7), float(sum(map(ord, t)) % 11), 1.0] for t in texts]

    def rerank(self, query, docs):
        return [100.0 if d == query else 5.0 for d in docs]


def _engine():
    engine = create_engine("sqlite://")
    for tbl in (m.Threat_Category, m.Threat_Type, m.Threat_Catalogue, m.Threat_Actor,
                m.ThreatType_ThreatActor_Map, m.Threat_Catalogue_Category_Map):
        tbl.__table__.create(engine)
    return engine


def _session(engine):
    return sessionmaker(bind=engine, future=True)()


def _seed_actors(s, *names, deleted=()):
    for i, n in enumerate(names, start=1):
        s.execute(m.Threat_Actor.__table__.insert().values(
            ThreatActorID=i, ThreatActorName=n,
            IsActive=True, IsDeleted=n in deleted))


def _seed_type_and_catalogue(s, *, threat_name="Credential theft", catalogue_id=10):
    s.execute(m.Threat_Category.__table__.insert().values(
        ThreatCategoryID=1, ThreatCategoryName="Spoofing", IsActive=True, IsDeleted=False))
    s.execute(m.Threat_Type.__table__.insert().values(
        ThreatTypeID=7, ThreatTypeName="Spoofing", ThreatCategoryID=1,
        IsActive=True, IsDeleted=False))
    s.execute(m.Threat_Catalogue.__table__.insert().values(
        ThreatCatalogueID=catalogue_id, ThreatTypeID=7, ThreatName=threat_name,
        IsActive=True, IsDeleted=False))


_PROPOSED = {"category": "Spoofing", "type": "Spoofing", "name": "Credential theft"}


# --- nearest_library_actors: the fallback leg ------------------------------------------------

def test_nearest_fallback_returns_only_live_library_rows():
    """The fallback must never launder a deleted row or an invented name into a threat —
    every (id, name) it returns has to be a LIVE Threat_Actor row, id included, because
    promotion later links by that id."""
    engine = _engine()
    with _session(engine) as s:
        _seed_actors(s, "APT33", "Malicious insider", "Retired Group",
                    deleted=("Retired Group",))
        s.commit()
        out = nearest_library_actors(s, FakeLLM(), "insider misuse of privileged access")
    assert out, "the fallback must never return empty while live actors exist"
    assert {nm for _aid, nm in out} <= {"APT33", "Malicious insider"}
    assert "Retired Group" not in {nm for _aid, nm in out}
    assert all(isinstance(aid, int) for aid, _nm in out), "every actor must carry its real key"


def test_nearest_fallback_is_empty_when_the_actor_table_is():
    """Branch 3 of the gate: an empty library yields [], never a hallucinated adversary."""
    engine = _engine()
    with _session(engine) as s:
        assert nearest_library_actors(s, FakeLLM(), "anything at all") == []


def test_nearest_fallback_ignores_a_blank_query():
    """A blank query has no signal to rank by — returning arbitrary rows would attach random
    adversaries to a threat that described none."""
    engine = _engine()
    with _session(engine) as s:
        _seed_actors(s, "APT33")
        s.commit()
        assert nearest_library_actors(s, FakeLLM(), "   ") == []


# --- find_threat_in_library: which actor source each branch trusts ---------------------------

def test_verified_catalogue_match_serves_curated_type_map_actors():
    """Branch 1: a name-verified catalogue match must serve the matched TYPE's own map rows
    (name-sorted, live only) and mark them validated — this is the only path allowed to claim
    curated provenance."""
    engine = _engine()
    with _session(engine) as s:
        _seed_type_and_catalogue(s)
        _seed_actors(s, "Zeta Group", "Alpha Crew", "Ghost Cell", deleted=("Ghost Cell",))
        for aid in (1, 2, 3):  # includes the deleted actor — it must be filtered out
            s.execute(m.ThreatType_ThreatActor_Map.__table__.insert().values(
                ThreatTypeID=7, ThreatActorID=aid))
        s.commit()
        r = find_threat_in_library(s, FakeLLM(), _PROPOSED)
    assert r.status == GroundingStatus.verified
    assert r.catalogue_id == 10, "catalogue_id set <=> name-match verified"
    assert r.actors == ["Alpha Crew", "Zeta Group"], "name-sorted for stable display"
    assert r.actor_ids == [2, 1], "ids ride along in the same order as the names"
    assert r.actors_validated is True


def test_verified_match_without_map_rows_falls_back_unvalidated():
    """Branch 2: a catalogue type a curator has not yet linked actors to still gets library
    actors — but actors_validated=False records that this is a similarity guess, so nothing
    downstream may write it back as a curated link."""
    engine = _engine()
    with _session(engine) as s:
        _seed_type_and_catalogue(s)   # no map rows on purpose
        _seed_actors(s, "APT33", "Malicious insider")
        s.commit()
        r = find_threat_in_library(s, FakeLLM(), _PROPOSED)
    assert r.status == GroundingStatus.verified
    assert r.catalogue_id == 10
    assert r.actors, "a threat is never actor-less while the library has actors"
    assert set(r.actors) <= {"APT33", "Malicious insider"}
    assert r.actors_validated is False
    assert len(r.actor_ids) == len(r.actors)


def test_unverified_type_yields_no_ids_and_unvalidated_library_actors():
    """An unverified type has no trusted library scope: no type_id, no catalogue_id — yet
    the actors still come from the library (never the model), flagged unvalidated."""
    engine = _engine()
    with _session(engine) as s:
        _seed_type_and_catalogue(s)
        _seed_actors(s, "APT33", "Malicious insider")
        s.commit()
        r = find_threat_in_library(s, FakeLLM(), {
            "category": "Spoofing", "type": "Quantum lattice disruption",
            "name": "Credential theft"})
    assert r.status == GroundingStatus.unverified
    assert r.type_id is None and r.catalogue_id is None
    assert set(r.actors) <= {"APT33", "Malicious insider"}
    assert r.actors_validated is False


# --- ThreatActorsJSON round-trip -------------------------------------------------------------

def test_stored_actor_pairs_round_trip_unchanged():
    """Promotion links by the STORED ids, not by re-resolving names — so the blob written at
    identification time must come back exactly, names and ids in lock-step order."""
    blob = json.dumps({"actors": ["Alpha Crew", "Zeta Group"], "actor_ids": [2, 1],
                    "validated": True})
    assert stored_actors(blob) == ["Alpha Crew", "Zeta Group"]
    assert stored_actor_ids(blob) == [2, 1]


def test_stored_actor_ids_refuse_a_mismatched_or_legacy_blob():
    """A length mismatch means the pairing can no longer be trusted — [] forces callers back
    to name resolution instead of linking a name to another actor's id. A legacy blob written
    before actor_ids existed degrades the same way."""
    mismatched = json.dumps({"actors": ["A", "B"], "actor_ids": [5], "validated": True})
    assert stored_actor_ids(mismatched) == []
    assert stored_actors(mismatched) == ["A", "B"], "names still serve — only the ids are void"
    legacy = json.dumps({"actors": ["A", "B"], "validated": False})
    assert stored_actor_ids(legacy) == []
    assert stored_actors(legacy) == ["A", "B"]
