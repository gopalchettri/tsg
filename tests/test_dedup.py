"""Catalogue-level dedup → unique top-N scenarios (no duplicates), scoped per
(session, subsystem). Covers the app-level selection pass, the structural IdentityHash
backstop (SubsystemID + dedup_key folded in), and the config count binding.

The deterministic ranker itself is unchanged — that stays pinned by test_slice.py's
test_scoping_deterministic and the scoping-rule suite.
"""
from __future__ import annotations

import hashlib
import json
import uuid

import pytest
from sqlalchemy import insert, select
from sqlalchemy.exc import IntegrityError

from app.db import models as m
from app.db.dal import now
from app.pipeline.scoping import Scored
from app.pipeline.tasks import _dedup_key, _normalize, _select_unique_top_n, find_threats, write_scenarios
from tests.conftest import DEFAULT_ASSET_CONTEXT, StubLLM
from tests.test_slice import SUB, SUB2, _active_count, _seed_session

_TID = "33333333-3333-4333-8333-333333333333"


# --- stub models producing the shapes dedup has to handle -------------------
class _DupCatalogueLLM(StubLLM):
    """Two proposals that BOTH ground to the seeded type 10 / catalogue 20 — the
    catalogue-level duplicate the whole feature exists to collapse."""

    def chat(self, messages, *, model=None, temperature=None):
        if "stride threats" in messages[0]["content"].lower():
            from app.pipeline.llm import Provenance
            out = [{"category": "Tampering", "type": "Firmware Tampering", "name": "Bootloader implant",
                    "actors": ["Hacker"]}] * 2
            return json.dumps(out), Provenance(model="stub")
        return super().chat(messages, model=model)


class _UngroundedLLM(StubLLM):
    """Two proposals that match NONE of the seeded masters (both grounded `flagged`,
    ThreatTypeID/ThreatCatalogueID NULL) — so dedup falls back to normalized text."""

    def __init__(self, proposals):
        self._proposals = proposals

    def chat(self, messages, *, model=None, temperature=None):
        if "stride threats" in messages[0]["content"].lower():
            from app.pipeline.llm import Provenance
            return json.dumps(self._proposals), Provenance(model="stub")
        return super().chat(messages, model=model)


def _scenarios(db, sid):
    return db.execute(select(m.Threat_Scenario_Output)
                    .where(m.Threat_Scenario_Output.SessionID == sid,
                            m.Threat_Scenario_Output.Superseded == 0)).scalars().all()


def _run(db, llm, sub=SUB, session=None):
    session = session or _seed_session(db, subs=[sub] if sub is SUB else [SUB, SUB2])
    threats, _ = find_threats(db, session, sub, DEFAULT_ASSET_CONTEXT, llm, _TID)
    db.commit()
    write_scenarios(db, session, sub, DEFAULT_ASSET_CONTEXT, threats, llm, _TID)
    db.commit()
    return session


# --- _dedup_key / _normalize (pure) -----------------------------------------
def test_dedup_key_precedence_and_null_name():
    assert _dedup_key({"catalogue_id": 20, "threat_type_id": 10, "threat_type": "X"}) == "cat:20"
    assert _dedup_key({"catalogue_id": None, "threat_type_id": 10}) == "type:10"
    # ThreatType is NOT NULL, ThreatName is nullable — None must not crash, folds as ""
    assert _dedup_key({"threat_type": "Firmware Tampering", "threat_name": None}) == \
        "txt:" + _normalize("Firmware Tampering\x1f")


def test_normalize_folds_punctuation_case_and_whitespace():
    assert _normalize("OTA-Poisoning!") == _normalize("ota   poisoning")
    assert _normalize("Alpha Threat") != _normalize("Beta Threat")


# --- unique-top-N selection pass (pure) -------------------------------------
def test_select_unique_top_n_frees_the_slot_and_yields_n_distinct():
    # rank order: a(cat10), b(cat10 dup of a), c(cat11), d(cat12); threshold already applied
    scored = [Scored("a", 80.0, 1, True, "grounding=grounded"),
            Scored("b", 80.0, 2, True, "grounding=grounded"),
            Scored("c", 70.0, 3, True, "grounding=grounded"),
            Scored("d", 60.0, 4, True, "grounding=grounded")]
    enriched = {"a": {"catalogue_id": 10}, "b": {"catalogue_id": 10},
                "c": {"catalogue_id": 11}, "d": {"catalogue_id": 12}}
    _select_unique_top_n(scored, enriched, top_n=2)
    by = {s.threat_id: s for s in scored}
    assert by["a"].selected is True
    assert by["b"].selected is False and "duplicate" in by["b"].reason        # dup never eats a slot
    assert by["c"].selected is True                                            # got the freed slot
    assert by["d"].selected is False and "beyond top-2" in by["d"].reason      # count now full
    assert sum(s.selected for s in scored) == 2                               # exactly N DISTINCT


def test_select_unique_top_n_never_promotes_a_threshold_excluded_threat():
    # a threat scoring already excluded stays excluded and never consumes a slot
    scored = [Scored("x", 40.0, 1, False, "below score threshold (55.0)"),
            Scored("y", 70.0, 2, True, "grounding=grounded")]
    _select_unique_top_n(scored, {"x": {"catalogue_id": 1}, "y": {"catalogue_id": 2}}, top_n=1)
    assert scored[0].selected is False and "below score threshold" in scored[0].reason
    assert scored[1].selected is True


# --- end-to-end: one scenario per unique catalogue --------------------------
def test_same_catalogue_threats_yield_one_scenario_other_demoted(db):
    session = _run(db, _DupCatalogueLLM())
    sid = session["SessionID"]
    assert len(_scenarios(db, sid)) == 1                                       # only the unique winner
    assert _active_count(db, m.Identified_Threat) == 2                         # both proposals still audited

    scoped = db.execute(select(m.Scoped_Threat)
                    .where(m.Scoped_Threat.SessionID == sid,
                            m.Scoped_Threat.Superseded == 0)).scalars().all()
    assert len(scoped) == 2                                                    # provenance for BOTH kept
    demoted = [s for s in scoped if s.Selected == 0]
    assert len(demoted) == 1
    assert demoted[0].Reason == "duplicate of higher-ranked threat"
    assert demoted[0].Score == 70.0 and demoted[0].ScopeRank in (1, 2)         # full audit row, not a stub


def test_different_catalogue_threats_are_not_merged(db):
    from tests.test_cascade import _TwoThreatLLM                               # type 10/cat 20 + type 11/cat 21
    session = _run(db, _TwoThreatLLM())
    assert len(_scenarios(db, session["SessionID"])) == 2


def test_ungrounded_distinct_names_not_merged(db):
    session = _run(db, _UngroundedLLM([
        {"category": "Tampering", "type": "Mystery Alpha", "name": "Alpha threat", "actors": []},
        {"category": "Tampering", "type": "Mystery Beta", "name": "Beta threat", "actors": []}]))
    assert len(_scenarios(db, session["SessionID"])) == 2


def test_ungrounded_identical_normalized_text_merged(db):
    session = _run(db, _UngroundedLLM([
        {"category": "Tampering", "type": "Zeta-Mystery!", "name": "Rare  Event", "actors": []},
        {"category": "Tampering", "type": "zeta mystery", "name": "rare event", "actors": []}]))
    assert len(_scenarios(db, session["SessionID"])) == 1                      # same txt: key → collapsed


# --- structural backstop: SubsystemID + dedup_key folded into IdentityHash --
def test_sibling_subsystems_same_catalogue_both_get_scenarios(db):
    # The same catalogue-20 threat in two sibling subsystems must NOT cross-suppress:
    # SubsystemID is folded into IdentityHash, so the (SessionID, IdentityHash) unique
    # index sees two distinct hashes, not a collision.
    session = _seed_session(db, subs=[SUB, SUB2])
    for sub in (SUB, SUB2):
        _run(db, StubLLM(), sub=sub, session=session)
    rows = _scenarios(db, session["SessionID"])
    assert len(rows) == 2
    assert {r.SubsystemID for r in rows} == {SUB["id"], SUB2["id"]}
    assert rows[0].IdentityHash != rows[1].IdentityHash


def test_double_active_scenario_with_same_folded_identity_is_rejected(db):
    session = _seed_session(db)
    sid = session["SessionID"]
    identity = hashlib.sha256(f"{sid}|{SUB['id']}|cat:20".encode()).hexdigest()
    base = dict(SessionID=sid, TenantID="default", SubsystemID=SUB["id"], Status="complete",
                Accepted=0, Superseded=0, IdentityHash=identity, GenerationEpoch=1, CreatedAt=now())
    db.execute(insert(m.Threat_Scenario_Output).values(
        OutputID=str(uuid.uuid4()), ScopedThreatID=str(uuid.uuid4()), **base))
    with pytest.raises(IntegrityError):
        db.execute(insert(m.Threat_Scenario_Output).values(
            OutputID=str(uuid.uuid4()), ScopedThreatID=str(uuid.uuid4()), **base))
    db.rollback()


# --- regen must never be blocked by dedup -----------------------------------
def test_targeted_regen_of_a_catalogue_duplicate_is_not_demoted(db):
    # Two same-catalogue threats exist; a targeted regen of the SECOND (which a full run
    # would demote as a duplicate) must still generate — dedup runs only when
    # target_threat_ids is None.
    session = _seed_session(db)
    threats, _ = find_threats(db, session, SUB, DEFAULT_ASSET_CONTEXT, _DupCatalogueLLM(), _TID)
    db.commit()
    target = threats[1]["threat_id"]
    provs = write_scenarios(db, session, SUB, DEFAULT_ASSET_CONTEXT, threats, _DupCatalogueLLM(), _TID,
                            target_threat_ids={target})
    assert len(provs) == 1                                                     # regenerated, not withheld


# --- config: scenario count bound to threat count ---------------------------
def test_config_rejects_scenario_count_above_threat_count():
    from pydantic import ValidationError

    from app.core.config import Settings

    with pytest.raises(ValidationError):
        Settings(scoping_top_n=20, max_threats_per_subsystem=12)
    Settings(scoping_top_n=12, max_threats_per_subsystem=12)                   # equal is allowed
