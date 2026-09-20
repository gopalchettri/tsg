"""A scenario's identity must survive promote-to-library.

IdentityHash is folded from a threat's CURRENT library ids, and promote-to-library rewrites those
ids on an AI-found threat (it links the threat to the catalogue row it just minted). Everything
that later asks "which scenario is this?" by re-folding that hash therefore got a different answer
than the rows on disk carry — while the rows themselves never changed.

Two consequences, both fixed and both pinned below:

  * a regeneration stamped its rewrite with the NEW identity and then retired "whatever active row
    has it" — which was nothing, leaving TWO live versions of one scenario, each separately
    acceptable, so one risk could reach the register twice with two remediation plans;
  * "generate next set" recomputed the threat's identity, failed to match its own scenario's
    stored hash, and served the same threat a second time.

The fix in both places is the same: use the identity already stored rather than re-deriving it
from data that moved underneath it.
"""
from __future__ import annotations

import json
import uuid

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker
from test_accept_any_version import HASH_10, _engine, _now, _seed_session

from app.core.enums import ScenarioStatus
from app.db import dal
from app.db import models as m
from app.pipeline import scoping, tasks

#: What promotion leaves behind: the same threat, now carrying the catalogue id it was linked to.
#: `_dedup_key` prefers that id over the type/name pair, so the fold lands somewhere else entirely.
_TID = str(uuid.uuid4())
_INFO_AFTER_PROMOTION = {"threat_id": _TID, "catalogue_id": 77, "threat_type_id": 5,
                         "threat_type": "Data exfiltration", "threat_name": "USB export"}


def _scored(threat_id: str = _TID) -> scoping.Scored:
    return scoping.Scored(threat_id=threat_id, score=9.5, rank=1, selected=True,
                        reason="verified library match")


def _row(sid: str, scoped_id: str, *, identity: str | None):
    return tasks._build_scenario_output_row(
        scoped_id, sid, "t", 0, {"scenario_title": "rewrite", "scenario_statement": "s"}, {},
        2, "86", "u1", _INFO_AFTER_PROMOTION, scenario_number=1, source="generated",
        span=(_now(), _now()), identity=identity)


def test_a_rewrite_keeps_its_targets_identity_and_a_fresh_row_folds_its_own():
    """The row builder's two modes, side by side: a regeneration is handed the identity its target
    carries, while a brand-new scenario folds one from the threat as it stands."""
    sid = str(uuid.uuid4())
    inherited = _row(sid, str(uuid.uuid4()), identity=HASH_10)
    folded = _row(sid, str(uuid.uuid4()), identity=None)

    assert inherited["IdentityHash"] == HASH_10
    assert folded["IdentityHash"] == dal.identity_hash(sid, 0, _INFO_AFTER_PROMOTION)
    assert folded["IdentityHash"] != HASH_10, (
        "the fold really does move after a promotion — which is why a rewrite must not re-fold")


def test_a_regeneration_retires_the_version_it_replaced_after_a_promotion():
    """End to end through the real reconcile: promote, then regenerate. The old version must end
    up superseded and the rewrite must point back at it — not sit beside it as a second live
    version of one scenario, which is how one risk got two accepted versions and two plans."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid = _seed_session(Session)
    old_scoped, new_scoped = str(uuid.uuid4()), str(uuid.uuid4())
    old_id = str(uuid.uuid4())
    with Session() as s:
        s.execute(m.Scoped_Threat.__table__.insert().values(
            ScopedThreatID=old_scoped, SessionID=sid, TenantID="t", EntityID="86", SubsystemID=0,
            ThreatID=_TID, Score=9.5, ScopeRank=1, Selected=1, Superseded=0, CreatedAt=_now()))
        s.execute(m.Threat_Scenario.__table__.insert().values(
            ScenarioID=old_id, SessionID=sid, TenantID="t", EntityID="86", UserID="u1",
            SubsystemID=0, ScopedThreatID=old_scoped, Status=str(ScenarioStatus.complete),
            ScenarioJSON=json.dumps({"scenario_title": "phishing"}),
            Accepted=1, Superseded=0, IdentityHash=HASH_10, ScenarioNumber=1,
            GenerationEpoch=1, CreatedAt=_now()))
        s.commit()

    target = tasks.RegenTarget(scenario_id=old_id, threat_id=_TID, scoped_threat_id=old_scoped,
                            scenario_number=1, identity_hash=HASH_10)
    with Session() as s:
        assert tasks._reconcile_targeted_regen(
            s, sid, 0, "t", "86", "u1",
            pairs=[(_scored(), new_scoped, target)],
            scenarios={new_scoped: ({"scenario_title": "usb export"}, {}, (_now(), _now()))},
            enriched={_TID: _INFO_AFTER_PROMOTION}, epoch=2, task_id="task-1",
            regen_mode=True) is True
        s.commit()

    with Session() as s:
        rows = {str(r["ScenarioID"]): r for r in s.execute(
            select(m.Threat_Scenario.ScenarioID, m.Threat_Scenario.Superseded,
                m.Threat_Scenario.Accepted, m.Threat_Scenario.IdentityHash,
                m.Threat_Scenario.ReplacesScenarioID)
            .where(m.Threat_Scenario.SessionID == sid)).mappings()}
    new_id = next(oid for oid in rows if oid != old_id)
    assert rows[old_id]["Superseded"] == 1, "the version being replaced is retired"
    assert rows[old_id]["Accepted"] == 1, "its decision is untouched — only accept may move that"
    assert rows[new_id]["Superseded"] == 0
    assert rows[new_id]["IdentityHash"] == HASH_10, "the rewrite is the same scenario"
    assert str(rows[new_id]["ReplacesScenarioID"]) == old_id, "and says which version it replaced"


def test_next_set_leaves_alone_a_threat_that_already_has_a_scenario():
    """The other half of the same drift. The threat's scenario is on screen — accepted, even — so
    "generate next set" must not serve it again just because its identity now folds elsewhere."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid = _seed_session(Session)
    scoped_id = str(uuid.uuid4())
    with Session() as s:
        s.execute(m.Identified_Threat.__table__.insert().values(
            ThreatID=_TID, SessionID=sid, SubsystemID=0, ThreatCategory="Exfiltration",
            ThreatType="Data exfiltration", ThreatName="USB export",
            ThreatTypeID=5, ThreatCatalogueID=77,  # stamped by promote-to-library
            GroundingStatus="verified", Superseded=0, CreatedAt=_now()))
        s.execute(m.Scoped_Threat.__table__.insert().values(
            ScopedThreatID=scoped_id, SessionID=sid, TenantID="t", EntityID="86", SubsystemID=0,
            ThreatID=_TID, Score=9.5, ScopeRank=1, Selected=1, Superseded=0, CreatedAt=_now()))
        s.execute(m.Threat_Scenario.__table__.insert().values(
            ScenarioID=str(uuid.uuid4()), SessionID=sid, TenantID="t", EntityID="86", UserID="u1",
            SubsystemID=0, ScopedThreatID=scoped_id, Status=str(ScenarioStatus.complete),
            ScenarioJSON=json.dumps({"scenario_title": "usb export"}),
            # Written BEFORE the promotion, so it carries the identity of that moment.
            Accepted=1, Superseded=0, IdentityHash=HASH_10, ScenarioNumber=1,
            GenerationEpoch=1, CreatedAt=_now()))
        s.commit()

    with Session() as s:
        assert dal.identity_hash(sid, 0, _INFO_AFTER_PROMOTION) != HASH_10, (
            "precondition: the fold has moved, or this test proves nothing")
        assert dal.next_unserved_unique_threats(s, sid, 0, 5) == []
