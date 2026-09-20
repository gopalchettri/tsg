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
from datetime import timedelta

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from test_accept_any_version import HASH_10, _engine, _now, _seed_session

from app.core.enums import ScenarioStatus, StageStatus, SubsystemLevel
from app.db import dal
from app.db import models as m
from app.pipeline import scoping, tasks


class _FakeLLM:
    """Same shape as test_scenario_batch_finalize_order's — one canned scenario, no network."""

    def chat(self, messages, temperature=None, expected_type=None, **kwargs):
        return json.dumps({
            "scenario_title": "Firmware swapped at the loading bay",
            "scenario_statement": "An insider exchanges the vendor package before installation.",
            "risk_statement": "Loss of control at the pumping station.",
            "supporting_systems_involved": [],
        }), None

    def embed(self, texts, kind=None):
        return [[0.0] * 8 for _ in texts]

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


def test_a_target_with_no_stored_identity_is_still_retired():
    """The case identity-matching cannot serve at all.

    A row written before scenarios carried an IdentityHash has nothing to match: the rewrite folds
    a fresh hash, the identity-matching retire finds no row holding it, and the target stays live
    beside its own replacement — two versions of one scenario, both separately acceptable, which
    is the outcome all of this exists to prevent. Naming the row by id cannot drift or miss."""
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
            ScenarioJSON=json.dumps({"scenario_title": "legacy"}),
            Accepted=0, Superseded=0, IdentityHash=None, ScenarioNumber=1,
            GenerationEpoch=1, CreatedAt=_now()))
        s.commit()

    target = tasks.RegenTarget(scenario_id=old_id, threat_id=_TID, scoped_threat_id=old_scoped,
                            scenario_number=1, identity_hash=None)
    with Session() as s:
        assert tasks._reconcile_targeted_regen(
            s, sid, 0, "t", "86", "u1",
            pairs=[(_scored(), new_scoped, target)],
            scenarios={new_scoped: ({"scenario_title": "rewritten"}, {}, (_now(), _now()))},
            enriched={_TID: _INFO_AFTER_PROMOTION}, epoch=2, task_id="task-1",
            regen_mode=True) is True
        s.commit()

    with Session() as s:
        rows = {str(r["ScenarioID"]): r for r in s.execute(
            select(m.Threat_Scenario.ScenarioID, m.Threat_Scenario.Superseded,
                m.Threat_Scenario.ReplacesScenarioID)
            .where(m.Threat_Scenario.SessionID == sid)).mappings()}
    new_id = next(oid for oid in rows if oid != old_id)
    assert rows[old_id]["Superseded"] == 1, "the legacy version is retired, hash or no hash"
    assert str(rows[new_id]["ReplacesScenarioID"]) == old_id
    assert sum(1 for r in rows.values() if not r["Superseded"]) == 1, "exactly one live version"


def test_a_rewrite_is_not_asked_to_differ_from_its_own_text(monkeypatch, tmp_path):
    """Through the REAL batch, not the reconcile alone — `write_scenarios` folds a second identity
    map of its own, and it must agree with what the rows carry.

    `others` is "scenarios already on screen, differ from these", built by excluding the item's own
    identity. Recomputed after a promote-to-library, the exclusion missed and the target's OWN text
    was handed back to the model as something to differ from — steering a rewrite away from itself.
    Seeded here with a distinctive sentence so the miss cannot hide. The database outcome is
    asserted too: one live version, pointing at the one it replaced."""
    engine = create_engine(f"sqlite:///{tmp_path / 'regen.db'}",
                        connect_args={"check_same_thread": False})
    for tbl in (m.Scenario_Session, m.Subsystem_Stage_State, m.Identified_Threat, m.Scoped_Threat,
                m.Threat_Scenario, m.Threat_Scenario_Control_Map, m.Scenario_Audit, m.Prompt_Log):
        tbl.__table__.create(engine)
    Session = sessionmaker(bind=engine, future=True)
    sid, old_scoped, old_id = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    own_text = "A courier swaps the vendor USB before the firmware window."

    with Session() as s:
        s.execute(m.Scenario_Session.__table__.insert().values(
            SessionID=sid, TenantID="t", EntityID="86", UserID="u1", AssetID="1",
            AssetName="Pumping Station", SessionStatus="active",
            CurrentStage="SCENARIO_GENERATION", StageStatus="RUNNING", Mode="AUTO",
            SubsystemsJSON=json.dumps([{"id": 41, "name": "SCADA HMI", "asset_type": "OT"}]),
            CreatedAt=_now(), UpdatedAt=_now()))
        for level in (SubsystemLevel.THREATS, SubsystemLevel.SCENARIOS, SubsystemLevel.LOCK):
            s.execute(m.Subsystem_Stage_State.__table__.insert().values(
                StateID=str(uuid.uuid4()), SessionID=sid, TenantID="t", EntityID="86",
                SubsystemID=0, Level=level, Status=StageStatus.IDLE, GenerationEpoch=1,
                LeaseExpiresAt=_now() + timedelta(minutes=30), UpdatedAt=_now(), CreatedAt=_now()))
        s.execute(m.Scoped_Threat.__table__.insert().values(
            ScopedThreatID=old_scoped, SessionID=sid, TenantID="t", EntityID="86", SubsystemID=0,
            ThreatID=_TID, Score=9.5, ScopeRank=1, Selected=1, Superseded=0, CreatedAt=_now()))
        s.execute(m.Threat_Scenario.__table__.insert().values(
            ScenarioID=old_id, SessionID=sid, TenantID="t", EntityID="86", UserID="u1",
            SubsystemID=0, ScopedThreatID=old_scoped, Status=str(ScenarioStatus.complete),
            ScenarioJSON=json.dumps({"scenario_title": "USB swap", "scenario_statement": own_text}),
            # Written before the promotion: the identity of that moment, not of the threat now.
            Accepted=1, Superseded=0, IdentityHash=HASH_10, ScenarioNumber=1,
            GenerationEpoch=1, CreatedAt=_now()))
        s.commit()

    captured: dict = {}
    real_batch = tasks._generate_scenario_batch
    monkeypatch.setattr(tasks, "_fetch_intel", lambda *a, **k: None)
    monkeypatch.setattr(tasks.bus, "publish", lambda *a, **k: None)
    monkeypatch.setattr(tasks, "_finalize_scenario_batch", lambda *a, **k: None)
    monkeypatch.setattr(tasks, "_generate_scenario_batch",
                        lambda *a, **k: (captured.setdefault("per_item", a[8]), real_batch(*a, **k))[1])

    threats = [{"threat_id": _TID, "grounding_status": "verified", "category": "Exfiltration",
                "threat_type": "Data exfiltration", "threat_name": "USB export",
                "library_threat_type": None, "library_threat_name": None,
                "threat_type_id": 5, "catalogue_id": 77,  # what promote-to-library left behind
                "actors": []}]
    target = tasks.RegenTarget(scenario_id=old_id, threat_id=_TID, scoped_threat_id=old_scoped,
                            scenario_number=1, identity_hash=HASH_10)
    with Session() as s:
        session_row = dict(dal.load_session(s, sid))
        tasks.write_scenarios(s, session_row, json.loads(session_row["SubsystemsJSON"]),
                            {"name": "Pumping Station", "asset_type": "Pumping Station"},
                            threats, _FakeLLM(), str(uuid.uuid4()),
                            regen_targets={old_id: target})

    per_item = captured["per_item"]
    assert len(per_item) == 1, "one target, one work item"
    coverage = next(iter(per_item.values()))["coverage"]
    assert own_text not in (coverage.others or []), (
        "the rewrite must not be told to differ from the very text it is replacing")

    with Session() as s:
        rows = {str(r["ScenarioID"]): r for r in s.execute(
            select(m.Threat_Scenario.ScenarioID, m.Threat_Scenario.Superseded,
                m.Threat_Scenario.IdentityHash, m.Threat_Scenario.ReplacesScenarioID)
            .where(m.Threat_Scenario.SessionID == sid)).mappings()}
    live = [r for r in rows.values() if not r["Superseded"]]
    assert len(live) == 1 and live[0]["IdentityHash"] == HASH_10
    assert str(live[0]["ReplacesScenarioID"]) == old_id


def _promoted_session(Session):
    """A session whose accepted scenario 6 has been through the REAL promote-to-library.

    Every other test here simulates the promotion by stamping the catalogue id the way promote
    does. This one calls the actual function, so the drift under test is the one production
    produces — including the detail that decides the rest: the catalogue row it mints is INACTIVE,
    pending curation, and matching only considers active rows.
    """
    from app.pipeline.promote import promote_scenario_to_library

    sid = _seed_session(Session)
    tid, scoped_id, oid = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    # An AI-FOUND threat: no catalogue id yet, which is the case promotion changes.
    info = {"threat_id": tid, "catalogue_id": None, "threat_type_id": None,
            "threat_type": "Data exfiltration", "threat_name": "USB export of billing records"}
    identity = dal.identity_hash(sid, 0, info)
    with Session() as s:
        s.execute(m.Identified_Threat.__table__.insert().values(
            ThreatID=tid, SessionID=sid, SubsystemID=0, ThreatCategory="Exfiltration",
            ThreatType=info["threat_type"], ThreatName=info["threat_name"],
            ThreatTypeID=None, ThreatCatalogueID=None, ThreatCategoryID=None,
            GroundingStatus="unverified", Superseded=0, CreatedAt=_now()))
        s.execute(m.Scoped_Threat.__table__.insert().values(
            ScopedThreatID=scoped_id, SessionID=sid, TenantID="t", EntityID="86", SubsystemID=0,
            ThreatID=tid, Score=9.5, ScopeRank=1, Selected=1, Superseded=0, CreatedAt=_now()))
        s.execute(m.Threat_Scenario.__table__.insert().values(
            ScenarioID=oid, SessionID=sid, TenantID="t", EntityID="86", UserID="u1",
            SubsystemID=0, ScopedThreatID=scoped_id, Status=str(ScenarioStatus.complete),
            ScenarioJSON=json.dumps({"scenario_title": "USB export",
                                    "scenario_statement": "An agent copies the payment list."}),
            Accepted=1, Superseded=0, IdentityHash=identity, ScenarioNumber=1,
            GenerationEpoch=1, CreatedAt=_now()))
        s.commit()

    with Session() as s:
        session_row = dict(dal.load_session(s, sid))
        promote_scenario_to_library(s, session_row, oid, "u1")

    with Session() as s:
        threat = s.execute(select(m.Identified_Threat.ThreatCatalogueID,
                                m.Identified_Threat.ThreatTypeID)
                        .where(m.Identified_Threat.ThreatID == tid)).mappings().one()
        drifted = dal.identity_hash(sid, 0, {**info, "catalogue_id": threat["ThreatCatalogueID"],
                                            "threat_type_id": threat["ThreatTypeID"]})
    assert threat["ThreatCatalogueID"] is not None, "the real promote stamped a catalogue id"
    assert drifted != identity, (
        "precondition: the threat's identity really did move, or this proves nothing")
    return sid, tid, scoped_id, oid, identity


def test_promote_then_regenerate_leaves_exactly_one_live_version(monkeypatch):
    """THE bug, end to end, through the real promote: accept a scenario, promote its threat to the
    library, then regenerate it.

    Before the fix the rewrite was stamped with the threat's NEW identity and retired "whatever
    holds it" — nothing — so the accepted version stayed live beside its replacement. Two versions
    of one scenario, carrying different identities, each separately acceptable and each able to
    hold its own remediation plan: one risk, counted twice."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid, tid, scoped_id, oid, identity = _promoted_session(Session)

    new_scoped = str(uuid.uuid4())
    target = tasks.RegenTarget(scenario_id=oid, threat_id=tid, scoped_threat_id=scoped_id,
                            scenario_number=1, identity_hash=identity)
    with Session() as s:
        # The threat AS IT IS NOW — carrying the ids promotion stamped, which is what the
        # regeneration would fold a fresh identity from if it re-derived one.
        enriched = {t["threat_id"]: t for t in dal.active_threats(s, sid, 0)}
        assert tasks._reconcile_targeted_regen(
            s, sid, 0, "t", "86", "u1",
            pairs=[(_scored(tid), new_scoped, target)],
            scenarios={new_scoped: ({"scenario_title": "rewritten"}, {}, (_now(), _now()))},
            enriched=enriched, epoch=2, task_id="task-1", regen_mode=True) is True
        s.commit()

    with Session() as s:
        rows = {str(r["ScenarioID"]): r for r in s.execute(
            select(m.Threat_Scenario.ScenarioID, m.Threat_Scenario.Superseded,
                m.Threat_Scenario.Accepted, m.Threat_Scenario.IdentityHash,
                m.Threat_Scenario.ReplacesScenarioID)
            .where(m.Threat_Scenario.SessionID == sid)).mappings()}
    live = [r for r in rows.values() if not r["Superseded"]]
    assert len(live) == 1, "one scenario, one live version — this is the whole bug"
    assert live[0]["IdentityHash"] == identity, (
        "the rewrite kept the identity its target carried, so the accept guard still sees "
        "one scenario rather than two unrelated ones")
    assert str(live[0]["ReplacesScenarioID"]) == oid
    assert rows[oid]["Superseded"] == 1, "the version it replaced is retired"
    assert rows[oid]["Accepted"] == 1, "its decision is untouched — only accept may move that"


def test_next_set_cannot_replace_an_accepted_scenario_after_a_promotion():
    """The path that was still open after the first fix, and the reason it mattered.

    The AI re-proposes a threat that is already here — common, it is a real threat for this asset.
    It does not ground onto the catalogue row promotion just minted, because that row is INACTIVE
    pending curation, so it folds the threat's OLD identity. That spelling was missing from the
    dedup dictionary, so the proposal was admitted as a NEW threat, its scenario was written under
    the old identity, and supersede_by_identity_hashes then matched the ACCEPTED scenario and
    retired it — a reviewer's decision silently replaced, looking like an ordinary regeneration.

    Both spellings now resolve to the same threat, so the re-proposal is recognised for what it
    is before anything is written."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid, tid, _scoped_id, _oid, identity = _promoted_session(Session)

    with Session() as s:
        known = dal.active_identified_threat_identities(s, sid, 0)

    assert known.get(identity) == tid, (
        "the identity the accepted scenario carries must still resolve to its threat")
    with Session() as s:
        assert dal.next_unserved_unique_threats(s, sid, 0, 5) == [], (
            "and the threat counts as served, so next-set will not re-serve it either")


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
