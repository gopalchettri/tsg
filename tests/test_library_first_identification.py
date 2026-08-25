"""P2 gate for library-first threat identification (tasks.find_threats, Stage 1a/1b).

Asserts the whole redesigned flow on real SQLite tables with a deterministic fake LLM:

  - retrieval fills from the library FIRST: validated candidates land as Identified_Threat
    rows carrying MASTER ids (ThreatTypeID/ThreatCatalogueID), verified, GroundingScore 100,
    the type's LINKED actors (validated=True)
  - a tech_gate rule hard-excludes a non-applicable type (metadata filter)
  - the LLM validator's NOT_RELEVANT is a HARD DROP with a recorded justification
  - generation runs only for the SHORTFALL, and a generated proposal that matches a
    retrieved library row is dropped as an identity duplicate attributed to that row
  - a genuinely novel proposal survives as unverified (the promotion path input)
  - the grounding_summary audit row carries retrieved/generated counts, the validator
    outcome, and the coverage report
  - the coverage gap reaches the BOARD (progress.coverage), not just an audit row
  - Phase 2c: a threat type the SECTOR filter excludes still enters the pool when an actor
    operating in this sector uses it (ThreatType_ThreatActor_Map read backwards), and the
    audit records WHICH actor put it there
  - Phase 2b: each threat is recorded against the asset AND every supporting system a
    tech_gate does not rule out, so the coverage grid is 2D and an uncovered
    (system x STRIDE) cell is reported instead of being invisible

House pattern: real SQLite, bus.publish stubbed, no Mongo/Redis/real models.
"""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core.enums import GroundingStatus, StageStatus, SubsystemLevel
from app.db import models as m
from app.pipeline import embeddings, tasks
from app.pipeline.tasks import find_threats, set_up_progress_tracking


@pytest.fixture(autouse=True)
def _isolated_embeddings(monkeypatch):
    """Force the in-memory embedding store and clear the process caches: a REAL local Mongo
    (docker compose dev) would otherwise serve real 1024-dim vectors for library names that
    exist in the real seed, colliding with the fake 256-dim test vectors — and the test would
    WRITE fake vectors into the real store."""
    monkeypatch.setenv("TSG_EMBEDDING_STORE", "memory")
    embeddings._L1.clear()
    embeddings._MATRIX.clear()
    yield
    embeddings._L1.clear()
    embeddings._MATRIX.clear()

SID = str(uuid.uuid4())
TASK_ID = str(uuid.uuid4())
NOW = datetime.now(UTC)

SUBSYSTEMS = [{"id": 41, "name": "SCADA HMI Server", "asset_type": "OT",
               "technology_used": ["Siemens SCADA"], "vendor_name": "Siemens",
               "criticality": "High"},
              {"id": 42, "name": "Customer Billing Portal", "asset_type": "IT",
               "technology_used": ["Django"], "vendor_name": "In-house",
               "criticality": "Medium"}]
ASSET_CONTEXT = {"name": "Water Pumping Station", "asset_type": "Pumping Station",
                 "sector": "Energy & Water", "sub_sector": "Water Supply",
                 "critical_service": ["Potable water supply"]}


class FakeLLM:
    """Deterministic: one-hot embeddings per unique text (no accidental cosine collisions),
    exact-match reranking, and canned chat answers per stage recognized by system text."""

    def __init__(self):
        self._slots: dict[str, int] = {}
        self.chat_calls: list[tuple[str, str]] = []

    def embed(self, texts, kind=None):
        out = []
        for t in texts:
            idx = self._slots.setdefault(t, len(self._slots))
            v = [0.0] * 256
            v[idx % 256] = 1.0
            out.append(v)
        return out

    def rerank(self, query, docs):
        return [95.0 if d.strip().lower() == query.strip().lower() else 5.0 for d in docs]

    def chat(self, messages, temperature=None, expected_type=None):
        system, user = messages[0]["content"], messages[-1]["content"]
        self.chat_calls.append((system, user))
        if "VALIDATING pre-selected library threats" in system:
            payload = json.loads(user[user.index("{"):])
            verdicts = []
            for cand in payload["candidate_threats"]:
                bad = "web application" in (cand.get("name") or "").lower()
                verdicts.append({
                    "index": cand["index"],
                    "verdict": "NOT_RELEVANT" if bad else "RELEVANT",
                    "justification": ("no web application exists on this asset" if bad
                                      else "SCADA controls pump setpoints directly")})
            return json.dumps(verdicts), None
        # Stage-1b gap generation: one duplicate of a library row + one genuinely novel.
        return json.dumps([
            {"category": "Tampering", "type": "Logic/Configuration Manipulation",
             "name": "Unauthorised setpoint modification",
             "generic_name": "Unauthorised setpoint modification", "actors": []},
            {"category": "Repudiation", "type": "Audit Evidence Loss",
             "name": "Loss of operator attribution from shared logins",
             "generic_name": "Loss of operator attribution", "actors": []},
        ]), None


def _engine():
    engine = create_engine("sqlite://")
    for tbl in (m.Scenario_Session, m.Subsystem_Stage_State, m.Identified_Threat,
                m.Identified_Duplicate_Threat, m.Scenario_Audit, m.Prompt_Log,
                m.Threat_Category, m.Threat_Type, m.Threat_Catalogue,
                m.Threat_Catalogue_Category_Map, m.Threat_Actor,
                m.ThreatType_ThreatActor_Map, m.Config_Threat_Rule):
        tbl.__table__.create(engine)
    return engine


def _seed_library(s) -> None:
    for cid, name in ((4, "Repudiation"), (5, "Spoofing"), (6, "Tampering")):
        s.execute(m.Threat_Category.__table__.insert().values(
            ThreatCategoryID=cid, ThreatCategoryName=name, IsActive=True, IsDeleted=False))
    for tid, name, cat in ((7, "Logic/Configuration Manipulation", 6),
                           (9, "Credential Abuse", 5),
                           (11, "Retail POS Skimming", 5)):
        s.execute(m.Threat_Type.__table__.insert().values(
            ThreatTypeID=tid, ThreatTypeName=name, ThreatCategoryID=cat,
            IsActive=True, IsDeleted=False))
    # Phase 2c: scoped to a sector this session CANNOT see, so the metadata filter alone
    # drops it. It gets in only because APT33 - linked to type 7, which IS visible here -
    # also uses it. This is the whole actor leg in one row.
    s.execute(m.Threat_Type.__table__.insert().values(
        ThreatTypeID=13, ThreatTypeName="Spear-phishing for Initial Access",
        ThreatCategoryID=5, SectorID=999, IsActive=True, IsDeleted=False))
    for cid, name, tid, desc in (
            (418, "Unauthorised setpoint modification", 7,
             "An actor alters pump setpoints so control logic integrity is lost."),
            (522, "Web application parameter tampering", 7,
             "Tampering with parameters of a public web application."),
            (205, "Credential phishing and MFA session theft", 9,
             "Phishing steals operator credentials and session tokens."),
            (900, "Payment card skimming at POS terminals", 11,
             "Skimming devices harvest card data at retail POS."),
            (733, "Spear-phishing of control room engineers", 13,
             "Tailored email lures an engineer into running attacker code.")):
        s.execute(m.Threat_Catalogue.__table__.insert().values(
            ThreatCatalogueID=cid, ThreatName=name, ThreatTypeID=tid, Description=desc,
            IsActive=True, IsDeleted=False))
    # multi-category membership: phishing is Spoofing AND Repudiation (map is authoritative)
    for cat_id, cid in ((6, 418), (6, 522), (5, 205), (4, 205), (5, 900), (5, 733)):
        s.execute(m.Threat_Catalogue_Category_Map.__table__.insert().values(
            ThreatCategoryID=cat_id, ThreatCatalogueID=cid))
    s.execute(m.Threat_Actor.__table__.insert().values(
        ThreatActorID=1, ThreatActorName="APT33", IsCapable=1, IsActive=True, IsDeleted=False))
    s.execute(m.ThreatType_ThreatActor_Map.__table__.insert().values(
        ThreatTypeID=7, ThreatActorID=1))
    # the second hop: the same actor also uses the out-of-sector type
    s.execute(m.ThreatType_ThreatActor_Map.__table__.insert().values(
        ThreatTypeID=13, ThreatActorID=1))
    # tech_gate: POS skimming applies only to RETAIL subsystems — none here, so type 11 is OUT
    s.execute(m.Config_Threat_Rule.__table__.insert().values(
        ThreatRuleID=1, RuleType="tech_gate", ThreatTypeID=11, RuleKey="asset_type",
        RuleValue="RETAIL", IsActive=True, IsDeleted=False))
    # tech_gate: setpoint manipulation is an OT concern. The ASSET still passes (system 41 is
    # OT and the asset-level gate is an any()), but the per-system attribution must NOT put
    # this threat on the IT billing portal — that narrowing is what Phase 2b buys.
    s.execute(m.Config_Threat_Rule.__table__.insert().values(
        ThreatRuleID=2, RuleType="tech_gate", ThreatTypeID=7, RuleKey="asset_type",
        RuleValue="OT", IsActive=True, IsDeleted=False))


def _seed_session(s) -> dict:
    row = {"SessionID": SID, "TenantID": "t", "EntityID": "e", "UserID": "u",
           "AssetName": "Water Pumping Station", "AssetID": "1", "SessionStatus": "active",
           "CurrentStage": "THREAT_IDENTIFICATION", "StageStatus": "IDLE", "Mode": "AUTO",
           "SubsystemsJSON": json.dumps(SUBSYSTEMS), "SectorIDsJSON": json.dumps([]),
           "CreatedAt": NOW, "UpdatedAt": NOW}
    s.execute(m.Scenario_Session.__table__.insert().values(**row))
    set_up_progress_tracking(s, SID, "t", "e")
    s.commit()
    return row


def test_library_first_identification_end_to_end(monkeypatch):
    monkeypatch.setattr(tasks.bus, "publish", lambda *a, **k: None)
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    llm = FakeLLM()
    with Session() as s:
        _seed_library(s)
        scenario_session = _seed_session(s)
        threats, _prov = find_threats(s, scenario_session, SUBSYSTEMS, ASSET_CONTEXT, llm,
                                      TASK_ID, max_threats=4)

    # --- library rows first, master identity intact -----------------------------------
    with Session() as s:
        all_rows = list(s.execute(select(m.Identified_Threat)).scalars())
        # SubsystemID 0 only: Phase 2b also writes a copy of each threat on every supporting
        # system it reaches, and those copies share the catalogue id (asserted separately
        # below). Every consumer — scoping, scenarios, next-set, accept — reads unit 0.
        rows = {r.ThreatCatalogueID: r for r in all_rows if r.SubsystemID == 0}
        retrieved = {cid: r for cid, r in rows.items() if cid is not None}
        # 418 + 205 sector-visible, 733 admitted by the ACTOR leg;
        # 522 validator-dropped; 900 gate-excluded
        assert set(retrieved) == {418, 205, 733}
        for r in retrieved.values():
            assert str(r.GroundingStatus) == str(GroundingStatus.verified)
            assert r.GroundingScore == 100.0
            assert r.ThreatTypeID in (7, 9, 13)
            assert r.LibraryThreatName == r.ThreatName  # master name on every column
        actors_418 = json.loads(retrieved[418].ThreatActorsJSON)
        assert actors_418 == {"actors": ["APT33"], "validated": True}

        # --- shortfall generation: duplicate dropped, novel survives -------------------
        novel = [r for cid, r in rows.items() if cid is None]
        assert len(novel) == 1
        assert "operator attribution" in novel[0].ThreatName
        assert str(novel[0].GroundingStatus) == str(GroundingStatus.unverified)
        dups = list(s.execute(select(m.Identified_Duplicate_Threat)).scalars())
        assert len(dups) == 1
        assert dups[0].DuplicateReason == "identity"
        assert dups[0].DuplicateOfThreatID == retrieved[418].ThreatID

        # --- stage completed + audit carries the full provenance -----------------------
        stage = s.execute(select(m.Subsystem_Stage_State).where(
            m.Subsystem_Stage_State.Level == SubsystemLevel.THREATS)).scalar_one()
        assert str(stage.Status) == str(StageStatus.COMPLETE)
        audit = [json.loads(a.DetailJSON) for a in s.execute(
            select(m.Scenario_Audit)).scalars() if a.DetailJSON]
        summary = next(d for d in audit if "retrieved" in d)
        assert summary["retrieved"] == 3 and summary["generated"] == 1
        assert summary["validator"]["kept"] == 3
        assert summary["validator"]["dropped"][0]["catalogue_id"] == 522
        assert "no web application" in summary["validator"]["dropped"][0]["justification"]
        cov = summary["coverage"]
        # --- Phase 2b: the grid is 2D ---------------------------------------------------
        # 3 units (asset + 2 supporting systems) x 3 STRIDE categories.
        # --- Phase 2c: the actor leg, and the audit trail it leaves ----------------------
        # Sources are the DISTINGUISHING reason each threat is in the pool.
        assert summary["selection_sources"] == {
            "hybrid": 1,        # 418, sector-visible and gated
            "rules": 1,         # 205, sector-visible and ungated (universal tier)
            "actor_intel": 1,   # 733, reachable ONLY through APT33
            "generated": 1,
        }
        # The audit answers "why is this here?" with a group, not a similarity number.
        # BOTH APT33 types appear: the evidence is a fact about the type, recorded wherever
        # it is true. selection_source above is the separate question of whether that fact is
        # what got the threat INTO the pool - for 418 it was not, for 733 it was.
        assert sorted(d["threat_name"] for d in summary["actor_derived"]) == [
            "Spear-phishing of control room engineers", "Unauthorised setpoint modification"]
        assert all(d["actors"] == ["APT33"] for d in summary["actor_derived"])

        assert cov["cells"] == 9
        assert summary["units"] == [0, 41, 42]

        # The asset's working set is untouched by the fan-out: 3 retrieved + 1 novel.
        assert len([r for r in all_rows if r.SubsystemID == 0]) == 4
        by_unit = {u: {r.ThreatCatalogueID for r in all_rows if r.SubsystemID == u}
                for u in (0, 41, 42)}
        # 418 is OT-gated: recorded on the SCADA server, NOT on the billing portal.
        assert 418 in by_unit[41] and 418 not in by_unit[42]
        # 205 (Credential Abuse) and 733 (spear-phishing) carry no gate — universal, so
        # they reach both systems.
        assert 205 in by_unit[41] and 205 in by_unit[42]
        assert 733 in by_unit[41] and 733 in by_unit[42]

        # ...and the grid now SEES what the flat version could not: no Tampering threat was
        # identified for the IT subsystem. A reportable gap, not silence — this assertion is
        # the whole point of the matrix.
        assert cov["unexplained"] == 1
        assert cov["gaps"] == [[42, "Tampering"]]

        # ...and the gap REACHES THE CLIENT. Recording it in an audit blob nobody reads would
        # leave the reviewer with a session that looks complete, which is the exact failure the
        # matrix exists to prevent. This is the board's per-supporting-system dimension.
        from app.api import sessions as sessions_mod
        verdict = sessions_mod._coverage_verdict(s, SID)
        assert verdict["complete"] is False
        assert verdict["unexplained"] == 1
        assert verdict["units"] == [0, 41, 42]
        assert verdict["gaps"] == [{"subsystem_id": 42, "category": "Tampering"}]

    # --- return value feeds write_scenarios: retrieved first, then novel ---------------
    by_name = {t["threat_name"]: t for t in threats}
    spear = by_name["Spear-phishing of control room engineers"]
    assert spear["selection_source"] == "actor_intel"
    assert spear["actor_evidence"] == ["APT33"]
    # 418's type is ALSO used by APT33, so it carries the same evidence - but it was already
    # in the pool on its own merits, which is exactly what selection_source distinguishes.
    assert by_name["Unauthorised setpoint modification"]["selection_source"] == "hybrid"
    assert by_name["Unauthorised setpoint modification"]["actor_evidence"] == ["APT33"]
    # ...and a threat whose type no actor is linked to claims nothing it cannot support
    assert by_name["Credential phishing and MFA session theft"]["actor_evidence"] == []
    assert threats[0]["validator_verdict"] == "RELEVANT"
    assert len(threats) == 4


def test_empty_library_degrades_to_generation_only(monkeypatch):
    """No library rows → the funnel returns [] loudly and the pre-redesign generation-only
    path runs unchanged. The degraded-library ladder's 'genuinely empty' rung."""
    monkeypatch.setattr(tasks.bus, "publish", lambda *a, **k: None)
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    llm = FakeLLM()
    with Session() as s:
        scenario_session = _seed_session(s)  # library tables exist but are EMPTY
        threats, _prov = find_threats(s, scenario_session, SUBSYSTEMS, ASSET_CONTEXT, llm,
                                      TASK_ID, max_threats=4)
    assert len(threats) == 2                      # both fake proposals, generation-only
    assert all(t.get("selection_source") is None for t in threats)
    # only the threats-stage chat ran — no validator call without candidates
    assert all("VALIDATING pre-selected" not in sys for sys, _ in llm.chat_calls)


def test_generation_asks_for_a_buffer_so_n_new_threats_actually_land(monkeypatch):
    """find_threats(N) must return N whenever N obtainable threats exist.

    THE BUG. Stage 1b asked the model for EXACTLY `shortfall`, then the consume loop dropped any
    proposal duplicating what the session already holds — and nothing refilled them. So
    find_threats(5) structurally returned fewer than 5 whenever the model repeated anything, and
    next-set's "show more 5" delivered 4. cascade._buffered_ask tried to compensate from OUTSIDE
    by over-asking, which is why it collided with max_threats_per_asset (a per-call identification
    ceiling, unrelated to delivery) and forced operators to keep two settings in a 2x ratio.

    The buffer now lives in Stage 1b, where the loss is measurable. This test pins that: the model
    honours whatever count it is asked for and repeats itself half the time, so a bare-shortfall
    ask cannot reach the target and a buffered one can.
    """
    monkeypatch.setattr(tasks.bus, "publish", lambda *a, **k: None)

    asked: list[int] = []
    real_prompt = tasks.prompts.threats_prompt

    def _capture(*a, **kw):
        if kw.get("quota") is not None:          # the gap-generation call, not the threats prompt
            asked.append(kw["max_threats"])
        return real_prompt(*a, **kw)
    monkeypatch.setattr(tasks.prompts, "threats_prompt", _capture)

    class _RepeatingLLM(FakeLLM):
        """Returns EXACTLY as many proposals as it was asked for, half of them the same threat.

        Honouring the requested count is what makes this test load-bearing: a fake that always
        returns a fixed surplus would pass on the old code too, because the consume loop already
        takes survivors up to the target. The defect was never the loop — it was the ask.
        """
        def chat(self, messages, temperature=None, expected_type=None):
            if "VALIDATING pre-selected library threats" in messages[0]["content"]:
                return super().chat(messages, temperature, expected_type)
            out = []
            for i in range(asked[-1]):
                if i % 2 == 0:      # a repeat — only the first copy survives identity dedup
                    out.append({"category": "Tampering", "type": "Logic/Configuration Manipulation",
                                "name": "Unauthorised setpoint modification",
                                "generic_name": "Unauthorised setpoint modification", "actors": []})
                else:
                    out.append({"category": "Repudiation", "type": "Audit Evidence Loss",
                                "name": f"Distinct novel threat {i}",
                                "generic_name": f"Distinct novel threat {i}", "actors": []})
            return json.dumps(out), None

    want = 5
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        _seed_library(s)
        scenario_session = _seed_session(s)
        threats, _prov = find_threats(s, scenario_session, SUBSYSTEMS, ASSET_CONTEXT,
                                    _RepeatingLLM(), TASK_ID, max_threats=want)

    assert asked, "gap generation never ran — the library filled everything, so this test is vacuous"
    # THE assertion. Set TSG_GAP_GENERATION_BUFFER=1.0 (which makes _gap_ask return the bare
    # shortfall, i.e. the old behaviour) and this fails: the model repeats itself, the repeats are
    # dropped, and nothing refills them.
    names = [t.get("threat_name") for t in threats]
    assert len(threats) == want, (
        f"asked for {want}, got {len(threats)} — generation under-delivered because its ask was "
        f"not buffered against dedup loss (gap asks: {asked}, delivered: {names})")
    assert len(set(names)) == len(names), f"delivered set is not unique: {names}"
