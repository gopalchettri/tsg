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
from sqlalchemy import func, insert, select
from sqlalchemy.exc import IntegrityError

from app.core.enums import GroundingStatus, ScenarioStatus, SubsystemLevel
from app.db import dal
from app.db import models as m
from app.db.dal import now
from app.pipeline.scoping import Scored
from app.pipeline.tasks import _dedup_key, _normalize, _select_unique_top_n, find_threats, write_scenarios
from tests.conftest import DEFAULT_ASSET_CONTEXT, StubLLM
from app.pipeline.tasks import ASSET_UNIT_ID
from tests.test_slice import SUB, _active_count, _seed_session

_TID = "33333333-3333-4333-8333-333333333333"


# --- stub models producing the shapes dedup has to handle -------------------
class _DupCatalogueLLM(StubLLM):
    """Two proposals that BOTH ground to the seeded type 10 / catalogue 20 — the
    catalogue-level duplicate the whole feature exists to collapse."""

    def chat(self, messages, *, model=None, temperature=None):
        if "json array" in messages[0]["content"].lower():
            from app.pipeline.llm import Provenance
            out = [{"category": "Tampering", "type": "Firmware Tampering", "name": "Bootloader implant",
                    "actors": ["Hacker"]}] * 2
            return json.dumps(out), Provenance(model="stub")
        return super().chat(messages, model=model)


class _UngroundedLLM(StubLLM):
    """Two proposals that match NONE of the seeded masters (both come back `unverified`,
    ThreatTypeID/ThreatCatalogueID NULL) — so dedup falls back to normalized text."""

    def __init__(self, proposals):
        self._proposals = proposals

    def chat(self, messages, *, model=None, temperature=None):
        if "json array" in messages[0]["content"].lower():
            from app.pipeline.llm import Provenance
            return json.dumps(self._proposals), Provenance(model="stub")
        return super().chat(messages, model=model)


def _scenarios(db, sid):
    return db.execute(select(m.Threat_Scenario_Output)
                    .where(m.Threat_Scenario_Output.SessionID == sid,
                            m.Threat_Scenario_Output.Superseded == 0)).scalars().all()


def _run(db, llm, sub=SUB, session=None):
    session = session or _seed_session(db, subs=[sub])
    threats, _ = find_threats(db, session, [sub], DEFAULT_ASSET_CONTEXT, llm, _TID)
    db.commit()
    write_scenarios(db, session, [sub], DEFAULT_ASSET_CONTEXT, threats, llm, _TID)
    db.commit()
    return session


# --- _dedup_key / _normalize (pure) -----------------------------------------
def test_dedup_key_precedence_and_null_name():
    assert _dedup_key({"catalogue_id": 20, "threat_type_id": 10, "threat_type": "X"}) == "cat:20"
    assert _dedup_key({"catalogue_id": None, "threat_type_id": 10}) == "type:10"
    # ThreatType is NOT NULL, ThreatName is nullable — None must not crash, folds as ""
    assert _dedup_key({"threat_type": "Firmware Tampering", "threat_name": None}) == \
        "txt:" + _normalize("Firmware Tampering") + "|"


def test_dedup_key_txt_fallback_does_not_over_collapse():
    # empty type + null name → per-threat-unique via threat_id, NOT a shared bare "txt:" that
    # collapses every distinct ungrounded proposal into one.
    k1 = _dedup_key({"threat_type": "", "threat_name": None, "threat_id": "id-1"})
    k2 = _dedup_key({"threat_type": "", "threat_name": None, "threat_id": "id-2"})
    assert k1 == "txt:tid:id-1" and k2 == "txt:tid:id-2" and k1 != k2
    # the delimiter must survive normalization: ('Firmware'/'Tampering') must NOT fold onto
    # ('Firmware Tampering'/None) the way the old '\x1f'-joined key did (it stripped the separator).
    assert _dedup_key({"threat_type": "Firmware", "threat_name": "Tampering"}) != \
        _dedup_key({"threat_type": "Firmware Tampering", "threat_name": None})


def test_normalize_folds_punctuation_case_and_whitespace():
    assert _normalize("OTA-Poisoning!") == _normalize("ota   poisoning")
    assert _normalize("Alpha Threat") != _normalize("Beta Threat")


# --- unique-top-N selection pass (pure) -------------------------------------
def test_select_unique_top_n_frees_the_slot_and_yields_n_distinct():
    # rank order: a(cat10), b(cat10 dup of a), c(cat11), d(cat12); threshold already applied
    scored = [Scored("a", 80.0, 1, True, "grounding=verified"),
            Scored("b", 80.0, 2, True, "grounding=verified"),
            Scored("c", 70.0, 3, True, "grounding=verified"),
            Scored("d", 60.0, 4, True, "grounding=verified")]
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
            Scored("y", 70.0, 2, True, "grounding=verified")]
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


def test_ungrounded_separator_boundary_not_over_collapsed(db):
    # ('Novel Alpha'/'Rare Beta') vs ('Novel Alpha Rare'/'Beta') normalize-collide across the old
    # '\x1f' separator but are distinct once the delimiter is applied AFTER normalization.
    session = _run(db, _UngroundedLLM([
        {"category": "Tampering", "type": "Novel Alpha", "name": "Rare Beta", "actors": []},
        {"category": "Tampering", "type": "Novel Alpha Rare", "name": "Beta", "actors": []}]))
    assert len(_scenarios(db, session["SessionID"])) == 2


# --- structural backstop: dedup_key folded into IdentityHash on the asset unit ----
# ponytail: no more "sibling subsystems" cross-suppression test — SubsystemID is now a
# fixed sentinel (ASSET_UNIT_ID) on every row (see tasks.py's asset-centric comment), so
# there is only ever one dedup scope per session, not one per supporting system.
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
    threats, _ = find_threats(db, session, [SUB], DEFAULT_ASSET_CONTEXT, _DupCatalogueLLM(), _TID)
    db.commit()
    target = threats[1]["threat_id"]
    provs = write_scenarios(db, session, [SUB], DEFAULT_ASSET_CONTEXT, threats, _DupCatalogueLLM(), _TID,
                            target_threat_ids={target})
    assert len(provs) == 1                                                     # regenerated, not withheld


# --- regen ranker parity + folded-identity collision (Fixes 1 & 2) ----------
def _seed_threat(db, sid, ss, *, threat_id, grounding_status, catalogue_id, type_id,
                threat_type, threat_name, library_type=None, library_name=None):
    """Insert one Identified_Threat directly so its score/catalogue is fully deterministic
    (bypasses the grounding pipeline). Shape matches dal.active_threats' read-back."""
    db.execute(insert(m.Identified_Threat).values(
        ThreatID=threat_id, SessionID=sid, TenantID="default", SubsystemID=ss,
        ThreatCategory="Tampering", ThreatType=threat_type, ThreatName=threat_name,
        LibraryThreatType=library_type, LibraryThreatName=library_name,
        ThreatTypeID=type_id, ThreatCatalogueID=catalogue_id,
        GroundingStatus=grounding_status, GroundingScore=None, Superseded=0, CreatedAt=now()))


def _active_winner_count(db, sid, threat_id):
    return db.execute(
        select(func.count()).select_from(m.Threat_Scenario_Output)
        .join(m.Scoped_Threat, m.Threat_Scenario_Output.ScopedThreatID == m.Scoped_Threat.ScopedThreatID)
        .where(m.Threat_Scenario_Output.SessionID == sid, m.Threat_Scenario_Output.Superseded == 0,
            m.Scoped_Threat.ThreatID == threat_id)).scalar()


def test_beyond_cutoff_unique_winner_is_regenerable(db, monkeypatch):
    # Two cat-20 duplicates rank first (verified, score 70); the cat-21 unique winner scores lower
    # (unverified, 65) so it lands at raw rank 3 — beyond scoping_top_n=2 in the duplicate-inclusive
    # ranking, yet a full run keeps it via free-the-slot. Regenerating it must NOT be re-excluded as
    # 'beyond top-N' (that raised RegenerateConflict → the Regenerate control silently did nothing).
    from app.core.config import get_settings
    session = _seed_session(db)
    sid, ss = session["SessionID"], ASSET_UNIT_ID
    dup1, dup2, winner = ("a0000000-0000-4000-8000-000000000001",
                        "a0000000-0000-4000-8000-000000000002",
                        "a0000000-0000-4000-8000-000000000003")
    for tid in (dup1, dup2):
        _seed_threat(db, sid, ss, threat_id=tid, grounding_status=str(GroundingStatus.verified),
                    catalogue_id=20, type_id=10, threat_type="Firmware Tampering", threat_name="Bootloader implant",
                    library_type="Firmware Tampering", library_name="Bootloader implant")
    _seed_threat(db, sid, ss, threat_id=winner, grounding_status=str(GroundingStatus.unverified),
                catalogue_id=21, type_id=11, threat_type="Config Tampering", threat_name="OTA poisoning",
                library_type="Config Tampering", library_name="OTA poisoning")
    db.commit()
    monkeypatch.setattr(get_settings(), "scoping_top_n", 2)

    write_scenarios(db, session, [SUB], DEFAULT_ASSET_CONTEXT, dal.active_threats(db, sid, ss), StubLLM(), _TID)
    db.commit()
    assert len(_scenarios(db, sid)) == 2                                       # one per unique catalogue
    assert _active_winner_count(db, sid, winner) == 1                          # winner active despite raw rank 3

    epoch = dal.next_epoch(db, sid, ss, (SubsystemLevel.SCENARIOS,))
    dal.reset_stage_for_regen(db, sid, ss, (SubsystemLevel.SCENARIOS,), epoch)
    provs = write_scenarios(db, session, [SUB], DEFAULT_ASSET_CONTEXT, dal.active_threats(db, sid, ss),
                            StubLLM(), _TID, epoch=epoch, target_threat_ids={winner})
    assert len(provs) == 1                                                     # regenerated, not silently skipped
    assert _active_winner_count(db, sid, winner) == 1


def test_regen_two_same_catalogue_outputs_no_integrityerror(db):
    # Legacy pre-dedup state: two active same-catalogue (cat 20) outputs with DISTINCT old-style
    # IdentityHashes, so both are active. Regenerating both recomputes IdentityHash via the folded
    # dedup_key → both collapse to sha256(sid|ss|cat:20). Without the regen-branch guard the two
    # rows collide on UX_Scenario_ActiveIdentity in one bulk insert → IntegrityError.
    session = _seed_session(db)
    sid, ss = session["SessionID"], ASSET_UNIT_ID
    t1, t2 = "b0000000-0000-4000-8000-000000000001", "b0000000-0000-4000-8000-000000000002"
    for i, tid in enumerate((t1, t2)):
        _seed_threat(db, sid, ss, threat_id=tid, grounding_status=str(GroundingStatus.verified),
                    catalogue_id=20, type_id=10, threat_type="Firmware Tampering", threat_name="Bootloader implant",
                    library_type="Firmware Tampering", library_name="Bootloader implant")
        scoped_id = str(uuid.uuid4())
        db.execute(insert(m.Scoped_Threat).values(
            ScopedThreatID=scoped_id, SessionID=sid, TenantID="default", SubsystemID=ss, ThreatID=tid,
            Score=70.0, ScopeRank=i + 1, Selected=1, Reason="grounding=verified", Superseded=0, CreatedAt=now()))
        db.execute(insert(m.Threat_Scenario_Output).values(
            OutputID=str(uuid.uuid4()), SessionID=sid, TenantID="default", SubsystemID=ss, ScopedThreatID=scoped_id,
            Status=str(ScenarioStatus.complete), ScenarioJSON="{}", Accepted=0, Superseded=0,
            IdentityHash=f"legacy-{i}", GenerationEpoch=1, CreatedAt=now()))
    db.commit()

    epoch = dal.next_epoch(db, sid, ss, (SubsystemLevel.SCENARIOS,))
    dal.reset_stage_for_regen(db, sid, ss, (SubsystemLevel.SCENARIOS,), epoch)
    # would raise IntegrityError here without the regen-branch de-dup + identity-hash supersede
    write_scenarios(db, session, [SUB], DEFAULT_ASSET_CONTEXT, dal.active_threats(db, sid, ss),
                    StubLLM(), _TID, epoch=epoch, target_threat_ids={t1, t2})
    db.commit()
    active = _scenarios(db, sid)
    assert len(active) == 1                                                    # exactly one active per key
    assert active[0].IdentityHash == hashlib.sha256(f"{sid}|{ss}|cat:20".encode()).hexdigest()


# --- config: scenario count bound to threat count ---------------------------
def test_config_rejects_scenario_count_above_threat_count():
    from pydantic import ValidationError

    from app.core.config import Settings

    with pytest.raises(ValidationError):
        Settings(scoping_top_n=20, max_threats_per_asset=12)
    Settings(scoping_top_n=12, max_threats_per_asset=12)                       # equal is allowed


def test_thin_dedup_headroom_warns_without_raising():
    # scoping_top_n=5 with only 6 candidates (< 5*1.25 = 6.25 headroom) must WARN, not raise —
    # catalogue dedup can under-shoot scoping_top_n when the model repeats itself.
    import structlog

    from app.core.config import Settings

    with structlog.testing.capture_logs() as logs:
        s = Settings(scoping_top_n=5, max_threats_per_asset=6)
    assert s.scoping_top_n == 5                                                # constructed, did NOT raise
    assert any(e.get("event") == "config.thin_dedup_headroom" for e in logs)
