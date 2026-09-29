"""The library-first control-mapping invariant: ONE query per output yields DISTINCT
ControlLibraryIDs with MapRank strictly 1..N, best score first, and SuggestedControl NEVER written
(the LLM no longer proposes controls).

N is decided by control_map_min_count (a floor to reach, backfilled only from above
control_map_backfill_min_score) and control_map_max_count (a ceiling whose drops are counted in the
audit). It is NOT control_map_top_k, which was one number trying to be both and therefore capped
every scenario at five while leaving no floor at all.

Replaces test_control_suggestion_match.py, whose premise was the deleted LLM-suggestion path.
Real SQLite tables, grounding stubbed — same house pattern as test_control_mapping_durable.py.
"""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.enums import ScenarioStatus, StageStatus, SubsystemLevel
from app.db import models as m
from app.pipeline import control_mapping, control_relevance, grounding


def _engine():
    engine = create_engine("sqlite://")
    for tbl in (m.Scenario_Session, m.Subsystem_Stage_State, m.Threat_Scenario,
                m.Threat_Scenario_Control_Map, m.Scenario_Audit,
                # map_controls joins these to put the THREAT in the control query
                # (control_mapping._retrieval_query) — without them the join
                # errors and mapping silently degrades to zero controls.
                m.Scoped_Threat, m.Identified_Threat):
        tbl.__table__.create(engine)
    return engine


def _seed(s, session_id: str, task_id: str) -> str:
    now = datetime.now(UTC)
    scenario_id = str(uuid.uuid4())
    s.execute(m.Scenario_Session.__table__.insert().values(
        SessionID=session_id, TenantID="t", EntityID="e", UserID="u",
        AssetName="a", AssetID="1", SessionStatus="active", CurrentStage="SCENARIOS",
        StageStatus="RUNNING", Mode="full", SubsystemsJSON="[]",
    ))
    s.execute(m.Subsystem_Stage_State.__table__.insert().values(
        StateID=str(uuid.uuid4()), SessionID=session_id,
        SubsystemID=0, Level=SubsystemLevel.SCENARIOS, Status=StageStatus.RUNNING,
        GenerationEpoch=1, ActiveTaskID=task_id,
        LeaseExpiresAt=now + timedelta(minutes=10), HeartbeatAt=now, AttemptCount=1, UpdatedAt=now,
    ))
    s.execute(m.Threat_Scenario.__table__.insert().values(
        ScenarioID=scenario_id, SessionID=session_id,
        SubsystemID=0, ScopedThreatID=str(uuid.uuid4()), Status=ScenarioStatus.complete,
        ScenarioJSON=json.dumps({"scenario_title": "Credential theft against the HMI",
                                "scenario_statement": "An attacker replays operator credentials."}),
        Accepted=0, Superseded=0, ScenarioNumber=1, GenerationEpoch=1, CreatedAt=now,
    ))
    s.commit()
    return scenario_id


def test_map_controls_actually_threads_the_threat_into_the_query(monkeypatch):
    """THE regression the pure-function test above cannot catch.

    collect_control_query taking a threat proves nothing unless map_controls PASSES one. An
    audit reverted map_controls' call to the narrative-only form and the entire suite still
    passed: every existing map_controls test seeds a ScopedThreatID with no matching
    Scoped_Threat row, so the OUTER join yields NULLs and the threat-augmented call is
    byte-identical to the reverted one — and all of them stub ground_control_queries with a
    lambda that ignores `flat`, so the query TEXT is never observed.

    This test seeds the real chain and asserts on the query map_controls BUILDS. It pins, in
    one assertion: the two join predicates, the library-spelling preference (ltname/lttype over
    tname/ttype), the argument order, and the threat's position as a PREFIX. Break any of them
    and the measured failure returns — the correct control scoring 1.9/100 while the API
    publishes `controls: []` as a library gap.

    The expected text now also pins the WIDENED select: ThreatCategory leads (it rides
    eligible_outputs' own row, never a second query per scenario) and the stored actors would
    follow the name if this threat had any. Order is the one builder's: category, type, name,
    actors, title, statement, risk, asset, involved systems."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid, task_id = str(uuid.uuid4()), str(uuid.uuid4())
    scoped_id, threat_id = str(uuid.uuid4()), str(uuid.uuid4())
    now = datetime.now(UTC)
    with Session() as s:
        scenario_id = _seed(s, sid, task_id)
        # Point the seeded output at a REAL scoped/threat chain — the piece every other
        # map_controls test leaves dangling.
        s.execute(m.Threat_Scenario.__table__.update()
                .where(m.Threat_Scenario.ScenarioID == scenario_id)
                .values(ScopedThreatID=scoped_id))
        s.execute(m.Scoped_Threat.__table__.insert().values(
            ScopedThreatID=scoped_id, SessionID=sid,
            SubsystemID=0, ThreatID=threat_id, Score=90.0, ScopeRank=1, Selected=1,
            Superseded=0, CreatedAt=now))
        # Proposed vs library spelling deliberately DIFFER, so the assertion below proves the
        # curator's wording wins — the library is what the controls were written against.
        s.execute(m.Identified_Threat.__table__.insert().values(
            ThreatID=threat_id, SessionID=sid, SubsystemID=0,
            ThreatCategory="Tampering", ThreatType="model wording for the type",
            ThreatName="model wording for the name",
            LibraryThreatType="Supply Chain Compromise",
            LibraryThreatName="Compromised OT supply chain or hardware",
            GroundingStatus="verified", GroundingScore=100.0, Superseded=0, CreatedAt=now))
        s.commit()

    seen: list[str] = []

    def _capture(llm, flat, candidates, s_):
        seen.extend(q for q, _qv in flat)
        return [grounding.ControlMatches([], True) for _ in flat]

    monkeypatch.setattr(grounding, "get_control_candidates",
                        lambda sess, itot: [{"ControlLibraryID": 1, "text": "c1"}])
    monkeypatch.setattr(control_mapping, "_min_score",
                        lambda sess, llm, s_: grounding.Threshold(60.0, "test"))
    monkeypatch.setattr(grounding, "ground_control_queries", _capture)

    class _FakeLLM:
        def embed(self, texts, kind):
            return [[0.0] for _ in texts]

    with Session() as s:
        control_mapping.map_controls(s, {"SessionID": sid, "TenantID": "t", "EntityID": "e"},
                                    {}, [], _FakeLLM(), 0, task_id, 1, durable=True)

    assert seen == [
        "Tampering Supply Chain Compromise Compromised OT supply chain or hardware "
        "Credential theft against the HMI An attacker replays operator credentials."
    ], seen


def _run_one_mapping(monkeypatch, matches):
    """One map_controls pass over ONE seeded scenario, with `matches` as the reranked result.

    The candidate pool is derived from the matches, because
    control_relevance.validate_control_mapping refuses a map row for a control that was never in
    this scenario's candidate set — a stub whose reranker invents ids the pool never held is
    describing a state the production path cannot reach.

    Returns (map rows best-rank-first, the controls_mapped audit detail).
    """
    Session = sessionmaker(bind=_engine(), future=True)
    sid, task_id = str(uuid.uuid4()), str(uuid.uuid4())
    with Session() as s:
        _seed(s, sid, task_id)
    pool = [{"ControlLibraryID": cid, "ITOT": None, "Domain": None, "text": f"c{cid}"}
            for cid in dict.fromkeys(row["ControlLibraryID"] for row, _score in matches)]
    monkeypatch.setattr(grounding, "get_control_candidates", lambda sess, itot: pool)
    monkeypatch.setattr(control_mapping, "_min_score",
                        lambda sess, llm, s: grounding.Threshold(60.0, "test"))
    monkeypatch.setattr(grounding, "ground_control_queries",
                        lambda llm, flat, candidates, s: [
                            grounding.ControlMatches(list(matches), True) for _ in flat])

    class _FakeLLM:
        def embed(self, texts, kind):
            return [[0.0] for _ in texts]

    with Session() as s:
        control_mapping.map_controls(s, {"SessionID": sid, "TenantID": "t", "EntityID": "e"},
                                     {}, [], _FakeLLM(), 0, task_id, 1, durable=True)
    with Session() as s:
        rows = s.execute(m.Threat_Scenario_Control_Map.__table__.select()
                         .order_by(m.Threat_Scenario_Control_Map.MapRank)).fetchall()
        detail = json.loads(s.execute(m.Scenario_Audit.__table__.select()).fetchall()[0].DetailJSON)
    return rows, detail


def _scored(*pairs):
    return [({"ControlLibraryID": cid}, score) for cid, score in pairs]


def test_eight_controls_above_the_cutoff_all_get_mapped(monkeypatch):
    """control_map_top_k was a HARD CAP of 5 that silently discarded controls which HAD cleared
    the cutoff — and told nobody, so "the library had exactly five good controls" and "the library
    had eight and three were thrown away" were indistinguishable afterwards. min_count is a floor
    now, not a ceiling: eight above the cutoff means eight rows."""
    rows, detail = _run_one_mapping(monkeypatch, _scored(*[(i, 95.0 - i) for i in range(1, 9)]))
    assert [r.ControlLibraryID for r in rows] == list(range(1, 9))
    assert [r.MapRank for r in rows] == list(range(1, 9))
    assert (detail["mapped_count"], detail["cleared_cutoff_count"]) == (8, 8)
    assert (detail["capped_count"], detail["backfilled_count"]) == (0, 0)


def test_forty_above_the_cutoff_stop_at_max_count_and_the_cap_is_recorded(monkeypatch):
    """The ceiling stays — one scenario must not attach half the library — but it is no longer
    SILENT: capped_count says how many controls that had cleared the cutoff it dropped, which is
    the number nothing anywhere used to record."""
    rows, detail = _run_one_mapping(monkeypatch, _scored(*[(i, 99.0 - i * 0.5) for i in range(1, 41)]))
    from app.core.config import get_settings
    ceiling = get_settings().control_map_max_count
    assert len(rows) == ceiling
    assert detail["mapped_count"] == ceiling
    assert detail["cleared_cutoff_count"] == 40
    assert detail["capped_count"] == 40 - ceiling


def test_a_shortfall_backfills_only_from_above_the_backfill_floor(monkeypatch):
    """Too few clear the cutoff, so the best remaining matches fill up to min_count — but ONLY
    from above control_map_backfill_min_score. Without that floor the backfill would attach
    whatever ranked last, a control with no relation to the scenario presented as a real match."""
    from app.core.config import get_settings
    s = get_settings()
    above_floor = s.control_map_backfill_min_score + 5.0
    rows, detail = _run_one_mapping(monkeypatch, _scored(
        (1, 95.0), (2, 90.0),                                     # cleared the 60.0 cutoff
        (3, above_floor), (4, above_floor - 1), (5, above_floor - 2),   # backfill candidates
        (6, s.control_map_backfill_min_score - 1)))               # below the floor: never added
    assert detail["mapped_count"] == s.control_map_min_count == 5
    assert (detail["cleared_cutoff_count"], detail["backfilled_count"]) == (2, 3)
    assert [r.ControlLibraryID for r in rows] == [1, 2, 3, 4, 5]
    assert 6 not in {r.ControlLibraryID for r in rows}


def test_nothing_below_the_backfill_floor_is_ever_mapped(monkeypatch):
    """The floor is absolute: a shortfall it cannot fill comes back SHORT. An arbitrary control is
    worse than a missing one on a remediation plan, and `mapped_count` under `min_count` is a
    reviewable fact — padding it is not."""
    from app.core.config import get_settings
    floor = get_settings().control_map_backfill_min_score
    rows, detail = _run_one_mapping(monkeypatch, _scored(
        (1, 95.0), (2, floor - 0.1), (3, floor - 10), (4, 1.0)))
    assert [r.ControlLibraryID for r in rows] == [1], "only the control that cleared the cutoff"
    assert (detail["mapped_count"], detail["backfilled_count"]) == (1, 0)
    assert detail["dropped_below_cutoff_count"] == 3
    assert detail["warning_count"] >= 1, "being short of the floor must be recorded, not hidden"


def test_one_query_yields_distinct_ranked_controls(monkeypatch):
    """The GAP the redesign guards against: collapsing to one best match per query would cap
    every scenario at ONE control. 7 reranked matches (one duplicate id, one below threshold)
    must persist as 5 distinct rows, MapRank 1..5, no SuggestedControl.

    The 5 here is no longer a cap, it is what the library offered: five controls cleared the 60.0
    cutoff, so min_count was already met and control 6 (40.0, below the cutoff) was never borrowed.
    See the four tests above for the floor/ceiling rules that replaced control_map_top_k."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid, task_id = str(uuid.uuid4()), str(uuid.uuid4())
    with Session() as s:
        scenario_id = _seed(s, sid, task_id)

    matches = [
        ({"ControlLibraryID": 1}, 95.0),
        ({"ControlLibraryID": 2}, 90.0),
        ({"ControlLibraryID": 1}, 88.0),   # duplicate id — best[cid] keeps the 95.0 row
        ({"ControlLibraryID": 3}, 85.0),
        ({"ControlLibraryID": 4}, 80.0),
        ({"ControlLibraryID": 5}, 75.0),
        ({"ControlLibraryID": 6}, 40.0),   # below min score — dropped
    ]
    monkeypatch.setattr(grounding, "get_control_candidates",
                        lambda sess, itot: [{"ControlLibraryID": i, "text": f"c{i}"}
                                            for i in range(1, 7)])
    monkeypatch.setattr(control_mapping, "_min_score",
                        lambda sess, llm, s: grounding.Threshold(60.0, "test"))
    monkeypatch.setattr(grounding, "ground_control_queries",
                        lambda llm, flat, candidates, s: [
                            grounding.ControlMatches(list(matches), True) for _ in flat])

    class _FakeLLM:
        def embed(self, texts, kind):
            return [[0.0] for _ in texts]

    scenario_session = {"SessionID": sid, "TenantID": "t", "EntityID": "e"}
    with Session() as s:
        control_mapping.map_controls(s, scenario_session, {}, [], _FakeLLM(), 0, task_id, 1,
                                     durable=True)

    with Session() as s:
        rows = s.execute(m.Threat_Scenario_Control_Map.__table__.select()
                         .order_by(m.Threat_Scenario_Control_Map.MapRank)).fetchall()
    assert [r.ControlLibraryID for r in rows] == [1, 2, 3, 4, 5]      # distinct, best-first
    assert [r.MapRank for r in rows] == [1, 2, 3, 4, 5]               # strictly increasing
    assert [r.Score for r in rows] == [95.0, 90.0, 85.0, 80.0, 75.0]  # dedup kept the best
    assert all(r.SuggestedControl is None for r in rows)              # LLM suggestions are gone
    assert all(r.ScenarioID == scenario_id for r in rows)


# --- F5: the scenario-to-involved-system join ---------------------------------------------------

def test_an_involved_system_resolves_by_id_when_its_name_no_longer_matches():
    """THE F5 REGRESSION PIN. The per-scenario ITOT context joined the scenario's involved systems
    to their category ids BY NAME, requiring an exact non-null string match against the session
    JSON. A system renamed in onboarding after the session was scoped — or a name the model reworded
    — contributed no category at all, so the scenario's ITOT context quietly narrowed to the asset's
    alone. `supporting_system_id` is the stable key and the public contract carries it."""
    index = control_mapping._system_category_index([
        {"id": 306, "name": "OT Telecom Network", "asset_type_id": 2},
        {"id": 307, "name": "Billing", "asset_type_id": 1},
    ])
    resolved = control_mapping._involved_system_categories({"supporting_systems_involved": [
        # Renamed since scoping: the name misses, the id hits.
        {"supporting_system_id": 306, "supporting_system": "Telecom Net (2026 rename)"},
        # No id at all (an older stored scenario): the name is still a door.
        {"supporting_system": "Billing"},
    ]}, index)
    assert resolved.category_ids == [2, 1]
    assert resolved.unresolved == ()


def test_an_unresolvable_involved_system_is_recorded_rather_than_silently_dropped():
    """The other half of F5: silence was the defect, not the fallback. A system matching neither
    door narrows the context and must SAY so, all the way into the audit row."""
    index = control_mapping._system_category_index([
        {"id": 306, "name": "OT Telecom Network", "asset_type_id": 2}])
    resolved = control_mapping._involved_system_categories({"supporting_systems_involved": [
        {"supporting_system_id": 306, "supporting_system": "OT Telecom Network"},
        {"supporting_system_id": 999, "supporting_system": "Decommissioned rig"},
        {"supporting_system": "Never scoped"},
        {"supporting_system": "   "},          # nothing named at all — not a miss, just empty
        "not a dict",
    ]}, index)
    assert resolved.category_ids == [2]
    assert resolved.unresolved == ("Never scoped", "id=999")
    # ...and it reaches the audit row, which is the whole point of carrying it on the plan.
    plan = control_mapping._ScenarioMappingPlan(
        "scn-1", "q", control_relevance.ItotApplicabilityContext(), resolved.unresolved)
    detail = control_mapping._relevance_detail([plan], {})
    assert detail["unresolved_involved_systems"] == ["Never scoped", "id=999"]


# --- the effective cutoff, and the floor that is a fraction of it -------------------------------

class _UnpinnedSettings:
    """Settings with neither the cutoff nor the deprecated absolute floor supplied, so `_min_score`
    and `_backfill_floor` both take their runtime-resolution branch."""
    model_fields_set: set[str] = set()
    embedding_model = "emb-A"
    reranker_model = "rr-A"
    control_map_backfill_ratio = 0.42
    control_map_backfill_min_score = 25.0
    control_map_min_score = 60.0


def _cutoff(monkeypatch, *, stored, settings=None):
    """`_min_score` with `latest_control_map_cutoff` answering `stored`, everything else real."""
    monkeypatch.setattr(control_mapping.grounding, "latest_control_map_cutoff",
                        lambda sess, pair: stored)
    monkeypatch.setattr(control_mapping.grounding, "resolve_thresholds",
                        lambda sess, llm, s: grounding.Threshold(88.0, "calibrated"))
    return control_mapping._min_score(object(), None, settings or _UnpinnedSettings())


def test_a_stored_control_map_cutoff_beats_the_borrowed_threat_threshold(monkeypatch):
    """The wiring: POST /v1/tsg/control-map/calibrate stores ControlMapTh and its Swagger promises
    "control matching picks it up with no restart". Nothing read it, so the promise was false and
    every pass kept borrowing a threshold measured label-vs-label for a different question."""
    assert _cutoff(monkeypatch, stored=41.0) == grounding.Threshold(
        41.0, "calibrated_for_control_mapping")
    # No measurement for this pair: fall through, and SAY it was borrowed.
    assert _cutoff(monkeypatch, stored=None) == grounding.Threshold(
        88.0, "borrowed_from_threat_grounding_uncalibrated")


def test_a_stored_measurement_outranks_a_pinned_env_cutoff(monkeypatch):
    """Precedence is STORED → env → borrowed, by the owner's decision (2026-09-25). It used to be
    env first, and this test used to pin THAT; the order is the whole of the decision, so inverting
    it without inverting this test would have left the suite asserting the superseded rule.

    The reasoning the order encodes: `TSG_CONTROL_MAP_MIN_SCORE` is a GUESS made before anyone
    measured this deployment, while the stored value is the answer from scoring real scenarios
    against the real library. So a measurement wins even when the env file disagrees — and an
    operator editing the env file afterwards changes nothing, which is why `origin` has to say which
    branch answered."""
    class _Pinned(_UnpinnedSettings):
        model_fields_set = {"control_map_min_score"}       # env says 60.0

    assert _cutoff(monkeypatch, stored=41.0, settings=_Pinned()) == grounding.Threshold(
        41.0, "calibrated_for_control_mapping")


def test_the_env_cutoff_is_what_runs_until_the_first_calibration_is_stored(monkeypatch):
    """The other half of the same rule, and the state EVERY deployment starts in: a first boot has no
    stored row, so the operator's env value is the cutoff — not the borrowed threat threshold. That
    is what keeps the env setting worth having; without this the inversion above would read as "the
    env file no longer matters", which is only true once a measurement exists."""
    class _Pinned(_UnpinnedSettings):
        model_fields_set = {"control_map_min_score"}

    assert _cutoff(monkeypatch, stored=None, settings=_Pinned()) == grounding.Threshold(
        60.0, "env_pinned")
    # And with neither, the borrowed threshold — still last, still labelled as never measured here.
    assert _cutoff(monkeypatch, stored=None) == grounding.Threshold(
        88.0, "borrowed_from_threat_grounding_uncalibrated")


def test_a_stored_zero_beats_a_pinned_env_cutoff_because_zero_is_a_measurement(monkeypatch):
    """The inversion makes the absence-is-None rule load-bearing in a new place. A falsy test would
    hand a pinned 60.0 back while a measured 0.0 sat in the database — reporting `env_pinned` for a
    deployment whose own measurement said "admit everything". Absence is None; 0.0 is an answer."""
    class _Pinned(_UnpinnedSettings):
        model_fields_set = {"control_map_min_score"}

    assert _cutoff(monkeypatch, stored=0.0, settings=_Pinned()) == grounding.Threshold(
        0.0, "calibrated_for_control_mapping")


def test_a_stored_cutoff_for_another_model_pair_is_never_used(monkeypatch):
    """A cutoff measured under a different embedding+reranker pair is not a cutoff for this one, and
    reading it would be WORSE than borrowing — it would arrive labelled as measured. The pair filter
    lives in `grounding.latest_control_map_cutoff`; this pins that `_min_score` asks it with the
    RUNNING process's own pair and honours the None it gets back."""
    asked: list[tuple[str, str]] = []

    def _reader(sess, pair):
        asked.append(pair)
        return 41.0 if pair == ("emb-DEV", "rr-DEV") else None      # measured on dev only

    monkeypatch.setattr(control_mapping.grounding, "latest_control_map_cutoff", _reader)
    monkeypatch.setattr(control_mapping.grounding, "resolve_thresholds",
                        lambda sess, llm, s: grounding.Threshold(88.0, "calibrated"))
    resolved = control_mapping._min_score(object(), None, _UnpinnedSettings())
    assert asked == [("emb-A", "rr-A")]
    assert resolved.origin == "borrowed_from_threat_grounding_uncalibrated"
    assert resolved.value == 88.0, "the dev number must not leak in under any origin"


def test_a_stored_zero_cutoff_is_a_measurement_not_an_absent_one(monkeypatch):
    """`grounding.record_control_map_finished` keys success on `cutoff is not None`, so a measured
    0.0 IS stored as a success row. A falsy test here would discard it and report a borrowed number
    as the cutoff in force — the provenance lie the origin field exists to prevent. 0 admits every
    candidate, which is a loud reviewable outcome; the same behaviour unexplained is not."""
    assert _cutoff(monkeypatch, stored=0.0) == grounding.Threshold(
        0.0, "calibrated_for_control_mapping")


def test_the_backfill_floor_moves_with_the_cutoff_that_is_actually_in_force(monkeypatch):
    """THE RATIO PIN. The floor used to be an absolute 25.0 while the cutoff was resolved at runtime
    from three sources, so it silently changed meaning every time that number moved: 42% of a cutoff
    of 60, 83% of a cutoff of 30, and at any cutoff at or below 25 the band was EMPTY and
    control_map_min_count silently unreachable. A stored measurement must move the floor with it."""
    s = _UnpinnedSettings()
    assert control_mapping._backfill_floor(60.0, s) == pytest.approx(25.2)
    assert control_mapping._backfill_floor(30.0, s) == pytest.approx(12.6)
    assert control_mapping._backfill_floor(20.0, s) == pytest.approx(8.4)


def test_the_backfill_band_is_non_empty_for_every_cutoff_the_settings_permit():
    """The guarantee the deleted boot validator could not give: it could only bound the EXPLICITLY
    PINNED cutoff, and two of the three sources are invisible to config.py. `gt=0.0, lt=1.0` on the
    ratio plus this resolution cover all three — a fraction strictly inside (0, 1) of any positive
    cutoff is strictly below that cutoff, so there is always a band for backfill to draw from."""
    from app.core.config import Settings
    for ratio in (0.01, 0.42, 0.99):
        s = Settings(control_map_backfill_ratio=ratio)
        for cutoff in (0.01, 1.0, 25.0, 42.5, 60.0, 100.0):
            floor = control_mapping._backfill_floor(cutoff, s)
            assert 0.0 <= floor < cutoff, f"empty band at ratio={ratio} cutoff={cutoff}"
    # And the bounds are enforced at boot, so a ratio that COULD empty the band cannot be loaded.
    for bad in (0.0, 1.0, 1.5, -0.1):
        with pytest.raises(ValueError):
            Settings(control_map_backfill_ratio=bad)


def test_a_deprecated_absolute_floor_that_would_empty_the_band_is_refused(monkeypatch):
    """The override stays honoured — existing .env files keep their number — but only while it is
    genuinely below the cutoff in force. Its author could not have known what a later measurement
    would resolve the cutoff to, and obeying it there reinstates the exact empty band this
    replaces."""
    class _PinnedFloor(_UnpinnedSettings):
        model_fields_set = {"control_map_backfill_min_score"}
        control_map_backfill_min_score = 25.0

    s = _PinnedFloor()
    assert control_mapping._backfill_floor(60.0, s) == 25.0, "an override below the cutoff is obeyed"
    logged: list[str] = []
    monkeypatch.setattr(control_mapping.log, "warning",
                        lambda event, **kw: logged.append(event))
    assert control_mapping._backfill_floor(20.0, s) == pytest.approx(8.4), (
        "an override at or above the cutoff falls back to the ratio rather than empty the band")
    assert logged == ["controls.backfill_floor_override_ignored"], (
        "and it is never silent — neither obeying nor ignoring it may go unrecorded")


def test_the_resolved_floor_is_recorded_beside_the_cutoff_in_the_audit_row(monkeypatch):
    """The floor is now DERIVED, so a reviewer cannot reconstruct it from the settings alone — a
    stored measurement moves the cutoff and the floor with it, with no config change. Both the
    number and the cutoff's origin have to be on the row."""
    rows, detail = _run_one_mapping(monkeypatch, _scored((1, 95.0), (2, 90.0)))
    assert rows
    assert detail["effective_min_score"] == 60.0            # _run_one_mapping stubs the cutoff
    assert detail["effective_backfill_min_score"] == pytest.approx(25.2)
    assert detail["effective_min_score_origin"] == "test"


def test_the_cutoff_resolves_without_constructing_an_llm_client(monkeypatch):
    """F3's second half. `grounding.resolve_thresholds` declares `llm: LLMClient | None` and
    documents it as "accepted but unused", so the top-up's `_min_score(sess, llm or get_llm(), s)`
    built a client purely to fill a parameter nothing reads — cost on the one path whose entire
    purpose is to be cheap enough to fail open."""
    def _no_client():
        raise AssertionError("no LLM client may be constructed to fill an unused parameter")
    monkeypatch.setattr(control_mapping, "get_llm", _no_client)
    seen: list[object] = []
    monkeypatch.setattr(control_mapping.grounding, "resolve_thresholds",
                        lambda sess, llm, s: (seen.append(llm),
                                            grounding.Threshold(60.0, "static_default"))[1])

    class _UnpinnedSettings:
        model_fields_set: set[str] = set()

    assert control_mapping._min_score(None, None, _UnpinnedSettings()).value == 60.0
    assert seen == [None], "None must be forwarded, not replaced with a freshly built client"


def test_empty_candidate_library_still_returns_control_matches_not_bare_lists():
    """ground_control_queries is typed `-> list[ControlMatches]`. Its empty-`rows` fast path
    used to return `[[] for _ in queries]` — a bare list, not the NamedTuple every caller
    trusts. map_controls (above) reads `.answered` on every returned item unconditionally, so
    an empty control library would have crashed with AttributeError instead of the intended
    "answered, zero matches" outcome the type exists to express."""
    class _UncalledLLM:
        def embed(self, texts, kind):
            raise AssertionError("the empty-rows fast path must return before touching the LLM")

    from app.core.config import get_settings

    out = grounding.ground_control_queries(
        _UncalledLLM(), [("q1", None), ("q2", None)], [], get_settings())
    assert out == [grounding.ControlMatches([], True), grounding.ControlMatches([], True)]
    assert all(isinstance(r, grounding.ControlMatches) for r in out)
    assert all(r.answered is True and r.matches == [] for r in out)
