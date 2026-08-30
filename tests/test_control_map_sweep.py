"""The control-mapping retry queue must have a CONSUMER.

`map_controls` selects on `ControlsMappedAt IS NULL` and three of its paths deliberately return
without stamping — `controls.no_candidates`, `controls.lease_lost`, and a per-output unanswered
rerank — each documented as safe because "the row just stays in the queue and the next run
retries it". There was no next run: the only caller is `_finalize_scenario_batch`, the tail of a
scenario batch for that same session. So for a finished session every "recoverable" failure was
permanent — one 429 during its only pass and that scenario had no controls forever, published as
`controls: []`, which the API documents in three places as a genuine library gap.

test_control_mapping_retry.py pins the PRODUCER half (a failed rerank stays in the queue). This
file pins the half that was missing entirely: something drains it. Plus the three fences that
keep the sweep off work it must not touch.
Real SQLite tables, grounding stubbed — same house pattern as test_control_text_mapping.py.
"""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.core.enums import ScenarioStatus, StageStatus, SubsystemLevel
from app.db import models as m
from app.pipeline import cascade, control_mapping, grounding

EPOCH = 1
STALE = get_settings().stage_lease_seconds + 60   # older than one lease => the pipeline is done


def _engine():
    engine = create_engine("sqlite://")
    for tbl in (m.Scenario_Session, m.Subsystem_Stage_State, m.Threat_Scenario_Output,
                m.Threat_Scenario_Control_Map, m.Scenario_Audit,
                m.Scoped_Threat, m.Identified_Threat):
        tbl.__table__.create(engine)
    return engine


def _seed(s, *, created_offset_days: int = 1, stage_status: str = StageStatus.AWAITING_DECISION,
        settled_secs_ago: int = STALE, lock_status: str = StageStatus.IDLE,
        lock_task: str | None = None, accepted: int = 0,
        superseded: int = 0) -> tuple[str, str]:
    """One session whose SCENARIOS stage is settled and whose single complete output was never
    control-mapped — i.e. exactly the state the old code stranded forever."""
    now = datetime.now(UTC)
    sid, scenario_id = str(uuid.uuid4()), str(uuid.uuid4())
    s.execute(m.Scenario_Session.__table__.insert().values(
        SessionID=sid, TenantID="t", EntityID="e", UserID="u",
        AssetName="a", AssetID="1", SessionStatus="completed", CurrentStage="SCENARIOS",
        StageStatus="COMPLETE", Mode="full", SubsystemsJSON="[]",
        CreatedAt=control_mapping.CONTROL_MAP_SWEEP_FROM + timedelta(days=created_offset_days)))
    for level, status, task in ((SubsystemLevel.SCENARIOS, stage_status, None),
                                (SubsystemLevel.LOCK, lock_status, lock_task)):
        s.execute(m.Subsystem_Stage_State.__table__.insert().values(
            StateID=str(uuid.uuid4()), SessionID=sid, TenantID="t", EntityID="e",
            SubsystemID=0, Level=level, Status=status, GenerationEpoch=EPOCH,
            ActiveTaskID=task, AttemptCount=1,
            UpdatedAt=now - timedelta(seconds=settled_secs_ago)))
    s.execute(m.Threat_Scenario_Output.__table__.insert().values(
        ScenarioID=scenario_id, SessionID=sid, TenantID="t", EntityID="e", UserID="u",
        SubsystemID=0, ScopedThreatID=str(uuid.uuid4()), Status=ScenarioStatus.complete,
        ScenarioJSON=json.dumps({"scenario_title": "Setpoint manipulation on the HMI",
                                "scenario_statement": "An attacker writes an unsafe setpoint."}),
        Accepted=accepted, Superseded=superseded, ScenarioNumber=1, GenerationEpoch=EPOCH,
        ControlsMappedAt=None, CreatedAt=now))
    s.commit()
    return sid, scenario_id


def _stub_grounding(monkeypatch, *, matches=((1, 91.0), (2, 77.0))):
    monkeypatch.setattr(grounding, "get_control_candidates",
                        lambda sess, itot: [{"ControlLibraryID": 1, "text": "c1"}])
    monkeypatch.setattr(control_mapping, "_min_score",
                        lambda sess, llm, s_: grounding.Threshold(60.0, "test"))
    monkeypatch.setattr(grounding, "ground_control_queries",
                        lambda llm, flat, candidates, s_: [
                            grounding.ControlMatches(
                                [({"ControlLibraryID": cid}, sc) for cid, sc in matches], True)
                            for _ in flat])


class _FakeLLM:
    def embed(self, texts, kind):
        return [[0.0] for _ in texts]


def _mapped(s, scenario_id) -> tuple[int, object]:
    n = len(s.execute(select(m.Threat_Scenario_Control_Map.ControlLibraryID)
                    .where(m.Threat_Scenario_Control_Map.ScenarioID == scenario_id)).all())
    stamp = s.execute(select(m.Threat_Scenario_Output.ControlsMappedAt)
                    .where(m.Threat_Scenario_Output.ScenarioID == scenario_id)).scalar_one()
    return n, stamp


def test_the_sweep_maps_an_output_the_pipeline_left_stranded(monkeypatch):
    """THE regression. Before this consumer existed, an output left unstamped by ANY of
    map_controls' three recoverable paths stayed unstamped and unmapped forever — nothing
    anywhere re-ran mapping for a finished session, and nothing clears ControlsMappedAt either,
    so the queue was write-only. Delete run_control_map_sweep (or its beat entry) and this
    scenario's controls are permanently `[]`, indistinguishable from a real library gap."""
    Session = sessionmaker(bind=_engine(), future=True)
    _stub_grounding(monkeypatch)
    with Session() as s:
        sid, scenario_id = _seed(s)
        assert control_mapping.sessions_awaiting_control_mapping(s) == [(sid, 0, EPOCH)]
        assert cascade.run_control_map_sweep(s, _FakeLLM()) == [sid]
        n, stamp = _mapped(s, scenario_id)
        assert n == 2, "the sweep must actually write the control map rows"
        assert stamp is not None, "and stamp the output, so it leaves the queue"
        # Idempotent: a second tick finds nothing, so beat cannot re-rank the same output forever.
        assert control_mapping.sessions_awaiting_control_mapping(s) == []
        assert cascade.run_control_map_sweep(s, _FakeLLM()) == []


def test_sessions_created_before_ship_time_are_never_swept(monkeypatch):
    """The owner's explicit decision: "i do not want controls to mapped to the already created
    sessions". CONTROL_MAP_SWEEP_FROM is the whole guarantee — a constant, not a setting, so it
    cannot be widened by an env edit."""
    Session = sessionmaker(bind=_engine(), future=True)
    _stub_grounding(monkeypatch)
    with Session() as s:
        _sid, scenario_id = _seed(s, created_offset_days=-1)   # one day BEFORE ship time
        assert control_mapping.sessions_awaiting_control_mapping(s) == []
        assert cascade.run_control_map_sweep(s, _FakeLLM()) == []
        assert _mapped(s, scenario_id) == (0, None)


def test_a_running_scenarios_stage_is_never_swept(monkeypatch):
    """A live batch owns the session and maps at its own tail. Sweeping it would put two writers
    on one subsystem: duplicate (scenario_id, ControlLibraryID) inserts, an IntegrityError, and the
    real batch losing its ENTIRE mapping to one swallowed `controls.mapping_failed`."""
    Session = sessionmaker(bind=_engine(), future=True)
    _stub_grounding(monkeypatch)
    with Session() as s:
        _seed(s, stage_status=StageStatus.RUNNING)
        assert control_mapping.sessions_awaiting_control_mapping(s) == []


def test_a_just_settled_stage_is_never_swept(monkeypatch):
    """write_scenarios settles the stage BEFORE it maps controls — even more so since mapping
    moved after the commit — so "settled" alone does not mean mapping has run. There is a window
    where the in-pipeline mapping is still going, and sweeping into it would put two writers on
    one subsystem. One stage_lease_seconds is the codebase's own "this work step is no longer
    alive", so no second grace knob is invented."""
    Session = sessionmaker(bind=_engine(), future=True)
    _stub_grounding(monkeypatch)
    with Session() as s:
        _seed(s, settled_secs_ago=5)
        assert control_mapping.sessions_awaiting_control_mapping(s) == []


def test_a_held_subsystem_lock_defers_the_sweep(monkeypatch):
    """The queue read cannot see a regenerate/next-set that STARTS between the read and the map.
    _subsystem_lock is the codebase's one-writer-per-subsystem fence ([R5]) and closes it: the
    row stays in the queue rather than being mapped twice, so the next tick picks it up."""
    Session = sessionmaker(bind=_engine(), future=True)
    _stub_grounding(monkeypatch)
    with Session() as s:
        sid, scenario_id = _seed(s, lock_status=StageStatus.RUNNING, lock_task=str(uuid.uuid4()))
        assert control_mapping.sessions_awaiting_control_mapping(s) == [(sid, 0, EPOCH)]
        assert cascade.run_control_map_sweep(s, _FakeLLM()) == []
        assert _mapped(s, scenario_id) == (0, None), "deferred, NOT stamped — it must retry later"


def test_an_accepted_but_superseded_output_is_still_swept(monkeypatch):
    """The predicate used to be `active(Superseded)` alone, which silently excluded these.

    An ACCEPTED output that a later regenerate superseded is still rendered by /results — it is
    the `replaced_scenarios` history a reviewer sees, and test_accept_any_version.py pins that it
    is shown. Excluding it from the queue meant a scenario a reviewer had SIGNED OFF carried a
    permanently empty control list. This is audit gap 20, which the first version of the sweep
    was claimed to cover and did not.
    """
    Session = sessionmaker(bind=_engine(), future=True)
    _stub_grounding(monkeypatch)
    with Session() as s:
        sid, scenario_id = _seed(s, accepted=1, superseded=1)
        assert control_mapping.sessions_awaiting_control_mapping(s) == [(sid, 0, EPOCH)]
        assert cascade.run_control_map_sweep(s, _FakeLLM()) == [sid]
        n, stamp = _mapped(s, scenario_id)
        assert n == 2 and stamp is not None


def test_an_unaccepted_superseded_output_is_still_ignored(monkeypatch):
    """Control for the test above: widening the predicate must not drag in every dead row.
    A superseded output nobody accepted was replaced and is not shown — mapping it would be
    rerank spend on a row no one will ever read."""
    Session = sessionmaker(bind=_engine(), future=True)
    _stub_grounding(monkeypatch)
    with Session() as s:
        _seed(s, accepted=0, superseded=1)
        assert control_mapping.sessions_awaiting_control_mapping(s) == []


def test_the_queue_is_drained_oldest_first(monkeypatch):
    """LIMIT with no ORDER BY is an arbitrary TOP-N on SQL Server — and an arbitrary set can be a
    STABLE one. Paired with a session that always fails, the optimiser could hand back the same
    doomed rows every tick while everything behind them starved forever. Oldest-first is
    deterministic AND drains the queue."""
    Session = sessionmaker(bind=_engine(), future=True)
    _stub_grounding(monkeypatch)
    with Session() as s:
        newer, _ = _seed(s, settled_secs_ago=STALE)
        older, _ = _seed(s, settled_secs_ago=STALE * 3)
        assert [sid for sid, _ss, _e in control_mapping.sessions_awaiting_control_mapping(s)] ==             [older, newer]


def test_one_failing_session_does_not_stall_the_others(monkeypatch):
    """Without per-session isolation the first raising session killed the whole tick — and since
    the queue is ordered oldest-first, that same session would head every subsequent tick too.
    One poison row would have blocked the entire queue permanently, which is exactly the class of
    silent, self-perpetuating failure this sweep was built to end."""
    Session = sessionmaker(bind=_engine(), future=True)
    _stub_grounding(monkeypatch)
    with Session() as s:
        poison, poison_out = _seed(s, settled_secs_ago=STALE * 3)   # ordered FIRST
        healthy, healthy_out = _seed(s, settled_secs_ago=STALE)

        real_load = cascade.dal.load_session

        def _load(sess_, session_id):
            if session_id == poison:
                raise RuntimeError("transient read failure on this one session")
            return real_load(sess_, session_id)

        monkeypatch.setattr(cascade.dal, "load_session", _load)
        assert cascade.run_control_map_sweep(s, _FakeLLM()) == [healthy]
        assert _mapped(s, healthy_out)[0] == 2, "the healthy session must still be mapped"
        assert _mapped(s, poison_out) == (0, None), "the failing one stays queued for the next tick"
