"""The recurrence guard: a rerank that never answered must NOT be recorded as "nothing matched".

THE BUG THIS PINS. `map_controls` used to stamp `ControlsMappedAt` over every selected output,
including ones whose rerank item had failed. That stamp is permanent -- nothing in the codebase
clears it -- and `ControlsMappedAt IS NULL` is the only thing that keeps an output eligible for a
later mapping run. So one transient 429 permanently produced `ControlsMapped: true` with an empty
control list, which app/api/schemas.py documents in three places as "a genuine library-gap
signal, not an error". A reviewer had no way to tell a curated fact about the control library
from an HTTP timeout, and no later run would ever revisit it.

The fix is not a warning. `grounding.ControlMatches` carries `answered` as a field, so "we
reranked and nothing scored" and "we never got an answer" are different values rather than the
same `[]`, and an unanswered output is simply never stamped -- it stays in the queue.

These tests fail if anyone re-widens the stamp back to every output, which is the only way the
symptom can return.
"""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.enums import ScenarioStatus, StageStatus, SubsystemLevel
from app.db import models as m
from app.pipeline import control_mapping, grounding

NOW = datetime.now(UTC)


def _engine():
    engine = create_engine("sqlite://")
    for tbl in (m.Scenario_Session, m.Subsystem_Stage_State, m.Threat_Scenario_Output,
                m.Threat_Scenario_Control_Map, m.Scenario_Audit):
        tbl.__table__.create(engine)
    return engine


def _seed(s, session_id: str, task_id: str, n_outputs: int = 3) -> list[str]:
    s.execute(m.Scenario_Session.__table__.insert().values(
        SessionID=session_id, TenantID="t", EntityID="e", UserID="u", AssetName="a", AssetID="1",
        SessionStatus="active", CurrentStage="SCENARIOS", StageStatus="RUNNING", Mode="full",
        SubsystemsJSON="[]"))
    s.execute(m.Subsystem_Stage_State.__table__.insert().values(
        StateID=str(uuid.uuid4()), SessionID=session_id, TenantID="t", EntityID="e",
        SubsystemID=0, Level=SubsystemLevel.SCENARIOS, Status=StageStatus.RUNNING,
        GenerationEpoch=1, ActiveTaskID=task_id, LeaseExpiresAt=NOW + timedelta(minutes=10),
        HeartbeatAt=NOW, AttemptCount=1, UpdatedAt=NOW))
    ids = []
    for i in range(n_outputs):
        oid = str(uuid.uuid4())
        ids.append(oid)
        s.execute(m.Threat_Scenario_Output.__table__.insert().values(
            OutputID=oid, SessionID=session_id, TenantID="t", EntityID="e", UserID="u",
            SubsystemID=0, ScopedThreatID=str(uuid.uuid4()), Status=ScenarioStatus.complete,
            ScenarioJSON=json.dumps({"scenario_title": f"title {i}",
                                    "scenario_statement": f"statement {i}"}),
            Accepted=0, Superseded=0, ScenarioNumber=1, GenerationEpoch=1, CreatedAt=NOW))
    s.commit()
    return ids


class _FakeLLM:
    def embed(self, texts, kind):
        return [[0.0] for _ in texts]


def _stub(monkeypatch, results_for):
    """results_for(index) -> ControlMatches, so each test scripts its own per-query outcome."""
    monkeypatch.setattr(grounding, "get_control_candidates",
                        lambda sess, itot: [{"ControlLibraryID": 1, "ControlCode": "C1",
                                            "Domain": "d", "ControlName": "MFA", "text": "MFA"}])
    monkeypatch.setattr(control_mapping, "_min_score",
                        lambda sess, llm, s: grounding.Threshold(0.0, "test"))
    monkeypatch.setattr(grounding, "ground_control_queries",
                        lambda llm, flat, candidates, s: [results_for(i)
                                                        for i in range(len(flat))])


def _run(Session, sid, task_id):
    with Session() as s:
        control_mapping.map_controls(s, {"SessionID": sid, "TenantID": "t", "EntityID": "e"},
                                    {}, [], _FakeLLM(), 0, task_id, 1, durable=True)


def _state(Session):
    with Session() as s:
        outputs = {r.OutputID: r for r in s.execute(
            m.Threat_Scenario_Output.__table__.select()).all()}
        maps = s.execute(m.Threat_Scenario_Control_Map.__table__.select()).all()
        audits = [json.loads(a.DetailJSON) for a in s.execute(
            m.Scenario_Audit.__table__.select()).all() if a.DetailJSON]
    return outputs, maps, audits


_HIT = grounding.ControlMatches([({"ControlLibraryID": 1}, 90.0)], True)
_NO_MATCH = grounding.ControlMatches([], True)      # reranked fine, nothing scored
_NO_ANSWER = grounding.ControlMatches([], False)    # the rerank item failed


def test_unanswered_output_is_not_stamped_and_is_retried(monkeypatch):
    """THE regression guard. Output #1's rerank fails; it must be left unstamped, and a second
    mapping run must pick it up and map it once the provider recovers."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid, task_id = str(uuid.uuid4()), str(uuid.uuid4())
    with Session() as s:
        ids = _seed(s, sid, task_id)

    _stub(monkeypatch, lambda i: _NO_ANSWER if i == 1 else _HIT)
    _run(Session, sid, task_id)

    outputs, maps, audits = _state(Session)
    stamped = {oid for oid, r in outputs.items() if r.ControlsMappedAt is not None}
    assert ids[1] not in stamped, "an output we never got an answer for must stay in the queue"
    assert stamped == {ids[0], ids[2]}
    assert {r.OutputID for r in maps} == {ids[0], ids[2]}
    # ...and the degradation is PERSISTED, not just logged, so a later reader can tell this
    # run apart from a clean one (the tasks._validate_candidates `degraded` discipline).
    assert audits[0]["unanswered"] == 1
    assert audits[0]["mapped"] == 2

    # --- the recurrence half: the provider recovers and the next run finishes the job -------
    _stub(monkeypatch, lambda i: _HIT)
    _run(Session, sid, task_id)

    outputs, maps, _ = _state(Session)
    assert all(r.ControlsMappedAt is not None for r in outputs.values())
    assert {r.OutputID for r in maps} == set(ids), "the retried output finally got its controls"


def test_a_real_empty_result_is_still_stamped(monkeypatch):
    """The other half of the distinction, and the reason this cannot just retry everything: a
    query that DID rerank and matched nothing is a finished answer. Stamping it is correct --
    re-reranking it every run would spend money to re-derive the same negative."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid, task_id = str(uuid.uuid4()), str(uuid.uuid4())
    with Session() as s:
        ids = _seed(s, sid, task_id)

    _stub(monkeypatch, lambda i: _NO_MATCH)
    _run(Session, sid, task_id)

    outputs, maps, audits = _state(Session)
    assert all(outputs[oid].ControlsMappedAt is not None for oid in ids)
    assert maps == []                       # a genuine library gap: mapped, nothing matched
    assert audits[0]["unanswered"] == 0     # and NOT reported as a degradation


def test_total_rerank_failure_still_rolls_back_and_stamps_nothing(monkeypatch):
    """Pins the case that was ALREADY correct, so the fix above cannot regress it: when every
    rerank fails, llm.rerank_many raises, map_controls rolls back, and no output is stamped --
    so the whole session is retried rather than silently recorded as control-free."""
    engine = _engine()
    Session = sessionmaker(bind=engine, future=True)
    sid, task_id = str(uuid.uuid4()), str(uuid.uuid4())
    with Session() as s:
        ids = _seed(s, sid, task_id)

    monkeypatch.setattr(grounding, "get_control_candidates",
                        lambda sess, itot: [{"ControlLibraryID": 1, "text": "MFA"}])
    monkeypatch.setattr(control_mapping, "_min_score",
                        lambda sess, llm, s: grounding.Threshold(0.0, "test"))

    def _boom(*a, **k):
        raise RuntimeError("rerank_many: all 3 rerank calls failed")
    monkeypatch.setattr(grounding, "ground_control_queries", _boom)

    _run(Session, sid, task_id)             # swallowed by design; generation must not fail

    outputs, maps, audits = _state(Session)
    assert all(outputs[oid].ControlsMappedAt is None for oid in ids)
    assert maps == [] and audits == []
