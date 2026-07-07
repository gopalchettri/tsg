"""Coverage for the `/regenerate/scenarios` API — the single surviving regenerate
granularity — plus the check that the old overloaded endpoint is gone.
"""
from __future__ import annotations

from sqlalchemy import select

from app.core.enums import RegenGranularity
from app.db import models as m
from app.db.dal import load_session
from app.pipeline import cascade
from tests.conftest import StubLLM, make_client
from tests.test_cascade import _leave_review, _output_ids, _reserve_epoch, _run_to_review
from tests.test_slice import SUB


# --- 1/2: scenarios endpoint (single / multi output_ids) ---
def test_scenario_1_single_output_id(db):
    sid = _run_to_review(db, StubLLM())
    session = dict(load_session(db, sid))
    output_id = _output_ids(db, sid)[0]
    _leave_review(db, sid)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.scenario)
    outcome = cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.scenario, [output_id], epoch,
                                       StubLLM(), "t")
    assert outcome == "review"
    assert db.execute(select(m.Threat_Scenario_Output.c.Superseded)
                      .where(m.Threat_Scenario_Output.c.OutputID == output_id)).scalar() == 1


def test_scenario_2_multi_output_ids_siblings_untouched(db):
    from tests.test_cascade import _TwoThreatLLM

    sid = _run_to_review(db, _TwoThreatLLM())
    session = dict(load_session(db, sid))
    outputs = _output_ids(db, sid)
    assert len(outputs) == 2
    _leave_review(db, sid)
    epoch = _reserve_epoch(db, sid, SUB["id"], RegenGranularity.scenario)
    cascade.run_regeneration(db, session, SUB["id"], RegenGranularity.scenario, outputs, epoch, _TwoThreatLLM(), "t")

    for oid in outputs:
        assert db.execute(select(m.Threat_Scenario_Output.c.Superseded)
                          .where(m.Threat_Scenario_Output.c.OutputID == oid)).scalar() == 1
    active = db.execute(select(m.Threat_Scenario_Output).where(
        m.Threat_Scenario_Output.c.SessionID == sid, m.Threat_Scenario_Output.c.Superseded == 0)).mappings().all()
    assert len(active) == 2  # both regenerated, none lost


# --- old endpoint is gone ---
def test_old_single_regenerate_endpoint_removed():
    client = make_client({"5"})
    r = client.post("/v1/sessions/x/regenerate", json={"granularity": "profile", "subsystem_id": SUB["id"]})
    assert r.status_code == 404  # route no longer exists at all
