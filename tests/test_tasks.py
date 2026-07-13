"""Unit tests for pure helpers in the pipeline orchestrator (`tasks.py`), plus the
transaction discipline `_ask_ai` enforces on every stage that calls it.

Orchestration flow (find_threats/write_scenarios) is covered end-to-end in
`test_slice.py` / `test_cascade.py`; this file pins the small, pure boundaries.
"""
from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app.db import models as m
from app.pipeline import validation
from app.pipeline.llm import Provenance
from app.pipeline.tasks import _safe_text, find_threats, write_scenarios
from tests.conftest import DEFAULT_ASSET_CONTEXT
from tests.test_cascade import _TwoThreatLLM
from tests.test_slice import SUB, _seed_session


def test_safe_text_coerces_untrusted_model_fields():
    # A proposal's fields are untrusted model JSON. A real string passes through; null / non-string
    # collapse to the column default — so a dict can't crash the pyodbc bind and the nullable
    # ThreatName stays NULL rather than becoming "".
    assert _safe_text("Phishing", "") == "Phishing"
    assert _safe_text(None, "") == ""
    assert _safe_text({"name": "x"}, "") == ""
    assert _safe_text(123, "") == ""
    assert _safe_text(None, None) is None
    assert _safe_text(["nested"], None) is None


class _SecondScenarioUnparseable(_TwoThreatLLM):
    """Two grounded threats, a good FIRST scenario, then junk the parser must reject.

    That ordering is the whole point: it is the shape that used to drag the first
    scenario's already-written Prompt_Log row into `_ask_ai`'s rollback."""

    def __init__(self, sess):
        self._sess = sess
        self.scenario_calls = 0
        self.txn_open_at_call: list[bool] = []

    def chat(self, messages, *, model=None):
        # `_ask_ai` commits immediately before it calls us, so nothing may be pending here.
        # An open transaction at this point is a DB lock about to be held across a blocking
        # network call — which a pyodbc driver that can't yield the gevent hub turns into a
        # frozen worker. Recorded rather than asserted so a failure names the call index.
        self.txn_open_at_call.append(self._sess.in_transaction())
        if "stride threats" in messages[0]["content"].lower():
            return super().chat(messages, model=model)
        self.scenario_calls += 1
        if self.scenario_calls == 2:
            return "}} not json {{", Provenance(model="stub")
        return super().chat(messages, model=model)


def _active(sess, table) -> int:
    return sess.execute(select(func.count()).select_from(table).where(table.Superseded == 0)).scalar()


def _prompt_logs(sess, stage: str, *, parsed: bool) -> int:
    return sess.execute(select(func.count()).select_from(m.Prompt_Log).where(
        m.Prompt_Log.Stage == stage, m.Prompt_Log.ParseSucceeded == parsed)).scalar()


def test_scenario_parse_failure_keeps_earlier_prompt_logs_and_never_locks_across_the_llm_call(db):
    """A stage makes N AI calls; the Nth fails. Neither the locks nor the audit trail of the
    N-1 that succeeded may be collateral damage."""
    session = _seed_session(db)
    llm = _SecondScenarioUnparseable(db)
    threats, _ = find_threats(db, session, SUB, DEFAULT_ASSET_CONTEXT, llm, "11111111-1111-4111-8111-111111111111")
    db.commit()

    with pytest.raises(validation.LLMResponseParseError):
        write_scenarios(db, session, SUB, DEFAULT_ASSET_CONTEXT, threats, llm, "11111111-1111-4111-8111-111111111111")

    assert llm.scenario_calls == 2  # the failure landed on the SECOND scenario, not the first

    # 1. No transaction — so no lock — is ever open when a blocking LLM call starts.
    #    Three calls: one for threats, two for scenarios.
    assert llm.txn_open_at_call == [False, False, False]

    # 2. Prompt_Log is the ONLY place raw model output is stored. The first scenario parsed
    #    fine, so its row must outlive the second's rollback; the failure gets its own row.
    assert _prompt_logs(db, "scenario", parsed=True) == 1
    assert _prompt_logs(db, "scenario", parsed=False) == 1

    # 3. The supersede+rebuild is all-or-nothing: it never started, so nothing is half-applied
    #    and `GET /results` (a bare `Superseded = 0` filter) still sees the prior generation.
    assert _active(db, m.Scoped_Threat) == 0
    assert _active(db, m.Threat_Scenario_Output) == 0
    assert _active(db, m.Identified_Threat) == 2
