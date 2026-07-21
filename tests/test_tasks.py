"""Unit tests for pure helpers in the pipeline orchestrator (`tasks.py`), plus the
transaction discipline `_ask_ai` enforces on every stage that calls it.

Orchestration flow (find_threats/write_scenarios) is covered end-to-end in
`test_slice.py` / `test_cascade.py`; this file pins the small, pure boundaries.
"""
from __future__ import annotations

import uuid

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


def test_find_threats_pins_the_configured_threat_identification_temperature(db):
    """[REVIEW-FIX] find_threats must pass Settings.threat_identification_temperature through
    to the actual chat() call — a config value nobody threads through to the real call is a
    setting that does nothing. Spies on temperature instead of asserting on stored threats
    (that's test_find_threats_repeats_the_same_grounded_threats_for_identical_inputs's job,
    against a real model); this only pins the wiring."""
    from app.core.config import get_settings

    class _SpyLLM(_TwoThreatLLM):
        def __init__(self):
            self.temperatures: list[float | None] = []

        def chat(self, messages, *, model=None, temperature=None):
            self.temperatures.append(temperature)
            return super().chat(messages, model=model)

    session = _seed_session(db)
    llm = _SpyLLM()
    find_threats(db, session, SUB, DEFAULT_ASSET_CONTEXT, llm,
                "11111111-1111-4111-8111-111111111111")
    assert llm.temperatures == [get_settings().threat_identification_temperature] * len(llm.temperatures)
    assert get_settings().threat_identification_temperature == 0.0  # the documented default


class _SecondScenarioUnparseable(_TwoThreatLLM):
    """Two grounded threats, a good FIRST scenario, then junk the parser must reject.

    That ordering is the whole point: it is the shape that used to drag the first
    scenario's already-written Prompt_Log row into `_ask_ai`'s rollback."""

    def __init__(self, sess):
        self._sess = sess
        self.scenario_calls = 0
        self.txn_open_at_call: list[bool] = []

    def chat(self, messages, *, model=None, temperature=None):
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


def test_failure_client_message_distinguishes_a_guardrail_block():
    # [REVIEW-FIX] previously a guardrail block produced the identical opaque "stage
    # processing failed" message as any other random failure — a reviewer/operator couldn't
    # tell a proxy-side content guardrail fired from a network blip or a real bug.
    from litellm.exceptions import RejectedRequestError

    from app.pipeline.tasks import _failure_client_message

    exc = RejectedRequestError(message="blocked", model="glm-5", llm_provider="openai", request_data={})
    assert _failure_client_message(exc) == "content blocked by a configured safety guardrail"


def test_failure_client_message_falls_back_to_generic_message_for_other_errors():
    from app.pipeline.tasks import _failure_client_message

    assert _failure_client_message(RuntimeError("boom")) == "stage processing failed"


def test_write_scenarios_records_moderation_off_by_default(db):
    # default Settings: llm_moderation_enabled=False — moderate() must be a no-op that
    # still records checked=False (not silently absent) inside the same ValidationJSON
    # blob validate_scenario's own report already lands in.
    import json

    session = _seed_session(db)
    llm = _TwoThreatLLM()
    threats, _ = find_threats(db, session, SUB, DEFAULT_ASSET_CONTEXT, llm,
                            "11111111-1111-4111-8111-111111111111")
    db.commit()
    write_scenarios(db, session, SUB, DEFAULT_ASSET_CONTEXT, threats, llm,
                    "11111111-1111-4111-8111-111111111111")
    rows = db.execute(select(m.Threat_Scenario_Output)
                    .where(m.Threat_Scenario_Output.Superseded == 0)).scalars().all()
    assert rows
    for row in rows:
        report = json.loads(row.ValidationJSON)
        assert report["moderation"] == {"checked": False, "flagged": False, "categories": [], "error": None}


def test_pipeline_output_rows_carry_entity_and_user_id(db):
    # Identified_Threat/Threat_Scenario_Output already had an EntityID column (migration 0015)
    # that was never populated by app code — every row ever written had EntityID=NULL. Scoped_Threat
    # had no EntityID/UserID column at all. All 3 now get both, sourced from the session row.
    session = _seed_session(db)  # EntityID="5", UserID="u1" (see _seed_session's defaults)
    sid = session["SessionID"]
    llm = _TwoThreatLLM()
    tid = "22222222-2222-4222-8222-222222222222"
    threats, _ = find_threats(db, session, SUB, DEFAULT_ASSET_CONTEXT, llm, tid)
    db.commit()
    write_scenarios(db, session, SUB, DEFAULT_ASSET_CONTEXT, threats, llm, tid)

    identified = db.execute(select(m.Identified_Threat).where(m.Identified_Threat.SessionID == sid)).scalars().all()
    scoped = db.execute(select(m.Scoped_Threat).where(m.Scoped_Threat.SessionID == sid)).scalars().all()
    outputs = db.execute(select(m.Threat_Scenario_Output).where(m.Threat_Scenario_Output.SessionID == sid)).scalars().all()
    assert identified and scoped and outputs
    for row in (*identified, *scoped, *outputs):
        assert row.EntityID == "5"
        assert row.UserID == "u1"


def test_write_scenarios_resolves_active_context_fields_once_not_per_threat(db, monkeypatch):
    # [REVIEW-FIX] a caller (e.g. cascade.py's regen path) that doesn't pass pre-resolved
    # asset_active_fields/sub_active_fields must not make write_scenarios re-query
    # Context_Field_Config once per selected threat — that's an N+1 that scales with batch size.
    # _TwoThreatLLM produces 2 selected threats; a per-threat query would show up as 2+ calls to
    # the combined fetch instead of the correct 1 (both groups, in one round-trip, once for the
    # whole call).
    from app.db import dal

    calls = 0
    real_by_group = dal.active_context_fields_by_group

    def _counting(sess):
        nonlocal calls
        calls += 1
        return real_by_group(sess)

    session = _seed_session(db)
    llm = _TwoThreatLLM()
    threats, _ = find_threats(db, session, SUB, DEFAULT_ASSET_CONTEXT, llm,
                            "11111111-1111-4111-8111-111111111111")
    db.commit()
    monkeypatch.setattr(dal, "active_context_fields_by_group", _counting)
    write_scenarios(db, session, SUB, DEFAULT_ASSET_CONTEXT, threats, llm,
                    "11111111-1111-4111-8111-111111111111")
    assert calls == 1


def test_write_scenarios_soft_flags_a_moderated_scenario_without_blocking_it(db, monkeypatch):
    # [PLAN] a flagged scenario must still be written (soft-flag-for-review, never a hard
    # reject) — this app's whole purpose is writing about attacks/breaches/sabotage, exactly
    # what moderation categories are tuned to flag.
    import json

    from app.pipeline.llm import ModerationResult

    monkeypatch.setattr("app.pipeline.tasks.moderate",
                        lambda text: ModerationResult(checked=True, flagged=True, categories=["violence"]))
    session = _seed_session(db)
    llm = _TwoThreatLLM()
    threats, _ = find_threats(db, session, SUB, DEFAULT_ASSET_CONTEXT, llm,
                            "11111111-1111-4111-8111-111111111111")
    db.commit()
    write_scenarios(db, session, SUB, DEFAULT_ASSET_CONTEXT, threats, llm,
                    "11111111-1111-4111-8111-111111111111")
    rows = db.execute(select(m.Threat_Scenario_Output)
                    .where(m.Threat_Scenario_Output.Superseded == 0)).scalars().all()
    assert rows  # still written — never rejected over a moderation flag
    for row in rows:
        report = json.loads(row.ValidationJSON)
        assert report["moderation"]["flagged"] is True
        assert report["moderation"]["categories"] == ["violence"]


def _live_llm_determinism_check_enabled() -> bool:
    """Opt-in ONLY (not just reachable): unlike the fake-Redis-vs-real-Redis split elsewhere in
    this suite, a real LLM call costs real money on every run, so — unlike a free local
    service — this must never fire just because a dev's box happens to have a reachable
    litellm proxy. Requires TSG_RUN_LIVE_LLM_TESTS=1 AND a healthy proxy."""
    import os

    if not os.environ.get("TSG_RUN_LIVE_LLM_TESTS"):
        return False
    from app.pipeline.selfcheck import check_litellm_proxy_health
    return check_litellm_proxy_health() is None


@pytest.mark.skipif(not _live_llm_determinism_check_enabled(),
                    reason="live-model determinism check: set TSG_RUN_LIVE_LLM_TESTS=1 with a "
                            "reachable litellm proxy to opt in (makes real, billable LLM calls)")
def test_find_threats_repeats_the_same_grounded_threats_for_identical_inputs(db):
    """Live-model check for the mentor-vetted determinism plan (see the project's own plan
    notes): temperature alone can't guarantee repeatability if the CONFIGURED model has a
    fallback chain (docker/litellm.config.yaml can switch models under latency/timeout) — a
    different model answering is an EXPECTED source of difference, not a bug. So this compares
    the STORED, grounded outcome (ThreatTypeID/ThreatCatalogueID/GroundingStatus), not raw
    wording, and skips (rather than fails) when Provenance.model_version shows a different
    model actually answered each run — that case tells us nothing about repeatability."""
    from app.core.config import get_settings
    from app.pipeline.llm import LiteLLMClient

    llm = LiteLLMClient(get_settings())

    def run_once(tag: str) -> tuple[str | None, list[tuple]]:
        session = _seed_session(db, sid=str(uuid.uuid4()))
        _, prov = find_threats(db, session, SUB, DEFAULT_ASSET_CONTEXT, llm, tag)
        db.commit()
        rows = db.execute(
            select(m.Identified_Threat.ThreatTypeID, m.Identified_Threat.ThreatCatalogueID,
                m.Identified_Threat.GroundingStatus)
            .where(m.Identified_Threat.SessionID == session["SessionID"], m.Identified_Threat.Superseded == 0)
        ).all()
        keys = sorted((r.ThreatTypeID, r.ThreatCatalogueID, str(r.GroundingStatus)) for r in rows)
        return (prov.model_version if prov else None), keys

    model_version_1, keys1 = run_once("det-check-1")
    model_version_2, keys2 = run_once("det-check-2")

    if model_version_1 != model_version_2:
        pytest.skip(f"a fallback fired between runs ({model_version_1!r} vs {model_version_2!r}) — "
                    "not a repeatability failure, a different model answered")
    assert keys1 == keys2, (
        f"same model ({model_version_1}) gave different grounded threats across two runs "
        f"with identical inputs: {keys1} vs {keys2}")


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
