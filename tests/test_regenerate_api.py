"""Coverage for the `/regenerate/scenarios` API — the single surviving regenerate
granularity — plus the check that the old overloaded endpoint is gone.
"""
from __future__ import annotations

from sqlalchemy import func, select

from app.core.enums import AuditEventType, RegenGranularity
from app.db import models as m
from app.db.dal import load_session
from app.pipeline import cascade
from app.pipeline.tasks import ASSET_UNIT_ID
from tests.conftest import StubLLM, make_client
from tests.test_cascade import _leave_review, _output_ids, _reserve_epoch, _run_to_review
from tests.test_slice import SUB


# --- 1/2: scenarios endpoint (single / multi output_ids) ---
def test_scenario_1_single_output_id(db, monkeypatch):
    sid = _run_to_review(db, StubLLM())
    session = dict(load_session(db, sid))
    output_id = _output_ids(db, sid)[0]
    _leave_review(db, sid)
    epoch = _reserve_epoch(db, sid, ASSET_UNIT_ID, RegenGranularity.scenario)
    published: list = []  # override conftest's autouse no-op so the advisory SSE is observable
    monkeypatch.setattr("app.sse.bus.publish", lambda sid_, event: published.append(event))
    outcome = cascade.run_regeneration(db, session, ASSET_UNIT_ID, RegenGranularity.scenario, [output_id], epoch,
                                       StubLLM(), "11111111-1111-4111-8111-111111111111")
    assert outcome == "review"
    assert db.execute(select(m.Threat_Scenario_Output.Superseded)
                      .where(m.Threat_Scenario_Output.OutputID == output_id)).scalar() == 1
    # the regen_result advisory names the replaced id and its fresh (distinct) replacement
    regen_events = [e for e in published if str(e.get("type")) == "regen_result"]
    assert len(regen_events) == 1
    assert regen_events[0]["requested_output_ids"] == [output_id]
    assert regen_events[0]["new_output_ids"] and output_id not in regen_events[0]["new_output_ids"]


def test_scenario_2_multi_output_ids_siblings_untouched(db):
    from tests.test_cascade import _TwoThreatLLM

    sid = _run_to_review(db, _TwoThreatLLM())
    session = dict(load_session(db, sid))
    outputs = _output_ids(db, sid)
    assert len(outputs) == 2
    _leave_review(db, sid)
    epoch = _reserve_epoch(db, sid, ASSET_UNIT_ID, RegenGranularity.scenario)
    cascade.run_regeneration(db, session, ASSET_UNIT_ID, RegenGranularity.scenario, outputs, epoch, _TwoThreatLLM(), "11111111-1111-4111-8111-111111111111")

    for oid in outputs:
        assert db.execute(select(m.Threat_Scenario_Output.Superseded)
                          .where(m.Threat_Scenario_Output.OutputID == oid)).scalar() == 1
    active = db.execute(select(m.Threat_Scenario_Output.__table__).where(
        m.Threat_Scenario_Output.SessionID == sid, m.Threat_Scenario_Output.Superseded == 0)).mappings().all()
    assert len(active) == 2  # both regenerated, none lost


def test_publish_regen_result_after_commit_never_raises_even_when_rollback_fails():
    """The helper's contract is 'must NEVER raise' — including the residual class the SSE-capture
    test below can't reach: the SELECT fails on a broken connection AND the cleanup rollback fails
    too (an unclassified-disconnect SQLSTATE makes ROLLBACK re-raise). Either escaping would land
    in run_regeneration's generic except and misreport a committed success as a failure."""
    class BrokenSession:
        def execute(self, *a, **k):
            raise RuntimeError("select failed on broken connection")

        def rollback(self):
            raise RuntimeError("rollback failed too (unclassified disconnect)")

    cascade._publish_regen_result_after_commit(  # must swallow both failures, not raise
        BrokenSession(), "33333333-3333-4333-8333-333333333333", ASSET_UNIT_ID, ["x"], 2)


def test_regen_result_publish_failure_never_fails_a_committed_regen(db, monkeypatch):
    """Root-cause guard: the advisory regen_result tail (id lookup + publish) runs inside
    run_regeneration's try block — if it could raise, a regen that already COMMITTED would be
    routed through tasks._record_failure and the client told it failed (spurious stage_error
    audit + error SSE). _publish_regen_result_after_commit must swallow, so a committed success
    can never be downgraded."""
    sid = _run_to_review(db, StubLLM())
    session = dict(load_session(db, sid))
    output_id = _output_ids(db, sid)[0]
    _leave_review(db, sid)
    epoch = _reserve_epoch(db, sid, ASSET_UNIT_ID, RegenGranularity.scenario)
    published: list = []

    def exploding_publish(sid_, event):
        if str(event.get("type")) == "regen_result":
            raise RuntimeError("advisory publish blew up")
        published.append(event)

    monkeypatch.setattr("app.sse.bus.publish", exploding_publish)
    outcome = cascade.run_regeneration(db, session, ASSET_UNIT_ID, RegenGranularity.scenario, [output_id], epoch,
                                       StubLLM(), "11111111-1111-4111-8111-111111111111")
    assert outcome == "review"  # committed success stands — never rerouted through _record_failure
    assert not [e for e in published if str(e.get("type")) == "error"]  # no spurious error SSE
    assert db.execute(select(m.Threat_Scenario_Output.Superseded)
                      .where(m.Threat_Scenario_Output.OutputID == output_id)).scalar() == 1  # data intact


def test_regenerate_accepts_non_canonical_output_id_spellings(db):
    """[canonicalization] THE REPORTED BUG: get_threat_id_to_redo compared raw client ids against
    `found.keys()`, which GUID.result_processor had already canonicalized — so an UPPERCASE id
    (exactly what SSMS and .NET Guid.ToString() render) matched its row in SQL yet was reported
    missing, producing `regenerate_conflict: scenario output(s) not found or not active` on a
    perfectly valid request. Every spelling uuid.UUID() accepts must now resolve."""
    from tests.test_cascade import _TwoThreatLLM

    # one session (UX_Session_ActiveAsset allows only one active session per asset), two
    # scenarios -> two independent regens, each addressed by a different non-canonical spelling
    sid = _run_to_review(db, _TwoThreatLLM())
    session = dict(load_session(db, sid))
    first, second = _output_ids(db, sid)

    for output_id, spelling in ((first, str.upper), (second, lambda s: s.replace("-", ""))):
        _leave_review(db, sid)
        epoch = _reserve_epoch(db, sid, ASSET_UNIT_ID, RegenGranularity.scenario)

        outcome = cascade.run_regeneration(db, session, ASSET_UNIT_ID, RegenGranularity.scenario,
                                        [spelling(output_id)], epoch, _TwoThreatLLM(),
                                        "11111111-1111-4111-8111-111111111111")

        assert outcome == "review", spelling(output_id)
        assert db.execute(select(m.Threat_Scenario_Output.Superseded)
                        .where(m.Threat_Scenario_Output.OutputID == output_id)).scalar() == 1


def test_regenerate_malformed_output_id_is_a_conflict_not_a_crash(db):
    """A malformed id must never reach GUID.bind_processor (a StatementError no handler maps →
    500); it is dropped from the WHERE clause and reported through the normal not-found path."""
    sid = _run_to_review(db, StubLLM())
    session = dict(load_session(db, sid))
    _leave_review(db, sid)
    epoch = _reserve_epoch(db, sid, ASSET_UNIT_ID, RegenGranularity.scenario)
    output_id = _output_ids(db, sid)[0]
    # must not raise — the point of the fix. (Outcome is None because this pre-lock conflict
    # leaves the epoch reserved by _reserve_epoch sitting IDLE; via HTTP the same check runs in
    # _do_regenerate BEFORE any state is touched, so a real caller just gets the 409.)
    outcome = cascade.run_regeneration(db, session, ASSET_UNIT_ID, RegenGranularity.scenario,
                                    ["not-a-guid"], epoch, StubLLM(),
                                    "11111111-1111-4111-8111-111111111111")
    assert outcome is None
    # nothing was mutated by the rejected request
    assert db.execute(select(m.Threat_Scenario_Output.Superseded)
                    .where(m.Threat_Scenario_Output.OutputID == output_id)).scalar() == 0


def test_regen_and_its_audit_row_commit_atomically(db, monkeypatch):
    """[atomicity] The regeneration and its `regeneration_completed` audit row now share ONE
    transaction. Previously the audit was a SECOND transaction after the work had already
    committed, so a failure writing it left the scenarios committed while the generic handler
    reported the whole hop as failed — a stage_error audit row and an error SSE for a
    regeneration that had actually succeeded. With one transaction there is no such in-between
    state: a failing audit write rolls the scenarios back too, so the reported failure is TRUE."""
    sid = _run_to_review(db, StubLLM())
    session = dict(load_session(db, sid))
    output_id = _output_ids(db, sid)[0]
    _leave_review(db, sid)
    epoch = _reserve_epoch(db, sid, ASSET_UNIT_ID, RegenGranularity.scenario)

    real_append = cascade.dal.append_audit

    def fail_on_regen_audit(sess_, **kw):
        if str(kw.get("EventType")) == str(AuditEventType.regeneration_completed):
            raise RuntimeError("audit write failed")
        return real_append(sess_, **kw)

    monkeypatch.setattr(cascade.dal, "append_audit", fail_on_regen_audit)
    cascade.run_regeneration(db, session, ASSET_UNIT_ID, RegenGranularity.scenario, [output_id], epoch,
                            StubLLM(), "11111111-1111-4111-8111-111111111111")

    # neither half landed: the original scenario is untouched and no replacement was committed
    assert db.execute(select(m.Threat_Scenario_Output.Superseded)
                    .where(m.Threat_Scenario_Output.OutputID == output_id)).scalar() == 0
    assert db.execute(select(func.count()).select_from(m.Threat_Scenario_Output).where(
        m.Threat_Scenario_Output.SessionID == sid,
        m.Threat_Scenario_Output.GenerationEpoch == epoch)).scalar() == 0
    # and no regeneration_completed row claims work that never survived
    assert db.execute(select(func.count()).select_from(m.Scenario_Audit).where(
        m.Scenario_Audit.SessionID == sid,
        m.Scenario_Audit.EventType == str(AuditEventType.regeneration_completed))).scalar() == 0


def test_regenerate_retries_a_failure_card_individually(db):
    """[fix 11] A full-run threat whose generation failed leaves a Status=error FAILURE CARD with
    a real OutputID. Targeting that id through the NORMAL regenerate path — no special retry
    machinery — generates the missing scenario and supersedes the card, without touching the
    sibling that succeeded. This is the retry loop the card exists for."""
    from tests.test_cascade import _TwoThreatLLM
    from tests.test_tasks import _SecondScenarioUnparseable

    # partial full run: threat 1 succeeds, threat 2's scenario fails → 1 complete + 1 error card
    sid = _run_to_review(db, _SecondScenarioUnparseable(db))
    session = dict(load_session(db, sid))
    card_id = db.execute(select(m.Threat_Scenario_Output.OutputID).where(
        m.Threat_Scenario_Output.SessionID == sid,
        m.Threat_Scenario_Output.Status == "error",
        m.Threat_Scenario_Output.Superseded == 0)).scalar_one()

    _leave_review(db, sid)
    epoch = _reserve_epoch(db, sid, ASSET_UNIT_ID, RegenGranularity.scenario)
    outcome = cascade.run_regeneration(db, session, ASSET_UNIT_ID, RegenGranularity.scenario,
                                    [card_id], epoch, _TwoThreatLLM(),
                                    "11111111-1111-4111-8111-111111111111")

    assert outcome == "review"
    # the card is retired, and BOTH threats now have a real, complete scenario
    assert db.execute(select(m.Threat_Scenario_Output.Superseded).where(
        m.Threat_Scenario_Output.OutputID == card_id)).scalar() == 1
    active = db.execute(select(m.Threat_Scenario_Output.Status).where(
        m.Threat_Scenario_Output.SessionID == sid,
        m.Threat_Scenario_Output.Superseded == 0)).scalars().all()
    assert sorted(str(a) for a in active) == ["complete", "complete"]


# --- old endpoint is gone ---
def test_old_single_regenerate_endpoint_removed():
    client = make_client({"5"})
    r = client.post("/v1/sessions/x/regenerate", json={"granularity": "profile", "subsystem_id": SUB["id"]})
    assert r.status_code == 404  # route no longer exists at all
