"""The remediation top-up must not impersonate the scored mapping pass.

Three defects this pins, all found by auditing the top-up against the mapping it stands in for:

R1 — it used to stamp ControlsMappedAt. Both routes back to the REAL, score-filtered mapping
     (control_mapping.eligible_outputs and sessions_awaiting_control_mapping) select on that stamp
     being NULL, so claiming it retired the scenario from scored mapping for good: one transient
     rerank failure became a permanent, authoritative-looking bad mapping. The fix is a gate — the
     top-up only runs for a scenario the scored pass has ALREADY settled — so the stamp is never
     written by this path and the two mapping guards stay untouched.
R2 — it appended MapRank by insertion order, but `MappedControl.map_rank` is a published contract
     ("1 = best match"), so a topped-up control scoring 80 could rank below one scoring 55. The
     first fix for that, `renumber_map_ranks_by_score`, was itself a defect: a SECOND ordering
     implementation, re-deriving rank for the whole scenario from Score ALONE and so discarding the
     IT/OT demotion and the domain tie-break that `select_applicable_controls` had just applied. It
     is deleted; the top-up now runs the one rule over the MERGED set of existing + added controls.
R3 — its audit counted fillers against the RAW control_map_min_score setting, while the mapping pass
     applies the calibrated value whenever that setting is unpinned; the one number a reviewer uses
     to judge filler quality could be measured against a cutoff nothing ever applied.
R4 — its documented fail-open covered only two of its three phases: the whole read, including a full
     Control_Library SELECT, ran outside every try, so a timeout there 500'd the plan route.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.db import models as m
from app.pipeline import control_mapping, grounding

SESSION_ID = "5aa85f64-5717-4562-b3fc-2c963f66afa6"
SCENARIO_ID = "3fa85f64-5717-4562-b3fc-2c963f66afa6"


def _engine():
    engine = create_engine("sqlite://")
    for table in (m.Scenario_Session, m.Threat_Scenario, m.Scoped_Threat, m.Identified_Threat,
                  m.Threat_Scenario_Control_Map, m.Control_Library, m.Risk_Treatment_Plan,
                  m.Scenario_Audit, m.ctm_scan_category):
        table.__table__.create(engine)
    with sessionmaker(bind=engine, future=True)() as s:
        # The two categories the per-scenario ITOT context resolves against.
        for cid, code, name in ((1, "IT", "Information Technology (IT)"),
                                (2, "OT", "Operational Technology (OT)")):
            s.execute(m.ctm_scan_category.__table__.insert().values(id=cid, code=code, name=name))
        s.commit()
    return engine


def _now():
    return datetime(2026, 9, 24, 12, 0, tzinfo=UTC)


def _seed(Session, *, controls_mapped_at, mapped=(), asset_context=None,
          scenario_source="generated"):
    """One accepted scenario, optionally already carrying map rows.

    `scenario_source` is a parameter because NULL is a real stored value (every row written before
    the column existed carries it, and the wire publishes `ScenarioSource or "generated"`), and
    because the provenance guards on both paths into a control map have to agree about it.
    """
    with Session() as s:
        s.execute(m.Scenario_Session.__table__.insert().values(
            SessionID=SESSION_ID, TenantID="t", EntityID="86", UserID="u1", AssetID=7,
            AssetName="Plant", SessionStatus="completed", CurrentStage="APPROVED",
            StageStatus="COMPLETE", Mode="AUTO", CurrentSubsystemIndex=0,
            SubsystemsJSON="[]", AssetContextJSON=json.dumps(asset_context or {}),
            CreatedAt=_now(), UpdatedAt=_now()))
        s.execute(m.Threat_Scenario.__table__.insert().values(
            ScenarioID=SCENARIO_ID, SessionID=SESSION_ID, TenantID="t", EntityID="86", UserID="u1",
            SubsystemID=0, ScopedThreatID="7c9e6679-7425-40de-944b-e07fc1f90ae7",
            Status="complete", Accepted=1, Superseded=0, IdentityHash="a" * 64,
            ScenarioNumber=1, GenerationEpoch=1, CreatedAt=_now(), ControlMapAttempts=0,
            ControlsMappedAt=controls_mapped_at, ScenarioSource=scenario_source,
            ScenarioJSON=json.dumps({"scenario_title": "T", "scenario_statement": "s"})))
        for cid, rank, score in mapped:
            s.execute(m.Threat_Scenario_Control_Map.__table__.insert().values(
                ScenarioID=SCENARIO_ID, ControlLibraryID=cid, SessionID=SESSION_ID,
                MapRank=rank, Score=score, CreatedAt=_now()))
        s.commit()


def _patch_db_session(monkeypatch, Session):
    @contextmanager
    def fake_db_session():
        with Session() as s:
            yield s
            s.commit()
    monkeypatch.setattr(control_mapping, "db_session", fake_db_session)


def _ranks(Session):
    cmap = m.Threat_Scenario_Control_Map
    with Session() as s:
        return [(r.ControlLibraryID, r.MapRank) for r in s.execute(
            select(cmap.ControlLibraryID, cmap.MapRank)
            .where(cmap.ScenarioID == SCENARIO_ID).order_by(cmap.MapRank)).all()]


# --- R1 -------------------------------------------------------------------------------------

def test_a_scenario_awaiting_scored_mapping_is_never_topped_up(monkeypatch):
    """THE regression pin. With ControlsMappedAt NULL the scored pass has not settled this
    scenario, so the top-up must decline and leave it for map_controls / the retry sweep."""
    Session = sessionmaker(bind=_engine(), future=True)
    _seed(Session, controls_mapped_at=None)
    _patch_db_session(monkeypatch, Session)

    def _never_grounds(*_a, **_k):
        raise AssertionError("grounding must not run for a scenario awaiting scored mapping")
    monkeypatch.setattr(control_mapping.grounding, "ground_control_queries", _never_grounds)

    assert control_mapping.top_up_scenario_controls(SESSION_ID, SCENARIO_ID) == 0
    assert _ranks(Session) == []


def test_the_scored_mapping_pass_can_still_claim_that_scenario(monkeypatch):
    """The other half of R1: having declined, the scenario is STILL selectable by the real mapping
    predicate. Drives the predicate itself rather than asserting the column, the same discipline
    test_no_mapping_pass_can_ever_select_a_manual_scenario uses."""
    Session = sessionmaker(bind=_engine(), future=True)
    _seed(Session, controls_mapped_at=None)
    _patch_db_session(monkeypatch, Session)
    control_mapping.top_up_scenario_controls(SESSION_ID, SCENARIO_ID)
    with Session() as s:
        assert [r[0] for r in control_mapping.eligible_outputs(s, SESSION_ID)] == [SCENARIO_ID]


@pytest.mark.parametrize("scenario_source", [None, "", "generated", "library", "manual"])
def test_both_manual_guards_read_provenance_the_same_way(scenario_source):
    """Two ways into a control map, one provenance rule each — and they must never disagree.

    The scored path decides in SQL (`_not_hand_written`, applied by eligible_outputs AND by
    sessions_awaiting_control_mapping); the top-up decides in Python (`_top_up_refused`). One row
    classified `manual` by one and not by the other is how a hand-written scenario would get
    controls added to it by the path that guessed wrong, so this drives BOTH against the same
    stored value, including the values that are not literal strings.

    NULL IS THE ONE THAT MATTERS. It means "generated" everywhere that reads it, so both guards
    must treat it as mappable. `ScenarioSource != 'manual'` alone would not: in SQL that is NULL,
    not TRUE, so every AI scenario with an unset source would silently vanish from both selections
    — the permanent empty control list the retry sweep exists to prevent, reintroduced by a guard
    meant to protect manual rows.
    """
    Session = sessionmaker(bind=_engine(), future=True)
    _seed(Session, controls_mapped_at=None, scenario_source=scenario_source)
    hand_written = scenario_source == "manual"

    with Session() as s:
        selectable = [r[0] for r in control_mapping.eligible_outputs(s, SESSION_ID)]
        # The stamp is what the top-up gate additionally requires (see _top_up_refused), so it is
        # set HERE rather than on the row: this asserts about provenance, not about the stamp.
        refused = control_mapping._top_up_refused(
            s, SESSION_ID, SCENARIO_ID,
            {"Accepted": 1, "ScenarioSource": scenario_source, "ControlsMappedAt": _now()})

    assert bool(selectable) is not hand_written, f"scored path disagrees on {scenario_source!r}"
    assert refused is hand_written, f"top-up path disagrees on {scenario_source!r}"


# --- R2 -------------------------------------------------------------------------------------
# These used to call control_mapping.renumber_map_ranks_by_score directly. That function is GONE:
# it was a SECOND ordering implementation that re-derived MapRank for the whole scenario from Score
# alone, silently discarding the IT/OT demotion and the domain tie-break
# control_relevance.select_applicable_controls had just applied — so on every topped-up scenario the
# demotion the per-scenario ITOT context exists to produce was undone. The tests now DRIVE the
# top-up and assert the composite order it writes, which is the only thing that pins the one rule
# actually reaching the table.

def _library(Session, rows):
    """Live Control_Library rows: (id, ITOT, Domain)."""
    with Session() as s:
        for cid, itot, domain in rows:
            s.execute(m.Control_Library.__table__.insert().values(
                ControlLibraryID=cid, ControlCode=f"C{cid}", ControlName=f"Control {cid}",
                ControlDescription="-", ITOT=itot, Domain=domain, IsActive=True, IsDeleted=False))
        s.commit()


def _drive_top_up(monkeypatch, Session, *, added, min_count, min_score=60.0, labels=None):
    """One real top_up_scenario_controls pass. `added` is (id, ITOT, score) per reranked candidate.

    The pool carries exactly the ids the fake reranker scores, because
    control_relevance.validate_control_mapping refuses a map row for a control that was never in
    this scenario's candidate set.
    """
    from app.core.config import get_settings
    _patch_db_session(monkeypatch, Session)
    pool = [{"ControlLibraryID": cid, "ITOT": itot, "Domain": "Network", "text": f"c{cid}"}
            for cid, itot, _score in added]
    by_id = {row["ControlLibraryID"]: row for row in pool}
    matches = [(by_id[cid], score) for cid, _itot, score in added]
    monkeypatch.setattr(control_mapping.grounding, "get_control_candidates",
                        lambda sess, itot_labels: pool)
    monkeypatch.setattr(control_mapping, "_resolve_control_labels", lambda *_a: labels)
    monkeypatch.setattr(control_mapping.grounding, "ground_control_queries",
                        lambda llm, flat, candidates, s: [
                            grounding.ControlMatches(list(matches), True) for _ in flat])
    monkeypatch.setattr(control_mapping, "_min_score",
                        lambda sess, llm, s: grounding.Threshold(min_score, "test"))
    monkeypatch.setattr(get_settings(), "control_map_min_count", min_count)
    monkeypatch.setattr(get_settings(), "remediation_control_top_up_enabled", True)
    return control_mapping.top_up_scenario_controls(SESSION_ID, SCENARIO_ID)


def test_a_topped_up_control_that_outscores_an_existing_one_outranks_it(monkeypatch):
    """A topped-up control that outscores an existing one must rank ABOVE it — map_rank is a
    published contract ("1 = best match"), and appending by insertion order broke it. Pinned through
    the top-up, not through a rank helper, because the helper is what got it wrong twice."""
    Session = sessionmaker(bind=_engine(), future=True)
    _seed(Session, controls_mapped_at=_now(), mapped=[(11, 1, 55.0)])
    _library(Session, [(11, "IT", "Network"), (22, "IT", "Network")])
    assert _drive_top_up(monkeypatch, Session, added=[(22, "IT", 80.0)], min_count=2) == 1
    assert _ranks(Session) == [(22, 1), (11, 2)]


def test_unscored_existing_rows_are_not_reordered_ahead_of_scored_ones(monkeypatch):
    """Legacy rows carry NULL Score and their order is the person's own choice, so they must never be
    re-ordered ahead of scored rows — nor shuffled among themselves."""
    Session = sessionmaker(bind=_engine(), future=True)
    _seed(Session, controls_mapped_at=_now(), mapped=[(11, 1, None), (22, 2, None)])
    _library(Session, [(11, "IT", "Network"), (22, "IT", "Network"), (33, "IT", "Network")])
    assert _drive_top_up(monkeypatch, Session, added=[(33, "IT", 80.0)], min_count=3) == 1
    assert _ranks(Session) == [(33, 1), (11, 2), (22, 3)]


def test_the_itot_demotion_survives_the_top_up_rather_than_being_renumbered_away(monkeypatch):
    """THE F1 REGRESSION PIN. renumber_map_ranks_by_score re-derived rank from Score ALONE, so an
    ITOT-incompatible control scoring 95 was promoted straight back over a compatible one scoring
    61 — exactly the demotion the per-scenario ITOT context had just applied. ITOT is the PRIMARY
    ordering key; a second pass over Score cannot be allowed to overturn it."""
    Session = sessionmaker(bind=_engine(), future=True)
    # The scenario's own asset category resolves to IT, so an OT control is incompatible.
    _seed(Session, controls_mapped_at=_now(), mapped=[(11, 1, 61.0)],
          asset_context={"asset_type_id": 1})
    _library(Session, [(11, "IT", "Network"), (22, "OT", "Network")])
    added = _drive_top_up(monkeypatch, Session, added=[(22, "OT", 95.0)], min_count=2,
                          labels=["IT", "OT"])
    assert added == 1
    assert _ranks(Session) == [(11, 1), (22, 2)], (
        "the OT control outscores the IT one by 34 points and must STILL rank behind it")


def test_a_scenario_already_at_the_floor_is_left_completely_alone(monkeypatch):
    """No shortfall means no grounding and no rank write at all — the existing order is untouched."""
    Session = sessionmaker(bind=_engine(), future=True)
    _seed(Session, controls_mapped_at=_now(), mapped=[(11, 1, 55.0), (22, 2, 80.0)])
    _library(Session, [(11, "IT", "Network"), (22, "IT", "Network")])

    def _never_grounds(*_a, **_k):
        raise AssertionError("a scenario at the floor must cost no grounding")
    monkeypatch.setattr(control_mapping.grounding, "ground_control_queries", _never_grounds)
    _patch_db_session(monkeypatch, Session)
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "control_map_min_count", 2)
    assert control_mapping.top_up_scenario_controls(SESSION_ID, SCENARIO_ID) == 0
    assert _ranks(Session) == [(11, 1), (22, 2)]


# --- F3: the fail-open must cover the READ, not only the two later phases -------------------------

def test_a_failing_read_fails_open_instead_of_reaching_the_caller(monkeypatch):
    """THE F3 REGRESSION PIN. `_read_top_up_plan` ran outside every try, so a pyodbc timeout in it —
    it issues a full Control_Library SELECT — escaped into the HTTP handler and 500'd
    POST /v1/remediation-plans, while the identical failure one phase later logged and returned 0.
    The documented posture is fail-open: the plan proceeds from the controls already mapped."""
    Session = sessionmaker(bind=_engine(), future=True)
    _seed(Session, controls_mapped_at=_now(), mapped=[(11, 1, 55.0)])
    _library(Session, [(11, "IT", "Network")])
    _patch_db_session(monkeypatch, Session)

    def _timeout(*_a, **_k):
        raise RuntimeError("pyodbc: query timeout expired")
    monkeypatch.setattr(control_mapping.grounding, "get_control_candidates", _timeout)
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "control_map_min_count", 5)
    assert control_mapping.top_up_scenario_controls(SESSION_ID, SCENARIO_ID) == 0
    assert _ranks(Session) == [(11, 1)], "the controls already mapped are left exactly as they were"


def _audit(Session) -> dict:
    with Session() as s:
        return json.loads(s.execute(
            select(m.Scenario_Audit.DetailJSON)
            .where(m.Scenario_Audit.ScenarioID == SCENARIO_ID)).scalar_one())


def test_a_widened_candidate_pool_is_recorded_in_the_audit_row(monkeypatch):
    """F6(e). When the label-filtered pool leaves fewer than `need` candidates the top-up re-fetches
    the WHOLE library — dropping the ITOT discipline the label filter exists to enforce — and
    recorded nothing at all, so a widened pool was indistinguishable from one that never needed to
    be."""
    Session = sessionmaker(bind=_engine(), future=True)
    _seed(Session, controls_mapped_at=_now(), mapped=[(11, 1, 55.0)])
    _library(Session, [(11, "IT", "Network"), (22, "IT", "Network")])
    # need = 3, but the label-filtered pool offers only control 22.
    assert _drive_top_up(monkeypatch, Session, added=[(22, "IT", 80.0)], min_count=4,
                         labels=["IT"]) == 1
    assert _audit(Session)["itot_pool_widened"] is True


def test_an_unwidened_pool_says_so_rather_than_leaving_the_field_out(monkeypatch):
    """The control for the test above: a fail-open flag that only ever appears when it fired cannot
    be told apart from a missing field on an older row."""
    Session = sessionmaker(bind=_engine(), future=True)
    _seed(Session, controls_mapped_at=_now(), mapped=[(11, 1, 55.0)])
    _library(Session, [(11, "IT", "Network"), (22, "IT", "Network")])
    assert _drive_top_up(monkeypatch, Session, added=[(22, "IT", 80.0)], min_count=2,
                         labels=["IT"]) == 1
    assert _audit(Session)["itot_pool_widened"] is False


def test_a_missing_session_row_is_logged_not_collapsed_into_nothing_to_do(monkeypatch):
    """F6(c). `_read_top_up_plan` folded "this scenario's session row is gone" into the same silent
    `return None` as "already at the floor", so an orphaned or concurrently-deleted session was
    indistinguishable from a healthy no-op.

    The window is real: `dal.scenario_row` INNER-joins Scenario_Session, so the session row existed
    when the gate ran and is gone by the time `dal.load_session` reads it — a concurrent delete.
    """
    Session = sessionmaker(bind=_engine(), future=True)
    _seed(Session, controls_mapped_at=_now(), mapped=[(11, 1, 55.0)])
    _library(Session, [(11, "IT", "Network")])
    _patch_db_session(monkeypatch, Session)
    monkeypatch.setattr(control_mapping.dal, "load_session", lambda sess, session_id: None)
    logged: list[dict] = []
    monkeypatch.setattr(control_mapping.log, "warning",
                        lambda event, **kw: logged.append({"event": event, **kw}))
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "control_map_min_count", 5)
    assert control_mapping.top_up_scenario_controls(SESSION_ID, SCENARIO_ID) == 0
    assert [e for e in logged if e["event"] == "controls.top_up_session_missing"], logged


def test_the_authz_boundary_still_raises_and_is_never_swallowed(monkeypatch):
    """The other half of F3: `authorize` runs OUTSIDE the new try on purpose. A 403 degrading into
    "we added no controls" would hand the caller a plan it was not entitled to."""
    Session = sessionmaker(bind=_engine(), future=True)
    _seed(Session, controls_mapped_at=_now())
    _patch_db_session(monkeypatch, Session)

    class _Forbidden(Exception):
        pass

    def _deny(_sess):
        raise _Forbidden("not your entity")

    try:
        control_mapping.top_up_scenario_controls(SESSION_ID, SCENARIO_ID, authorize=_deny)
    except _Forbidden:
        return
    raise AssertionError("the authz failure must propagate, not fail open")
