"""End-to-end proof of when the review queue empties: `progress.overall` awaiting_review -> complete.

Why this file exists. The two halves of that transition were each covered and the JOIN between
them was not:

  * `test_session_lifecycle_predicates.py` pins `get_overall_status`'s truth table, but hands it
    `undecided` as a literal — it never asks where that boolean comes from.
  * `test_scenario_reject.py` / `test_decision_attribution.py` pin that accept and reject stamp
    their columns, but never read a board afterwards.

So nothing asserted the actual claim a reviewer depends on: that DECIDING SCENARIOS is what
empties the queue. A regression that stopped `has_undecided_scenarios` from seeing rejections
(or counted superseded rows, or counted failure cards) would leave every test above green while
every session sat at `awaiting_review` forever.

Each test here therefore asserts the PUBLISHED value — `dal.load_session_board` then
`sessions.build_board`, exactly what `GET /v1/sessions/{id}` runs — rather than re-deriving the
predicate and checking this file's own arithmetic, which would prove nothing.
"""
from __future__ import annotations

import pytest
from sqlalchemy.orm import sessionmaker

from app.api import sessions as sessions_mod
from app.core.enums import ScenarioStatus
from app.db import dal
from app.db import models as m
from app.pipeline import accept as accept_mod
from app.pipeline.accept import reject_scenarios
from app.sse import bus
from tests.test_accept_any_version import _engine, _scenario, _seed_session

#: _seed_session's entity/creator. Decisions are entity-scoped, not owner-restricted.
ENTITY = "86"
ACTOR = "u1"


@pytest.fixture()
def Session():
    return sessionmaker(bind=_engine(), future=True)


def _overall(Session, sid: str) -> str:
    """The published `progress.overall`, through the same two calls the GET route makes."""
    with Session() as s:
        return sessions_mod.build_board(s, dal.load_session_board(s, sid))["progress"]["overall"]


def _accept(Session, sid: str, subset, monkeypatch) -> int:
    monkeypatch.setattr(bus, "publish", lambda *a, **k: None)
    with Session() as s:
        return accept_mod.accept_session(s, sid, ENTITY, ACTOR, subset=subset)


def _reject(Session, sid: str, ids, monkeypatch) -> int:
    monkeypatch.setattr(bus, "publish", lambda *a, **k: None)
    with Session() as s:
        return reject_scenarios(s, sid, ENTITY, ACTOR, ids)


def _five(Session) -> tuple[str, list[str]]:
    """A session at the review barrier with five distinct, active, undecided scenarios."""
    sid = _seed_session(Session)
    ids = [_scenario(Session, sid, identity=f"ident-{n}", number=1, superseded=0, title=f"S{n}")
           for n in range(5)]
    return sid, ids


def _supersede(Session, scenario_id: str) -> None:
    """What a regeneration does to the old row: retire it, leaving its decision intact."""
    with Session() as s:
        s.execute(m.Threat_Scenario.__table__.update()
                  .where(m.Threat_Scenario.ScenarioID == scenario_id).values(Superseded=1))
        s.commit()


# --- claim 1: generated, nobody has decided -----------------------------------------------

def test_five_undecided_scenarios_read_awaiting_review(Session):
    sid, _ = _five(Session)
    assert _overall(Session, sid) == "awaiting_review"


# --- claims 2 + 3: the mixed case (accept some, reject the rest) ---------------------------

def test_accepting_three_of_five_is_not_enough(Session, monkeypatch):
    """A PARTIAL decision must not empty the queue — two scenarios still owe an answer."""
    sid, ids = _five(Session)
    assert _accept(Session, sid, ids[:3], monkeypatch) == 3
    assert _overall(Session, sid) == "awaiting_review"


def test_accept_three_then_reject_two_completes_the_session(Session, monkeypatch):
    """THE headline claim: accept 3 + reject 2 = every scenario decided = complete."""
    sid, ids = _five(Session)
    assert _accept(Session, sid, ids[:3], monkeypatch) == 3
    assert _overall(Session, sid) == "awaiting_review"

    assert _reject(Session, sid, ids[3:], monkeypatch) == 2
    assert _overall(Session, sid) == "complete"


def test_the_order_of_the_two_calls_does_not_matter(Session, monkeypatch):
    """Reject first, then accept — the queue is a count, not a sequence."""
    sid, ids = _five(Session)
    assert _reject(Session, sid, ids[3:], monkeypatch) == 2
    assert _overall(Session, sid) == "awaiting_review"

    assert _accept(Session, sid, ids[:3], monkeypatch) == 3
    assert _overall(Session, sid) == "complete"


# --- claims 4 + 5: either decision ALONE can finish a session ------------------------------

def test_accepting_all_five_completes_without_any_reject(Session, monkeypatch):
    sid, _ = _five(Session)
    assert _accept(Session, sid, None, monkeypatch) == 5   # subset=None is mode="all"
    assert _overall(Session, sid) == "complete"


def test_rejecting_all_five_completes_without_any_accept(Session, monkeypatch):
    """The path that disappears if the reject endpoint is ever removed: a reviewer who wants
    NOTHING has no other way to empty the queue (see accept mode="none" below)."""
    sid, ids = _five(Session)
    assert _reject(Session, sid, ids, monkeypatch) == 5
    assert _overall(Session, sid) == "complete"


# --- claim 6: the trap --------------------------------------------------------------------

def test_accept_mode_none_decides_nothing_and_leaves_the_queue_open(Session, monkeypatch):
    """`mode: "none"` maps to an EMPTY subset (sessions.py::_subset_for), not to None.

    An empty subset matches no rows, so it decides nothing: a successful call returning 0 that
    leaves all five scenarios pending. It is NOT a way to dismiss a session. Were it ever to
    behave like accept-all (subset=None), this call would silently accept five scenarios nobody
    approved — which is why the distinction is asserted rather than assumed.
    """
    sid, ids = _five(Session)
    assert _accept(Session, sid, [], monkeypatch) == 0
    assert _overall(Session, sid) == "awaiting_review"

    with Session() as s:
        decided = s.execute(
            m.Threat_Scenario.__table__.select().where(
                m.Threat_Scenario.SessionID == sid)).mappings().all()
    assert [r["Accepted"] for r in decided] == [0] * 5
    assert [r["RejectedAt"] for r in decided] == [None] * 5
    assert len(ids) == 5


# --- claim 7: a failure card is not a blocker ----------------------------------------------

def test_a_failure_card_never_holds_the_queue_open(Session, monkeypatch):
    """A scenario whose generation failed carries no content, so it can never be decided. It is
    excluded from the waiting count for exactly that reason — otherwise one bad card would park
    a session at awaiting_review permanently, with no legal way out."""
    sid = _seed_session(Session)
    good = [_scenario(Session, sid, identity=f"ok-{n}", number=1, superseded=0, title=f"S{n}")
            for n in range(4)]
    _scenario(Session, sid, identity="broken", number=1, superseded=0,
              status=str(ScenarioStatus.error), title="failed")

    assert _accept(Session, sid, None, monkeypatch) == 4   # 4, not 5 — the card is skipped
    assert _overall(Session, sid) == "complete"
    assert len(good) == 4


# --- claim 8: it can go backwards ----------------------------------------------------------

def test_regenerating_a_decided_scenario_reopens_the_queue(Session, monkeypatch):
    """Regeneration retires the decided row and writes a fresh undecided one, so a session that
    had reached `complete` honestly returns to `awaiting_review`. The retired row keeps its
    acceptance; it is simply no longer something a reviewer owes an answer on."""
    sid = _seed_session(Session)
    a = _scenario(Session, sid, identity="ident-a", number=1, superseded=0, title="A")
    b = _scenario(Session, sid, identity="ident-b", number=1, superseded=0, title="B")

    assert _accept(Session, sid, [a, b], monkeypatch) == 2
    assert _overall(Session, sid) == "complete"

    _supersede(Session, a)
    _scenario(Session, sid, identity="ident-a", number=1, superseded=0, title="A-v2")
    assert _overall(Session, sid) == "awaiting_review"

    with Session() as s:
        retired = s.execute(m.Threat_Scenario.__table__.select().where(
            m.Threat_Scenario.ScenarioID == a)).mappings().one()
    assert retired["Accepted"] == 1 and retired["Superseded"] == 1


# --- the superseded/decided interactions the count must ignore -----------------------------

def test_the_board_never_says_decide_while_the_api_would_refuse_a_decision(Session, monkeypatch):
    """`progress.overall` must not report `awaiting_review` before a decision is actually possible.

    Found by a live run, not by this suite. The SCENARIOS stage reaches AWAITING_DECISION as soon
    as the scenario rows land, but the SESSION only moves to completed/REVIEW once control mapping
    finishes — the longest step in the pipeline. For that whole window the board said
    `awaiting_review` while accept and reject both returned
    `409 accept_conflict / generation_in_progress`, because the decision gate reads the SESSION and
    this rollup read only the stage.

    Observed on a real session: `session_status=active`, `current_stage=THREAT_IDENTIFICATION`,
    `progress.overall=awaiting_review`, six scenarios with no controls mapped, and every accept
    rejected. A UI switching on this field — which its own API documentation instructs — rendered
    a Review button that could not work.

    Every seeded fixture in this suite starts at the barrier, which is exactly why no unit test
    could see it. This one asserts the invariant directly: the board may only invite a decision
    the API would accept.
    """
    from app.core.enums import SessionStatus, StageStatus

    mid_generation = sessions_mod.get_overall_status(
        str(StageStatus.COMPLETE), str(StageStatus.AWAITING_DECISION),
        str(SessionStatus.active), undecided=True)
    assert str(mid_generation) == "in_progress", (
        "the board invited a decision while the session was still generating — the exact state a "
        "live run hit, where every accept came back 409 generation_in_progress")

    at_the_barrier = sessions_mod.get_overall_status(
        str(StageStatus.COMPLETE), str(StageStatus.AWAITING_DECISION),
        str(SessionStatus.completed), undecided=True)
    assert str(at_the_barrier) == "awaiting_review", "a genuinely reviewable session must say so"


def test_a_rejected_scenario_survives_being_regenerated_away(Session, monkeypatch):
    """A DECIDED row stays visible in /results even once a regeneration supersedes it — and that
    now holds for a rejection, not only an acceptance.

    The asymmetry this closes: /results has always re-added the accepted row (a reviewer's yes
    must not vanish), but a declined scenario dropped out of the default view the moment it was
    superseded. Same kind of fact, opposite treatment, so a reviewer could not see what had
    already been turned down and could regenerate straight back into it.
    """
    from contextlib import contextmanager

    from app.api.deps import Principal

    sid = _seed_session(Session)
    keep = _scenario(Session, sid, identity="keep", number=1, superseded=0, title="keep")
    nope = _scenario(Session, sid, identity="nope", number=1, superseded=0, title="declined")

    assert _accept(Session, sid, [keep], monkeypatch) == 1
    assert _reject(Session, sid, [nope], monkeypatch) == 1

    # Regeneration retires the declined row and writes a fresh one into its slot.
    _supersede(Session, nope)
    replacement = _scenario(Session, sid, identity="nope", number=1, superseded=0, title="v2")

    @contextmanager
    def fake_db_session():
        with Session() as s:
            yield s

    with Session() as s:
        board_row = dict(dal.load_session(s, sid))
    monkeypatch.setattr(sessions_mod, "db_session", fake_db_session)
    monkeypatch.setattr(sessions_mod, "get_authorized_session", lambda *a, **k: board_row)
    monkeypatch.setattr(sessions_mod, "build_board", lambda *a, **k: {
        "progress": {"threats": "COMPLETE", "scenarios": "COMPLETE",
                     "overall": "awaiting_review", "error_message": {}}})

    principal = Principal(claims={"sub": ACTOR}, entities={ENTITY}, client_id="c", tenant_id="t")
    results = sessions_mod.get_results(sid, include_replaced=False, principal=principal)
    ids = {sc.scenario_id for sc in results.scenarios}

    assert nope in ids, "the rejected version vanished once it was superseded"
    assert keep in ids, "the accepted version must still be here too"
    assert replacement in ids, "the current version must still be here"

    declined = next(sc for sc in results.scenarios if sc.scenario_id == nope)
    assert declined.rejected_by == ACTOR and declined.rejected_at is not None
    assert declined.accepted is False


def test_a_superseded_undecided_row_does_not_hold_the_queue_open(Session, monkeypatch):
    """Only ACTIVE rows are owed an answer. A replaced version that was never decided is history,
    not a pending review item."""
    sid = _seed_session(Session)
    old = _scenario(Session, sid, identity="ident-a", number=1, superseded=1, title="A-old")
    new = _scenario(Session, sid, identity="ident-a", number=1, superseded=0, title="A-new")

    assert _accept(Session, sid, [new], monkeypatch) == 1
    assert _overall(Session, sid) == "complete"

    with Session() as s:
        stale = s.execute(m.Threat_Scenario.__table__.select().where(
            m.Threat_Scenario.ScenarioID == old)).mappings().one()
    assert stale["Accepted"] == 0 and stale["RejectedAt"] is None
