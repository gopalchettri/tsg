"""The session step trail: who did what, when, and TO WHAT.

Every step of every session has been written to Scenario_Audit since the beginning and no endpoint
ever read it back — the two pre-existing audit routes cover treatment plans only, so identification,
scoping, generation, review and accept/reject had no read path at all.

These pin the two properties that make the trail readable rather than merely present:

1. EVERY ROW NAMES ITS SUBJECT. Without it the trail reads as an unexplained hop between people —
   user1, then system, then user2 — because the subject is changing and nothing says so.
2. A PERSON IS NAMED ONLY WHEN A PERSON ACTED. `audit_row` used to back-fill ActorUserID with the
   session owner, so pipeline steps carried user1's name and the timeline was actively misleading.

Both are written so the ORIGINAL behaviour fails them.
"""
from __future__ import annotations

import uuid
from contextlib import contextmanager
from datetime import datetime

from sqlalchemy.orm import sessionmaker

import app.api.sessions as sessions_api
from app.api.deps import Principal
from app.db import dal
from app.db import models as m
from tests.test_accept_any_version import _engine, _seed_session

CREATOR = "u1"
REVIEWER = "u2"


def _principal() -> Principal:
    return Principal(claims={"sub": CREATOR}, entities={"86"}, client_id="c", tenant_id="t")


def _wire(Session, monkeypatch) -> None:
    @contextmanager
    def fake_db_session():
        with Session() as s:
            yield s
            s.commit()

    monkeypatch.setattr(sessions_api, "db_session", fake_db_session)
    monkeypatch.setattr(sessions_api, "get_authorized_session",
                        lambda sess, sid, principal: {"SessionID": sid, "EntityID": "86"})


def _event(Session, sid: str, event: str, *, actor=None, scenario_id=None, detail=None, at=None):
    """Write one audit row through the REAL dal helper, so the actor/type defaulting under test is
    the same code the pipeline uses.

    `at` overrides CreatedAt. It matters: rows written in one test run share a timestamp to the
    microsecond, and an ordering assertion over identical values passes whether the query says ASC
    or DESC. Mutation-testing caught exactly that — the ordering test was vacuous until the
    timestamps were made distinct."""
    with Session() as s:
        row = dal.audit_row(s, AuditID=dal.guid(), SessionID=sid, TenantID="t", EntityID="86",
                            EventType=event, ActorUserID=actor, ScenarioID=scenario_id,
                            DetailJSON=detail)
        if at is not None:
            row["CreatedAt"] = at
        s.execute(m.Scenario_Audit.__table__.insert().values(**row))
        s.commit()


def _trail(sid: str, **kw):
    """Every Query param is passed explicitly. Calling a route function directly leaves unpassed
    ones as FastAPI's `Query` sentinel rather than their default — the same trap deps.py documents
    for Header params ("on a real request these are str; when a dependency is called directly
    (tests) an unpassed Header param is FastAPI's sentinel")."""
    args = {"scenario_id": None, "event": None, "actor": None, "since": None, "until": None,
            "limit": 100, "offset": 0}
    args.update(kw)
    return sessions_api.get_session_audit(sid, principal=_principal(), **args)


def test_every_row_names_its_subject(monkeypatch):
    """The user's own complaint: 'it started with user 1 and then system then user 2 then system
    its confusing.' The actors alternate because the SUBJECT alternates — session, then scenario,
    then plan. Each row now says which, so the sequence explains itself."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _wire(Session, monkeypatch)
    scenario, plan = str(uuid.uuid4()), str(uuid.uuid4())

    _event(Session, sid, "session_started", actor=CREATOR)
    _event(Session, sid, "grounding_summary")                       # pipeline, no actor
    _event(Session, sid, "scenario_accepted", actor=REVIEWER, scenario_id=scenario)
    _event(Session, sid, "treatment_plan_reviewed", actor=REVIEWER, scenario_id=scenario,
           detail=f'{{"plan_id": "{plan}"}}')

    subjects = [(e.event, e.subject_type) for e in _trail(sid).events]

    assert ("session_started", "session") in subjects
    assert ("grounding_summary", "session") in subjects
    assert ("scenario_accepted", "scenario") in subjects, "a per-scenario step did not name it"
    assert ("treatment_plan_reviewed", "plan") in subjects, "a plan step did not name the plan"

    plan_row = next(e for e in _trail(sid).events if e.event == "treatment_plan_reviewed")
    assert plan_row.plan_id == plan
    assert plan_row.scenario_id == scenario, (
        "a plan step must still name its scenario — this is why the worker writes must stamp "
        "ScenarioID; without it the row cannot say which plan the reader is looking at")


def test_a_person_is_named_only_when_a_person_acted(monkeypatch):
    """The trail used to stamp the session OWNER onto pipeline rows, so every step looked like
    user1 had done it personally. NULL is the honest answer and actor_type says so outright."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _wire(Session, monkeypatch)

    _event(Session, sid, "session_started", actor=CREATOR)
    _event(Session, sid, "grounding_summary")   # the worker: nobody chose this

    by_event = {e.event: e for e in _trail(sid).events}

    assert by_event["session_started"].actor_user_id == CREATOR
    assert by_event["session_started"].actor_type == "user"
    assert by_event["grounding_summary"].actor_user_id is None, (
        "a pipeline step was attributed to a person — the session-owner back-fill is back")
    assert by_event["grounding_summary"].actor_type == "system"


def test_the_trail_is_ordered_and_paged(monkeypatch):
    """Oldest-first, because this is read as a timeline. Paging is mandatory: the trail grows with
    scenarios x subsystems x regenerations, and the older treatment-audit read is unbounded."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _wire(Session, monkeypatch)
    # DISTINCT timestamps, one minute apart. Identical ones make the ordering assertion vacuous.
    for i in range(5):
        _event(Session, sid, "subsystem_advanced", actor=f"u{i}",
               at=datetime(2026, 8, 30, 9, i, 0))

    first, second = _trail(sid, limit=2, offset=0), _trail(sid, limit=2, offset=2)

    assert len(first.events) == 2 and len(second.events) == 2
    assert first.limit == 2 and second.offset == 2
    # The OLDEST two, in order — pins direction, not merely sortedness.
    assert [e.at for e in first.events] == [datetime(2026, 8, 30, 9, 0, 0),
                                            datetime(2026, 8, 30, 9, 1, 0)], (
        "the timeline is not oldest-first")
    assert second.events[0].at == datetime(2026, 8, 30, 9, 2, 0), "paging skipped the wrong rows"
    assert not ({e.audit_id for e in first.events} & {e.audit_id for e in second.events}), (
        "pages overlap — the AuditID tie-break is not making paging stable")


def test_filtering_by_scenario_narrows_the_trail(monkeypatch):
    """The per-scenario view: 'what happened to THIS scenario'. Filtered in SQL on the indexed
    column, not by parsing DetailJSON in Python."""
    Session = sessionmaker(bind=_engine(), future=True)
    sid = _seed_session(Session)
    _wire(Session, monkeypatch)
    a, b = str(uuid.uuid4()), str(uuid.uuid4())

    _event(Session, sid, "session_started", actor=CREATOR)
    _event(Session, sid, "scenario_accepted", actor=REVIEWER, scenario_id=a)
    _event(Session, sid, "scenario_rejected", actor=REVIEWER, scenario_id=b)

    only_a = _trail(sid, scenario_id=a)
    assert [e.event for e in only_a.events] == ["scenario_accepted"]
    assert all(e.scenario_id == a for e in only_a.events)
