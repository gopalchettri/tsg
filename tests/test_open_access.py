"""Who may reach an assessment — a deliberate product decision, pinned so it is not "fixed" back.

Entity scope is the WHOLE authorization boundary: any authenticated colleague in the entity may
open, stream, export, regenerate and decide any assessment in it. Per-user access control was
built (an owner check in get_authorized_session, an owner check on accept/reject, and per-user
filtering on the three cross-session list queries) and then removed on purpose, because covering
for a teammate on leave is normal work and a second person approving a remediation plan is a
requirement that owner-only access makes impossible.

The control is DETECTIVE, not preventive: dal.decide_scenarios writes one Scenario_Audit row per
decided scenario naming the acting user, so "who accepted this, and when" is always answerable —
see tests/test_scenario_reject.py. A wrong decision is attributable after the fact rather than
blocked beforehand.

What is NOT open: authentication. Every route verifies X-API-Key against a stored hash and checks
entity scope, and app/api/route_audit.py refuses to boot if any route is missing that. A URL alone
gets a 401, not data.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import sessionmaker

from app.api.deps import Principal
from app.api.sessions import get_authorized_session
from app.db import dal
from app.db import models as m
from tests.test_accept_any_version import _engine, _scenario, _seed_session

OWNER, COLLEAGUE, ENTITY = "u1", "sam", "86"


def _principal(user_id: str | None, entity: str = ENTITY) -> Principal:
    return Principal(claims={"sub": user_id} if user_id is not None else {}, entities={entity})


@pytest.fixture
def db():
    return sessionmaker(bind=_engine(), future=True)


def test_a_colleague_in_the_same_entity_may_open_the_assessment(db):
    """The decision itself. If this ever starts failing, per-user access control was reintroduced
    — check that it was asked for, rather than assuming a bug was fixed."""
    sid = _seed_session(db)
    with db() as s:
        assert get_authorized_session(s, sid, _principal(COLLEAGUE))["SessionID"] == sid


def test_entity_scope_is_still_enforced(db):
    """Open WITHIN the entity, closed across entities — the boundary that did not move."""
    sid = _seed_session(db)
    with db() as s, pytest.raises(dal.EntityForbidden):
        get_authorized_session(s, sid, _principal(OWNER, entity="99"))


def test_an_unknown_session_is_404_not_403(db):
    """404-before-403 stays: a caller outside the entity must not be able to tell "does not
    exist" from "not yours" by probing ids."""
    with db() as s, pytest.raises(dal.NotFoundError):
        get_authorized_session(s, str(uuid.uuid4()), _principal(OWNER))


def test_the_cross_session_list_is_entity_wide(db):
    """`user_id=None` means every user in the entity — what the entity-wide list route passes."""
    mine = _seed_session(db)
    _scenario(db, mine, identity="i-mine", number=1, superseded=0, title="mine")
    theirs = str(uuid.uuid4())
    now = datetime.now(UTC).replace(tzinfo=None)
    with db() as s:
        s.execute(m.Scenario_Session.__table__.insert().values(
            SessionID=theirs, TenantID="t", EntityID=ENTITY, UserID=COLLEAGUE, AssetID=8,
            AssetName="Payments", SessionStatus="completed", CurrentStage="REVIEW",
            StageStatus="SCENARIOS_AWAITING_DECISION", Mode="AUTO", CurrentSubsystemIndex=0,
            SubsystemsJSON="[]", CreatedAt=now, UpdatedAt=now))
        s.commit()
    _scenario(db, theirs, identity="i-theirs", number=1, superseded=0, title="theirs")

    with db() as s:
        everyone = dal.scenario_rows(s, entity_ids={ENTITY})
        just_owner = dal.scenario_rows(s, entity_ids={ENTITY}, user_id=OWNER)
    assert len(everyone) == 2          # entity-wide by default
    assert len(just_owner) == 1        # ...and still filterable when a caller wants one person
