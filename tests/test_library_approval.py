"""The curator approval step promote-to-library depends on.

Promotion mints Threat_Type/Threat_Catalogue rows PENDING (IsActive=0) so an AI's invention
cannot become organisational ground truth unreviewed, and every retrieval read filters
IsActive=1. Until 2026-09 nothing in the application could flip that bit: the admin CRUD routes
were deleted in 2026-08 as unused complexity, taking update_library_row's only caller with them.
promote-to-library went on answering 200 with a created_count while every promoted threat became
permanently unreachable — the endpoint's whole purpose, silently not happening for a year.

What this file pins:

1. THE ONE THAT MATTERS — a real promote leaves a threat retrieval cannot see; approving it makes
   retrieval see it. Asserted through the REAL promote_scenario_to_library and the REAL
   threat_retrieval funnel, because "the column flipped" is exactly the kind of assertion that
   let the original defect look healthy.
2. The parent TYPE is approved with the threat. Retrieval walks type-then-name, so approving only
   the threat changes nothing a session can see — a half-approval reporting success would be the
   same defect one level down.
3. A type shared by several ids in one batch is approved once, and reports so honestly.
4. Per-item outcomes: an unknown, soft-deleted, or type-orphaned id is `not_found` while the rest
   of the batch still approves. Idempotent — a second call is `already_approved`, not an error.
5. The queue lists what is waiting, and only what is waiting.
"""
from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import select, update
from sqlalchemy.orm import sessionmaker
from test_accept_any_version import _engine, _now, _seed_session

from app.api.deps import Principal
from app.api.schemas import LibraryApprovalBody
from app.api.threat_intel import approve_library_threats, pending_library
from app.core.enums import LibraryApprovalStatus, ScenarioStatus
from app.db import dal
from app.db import models as m
from app.pipeline import threat_retrieval

SUBSYSTEMS = [{"id": 0, "name": "Billing Gateway", "asset_type": "IT", "asset_type_id": 2,
            "technology_used": ["Oracle"], "vendor_name": "Oracle", "criticality": "High"}]
ASSET_CONTEXT = {"name": "Citizen Portal", "asset_type": "Information Technology (IT)",
                "asset_type_id": 2, "sector": "Government", "sub_sector": "Citizen Services",
                "critical_service": ["Billing"]}


class _ZeroVectorLLM:
    """Retrieval's own test double (test_retrieval_catalogue): ranking is irrelevant here —
    what is under test is whether a row reaches the funnel at all."""

    def embed(self, texts, kind=None):
        return [[0.0] * 8 for _ in texts]


class _Request:
    """FastAPI Request stand-in — the route reads .client.host for the audit log only."""
    client = None


def _principal() -> Principal:
    return Principal(claims={"sub": "curator-1"}, entities={"86"},
                    client_id="curator", tenant_id="t")


def _approve(ids: list[int]):
    return approve_library_threats(LibraryApprovalBody(catalogue_ids=ids), _Request(),
                                _principal())


def _sessionmaker():
    engine = _engine()
    # Retrieval joins these; _engine covers the session/scenario side only.
    for table in (m.Threat_Category, m.Threat_Actor, m.ThreatType_ThreatActor_Map,
                m.Threat_Catalogue_Category_Map):
        table.__table__.create(engine)
    return sessionmaker(bind=engine, future=True)


@pytest.fixture
def db(monkeypatch):
    """One SQLite database, wired into the route's db_session() so the routes run for real."""
    Session = _sessionmaker()
    monkeypatch.setattr("app.api.threat_intel.db_session", Session)
    return Session


def _promote_a_found_threat(Session) -> tuple[str, int, int]:
    """Run the REAL promote over an AI-found threat. Returns (session_id, type_id, catalogue_id).

    Seeded as promotion's actual input: an accepted scenario whose threat carries NO library ids,
    which is the case promotion exists to change."""
    from app.pipeline.promote import promote_scenario_to_library

    sid = _seed_session(Session)
    tid, scoped_id, oid = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    info = {"threat_id": tid, "catalogue_id": None, "threat_type_id": None,
            "threat_type": "Firmware Tampering",
            "threat_name": "Unpatched firmware on the RTU"}
    with Session() as s:
        s.execute(m.Identified_Threat.__table__.insert().values(
            ThreatID=tid, SessionID=sid, SubsystemID=0, ThreatCategory="Tampering",
            ThreatType=info["threat_type"], ThreatName=info["threat_name"],
            ThreatTypeID=None, ThreatCatalogueID=None, ThreatCategoryID=None,
            GroundingStatus="unverified", Superseded=0, CreatedAt=_now()))
        s.execute(m.Scoped_Threat.__table__.insert().values(
            ScopedThreatID=scoped_id, SessionID=sid, TenantID="t", EntityID="86", SubsystemID=0,
            ThreatID=tid, Score=9.5, ScopeRank=1, Selected=1, Superseded=0, CreatedAt=_now()))
        s.execute(m.Threat_Scenario.__table__.insert().values(
            ScenarioID=oid, SessionID=sid, TenantID="t", EntityID="86", UserID="u1",
            SubsystemID=0, ScopedThreatID=scoped_id, Status=str(ScenarioStatus.complete),
            ScenarioJSON=json.dumps({"scenario_title": "Firmware swap",
                                    "scenario_statement": "An insider flashes vendor firmware."}),
            Accepted=1, Superseded=0, IdentityHash=dal.identity_hash(sid, 0, info),
            ScenarioNumber=1, GenerationEpoch=1, CreatedAt=_now()))
        s.commit()

    with Session() as s:
        promote_scenario_to_library(s, dict(dal.load_session(s, sid)), oid, "u1")

    with Session() as s:
        row = s.execute(select(m.Identified_Threat.ThreatTypeID,
                            m.Identified_Threat.ThreatCatalogueID)
                        .where(m.Identified_Threat.ThreatID == tid)).mappings().one()
    assert row["ThreatCatalogueID"] is not None, "the real promote stamped a catalogue id"
    return sid, row["ThreatTypeID"], row["ThreatCatalogueID"]


def _retrieved_ids(Session) -> set[int]:
    with Session() as s:
        return {c["catalogue_id"] for c in threat_retrieval.retrieve_library_threats(
            s, _ZeroVectorLLM(), SUBSYSTEMS, ASSET_CONTEXT)}


# --------------------------------------------------------------------------- the one that matters

def test_a_promoted_threat_is_unreachable_until_approved_and_reachable_after(db):
    """End to end, through the real promote and the real retrieval funnel.

    This is the assertion the original defect would have failed. A test checking only that
    IsActive became 1 would pass against a route that approves the threat and leaves its type
    pending — which is indistinguishable, from a session's point of view, from approving
    nothing at all."""
    _sid, type_id, catalogue_id = _promote_a_found_threat(db)

    assert catalogue_id not in _retrieved_ids(db), (
        "precondition: promotion leaves the threat PENDING, so retrieval must not see it — "
        "if it already does, this test proves nothing about approval")

    result = _approve([catalogue_id])
    assert result.approved_count == 1
    assert result.results[0].status == LibraryApprovalStatus.approved
    assert result.results[0].type_activated is True, (
        "promotion minted the type pending too; approving the threat alone would leave it "
        "unreachable")

    assert catalogue_id in _retrieved_ids(db), (
        "the whole point: after approval a session can finally retrieve the promoted threat "
        "instead of re-inventing it")

    with db() as s:
        assert s.get(m.Threat_Type, type_id).IsActive
        assert s.get(m.Threat_Catalogue, catalogue_id).UpdatedBy == "curator-1", (
            "the approval is attributable — update_library_row's Updated* stamp")


# --------------------------------------------------------------------------- batch behaviour

def _seed_pending(s, *, type_id: int, catalogue_ids: list[int], type_active: bool = False) -> None:
    s.execute(m.Threat_Type.__table__.insert().values(
        ThreatTypeID=type_id, ThreatTypeName=f"Type {type_id}", ThreatCategoryID=None,
        IsActive=type_active, IsDeleted=False, Source="promote-api", CreatedAt=_now()))
    for cid in catalogue_ids:
        s.execute(m.Threat_Catalogue.__table__.insert().values(
            ThreatCatalogueID=cid, ThreatTypeID=type_id, ThreatName=f"Threat {cid}",
            IsActive=False, IsDeleted=False, Source="promote-api", CreatedAt=_now()))
    s.commit()


def test_a_shared_pending_type_is_approved_once_not_once_per_threat(db):
    """Two threats, one pending family. The type is activated by the first and reported as
    already handled by the second — not claimed twice."""
    with db() as s:
        _seed_pending(s, type_id=57, catalogue_ids=[812, 813])

    result = _approve([812, 813])
    assert result.approved_count == 2
    assert [r.type_activated for r in result.results] == [True, False], (
        "the second threat must not claim credit for a type the first already approved")


def test_an_already_active_type_is_left_alone(db):
    """A threat promoted under a type the library already had: nothing to do at the type level,
    and the response says so rather than implying a write that did not happen."""
    with db() as s:
        _seed_pending(s, type_id=58, catalogue_ids=[820], type_active=True)

    result = _approve([820])
    assert result.results[0].status == LibraryApprovalStatus.approved
    assert result.results[0].type_activated is False


def test_one_bad_id_does_not_sink_the_batch(db):
    """A curator approving twenty ids must not lose nineteen good writes to one stale id — and
    must be told which one it was."""
    with db() as s:
        _seed_pending(s, type_id=59, catalogue_ids=[830, 831])
        s.execute(update(m.Threat_Catalogue)
                .where(m.Threat_Catalogue.ThreatCatalogueID == 831)
                .values(IsDeleted=True))
        s.commit()

    result = _approve([830, 831, 9999])
    assert result.approved_count == 1
    assert [r.status for r in result.results] == [
        LibraryApprovalStatus.approved,
        LibraryApprovalStatus.not_found,   # soft-deleted answers like missing, on purpose
        LibraryApprovalStatus.not_found]


def test_a_threat_under_a_deleted_type_is_not_found_not_approved(db):
    """Approving cannot make such a row retrievable — retrieval requires a live parent type — so
    reporting `approved` would be the same false success this route exists to end."""
    with db() as s:
        _seed_pending(s, type_id=60, catalogue_ids=[840])
        s.execute(update(m.Threat_Type)
                .where(m.Threat_Type.ThreatTypeID == 60).values(IsDeleted=True))
        s.commit()

    result = _approve([840])
    assert result.approved_count == 0
    assert result.results[0].status == LibraryApprovalStatus.not_found
    with db() as s:
        assert not s.get(m.Threat_Catalogue, 840).IsActive, "nothing was written"


def test_approving_twice_is_not_an_error(db):
    """Idempotent: a curator double-clicking, or two curators working the same queue, gets a
    truthful `already_approved` rather than a 409 or a second phantom write."""
    with db() as s:
        _seed_pending(s, type_id=61, catalogue_ids=[850])

    assert _approve([850]).approved_count == 1
    second = _approve([850])
    assert second.approved_count == 0
    assert second.results[0].status == LibraryApprovalStatus.already_approved


def test_the_batch_is_capped():
    """No 'approve everything pending' by the back door: 101 ids is a validation error, so one
    call can never sweep an unbounded queue into the library."""
    with pytest.raises(ValueError):
        LibraryApprovalBody(catalogue_ids=list(range(101)))
    with pytest.raises(ValueError):
        LibraryApprovalBody(catalogue_ids=[])


# --------------------------------------------------------------------------- the queue

def test_the_queue_lists_what_is_waiting_and_nothing_else(db):
    """Pending rows only, with the parent type's state — the field that tells a curator whether
    approving this row will actually change anything."""
    with db() as s:
        _seed_pending(s, type_id=62, catalogue_ids=[860])
        _seed_pending(s, type_id=63, catalogue_ids=[861], type_active=True)
        s.execute(m.Threat_Catalogue.__table__.insert().values(
            ThreatCatalogueID=862, ThreatTypeID=63, ThreatName="Already curated",
            IsActive=True, IsDeleted=False, Source="functional_team_excel", CreatedAt=_now()))
        s.commit()

    queue = pending_library(limit=200, _principal=_principal())
    assert queue.pending_count == 2, "the active row must not appear in a pending queue"
    by_id = {r.catalogue_id: r for r in queue.pending}
    assert by_id[860].type_is_pending is True
    assert by_id[861].type_is_pending is False
    assert by_id[860].type_name == "Type 62"
