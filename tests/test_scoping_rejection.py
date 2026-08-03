"""Scoped_Threat.RejectionKind — the machine half of a scoping rejection.

`Reason` is prose for the reviewer; `RejectionKind` is the value code branches on. Until
2026-08-03 there was no second column and next-set decided re-servability with
`Reason LIKE 'beyond top-%'` against text written as `f"beyond top-{top_n} cutoff"`. Rewording
that one f-string — a change no type checker, linter or existing test would object to — would
have made the leftover pool return empty forever, silently, in every session.

These tests exist so that can never be true again:

- the DRIFT test asserts the prose is no longer load-bearing, by pointing the two at each other
  (a `top_n_cutoff` row whose Reason is nonsense must still be served; a `tech_gate` row whose
  Reason reads "beyond top-5 cutoff" must still be refused). Under the old predicate BOTH
  assertions invert, which is exactly what makes this a regression test rather than a restatement;
- the COMPLETENESS tests assert every rejection path sets a kind, because a path that forgets one
  writes NULL, and NULL is silently non-re-servable — the same failure wearing a different hat.
"""
from __future__ import annotations

from sqlalchemy import insert

from app.core.enums import RESERVABLE_REJECTIONS, GroundingStatus, ScopingRejection
from app.db import dal
from app.db import models as m
from app.pipeline.scoping import Scored, score_threats
from app.pipeline.tasks import ASSET_UNIT_ID, _select_unique_top_n

_SID = "aaaaaaaa-0000-4000-8000-000000000001"


def _tid(n: int) -> str:
    return f"00000000-0000-4000-8000-0000000000{n:02d}"


# --- completeness: no rejection path may leave the kind unset ------------------------------------
def test_score_threats_sets_a_kind_on_every_unselected_threat():
    """A new rejection path that forgets `rejection` writes NULL, and NULL never comes back from
    the pool. Nothing else fails when that happens, so only this assertion catches it."""
    threats = [{"threat_id": _tid(i), "grounding_status": GroundingStatus.verified}
            for i in range(1, 6)]
    scored = score_threats(threats, score_threshold=None, top_n=2)
    assert [s.selected for s in scored] == [True, True, False, False, False]
    for s in scored:
        assert (s.rejection is None) == s.selected, f"{s.threat_id}: rejection must be set iff rejected"
    assert {s.rejection for s in scored if not s.selected} == {ScopingRejection.top_n_cutoff}


def test_below_threshold_and_top_n_get_DIFFERENT_kinds():
    """Both are "didn't make the cut" in prose and opposite in behaviour: a below-threshold threat
    re-scores below threshold every time, a top-N casualty is re-selected the moment it is scored
    in target mode. Collapsing them re-creates the "no new threats" wedge."""
    threats = [{"threat_id": _tid(i),
                "grounding_status": GroundingStatus.verified if i < 3 else GroundingStatus.unverified}
            for i in range(1, 5)]
    # verified → 70, unverified → 65; a 68 floor rejects the unverified pair, top_n=1 the rest.
    scored = score_threats(threats, score_threshold=68.0, top_n=1)
    assert {s.rejection for s in scored if not s.selected} == {
        ScopingRejection.below_threshold, ScopingRejection.top_n_cutoff}


def test_select_unique_top_n_marks_duplicate_and_cutoff_separately():
    """The other writer. `_select_unique_top_n` MUTATES already-constructed Scored objects, so a
    forgotten assignment here leaves the field at its constructor default rather than raising."""
    scored = [Scored("a", 80.0, 1, True, "grounding=verified"),
            Scored("b", 80.0, 2, True, "grounding=verified"),   # duplicate of a
            Scored("c", 70.0, 3, True, "grounding=verified")]   # beyond top-1
    enriched = {"a": {"catalogue_id": 1}, "b": {"catalogue_id": 1}, "c": {"catalogue_id": 2}}
    _select_unique_top_n(scored, enriched, top_n=1)
    assert [s.rejection for s in scored] == [
        None, ScopingRejection.duplicate, ScopingRejection.top_n_cutoff]


# --- the drift regression: prose must not steer control flow -------------------------------------
def _seed_pool_row(db, n: int, *, reason: str | None, kind: str | None) -> str:
    """One Identified_Threat + its active Selected=0 Scoped_Threat marker, with Reason and
    RejectionKind set INDEPENDENTLY so a test can point them at each other."""
    db.execute(insert(m.Identified_Threat).values(
        ThreatID=_tid(n), SessionID=_SID, SubsystemID=ASSET_UNIT_ID,
        ThreatCategory="Cyber", ThreatType=f"Type {n}", ThreatName=f"Threat {n}",
        ThreatTypeID=n, ThreatCatalogueID=n,
        GroundingStatus=GroundingStatus.verified, Superseded=0))
    db.execute(insert(m.Scoped_Threat).values(
        ScopedThreatID=f"bbbbbbbb-0000-4000-8000-0000000000{n:02d}", SessionID=_SID,
        SubsystemID=ASSET_UNIT_ID, ThreatID=_tid(n), Score=70.0, ScopeRank=n,
        Selected=0, Reason=reason, RejectionKind=kind, Superseded=0))
    db.commit()
    return _tid(n)


def test_reservability_follows_the_kind_and_ignores_the_prose(db):
    """THE regression test. Both rows below have Reason and RejectionKind deliberately disagreeing.
    Under the old `Reason LIKE 'beyond top-%'` predicate the expected results are exactly inverted —
    row 1 skipped, row 2 served — so this fails loudly if anyone reintroduces prose matching."""
    servable = _seed_pool_row(db, 1, reason="totally reworded, no keywords at all",
                            kind=ScopingRejection.top_n_cutoff)
    permanent = _seed_pool_row(db, 2, reason="beyond top-5 cutoff", kind=ScopingRejection.tech_gate)

    picked = dal.next_unserved_unique_threats(db, _SID, ASSET_UNIT_ID, 5)
    assert servable in picked, "a top_n_cutoff row must be re-served whatever its Reason says"
    assert permanent not in picked, "a tech_gate row must stay out even if its Reason reads 'beyond top-'"


def test_a_legacy_null_kind_is_not_reservable(db):
    """Rows written before the column existed read NULL. Refusing them is the SAFE direction — a
    missed leftover is recoverable, re-serving a permanently-gated threat wedges the session on
    "no new threats". This is why scripts/backfill_rejection_kind.sql exists and is not optional
    on a pre-existing database."""
    legacy = _seed_pool_row(db, 3, reason="beyond top-5 cutoff", kind=None)
    assert legacy not in dal.next_unserved_unique_threats(db, _SID, ASSET_UNIT_ID, 5)


def test_only_top_n_cutoff_is_reservable():
    """Pins the constant itself. Adding a kind to RESERVABLE_REJECTIONS is a deliberate act; landing
    there by accident silently re-opens the wedge."""
    assert RESERVABLE_REJECTIONS == (ScopingRejection.top_n_cutoff,)
    assert set(ScopingRejection) - set(RESERVABLE_REJECTIONS) == {
        ScopingRejection.duplicate, ScopingRejection.tech_gate, ScopingRejection.below_threshold}
