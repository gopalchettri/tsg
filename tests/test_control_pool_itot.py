"""The two halves of the ITOT policy must agree, and the matching rule must have ONE copy.

Both pins are regressions on defects that were LATENT rather than live, which is exactly why they
need pinning: neither raises, neither logs, and the live library happened not to trigger either.

1. THE POOL FILTER AND THE DEMOTION RULE DISAGREED ABOUT AN UNLABELLED CONTROL. A blank ITOT
   matches no label — control_itot_vocabulary drops blanks, so there is nothing for it to equal —
   so `get_control_candidates`' `IN` dropped a control whose ITOT a curator left blank from the
   candidate pool for EVERY session; it could never be mapped to anything. Meanwhile
   control_relevance's ordering rule deliberately NEVER demotes a blank ITOT, because unclassified
   is not inapplicable. One half treated unlabelled as "applies to nothing", the other as "applies
   everywhere". Measured on the live library at the time: 1288 active controls, 731 IT + 557 OT and
   ZERO blank — so nothing was being lost yet, and the first unlabelled control a curator added
   would have vanished silently.

   Blank, not NULL, is what the tests below use, and deliberately: `Control_Library.ITOT` is
   `NVARCHAR(100) NOT NULL` in the deployment DDL and non-Optional on the model, so a NULL cannot be
   inserted to test with. The filter still carries an IS NULL arm as a one-term guard for the day
   that column is relaxed.

2. THE MATCHING RULE BRIEFLY HAD THREE COPIES. grounding restated it, a coverage sibling in
   grounding restated it again with no caller at all, and control_relevance holds the copy control
   mapping actually runs. This repo has already paid for two copies of one rule drifting (see
   control_relevance's module docstring on the two control-query builders that scored the same
   scenario differently), so a third was worth deleting rather than documenting.
"""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import models as m
from app.pipeline import control_relevance, grounding

IT, OT, PHY = 1, 2, 3


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    for tbl in (m.Control_Library, m.ctm_scan_category):
        tbl.__table__.create(engine)
    Session = sessionmaker(bind=engine, future=True)
    with Session() as sess:
        for cid, name, itot in ((1, "MFA", "IT"), (2, "Safety instrumented system", "OT"),
                                (3, "Physical access log review", ""),
                                (4, "Security awareness training", "   ")):
            sess.execute(m.Control_Library.__table__.insert().values(
                ControlLibraryID=cid, ControlName=name, ITOT=itot, ControlCode=f"C-{cid}",
                Domain="Access Control", ControlDescription=name,
                IsActive=True, IsDeleted=False))
        for cat_id, code, label in ((IT, "IT", "Information Technology (IT)"),
                                    (OT, "OT", "Operational Technology (OT)"),
                                    (PHY, "PHY", "Facilities")):
            sess.execute(m.ctm_scan_category.__table__.insert().values(
                id=cat_id, code=code, name=label))
        sess.commit()
    return Session


def _ids(sess, labels) -> set[int]:
    return {row["ControlLibraryID"] for row in grounding.get_control_candidates(sess, labels)}


def test_an_unlabelled_control_survives_a_narrowed_pool(db):
    """THE regression. A blank ITOT means UNCLASSIFIED, so it stays a candidate for every session —
    the same answer the demotion rule downstream already gives it. Revert the filter to a bare `IN`
    and controls 3 and 4 disappear from every session's pool with no error anywhere."""
    with db() as sess:
        assert _ids(sess, ["IT"]) == {1, 3, 4}, "empty and whitespace ITOT must both survive"
        assert _ids(sess, ["OT"]) == {2, 3, 4}


def test_narrowing_still_narrows(db):
    """The fix must not become "no filter at all" — an IT session must still not see the OT control.
    Widening the pool to everything would throw away the applicability signal the filter exists
    for."""
    with db() as sess:
        assert 2 not in _ids(sess, ["IT"])
        assert 1 not in _ids(sess, ["OT"])
        assert _ids(sess, None) == {1, 2, 3, 4}, "no labels means the whole library, unchanged"


def test_the_demotion_rule_agrees_with_the_pool_filter():
    """The other half, asserted from the other side: control_relevance treats a blank ITOT as
    unrepresented-but-not-excluded. If either side ever flips, the two disagree again — and the
    wrong way to reconcile them is to make this side exclude, which would narrow the pool, which is
    the defect the fail-open decision exists to prevent."""
    by_fold = control_relevance._vocabulary_by_fold({"IT", "OT"})
    assert control_relevance._match_category_to_vocabulary(None, None, by_fold) is None
    assert control_relevance._match_category_to_vocabulary("   ", "", by_fold) is None


def test_grounding_delegates_the_matching_rule_instead_of_restating_it(db, monkeypatch):
    """ONE implementation, pinned by replacing it: if resolve_asset_labels still carried its own copy
    of the code/parenthetical rule, swapping control_relevance's out would change nothing here."""
    monkeypatch.setattr(control_relevance, "_match_category_to_vocabulary",
                        lambda code, name, by_fold: "OT")
    with db() as sess:
        assert grounding.resolve_asset_labels(sess, {IT}, lambda: {"IT", "OT"}) == ["OT"], (
            "grounding must CALL control_relevance's rule, not keep a second copy of it")


def test_the_real_rule_still_matches_by_code_then_parenthetical(db):
    """...and with nothing stubbed, the delegated rule gives the answers the old copy gave — so the
    deduplication is a refactor, not a behaviour change. 'Facilities' must not match IT: a substring
    test once labelled it IT, because "IT" appears inside "FACILITIES"."""
    with db() as sess:
        assert grounding.resolve_asset_labels(sess, {IT, OT}, lambda: {"IT", "OT"}) == ["IT", "OT"]
        assert grounding.resolve_asset_labels(sess, {IT, PHY}, lambda: {"IT", "OT"}) is None, (
            "one unrepresentable category fails the WHOLE filter open — a silently narrowed pool is "
            "the defect this rule was adopted to prevent")


def test_the_dead_coverage_sibling_stays_deleted():
    """It was added with a docstring naming control mapping as its consumer and had ZERO callers —
    the partial-knowledge behaviour it was built for got solved in control_relevance instead. Dead
    code that claims a consumer it does not have is worse than no code: it tells the next reader the
    wiring exists."""
    for gone in ("resolve_asset_label_coverage", "AssetLabelCoverage"):
        assert not hasattr(grounding, gone), (
            f"grounding.{gone} is back. The partial-knowledge answer lives in "
            "control_relevance.ItotApplicabilityContext, which control mapping actually calls.")
