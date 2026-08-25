"""Pins core/stride.py: canonical order, the coverage quota, and the assignment that decides
which STRIDE category a multi-category library threat is actually STORED as.

The bug these exist for: Threat_Category ids are seeded ALPHABETICALLY (Denial of Service = 1
... Spoofing = 5, Tampering = 6), the catalogue is 74/75 multi-category, and the pipeline stored
`categories[0]` off a list ordered by that id. DoS won every row it appeared on. Measured on the
real seed: 46 of 75 threats labelled Denial of Service, and Spoofing, Tampering and Repudiation
labelled on ZERO. Several tests below assert those three are non-empty, which is precisely what
was false before.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.stride import STRIDE_ORDER, achieved, allocate, assign, in_stride_order
from app.db import dal
from app.db import models as m
from app.db.invariants import StartupInvariantError, _assert_stride_categories

S, T, R = "Spoofing", "Tampering", "Repudiation"
INFO, D, E = "Information Disclosure", "Denial of Service", "Elevation of Privilege"

#: The order dal.active_category_names USED to return — ORDER BY ThreatCategoryID over the
#: alphabetically-seeded ids. Kept verbatim as the input that must sort back to canonical.
SEED_ID_ORDER = [D, E, INFO, R, S, T]


def test_canonical_order_is_stride_not_alphabetical():
    assert STRIDE_ORDER == (S, T, R, INFO, D, E)
    assert in_stride_order(SEED_ID_ORDER) == [S, T, R, INFO, D, E]


def test_unknown_categories_sort_last_and_keep_their_order():
    # A renamed or custom Threat_Category still has to come out somewhere deterministic.
    assert in_stride_order(["Custom B", D, "Custom A", S]) == [S, D, "Custom B", "Custom A"]


def test_in_stride_order_deduplicates_and_drops_empties():
    assert in_stride_order([T, S, T, "", None, S]) == [S, T]


def test_quota_is_a_prefix_of_stride_for_small_counts():
    # The stated rule: 3 -> S,T,R and 5 -> S,T,R,I,D.
    assert allocate(3) == {S: 1, T: 1, R: 1}
    assert allocate(5) == {S: 1, T: 1, R: 1, INFO: 1, D: 1}


def test_quota_distributes_round_robin_beyond_six():
    assert allocate(10) == {S: 2, T: 2, R: 2, INFO: 2, D: 1, E: 1}
    assert sum(allocate(17).values()) == 17
    # Never lopsided: round-robin means no category leads another by more than one.
    spread = allocate(17)
    assert max(spread.values()) - min(spread.values()) <= 1


def test_quota_edge_counts():
    assert allocate(0) == {}
    assert allocate(-1) == {}
    assert allocate(1) == {S: 1}
    assert allocate(3, categories=[]) == {}


def test_quota_input_order_does_not_matter():
    # The live category list arrives in whatever order the DB gave it; the quota must not.
    assert allocate(3, categories=SEED_ID_ORDER) == {S: 1, T: 1, R: 1}


def test_additive_round_fills_the_thinnest_categories():
    # A next-set round on a session that already has 3 Spoofing and 2 Tampering must top up
    # what is missing, not restart at Spoofing.
    got = allocate(3, existing={S: 3, T: 2})
    assert got == {R: 1, INFO: 1, D: 1}
    assert S not in got and T not in got


def _cand(name, *cats):
    return {"threat_name": name, "categories": list(cats)}


def _cats(c):
    return c["categories"]


def test_assign_reproduces_the_requested_spread():
    # Modelled on the real catalogue: every row multi-category, DoS present on many of them,
    # and — as in the seed — ordered so the highest-ranked rows all carry DoS.
    rows = [_cand(f"dos-{i}", D, E, INFO) for i in range(10)]
    rows += [_cand(f"spoof-{i}", S, INFO) for i in range(4)]
    rows += [_cand(f"tamper-{i}", T, R) for i in range(4)]
    got = achieved(assign(rows, allocate(6), _cats))
    assert got == {S: 1, T: 1, R: 1, INFO: 1, D: 1, E: 1}


def test_high_ranked_denial_of_service_no_longer_crowds_out_the_rest():
    # THE regression. Ten DoS-carrying rows rank above a single Spoofing row; the old
    # score-ordered cap took the first six and labelled every one of them DoS, so the one
    # Spoofing threat in the pool never appeared at all.
    rows = [_cand(f"dos-{i}", D) for i in range(10)] + [_cand("spoofing-one", S)]
    picked = assign(rows, allocate(6), _cats)
    got = achieved(picked)
    assert got[S] == 1, "a high-ranked DoS block must not bury the only Spoofing threat"
    # DoS legitimately takes the other five. Nothing in this pool carries Tampering,
    # Repudiation, Information Disclosure or Elevation of Privilege, so under the SOFT rule
    # those four slots reallocate rather than returning a short set — see assign()'s docstring.
    # coverage_report still records them as unanswered cells; that is the honest outcome for a
    # pool that genuinely has nothing to say about them.
    assert len(picked) == 6
    assert got[D] == 5


def test_dos_takes_one_slot_when_other_categories_are_actually_available():
    # The realistic shape of the seeded library: DoS rows rank highest, but the pool DOES hold
    # threats for the other categories. Here the quota must hold DoS to its single slot —
    # this is the case the production skew was really about.
    rows = [_cand(f"dos-{i}", D, E) for i in range(10)]
    rows += [_cand(f"other-{i}", S, T, R, INFO) for i in range(6)]
    got = achieved(assign(rows, allocate(6), _cats))
    assert got == {S: 1, T: 1, R: 1, INFO: 1, D: 1, E: 1}


def test_categories_that_only_ever_lost_the_positional_tiebreak_now_win_slots():
    # Spoofing (id 5) and Tampering (id 6) held the HIGHEST ids, so on a row that also carried
    # a lower-id category they never appeared at categories[0] — labelled on zero threats.
    rows = [_cand(f"multi-{i}", D, E, INFO, R, S, T) for i in range(6)]
    got = achieved(assign(rows, allocate(6), _cats))
    for c in (S, T, R):
        assert got.get(c) == 1, f"{c} was labelled on nothing before this fix"


def test_assigned_category_is_always_one_the_threat_actually_carries():
    # The whole design rests on this: a slot is filled only by a candidate genuinely mapped to
    # that category, so the label is never a convenient fiction.
    rows = [_cand("a", S, INFO), _cand("b", T), _cand("c", R, D), _cand("d", E)]
    for cand, cat in assign(rows, allocate(4), _cats):
        assert cat in cand["categories"]


def test_a_threat_is_never_selected_twice():
    rows = [_cand("a", S, T, R), _cand("b", INFO, D, E)]
    picked = assign(rows, allocate(2), _cats)
    assert len({id(c) for c, _ in picked}) == len(picked)


def test_unfillable_category_reallocates_instead_of_shrinking_the_result():
    # SOFT quota: nothing here carries Repudiation, but the caller still asked for 3 threats
    # and gets 3. The unanswered cell is coverage.coverage_report's job to report, not this
    # function's to paper over by inventing one.
    rows = [_cand("a", S), _cand("b", T), _cand("c", D)]
    picked = assign(rows, allocate(3), _cats)
    assert len(picked) == 3
    assert R not in achieved(picked)


def test_assign_cannot_exceed_the_quota_total():
    rows = [_cand(f"x-{i}", S, T, R, INFO, D, E) for i in range(50)]
    assert len(assign(rows, allocate(4), _cats)) == 4


def test_assign_returns_what_it_can_when_candidates_run_out():
    assert len(assign([_cand("only", S)], allocate(5), _cats)) == 1
    assert assign([], allocate(5), _cats) == []


def test_uncategorised_candidate_is_never_placed():
    # Same rule as coverage.covered_cells: a threat carrying no category answers nothing and
    # cannot sit on the grid, so it must not be handed a label either.
    picked = assign([_cand("nameless"), _cand("real", S)], allocate(2), _cats)
    assert [c["threat_name"] for c, _ in picked] == ["real"]


def test_ranking_still_decides_who_wins_a_slot():
    # Score ordering is preserved WITHIN a category — the quota changes how many Spoofing
    # slots exist, never which Spoofing threat is the best one.
    rows = [_cand("best-spoof", S), _cand("worse-spoof", S)]
    picked = assign(rows, allocate(1), _cats)
    assert picked[0][0]["threat_name"] == "best-spoof"


def test_empty_quota_selects_nothing_so_callers_must_degrade_explicitly():
    # An unseeded Threat_Category table yields no categories and therefore an empty quota.
    # assign() correctly selects nothing from it — which is exactly why find_threats checks
    # `if target:` and falls back to rank order rather than silently returning zero threats.
    assert allocate(5, categories=[]) == {}
    assert assign([_cand("a", S), _cand("b", T)], {}, _cats) == []


def test_achieved_counts_by_assigned_category():
    assert achieved([(None, S), (None, S), (None, T)]) == {S: 2, T: 1}
    assert achieved([]) == {}


# --- The two DB-side halves of the fix ------------------------------------------------------
# Everything above pins pure functions. These pin the places the alphabetical order actually
# leaked from, and the guard that stops a renamed category degrading in silence.

#: Exactly how scripts/Seed_to_Threat_library.sql numbers them — ALPHABETICALLY. Kept as the
#: real ids, not tidied, because the point of the test is that this numbering no longer leaks.
SEED_IDS = ((1, D), (2, E), (3, INFO), (4, R), (5, S), (6, T))


def _category_engine(rows=SEED_IDS):
    engine = create_engine("sqlite://")
    m.Threat_Category.__table__.create(engine)
    with sessionmaker(engine)() as s:
        for cid, name in rows:
            s.execute(m.Threat_Category.__table__.insert().values(
                ThreatCategoryID=cid, ThreatCategoryName=name, IsActive=True, IsDeleted=False))
        s.commit()
    return engine


def test_active_category_names_returns_stride_order_from_alphabetical_ids():
    # THE single-source fix. The table is seeded exactly as production seeds it — DoS at id 1,
    # Spoofing at 5, Tampering at 6 — and the read must still come back canonical. Before this,
    # ORDER BY ThreatCategoryID put "Denial of Service" first in every list built from it,
    # including the prompt's "category: exactly one of ..." option line.
    with sessionmaker(_category_engine())() as s:
        assert dal.active_category_names(s) == [S, T, R, INFO, D, E]


def test_active_category_names_ignores_inactive_and_deleted_rows():
    engine = create_engine("sqlite://")
    m.Threat_Category.__table__.create(engine)
    with sessionmaker(engine)() as s:
        s.execute(m.Threat_Category.__table__.insert().values(
            ThreatCategoryID=5, ThreatCategoryName=S, IsActive=True, IsDeleted=False))
        s.execute(m.Threat_Category.__table__.insert().values(
            ThreatCategoryID=6, ThreatCategoryName=T, IsActive=False, IsDeleted=False))
        s.execute(m.Threat_Category.__table__.insert().values(
            ThreatCategoryID=4, ThreatCategoryName=R, IsActive=True, IsDeleted=True))
        s.commit()
        assert dal.active_category_names(s) == [S]


def test_boot_guard_passes_on_a_correctly_seeded_table():
    _assert_stride_categories(_category_engine())  # must not raise


def test_boot_guard_allows_an_unseeded_table():
    # dal.active_category_names documents unseeded as a supported state that falls back to the
    # canonical defaults, so a fresh DB that has not run the seed yet must still boot.
    engine = create_engine("sqlite://")
    m.Threat_Category.__table__.create(engine)
    _assert_stride_categories(engine)  # must not raise


@pytest.mark.parametrize("dropped", [S, T, R, INFO, D, E])
def test_boot_guard_refuses_to_start_when_a_category_is_missing(dropped):
    # A renamed or deactivated category used to degrade in silence: it matched no
    # _STRIDE_SCENARIO_SHAPES line, the quota quietly allocated one category fewer, and the
    # coverage grid stopped asking a question it should have asked. Every one of those is a
    # quieter version of the bug this whole change is about, so it now kills the boot.
    rows = [(cid, name) for cid, name in SEED_IDS if name != dropped]
    with pytest.raises(StartupInvariantError) as exc:
        _assert_stride_categories(_category_engine(rows))
    assert dropped in str(exc.value)
