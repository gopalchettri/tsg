"""Full behavioural pin for control_mapping.session_category_codes.

This function was RECONSTRUCTED from its docstring and its callers after being destroyed by a bad
edit; the original text does not survive anywhere. It passed the tests that already existed, but
those reach it only indirectly through session_is_ot, so several behaviours were merely *probably*
right rather than specified.

Every behaviour is pinned here directly, so the reconstruction is defined by tests rather than
trusted. Its two consumers are both narrow, and that is what makes the remaining uncertainty
benign — asserted at the bottom rather than assumed:

  * control_mapping.session_is_ot  -> `"OT" in codes`, exact set membership
  * tasks._prefer_kinds            -> checks "OT" then "IT", nothing else
"""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import models as m
from app.pipeline.control_mapping import session_category_codes, session_is_ot


def _sess(rows):
    engine = create_engine("sqlite://")
    m.ctm_scan_category.__table__.create(engine)
    s = sessionmaker(engine)()
    for cid, code, name in rows:
        s.execute(m.ctm_scan_category.__table__.insert().values(id=cid, code=code, name=name))
    s.commit()
    return s


def _codes(rows, asset_id, sub_ids=()):
    return session_category_codes(_sess(rows), [{"asset_type_id": i} for i in sub_ids],
                                {"asset_type_id": asset_id})


_ROWS = [(2, "IT", "Information Technology (IT)"),
        (3, "OT", "Operational Technology (OT)"),
        (7, "PHY_INFRA", "Physical Infrastructure")]


def test_no_categories_yields_an_empty_set_not_none():
    """session_is_ot does `"OT" in codes`, so None here would be a TypeError on every session
    whose asset carries no category id."""
    result = session_category_codes(_sess(_ROWS), [], {})
    assert result == set()


def test_code_is_returned_uppercased_and_stripped():
    assert _codes([(1, "  ot  ", "whatever")], 1) == {"OT"}


def test_parenthetical_is_read_when_the_code_is_missing():
    assert _codes([(1, None, "Operational Technology (OT)")], 1) == {"OT"}


def test_code_and_parenthetical_are_UNIONED_not_tried_in_order():
    """A row coded OT_LEGACY but named "... (OT)" is still OT. This helper replaced a check that
    read the NAME, so it must not be narrower than what it replaced."""
    assert _codes([(1, "OT_LEGACY", "Operational Technology (OT)")], 1) == {"OT_LEGACY", "OT"}


def test_a_substring_is_not_a_match():
    """THE word-boundary property. "OT" appears inside "PROTOTYPE" and "IT" inside "FACILITIES";
    neither may resolve to a category. Membership is exact-set, and the marker must be
    parenthesised."""
    codes = _codes([(1, "PROTOTYPE", "Prototype Facilities Lab")], 1)
    assert codes == {"PROTOTYPE"}
    assert "OT" not in codes and "IT" not in codes


def test_asset_and_every_subsystem_are_unioned():
    """Deliberately loose: one OT subsystem counts even when the asset itself is IT."""
    assert _codes(_ROWS, 2, sub_ids=[3, 7]) == {"IT", "OT", "PHY_INFRA"}


def test_null_code_and_null_name_do_not_crash():
    assert _codes([(1, None, None)], 1) == set()


def test_several_parentheticals_are_all_collected():
    """Documented consequence of reading every marker, NOT an accident: a name carrying two
    parentheticals yields both. Harmless — see the consumer tests below, which are what make it
    safe rather than merely tolerated."""
    assert _codes([(1, None, "Plant (Legacy) Systems (OT)")], 1) == {"LEGACY", "OT"}


# ---------------------------------------------------------------- consumer contracts
def test_session_is_ot_is_unaffected_by_extra_codes():
    """Exact membership, so a spurious 'LEGACY' cannot make a non-OT asset read as OT, and cannot
    stop an OT one being recognised."""
    assert session_is_ot(_sess([(1, None, "Plant (Legacy) Systems (OT)")]),
                        [], {"asset_type_id": 1}) is True
    assert session_is_ot(_sess([(1, "PROTOTYPE", "Prototype Lab")]),
                        [], {"asset_type_id": 1}) is False


@pytest.mark.parametrize("codes,expected_first", [
    ({"OT"}, "ics_advisory"),
    ({"IT"}, "cve"),
    ({"OT", "IT", "LEGACY"}, "ics_advisory"),   # OT anywhere wins, extras ignored
    ({"LEGACY", "PHY_INFRA"}, "pulse"),         # neither IT nor OT -> campaign reports lead
])
def test_prefer_kinds_only_reads_it_and_ot(codes, expected_first):
    """The other consumer. It looks for exactly two codes, which is why an extra one from a
    multi-parenthetical name cannot change intel ordering."""
    from app.pipeline.tasks import _prefer_kinds

    assert _prefer_kinds(codes)[0] == expected_first
