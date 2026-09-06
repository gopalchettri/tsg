"""grounding.resolve_asset_labels — the ONE rule mapping a session's asset categories onto a
consuming vocabulary.

Adopted after a real defect: an asset categorised {Physical, IT} was silently narrowed to
IT-only, so part of its nature stopped being considered and nothing said so. Two consumers now
share this function — the control-pool filter and the ATT&CK/CAPEC technique reference — precisely
so they cannot drift into different answers for the same session.
"""
from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import models as m
from app.pipeline.grounding import resolve_asset_labels

IT, OT, PHY = 2, 3, 7
_ROWS = [(IT, "IT", "Information Technology (IT)"),
        (OT, "OT", "Operational Technology (OT)"),
        (PHY, "PHY_INFRA", "Physical Infrastructure")]


def _sess(rows=_ROWS):
    engine = create_engine("sqlite://")
    m.ctm_scan_category.__table__.create(engine)
    s = sessionmaker(engine)()
    for cid, code, name in rows:
        s.execute(m.ctm_scan_category.__table__.insert().values(id=cid, code=code, name=name))
    s.commit()
    return s


def test_matches_by_code():
    assert resolve_asset_labels(_sess(), {OT}, lambda: {"IT", "OT"}) == ["OT"]


def test_union_for_a_multi_category_session():
    assert resolve_asset_labels(_sess(), {IT, OT}, lambda: {"IT", "OT"}) == ["IT", "OT"]


def test_matches_by_parenthetical_when_the_code_does_not():
    """Parenthesised, never substring: "IT" also appears inside "FACILITIES"."""
    sess = _sess([(99, "LEGACY_CODE", "Operational Technology (OT)")])
    assert resolve_asset_labels(sess, {99}, lambda: {"IT", "OT"}) == ["OT"]


def test_a_substring_match_does_not_count():
    sess = _sess([(98, "FAC", "FACILITIES")])
    assert resolve_asset_labels(sess, {98}, lambda: {"IT", "OT"}) is None, \
        "'IT' inside 'FACILITIES' must not resolve to the IT label"


def test_unrepresentable_category_means_NO_filter_not_a_narrowed_one():
    """THE regression this rule exists to prevent.

    {Physical, IT} against an IT/OT-only vocabulary must return None (filter nothing), never
    ["IT"] — which would silently drop everything Physical from consideration."""
    assert resolve_asset_labels(_sess(), {IT, PHY}, lambda: {"IT", "OT"}) is None


def test_the_vocabulary_is_not_built_when_there_are_no_categories():
    """Laziness is part of the contract, not an optimisation. Both callers previously built the
    vocabulary eagerly -- one querying Control_Library, one reading Mongo -- on sessions with no
    categories at all, which broke every test that never created those stores."""
    calls = []

    def factory():
        calls.append(1)
        return {"IT", "OT"}

    assert resolve_asset_labels(_sess(), set(), factory) is None
    assert calls == [], "no categories means the vocabulary must never be fetched"


def test_empty_inputs_mean_no_filter():
    assert resolve_asset_labels(_sess(), set(), lambda: {"IT", "OT"}) is None
    assert resolve_asset_labels(_sess(), {IT}, lambda: set()) is None


def test_vocabulary_drives_the_answer_so_nothing_is_hardcoded():
    """A richer vocabulary widens the rule with no code change — the property that lets the
    technique corpus and the control library use one implementation with different label sets."""
    assert resolve_asset_labels(_sess(), {IT, PHY}, lambda: {"IT", "OT", "PHY_INFRA"}) == ["IT", "PHY_INFRA"]


def test_both_consumers_get_the_same_answer_for_one_session():
    """Controls and techniques resolve through this same function; given the same vocabulary they
    must agree, which is the whole point of sharing it."""
    sess = _sess()
    controls = resolve_asset_labels(sess, {OT}, lambda: {"IT", "OT"})
    techniques = resolve_asset_labels(sess, {OT}, lambda: {"IT", "OT"})
    assert controls == techniques == ["OT"]
