"""`threats.proposals_dropped` must say WHY, not just how many.

Two validators reject an LLM threat proposal for four different causes — not a dict, missing
type/name, oversized, unknown category — and the log line used to merge all four into a bare
`dropped=N`. The code knows exactly which fired and discarded that one line later, so an operator
saw work vanish with nothing to act on: a model emitting malformed JSON read identically to one
inventing a seventh STRIDE category.

The category NAME is the half that matters. _usable_category's own docstring warns that an
invented category "would silently fall outside every quota, coverage and distribution
computation" — a count says a threat was lost, the name says which category the model keeps
reaching for, which is a curation signal and not merely a debugging one.
"""
from __future__ import annotations

from app.pipeline.threat_identification import (
    _REJECTED_CATEGORY_CAP,
    _REJECTED_CATEGORY_CHARS,
    _classify_rejections,
)

CATS = ["Spoofing", "Tampering", "Repudiation",
        "Information Disclosure", "Denial of Service", "Elevation of Privilege"]


def _ok(category="Spoofing", **kw):
    return {"category": category, "type": "Credential Abuse", "name": "Stolen operator login", **kw}


def test_an_invented_category_is_named_not_just_counted():
    """THE case this exists for. 'Supply Chain Compromise' is plausible and is not one of the six;
    the log has to carry the string, or the operator cannot tell it from malformed JSON."""
    usable, reasons, offenders = _classify_rejections(
        [_ok(), _ok(category="Supply Chain Compromise")], CATS)
    assert len(usable) == 1
    assert reasons == {"unknown_category": 1}
    assert offenders == ["Supply Chain Compromise"]


def test_malformed_carries_no_category_value():
    """A proposal with no name is malformed, not miscategorised. Reporting a category for it
    would send the reader after the wrong problem."""
    usable, reasons, offenders = _classify_rejections([_ok(), {"category": "Spoofing"}], CATS)
    assert len(usable) == 1
    assert reasons == {"malformed": 1}
    assert offenders == []


def test_both_causes_at_once_are_reported_separately():
    """The whole point: one number could not distinguish these, two reasons can."""
    usable, reasons, offenders = _classify_rejections(
        [_ok(), {"category": "Spoofing"}, _ok(category="Nonsense Category")], CATS)
    assert len(usable) == 1
    assert reasons == {"malformed": 1, "unknown_category": 1}
    assert offenders == ["Nonsense Category"]


def test_nothing_rejected_reports_nothing():
    """The caller only logs when `reasons` is truthy, so a clean round must stay silent."""
    usable, reasons, offenders = _classify_rejections([_ok(), _ok(category="Tampering")], CATS)
    assert len(usable) == 2
    assert reasons == {} and offenders == []


def test_case_and_padding_are_accepted_the_way_usable_category_accepts_them():
    """_usable_category casefolds and strips, so this classifier must not reject what the
    pipeline goes on to accept — otherwise the log accuses a proposal that was fine."""
    usable, reasons, _ = _classify_rejections([_ok(category="  spoofing  ")], CATS)
    assert len(usable) == 1 and reasons == {}


def test_a_flood_of_junk_categories_cannot_flood_the_log():
    """Model output reaching a log line is bounded on BOTH axes — length per value and number of
    distinct values — or one confused round fills the log with generated text."""
    props = [_ok(category=f"Invented {i} " + "x" * 200) for i in range(20)]
    _usable, reasons, offenders = _classify_rejections(props, CATS)
    assert reasons == {"unknown_category": 20}
    assert len(offenders) == _REJECTED_CATEGORY_CAP
    assert all(len(o) <= _REJECTED_CATEGORY_CHARS for o in offenders)


def test_an_unseeded_category_table_rejects_nothing_on_category():
    """_usable_category skips its check when `cats` is empty (an unseeded table) — the same
    degradation the quota path takes. The classifier must inherit that, not invent a policy."""
    usable, reasons, offenders = _classify_rejections([_ok(category="Anything At All")], [])
    assert len(usable) == 1 and reasons == {} and offenders == []
