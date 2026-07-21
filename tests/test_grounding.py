"""Unit tests for pure grounding logic — the band cutoffs (`label_match_from_score`/`pick_worse_of_two`, M2) and
the `find_closest_match` rerank length guard (M1). No DB, no network: a tiny stub LLM supplies
deterministic embed/rerank, and `EMBEDDING_STORE=memory` keeps `get_vectors` off Mongo.
End-to-end grounding is covered in `test_slice.py`; this file pins the boundaries.
"""
from __future__ import annotations

import pytest

from app.core.config import Settings
from app.core.enums import GroundingStatus
from app.pipeline import grounding
from app.pipeline.grounding import pick_worse_of_two, label_match_from_score


def test_route_bands_at_boundaries():
    s = Settings()  # defaults: confirm=60.0, grounded=75.0 (0–100 rerank scale)
    assert label_match_from_score(75.0, s) is GroundingStatus.grounded   # >= grounded → grounded
    assert label_match_from_score(74.9, s) is GroundingStatus.confirm    # just under grounded
    assert label_match_from_score(60.0, s) is GroundingStatus.confirm    # >= confirm → confirm
    assert label_match_from_score(59.9, s) is GroundingStatus.flagged    # under confirm → flagged


def test_worst_returns_lower_band():
    # overall confidence can be no higher than the weakest of Type / Threat-name.
    assert pick_worse_of_two(GroundingStatus.confirm, GroundingStatus.grounded) is GroundingStatus.confirm
    assert pick_worse_of_two(GroundingStatus.flagged, GroundingStatus.confirm) is GroundingStatus.flagged
    assert pick_worse_of_two(GroundingStatus.grounded, GroundingStatus.grounded) is GroundingStatus.grounded


def test_cosine_zero_vector_returns_zero_not_error():
    assert grounding.how_similar([0.0, 0.0], [1.0, 2.0]) == 0.0
    assert abs(grounding.how_similar([1.0, 0.0], [1.0, 0.0]) - 1.0) < 1e-9


def test_cosine_raises_on_length_mismatch_instead_of_silently_truncating():
    # [Fix] a length mismatch always means a real embedding-dimension problem (e.g. a stale
    # cached vector from before an EMBEDDING_PROVIDER/EMBEDDING_DIMENSIONS change) — zip()
    # would otherwise silently truncate to the shorter vector and return a numerically
    # plausible but meaningless score, with no error anywhere.
    with pytest.raises(ValueError, match="different lengths"):
        grounding.how_similar([1.0, 0.0, 0.0], [1.0, 0.0])


def test_shortlist_candidates_skips_a_dimension_mismatched_candidate_not_the_whole_call():
    # [Fix] one corrupted cache entry (wrong-length vector) must not take down scoring for
    # every OTHER candidate — it's skipped, logged, and the rest still get ranked normally.
    from app.pipeline.grounding import _shortlist_candidates

    s = Settings()
    qv = [1.0, 0.0]
    rows = [{"ThreatName": "good"}, {"ThreatName": "bad_dim"}, {"ThreatName": "also_good"}]
    name_vecs = {
        "good": [1.0, 0.0],           # matches qv's dimension, perfect match
        "bad_dim": [1.0, 0.0, 0.0],   # wrong dimension — must be skipped, not crash the call
        "also_good": [0.0, 1.0],      # matches qv's dimension, orthogonal (low score)
    }
    shortlist = _shortlist_candidates(qv, rows, name_vecs, "ThreatName", s)
    names = {r["ThreatName"] for r in shortlist}
    assert "bad_dim" not in names
    assert "good" in names  # the well-formed candidates still get scored and returned


class _BadRerankStub:
    """embed() is well-behaved; rerank() returns the WRONG count to trip the M1 guard."""

    def embed(self, texts, *, model=None, kind="query"):
        return [[float(len(t))] for t in texts]

    def rerank(self, query, docs, *, model=None):
        return []  # 0 scores for a non-empty shortlist → RuntimeError, not a silent drop


def test_best_match_rejects_rerank_length_mismatch(monkeypatch):
    monkeypatch.setenv("EMBEDDING_STORE", "memory")  # get_vectors stays off Mongo
    from app.core.config import get_settings

    get_settings.cache_clear()
    try:
        rows = [{"ThreatName": "a"}, {"ThreatName": "b"}]
        with pytest.raises(RuntimeError, match="2 docs"):
            grounding.find_closest_match(_BadRerankStub(), "q", rows, "ThreatName", Settings(), group="g")
    finally:
        get_settings.cache_clear()


def test_normalize_actors_hardens_untrusted_shapes():
    # The model output is untrusted: a bare string is wrapped; null / non-list scalars → [];
    # a list keeps ONLY strings, since a dict/list element would be unhashable at `a in allowed`.
    assert grounding.ensure_actor_list("Hacker") == ["Hacker"]
    assert grounding.ensure_actor_list(None) == []
    assert grounding.ensure_actor_list({"name": "X"}) == []
    assert grounding.ensure_actor_list(["APT29", {"name": "X"}, 123, ["nested"]]) == ["APT29"]


def test_text_coerces_untrusted_field_types():
    # type/name/category may come back null or non-string; coerce to '' so downstream
    # `.strip()` / `prefix + v` never crash.
    assert grounding.ensure_text("threat") == "threat"
    assert grounding.ensure_text(None) == ""
    assert grounding.ensure_text(123) == ""
    assert grounding.ensure_text({"a": 1}) == ""


class _EmbedSpyStub:
    """Fails the test if embed()/rerank() is ever called — proves the `if not rows`
    guard returns before any LLM call, not just before rerank() (see M1 empty-rows note).
    """

    def embed(self, texts, *, model=None, kind="query"):
        raise AssertionError("embed() must not be called when rows is empty")

    def rerank(self, query, docs, *, model=None):
        raise AssertionError("rerank() must not be called when rows is empty")


def test_best_match_empty_rows_returns_none_without_calling_llm():
    # Deleting the `if not rows: return None, 0.0` guard makes this fall through to
    # `llm.embed([query], ...)` before it could ever reach the later `if not shortlist`
    # guard — so this stub trips (AssertionError) iff that specific short-circuit is gone.
    assert grounding.find_closest_match(_EmbedSpyStub(), "q", [], "ThreatName", Settings(), group="g") == (None, 0.0)


def test_best_match_empty_shortlist_returns_none(monkeypatch):
    # grounding_shortlist_k == 0 → shortlist empty; must return (None, 0.0), never IndexError on ranked[0].
    monkeypatch.setenv("EMBEDDING_STORE", "memory")
    from app.core.config import get_settings

    get_settings.cache_clear()
    try:
        s = Settings(grounding_shortlist_k=0)
        rows = [{"ThreatName": "a"}, {"ThreatName": "b"}]
        assert grounding.find_closest_match(_BadRerankStub(), "q", rows, "ThreatName", s, group="g") == (None, 0.0)
    finally:
        get_settings.cache_clear()
