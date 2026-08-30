"""_shortlist_candidates' pure-Python fallback must skip a dimension-mismatched cached vector
with a warning, not crash the whole shortlist.

Previously this went through grounding.how_similar (raise ValueError -> catch -> skip). That
duplicate cosine implementation was merged into hybrid_search.cosine (which returns 0.0 on
mismatch instead of raising); _shortlist_candidates now does its own explicit length check
before calling it. This pins that the caller-visible behaviour — skip the bad candidate, keep
scoring the rest, log a warning naming it — is unchanged by that refactor.
"""
from __future__ import annotations

import pytest

from app.core.config import get_settings
from app.pipeline import grounding


def test_dimension_mismatched_candidate_is_skipped_not_crashed(monkeypatch):
    warnings: list[tuple[str, dict]] = []
    monkeypatch.setattr(grounding, "_np", None)  # force the pure-Python fallback branch
    monkeypatch.setattr(grounding.log, "warning", lambda event, **kw: warnings.append((event, kw)))

    qv = [1.0, 0.0, 0.0]
    rows = [{"name": "good"}, {"name": "stale"}]
    name_vecs = {"good": [1.0, 0.0, 0.0], "stale": [1.0, 0.0]}  # wrong dimension

    s = get_settings()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(s, "semantic_match_threshold", 0.0, raising=False)
        mp.setattr(s, "grounding_shortlist_k", 10, raising=False)
        result = grounding._shortlist_candidates(qv, rows, name_vecs, "name", s)

    assert [r["name"] for r in result] == ["good"]
    assert warnings == [("grounding.dimension_mismatch_skipped", {"candidate": "stale"})]
