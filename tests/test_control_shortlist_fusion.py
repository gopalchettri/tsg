"""The control shortlist is RRF-FUSED to control_map_shortlist_k, not unioned to twice it.

WHY THIS EXISTS. ground_control_queries used to append the BM25 top-ck to the cosine top-ck, so
the shortlist could be up to 2*ck. `control_map_shortlist_k` therefore did not mean what it said,
and the reranker — a CPU cross-encoder, the single most expensive thing in the pipeline (604s of
one 724s run) — silently scored roughly 40% more pairs than the configured number implies.

Two properties are pinned, because losing either one brings the cost back:

  * the shortlist never exceeds ck, so the setting is honest and cross-encoder cost is bounded;
  * a control the KEYWORD leg ranks first still survives fusion even when the cosine leg misses
    it entirely — the exact case the BM25 leg was added for. Truncating the old union would have
    satisfied the first property while quietly breaking this one.

No model and no database: a fake LLM supplies deterministic embeddings and records the pairs the
reranker is asked to score.
"""
from __future__ import annotations

from app.core.config import get_settings
from app.pipeline import grounding


class _FakeLLM:
    """Deterministic embeddings plus a rerank_many that records what it was asked to score."""

    def __init__(self, query_vec):
        self._q = query_vec
        self.scored_batches: list[list[str]] = []

    def embed(self, texts, kind="query"):
        return [self._q for _ in texts]

    def rerank_many(self, items):
        for _q, docs in items:                       # items = [(query, [doc_text, ...])]
            self.scored_batches.append(list(docs))
        # Uniform scores: this file is about WHICH docs get scored, not their final order.
        return [[(d, 50.0) for d in docs] for _q, docs in items]


def _rows(n: int) -> list[dict]:
    return [{"ControlLibraryID": i, "ControlCode": f"C{i}", "Domain": "d",
             "ControlName": f"control {i}", "text": f"control {i} generic text"}
            for i in range(n)]


def _vectors_favouring(rows, favoured: set[int]):
    """Vectors where `favoured` rows are cosine-similar to the query and the rest are not."""
    return {r["text"]: ([1.0, 0.0] if r["ControlLibraryID"] in favoured else [0.0, 1.0])
            for r in rows}


def _patch(monkeypatch, vecs, ck):
    """Force the dict path and return a Settings carrying the test's shortlist width.

    ground_control_queries takes `s` explicitly, so the width is passed in rather than patched
    onto the (frozen, pydantic) Settings class. The matrix path is disabled because it needs
    numpy-backed cached vectors this test has no use for; both paths funnel through the same
    _apply_shortlist ordering, which is what fusion consumes.
    """
    monkeypatch.setattr(grounding.embeddings, "get_matrix", lambda *a, **k: None)
    monkeypatch.setattr(grounding.embeddings, "get_vectors", lambda *a, **k: vecs)
    return get_settings().model_copy(update={"control_map_shortlist_k": ck})


def test_shortlist_is_capped_at_shortlist_k_not_double_it(monkeypatch):
    ck = 5
    rows = _rows(40)
    vecs = _vectors_favouring(rows, set(range(20)))   # cosine likes 0..19
    s = _patch(monkeypatch, vecs, ck)
    llm = _FakeLLM([1.0, 0.0])

    grounding.ground_control_queries(llm, [("control 33 generic text", None)], rows, s)

    assert llm.scored_batches, "the reranker must have been asked to score something"
    scored = llm.scored_batches[0]
    assert len(scored) <= ck, (
        f"shortlist was {len(scored)} for control_map_shortlist_k={ck} — the union bug is back; "
        "every extra entry is another CPU cross-encoder pair")


def test_a_keyword_only_match_survives_fusion(monkeypatch):
    """The recall half. Row 33 is invisible to the cosine leg but is the ONLY row carrying the
    query's rare token, so BM25 ranks it first. Fusion must keep it — this is what makes RRF
    safer than simply truncating the old union."""
    ck = 5
    rows = _rows(40)
    rows[33]["text"] = "zzqrare distinctive appliance"   # unique token, no cosine affinity
    vecs = _vectors_favouring(rows, set(range(20)))      # cosine never favours 33
    s = _patch(monkeypatch, vecs, ck)
    llm = _FakeLLM([1.0, 0.0])

    grounding.ground_control_queries(llm, [("zzqrare distinctive appliance", None)], rows, s)

    scored = llm.scored_batches[0]
    assert "zzqrare distinctive appliance" in scored, (
        "the keyword-only match was dropped — RRF must let the BM25 leg carry a control the "
        "cosine leg cannot see, otherwise fusing is just a narrower cosine shortlist")
    assert len(scored) <= ck
