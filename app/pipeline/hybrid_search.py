"""Hybrid retrieval: BM25 keyword scoring + vector cosine, fused by reciprocal rank (RRF).

One shared matching engine for every similarity site (controls, threat re-match, threat
retrieval, actor nearest-match). Deliberately a LEAF module — stdlib only, no app imports —
so any pipeline module can use it without an import cycle.

Why hybrid: vectors catch paraphrases ("Data leakage" ~ "Unauthorised disclosure") but dilute
rare exact tokens (product codes like "S7-1500", CVE ids) that BM25's IDF weighting rewards;
neither leg alone covers both. RRF fuses by RANK POSITION, so the two score scales never need
reconciling. An exact normalized-name match short-circuits to the front — byte-identical names
must match with certainty, which cosine cannot promise (two DIFFERENT threats once scored 0.969).

# in-process BM25 + cosine over in-memory candidates. Move to a real search engine
# (Atlas Search / OpenSearch) only when a corpus outgrows memory (~50k rows).
"""
from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Sequence
from typing import Any

# Mirrors tasks._normalize (strip punctuation, collapse whitespace, casefold) — kept local
# instead of imported so this module stays a leaf. If tasks._normalize ever changes, these
# only need to agree where both are applied to the same strings (dedup keys), which they
# currently are not.
_TOKEN_RE = re.compile(r"[^\w\s]")
_WS_RE = re.compile(r"\s+")


def tokenize(text: str | None) -> list[str]:
    """Punctuation stripped, casefolded, whitespace-split. '' and None -> []."""
    if not text:
        return []
    return _WS_RE.sub(" ", _TOKEN_RE.sub(" ", text)).strip().casefold().split()


def normalize_name(text: str | None) -> str:
    """Comparison key for the exact-name short-circuit: the tokenized text re-joined."""
    return " ".join(tokenize(text))


def bm25_scores(query_tokens: Sequence[str], docs_tokens: Sequence[Sequence[str]],
                k1: float = 1.5, b: float = 0.75) -> list[float]:
    """ BM25 of one query against every doc. Empty corpus -> []; all-empty docs -> zeros."""
    n_docs = len(docs_tokens)
    if n_docs == 0:
        return []
    avgdl = sum(len(d) for d in docs_tokens) / n_docs
    if avgdl == 0:
        return [0.0] * n_docs
    df: Counter[str] = Counter()
    for d in docs_tokens:
        df.update(set(d))
    scores: list[float] = []
    for d in docs_tokens:
        tf = Counter(d)
        dl = len(d)
        s = 0.0
        for t in query_tokens:
            f = tf.get(t)
            if not f:
                continue
            idf = math.log(1.0 + (n_docs - df[t] + 0.5) / (df[t] + 0.5))
            s += idf * (f * (k1 + 1.0)) / (f + k1 * (1.0 - b + b * dl / avgdl))
        scores.append(s)
    return scores


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    """Cosine similarity; 0.0 for zero-magnitude OR mismatched-length vectors (a stale cached
    vector from an embedding-model change must rank last, not crash the whole match)."""
    if len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return 0.0 if na == 0 or nb == 0 else dot / (na * nb)


def rrf_fuse(rankings: Sequence[Sequence[int]], k: int = 60) -> dict[int, float]:
    """Reciprocal-rank fusion: id -> sum of 1/(k + rank) over every ranking it appears in.
    Rank-based, so BM25 and cosine scales never need calibrating against each other."""
    fused: dict[int, float] = {}
    for ranking in rankings:
        for rank, doc_id in enumerate(ranking, start=1):
            fused[doc_id] = fused.get(doc_id, 0.0) + 1.0 / (k + rank)
    return fused


def _ranked_indices(scores: Sequence[float]) -> list[int]:
    """Indices best-first; ties break on the lower index so the result is deterministic.
    Indices whose score is 0 are EXCLUDED — a leg that knows nothing about a doc must not
    vote for it (RRF would otherwise reward mere presence in the candidate list)."""
    return [i for i in sorted(range(len(scores)), key=lambda i: (-scores[i], i))
            if scores[i] > 0.0]


def hybrid_match(query_text: str, candidates: Sequence[dict[str, Any]],
                query_vec: Sequence[float] | None = None,
                 *, rrf_k: int = 60, top_n: int | None = None,
                docs_tokens: Sequence[Sequence[str]] | None = None) -> list[tuple[int, float]]:
    """Rank `candidates` against one query. Returns [(candidate_index, fused_score)] best-first.

    Each candidate is a dict with:
    "text"   - the document text BM25 scores against (required)
    "vector" - its embedding, or None (vector leg skips it)
    "name"   - optional exact-match key; a candidate whose normalized name equals the
                normalized query is forced to the FRONT (score 1.0), before any fused result.

    `query_vec` None -> keyword-only. All-zero legs -> []. Deterministic for fixed inputs.
    `docs_tokens`: pre-tokenized candidate texts (aligned with `candidates`) for callers
    running MANY queries over one unchanging corpus — tokenizing per call re-does QxN work
    for nothing. None -> tokenize here, exactly as before."""
    if not candidates:
        return []
    q_tokens = tokenize(query_text)
    kw = bm25_scores(q_tokens, docs_tokens if docs_tokens is not None
                    else [tokenize(c.get("text")) for c in candidates])
    rankings: list[list[int]] = [_ranked_indices(kw)]
    if query_vec is not None:
        vec = [cosine(query_vec, c["vector"]) if c.get("vector") else 0.0 for c in candidates]
        rankings.append(_ranked_indices(vec))
    fused = rrf_fuse(rankings, k=rrf_k)

    q_name = normalize_name(query_text)
    exact = [i for i, c in enumerate(candidates)
            if q_name and normalize_name(c.get("name")) == q_name]
    ordered = sorted(fused, key=lambda i: (-fused[i], i))
    out: list[tuple[int, float]] = [(i, 1.0) for i in exact]
    out += [(i, fused[i]) for i in ordered if i not in set(exact)]
    return out[:top_n] if top_n is not None else out
