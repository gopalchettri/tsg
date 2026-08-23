"""Pins pipeline/hybrid_search.py: the shared BM25 + vector + RRF matching engine.

Small on purpose — the properties that matter are rare-token wins, paraphrase wins,
the exact-name short-circuit, zero-leg exclusion, and determinism."""
from app.pipeline.hybrid_search import (
    bm25_scores,
    cosine,
    hybrid_match,
    normalize_name,
    rrf_fuse,
    tokenize,
)


def test_tokenize_strips_punctuation_and_casefolds():
    assert tokenize("Siemens S7-1500, (SCADA)!") == ["siemens", "s7", "1500", "scada"]
    assert tokenize(None) == []
    assert tokenize("   ") == []


def test_bm25_rewards_rare_exact_token():
    # "s7" appears in one doc only — that doc must outrank docs sharing common words.
    docs = [tokenize(d) for d in (
        "tampering with control logic on the plant",
        "exploitation of S7 controller firmware",
        "tampering with records on the plant portal",
    )]
    scores = bm25_scores(tokenize("Siemens S7-1500 controller"), docs)
    assert scores[1] == max(scores) and scores[1] > 0


def test_bm25_empty_corpus_and_empty_docs():
    assert bm25_scores(["x"], []) == []
    assert bm25_scores(["x"], [[], []]) == [0.0, 0.0]


def test_cosine_mismatched_lengths_is_zero_not_crash():
    assert cosine([1.0, 0.0], [1.0, 0.0, 0.0]) == 0.0
    assert cosine([0.0, 0.0], [0.0, 0.0]) == 0.0
    assert abs(cosine([1.0, 2.0], [1.0, 2.0]) - 1.0) < 1e-9


def test_rrf_prefers_doc_ranked_well_in_both_legs():
    fused = rrf_fuse([[0, 1, 2], [1, 0, 2]])
    # doc 0 and doc 1 each hold one first and one second place — tie; doc 2 last in both.
    assert fused[0] == fused[1] > fused[2]


def test_hybrid_match_vector_leg_catches_paraphrase():
    # Query vector is close to candidate 1's vector; no keyword overlap at all.
    candidates = [
        {"text": "payment card skimming at retail terminals", "vector": [1.0, 0.0]},
        {"text": "unauthorised disclosure of information", "vector": [0.0, 1.0]},
    ]
    out = hybrid_match("data leakage", candidates, query_vec=[0.0, 1.0])
    assert out[0][0] == 1


def test_hybrid_match_exact_name_short_circuits_to_front():
    candidates = [
        {"text": "a very long highly relevant description about data leakage risks",
         "vector": [1.0, 0.0], "name": "Data leakage risks"},
        {"text": "short", "vector": [0.0, 1.0], "name": "Ransomware attack"},
    ]
    out = hybrid_match("Ransomware attack!", candidates, query_vec=[1.0, 0.0])
    assert out[0] == (1, 1.0)  # exact normalized name wins over both legs


def test_hybrid_match_zero_scoring_docs_are_excluded():
    candidates = [
        {"text": "completely unrelated words", "vector": None},
        {"text": "ransomware encrypts operational data", "vector": None},
    ]
    out = hybrid_match("ransomware", candidates)
    assert [i for i, _ in out] == [1]  # doc 0 scored 0 in every leg -> absent, not last


def test_hybrid_match_deterministic_and_top_n():
    candidates = [{"text": f"threat number {i} ransomware", "vector": None} for i in range(5)]
    a = hybrid_match("ransomware threat", candidates, top_n=3)
    b = hybrid_match("ransomware threat", candidates, top_n=3)
    assert a == b and len(a) == 3


def test_normalize_name_tolerates_spacing_and_case():
    assert normalize_name(" Multi-Factor  Authentication ") == normalize_name("multi factor authentication")
