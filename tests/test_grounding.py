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


def _unpinned(**kw) -> Settings:
    """Settings holding the DOCUMENTED default cutoffs, marked as NOT explicitly set.

    Both halves matter. resolve_thresholds' precedence rule 1 keys off `model_fields_set`, and
    this repo's own .env legitimately pins TSG_GROUNDING_* — the escape hatch config.py:252
    documents — so an inherited Settings() silently routes these tests through the env branch
    instead of the store/calibrate branch each one names, asserting the wrong thing with no hint
    that ambient config was the cause. Monkeypatching os.environ cannot fix it (the values arrive
    via the .env FILE, read at class-definition time); init kwargs outrank env and env_file, so
    passing them and then clearing the flag is the only hermetic form.
    """
    s = Settings(grounding_match_threshold=75.0, **kw)
    s.model_fields_set.discard("grounding_match_threshold")
    return s


def test_route_bands_at_boundaries():
    s = Settings(grounding_match_threshold=75.0)
    assert label_match_from_score(75.0, s) is GroundingStatus.verified      # >= cutoff → verified
    assert label_match_from_score(74.9, s) is GroundingStatus.unverified    # just under → unverified
    assert label_match_from_score(0.0, s) is GroundingStatus.unverified     # no match at all
    assert label_match_from_score(100.0, s) is GroundingStatus.verified     # perfect match


def test_worst_returns_lower_band():
    # overall confidence can be no higher than the weakest of Type / Threat-name.
    assert pick_worse_of_two(GroundingStatus.unverified, GroundingStatus.verified) is GroundingStatus.unverified
    assert pick_worse_of_two(GroundingStatus.verified, GroundingStatus.unverified) is GroundingStatus.unverified
    assert pick_worse_of_two(GroundingStatus.verified, GroundingStatus.verified) is GroundingStatus.verified
    assert pick_worse_of_two(GroundingStatus.unverified, GroundingStatus.unverified) is GroundingStatus.unverified


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


class _CountingEmbedStub:
    """Records every embed() batch so a test can assert HOW MANY round trips happened."""

    def __init__(self):
        self.batches: list[list[str]] = []

    def embed(self, texts, *, model=None, kind="query"):
        self.batches.append(list(texts))
        return [[0.1, 0.2, 0.3, 0.4] for _ in texts]


def test_prime_query_embeddings_uses_one_batched_call_and_dedupes():
    """[perf] Every proposal's type/name text is known before find_threats' loop, but each
    proposal used to embed its own pair — one round trip per proposed threat (up to
    max_threats_per_asset). Prime them in ONE call, deduped, so a repeated STRIDE type across
    proposals is embedded once rather than once per proposal."""
    llm = _CountingEmbedStub()
    cache: dict = {}
    proposals = [
        {"type": "Spoofing", "name": "Credential replay"},
        {"type": "Spoofing", "name": "Token forgery"},       # type repeats — must not re-embed
        {"type": "Tampering", "name": "Credential replay"},  # name repeats — must not re-embed
    ]

    grounding.prime_query_embeddings(llm, proposals, cache)

    assert len(llm.batches) == 1  # ONE round trip for all three proposals, not three
    assert sorted(llm.batches[0]) == ["Credential replay", "Spoofing", "Tampering", "Token forgery"]
    assert cache[("qv", "Spoofing")] == [0.1, 0.2, 0.3, 0.4]

    # already-primed texts are never re-embedded on a second call (additive next-set round)
    grounding.prime_query_embeddings(llm, proposals, cache)
    assert len(llm.batches) == 1


def test_prime_query_embeddings_failure_is_not_fatal():
    """Pure optimization: if the batched embed fails, each proposal still embeds its own pair
    on the existing path — priming must never break a run it only exists to speed up."""
    class _Boom:
        def embed(self, texts, *, model=None, kind="query"):
            raise RuntimeError("embedding service down")

    cache: dict = {}
    grounding.prime_query_embeddings(_Boom(), [{"type": "Spoofing", "name": "x"}], cache)
    assert cache == {}  # nothing primed, no exception escaped


# --- self-calibrating thresholds (resolve_thresholds) ---
# Each test uses a UNIQUE model pair: the resolver memoizes per (embedding, reranker) pair in a
# module-level dict, and reusing the default pair here would leak a fake calibration into every
# later find_threat_in_library test in the whole suite.

def test_resolve_thresholds_env_override_wins():
    s = Settings(grounding_match_threshold=80.0)
    # an explicitly-set value pins the cutoff — no store lookup, no calibration, sess/llm untouched
    assert grounding.resolve_thresholds(None, None, s) == 80.0


def test_resolve_thresholds_uses_stored_pair_and_memoizes(monkeypatch):
    calls = []
    monkeypatch.setattr(grounding.embeddings, "load_thresholds",
                        lambda key: calls.append(key) or 72.0)
    s = _unpinned(embedding_model="fake-emb-stored", reranker_model="fake-rr-stored")
    assert grounding.resolve_thresholds(None, None, s) == 72.0
    assert grounding.resolve_thresholds(None, None, s) == 72.0
    assert calls == [("fake-emb-stored", "fake-rr-stored")]  # second hit came from the memo


def test_resolve_thresholds_auto_calibrates_and_stores(monkeypatch):
    stored = {}
    monkeypatch.setattr(grounding.embeddings, "load_thresholds", lambda key: None)
    monkeypatch.setattr(grounding.embeddings, "store_thresholds",
                        lambda key, th: stored.update(key=key, th=th))
    monkeypatch.setattr(grounding, "_auto_calibrate", lambda sess, llm, s: 71.0)
    s = _unpinned(embedding_model="fake-emb-auto", reranker_model="fake-rr-auto")
    # allow_calibration=True is the BOOT-ONLY door (celery_app._init_worker) — see the next test
    assert grounding.resolve_thresholds(object(), object(), s, allow_calibration=True) == 71.0
    assert stored == {"key": ("fake-emb-auto", "fake-rr-auto"), "th": 71.0}


def test_resolve_thresholds_never_calibrates_outside_boot(monkeypatch):
    """[review-fix] Calibration is ~30 sequential chat calls plus ~180 embed/rerank calls. Run
    lazily from find_threat_in_library it executes INSIDE a leased THREATS stage whose lease
    covers roughly two chat calls — the lease expires mid-pass, the reaper ERRORs the row and
    cancels the session, and the worker's finish_stage then loses its CAS. A healthy run,
    cancelled, its spend discarded. Only the boot warm-up may calibrate."""
    monkeypatch.setattr(grounding.embeddings, "load_thresholds", lambda key: None)
    monkeypatch.setattr(grounding, "_auto_calibrate",
                        lambda sess, llm, s: pytest.fail("calibration must never run in-request"))
    s = _unpinned(embedding_model="fake-emb-lazy", reranker_model="fake-rr-lazy")
    # default allow_calibration=False → static default, no calibration attempted
    assert grounding.resolve_thresholds(object(), object(), s) == s.grounding_match_threshold


def test_uncalibrated_fallback_is_not_memoized_so_a_worker_self_heals(monkeypatch):
    """[review-fix] Memoizing the fallback pinned a worker to static thresholds for its whole
    life — even after a SIBLING worker stored a real calibration seconds later. The fallback
    must stay unmemoized so the next call picks up whatever now exists."""
    stored_now: dict = {}
    monkeypatch.setattr(grounding.embeddings, "load_thresholds", lambda key: stored_now.get(key))
    s = _unpinned(embedding_model="fake-emb-heal", reranker_model="fake-rr-heal")

    assert grounding.resolve_thresholds(None, None, s) == s.grounding_match_threshold
    stored_now[("fake-emb-heal", "fake-rr-heal")] = 73.0  # a sibling worker calibrates
    assert grounding.resolve_thresholds(None, None, s) == 73.0  # picked up, not pinned


_CAL_NAMES = [f"threat-{i}" for i in range(6)]


def _stub_library(monkeypatch):
    monkeypatch.setattr(grounding.embeddings, "_active_names", lambda sess, t, c: _CAL_NAMES)


def test_auto_calibrate_skips_billed_paraphrases_on_near_duplicate_library(monkeypatch):
    """A duplicate catalogue entry makes strict separation mathematically impossible, and it
    recurs identically on EVERY worker boot — so paying ~30 billed paraphrase calls to rediscover
    it each time is pure waste. Negatives are free (local embed+rerank), so the impossibility is
    detectable before spending anything: this pins that the paraphrase pass is never reached."""
    _stub_library(monkeypatch)
    monkeypatch.setattr(grounding, "_paraphrase",
                        lambda llm, n: pytest.fail("must not spend a billed paraphrase call"))
    monkeypatch.setattr(grounding, "find_closest_match",
                        lambda llm, q, rows, key, s, group=None, qv=None: ({"ThreatName": "dupe"}, 99.5))
    assert grounding._auto_calibrate(object(), object(), _unpinned()) is None


def test_auto_calibrate_still_calibrates_when_negatives_are_separable(monkeypatch):
    """The guard above must not fire on a healthy library — otherwise it would silently disable
    calibration everywhere. Negatives (scored against library-minus-one, so a SHORTER rows list)
    come back low; positives score high; a real cutoff is returned."""
    _stub_library(monkeypatch)
    monkeypatch.setattr(grounding, "_paraphrase", lambda llm, n: [f"reworded {n}"])

    def _fcm(llm, q, rows, key, s, group=None, qv=None):
        is_negative = len(rows) < len(_CAL_NAMES)  # `others` excludes the name under test
        return ({"ThreatName": "x"}, 10.0 if is_negative else 95.0)

    monkeypatch.setattr(grounding, "find_closest_match", _fcm)
    got = grounding._auto_calibrate(object(), object(), _unpinned())
    assert got is not None
    assert 10.0 < got < 95.0        # the one cutoff, midway between the classes


def test_boundary_between_stays_strictly_inside_a_sub_point_gap():
    """[review-fix] round()-ing the midpoint could land the cutoff ON or BELOW max(negatives)
    when the class gap was under ~1 point — and `score >= threshold` then bands a measured
    IMPOSTOR as verified, trusting master ids that do not describe it."""
    got = grounding.boundary_between([71.2], [71.4])
    assert got is not None and 71.2 < got < 71.4


def test_resolve_thresholds_falls_back_to_defaults_when_uncalibratable(monkeypatch):
    monkeypatch.setattr(grounding.embeddings, "load_thresholds", lambda key: None)
    monkeypatch.setattr(grounding, "_auto_calibrate", lambda sess, llm, s: None)
    s = _unpinned(embedding_model="fake-emb-none", reranker_model="fake-rr-none")
    # degrade-safe: never blocks a run — the static default + a warning
    assert grounding.resolve_thresholds(None, None, s) == s.grounding_match_threshold


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
