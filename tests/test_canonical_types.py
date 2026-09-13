"""grounding.canonical_types_for — the per-category Threat_Type vocabulary for threats_prompt.

WHY THIS FILE EXISTS: `threats_prompt` has accepted `canonical_types` since it was written and
nothing ever passed it, so gap-generated threats invented their own type wording, missed the
rerank cutoff, and landed type_id=None — which silently costs them the type's CURATED actors.
Wiring it up is only half the fix; the other half is that every failure mode here is INVISIBLE
in production (a bad vocabulary still produces a plausible threat), so it has to be pinned.

The vector leg is deliberately disabled in most tests (`get_vectors` -> {}), leaving BM25 as the
only text signal. That makes "does this type share a word with the asset text" exact and
deterministic, instead of asserting on cosine values that would drift with the embedding model.
"""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import models as m
from app.pipeline import embeddings, grounding, prompts
from app.pipeline.threat_identification import _reconcile_proposal_categories

SPOOFING, TAMPERING = 1, 6


class _StubLLM:
    """Only `embed` is reached: canonical_types_for embeds the asset query once."""

    def embed(self, texts, kind=None):
        return [[1.0, 0.0] for _ in texts]


def _session(types: list[tuple[int, str, int]]):
    engine = create_engine("sqlite://")
    for tbl in (m.Threat_Category, m.Threat_Type, m.Threat_Catalogue,
                m.Threat_Catalogue_Category_Map):
        tbl.__table__.create(engine)
    s = sessionmaker(bind=engine, future=True)()
    for cid, name in ((SPOOFING, "Spoofing"), (TAMPERING, "Tampering")):
        s.execute(m.Threat_Category.__table__.insert().values(
            ThreatCategoryID=cid, ThreatCategoryName=name, IsActive=True, IsDeleted=False))
    for tid, tname, cid in types:
        s.execute(m.Threat_Type.__table__.insert().values(
            ThreatTypeID=tid, ThreatTypeName=tname, ThreatCategoryID=cid,
            IsActive=True, IsDeleted=False))
    s.commit()
    return s


@pytest.fixture(autouse=True)
def _no_vectors(monkeypatch):
    """Keyword-only ranking: candidate vectors absent -> the cosine leg contributes nothing.
    Keeps every assertion below a statement about BM25 token overlap, not about an embedding."""
    monkeypatch.setattr(embeddings, "get_vectors", lambda *a, **k: {})


def _used(*names: str) -> list[dict]:
    """Retrieved-threat summaries, shaped as _build_threat_records emits them."""
    return [{"library_threat_type": n} for n in names]


# --- the wiring ---------------------------------------------------------------------------
def test_vocabulary_reaches_the_rendered_prompt():
    """End of the wire: what canonical_types_for returns must actually appear in the prompt."""
    s = _session([(1, "Credential Abuse", SPOOFING), (2, "Cloud/SaaS Abuse", SPOOFING)])
    canonical = grounding.canonical_types_for(s, _StubLLM(), ["Spoofing"], [], "any asset", 15)
    assert canonical == {"Spoofing": ["Credential Abuse", "Cloud/SaaS Abuse"]}

    body = " ".join(msg["content"] for msg in prompts.threats_prompt(
        "A", {"cii_asset_description": "x"}, [], max_threats=1, categories=["Spoofing"],
        canonical_types=canonical))
    assert "canonical type vocabulary" in body
    assert "Credential Abuse" in body and "Cloud/SaaS Abuse" in body


def test_absent_vocabulary_leaves_the_prompt_byte_identical():
    """The "changes nothing when there is nothing to say" check — an empty Threat_Type table
    must produce the prompt this codebase rendered before the feature existed."""
    s = _session([])
    assert grounding.canonical_types_for(s, _StubLLM(), ["Spoofing"], [], "asset", 15) == {}

    args = ("A", {"cii_asset_description": "x"}, [])
    kw = {"max_threats": 1, "categories": ["Spoofing"]}
    assert prompts.threats_prompt(*args, canonical_types=None, **kw) == \
           prompts.threats_prompt(*args, **kw)


# --- the correctness trap -----------------------------------------------------------------
def test_unresolvable_category_is_skipped_not_widened():
    """get_possible_types(sess, None) returns EVERY active type ([R6]). A category name that
    resolves to no row must therefore be OMITTED — passing None through would advertise the
    entire vocabulary as belonging to that one cell, which is worse than supplying nothing."""
    s = _session([(1, "Credential Abuse", SPOOFING), (2, "AI Abuse", TAMPERING)])
    out = grounding.canonical_types_for(
        s, _StubLLM(), ["Spoofing", "No Such Category"], [], "asset", 15)
    assert "No Such Category" not in out
    assert out["Spoofing"] == ["Credential Abuse"]  # NOT both types


# --- the cap ------------------------------------------------------------------------------
def test_cap_zero_disables_the_feature_entirely():
    """The escape hatch: 0 must behave as if the feature had never been added, no deploy."""
    s = _session([(1, "Credential Abuse", SPOOFING)])
    assert grounding.canonical_types_for(s, _StubLLM(), ["Spoofing"], [], "asset", 0) == {}


def test_cap_is_enforced_and_selection_follows_the_asset():
    """The operator's constraint: thousands of types must not all be sent — AND the survivors
    must depend on the asset. A cap over a constant ranking would send the same N forever,
    which is the failure the ranking exists to prevent, so (b) is the assertion that matters."""
    types = [(i, f"Type{i:03d} turbine", SPOOFING) for i in range(1, 21)]
    types += [(i, f"Type{i:03d} banking", SPOOFING) for i in range(21, 41)]
    types += [(i, f"Type{i:03d} inert", SPOOFING) for i in range(41, 201)]
    s = _session(types)

    turbine = grounding.canonical_types_for(s, _StubLLM(), ["Spoofing"], [], "turbine", 12)
    banking = grounding.canonical_types_for(s, _StubLLM(), ["Spoofing"], [], "banking", 12)

    assert len(turbine["Spoofing"]) == 12                        # (a) capped
    assert set(turbine["Spoofing"]) != set(banking["Spoofing"])  # (b) asset-dependent
    assert all("turbine" in n for n in turbine["Spoofing"])
    assert all("banking" in n for n in banking["Spoofing"])


# --- the fusion ---------------------------------------------------------------------------
def test_both_signals_contribute_neither_alone_decides():
    """What distinguishes real RRF fusion from "usage with extra steps".

    Alpha Abuse         — used by retrieved threats, shares NO word with the asset text
    Turbine Manipulation — never used, shares a word
    Both must survive a cap of 2; a type strong on neither must not. Drop either leg and one
    of the first two assertions fails.
    """
    s = _session([(1, "Alpha Abuse", SPOOFING),             # usage only
                  (2, "Turbine Manipulation", SPOOFING),    # words only
                  (3, "Zeta Abuse", SPOOFING)])             # neither
    out = grounding.canonical_types_for(
        s, _StubLLM(), ["Spoofing"], _used("Alpha Abuse", "Alpha Abuse"), "turbine", 2)

    assert "Alpha Abuse" in out["Spoofing"], "usage leg dropped"
    assert "Turbine Manipulation" in out["Spoofing"], "word-similarity leg dropped"
    assert "Zeta Abuse" not in out["Spoofing"]


def test_silent_legs_fall_back_to_deterministic_order_not_empty():
    """Nothing used these types and no word overlaps — bare labels vs asset prose is exactly
    the zero-BM25 case nearest_library_actors documents. Returning [] would drop the category
    out of the vocabulary silently; the deterministic ThreatTypeID order is the safe answer."""
    s = _session([(3, "Gamma Abuse", SPOOFING), (1, "Alpha Abuse", SPOOFING),
                  (2, "Beta Abuse", SPOOFING)])
    out = grounding.canonical_types_for(s, _StubLLM(), ["Spoofing"], [], "unrelated words", 2)
    assert out["Spoofing"] == ["Alpha Abuse", "Beta Abuse"]  # ThreatTypeID 1, 2


def test_ai_generated_rows_do_not_vote_in_the_usage_leg():
    """library_threat_type is None on an AI-generated threat. Counting those would let one
    hallucinated label promote itself into the vocabulary the next round — a feedback loop."""
    s = _session([(1, "Alpha Abuse", SPOOFING), (2, "Turbine Manipulation", SPOOFING)])
    retrieved = [{"library_threat_type": None, "threat_type": "Alpha Abuse"}]
    out = grounding.canonical_types_for(s, _StubLLM(), ["Spoofing"], retrieved, "turbine", 1)
    assert out["Spoofing"] == ["Turbine Manipulation"]


# --- category/type reconciliation -----------------------------------------------------------
# Stage 1 chooses the CATEGORY as well as the type, so a per-category vocabulary can be crossed:
# the model takes a listed type from one cell and files the threat under another. grounding
# resolves types WITHIN the assigned category, so the pair then reads as an invented type — a
# curated string, used verbatim exactly as instructed, recorded as AI-generated and stripped of
# the type's curated actors. Every case below is silent in production: the threat still looks
# fine, only its provenance is wrong.
_REP_TAM = {"Repudiation": ["Data/Telemetry Abuse"], "Tampering": ["AI Abuse"]}


def test_type_from_another_categorys_list_moves_the_proposal():
    props = [{"category": "Tampering", "type": "Data/Telemetry Abuse", "name": "x"}]
    assert _reconcile_proposal_categories(props, _REP_TAM, "sid") == 1
    assert props[0]["category"] == "Repudiation"


def test_normalized_equality_still_counts_as_verbatim():
    """The model echoes a listed type with different casing/punctuation. normalize_name is the
    codebase's comparison key; without it the repair would almost never fire."""
    props = [{"category": "Tampering", "type": "data telemetry abuse", "name": "x"}]
    assert _reconcile_proposal_categories(props, _REP_TAM, "sid") == 1
    assert props[0]["category"] == "Repudiation"


def test_near_miss_does_not_move():
    """EXACT equality only. A fuzzy move would relabel a threat's STRIDE cell on a near-miss,
    and the category drives the coverage quota — same discipline as _usable_category."""
    props = [{"category": "Tampering", "type": "Data Telemetry Abuses", "name": "x"}]
    assert _reconcile_proposal_categories(props, _REP_TAM, "sid") == 0
    assert props[0]["category"] == "Tampering"


def test_type_offered_by_two_categories_never_moves_anything():
    """[A2] widening can admit one type to several categories. Which the model meant is then
    unknowable, so an ambiguous type must not be allowed to relabel anything.

    The proposal is written under the FIRST-listed category on purpose. Drop the ambiguity
    guard and `owner` keeps whichever category was seen LAST — so a proposal filed under the
    last one would not move either way and this test would pass against broken code. Filed
    under the first, removing the guard drags it to the last, and the assertion bites."""
    canonical = {"Repudiation": ["Shared Abuse"], "Tampering": ["Shared Abuse"]}
    props = [{"category": "Repudiation", "type": "Shared Abuse", "name": "x"}]
    assert _reconcile_proposal_categories(props, canonical, "sid") == 0
    assert props[0]["category"] == "Repudiation"


def test_category_with_no_supplied_list_is_left_alone():
    """Information Disclosure has no curated types today, so it gets no list. Borrowing another
    cell's label is not evidence of mislabelling, and moving would vacate coverage we asked for."""
    props = [{"category": "Information Disclosure", "type": "Data/Telemetry Abuse", "name": "x"}]
    assert _reconcile_proposal_categories(props, _REP_TAM, "sid") == 0
    assert props[0]["category"] == "Information Disclosure"


def test_type_already_in_its_own_list_is_untouched():
    props = [{"category": "Tampering", "type": "AI Abuse", "name": "x"}]
    assert _reconcile_proposal_categories(props, _REP_TAM, "sid") == 0
    assert props[0]["category"] == "Tampering"


def test_no_vocabulary_means_no_reconciliation():
    """cap=0 / empty library: the repair must be inert, not merely harmless."""
    props = [{"category": "Tampering", "type": "Whatever", "name": "x"}]
    assert _reconcile_proposal_categories(props, {}, "sid") == 0
    assert props[0]["category"] == "Tampering"


def test_prompt_states_the_per_category_binding():
    """The PREVENTION half. The repair above is the safety net; this sentence is what stops the
    mismatch being produced. A repair that fires often means the prompt is not doing its job."""
    body = " ".join(msg["content"] for msg in prompts.threats_prompt(
        "A", {"cii_asset_description": "x"}, [], max_threats=1,
        categories=["Repudiation"], canonical_types={"Repudiation": ["Data/Telemetry Abuse"]}))
    assert "category you assign" in body
    assert "NOT interchangeable" in body
