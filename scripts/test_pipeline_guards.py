"""Self-check for the threat-pipeline guards added alongside the 2026-08 defect audit.

Plain asserts under __main__, matching scripts/test_db_connectivity.py and scripts/test_otx_feed.py
— this repo has no test framework and this file deliberately does not introduce one. No database,
no network, no real embedding model: every function under test is pure, or takes the LLM client as
a parameter (so a stub suffices).

Run:  python scripts/test_pipeline_guards.py

Each assertion pins one defect that was live before the audit. If one fails, the guard it names
has regressed — the docstring on each says what breaks in production when it does.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.pipeline import scoping  # noqa: E402
from app.pipeline.tasks import (_MAX_PROPOSAL_CHARS, _semantic_duplicates,  # noqa: E402
                                _usable_proposal)

ASSET = "Widget Control System"


class _StubLLM:
    """embed() picks a unit vector from the label's FIRST word, so two different label strings
    sharing a first word are exactly parallel (cosine 1.0) and anything else is orthogonal.
    Lets each case below control similarity outright instead of depending on a real model."""

    _AXES = {"alpha": [1.0, 0.0, 0.0], "beta": [0.0, 1.0, 0.0], "gamma": [0.0, 0.0, 1.0]}

    def embed(self, texts, kind=None):  # noqa: ARG002 — signature parity with LLMClient
        out = []
        for t in texts:
            head = t.split()[0].casefold() if t.split() else ""
            out.append(list(self._AXES.get(head, [0.0, 0.0, 1.0])))
        return out


def _threat(tid: str, name: str, category: str = "Information Disclosure") -> dict:
    """The summary shape find_threats builds and dal.active_threats reproduces."""
    return {"threat_id": tid, "threat_name": name, "category": category,
            "grounding_status": "unverified", "library_threat_name": None,
            "library_threat_type": None, "threat_type": "Sensitive data exposure",
            "threat_type_id": None, "catalogue_id": None, "actors": []}


def check_usable_proposal() -> None:
    """A non-dict element used to reach .get() in grounding.prime_query_embeddings and raise
    AttributeError — not the typed error [R8] expects, so it cancelled the whole session."""
    assert _usable_proposal({"type": "Data tampering", "name": "Tampering of Widget"}) is True
    assert _usable_proposal("Phishing") is False
    assert _usable_proposal(None) is False
    assert _usable_proposal(["nested"]) is False

    # Empty type/name used to be persisted, then rejected by scenario_prompt's ValueError. Because
    # nothing ever UPDATEs Identified_Threat, the resulting error card re-raised identically on
    # every regenerate — permanently unclearable.
    assert _usable_proposal({"type": "", "name": "Tampering of Widget"}) is False
    assert _usable_proposal({"type": "Data tampering", "name": None}) is False
    assert _usable_proposal({"type": "Data tampering"}) is False

    # Over-long used to raise inside llm.embed and lose EVERY threat in the round, not just this one.
    assert _usable_proposal({"type": "x" * (_MAX_PROPOSAL_CHARS + 1), "name": "n"}) is False
    assert _usable_proposal({"type": "x" * 10, "name": "y" * 10}) is True

    # Non-string values must not slip through as truthy.
    assert _usable_proposal({"type": 42, "name": "Tampering of Widget"}) is False
    print("ok  _usable_proposal")


def check_semantic_duplicates_same_category() -> None:
    """Two distinct threats whose stripped labels mean the same thing must collapse to one.
    identity_hash cannot see this: it compares ids and exact strings, so both survive it."""
    llm = _StubLLM()
    threats = [_threat("t1", "alpha disclosure of records"),
               _threat("t2", "alpha leakage of records")]
    dupes = _semantic_duplicates(llm, "sess", 0, threats, None, ASSET, threshold=0.92)
    assert dupes == {"t2"}, dupes  # first wins, later duplicate dropped
    print("ok  _semantic_duplicates drops a same-meaning threat")


def check_semantic_duplicates_identical_labels() -> None:
    """THE regression this file exists for. The old scan guarded self-comparison by VALUE
    (`other == label`), so two DISTINCT threats with byte-identical labels — cosine 1.0, the
    strongest signal available — were the one pair it silently skipped."""
    llm = _StubLLM()
    threats = [_threat("t1", "alpha disclosure"), _threat("t2", "alpha disclosure")]
    dupes = _semantic_duplicates(llm, "sess", 0, threats, None, ASSET, threshold=0.92)
    assert dupes == {"t2"}, dupes
    print("ok  _semantic_duplicates catches byte-identical labels")


def check_semantic_duplicates_category_gate() -> None:
    """The STRIDE-category gate is mandatory, not an optimisation. On the live embedder
    'Unauthorized disclosure of X' vs 'Unauthorized modification of X' scores 0.969 — above every
    genuine paraphrase — because embeddings track word overlap and those differ by one noun. They
    are opposite impact classes; no threshold separates them, only the category restriction does."""
    llm = _StubLLM()
    threats = [_threat("t1", "alpha disclosure", category="Information Disclosure"),
               _threat("t2", "alpha modification", category="Tampering")]
    dupes = _semantic_duplicates(llm, "sess", 0, threats, None, ASSET, threshold=0.92)
    assert dupes == set(), dupes  # identical vectors, different impact class — both survive
    print("ok  _semantic_duplicates respects the category gate")


def check_semantic_duplicates_no_chain_drop() -> None:
    """Similarity is not transitive, so comparison must run against SURVIVORS only. Comparing
    against already-dropped labels would chain-drop a threat for resembling one that is no longer
    there."""
    llm = _StubLLM()
    threats = [_threat("t1", "alpha one"), _threat("t2", "alpha two"), _threat("t3", "beta three")]
    dupes = _semantic_duplicates(llm, "sess", 0, threats, None, ASSET, threshold=0.92)
    assert dupes == {"t2"}, dupes  # t3 is orthogonal to the survivor and must be kept
    print("ok  _semantic_duplicates does not chain-drop")


def check_semantic_duplicates_against_priors() -> None:
    """A next-set round must not re-propose something the session already has."""
    llm = _StubLLM()
    priors = [_threat("p1", "alpha disclosure of records")]
    threats = [_threat("t1", "alpha leakage of records"), _threat("t2", "beta outage")]
    dupes = _semantic_duplicates(llm, "sess", 0, threats, priors, ASSET, threshold=0.92)
    assert dupes == {"t1"}, dupes
    print("ok  _semantic_duplicates compares against prior rounds")


def check_semantic_scan_failure_is_not_fatal() -> None:
    """A failed scan must degrade to 'no duplicates', never lose the round's threats."""

    class _Boom:
        def embed(self, texts, kind=None):  # noqa: ARG002
            raise RuntimeError("embedding backend down")

    dupes = _semantic_duplicates(_Boom(), "sess", 0,
                                 [_threat("t1", "alpha one"), _threat("t2", "alpha two")],
                                 None, ASSET, threshold=0.92)
    assert dupes == set(), dupes
    print("ok  _semantic_duplicates degrades safely on embed failure")


def check_ranking_is_stable_and_meaningful() -> None:
    """Rank order used to tie-break on threat_id, and dal.guid() puts its random bytes in the
    LEADING string positions — so with scores taking only two distinct values in practice, rank
    was a lottery. It now relies on list.sort being stable, preserving the model's own
    'most contextually relevant first' ordering."""
    threats = [_threat("zzz-last-alphabetically", "alpha one"),
               _threat("aaa-first-alphabetically", "alpha two"),
               _threat("mmm-middle", "alpha three")]
    scored = scoping.score_threats(threats, base_score=50.0, default_rule_weight=10.0,
                                   score_threshold=None)
    assert [s.threat_id for s in scored] == [t["threat_id"] for t in threats], \
        [s.threat_id for s in scored]
    assert all(s.selected for s in scored)  # no rules, no gate — nothing may be dropped
    assert len({s.score for s in scored}) == 1  # identical grounding status => identical score
    print("ok  score_threats preserves input order within a score band")


def check_score_floor_still_reachable() -> None:
    """The floor is dormant under the shipped rulebook but must still WORK — it is what a
    curator's negative-weight rule acts through."""
    threats = [_threat("t1", "alpha one")]
    scored = scoping.score_threats(threats, base_score=50.0, default_rule_weight=10.0,
                                   score_threshold=99.0)
    assert scored[0].selected is False
    assert str(scored[0].rejection) == "below_threshold", scored[0].rejection
    assert scored[0].selection is None  # selection is not None <=> selected
    print("ok  score_threats floor still rejects when it can bite")


def demo() -> None:
    check_usable_proposal()
    check_semantic_duplicates_same_category()
    check_semantic_duplicates_identical_labels()
    check_semantic_duplicates_category_gate()
    check_semantic_duplicates_no_chain_drop()
    check_semantic_duplicates_against_priors()
    check_semantic_scan_failure_is_not_fatal()
    check_ranking_is_stable_and_meaningful()
    check_score_floor_still_reachable()
    print("\nall pipeline guards pass")


if __name__ == "__main__":
    demo()
