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

from app.core.config import get_settings  # noqa: E402
from app.pipeline import scoping  # noqa: E402
from app.pipeline.cascade import (NextSetOutcome, _build_regen_audit_detail,  # noqa: E402
                                _next_set_outcome)
from app.pipeline.tasks import (_semantic_duplicates,  # noqa: E402
                                _usable_proposal, asset_agnostic_name, clean_library_name)

ASSET = "Widget Control System"


class _StubLLM:
    """embed() picks a unit vector from the label's FIRST word, so two different label strings
    sharing a first word are exactly parallel (cosine 1.0) and anything else is orthogonal.
    Lets each case below control similarity outright instead of depending on a real model."""

    # "trapx" sits at cosine 0.969 to "alpha" — the measured cross-class similarity of
    # 'Unauthorized disclosure of X' vs 'Unauthorized modification of X' on the live embedder.
    _AXES = {"alpha": [1.0, 0.0, 0.0], "beta": [0.0, 1.0, 0.0], "gamma": [0.0, 0.0, 1.0],
             "trapx": [0.969, 0.246779, 0.0]}

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
    assert _usable_proposal({"type": "x" * (get_settings().max_proposal_chars + 1), "name": "n"}) is False
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
    assert set(dupes) == {"t2"}, dupes  # first wins, later duplicate dropped
    assert dupes["t2"]["duplicate_of_threat_id"] == "t1", dupes  # linked to its survivor
    print("ok  _semantic_duplicates drops a same-meaning threat")


def check_semantic_duplicates_identical_labels() -> None:
    """THE regression this file exists for. The old scan guarded self-comparison by VALUE
    (`other == label`), so two DISTINCT threats with byte-identical labels — cosine 1.0, the
    strongest signal available — were the one pair it silently skipped."""
    llm = _StubLLM()
    threats = [_threat("t1", "alpha disclosure"), _threat("t2", "alpha disclosure")]
    dupes = _semantic_duplicates(llm, "sess", 0, threats, None, ASSET, threshold=0.92)
    assert set(dupes) == {"t2"}, dupes
    print("ok  _semantic_duplicates catches byte-identical labels")


def check_semantic_duplicates_category_gate() -> None:
    """Cross-category pairs are judged at the STRICTER cross ceiling (0.98), not skipped and not
    the normal threshold. Two contracts pinned at once: the measured 0.969 disclosure/modification
    trap (two REAL threats, different impact classes) must survive, while a byte-identical label
    the model merely relabelled into another category must be dropped."""
    llm = _StubLLM()
    # cosine(alpha, trapx) = 0.969 -> below the 0.98 cross ceiling -> both survive.
    threats = [_threat("t1", "alpha disclosure", category="Information Disclosure"),
               _threat("t2", "trapx modification", category="Tampering")]
    dupes = _semantic_duplicates(llm, "sess", 0, threats, None, ASSET, threshold=0.92)
    assert dupes == {}, dupes
    # cosine 1.0 (same first word) across categories -> at/above 0.98 -> relabel caught.
    threats = [_threat("t1", "alpha disclosure", category="Information Disclosure"),
               _threat("t2", "alpha disclosure", category="Tampering")]
    dupes = _semantic_duplicates(llm, "sess", 0, threats, None, ASSET, threshold=0.92)
    assert set(dupes) == {"t2"}, dupes
    print("ok  _semantic_duplicates cross-category ceiling: trap survives, relabel caught")


def check_clean_library_name() -> None:
    """The wrapper junk must be STRIPPED from the returned value, not merely tolerated —
    '\"Data exfiltration\"' used to pass validation and be stored quotes-and-all, becoming the
    triage query and (on auto-approve) the shared library entry's literal wording."""
    assert clean_library_name('"Data exfiltration by insiders"') == "Data exfiltration by insiders"
    assert clean_library_name("[Credential theft attack]") == "Credential theft attack"
    assert clean_library_name("  Sensitive data exposure  ") == "Sensitive data exposure"
    assert clean_library_name("e-mail account takeover") == "e-mail account takeover"  # interior kept
    assert clean_library_name("N/A") is None
    assert clean_library_name('["NA"]') is None
    assert clean_library_name("Ransomware") is None  # one word — below the two-word floor
    assert clean_library_name(None) is None
    print("ok  clean_library_name strips wrappers and keeps interiors")


def check_asset_name_stripping() -> None:
    """Three measured leak paths through the old literal re.escape boundary pattern."""
    # Trailing punctuation on the ASSET name no longer breaks the match.
    assert asset_agnostic_name("Data exfiltration from ACME Corp systems", "ACME Corp.") == \
        "Data exfiltration systems"
    # Possessive is consumed with the span instead of leaving a dangling 's.
    got = asset_agnostic_name("Citizen Portal's credentials exposed", "Citizen Portal")
    assert got == "credentials exposed", got
    # Mid-string removal consumes its preceding preposition — no more 'Compromise of leading to'.
    got = asset_agnostic_name("Compromise of Widget Control System leading to outage",
                            "Widget Control System")
    assert got == "Compromise leading to outage", got
    # The two preposition lists used to DISAGREE — the $-anchored tail cleanup lacked `from` and
    # `at`, so a trailing one survived into the library name. Both passes now share one constant.
    got = asset_agnostic_name("Data exfiltration from ACME Corp", "ACME Corp")
    assert got == "Data exfiltration", got
    got = asset_agnostic_name("Unauthorized access at ACME Corp", "ACME Corp")
    assert got == "Unauthorized access", got
    # Nothing-but-the-asset still returns None, never the raw asset-embedded string.
    assert asset_agnostic_name("Widget Control System", "Widget Control System") is None
    print("ok  asset_agnostic_name handles punctuation, possessive, mid-string")


def check_semantic_duplicates_no_chain_drop() -> None:
    """Similarity is not transitive, so comparison must run against SURVIVORS only. Comparing
    against already-dropped labels would chain-drop a threat for resembling one that is no longer
    there."""
    llm = _StubLLM()
    threats = [_threat("t1", "alpha one"), _threat("t2", "alpha two"), _threat("t3", "beta three")]
    dupes = _semantic_duplicates(llm, "sess", 0, threats, None, ASSET, threshold=0.92)
    assert set(dupes) == {"t2"}, dupes  # t3 is orthogonal to the survivor and must be kept
    print("ok  _semantic_duplicates does not chain-drop")


def check_semantic_duplicates_against_priors() -> None:
    """A next-set round must not re-propose something the session already has."""
    llm = _StubLLM()
    priors = [_threat("p1", "alpha disclosure of records")]
    threats = [_threat("t1", "alpha leakage of records"), _threat("t2", "beta outage")]
    dupes = _semantic_duplicates(llm, "sess", 0, threats, priors, ASSET, threshold=0.92)
    assert set(dupes) == {"t1"}, dupes
    assert dupes["t1"]["duplicate_of_threat_id"] == "p1", dupes  # linked to the prior-round threat
    print("ok  _semantic_duplicates compares against prior rounds")


def check_semantic_scan_failure_is_not_fatal() -> None:
    """A failed scan must degrade to 'no duplicates', never lose the round's threats."""

    class _Boom:
        def embed(self, texts, kind=None):  # noqa: ARG002
            raise RuntimeError("embedding backend down")

    dupes = _semantic_duplicates(_Boom(), "sess", 0,
                                 [_threat("t1", "alpha one"), _threat("t2", "alpha two")],
                                 None, ASSET, threshold=0.92)
    assert dupes == {}, dupes
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


def check_next_set_outcome_additive_failure_is_retryable() -> None:
    """A non-slot exception from the additive find_threats call used to be swallowed inside
    run_next_set with no signal reaching outcome classification, so an already-empty pool plus a
    failed additive call read as `exhausted` ("nothing further exists", greys the client's retry
    button) — indistinguishable from a genuine "nothing new exists". cascade.py now forces
    top_up_failed=True whenever that call raised (run_next_set's `additive_failed`, threaded into
    _settle_next_set_conflict's `retryable` and the generated branch's top_up_failed). This pins
    the contract that fix depends on: the SAME made=0/pool_size=0 inputs must flip outcome once
    that flag is set."""
    made = variants = pool_size = 0
    requested = 5
    assert _next_set_outcome(requested, made, variants, pool_size, top_up_failed=False) == \
        NextSetOutcome.exhausted  # the bug: what a swallowed additive failure used to report
    assert _next_set_outcome(requested, made, variants, pool_size, top_up_failed=True) == \
        NextSetOutcome.partial_retryable  # the fix: additive_failed now forces this path
    print("ok  _next_set_outcome: additive-failure signal flips exhausted -> partial_retryable")


def check_regen_audit_detail_carries_partial_failure_reasons() -> None:
    """A multi-target regen used to report ONLY what succeeded: _reconcile_targeted_regen computed
    which excluded targets failed transiently vs. no longer qualify, but discarded both sets once
    it returned — the audit trail and the client SSE carried no trace of them on a PARTIAL batch
    (the all-fail batch already reported this correctly; only the partial case leaked it). Pins
    that _build_regen_audit_detail's DetailJSON now carries both sets when given, and stays an
    honest empty list — never null, so a consumer never needs a None-check — when it isn't."""
    import json

    detail = json.loads(_build_regen_audit_detail(
        {"t1", "t2", "t3"}, ["o1", "o2", "o3"], epoch=5, user_note=None,
        failed_threat_ids={"t2"}, rescored_threat_ids={"t3"}))
    assert detail["failed_threat_ids"] == ["t2"], detail
    assert detail["rescored_threat_ids"] == ["t3"], detail

    bare = json.loads(_build_regen_audit_detail({"t1"}, ["o1"], epoch=1, user_note=None))
    assert bare["failed_threat_ids"] == [], bare
    assert bare["rescored_threat_ids"] == [], bare
    print("ok  _build_regen_audit_detail carries partial-batch failed/rescored ids")


def check_present_status_cutoff_is_caller_controlled() -> None:
    """A board/register with several rows used to call treatment._stale_cutoff() FRESH inside
    _present_status for every row, so rows evaluated later in the loop judged against a slightly
    LATER instant than rows evaluated first — and the register additionally computed a second,
    independent cutoff for its SQL filter, so a row could pass the filter as RUNNING while
    rendering as ERROR in the same response. _present_status now takes the cutoff as an argument
    instead of computing it, making it a pure function of its four inputs — this pins that: the
    SAME (status, updated_at) pair must classify identically regardless of when the CALL happens,
    only the passed-in cutoff decides it."""
    from datetime import datetime, timedelta

    from app.api.treatment import _present_status
    from app.core.enums import StageStatus

    now = datetime(2026, 1, 1, 12, 0, 0)
    fresh_updated_at = now - timedelta(seconds=10)
    old_cutoff = now - timedelta(seconds=5)     # updated_at is BEFORE this -> stale
    new_cutoff = now - timedelta(seconds=20)    # updated_at is AFTER this -> fresh

    status, _err, reason = _present_status(str(StageStatus.RUNNING), None, fresh_updated_at, old_cutoff)
    assert status == str(StageStatus.ERROR), status  # stale relative to the caller's own cutoff
    assert reason == "timed_out", reason  # the projection-only reason, no other writer exists

    status2, _err2, reason2 = _present_status(str(StageStatus.RUNNING), None, fresh_updated_at, new_cutoff)
    assert status2 == str(StageStatus.RUNNING), status2  # fresh relative to a DIFFERENT cutoff
    assert reason2 is None, reason2

    # COMPLETE/ERROR rows are never subject to staleness at all, regardless of clock.
    status3, _err3, _reason3 = _present_status(str(StageStatus.COMPLETE), None, fresh_updated_at, old_cutoff)
    assert status3 == str(StageStatus.COMPLETE), status3
    print("ok  _present_status: staleness decided by the caller's cutoff, not an internal clock")


def demo() -> None:
    check_usable_proposal()
    check_semantic_duplicates_same_category()
    check_semantic_duplicates_identical_labels()
    check_semantic_duplicates_category_gate()
    check_clean_library_name()
    check_asset_name_stripping()
    check_semantic_duplicates_no_chain_drop()
    check_semantic_duplicates_against_priors()
    check_semantic_scan_failure_is_not_fatal()
    check_ranking_is_stable_and_meaningful()
    check_score_floor_still_reachable()
    check_next_set_outcome_additive_failure_is_retryable()
    check_regen_audit_detail_carries_partial_failure_reasons()
    check_present_status_cutoff_is_caller_controlled()
    print("\nall pipeline guards pass")


if __name__ == "__main__":
    demo()
