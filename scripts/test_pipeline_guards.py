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

import ast
import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import get_settings
from app.core.enums import DuplicateReason
from app.pipeline import accept, scoping, tasks
from app.pipeline.cascade import NextSetOutcome, _build_regen_audit_detail, _next_set_outcome
from app.pipeline.tasks import (
    _scrub_model_output,
    _semantic_duplicates,
    _usable_proposal,
    asset_agnostic_name,
    clean_library_name,
)

ASSET = "Widget Control System"


class _StubLLM:
    """embed() picks a unit vector from the label's FIRST word, so two different label strings
    sharing a first word are exactly parallel (cosine 1.0) and anything else is orthogonal.
    Lets each case below control similarity outright instead of depending on a real model."""

    # "trapx" sits at cosine 0.969 to "alpha" — the measured cross-class similarity of
    # 'Unauthorized disclosure of X' vs 'Unauthorized modification of X' on the live embedder.
    _AXES = {"alpha": [1.0, 0.0, 0.0], "beta": [0.0, 1.0, 0.0], "gamma": [0.0, 0.0, 1.0],
             "trapx": [0.969, 0.246779, 0.0]}

    def embed(self, texts, kind=None):
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
    assert dupes["t2"]["reason"] == DuplicateReason.semantic_similarity, dupes
    print("ok  _semantic_duplicates drops a same-meaning threat")


def check_semantic_duplicates_identical_labels() -> None:
    """THE regression this file exists for. The old scan guarded self-comparison by VALUE
    (`other == label`), so two DISTINCT threats with byte-identical labels — cosine 1.0, the
    strongest signal available — were the one pair it silently skipped."""
    llm = _StubLLM()
    threats = [_threat("t1", "alpha disclosure"), _threat("t2", "alpha disclosure")]
    dupes = _semantic_duplicates(llm, "sess", 0, threats, None, ASSET, threshold=0.92)
    assert set(dupes) == {"t2"}, dupes
    # The audit pointer must name the SURVIVOR — a label-keyed last-writer-wins map used to
    # send an identical-label duplicate's DuplicateOfThreatID at itself (t2), a self-reference
    # to a threat that was never inserted.
    assert dupes["t2"]["duplicate_of_threat_id"] == "t1", dupes
    print("ok  _semantic_duplicates catches byte-identical labels")


def check_semantic_duplicates_category_gate() -> None:
    """Every pair is judged at the single 0.98 bar. Two contracts pinned at once: the measured
    0.969 disclosure/modification trap (two REAL threats, different impact classes) must survive,
    while a byte-identical label the model merely relabelled into another category must be dropped
    — recorded with the single unified semantic_similarity reason (category no longer splits it)."""
    llm = _StubLLM()
    # cosine(alpha, trapx) = 0.969 -> below the 0.98 bar -> both survive.
    threats = [_threat("t1", "alpha disclosure", category="Information Disclosure"),
               _threat("t2", "trapx modification", category="Tampering")]
    dupes = _semantic_duplicates(llm, "sess", 0, threats, None, ASSET, threshold=0.92)
    assert dupes == {}, dupes
    # cosine 1.0 (same first word) across categories -> at/above 0.98 -> relabel caught.
    threats = [_threat("t1", "alpha disclosure", category="Information Disclosure"),
               _threat("t2", "alpha disclosure", category="Tampering")]
    dupes = _semantic_duplicates(llm, "sess", 0, threats, None, ASSET, threshold=0.92)
    assert set(dupes) == {"t2"}, dupes
    assert dupes["t2"]["reason"] == DuplicateReason.semantic_similarity, dupes
    print("ok  _semantic_duplicates cross-category ceiling: trap survives, relabel caught")


def check_semantic_duplicates_category_never_lowers_bar() -> None:
    """THE fix this check pins: a shared STRIDE category must not discount the drop bar. The same
    0.969 pair as above, now BOTH in one category — under the old category-gated design they were
    judged at the session threshold (0.92) and silently merged as semantic_same_category, which
    collapsed a real asset run to 6 surviving threats. Category-blind, both must survive."""
    llm = _StubLLM()
    threats = [_threat("t1", "alpha disclosure", category="Information Disclosure"),
               _threat("t2", "trapx modification", category="Information Disclosure")]
    dupes = _semantic_duplicates(llm, "sess", 0, threats, None, ASSET, threshold=0.92)
    assert dupes == {}, dupes
    print("ok  _semantic_duplicates same-category pair below the meaning bar survives")


def check_scrub_model_output() -> None:
    """Gap-8 guard: model output is scrubbed through _SECRET_PATTERNS before persistence, with
    structure intact. If this fails, /results, the Excel export and the audit trail all serve
    whatever the model echoed back — hostnames, labeled creds — verbatim and forever."""
    scenario = {
        "scenario_title": "Telemetry tampering via historian access",
        "scenario_statement": "Reach hist-pgs-01.dewa.local with db_password=Hunter2",
        "other_plausible_entry_points": ["via ops@example.com phishing", "via USB"],
        "coverage": {"depth": 2},  # non-string scalar must pass through untouched
    }
    out = _scrub_model_output(dict(scenario), "sess", "t1")
    assert set(out) == set(scenario), out                      # keys preserved
    assert "hist-pgs-01.dewa.local" not in out["scenario_statement"], out
    assert "db_password" not in out["scenario_statement"], out
    assert "[REDACTED]" in out["scenario_statement"], out
    assert out["scenario_title"] == scenario["scenario_title"], out  # clean text untouched
    assert len(out["other_plausible_entry_points"]) == 2, out        # list shape preserved
    assert "ops@example.com" not in out["other_plausible_entry_points"][0], out
    assert out["coverage"] == {"depth": 2}, out
    print("ok  _scrub_model_output masks secrets, keeps structure")


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
        def embed(self, texts, kind=None):
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

    # Stored-ERROR branch: a NULL ErrorReason (rows that failed before the column existed)
    # reads as the historical catch-all, never as None — clients switch on `reason`.
    status4, _msg4, reason4 = _present_status(str(StageStatus.ERROR), "boom", fresh_updated_at,
                                              old_cutoff, None)
    assert status4 == str(StageStatus.ERROR) and reason4 == "generation_failed", (status4, reason4)
    print("ok  _present_status: staleness decided by the caller's cutoff, not an internal clock")


def check_scenario_receipts_carry_their_scenario_id() -> None:
    """Every scenario-path LLM call stamps Prompt_Log.CorrelationID with the ScopedThreatID.

    Without it the receipt (exact prompt + raw reply, written by _ask_ai even when parsing fails)
    cannot be joined to the scenario it produced, so "why does this card cite CVE-X?" is
    unanswerable. Three ways this regresses, all SILENT — nothing raises, the rows just go NULL
    or, worse, carry someone else's id:

      1. an _ask_ai call inside _generate_one_scenario dropping correlation_id — half the receipts
         go NULL while the fix still looks applied;
      2. a _generate_one_scenario call site not passing one — same, per path;
      3. write_variant_scenarios minting scoped_id AFTER the call again (it did, before 2026-08).
         Receipts then carry the PREVIOUS card's id, which is worse than NULL because a wrong id
         reads as an answer.

    Source-introspected rather than executed: this is a wiring invariant, and running it for real
    needs an LLM and a database. Same approach as scripts/test_promotion_retry_flow.py.
    """
    src = inspect.getsource(tasks)
    tree = ast.parse(src)
    fns = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}

    def calls_to(node, name):
        return [c for c in ast.walk(node) if isinstance(c, ast.Call)
                and isinstance(c.func, ast.Name) and c.func.id == name]

    gen = fns["_generate_one_scenario"]
    kwonly = [a.arg for a in gen.args.kwonlyargs]
    assert "correlation_id" in kwonly, (
        "_generate_one_scenario lost its keyword-only correlation_id parameter")

    asks = calls_to(gen, "_ask_ai")
    assert len(asks) == 2, f"expected 2 _ask_ai calls (attempt + repair), found {len(asks)}"
    for call in asks:
        assert any(k.arg == "correlation_id" for k in call.keywords), (
            f"_ask_ai at tasks.py line ~{call.lineno} is not stamping correlation_id — its "
            "Prompt_Log rows will be orphaned")

    # 3 sites: the batch generator's sequential and concurrent branches, plus the variant
    # path. Every one must stamp correlation_id as a LITERAL keyword — passing it inside a
    # **kwargs dict would still work at runtime but would make this check unenforceable.
    sites = calls_to(tree, "_generate_one_scenario")
    assert len(sites) == 3, (
        f"expected 3 call sites (batch sequential + batch concurrent + variant), "
        f"found {len(sites)}")
    for call in sites:
        assert any(k.arg == "correlation_id" for k in call.keywords), (
            f"_generate_one_scenario call at tasks.py line ~{call.lineno} passes no "
            "correlation_id — that whole path's receipts go NULL")

    variant = fns["write_variant_scenarios"]
    mint = min(n.lineno for n in ast.walk(variant) if isinstance(n, ast.Assign)
               and any(isinstance(t, ast.Name) and t.id == "scoped_id" for t in n.targets))
    call = min(c.lineno for c in calls_to(variant, "_generate_one_scenario"))
    assert mint < call, (
        f"write_variant_scenarios mints scoped_id at line ~{mint}, AFTER the generation call at "
        f"~{call}: receipts would be stamped with the previous card's id")

    print("scenario receipts: correlation_id wired on both paths; variant id minted pre-call")


def check_catalogued_threats_do_not_requeue_curation_cards() -> None:
    """A threat already linked to a library entry must never queue a pending curation card.

    The cause is a SPLIT decision. `_decide_candidate_fate` skips triage when the threat already
    carries a ThreatCatalogueID, so `verdict` keeps its default `review` — and the card-insert
    block then reads that verdict without re-checking why it holds. Any re-run of promotion (the
    reaper's retry sweep today; per-accept promotion once scenarios decide independently) therefore
    re-queued threats already in the library, giving curators duplicate work that approving cannot
    resolve.

    Pinned by source because reproducing it behaviourally needs a live catalogue, embeddings and a
    full promotion run — same approach as scripts/test_promotion_retry_flow.py.

    NOTE: weaker than a behavioural test. It proves the conjunct is still present, not that it
    still has the intended effect. Replace it if seeding a real promotion run ever gets cheap."""
    tree = ast.parse(inspect.getsource(accept._add_unverified_threats_to_library))

    # Locate every `if` whose body inserts a candidate card, then assert its condition consults
    # ThreatCatalogueID — i.e. a catalogued threat cannot reach the insert at all.
    card_guards = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        body = ast.dump(ast.Module(body=node.body, type_ignores=[]))
        if "CandidateKind" in body and "ProposedName" in body:
            card_guards.append(ast.dump(node.test))
    assert card_guards, "no candidate-card insert found in _add_unverified_threats_to_library"
    for cond in card_guards:
        assert "ThreatCatalogueID" in cond, (
            "the candidate-card insert no longer checks ThreatCatalogueID — a threat already in "
            "the library will be re-queued for curation on every promotion re-run")
    print("promotion: catalogued threats cannot re-queue a curation card")


#: The only function allowed to write a scenario's decision columns.
_DECISION_WRITER = "decide_scenarios"
_DECISION_COLUMNS = ("Accepted", "RejectedAt", "RejectedBy")


def check_only_one_function_writes_a_scenario_decision() -> None:
    """Accepted / RejectedAt / RejectedBy may be assigned ONLY inside dal.decide_scenarios.

    This is what makes the single-writer design a fact rather than a convention. decide_scenarios
    does three things together — applies the opposite decision's exclusion predicate, writes the
    row, and writes one Scenario_Audit ledger entry per scenario. A second writer anywhere gets
    none of them, and the failure is silent: the decision lands, the audit trail quietly does not,
    and accept/reject stop being mutually exclusive until CK_ScenarioOutput_DecisionExclusive
    surfaces as a 500 somewhere unrelated.

    Both are regressions this repo has already had in other forms, which is why the rule is
    enforced by parsing rather than by a comment asking nicely.
    """
    import ast
    from pathlib import Path

    app_dir = Path(__file__).resolve().parents[1] / "app"
    offenders: list[str] = []
    for path in sorted(app_dir.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        # Map every node to the function enclosing it, so a hit can name its writer.
        enclosing: dict[ast.AST, str] = {}
        for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]:
            for child in ast.walk(fn):
                enclosing.setdefault(child, fn.name)
        for node in ast.walk(tree):
            # `.values(Accepted=1, ...)` — the SQLAlchemy UPDATE spelling
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "values"):
                continue
            named = {kw.arg for kw in node.keywords if kw.arg in _DECISION_COLUMNS}
            if named and enclosing.get(node) != _DECISION_WRITER:
                offenders.append(
                    f"{path.relative_to(app_dir.parent)}: {sorted(named)} written in "
                    f"{enclosing.get(node) or '<module level>'}()")
    assert not offenders, (
        "a scenario decision is written outside dal.decide_scenarios:\n  "
        + "\n  ".join(offenders)
        + f"\nRoute the write through {_DECISION_WRITER} instead — it is what pairs the decision "
        "with its per-scenario audit row and with the opposite decision's exclusion predicate.")

    # The guard is worthless if the writer it whitelists has been renamed or gutted.
    import inspect

    from app.db import dal
    writer = getattr(dal, _DECISION_WRITER, None)
    assert writer is not None, f"dal.{_DECISION_WRITER} is gone — this guard now protects nothing"
    body = inspect.getsource(writer)
    assert all(c in body for c in _DECISION_COLUMNS), (
        f"dal.{_DECISION_WRITER} no longer writes {_DECISION_COLUMNS} — either it was split "
        "(update this guard's whitelist) or the decision write moved somewhere unguarded")
    print("decisions: only dal.decide_scenarios writes Accepted/RejectedAt/RejectedBy")


#: Every function that decides scenarios must pass the review gate first.
_GATE_CHECK = "_ensure_session_ready_to_accept"


def check_every_decision_route_passes_the_review_gate() -> None:
    """Any function calling dal.decide_scenarios must also call _ensure_session_ready_to_accept.

    The gate refuses a decision on a session that is cancelled, still generating, or otherwise not
    at a review barrier. A route that skips it writes a decision onto a session that was never
    offered for review, and nothing looks broken afterwards.

    NOT an ownership check: any authenticated colleague in the entity may decide, by deliberate
    decision (see sessions.py::get_authorized_session). Who did it is recorded per scenario.
    """
    import ast
    from pathlib import Path

    app_dir = Path(__file__).resolve().parents[1] / "app"
    offenders: list[str] = []
    for path in sorted(app_dir.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for fn in [n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]:
            called = {c.func.attr for c in ast.walk(fn)
                    if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)}
            called |= {c.func.id for c in ast.walk(fn)
                    if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
            if _DECISION_WRITER in called and _GATE_CHECK not in called:
                offenders.append(f"{path.relative_to(app_dir.parent)}: {fn.name}()")
    assert not offenders, (
        f"a function decides scenarios without calling {_GATE_CHECK} first:\n  "
        + "\n  ".join(offenders)
        + "\nA decision must not land on a session that was never offered for review.")
    print("decisions: every decision route passes the review gate first")


def demo() -> None:
    check_only_one_function_writes_a_scenario_decision()
    check_every_decision_route_passes_the_review_gate()
    check_scenario_receipts_carry_their_scenario_id()
    check_catalogued_threats_do_not_requeue_curation_cards()
    check_usable_proposal()
    check_semantic_duplicates_same_category()
    check_semantic_duplicates_identical_labels()
    check_semantic_duplicates_category_gate()
    check_semantic_duplicates_category_never_lowers_bar()
    check_scrub_model_output()
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
