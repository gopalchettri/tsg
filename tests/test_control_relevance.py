"""Pins app/pipeline/control_relevance.py — the pure control-mapping policy.

No DB, no LLM, no fixtures: that is the whole point of the module, so a test here that needed
either would mean the policy had leaked back into the IO layer.

Every test below corresponds to a measured defect the module's docstrings record, and the names
say which: threat identity leading the query (1.9 -> 60.6 on a real scenario), ITOT labels
surviving a partially unrepresentable category set, the never-truncate-silently rule, the floor
being reachable only from above the backfill score, and domain preference being an ordering key
that can never admit a sub-cutoff control.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.pipeline.control_relevance import (
    ControlSelection,
    ItotApplicabilityContext,
    build_control_retrieval_query,
    resolve_scenario_itot_applicability,
    resolve_scenario_security_domains,
    select_applicable_controls,
    validate_control_mapping,
)

CREATED_AT = datetime(2026, 9, 25, 10, 30, tzinfo=UTC)
IT_ONLY = ItotApplicabilityContext(("IT",), (), "scenario")
NO_CONTEXT = ItotApplicabilityContext()

# code + name per ctm_scan_category id, the two columns grounding.resolve_asset_labels reads.
CATEGORIES = {
    1: ("IT", "Information Technology (IT)"),
    2: ("OT", "Operational Technology (OT)"),
    3: ("DATA_INFO", "Data and information"),
    4: (None, "Unlabelled prototype rig (OT)"),
    5: ("FAC", "FACILITIES"),
}


def query(**overrides) -> str | None:
    """build_control_retrieval_query with everything blank unless a test names it."""
    parts = {"threat_category": None, "threat_type": None, "threat_name": None,
             "threat_actors": None, "scenario_title": None, "scenario_statement": None,
             "risk_statement": None, "asset_name": None, "asset_technology": None,
             "involved_system_names": None, "max_chars": 2000}
    return build_control_retrieval_query(**{**parts, **overrides})


def match(control_id, score, *, itot=None, domain=None):
    """One (control row, score) pair as grounding.ground_control_queries returns them."""
    return ({"ControlLibraryID": control_id, "ITOT": itot, "Domain": domain}, score)


def select(matches, **overrides) -> ControlSelection:
    """select_applicable_controls with the shipped-default-shaped knobs, overridable per test."""
    args = {"scenario_id": "scn-1", "session_id": "ses-1", "matches": matches,
            "itot_context": NO_CONTEXT, "preferred_domains": (), "min_score": 60.0,
            "backfill_min_score": 40.0, "min_count": 5, "max_count": 10,
            "created_at": CREATED_AT}
    return select_applicable_controls(**{**args, **overrides})


# --- the retrieval query ----------------------------------------------------------------------

def test_threat_identity_leads_the_query_ahead_of_the_narrative():
    # The measured property: querying on narrative alone scored the correct control 1.9 and an
    # impact-shaped one 14.0. The threat must come FIRST, category before type before name.
    text = query(threat_category="Supply chain", threat_type="Tampering",
                 threat_name="Compromised OT supply chain or hardware",
                 scenario_title="Telemetry severed", scenario_statement="Availability degraded",
                 asset_name="Water treatment plant")
    assert text is not None
    assert text.startswith("Supply chain Tampering Compromised OT supply chain or hardware")
    assert text.index("Compromised OT") < text.index("Telemetry severed")
    assert text.index("Telemetry severed") < text.index("Availability degraded")
    # Asset context trails: the clip bites there first, where the loss costs least.
    assert text.index("Availability degraded") < text.index("Water treatment plant")


def test_actors_and_involved_systems_are_labelled_and_ordered_around_the_narrative():
    text = query(threat_name="Ransomware", threat_actors=["APT33", "Insider"],
                 scenario_title="Plant halt", involved_system_names=["Historian", "HMI"])
    assert text == ("Ransomware Threat actors: APT33, Insider Plant halt "
                    "Involved systems: Historian, HMI")


def test_blank_and_non_string_parts_are_skipped_without_leaving_gaps():
    text = query(threat_category="   ", threat_type=None, threat_name="Phishing",
                 threat_actors=["", "   "], scenario_title={"not": "a string"},
                 scenario_statement="Credential theft", involved_system_names=[])
    assert text == "Phishing Credential theft"
    assert "  " not in text


def test_query_clips_on_a_word_boundary_and_never_mid_token():
    text = query(threat_name="Compromised vendor firmware update channel", max_chars=22)
    assert text == "Compromised vendor"
    assert len(text) <= 22
    # A limit landing exactly on a space keeps the word before it rather than backing off again.
    assert query(threat_name="Compromised vendor firmware", max_chars=18) == "Compromised vendor"
    # max_chars <= 0 is "no ceiling", not "clip everything away".
    assert query(threat_name="Compromised vendor", max_chars=0) == "Compromised vendor"


def test_query_is_none_when_nothing_groundable_remains():
    assert query() is None
    # None means "do not ask" — never an empty query the reranker would still be paid for.
    assert query(threat_name="   ", scenario_statement=None) is None
    assert query(threat_actors=[], involved_system_names=["", "  "]) is None


# --- ITOT applicability ------------------------------------------------------------------------

def test_scenario_own_systems_win_over_the_session_context():
    context = resolve_scenario_itot_applicability(
        asset_category_id=2, involved_system_category_ids=[], session_category_ids=[1],
        category_code_by_id=CATEGORIES, vocabulary={"IT", "OT"})
    assert context == ItotApplicabilityContext(("OT",), (), "scenario")
    assert context.is_complete


def test_session_context_is_the_fallback_only_when_the_scenario_names_no_systems():
    context = resolve_scenario_itot_applicability(
        asset_category_id=None, involved_system_category_ids=None, session_category_ids=[1, 2],
        category_code_by_id=CATEGORIES, vocabulary={"IT", "OT"})
    assert context == ItotApplicabilityContext(("IT", "OT"), (), "session")
    empty = resolve_scenario_itot_applicability(
        asset_category_id=None, involved_system_category_ids=[], session_category_ids=[],
        category_code_by_id=CATEGORIES, vocabulary={"IT", "OT"})
    assert empty == ItotApplicabilityContext((), (), "none")
    assert not empty.is_complete


def test_a_partly_unrepresentable_category_set_keeps_the_labels_that_did_match():
    # THE REGRESSION PIN. grounding.resolve_asset_labels returns None here — no filter at all —
    # so {IT, DATA_INFO} silently stopped narrowing on IT too. The IT label must survive, and the
    # unmatched id must be reported instead of discarded.
    context = resolve_scenario_itot_applicability(
        asset_category_id=1, involved_system_category_ids=[3], session_category_ids=[2],
        category_code_by_id=CATEGORIES, vocabulary={"IT", "OT"})
    assert context.labels == ("IT",)
    assert context.unrepresented_category_ids == (3,)
    assert context.derived_from == "scenario"
    assert not context.is_complete


def test_parenthesised_marker_matches_but_a_substring_never_does():
    # Category 4 carries no code at all — only "(OT)" inside its name.
    by_marker = resolve_scenario_itot_applicability(
        asset_category_id=4, involved_system_category_ids=None, session_category_ids=None,
        category_code_by_id=CATEGORIES, vocabulary={"IT", "OT"})
    assert by_marker.labels == ("OT",)
    # "IT" appears inside "FACILITIES": a substring test labelled a facilities category as IT.
    by_substring = resolve_scenario_itot_applicability(
        asset_category_id=5, involved_system_category_ids=None, session_category_ids=None,
        category_code_by_id=CATEGORIES, vocabulary={"IT", "OT"})
    assert by_substring.labels == ()
    assert by_substring.unrepresented_category_ids == (5,)


def test_an_empty_vocabulary_leaves_everything_unrepresented_rather_than_guessing():
    context = resolve_scenario_itot_applicability(
        asset_category_id=1, involved_system_category_ids=[2], session_category_ids=None,
        category_code_by_id=CATEGORIES, vocabulary=set())
    assert context.labels == ()
    assert context.unrepresented_category_ids == (1, 2)


# --- domain preference selection ---------------------------------------------------------------

def test_security_domains_keep_the_best_scored_names_deterministically():
    scored = [("Access Control", 0.81), ("Network Security", 0.44), ("Access Control", 0.92),
              ("   ", 0.99), ("Physical Security", 0.62)]
    assert resolve_scenario_security_domains(scored, 2) == frozenset(
        {"Access Control", "Physical Security"})
    assert resolve_scenario_security_domains(scored, 0) == frozenset()
    assert resolve_scenario_security_domains([], 3) == frozenset()


# --- control selection -------------------------------------------------------------------------

def test_eight_controls_above_the_cutoff_yield_eight_rows():
    # THE NEVER-TRUNCATE PIN: the old rule sliced at top_k=5 and told nobody.
    selection = select([match(i, 90.0 - i) for i in range(8)], max_count=10)
    assert selection.mapped_count == 8
    assert selection.cleared_cutoff_count == 8
    assert selection.capped_count == 0
    assert selection.backfilled_count == 0
    assert [row["MapRank"] for row in selection.rows] == list(range(1, 9))


def test_forty_above_the_cutoff_are_capped_and_the_cap_is_recorded():
    selection = select([match(i, 99.0 - i * 0.5) for i in range(40)], max_count=5)
    assert selection.mapped_count == 5
    assert selection.cleared_cutoff_count == 40
    assert selection.capped_count == 35
    assert [row["ControlLibraryID"] for row in selection.rows] == [0, 1, 2, 3, 4]


def test_backfill_reaches_the_floor_only_from_candidates_above_the_backfill_score():
    matches = [match("a", 88.0), match("b", 61.0),         # cleared
               match("c", 55.0), match("d", 52.0), match("e", 45.0),   # eligible backfill
               match("f", 20.0)]                                        # under the floor
    selection = select(matches, min_count=5, backfill_min_score=40.0)
    assert [row["ControlLibraryID"] for row in selection.rows] == ["a", "b", "c", "d", "e"]
    assert selection.cleared_cutoff_count == 2
    assert selection.backfilled_count == 3
    assert selection.dropped_below_cutoff_count == 1
    assert [row["MapRank"] for row in selection.rows] == [1, 2, 3, 4, 5]


def test_nothing_above_the_backfill_floor_stays_short_rather_than_padding():
    selection = select([match("a", 88.0), match("b", 61.0), match("c", 20.0), match("d", 10.0)],
                       min_count=5, backfill_min_score=40.0)
    assert [row["ControlLibraryID"] for row in selection.rows] == ["a", "b"]
    assert selection.backfilled_count == 0
    assert selection.dropped_below_cutoff_count == 2


def test_an_itot_incompatible_high_scorer_never_outranks_a_compatible_lower_one():
    selection = select([match("ot-high", 95.0, itot="OT"), match("it-low", 61.0, itot="IT"),
                        match("unlabelled", 70.0)],
                       itot_context=IT_ONLY, max_count=10)
    # Demoted, never dropped: the OT row is still mapped, just last.
    assert [row["ControlLibraryID"] for row in selection.rows] == ["unlabelled", "it-low", "ot-high"]
    assert selection.itot_demoted_count == 1
    # With no context there is nothing to be incompatible with, so score order alone governs.
    open_context = select([match("ot-high", 95.0, itot="OT"), match("it-low", 61.0, itot="IT")])
    assert [row["ControlLibraryID"] for row in open_context.rows] == ["ot-high", "it-low"]
    assert open_context.itot_demoted_count == 0


def test_a_preferred_domain_breaks_a_tie_and_never_outranks_a_better_score():
    """THE F2 REGRESSION PIN. `not domain_preferred` used to sit BEFORE `-score` in the cleared-
    controls sort key, so any control in a preferred domain beat a materially better-scoring one —
    on a 97-value un-normalized free-text vocabulary this repo documents as "reported as-is, never
    joined on". Domain must break ties and nothing more."""
    matches = [match("net", 72.0, domain="Network Security"),
               match("acl", 65.0, domain="Access Control"),
               match("acl-weak", 30.0, domain="Access Control")]
    preferred = select(matches, preferred_domains={"Access Control"}, min_count=2,
                       backfill_min_score=0.0)
    # 72.0 still leads 65.0: a 7-point better match is not overturned by a domain nudge.
    assert [row["ControlLibraryID"] for row in preferred.rows] == ["net", "acl"]
    # THE INVARIANT: domain is a sort key only. Even with a zero backfill floor and a preferred
    # domain, a control that did not clear the cutoff cannot be admitted while the floor is met.
    assert "acl-weak" not in [row["ControlLibraryID"] for row in preferred.rows]
    # And on an EXACT tie it does decide, which is the whole job it is left with.
    tied = [match("plain", 70.0, domain="Network Security"),
            match("pref", 70.0, domain="Access Control")]
    assert [row["ControlLibraryID"] for row in
            select(tied, preferred_domains={"Access Control"}, min_count=2).rows] == ["pref",
                                                                                     "plain"]


def test_itot_compatibility_still_outranks_score_even_though_domain_no_longer_does():
    """The other half of F2: moving domain after score must NOT move ITOT after it. A control
    compatible with the scenario's IT/OT nature answers the question asked; an incompatible one
    answers a different question, so it ranks behind whatever either scored."""
    selection = select([match("ot-best", 99.0, itot="OT", domain="Access Control"),
                        match("it-worst", 61.0, itot="IT")],
                       itot_context=IT_ONLY, preferred_domains={"Access Control"}, min_count=2)
    assert [row["ControlLibraryID"] for row in selection.rows] == ["it-worst", "ot-best"]


def test_duplicate_control_ids_are_deduped_keeping_the_best_score():
    # The map PK is (ScenarioID, ControlLibraryID): one duplicate is an IntegrityError that the
    # caller's except swallows, losing every control for the scenario.
    selection = select([match("a", 70.0), match("a", 85.0), match("b", 80.0)], min_count=1)
    assert [(row["ControlLibraryID"], row["Score"]) for row in selection.rows] == [
        ("a", 85.0), ("b", 80.0)]
    assert [row["MapRank"] for row in selection.rows] == [1, 2]


def test_rows_carry_the_passed_timestamp_and_the_full_map_row_shape():
    selection = select([match(7, 80.0)], min_count=1)
    assert selection.rows == [{"ScenarioID": "scn-1", "ControlLibraryID": 7, "SessionID": "ses-1",
                               "Score": 80.0, "MapRank": 1, "CreatedAt": CREATED_AT}]


# --- pre-persist validation --------------------------------------------------------------------

def test_a_row_outside_the_candidate_set_raises():
    rows = select([match("a", 80.0)], min_count=1).rows
    with pytest.raises(ValueError, match="not among"):
        validate_control_mapping(rows=rows, candidate_ids={"b", "c"}, itot_context=NO_CONTEXT,
                                 backfill_min_score=40.0, itot_by_control_id=None,
                                 expected_count=None)


def test_a_duplicate_control_id_raises():
    rows = [{"ControlLibraryID": "a", "Score": 80.0, "MapRank": 1},
            {"ControlLibraryID": "a", "Score": 70.0, "MapRank": 2}]
    with pytest.raises(ValueError, match="twice"):
        validate_control_mapping(rows=rows, candidate_ids={"a"}, itot_context=NO_CONTEXT,
                                 backfill_min_score=40.0, itot_by_control_id=None,
                                 expected_count=None)


def test_a_non_contiguous_map_rank_raises():
    rows = [{"ControlLibraryID": "a", "Score": 80.0, "MapRank": 1},
            {"ControlLibraryID": "b", "Score": 70.0, "MapRank": 3}]
    with pytest.raises(ValueError, match="MapRank"):
        validate_control_mapping(rows=rows, candidate_ids={"a", "b"}, itot_context=NO_CONTEXT,
                                 backfill_min_score=40.0, itot_by_control_id=None,
                                 expected_count=None)


def test_advisories_are_returned_not_raised():
    rows = select([match("a", 80.0), match("b", 35.0, itot="OT")],
                  itot_context=IT_ONLY, min_count=2, backfill_min_score=30.0).rows
    warnings = validate_control_mapping(
        rows=rows, candidate_ids={"a", "b"}, itot_context=IT_ONLY, backfill_min_score=40.0,
        itot_by_control_id={"a": "IT", "b": "OT"}, expected_count=5)
    assert any("below the backfill floor" in w for w in warnings)
    assert any("outside this scenario's ITOT context" in w for w in warnings)
    assert any("fewer than the 5 expected" in w for w in warnings)


def test_a_clean_batch_produces_no_warnings():
    rows = select([match("a", 80.0), match("b", 75.0)], itot_context=IT_ONLY, min_count=2).rows
    assert validate_control_mapping(rows=rows, candidate_ids={"a", "b"}, itot_context=IT_ONLY,
                                    backfill_min_score=40.0,
                                    itot_by_control_id={"a": "IT", "b": None},
                                    expected_count=2) == []


def test_the_advisory_facts_must_be_stated_explicitly():
    """Omitting them is a TypeError, not a silent skip.

    Both gate an advisory, so a default would let a caller skip two of the three checks and still
    receive [] — indistinguishable from a batch that was checked and found clean. Passing None is
    allowed; passing nothing is not.
    """
    rows = [{"ControlLibraryID": "a", "MapRank": 1, "Score": 90.0}]
    with pytest.raises(TypeError):
        validate_control_mapping(rows=rows, candidate_ids={"a"}, itot_context=NO_CONTEXT,
                                 backfill_min_score=40.0)      # type: ignore[call-arg]
    assert validate_control_mapping(rows=rows, candidate_ids={"a"}, itot_context=NO_CONTEXT,
                                    backfill_min_score=40.0, itot_by_control_id=None,
                                    expected_count=None) == []
