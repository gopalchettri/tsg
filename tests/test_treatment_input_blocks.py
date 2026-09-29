"""Unit pins for treatment_input.py — the snapshot builder's pieces, one rule at a time.

WHY THIS FILE EXISTS. Every rule below was previously reachable ONLY through the whole
173-line build_treatment_input: a check on the rating arithmetic had to invent a session row, a
scenario row and a fake Session, call the builder, and dig the answer out of a nested dict. The
arithmetic is pure, so it is tested as arithmetic here. The existing whole-builder tests
(test_treatment_risk_calibration.py, test_stage_cache_evidence_dropped_controls.py) still pin the
ASSEMBLY — key order, warning order, the round trip through regenerate — which is the orchestrator's
own job and cannot be checked piecewise.

Only read_library_controls_for_snapshot takes a Session, and only a fake one: the rule under test
there is what the function does when the read FAILS versus when it legitimately returns nothing.
"""
from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace

import pytest

from app.core.enums import ContentSource
from app.db import dal
from app.pipeline import treatment_input as ti


# ---------------------------------------------------------------------------
# The three register-consistency advisories (pure arithmetic — no DB, no rows)
# ---------------------------------------------------------------------------
def _consistency(**risk_input) -> list[str]:
    return ti.collect_register_consistency_warnings(
        risk_input, ti._assessment_window(risk_input))


def test_a_rating_that_reconciles_draws_no_warning() -> None:
    assert _consistency(likelihood_rating=4, impact_rating=5, final_risk_rating=20) == []


def test_a_rating_that_contradicts_the_product_is_named_with_its_arithmetic() -> None:
    """The reviewer must be able to check the claim, so the warning shows all four numbers."""
    (warning,) = _consistency(likelihood_rating=4, impact_rating=5, final_risk_rating=18)
    assert warning == ("final_risk_rating 18 does not equal likelihood x impact (4x5=20); "
                    "register values taken as-is")


@pytest.mark.parametrize("likelihood, impact, final", [
    ("4.5", "4.7", "21.15"),        # 2 dp, exact
    ("3.3", "3.3", "10.89"),        # binary float would make this 10.889999999999999
    ("2.4567", "4.4321", "10.89"),  # 8-dp product rounded to the register's own 2 dp
])
def test_a_decimal_register_is_compared_at_the_final_ratings_own_scale(
        likelihood, impact, final) -> None:
    """Two 4-dp scores multiply to up to 8 dp, which final_risk_rating cannot express — an exact
    != would flag every correctly-rounded decimal register."""
    assert _consistency(likelihood_rating=likelihood, impact_rating=impact,
                        final_risk_rating=final) == []


@pytest.mark.parametrize("final", ["1E+1", "0E+5", "0E+1000000"])
def test_the_same_value_is_compared_the_same_however_it_is_spelled(final) -> None:
    """pydantic keeps a string Decimal's exponent. '1E+1' once compared 2.4x4.4 to the nearest
    TEN and hid the mismatch; '0E+1000000' made quantize() raise, which was a 500."""
    assert _consistency(likelihood_rating="2.4", impact_rating="4.4",
                        final_risk_rating=final) != []


def test_an_eleven_digit_register_is_not_rounded_before_the_comparison() -> None:
    """MAX_PREC: the default 28-digit context rounded two 11-digit scores' 30-digit product
    before comparing, so an exact register was reported as inconsistent."""
    big = "12345.6789"
    assert _consistency(likelihood_rating=big, impact_rating=big,
                        final_risk_rating=str(Decimal(big) * Decimal(big))) == []


def test_one_missing_score_disables_the_arithmetic_without_claiming_uncalibrated() -> None:
    """A partly-filled register cannot be multiplied, but risk_level is present, so the plan IS
    calibrated — neither warning applies. Deliberately still silent about the missing PAIR: the
    prompt branches on its presence ("If likelihood_rating and impact_rating both exist"), so
    warning here would put an advisory on supported input."""
    assert _consistency(likelihood_rating=4, final_risk_rating=20, risk_level="High") == []


_UNCALIBRATED = ["risk_assessment carries no risk level and no final risk rating — "
                 "the plan is NOT risk-calibrated"]


def test_no_scores_and_no_level_is_flagged_as_not_risk_calibrated() -> None:
    assert _consistency(existing_controls=[]) == _UNCALIBRATED


def test_junk_scores_fold_into_the_no_scores_advisory_rather_than_raising() -> None:
    """_dec returns None on a malformed legacy blob deliberately: inside a POST, a branch is
    cheaper than an exception."""
    assert _consistency(likelihood_rating="not a number", impact_rating=None,
                        final_risk_rating="") == _UNCALIBRATED


@pytest.mark.parametrize("risk_input", [
    {"likelihood_rating": 4},                              # one surviving score, nothing to cite
    {"impact_rating": 5, "risk_level": ""},                # blank level is no level
    {"likelihood_rating": 4, "impact_rating": 5},          # a product, but no final and no level
])
def test_a_partly_scored_register_with_nothing_to_cite_is_still_flagged(risk_input) -> None:
    """The guard used to require ALL FOUR values to be absent, so one surviving likelihood silenced
    it — and that plan has no urgency signal at all: the prompt's ladder has no risk_level to climb,
    its rule 8 has no final_risk_rating to quote, and treatment._risk_alignment_warnings stands down
    the moment risk_level is None. An uncalibrated plan with zero trace. The approved payload made
    every one of these fields optional, so this shape is ordinary input now, not a legacy row."""
    assert _consistency(**risk_input) == _UNCALIBRATED


def test_a_final_rating_alone_is_enough_to_count_as_calibrated() -> None:
    """Rule 8 cites final_risk_rating verbatim, so there IS something to calibrate against."""
    assert _consistency(final_risk_rating=20) == []


def test_a_window_that_already_ended_is_flagged_at_plan_creation() -> None:
    (warning,) = _consistency(mitigation_start_date="2020-01-01",
                            mitigation_end_date="2020-03-01", risk_level="High")
    assert warning == "mitigation window ended 2020-03-01 — already in the past at plan creation"


def test_a_window_still_open_today_is_not_flagged() -> None:
    today = dal.now().date().isoformat()
    assert _consistency(mitigation_start_date=today, mitigation_end_date=today,
                        risk_level="High") == []


def test_an_unparseable_window_disables_the_check_instead_of_guessing() -> None:
    assert _consistency(mitigation_start_date="nonsense", mitigation_end_date="also nonsense",
                        risk_level="High") == []


# ---------------------------------------------------------------------------
# The assessment window: stored key names, and the INCLUSIVE day count
# ---------------------------------------------------------------------------
def test_the_window_is_stored_under_timeline_keys_and_counts_inclusively() -> None:
    """STORED keys stay timeline_* while the REQUEST fields are mitigation_*: the snapshot is a
    persisted record format, so renaming the request must not reshape every stored row. And
    1 Oct..31 Dec is 92 days of work — a same-day window is 1 day, not 0."""
    assert ti._assessment_window({"mitigation_start_date": "2026-10-01",
                                "mitigation_end_date": "2026-12-31"}) == {
        "timeline_start_date": "2026-10-01", "timeline_end_date": "2026-12-31",
        "total_days": 92}
    assert ti._assessment_window({"mitigation_start_date": "2026-10-01",
                                "mitigation_end_date": "2026-10-01"})["total_days"] == 1


@pytest.mark.parametrize("risk_input", [
    {},
    {"mitigation_start_date": "2026-10-01"},                        # half a pair
    {"mitigation_start_date": "x", "mitigation_end_date": "2026-10-01"},   # unparseable
])
def test_no_window_is_no_window(risk_input) -> None:
    assert ti._assessment_window(risk_input) is None


# ---------------------------------------------------------------------------
# Rating normalization on the way back OUT (regenerate re-reads what we store)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("stored, expected", [
    ("20", 20), (20, 20), (20.0, 20), ("20.00", 20), ("2E+1", 20),   # int, never 20.0
    ("4.5", 4.5), (4.5, 4.5),
    (None, None), ("", None), ("nonsense", None), ("NaN", None), ("Infinity", None),
])
def test_a_rating_is_stored_as_an_int_whenever_it_is_integral(stored, expected) -> None:
    """Prompt rule 6 orders the model to cite final_risk_rating VERBATIM, so storing 20.0 where
    every previous row stored 20 would silently reword every plan an integer register generates."""
    block = ti.build_risk_assessment_block({"final_risk_rating": stored}, None)
    assert block["final_risk_rating"] == expected
    assert type(block["final_risk_rating"]) is type(expected)


def test_storing_the_ratings_is_idempotent_so_regenerate_cannot_drift() -> None:
    """regenerate rebuilds risk_input from the stored block WITHOUT re-entering the schema, so a
    second pass over our own output must produce the same bytes."""
    first = ti.build_risk_assessment_block(
        {"likelihood_rating": "4.50", "impact_rating": 4, "final_risk_rating": "18.0"}, None)
    assert ti.build_risk_assessment_block(first, None) == first


# ---------------------------------------------------------------------------
# The library-controls read: TWO DISTINCT warnings, and the lookup_failed signal
# ---------------------------------------------------------------------------
class _Sess:
    """A Session stand-in: `fail` makes the library read raise, otherwise it returns no rows."""

    def __init__(self, fail: bool = False):
        self.fail, self.rolled_back = fail, False

    def rollback(self):
        self.rolled_back = True

    def execute(self, *a, **k):
        if self.fail:
            raise RuntimeError("db down")
        return SimpleNamespace(mappings=lambda: SimpleNamespace(all=lambda: []))


_SCENARIO = {"ScenarioID": "s-1", "ScenarioSource": "AI"}


def test_a_failed_lookup_says_so_and_reports_that_it_failed() -> None:
    """A hard lookup failure must never masquerade as an empty map: "no controls exist for this
    scenario" is a fact about the scenario, "we could not look" is a fact about the database."""
    sess = _Sess(fail=True)
    controls, warnings, lookup_failed = ti.read_library_controls_for_snapshot(sess, _SCENARIO)
    assert (controls, lookup_failed, sess.rolled_back) == ([], True, True)
    assert warnings == ["library control lookup failed — plan generated without mapped controls"]


def test_a_genuinely_empty_map_gets_the_other_warning_and_did_not_fail() -> None:
    controls, warnings, lookup_failed = ti.read_library_controls_for_snapshot(_Sess(), _SCENARIO)
    assert (controls, lookup_failed) == ([], False)
    assert warnings == ["no library-mapped controls for this scenario (Step-4 map is empty)"]


def test_a_short_ai_map_reports_the_floor_the_top_up_could_not_reach(monkeypatch) -> None:
    """The top-up fails OPEN, so an AI scenario can arrive short — say so, or 2-of-5 reads like
    a full plan."""
    monkeypatch.setattr(ti, "_library_controls",
                        lambda sess, sid: ([{"control_code": "C1"}, {"control_code": "C2"}], []))
    # The floor is PINNED to a distinct 9 on the LIVE setting control_map_min_count, not read back
    # out of get_settings(). Reading it back made this test pass whichever count the code used: the
    # deprecated remediation_control_min_count it was meant to catch defaulted to 5 as well, so the
    # regression was invisible. That field is now deleted; its env spelling still supplies this one.
    monkeypatch.setattr(ti, "get_settings", lambda: SimpleNamespace(
        control_map_min_count=9, remediation_control_top_up_enabled=True))
    _, warnings, lookup_failed = ti.read_library_controls_for_snapshot(_Sess(), _SCENARIO)
    assert lookup_failed is False
    assert warnings == ["only 2 of the minimum 9 library-mapped controls — top-up could "
                        "not reach the floor"]


def test_a_short_ai_map_is_reported_even_when_the_top_up_is_switched_off(monkeypatch) -> None:
    """Being under the floor is ARITHMETIC about this scenario's map; whether the top-up feature is
    switched on is CONFIGURATION. The gate used to ask the second question, so a deployment that
    turned the top-up off lost the signal entirely and a 2-of-9 map generated a plan that read
    exactly like a full one. The flag decides the WORDING instead — a disabled top-up must not be
    blamed for not reaching a floor nobody asked it to reach."""
    monkeypatch.setattr(ti, "_library_controls",
                        lambda sess, sid: ([{"control_code": "C1"}, {"control_code": "C2"}], []))
    monkeypatch.setattr(ti, "get_settings", lambda: SimpleNamespace(
        control_map_min_count=9, remediation_control_top_up_enabled=False))
    _, warnings, _ = ti.read_library_controls_for_snapshot(_Sess(), _SCENARIO)
    assert warnings == ["only 2 of the minimum 9 library-mapped controls — control top-up is "
                        "switched off for this deployment"]


def test_a_manual_scenario_is_never_measured_against_the_top_up_floor(monkeypatch) -> None:
    """The top-up never touches a manual scenario, so there is no floor it failed to reach."""
    monkeypatch.setattr(ti, "_library_controls", lambda sess, sid: ([{"control_code": "C1"}], []))
    _, warnings, _ = ti.read_library_controls_for_snapshot(
        _Sess(), {"ScenarioID": "s-1", "ScenarioSource": str(ContentSource.manual)})
    assert warnings == []


class _TwoCallSess:
    """The map/library join reads FINE and the standards decoration is the statement that fails —
    the granularity the one shared try could not express. `standards` decides what the second
    statement returns (rows, or an exception)."""

    def __init__(self, standards):
        self.standards, self.calls, self.rolled_back = standards, 0, False

    def rollback(self):
        self.rolled_back = True

    def execute(self, *a, **k):
        self.calls += 1
        if self.calls == 1:
            mapped = {"MapRank": 1, "Score": 91, "ControlLibraryID": 28,
                    "ControlCode": "CII-CID-028", "ITOT": "OT", "Domain": "IAM",
                    "ControlName": "MFA", "ControlDescription": "d"}
            return SimpleNamespace(mappings=lambda: SimpleNamespace(all=lambda: [mapped]))
        if isinstance(self.standards, Exception):
            raise self.standards
        return SimpleNamespace(all=lambda: self.standards)


def test_a_failed_standards_subread_keeps_the_controls_it_already_read(monkeypatch) -> None:
    """The standards read is DECORATION; the map read is the payload. Sharing one failure boundary
    meant a broken Control_Standard pair discarded a control map that had already read fine — and
    then said "library control lookup failed", a fact about the whole map. The consequences were not
    cosmetic: an empty library_mapped forces control_coverage "gaps" with NO recommended controls,
    so the plan recommended nothing, and lookup_failed suppressed the dropped-control comparison on
    regenerate, so the reasons went too."""
    # Floor pinned at 1 so the shortfall advisory stays out of this assertion — the rule under test
    # is the standards boundary, and one control is above a floor of one.
    monkeypatch.setattr(ti, "get_settings", lambda: SimpleNamespace(
        control_map_min_count=1, remediation_control_top_up_enabled=True,
        treatment_free_text_cap=2000))   # _clip reads the cap: this read is not monkeypatched away
    sess = _TwoCallSess(RuntimeError("no such table: Control_Standard"))
    controls, warnings, lookup_failed = ti.read_library_controls_for_snapshot(sess, _SCENARIO)
    assert lookup_failed is False and sess.rolled_back is True
    assert [(c["control_code"], c["standards"]) for c in controls] == [("CII-CID-028", [])]
    assert warnings == ["control standards could not be read — mapped controls are listed without "
                        "their standards"]


def test_standards_are_grouped_onto_their_own_control(monkeypatch) -> None:
    """Nothing observed the grouping before: swapping the two selected columns would have silently
    emptied every control's standards in every snapshot."""
    monkeypatch.setattr(ti, "get_settings", lambda: SimpleNamespace(
        control_map_min_count=1, remediation_control_top_up_enabled=True,
        treatment_free_text_cap=2000))   # _clip reads the cap: this read is not monkeypatched away
    controls, warnings, _ = ti.read_library_controls_for_snapshot(
        _TwoCallSess([(28, "IEC 62443"), (28, "ISO 27001"), (99, "NIST CSF")]), _SCENARIO)
    assert controls[0]["standards"] == ["IEC 62443", "ISO 27001"]   # 99 belongs to another control
    assert warnings == []


# ---------------------------------------------------------------------------
# The TSG-derived blocks
# ---------------------------------------------------------------------------
def test_a_broken_threat_join_gives_an_explicit_null_plus_a_warning() -> None:
    """Both hops to Identified_Threat are OUTER joins, so a broken linkage nulls the columns —
    an explicit null beats a silently empty block."""
    block, warnings = ti.build_threat_block({"ThreatCategory": "Tampering"})
    assert block is None
    assert warnings == ["threat join returned no rows — plan generated without threat identity"]


def test_the_library_threat_names_win_over_the_raw_ones() -> None:
    block, warnings = ti.build_threat_block({
        "ThreatCategory": "Spoofing", "ThreatType": "raw type", "ThreatName": "raw name",
        "LibraryThreatType": "lib type", "LibraryThreatName": "lib name"})
    assert warnings == []
    assert (block["type"], block["name"]) == ("lib type", "lib name")


def test_actors_come_from_the_raw_stored_list_even_when_unvalidated() -> None:
    """The scenario being treated was written from that same RAW list, so a validated_actors gate
    would plan against adversaries the scenario names out loud."""
    block, _ = ti.build_threat_block(
        {"ThreatName": "n", "ThreatActorsJSON":
            '{"actors": ["APT-X", "", "Insider"], "validated": false}'})
    assert block["actors"] == ["APT-X", "Insider"]   # the blank is dropped, the rest survive


def test_the_scenario_block_keeps_only_dict_shaped_involved_systems() -> None:
    block = ti.build_scenario_block({
        "scenario_title": "T", "scenario_statement": "S", "risk_statement": "R",
        "supporting_systems_involved": [
            {"supporting_system": "PLC", "is_entry_point": True, "justification": "j"},
            "junk", None,
            {"supporting_system": "HMI"}]})
    assert list(block) == ["scenario_title", "scenario_statement", "risk_statement",
                        "supporting_systems_involved"]
    assert block["supporting_systems_involved"] == [
        {"supporting_system": "PLC", "is_entry_point": True, "justification": "j"},
        {"supporting_system": "HMI", "is_entry_point": False, "justification": None}]


def test_scenario_suggested_is_gone_from_the_block_and_legacy_keys_stay_inert() -> None:
    """The LLM no longer proposes controls (library-first redesign), so library_mapped is the
    whole TSG-derived control input."""
    assert "scenario_suggested" not in ti.build_scenario_block({"scenario_suggested": ["x"]})


def test_register_controls_are_blank_stripped_and_deduped_in_order() -> None:
    """Done HERE, not only in the schema validator: regenerate rebuilds risk_input from the
    stored snapshot and never re-enters the schema, so a legacy row's blanks and dupes would
    otherwise re-enter the baseline forever."""
    block = ti.build_existing_controls_block(
        {"existing_controls": ["MFA", "", "  ", "Segmentation", "MFA"]}, [])
    assert block["register_controls"] == ["MFA", "Segmentation"]
    assert block["library_mapped_count"] == 0


def test_an_orphan_justification_is_dropped_rather_than_handed_to_the_model() -> None:
    """A justification whose Yes/No answer is absent justifies nothing (the schema does not
    pair-validate the two)."""
    orphan = {"existing_controls": [],
            "existing_controls_all_subsystems_justification": "because"}
    assert ti.build_existing_controls_block(orphan, [])[
        "applied_to_all_subsystems_justification"] is None
    paired = {**orphan, "existing_controls_all_subsystems": "Yes"}
    assert ti.build_existing_controls_block(paired, [])[
        "applied_to_all_subsystems_justification"] == "because"


def test_free_text_entering_the_snapshot_is_redacted_and_capped() -> None:
    """_clip is the door UI-supplied body text enters through: a seeded credential must not
    survive, and the truncation is MARKED rather than a silent mid-word cut."""
    cap = ti.get_settings().treatment_free_text_cap
    (leaked,) = ti.build_existing_controls_block(
        {"existing_controls": ["rotate then db_password=Hunter2SecretValue"]}, []
    )["register_controls"]
    assert "Hunter2SecretValue" not in leaked
    (clipped,) = ti.build_existing_controls_block({"existing_controls": ["x" * (cap + 500)]},
                                                [])["register_controls"]
    assert clipped.endswith(" [truncated]") and len(clipped) == cap + len(" [truncated]")


def test_every_builder_caps_its_free_text_not_only_the_register_controls() -> None:
    """_clip is THE ONE DOOR. It was applied per call site until 2026-09, so the scenario block, the
    threat block and impacted_business_division went through redact() alone — and the AI-authored
    scenario text has no length bound anywhere upstream, so an oversized value was frozen into
    InputSnapshotJSON, re-sent on every regeneration, and crowded the register's own controls out of
    the context window, with no truncation log to tell anyone. One field per builder, since the
    defect was per call site rather than per field."""
    cap = ti.get_settings().treatment_free_text_cap
    long = "x" * (cap + 500)
    marked = cap + len(" [truncated]")

    scenario = ti.build_scenario_block({
        "scenario_title": long, "scenario_statement": long, "risk_statement": long,
        "supporting_systems_involved": [{"supporting_system": "PLC", "justification": long}]})
    assert len(scenario["scenario_statement"]) == marked
    assert len(scenario["scenario_title"]) == marked
    assert len(scenario["risk_statement"]) == marked
    assert len(scenario["supporting_systems_involved"][0]["justification"]) == marked

    threat, _ = ti.build_threat_block({"ThreatName": long, "ThreatType": long,
                                    "ThreatCategory": long})
    assert len(threat["name"]) == marked and len(threat["type"]) == marked
    assert len(threat["category"]) == marked

    assert len(ti.build_risk_assessment_block(
        {"impacted_business_division": long}, None)["impacted_business_division"]) == marked
    echo = ti.build_register_echo_block({"risk_owner": long, "impacted_business_division": long})
    assert len(echo["risk_owner"]) == marked and len(echo["impacted_business_division"]) == marked


def test_the_register_echo_block_carries_exactly_the_three_prompt_hidden_echoes() -> None:
    """Stripped from the prompt because risk_owner is a person's name the model must never see;
    impacted_business_division also rides risk_assessment as org context, hence both."""
    assert ti.build_register_echo_block(
        {"risk_identification_date": "2026-06-14T08:31:00", "risk_owner": "Head of OT",
        "impacted_business_division": "Water Ops", "final_risk_rating": 20}) == {
        "risk_identification_date": "2026-06-14T08:31:00", "risk_owner": "Head of OT",
        "impacted_business_division": "Water Ops"}
