"""The WIRE SHAPE of POST /v1/remediation-plans, as the owner approved it on 2026-09-24.

Models only — no HTTP, no database, no fixtures. Every rule pinned here is one this half of the
change owns outright: what the request may say, what "not provided" looks like, and which
contradictions are refusable without asking the library. The other half (does control 1483 exist,
is threat_category_id 5 really "Tampering", does the code agree with the id) needs the library and
is pinned by the suites that drive the real route.

The two approved payloads are transcribed at the top and asserted as-is. They are the contract: if
one of them stops validating, the API stopped accepting what the owner signed off, whatever the
rest of this file says.
"""
from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal

import pytest
from pydantic import ValidationError

from app.api.schemas_references import ControlReference
from app.api.schemas_treatment import (
    _MANUAL_SCENARIO_EXAMPLE,
    _REGISTER_EXAMPLE,
    ManualScenarioIn,
    RemediationPlanBody,
    TreatmentPlanBody,
)

# ── The approved payloads, verbatim ────────────────────────────────────────────────────────────
APPROVED_MANUAL_PAYLOAD = {
    "is_manual": True,
    "manual_scenario": {
        "entity_id": 142, "asset_id": 1200, "sector_id": 183, "subsector_id": 198,
        "service_id": 1707, "supporting_system_id": [1550, 1551],
        "threat_category_id": 5, "threat_category_name": "Tampering",
        "threat_type_id": 42, "threat_type_name": "Engineering Workstation Compromise",
        "threat_id": 126, "threat_name": "Engineering workstation compromise",
        "threat_scenario": "Threat actors compromise an engineering workstation, programming "
                           "laptop or project repository through phishing, malware, portable "
                           "media, stolen laptop or weak endpoint controls. The workstation is "
                           "then used to access controller projects, firmware files, recipes, "
                           "network paths or privileged tools.",
        "risk_statement": "Compromise of engineering workstations can expose controller logic and "
                          "enable trusted changes to devices, making the attack difficult to "
                          "distinguish from normal engineering activity.",
        "mapped_controls": [
            {"control_id": 1483, "control_code": "CII-CID-195",
             "control_name": "Malicious Code Protection (Anti-Malware)"},
            {"control_id": 1486, "control_code": "CII-CID-198", "control_name": "Mobile Code"},
            {"control_id": 1490, "control_code": "CII-CID-202",
             "control_name": "Malicious Link & File Protections"},
            {"control_id": 1501, "control_code": "CII-CID-213",
             "control_name": "Phishing & Spam Protection"},
            {"control_id": 1508, "control_code": "CII-CID-220", "control_name": "User Awareness"}],
    },
    "existing_controls": [
        {"control_id": 1490, "control_code": "CII-CID-202",
         "control_name": "Malicious Link & File Protections"},
        {"control_id": 1501, "control_code": "CII-CID-213",
         "control_name": "Phishing & Spam Protection"},
        {"control_id": 1486, "control_code": "CII-CID-198", "control_name": "Mobile Code"}],
    "likelihood_rating": 3, "impact_rating": 2.46, "final_risk_rating": 7.38,
    "risk_level": "Medium",
    "risk_identification_date": "2026-09-18T15:38:19.853",
    "risk_owner": "Head of Traffic Operations",
    "impacted_business_division": "Traffic Management",
    "existing_controls_all_subsystems": "No",
    "existing_controls_all_subsystems_justification":
        "Intelligent Traffic Systems Platform; Traffic Signal Control System",
    "mitigation_start_date": "2026-09-18T15:38:19.853",
    "mitigation_end_date": "2026-12-17T15:38:19.853",
}

APPROVED_EXISTING_SCENARIO_PAYLOAD = {
    "is_manual": False,
    "session_id": "8bd26529-2031-8428-9ed7-01a0d4840e23",
    "scenario_id": "0aed3720-ab97-83fa-ab43-01a0d4890bd4",
    "existing_controls": [
        {"control_id": 1490, "control_code": "CII-CID-202",
         "control_name": "Malicious Link & File Protections"},
        {"control_id": 1501, "control_code": "CII-CID-213",
         "control_name": "Phishing & Spam Protection"},
        {"control_id": 1508, "control_code": "CII-CID-220", "control_name": "User Awareness"}],
    "likelihood_rating": 4, "impact_rating": 5, "final_risk_rating": 20,
    "risk_level": "Critical",
    "risk_identification_date": "2026-09-15T09:30:00Z",
    "risk_owner": "Head of OT Operations",
    "impacted_business_division": "Power Generation Operations",
    "existing_controls_all_subsystems": "No",
    "existing_controls_all_subsystems_justification":
        "Controls are deployed on corporate IT systems only.",
    "mitigation_start_date": "2026-10-01T00:00:00",
    "mitigation_end_date": "2026-12-31T00:00:00",
}

#: The routing half of an is_manual=false request — every register field below is optional, so this
#: is also the smallest valid payload of that kind.
EXISTING_SCENARIO_ROUTING = {k: APPROVED_EXISTING_SCENARIO_PAYLOAD[k]
                             for k in ("is_manual", "session_id", "scenario_id")}

#: The smallest valid manual scenario the contract publishes: ids for the asset, the threat named
#: (here by name), the two narratives, and nothing else.
SMALLEST_MANUAL_SCENARIO = {
    "entity_id": 142, "asset_id": 1200, "supporting_system_id": 1550,
    "threat_category_name": "Tampering",
    "threat_type_name": "Engineering Workstation Compromise",
    "threat_name": "Engineering workstation compromise",
    "threat_scenario": "An engineering workstation is compromised through phishing.",
    "risk_statement": "Controller logic can be changed in a way that looks like engineering work.",
}


def _existing_scenario(**register) -> RemediationPlanBody:
    return RemediationPlanBody.model_validate({**EXISTING_SCENARIO_ROUTING, **register})


def _refusal(body: dict) -> str:
    """The 422's messages and field locations as one searchable string."""
    with pytest.raises(ValidationError) as caught:
        RemediationPlanBody.model_validate(body)
    return "\n".join(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in caught.value.errors())


# ── The contract itself ────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("payload", [APPROVED_MANUAL_PAYLOAD, APPROVED_EXISTING_SCENARIO_PAYLOAD],
                         ids=["is_manual=true", "is_manual=false"])
def test_both_approved_payloads_are_accepted_exactly_as_signed_off(payload):
    RemediationPlanBody.model_validate(payload)


@pytest.mark.parametrize("payload", [
    {"is_manual": True, "manual_scenario": SMALLEST_MANUAL_SCENARIO},
    EXISTING_SCENARIO_ROUTING,
], ids=["manual", "existing"])
def test_the_smallest_valid_payload_of_each_kind_is_accepted(payload):
    """Every register field is optional, on both routes. The contract publishes these two bodies as
    complete requests, so a UI that has an asset and a threat but no scoring yet can still ask for
    a plan."""
    body = RemediationPlanBody.model_validate(payload)
    assert (body.existing_controls, body.likelihood_rating, body.risk_level) == (None, None, None)


def test_the_published_examples_are_the_approved_payloads():
    """The examples in /openapi.json are separate expressions from the fields they illustrate, and
    an example nobody validates is how TreatmentPlanRegenerateBody ended up advertising a body that
    was a 422. Both halves are checked here against the transcribed contract, not just against the
    models: an example that validates but has drifted from what the owner approved is still wrong.
    """
    assert _MANUAL_SCENARIO_EXAMPLE == APPROVED_MANUAL_PAYLOAD["manual_scenario"]
    assert _REGISTER_EXAMPLE == {k: v for k, v in APPROVED_MANUAL_PAYLOAD.items()
                                 if k not in ("is_manual", "manual_scenario")}
    published = RemediationPlanBody.model_config["json_schema_extra"]["examples"]
    assert published[0] == APPROVED_MANUAL_PAYLOAD
    assert published[1] == APPROVED_EXISTING_SCENARIO_PAYLOAD
    for example in (*published, TreatmentPlanBody.model_config["json_schema_extra"]["example"]):
        RemediationPlanBody.model_validate(example) if "is_manual" in example else \
            TreatmentPlanBody.model_validate(example)


# ── Control references ─────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("entry, expected", [
    ({"control_id": 1483}, (1483, None, None)),
    ({"control_code": "CII-CID-195"}, (None, "CII-CID-195", None)),
    ({"control_name": "Mobile Code"}, (None, None, "Mobile Code")),
    ({"control_code": "CII-CID-198", "control_name": "sample name"},
     (None, "CII-CID-198", "sample name")),
    ({"control_id": 1483, "control_code": "CII-CID-195", "control_name": "Anti-Malware"},
     (1483, "CII-CID-195", "Anti-Malware")),
])
def test_any_one_key_is_enough_and_every_key_sent_is_carried_through(entry, expected):
    """The flexible forms the contract lists, in BOTH modes. Nothing is dropped because something
    stronger is present: the resolver needs the name the caller sent in order to refuse an id that
    disagrees with it, and that refusal is impossible if this model keeps only the id."""
    reference = ControlReference.model_validate(entry)
    assert (reference.control_id, reference.control_code, reference.control_name) == expected


@pytest.mark.parametrize("text, expected", [
    ("CII-CID-220", ("CII-CID-220", "CII-CID-220")),      # code-shaped: code AND the verbatim text
    ("Quarterly phishing simulation", (None, "Quarterly phishing simulation")),
    ("anti-malware", (None, "anti-malware")),             # hyphenated prose is not a code
    ("MFA", (None, "MFA")),
])
def test_a_plain_string_entry_still_works_and_never_loses_its_text(text, expected):
    """`"CII-CID-220"` in mapped_controls and free text in existing_controls both stay legal — every
    caller shipped before the redesign sends strings.

    The verbatim text ALWAYS lands in control_name, including when the string was read as a code.
    That is what makes the code/free-text guess harmless: a free-text entry that happens to look
    like a code ("ISO-27001 review") is still in the baseline the gap analysis reads, so no entry
    can be lost to the heuristic — only misfiled, and the resolver reads the code first anyway.
    """
    reference = ControlReference.model_validate(text)
    assert (reference.control_code, reference.control_name) == expected


@pytest.mark.parametrize("entry", [{}, {"control_code": ""}, {"control_name": "   "},
                                   {"control_id": None}, {"control_id": "", "control_code": " "}])
def test_a_control_entry_that_names_nothing_is_refused_naming_all_three_keys(entry):
    """Blank means absent (a UI sends "" for an untouched field), so an entry whose every key is
    blank names no control at all. Refused rather than dropped: the caller built an object, and
    silently dropping it would lose a control they believe they sent — with the message naming all
    three keys, because the caller cannot otherwise tell which ones they had to choose from."""
    with pytest.raises(ValidationError) as caught:
        ControlReference.model_validate(entry)
    message = caught.value.errors()[0]["msg"]
    assert "control_id" in message and "control_code" in message and "control_name" in message


@pytest.mark.parametrize("bad_id", [0, -1, -1483])
def test_a_control_id_that_cannot_be_a_row_is_refused_not_looked_up(bad_id):
    """0 and negatives are no row in any library. Refusing at the boundary keeps a caller's
    arithmetic slip from becoming 'control not found' three layers down — or worse, a scenario
    quietly saved with one control fewer than the caller listed."""
    assert "control_id" in _refusal(
        {**EXISTING_SCENARIO_ROUTING, "existing_controls": [{"control_id": bad_id}]})


def test_a_misspelled_control_key_is_refused_naming_it():
    """extra="forbid", for TreatmentPlanBody's own documented reason: `control_cod` accepted and
    ignored looks exactly like a control TSG lost."""
    assert "control_cod" in _refusal(
        {**EXISTING_SCENARIO_ROUTING, "existing_controls": [{"control_cod": "CII-CID-195"}]})


@pytest.mark.parametrize("entries", [
    [{"control_id": 1483}, {"control_id": 1483, "control_name": "Anti-Malware"}],
    ["CII-CID-195", "cii-cid-195"],
    [{"control_code": "CII-CID-195"}, {"control_code": " cii-cid-195 "}],
    ["Quarterly phishing simulation", {"control_name": "quarterly phishing simulation"}],
])
def test_mapped_controls_refuses_one_control_named_twice_however_it_was_spelled(entries):
    """The control-map table's key is (scenario, control): a repeat wrote one row and silently lost
    the other, which is why _distinct_codes refused duplicate CODES. Now that the same control can
    arrive as an id, a code or a name, the refusal follows the control rather than the spelling."""
    refusal = _refusal({"is_manual": True,
                        "manual_scenario": {**SMALLEST_MANUAL_SCENARIO, "mapped_controls": entries}})
    assert "named twice" in refusal


def test_two_different_controls_that_share_a_name_are_not_a_duplicate():
    """Different ids are different controls, full stop. Comparing the strongest key the two entries
    SHARE is what keeps a coincidental name collision from refusing a legitimate pair — the
    alternative (compare every key) would reject two real library rows that happen to share a
    name, and a caller could not do anything about it."""
    body = _existing_scenario(existing_controls=[{"control_id": 1, "control_name": "Mobile Code"},
                                                 {"control_id": 2, "control_name": "Mobile Code"}])
    assert [c.control_id for c in body.existing_controls] == [1, 2]


def test_existing_controls_collapses_a_repeat_instead_of_refusing_it():
    """The register's list is a gap-analysis BASELINE, not rows to write: a control listed twice
    covers what it covered once. _cap_control_text has always collapsed repeats silently and the
    snapshot builder collapses them again downstream, so refusing them here would start rejecting
    requests that have been valid since the endpoint shipped. What DID change: the comparison now
    follows the control, so ["CII-CID-213", "cii-cid-213"] is one entry rather than two."""
    body = _existing_scenario(existing_controls=["CII-CID-213", "cii-cid-213", "MFA", " mfa "])
    assert [(c.control_code, c.control_name) for c in body.existing_controls] == [
        ("CII-CID-213", "CII-CID-213"), (None, "MFA")]


def test_blank_string_entries_are_dropped_and_order_is_never_rearranged():
    """A shipped UI sends ["", ""] for a form whose control rows are empty, and the documented
    "no entries means a risk with no controls" answer has to survive that. Order is the caller's
    order of relevance, so the surviving entries come back in the order they were sent."""
    body = _existing_scenario(existing_controls=["", "  ", "Zebra", "CII-CID-213", "Apple"])
    assert [c.control_name for c in body.existing_controls] == ["Zebra", "CII-CID-213", "Apple"]


def test_a_control_entry_over_the_text_cap_is_refused():
    """500 characters per entry, inherited from _cap_control_text — the baseline is fed to the AI,
    and an essay in one entry is a prompt, not a control."""
    assert "control_name" in _refusal(
        {**EXISTING_SCENARIO_ROUTING, "existing_controls": ["x" * 501]})


@pytest.mark.parametrize("not_provided", [{}, {"existing_controls": None},
                                          {"existing_controls": ""}, {"existing_controls": []}])
def test_existing_controls_is_optional_on_both_routes(not_provided):
    """Absent, null, "" and [] all mean "no recorded controls" — the register does not always have
    them, and it used to be a required key on both routes."""
    assert not _existing_scenario(**not_provided).existing_controls
    manual = RemediationPlanBody.model_validate(
        {"is_manual": True, "manual_scenario": SMALLEST_MANUAL_SCENARIO, **not_provided})
    assert not manual.existing_controls


@pytest.mark.parametrize("not_provided", [{}, {"mapped_controls": None},
                                         {"mapped_controls": ""}, {"mapped_controls": []}])
def test_a_manual_scenario_without_mapped_controls_is_accepted(not_provided):
    """"A manual scenario without mapped_controls is saved with no controls, and the plan says so.
    Nothing is added, because top-up is for AI scenarios only." It was a REQUIRED, non-empty list
    until 2026-09, so an empty picker cost the caller the whole request."""
    scenario = ManualScenarioIn.model_validate({**SMALLEST_MANUAL_SCENARIO, **not_provided})
    assert not scenario.mapped_controls


def test_mapped_controls_exists_only_on_the_manual_scenario():
    """An AI scenario's controls come from the session — accepting them here would let a caller
    replace the controls TSG mapped, which is the one thing the control mapper is never allowed to
    do either."""
    assert "mapped_controls" not in TreatmentPlanBody.model_fields
    assert "mapped_controls" in ManualScenarioIn.model_fields


# ── The manual threat triple ───────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("named", [
    {"threat_category_id": 5, "threat_type_id": 42, "threat_id": 126},
    {"threat_category_name": "Tampering", "threat_type_name": "Engineering Workstation Compromise",
     "threat_name": "Engineering workstation compromise"},
    {"threat_category_id": 5, "threat_type_name": "Engineering Workstation Compromise",
     "threat_id": 126, "threat_name": "Engineering workstation compromise"},
])
def test_each_library_row_may_be_named_by_id_by_name_or_by_both(named):
    scenario = ManualScenarioIn.model_validate(
        {k: v for k, v in SMALLEST_MANUAL_SCENARIO.items() if not k.startswith("threat_")}
        | {"threat_scenario": SMALLEST_MANUAL_SCENARIO["threat_scenario"],
           "risk_statement": SMALLEST_MANUAL_SCENARIO["risk_statement"]} | named)
    for field, value in named.items():
        assert getattr(scenario, field) == value


def test_an_id_and_a_name_that_disagree_are_both_carried_to_the_resolver():
    """Deliberately NOT refused here: id 5 with the name "Spoofing" is a caller mistake, but only
    the library can see it. The one thing this model must not do is drop either half — a model that
    kept the id and discarded the name would make the mismatch unnoticeable for good, and the
    request would be resolved as something the caller never described."""
    scenario = ManualScenarioIn.model_validate(
        {**SMALLEST_MANUAL_SCENARIO, "threat_category_id": 5,
         "threat_category_name": "Spoofing"})
    assert (scenario.threat_category_id, scenario.threat_category_name) == (5, "Spoofing")


@pytest.mark.parametrize("pair, blanked", [
    ("threat_category_id or threat_category_name", {"threat_category_name": "   "}),
    ("threat_type_id or threat_type_name", {"threat_type_name": ""}),
    ("threat_id or threat_name", {"threat_name": None}),
])
def test_a_threat_row_named_by_neither_key_is_refused_naming_that_pair(pair, blanked):
    refusal = _refusal({"is_manual": True,
                        "manual_scenario": {**SMALLEST_MANUAL_SCENARIO, **blanked}})
    assert pair in refusal


@pytest.mark.parametrize("field", ["threat_category_id", "threat_type_id", "threat_id"])
def test_a_threat_id_that_cannot_be_a_row_is_refused(field):
    assert field in _refusal({"is_manual": True,
                              "manual_scenario": {**SMALLEST_MANUAL_SCENARIO, field: 0}})


@pytest.mark.parametrize("field", ["threat_category_name", "threat_type_name", "threat_name"])
def test_a_library_name_of_punctuation_alone_is_refused(field):
    """G8, unchanged: a pending curator row called '--' is a row no curator can act on."""
    assert field in _refusal({"is_manual": True,
                              "manual_scenario": {**SMALLEST_MANUAL_SCENARIO, field: "--"}})


def test_scenario_title_is_gone_and_a_stale_client_is_told_so():
    """Deleted with the redesign — it is absent from the approved payload, and it duplicated
    content the scenario already carries. A caller still sending it gets a 422 naming the field
    rather than a silent drop, which is the difference between learning the field is gone and
    believing TSG stored a title it threw away."""
    assert "scenario_title" not in ManualScenarioIn.model_fields
    assert "scenario_title" in _refusal(
        {"is_manual": True,
         "manual_scenario": {**SMALLEST_MANUAL_SCENARIO, "scenario_title": "Ransomware on SCADA"}})


# ── The register's numbers ─────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("sent, expected", [
    (3, Decimal("3")), (2.46, Decimal("2.46")), ("7.38", Decimal("7.38")), (0, Decimal("0")),
    ("", None), (None, None), ("   ", None),
])
def test_every_rating_takes_an_int_a_decimal_or_nothing_at_all(sent, expected):
    body = _existing_scenario(likelihood_rating=sent, impact_rating=sent, final_risk_rating=sent)
    assert (body.likelihood_rating, body.impact_rating, body.final_risk_rating) == (
        expected, expected, expected)


@pytest.mark.parametrize("field", ["likelihood_rating", "impact_rating", "final_risk_rating"])
def test_no_rating_may_be_negative(field):
    """The one bound the contract keeps on the ratings: a negative score is not a score. The
    precision and digit ceilings are pinned by test_treatment_risk_calibration.py."""
    assert field in _refusal({**EXISTING_SCENARIO_ROUTING, field: -1})


@pytest.mark.parametrize("sent, expected", [
    ("Critical", "Critical"), ("Low", "Low"),          # the toolkit's own vocabulary
    ("Severe", "Severe"), ("Very High", "Very High"),  # another register's, accepted and echoed
    ("", None), (None, None),
])
def test_risk_level_takes_any_non_empty_label_and_still_knows_the_toolkit_four(sent, expected):
    """It was a closed enum, so a deployment whose register says "Severe" lost the whole plan
    request over a label TSG only ever echoes. The four known values stay in the annotation — and
    therefore in /openapi.json, where a client generates its picker from them — but they no longer
    decide whether the request is legal. Both branches are `str` at runtime (RiskLevel is a
    StrEnum), so nothing downstream can tell which one validated."""
    level = _existing_scenario(risk_level=sent).risk_level
    assert level == expected
    assert level is None or isinstance(level, str)


# ── The two calendars ──────────────────────────────────────────────────────────────────────────
def test_a_mitigation_date_with_an_offset_keeps_the_day_the_caller_wrote():
    """THE regression this pins. "2026-10-01T02:00:00+05:30" is 2026-09-30 in UTC, so normalizing
    the offset first — which is exactly what risk_identification_date must do — would date the
    mitigation window a day EARLY, and every action's start_date/end_date is computed from that
    window. A mitigation window is a business calendar, not an instant: the caller's 1 October is
    1 October."""
    body = _existing_scenario(mitigation_start_date="2026-10-01T02:00:00+05:30",
                             mitigation_end_date="2026-12-31T23:30:00+05:30")
    assert (body.mitigation_start_date, body.mitigation_end_date) == (date(2026, 10, 1),
                                                                     date(2026, 12, 31))


@pytest.mark.parametrize("sent, expected", [
    ("2026-10-01", date(2026, 10, 1)),
    ("2026-10-01T00:00:00", date(2026, 10, 1)),
    ("2026-09-18T15:38:19.853", date(2026, 9, 18)),
    ("2026-10-01T23:59:59Z", date(2026, 10, 1)),
    (datetime(2026, 10, 1, 15, 38), date(2026, 10, 1)),
    (date(2026, 10, 1), date(2026, 10, 1)),
])
def test_a_mitigation_date_accepts_a_date_or_a_timestamp(sent, expected):
    """The register sends timestamps for fields that are calendar dates, and pydantic refuses a
    non-midnight datetime for a `date` — so the whole plan request was a 422 over a time nobody
    needed."""
    assert _existing_scenario(mitigation_start_date=sent,
                             mitigation_end_date="2027-01-31T08:00:00").mitigation_start_date == expected


@pytest.mark.parametrize("sent", ["01/10/2026", "2026-13-40", "next tuesday", 123])
def test_an_unparseable_mitigation_date_is_still_a_422(sent):
    """Accepting timestamps must not turn a malformed date into a silent None: the validator hands
    anything it cannot read back to pydantic, whose own date error is the answer."""
    assert "mitigation_start_date" in _refusal(
        {**EXISTING_SCENARIO_ROUTING, "mitigation_start_date": sent,
         "mitigation_end_date": "2026-12-31"})


@pytest.mark.parametrize("window, complaint", [
    ({"mitigation_start_date": "2026-10-01T02:00:00"}, "must be provided together"),
    ({"mitigation_end_date": "2026-10-01T02:00:00"}, "must be provided together"),
    ({"mitigation_start_date": "2026-10-02T00:00:00",
      "mitigation_end_date": "2026-10-01T23:59:59"}, "on or after"),
])
def test_the_window_pairing_and_ordering_rules_survive_the_timestamp_change(window, complaint):
    """Accepting a time must not weaken the window: half a window still dates nothing, and an end
    before its start would produce a plan whose actions run backwards. The ordering case is a
    same-instant-different-day pair on purpose — it only fails if the comparison runs on the
    calendar dates the caller wrote."""
    assert complaint in _refusal({**EXISTING_SCENARIO_ROUTING, **window})


def test_risk_identification_date_is_still_normalized_to_utc():
    """The opposite rule to the two mitigation dates, and deliberately so: this one is an INSTANT
    (when the risk was recorded), it is stored in a datetime2 column the driver strips tzinfo from,
    and everything in this schema is UTC by convention."""
    body = _existing_scenario(risk_identification_date="2026-09-18T15:38:19.853+05:30")
    assert body.risk_identification_date == datetime(2026, 9, 18, 10, 8, 19, 853000)
    assert body.risk_identification_date.tzinfo is None


# ── Integer ids on the asset half ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("sent", [142, "142"])
def test_entity_id_is_the_same_entity_as_a_number_or_as_a_string(sent):
    """The approved payload publishes `"entity_id": 142` because that is what the register holds,
    while every caller of POST /v1/sessions has always sent "142". The column is nvarchar and every
    entity comparison in the codebase is a string comparison, so both normalize to the string."""
    assert ManualScenarioIn.model_validate(
        {**SMALLEST_MANUAL_SCENARIO, "entity_id": sent}).entity_id == "142"


@pytest.mark.parametrize("sent, expected", [(1550, [1550]), ([1550], [1550]),
                                            ([1550, 1551], [1550, 1551])])
def test_one_supporting_system_may_be_sent_bare_or_as_a_list(sent, expected):
    """The contract's smallest valid payload sends `"supporting_system_id": 1550`."""
    assert ManualScenarioIn.model_validate(
        {**SMALLEST_MANUAL_SCENARIO, "supporting_system_id": sent}).supporting_system_id == expected


def test_a_repeated_supporting_system_is_still_refused_after_the_bare_form():
    """Wrapping a scalar must not have created a second code path that skips the duplicate check —
    a repeated id corrupts the one-row-per-id Subsystem_Stage_State rows downstream."""
    assert "duplicates" in _refusal(
        {"is_manual": True,
         "manual_scenario": {**SMALLEST_MANUAL_SCENARIO, "supporting_system_id": [1550, 1550]}})


# ── Routing, unchanged ─────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("body, complaint", [
    ({"is_manual": True}, "requires manual_scenario"),
    ({"is_manual": True, "manual_scenario": SMALLEST_MANUAL_SCENARIO,
      "session_id": "8bd26529-2031-8428-9ed7-01a0d4840e23"}, "must not send session_id"),
    ({"is_manual": False}, "requires session_id and scenario_id"),
    ({**EXISTING_SCENARIO_ROUTING, "manual_scenario": SMALLEST_MANUAL_SCENARIO},
     "must not send manual_scenario"),
])
def test_a_request_may_only_be_one_kind_of_request(body, complaint):
    """The register half became optional; the routing half did not."""
    assert complaint in _refusal(body)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
