"""A resolved control reference reaches the AI whole, or the build fails.

THE BUG. The shape of a resolved control reference was hand-listed in TWO places: `as_reference`
(app/api/library_references.py), which produces it, and `build_existing_controls_block`
(app/pipeline/treatment_input.py), which rebuilds it key by key for the snapshot the model reads.
Add a sixth key to the producer and the consumer silently drops it — no error, no warning. The
model then judges control coverage without data the SHIPPED PROMPT tells it it has
(prompts.py: "register_controls entries with a control_code carry the library's name, domain and
description"), so the output is quietly worse and nothing anywhere says so.

WHY A TEST AND NOT A SHARED IMPORT. app/pipeline must not import app/api — treatment_input takes
only app.core and app.db, and inverting that to share a constant would trade a silent data bug for
a layering one. The producer now derives its keys from the dataclass, so that half extends itself;
this file is what holds the consumer to it. Same shape as tests/test_threat_block_parity.py and
tests/test_treatment_plan_history_parity.py, which pin other cross-module lists the same way.

THE TEST GROWS ITSELF. It is parametrised over CONTROL_REFERENCE_KEYS, so adding a field to
_LibraryControl adds a case that FAILS until build_existing_controls_block carries it. That is the
property that makes this a fix rather than a repair: the next person cannot reintroduce the bug by
doing nothing.
"""
from __future__ import annotations

import pytest

from app.api.library_references import CONTROL_REFERENCE_KEYS, _LibraryControl
from app.pipeline.treatment_input import build_existing_controls_block

#: One distinctive value per key, so a dropped key shows up as a missing value rather than as a
#: default that happens to match.
_PROBE = {"control_id": 4242, "control_code": "PROBE-CODE", "control_name": "Probe Control Name",
          "domain": "Probe Domain", "control_description": "Probe description text"}


def _resolved_reference() -> dict:
    """Exactly what the resolver hands downstream for a control named by any of its keys."""
    control = _LibraryControl(**{k: _PROBE[k] for k in CONTROL_REFERENCE_KEYS})
    return control.as_reference()


def test_the_probe_covers_every_key():
    """Guards the guard: a key added to the dataclass with no probe value would otherwise make the
    parametrised test below silently vacuous rather than failing."""
    assert set(CONTROL_REFERENCE_KEYS) <= set(_PROBE), (
        f"add a distinctive probe value for {set(CONTROL_REFERENCE_KEYS) - set(_PROBE)}")


def test_as_reference_carries_every_field():
    """The producer half. Derived from the dataclass, so this really asserts that nobody has
    reverted it to a hand-typed dict."""
    assert set(_resolved_reference()) == set(CONTROL_REFERENCE_KEYS)


@pytest.mark.parametrize("key", CONTROL_REFERENCE_KEYS)
def test_every_resolved_key_survives_into_the_snapshot(key):
    """The consumer half, one case per key — and the case that appears on its own when a field is
    added. A key the resolver fetches and the snapshot drops is a control the model was promised
    detail about and never received."""
    # No library_mapped rows: this asserts about the REGISTER half, which is where a resolved
    # reference lands and where the rebuild that drops keys lives.
    block = build_existing_controls_block({"existing_controls": [_resolved_reference()]}, [])
    entries = block.get("register_controls") or []
    assert entries, "the resolved reference produced no register entry at all"

    entry = entries[0]
    assert isinstance(entry, dict), (
        f"a RESOLVED reference must stay an object, not be flattened to text — got {entry!r}")
    assert key in entry, (
        f"{key!r} reached build_existing_controls_block and was dropped from the snapshot. It is "
        f"listed in as_reference (derived from _LibraryControl) but not carried by the rebuild in "
        f"treatment_input.build_existing_controls_block — add it there.")
    assert entry[key] == _PROBE[key] or str(_PROBE[key]).startswith(str(entry[key])[:10]), (
        f"{key!r} survived but its value changed: {entry[key]!r} is not {_PROBE[key]!r} "
        "(clipping is allowed; substitution is not)")


# --- the two control lists behave OPPOSITELY, and each says so ---------------------------------
def _description(model, field: str) -> str:
    return model.model_fields[field].description or ""


def test_the_register_collapses_duplicates_and_its_description_says_so():
    """THE BUG: this field's published description claimed "naming one control twice is a 422".
    It never was — existing_controls is a gap-analysis BASELINE, so a repeat is collapsed silently
    (_collapse_controls_named_twice). The sentence was true of the OTHER list and had been copied.
    A client reading your OpenAPI was coded against an error that never arrives.

    Pinned by BEHAVIOUR AND PROSE together, because fixing only the sentence leaves the next
    copy-paste free to reintroduce it. `naming one control twice is a 422` appearing anywhere in
    this field's description fails the test, whatever else the sentence says."""
    from pydantic import TypeAdapter

    from app.api.schemas_references import ControlReference, RegisterControlReferenceList
    from app.api.schemas_treatment import TreatmentPlanBody

    text = _description(TreatmentPlanBody, "existing_controls")
    assert "is a 422" not in text.replace("mapped_controls is the opposite: a duplicate there "
                                          "is a 422", ""), (
        "existing_controls' description claims a 422 for duplicates; the validator collapses them")

    twice = [ControlReference(control_id=7), ControlReference(control_id=7)]
    collapsed = TypeAdapter(RegisterControlReferenceList).validate_python(twice)
    assert len(collapsed) == 1, "the register must collapse a repeat, not refuse it"


def test_the_scenario_list_refuses_duplicates_and_its_description_says_so():
    """The other half of the pair. mapped_controls entries become rows in a table whose composite
    primary key is (scenario, control), so a duplicate is a 500 waiting to happen and is refused
    at the edge instead. The two lists reading oppositely is deliberate; both must document what
    they actually do."""
    import pytest as _pytest
    from pydantic import TypeAdapter, ValidationError

    from app.api.schemas_references import ControlReference, ScenarioControlReferenceList
    from app.api.schemas_treatment import ManualScenarioIn

    assert "422" in _description(ManualScenarioIn, "mapped_controls")

    twice = [ControlReference(control_id=7), ControlReference(control_id=7)]
    with _pytest.raises(ValidationError):
        TypeAdapter(ScenarioControlReferenceList).validate_python(twice)
