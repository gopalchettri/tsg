"""Resolving a request's LIBRARY REFERENCES — one pin per rule of app/api/library_references.py.

WHY THIS FILE EXISTS. The approved payload (2026-09) lets a caller name a Control Library row by
`control_id`, `control_code`, `control_name` or any mix, and the manual scenario's threat triple by
id, by name or both. Nothing in the wire schema can say whether id 1483 IS 'CII-CID-195' — that
needs the library — so every rule below is a rule only the resolver can enforce, and each one has a
failure mode worth a test:

  R1  precedence is id, then code, then name (the contract's own order)
  R2  matching is case-insensitive, by the SAME rule the library has always been matched by
  R3  only ACTIVE, undeleted rows resolve, and an unknown/retired reference is a 422 that names it
  R4  an id and a code naming two DIFFERENT controls is a 422 that says which two keys disagree
  R5  a name several active rows answer to cannot be guessed at
  R6  the register's free text is never rejected; a library HANDLE that misses always is
  R7  one query for a whole list, never one per entry (this is the request path)
  R8  the threat triple's ids and names must agree, and ids reach the same library rules as names
  R9  a resolved reference contributes CODE AND NAME to the gap-analysis baseline
  R10 a manual scenario with no mapped_controls is saved with none, and its plan says so

The first nine run against a two-table SQLite database and a real Session — the SQL itself is under
test (a case rule and an OR'd WHERE cannot be checked with a fake). R10 needs the whole route.
"""
from __future__ import annotations

import json
import uuid

import pytest
from conftest import register_sqlite_json_value
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session

from app.api.library_references import (
    resolve_manual_threat_identity,
    resolve_register_control_references,
    resolve_scenario_control_references,
)
from app.api.schemas_references import ControlReference, ManualThreatIdentity
from app.db import models as m
from app.pipeline.treatment_input import register_control_text

# One active control per naming style, one RETIRED and one DELETED row, plus a NAME TWIN: two active
# rows whose ControlName is identical, which the live library does not forbid (app/db/invariants.py
# pins UX_Control_Library_Code on ControlCode alone — ControlName carries no unique index).
_ACTIVE = {1483: ("CII-CID-195", "Malicious Code Protection (Anti-Malware)"),
           1486: ("CII-CID-198", "Mobile Code"),
           1501: ("CII-CID-213", "Phishing & Spam Protection"),
           1508: ("CII-CID-220", "User Awareness"),
           1600: ("CII-CID-300", "Twinned Name"),
           1601: ("CII-CID-301", "Twinned Name")}
_RETIRED = (1900, "CII-CID-900", "Retired Control")      # IsActive = 0
_DELETED = (1901, "CII-CID-901", "Deleted Control")      # IsDeleted = 1


@pytest.fixture
def library() -> tuple[Session, list[str]]:
    """A Session over the Control Library and the threat-library masters, plus the list of every
    SQL statement it executed — R7 is a claim about round trips, so the count has to be observed."""
    engine = create_engine("sqlite://", future=True)
    statements: list[str] = []
    event.listen(engine, "before_cursor_execute",
                 lambda conn, cursor, statement, *rest: statements.append(statement))
    for table in (m.Control_Library, m.Threat_Category, m.Threat_Type, m.Threat_Catalogue):
        table.__table__.create(engine)
    with Session(engine) as sess:
        for control_id, (code, name) in _ACTIVE.items():
            sess.execute(m.Control_Library.__table__.insert().values(
                ControlLibraryID=control_id, ControlCode=code, ControlName=name, ITOT="OT",
                Domain="Endpoint Security", ControlDescription="-", IsActive=True, IsDeleted=False))
        for control_id, code, name in (_RETIRED, _DELETED):
            sess.execute(m.Control_Library.__table__.insert().values(
                ControlLibraryID=control_id, ControlCode=code, ControlName=name, ITOT="OT",
                Domain="Endpoint Security", ControlDescription="-",
                IsActive=control_id != _RETIRED[0], IsDeleted=control_id == _DELETED[0]))
        sess.execute(m.Threat_Category.__table__.insert().values(
            ThreatCategoryID=5, ThreatCategoryName="Tampering", IsActive=True, IsDeleted=False))
        sess.execute(m.Threat_Category.__table__.insert().values(
            ThreatCategoryID=9, ThreatCategoryName="Retired Category", IsActive=False,
            IsDeleted=False))
        sess.execute(m.Threat_Type.__table__.insert().values(
            ThreatTypeID=42, ThreatTypeName="Engineering Workstation Compromise",
            ThreatCategoryID=5, IsActive=True, IsDeleted=False))
        sess.execute(m.Threat_Catalogue.__table__.insert().values(
            ThreatCatalogueID=126, ThreatTypeID=42,
            ThreatName="Engineering workstation compromise", IsActive=True, IsDeleted=False))
        sess.commit()
        statements.clear()
        yield sess, statements


def _refusal(exc_info) -> str:
    """Every message of a resolver 422, joined — the errors are a LIST (one per complaint)."""
    return " | ".join(str(e["msg"]) for e in exc_info.value.errors())


def _references(*entries) -> list[ControlReference]:
    """The entries as the schema hands them over: ControlReference models, bare strings included."""
    return [ControlReference.model_validate(entry) for entry in entries]


# ---------------------------------------------------------------------------
# R1 + R2 + R7: precedence, the case rule, and the round-trip count
# ---------------------------------------------------------------------------
def test_an_entry_resolves_by_id_then_code_then_name(library) -> None:
    """The contract's order, pinned per key AND as precedence: an id and a code that agree resolve
    once, and the mixed entry `{code, name}` is decided by the CODE with the name ignored — which is
    what makes `{"control_code": "CII-CID-198", "control_name": "sample name"}` a valid entry."""
    sess, _ = library
    assert resolve_scenario_control_references(sess, _references(
        {"control_id": 1483},
        {"control_code": "CII-CID-198"},
        {"control_name": "Phishing & Spam Protection"},
        {"control_id": 1508, "control_code": "CII-CID-220", "control_name": "User Awareness"},
        {"control_code": "CII-CID-195", "control_name": "sample name"},
    )) == [1483, 1486, 1501, 1508, 1483]


def test_codes_and_names_match_case_insensitively_like_the_library_lookup(library) -> None:
    """The rule is inherited, not invented: UPPER() in SQL against .upper() in Python, which is how
    the Control Library has been matched by code since the manual save shipped. Two case rules on
    one column is the drift class this codebase keeps getting bitten by, so the NAME door uses the
    same one."""
    sess, _ = library
    assert resolve_scenario_control_references(sess, _references(
        {"control_code": "cii-cid-198"}, {"control_name": "mOBILE cODE"})) == [1486, 1486]


def test_a_mixed_twenty_five_entry_list_costs_one_query(library) -> None:
    """R7 — the whole point of the index. These lists cap at 50 and are resolved on the REQUEST
    path, inside the transaction that writes the scenario: one lookup per entry would be a
    25-round-trip N+1 there. The WHERE is the OR of the key sets the list actually carries, so the
    count is one however the entries are named."""
    sess, statements = library
    entries = _references(*([{"control_id": 1483}, {"control_code": "CII-CID-198"},
                             {"control_name": "User Awareness"},
                             "CII-CID-213", "Quarterly phishing simulation"] * 5))
    assert len(entries) == 25
    resolve_register_control_references(sess, entries)
    assert len(statements) == 1, statements


def test_a_list_that_names_nothing_costs_no_query_at_all(library) -> None:
    sess, statements = library
    assert resolve_scenario_control_references(sess, None) == []
    assert resolve_register_control_references(sess, []) == []
    assert statements == []


# ---------------------------------------------------------------------------
# R3 + R4 + R5: what is refused, and how the refusal reads
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("entry, says", [
    ({"control_code": "CII-CID-404"}, "not active Control Library codes: ['CII-CID-404']"),
    ({"control_code": _RETIRED[1]}, f"not active Control Library codes: ['{_RETIRED[1]}']"),
    ({"control_code": _DELETED[1]}, f"not active Control Library codes: ['{_DELETED[1]}']"),
    ({"control_id": 4040}, "not active Control Library ids: [4040]"),
    ({"control_id": _RETIRED[0]}, f"not active Control Library ids: [{_RETIRED[0]}]"),
    ({"control_name": "No Such Control"}, "not Control Library control names: ['No Such Control']"),
])
def test_an_unknown_or_retired_scenario_control_is_a_422_naming_it(library, entry, says) -> None:
    """A scenario's controls become Threat_Scenario_Control_Map rows and a plan may only recommend a
    real library row, so unknown, retired and deleted are ONE answer here. The code sentence is the
    wording the code-only path shipped with, kept verbatim because integrators parse it."""
    sess, _ = library
    with pytest.raises(Exception) as caught:
        resolve_scenario_control_references(sess, _references(entry))
    assert says in _refusal(caught)
    assert caught.value.errors()[0]["loc"][-1] == "mapped_controls"


def test_every_offender_in_one_list_is_named_in_one_422(library) -> None:
    """The caller fixes a control list in ONE editing pass. Reporting the first miss and stopping is
    how an integrator with three stale codes discovers them one deploy at a time."""
    sess, _ = library
    with pytest.raises(Exception) as caught:
        resolve_scenario_control_references(sess, _references(
            {"control_id": 4040}, {"control_code": "CII-CID-404"}, {"control_name": "Nope"},
            {"control_id": 1483}))
    says = _refusal(caught)
    assert "ids: [4040]" in says and "codes: ['CII-CID-404']" in says and "['Nope']" in says


def test_an_id_and_a_code_naming_two_controls_is_refused_saying_which(library) -> None:
    """R4 — the check the wire layer could not do. `{"control_id": 1483, "control_code":
    "CII-CID-198"}` is a perfectly well-shaped entry that names two different controls; resolving it
    by the id alone would write a control the caller did NOT name into the scenario, under a code
    they will read back later and not recognise."""
    sess, _ = library
    for resolve in (resolve_scenario_control_references, resolve_register_control_references):
        with pytest.raises(Exception) as caught:
            resolve(sess, _references({"control_id": 1483, "control_code": "CII-CID-198"}))
        says = _refusal(caught)
        assert "control_id 1483 is 'CII-CID-195'" in says
        assert "control_code 'CII-CID-198' is control_id 1486" in says


def test_an_id_that_agrees_with_its_code_is_not_a_conflict(library) -> None:
    sess, _ = library
    assert resolve_scenario_control_references(sess, _references(
        {"control_id": 1486, "control_code": "cii-cid-198", "control_name": "Mobile Code"},
    )) == [1486]


def test_a_name_two_active_controls_share_cannot_be_guessed_for_a_scenario(library) -> None:
    """R5 — picking one would map a control the caller never chose. The 422 names the candidates so
    the fix is one edit."""
    sess, _ = library
    with pytest.raises(Exception) as caught:
        resolve_scenario_control_references(sess, _references({"control_name": "Twinned Name"}))
    says = _refusal(caught)
    assert "'Twinned Name' is the name of 2 active Control Library rows" in says
    assert "CII-CID-300, CII-CID-301" in says


# ---------------------------------------------------------------------------
# R6 + R9: the register's baseline is tolerant of TEXT and strict about HANDLES
# ---------------------------------------------------------------------------
def test_register_free_text_survives_and_a_resolved_reference_is_canonicalized(library) -> None:
    """The baseline's documented job is unchanged: an entry that matches no library row is kept
    verbatim, never rejected. A reference that DOES resolve comes back as the library's own
    id/code/name, so a mis-cased code reaches the model as the library spells it."""
    sess, _ = library
    resolved = resolve_register_control_references(sess, _references(
        "Quarterly phishing simulation",          # free text, kept
        "cii-cid-198",                            # a code-shaped string, resolved and canonicalized
        {"control_name": "user awareness"},       # a name, resolved
        {"control_id": 1501}))
    assert resolved[0].control_name == "Quarterly phishing simulation"
    assert resolved[1] == {"control_id": 1486, "control_code": "CII-CID-198",
                           "control_name": "Mobile Code"}
    assert resolved[2]["control_code"] == "CII-CID-220"
    assert resolved[3]["control_name"] == "Phishing & Spam Protection"


@pytest.mark.parametrize("entry", ["CII-CID-404", "ISO-27001 gap review", "Twinned Name"])
def test_a_register_entry_that_names_no_library_row_is_never_rejected(library, entry) -> None:
    """Three shapes that must all stay text: a code-shaped string nothing answers to, hyphenated
    prose with a digit in it (which the schema's code heuristic guesses IS a code — a guess can
    never be the basis of a refusal), and a name two rows share, where only the caller could say
    which one they meant and the model can still read the words."""
    sess, _ = library
    (kept,) = resolve_register_control_references(sess, _references(entry))
    assert register_control_text(kept) == entry


@pytest.mark.parametrize("entry, says", [
    ({"control_id": 4040}, "not active Control Library ids: [4040]"),
    ({"control_code": "CII-CID-404"}, "not active Control Library codes: ['CII-CID-404']"),
    ({"control_code": _RETIRED[1]}, "not active Control Library codes"),
])
def test_a_register_entry_naming_a_library_handle_that_misses_is_a_422(library, entry, says) -> None:
    """The other half of R6: an id, or a `control_code` KEY, is an assertion only the library can
    settle — a register that believes it recorded control 4040 must not be told its risk has no
    controls. (A code the schema GUESSED from a bare string is the case above, and stays text.)"""
    sess, _ = library
    with pytest.raises(Exception) as caught:
        resolve_register_control_references(sess, _references(entry))
    assert says in _refusal(caught)
    assert tuple(caught.value.errors()[0]["loc"]) == ("body", "existing_controls")


def test_a_resolved_reference_contributes_its_code_and_its_name_to_the_baseline() -> None:
    """R9 — no DB. prompts rule 2 matches the baseline to the mapped controls BY MEANING: a bare
    'CII-CID-198' has no meaning to match, so resolving a code and then feeding the model only the
    code would make the gap analysis worse than the free text it replaced. Both halves travel."""
    assert register_control_text({"control_id": 1486, "control_code": "CII-CID-198",
                                 "control_name": "Mobile Code"}) == "CII-CID-198 — Mobile Code"
    # A dict is what crashed the live POST (the old builder called .strip() on every entry), so the
    # renderer takes every shape the list can hold, including one no resolver ever saw.
    assert register_control_text("free text") == "free text"
    assert register_control_text({"control_name": "free text"}) == "free text"
    assert register_control_text({"control_code": "X-1", "control_name": "X-1"}) == "X-1"
    assert register_control_text({"control_id": 1486}) == "control_id 1486"
    assert register_control_text({}) is None and register_control_text(None) is None


# ---------------------------------------------------------------------------
# R8: the threat triple through the id door
# ---------------------------------------------------------------------------
def _identity(**fields) -> ManualThreatIdentity:
    return ManualThreatIdentity.model_validate(
        {"threat_category_name": "Tampering",
         "threat_type_name": "Engineering Workstation Compromise",
         "threat_name": "Engineering workstation compromise", **fields})


def test_an_id_resolves_to_the_librarys_own_wording(library) -> None:
    """Ids in, NAMES out: every rule the save then applies — the library combination checks, the
    pending-row proposals, their 422 messages — speaks names, so resolving to names is what lets the
    id door reuse them instead of growing a second answer to "does the library hold this"."""
    sess, _ = library
    names = resolve_manual_threat_identity(sess, ManualThreatIdentity.model_validate(
        {"threat_category_id": 5, "threat_type_id": 42, "threat_id": 126}))
    assert (names.threat_category, names.threat_type, names.threat) == (
        "Tampering", "Engineering Workstation Compromise", "Engineering workstation compromise")


def test_names_only_are_carried_through_untouched_and_cost_no_query(library) -> None:
    """The payload every caller shipped before the ids existed pays nothing for them."""
    sess, statements = library
    names = resolve_manual_threat_identity(sess, _identity())
    assert names.threat_type == "Engineering Workstation Compromise"
    assert statements == []


@pytest.mark.parametrize("fields, field, says", [
    ({"threat_category_id": 5, "threat_category_name": "Spoofing"}, "threat_category_name",
     "threat_category_id 5 is 'Tampering' in the threat library, not 'Spoofing'"),
    ({"threat_type_id": 42, "threat_type_name": "Phishing"}, "threat_type_name",
     "threat_type_id 42 is 'Engineering Workstation Compromise' in the threat library"),
    ({"threat_id": 126, "threat_name": "Something else"}, "threat_name",
     "threat_id 126 is 'Engineering workstation compromise' in the threat library"),
])
def test_an_id_that_disagrees_with_its_name_is_refused_naming_both(library, fields, field,
                                                                  says) -> None:
    """Sending id 5 with the name 'Spoofing' is a caller mistake only the library can see —
    resolving it silently by the id would save a scenario under a category they did not choose."""
    sess, _ = library
    with pytest.raises(Exception) as caught:
        resolve_manual_threat_identity(sess, _identity(**fields))
    assert says in _refusal(caught)
    assert caught.value.errors()[0]["loc"][-1] == field


def test_an_id_and_a_name_that_agree_loosely_still_agree(library) -> None:
    """normalize_name, the library's OWN identity key: 'engineering  workstation compromise' and
    the library's spelling are one row there, so they cannot be a disagreement here."""
    sess, _ = library
    names = resolve_manual_threat_identity(sess, _identity(
        threat_id=126, threat_name="Engineering  workstation   compromise"))
    assert names.threat == "Engineering workstation compromise"


@pytest.mark.parametrize("fields, field", [
    ({"threat_category_id": 404}, "threat_category_id"),
    ({"threat_category_id": 9}, "threat_category_id"),    # inactive: not a category
    ({"threat_type_id": 404}, "threat_type_id"),
    ({"threat_id": 404}, "threat_id"),
])
def test_an_id_no_library_row_has_is_refused_on_that_field(library, fields, field) -> None:
    """A type or threat the library does not hold is PROPOSED by name — but an id nobody issued
    cannot be proposed, only mistyped. The inactive category is refused for the reason
    grounding.find_category refuses it: the six STRIDE categories are never minted, so an inactive
    one is not a category a scenario can be filed under."""
    sess, _ = library
    with pytest.raises(Exception) as caught:
        resolve_manual_threat_identity(sess, _identity(**{**fields}))
    assert caught.value.errors()[0]["loc"][-1] == field
    assert "is not a threat-library" in _refusal(caught)


# ---------------------------------------------------------------------------
# R10 + the id door end to end: the whole route, against a real database
# ---------------------------------------------------------------------------
TENANT, ENTITY, USER = "t", "86", "u1"
ASSET, SUPPORT = 103, 321

_RISK = {"likelihood_rating": 4, "impact_rating": 5, "final_risk_rating": 20,
         "risk_level": "Critical"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    """The real app over a file-backed SQLite database, one asset owned by ENTITY, the threat library
    and Control Library of the fixture above, and the plan enqueue stubbed (its documented seam)."""
    monkeypatch.setenv("TSG_DB_DSN", f"sqlite:///{tmp_path / 'references.db'}")
    monkeypatch.setenv("TSG_RISK_MODULE_ENABLED", "true")
    from app.core.config import get_settings
    from app.db.engine import _sessionmaker, get_engine
    get_settings.cache_clear()
    get_engine.cache_clear()
    _sessionmaker.cache_clear()
    register_sqlite_json_value(get_engine())

    engine = create_engine(f"sqlite:///{tmp_path / 'references.db'}", future=True)
    for table in (m.Scenario_Session, m.Subsystem_Stage_State, m.Identified_Threat,
                  m.Scoped_Threat, m.Threat_Scenario, m.Scenario_Audit, m.Threat_Category,
                  m.Threat_Type, m.Threat_Catalogue, m.ThreatType_ThreatActor_Map,
                  m.Threat_Catalogue_Category_Map, m.Control_Library, m.Control_Standard,
                  m.Control_Library_Standard_Map, m.Threat_Scenario_Control_Map,
                  m.Risk_Treatment_Plan, m.Threat_Actor, m.Prompt_Log, m.ctm_scan_entity,
                  m.ctm_scan_entity_bu, m.onboarding_supporting_systems,
                  m.ctm_scan_entity_supporting_system, m.Config_Tuning,
                  m.Grounding_Calibration_Run):
        table.__table__.create(engine, checkfirst=True)
    engine.dispose()

    from app.db.engine import db_session
    with db_session() as sess:
        for control_id, (code, name) in _ACTIVE.items():
            sess.execute(m.Control_Library.__table__.insert().values(
                ControlLibraryID=control_id, ControlCode=code, ControlName=name, ITOT="OT",
                Domain="Endpoint Security", ControlDescription="-", IsActive=True, IsDeleted=False))
        sess.execute(m.Threat_Category.__table__.insert().values(
            ThreatCategoryID=5, ThreatCategoryName="Tampering", IsActive=True, IsDeleted=False))
        sess.execute(m.Threat_Type.__table__.insert().values(
            ThreatTypeID=42, ThreatTypeName="Engineering Workstation Compromise",
            ThreatCategoryID=5, IsActive=True, IsDeleted=False, Source="functional_team_excel"))
        sess.execute(m.Threat_Catalogue.__table__.insert().values(
            ThreatCatalogueID=126, ThreatTypeID=42,
            ThreatName="Engineering workstation compromise", IsActive=True, IsDeleted=False,
            Source="functional_team_excel"))
        sess.execute(m.ctm_scan_entity.__table__.insert().values(
            id=ASSET, name="Engineering Workstation", criticality=3, type="Plant",
            is_deleted=False))
        sess.execute(m.ctm_scan_entity_bu.__table__.insert().values(
            ctm_scan_entity_id=ASSET, group_id=int(ENTITY), service_id=None))
        sess.execute(m.onboarding_supporting_systems.__table__.insert().values(
            id=SUPPORT, name="Project Repository", is_deleted=False))
        sess.execute(m.ctm_scan_entity_supporting_system.__table__.insert().values(
            ctm_scan_entity_id=ASSET, onboarding_supporting_system_id=SUPPORT))
        sess.commit()

    import app.api.treatment as treatment_api
    monkeypatch.setattr(treatment_api, "enqueue_treatment_plan", lambda *a, **k: None)

    from app.api.deps import Principal, get_principal
    from app.main import create_app
    app = create_app()
    app.dependency_overrides[get_principal] = lambda: Principal(
        claims={"sub": USER}, entities={ENTITY}, client_id="reference-test", tenant_id=TENANT)
    yield TestClient(app)
    app.dependency_overrides.clear()


def _manual(**overrides) -> dict:
    return {"is_manual": True, **_RISK, "manual_scenario": {
        "entity_id": ENTITY, "asset_id": ASSET, "supporting_system_id": [SUPPORT],
        "threat_scenario": "A phished engineer laptop is used to change controller logic on the "
                           "Engineering Workstation.",
        "risk_statement": "Trusted changes to controller logic disrupt operations.",
        **overrides}}


def _post(client, body: dict, key: str = "key-1"):
    return client.post("/v1/remediation-plans", json=body, headers={"Idempotency-Key": key})


def _snapshot(scenario_id: str) -> dict:
    from app.db.engine import db_session
    with db_session() as sess:
        return json.loads(sess.execute(
            select(m.Risk_Treatment_Plan.InputSnapshotJSON)
            .where(m.Risk_Treatment_Plan.ScenarioID == scenario_id)).scalar_one())


def test_a_manual_scenario_named_entirely_by_ids_is_saved_and_planned(client) -> None:
    """The id door, end to end: the threat triple by id and the controls by id, with no names at all.
    The threat row must link the SAME library rows a name-shaped request links, and the register's
    id-named control must reach the AI as the library's code and name."""
    from app.db.engine import db_session

    body = _manual(threat_category_id=5, threat_type_id=42, threat_id=126,
                   mapped_controls=[{"control_id": 1486}, {"control_id": 1483}])
    response = _post(client, {**body, "existing_controls": [{"control_id": 1501}]})
    assert response.status_code == 202, response.text
    scenario_id = response.json()["scenario_id"]

    with db_session() as sess:
        threat = sess.execute(select(m.Identified_Threat)).scalar_one()
        assert (threat.ThreatCategoryID, threat.ThreatTypeID, threat.ThreatCatalogueID) == (
            5, 42, 126)
        assert threat.GroundingStatus == "verified"      # an approved library row, not a proposal
        assert threat.ThreatName == "Engineering workstation compromise"
        ranked = [r.ControlLibraryID for r in sess.execute(
            select(m.Threat_Scenario_Control_Map)
            .order_by(m.Threat_Scenario_Control_Map.MapRank)).scalars()]
        assert ranked == [1486, 1483]                    # the caller's order, not the library's
        # Nothing was proposed: every id named a row the library already holds.
        assert "library_promoted" not in {a.EventType for a in sess.execute(
            select(m.Scenario_Audit)).scalars()}
    assert _snapshot(scenario_id)["existing_controls"]["register_controls"] == [
        "CII-CID-213 — Phishing & Spam Protection"]


def test_a_manual_scenario_with_no_mapped_controls_is_saved_with_none_and_says_so(client) -> None:
    """R10, the contract's own closing note: "A manual scenario without mapped_controls is saved with
    no controls, and the plan says so. Nothing is added, because top-up is for AI scenarios only."

    Two halves, both pinned here: the save writes NO control-map rows (and does not fail on an empty
    executemany), and the plan's frozen snapshot carries the empty-map warning — not the top-up floor
    warning, which is an AI scenario's signal and would blame a pass that never runs on this row."""
    from app.db.engine import db_session

    response = _post(client, _manual(threat_category_name="Tampering",
                                     threat_type_name="Engineering Workstation Compromise",
                                     threat_name="Engineering workstation compromise"))
    assert response.status_code == 202, response.text
    scenario_id = response.json()["scenario_id"]
    with db_session() as sess:
        assert sess.execute(select(func.count()).select_from(m.Threat_Scenario_Control_Map)
                            ).scalar() == 0
        scenario = sess.execute(select(m.Threat_Scenario)).scalar_one()
        # Still stamped mapped: that column is what keeps both control-mapping selections off a
        # person's scenario, and it must not depend on whether they listed any controls.
        assert scenario.ControlsMappedAt is not None and scenario.Accepted == 1

    snapshot = _snapshot(scenario_id)
    assert snapshot["existing_controls"]["library_mapped"] == []
    assert "no library-mapped controls for this scenario (Step-4 map is empty)" in snapshot[
        "warnings"]
    assert not [w for w in snapshot["warnings"] if "library-mapped controls —" in w]


def test_a_control_whose_id_and_code_disagree_saves_nothing(client) -> None:
    """The conflict 422 is raised inside the save's own transaction, so the all-or-nothing rule
    covers it: no session, no threat, no scenario, and the Idempotency-Key is free to be retried."""
    from app.db.engine import db_session

    response = _post(client, _manual(
        threat_category_id=5, threat_type_id=42, threat_id=126,
        mapped_controls=[{"control_id": 1483, "control_code": "CII-CID-198"}]))
    assert response.status_code == 422, response.text
    (error,) = response.json()["details"]["errors"]
    assert error["loc"][-1] == "mapped_controls"
    assert "one entry cannot name two controls" in error["msg"]
    with db_session() as sess:
        for table in (m.Scenario_Session, m.Identified_Threat, m.Threat_Scenario):
            assert sess.execute(select(func.count()).select_from(table)).scalar() == 0

    # The same key now works, which is what "nothing is saved" has to mean in practice.
    assert _post(client, _manual(threat_category_id=5, threat_type_id=42, threat_id=126,
                                 mapped_controls=[{"control_id": 1483}])).status_code == 202


def test_a_bad_register_control_reference_refuses_before_the_scenario_is_saved(client) -> None:
    """`existing_controls` belongs to the register half, which is resolved BEFORE the manual save on
    this route: a 422 there must not leave a committed scenario behind whose ids the standard 422
    envelope has nowhere to report."""
    from app.db.engine import db_session

    response = _post(client, {**_manual(threat_category_id=5, threat_type_id=42, threat_id=126),
                              "existing_controls": [{"control_id": 4040}]})
    assert response.status_code == 422, response.text
    assert "not active Control Library ids: [4040]" in response.text
    with db_session() as sess:
        assert sess.execute(select(func.count()).select_from(m.Scenario_Session)).scalar() == 0


def test_the_path_route_resolves_the_registers_references_too(client) -> None:
    """Both remediation routes freeze the same baseline, so the resolution cannot live on one of
    them. This drives the per-scenario path route against the scenario the manual save just made."""
    first = _post(client, _manual(threat_category_id=5, threat_type_id=42, threat_id=126,
                                  mapped_controls=[{"control_id": 1483}]))
    session_id, scenario_id = first.json()["session_id"], first.json()["scenario_id"]
    # A second scenario is not needed: regenerate reuses the frozen register half, and the path
    # route refuses a second first-generation — so the pin is on the 422 the path route raises.
    bad = client.post(f"/v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan",
                      json={**_RISK, "existing_controls": [{"control_code": "CII-CID-404"}]})
    assert bad.status_code == 422, bad.text
    assert "not active Control Library codes: ['CII-CID-404']" in bad.text
    assert str(uuid.UUID(scenario_id)) == scenario_id.lower()   # the ids are real uuids
