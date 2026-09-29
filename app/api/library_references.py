"""Resolving a REQUEST's library references against the rows TSG actually holds.

app/api/schemas_references.py polices the SHAPE of a `ControlReference` / `ManualThreatIdentity`
and says, in its own module docstring, what it deliberately cannot answer: "Whether id 1483 really
is `CII-CID-195`, and whether `threat_category_id` 5 really is named 'Tampering', needs the library
and is resolved by the route inside the same transaction that writes the scenario." This module is
that resolution — the ONE place a wire reference becomes a library row, so the remediation route and
the manual-scenario save can never answer "does this control exist" two different ways.

WHY IT IS ITS OWN MODULE. Its two callers are app/api/sessions.py (the manual save's controls and
threat triple) and app/api/treatment.py (the register's `existing_controls`, on both remediation
routes). Both files are already over a thousand lines, and a resolution rule that lived in one of
them would be copied into the other the first time the second needed it — which is exactly how the
Control Library ended up being matched by two different case rules once before.

RESOLUTION PRECEDENCE IS FIXED BY THE APPROVED CONTRACT: id first, then code, then name. The same
order schemas_references._CONTROL_KEYS_STRONGEST_FIRST uses for duplicate detection, so the two can
never disagree about which key identifies an entry.

ONE QUERY PER LIST, NEVER ONE PER ENTRY. These lists hold up to _MAX_BATCH (50) entries and are
resolved on the REQUEST path; a per-entry lookup would be a 50-round-trip N+1 inside the transaction
that writes the scenario. _load_control_library_index issues a single SELECT whose WHERE is the OR of
the three key sets the list actually carries, so a mixed 25-entry list costs exactly one round trip.

CASE-INSENSITIVITY IS INHERITED, NOT INVENTED: `UPPER()` in SQL against `str.upper()` in Python, the
rule sessions._resolve_control_codes has matched ControlCode by since the manual save shipped. Names
are matched the same way for the same reason — two case rules on one column is the drift this
codebase keeps getting bitten by, and a column matched one way by the resolver and another way by
the caller's own `identity_keys()` dedup would accept a list the resolver then calls a duplicate.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi.exceptions import RequestValidationError
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.naming import normalize_name
from app.db import models as m

#: Where a control list's 422 points, per route. The manual save's list is nested inside
#: `manual_scenario`; the register's is a top-level body field.
MANUAL_CONTROLS_LOC = ("body", "manual_scenario", "mapped_controls")
REGISTER_CONTROLS_LOC = ("body", "existing_controls")


def _validation_error(loc: tuple[str, ...], entries: list[dict]) -> RequestValidationError:
    """One 422 carrying EVERY complaint about one list, in the standard envelope.

    Every problem with the list travels in a single response (`details.errors` is a list —
    app/api/errors.py::_handle_validation_error) because the caller fixes a control list in one
    editing pass: reporting the first unknown code and stopping is what made an integrator with
    three stale codes discover them one deploy at a time.
    """
    return RequestValidationError([{"type": "value_error", "loc": loc, **entry}
                                   for entry in entries])


# ---------------------------------------------------------------------------
# Control Library references
# ---------------------------------------------------------------------------
def _fold_for_the_library(text: str) -> str:
    """The Control Library's matching key: trim + upper, the Python half of the
    `func.upper(ControlCode).in_([c.upper() for c in codes])` rule this resolver inherited."""
    return text.strip().upper()


@dataclass(frozen=True)
class _LibraryControl:
    """One ACTIVE, undeleted Control_Library row — the only kind that resolves."""

    control_id: int
    control_code: str
    control_name: str
    #: Domain and description ride along so a register entry that named a library row reaches the
    #: AI with the same detail a mapped control gets from the snapshot (treatment_input reads
    #: name/domain/description for map rows) — a bare "CODE — NAME" line asked the model to judge
    #: coverage of a control it had never been told the meaning of.
    domain: str | None = None
    control_description: str | None = None

    def as_reference(self) -> dict[str, Any]:
        """The canonical reference: the LIBRARY's spelling of all five keys, whichever one the
        caller sent. The register's baseline is rendered from this downstream
        (treatment_input.build_existing_controls_block), so a caller's mis-cased code or loosely
        spelled name reaches the model as the library's own text rather than as their typo."""
        return {"control_id": self.control_id, "control_code": self.control_code,
                "control_name": self.control_name, "domain": self.domain,
                "control_description": self.control_description}


@dataclass
class _ControlLibraryIndex:
    """The one SELECT's rows, keyed the three ways a reference can name them."""

    by_id: dict[int, _LibraryControl]
    by_code: dict[str, _LibraryControl]
    #: Folded name -> every row carrying it. A LIST because ControlName has no unique index
    #: (app/db/invariants.py pins UX_Control_Library_Code on ControlCode alone), so two active
    #: rows may legitimately share a name and only the caller can say which one they meant.
    by_name: dict[str, list[_LibraryControl]]


def _reference_keys(entry: Any) -> tuple[int | None, str | None, str | None]:
    """(control_id, control_code, control_name) from a ControlReference, from that model dumped to
    a dict (`body.model_dump(mode="json")` — how the register's list arrives), or from a bare
    string.

    A bare string fills CODE AND NAME both, exactly as ControlReference._accept_a_plain_string
    does, rather than re-deciding here whether it looks like a library code: this resolver holds
    the real code index, so it can simply try the code first and fall back to the name — the
    heuristic's answer is never needed. (Strings do not survive schema validation, so this arm is
    for a path that bypassed it, never the published contract.)
    """
    if isinstance(entry, str):
        text = entry.strip()
        return None, text or None, text or None
    get = entry.get if isinstance(entry, dict) else lambda key: getattr(entry, key, None)
    control_id, code, name = get("control_id"), get("control_code"), get("control_name")
    return (int(control_id) if control_id is not None else None,
            (code or "").strip() or None, (name or "").strip() or None)


def _load_control_library_index(sess: Session, entries: list[Any]) -> _ControlLibraryIndex:
    """ONE query for a whole list — see this module's header.

    Only ACTIVE, undeleted rows are loaded, so "retired" and "unknown" are the same answer here and
    neither can resolve. That filter is the one pipeline.treatment_input._library_controls applies
    when it reads a scenario's mapped controls for the snapshot: a control that could resolve here
    but not there would be accepted into a scenario and then silently missing from its own plan.
    """
    ids, codes, names = set(), set(), set()
    for entry in entries:
        control_id, code, name = _reference_keys(entry)
        if control_id is not None:
            ids.add(control_id)
        if code:
            codes.add(_fold_for_the_library(code))
        if name:
            names.add(_fold_for_the_library(name))
    lib = m.Control_Library
    named: list = []
    if ids:
        named.append(lib.ControlLibraryID.in_(sorted(ids)))
    if codes:
        named.append(func.upper(lib.ControlCode).in_(sorted(codes)))
    if names:
        named.append(func.upper(lib.ControlName).in_(sorted(names)))
    index = _ControlLibraryIndex({}, {}, {})
    if not named:
        return index
    rows = sess.execute(
        select(lib.ControlLibraryID, lib.ControlCode, lib.ControlName, lib.Domain,
               lib.ControlDescription)
        .where(or_(*named), lib.IsActive == True, lib.IsDeleted == False)
        # Deterministic, so an ambiguous name always reports its candidates in the same order
        # (a 422 whose list reshuffles between attempts reads like a moving target).
        .order_by(lib.ControlLibraryID)
    ).all()
    for control_id, code, name, domain, description in rows:
        row = _LibraryControl(int(control_id), str(code), str(name),
                              str(domain) if domain else None,
                              str(description) if description else None)
        index.by_id[row.control_id] = row
        index.by_code[_fold_for_the_library(row.control_code)] = row
        index.by_name.setdefault(_fold_for_the_library(row.control_name), []).append(row)
    return index


@dataclass(frozen=True)
class _EntryOutcome:
    """What the library said about ONE entry: the row it resolved to, or why it did not."""

    control: _LibraryControl | None = None
    #: An id and a code naming two different controls: refused on BOTH lists, because it is the one
    #: failure no reading of the entry makes harmless.
    conflict: str | None = None
    conflicting_keys: Any = None
    missing_id: int | None = None
    missing_code: str | None = None
    missing_name: str | None = None
    #: The codes of the several active rows answering to `missing_name`. Set WITH missing_name, so
    #: an ambiguous name is an unresolved name on the tolerant list (kept verbatim) and a named 422
    #: on the strict one, where guessing one of them would write the wrong control.
    ambiguous_codes: tuple[str, ...] = ()
    #: True when `missing_code` came from a bare string rather than a `control_code` key. Such a
    #: code is a GUESS (ControlReference._accept_a_plain_string fills both keys from one string),
    #: so it can never be the basis of a refusal — free text that happens to be hyphenated and to
    #: contain a digit must stay free text, which is what the register's baseline has always
    #: accepted.
    code_was_a_guess: bool = False


def _resolve_one_control_reference(entry: Any, index: _ControlLibraryIndex) -> _EntryOutcome:
    """One entry against the loaded index: id first, then code, then name.

    THE ID/CODE CONFLICT CHECK LIVES HERE and nowhere else. ControlReference cannot do it — it has
    no library — so `{"control_id": 1483, "control_code": "CII-CID-198"}` naming two different rows
    reaches the server as a perfectly well-shaped entry. Resolving it by the id alone would write
    the control the caller did NOT name into the scenario's control map, under a code they will
    later read back and not recognise.

    THE NAME IS NOT CONFLICT-CHECKED, deliberately, and this is the one asymmetry with the threat
    triple below. The approved contract spells it out for the entry
    `{"control_code": "CII-CID-198", "control_name": "sample name"}`: "The last entry works because
    the id or code decides, and the name is ignored." It has to be ignored — `control_name` doubles
    as the register's FREE TEXT (schemas_references.ControlReference.control_name), and a bare
    string lands in control_code and control_name both, so checking the name against the library
    would refuse every string entry whose text is not the library's own wording.
    """
    control_id, code, name = _reference_keys(entry)
    by_id = index.by_id.get(control_id) if control_id is not None else None
    if control_id is not None and by_id is None:
        # An integer id is only ever a library handle — there is no reading of it that is free
        # text, so a miss is the caller's error on every list, tolerant or strict.
        return _EntryOutcome(missing_id=control_id)
    by_code = index.by_code.get(_fold_for_the_library(code)) if code else None
    if by_id is not None and by_code is not None and by_id.control_id != by_code.control_id:
        return _EntryOutcome(
            conflict=(f"control_id {by_id.control_id} is {by_id.control_code!r} "
                      f"({by_id.control_name!r}) but control_code {by_code.control_code!r} is "
                      f"control_id {by_code.control_id} ({by_code.control_name!r}) — one entry "
                      "cannot name two controls"),
            conflicting_keys={"control_id": control_id, "control_code": code})
    if by_id is not None:
        return _EntryOutcome(control=by_id)
    if code and by_code is None:
        return _EntryOutcome(missing_code=code, code_was_a_guess=code == name)
    if by_code is not None:
        return _EntryOutcome(control=by_code)
    named = index.by_name.get(_fold_for_the_library(name), []) if name else []
    if len(named) > 1:
        return _EntryOutcome(missing_name=name,
                             ambiguous_codes=tuple(row.control_code for row in named))
    if named:
        return _EntryOutcome(control=named[0])
    return _EntryOutcome(missing_name=name)


def _unresolved_complaints(outcomes: list[_EntryOutcome], *,
                           names_are_free_text: bool) -> list[dict[str, Any]]:
    """Every complaint about one list as (msg, input) error bodies, in one place so the two policies
    cannot drift.

    The three "not active Control Library …" sentences keep the wording
    sessions._resolve_control_codes shipped with, verbatim for codes: integrators parse that
    message, and an entry named by an id or a name gets the same sentence with its own key so the
    shape stays one shape. `input` echoes THE OFFENDERS, not the whole list — the same choice that
    path made, and the reason its message was usable without a diff of the request.

    `names_are_free_text` is the whole difference between the two policies: on the register's
    baseline an unresolved or ambiguous NAME is text the caller is entitled to send, while an id or
    an explicit code key is a library handle whose miss is always their error.
    """
    missing_ids = [o.missing_id for o in outcomes if o.missing_id is not None]
    missing_codes = [o.missing_code for o in outcomes
                     if o.missing_code and not (names_are_free_text and o.code_was_a_guess)]
    unknown_names = [o.missing_name for o in outcomes
                     if o.missing_name and not o.ambiguous_codes and not names_are_free_text]
    complaints = [{"msg": o.conflict, "input": o.conflicting_keys}
                  for o in outcomes if o.conflict]
    if missing_ids:
        complaints.append({"msg": f"not active Control Library ids: {missing_ids}",
                           "input": missing_ids})
    if missing_codes:
        complaints.append({"msg": f"not active Control Library codes: {missing_codes}",
                           "input": missing_codes})
    if unknown_names:
        complaints.append({"msg": f"not Control Library control names: {unknown_names}",
                           "input": unknown_names})
    if not names_are_free_text:
        complaints += [
            {"msg": f"{o.missing_name!r} is the name of {len(o.ambiguous_codes)} active Control "
                    f"Library rows ({', '.join(o.ambiguous_codes)}) — name it by control_id or "
                    "control_code instead",
             "input": o.missing_name}
            for o in outcomes if o.ambiguous_codes]
    return complaints


def resolve_scenario_control_references(sess: Session, entries: list[Any] | None) -> list[int]:
    """Control_Library ids for a manual scenario's `mapped_controls`, IN THE CALLER'S ORDER.

    STRICT: every entry must resolve to an active library row, because these become
    Threat_Scenario_Control_Map rows and a plan may only ever recommend a real Control_Library row
    (pipeline.treatment._resolve_control_library_ids drops anything else). Unknown, retired and
    deleted are all the same 422, naming every offender at once — the shape the code-only path
    raised, kept because integrators parse it.

    None / [] means a scenario saved with NO control rows of its own; the plan-launch top-up
    (control_mapping.top_up_scenario_controls) then maps it the way an AI scenario is mapped. Codes
    a person sent are never re-mapped or replaced.

    A control named TWICE THROUGH DIFFERENT KEYS (`{"control_id": 1483}` beside
    `{"control_code": "CII-CID-195"}`, one row) is refused HERE, because only the library can see
    it: the schema's own duplicate check compares shared keys and these share none. Left alone, the
    two identical ids hit the map table's (scenario, control) key and the save 500s where the
    contract promises a 422.
    """
    entries = entries or []
    if not entries:
        return []
    index = _load_control_library_index(sess, entries)
    outcomes = [_resolve_one_control_reference(entry, index) for entry in entries]
    complaints = _unresolved_complaints(outcomes, names_are_free_text=False)
    first_entry_for: dict[int, int] = {}
    for position, outcome in enumerate(outcomes):
        if outcome.control is None:
            continue
        earlier = first_entry_for.setdefault(outcome.control.control_id, position)
        if earlier != position:
            complaints.append({
                "msg": f"entries {earlier + 1} and {position + 1} both name control "
                       f"{outcome.control.control_code!r} (control_id "
                       f"{outcome.control.control_id}) — one entry per control",
                "input": [entries[earlier], entries[position]]})
    if complaints:
        raise _validation_error(MANUAL_CONTROLS_LOC, complaints)
    return [outcome.control.control_id for outcome in outcomes if outcome.control]


def resolve_register_control_references(sess: Session,
                                        entries: list[Any] | None) -> list[dict[str, Any] | Any]:
    """The register's `existing_controls`, each entry canonicalized against the library or kept
    VERBATIM — the gap-analysis baseline, in the caller's order.

    TOLERANT, and that is the documented contract, not a shortcut: this list "doubles as the
    register's FREE TEXT: an entry that matches no library row is kept verbatim as the gap-analysis
    baseline, never rejected" (schemas_references.ControlReference.control_name), and
    TreatmentPlanBody publishes the same promise. So a name nothing answers to — or a name several
    rows answer to, where only the caller can say which — stays the text they sent, which is exactly
    what this field carried before it had a library reference at all.

    What is still refused: a `control_id` no active row has, a `control_code` KEY no active row has,
    and an id/code pair naming two different controls. All three are assertions only a library
    handle can make, and a register that believes it recorded control 1483 must not be told its risk
    has no controls.

    Returns canonical references (`_LibraryControl.as_reference`) for what resolved and the original
    entry for what did not; pipeline.treatment_input renders both into the baseline the model
    gap-analyses against. A row named twice through different keys is COLLAPSED to its first entry,
    for the reason schemas_references._collapse_controls_named_twice gives: a baseline entry listed
    twice covers exactly what it covered once.
    """
    entries = entries or []
    if not entries:
        return []
    index = _load_control_library_index(sess, entries)
    outcomes = [_resolve_one_control_reference(entry, index) for entry in entries]
    complaints = _unresolved_complaints(outcomes, names_are_free_text=True)
    if complaints:
        raise _validation_error(REGISTER_CONTROLS_LOC, complaints)
    seen: set[int] = set()
    kept = []
    for entry, outcome in zip(entries, outcomes, strict=True):
        if outcome.control is None:
            kept.append(entry)
        elif outcome.control.control_id not in seen:
            seen.add(outcome.control.control_id)
            kept.append(outcome.control.as_reference())
    return kept


# ---------------------------------------------------------------------------
# The manual scenario's threat triple
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ManualThreatNames:
    """The three threat-library rows a manual scenario names, AS NAMES — the library's own wording
    when an id resolved it, the caller's when they only sent a name.

    Names, not ids, because names are what the save already runs on end to end: grounding
    .find_category matches a category by name, dal.find_type_id_by_norm_name and
    sessions._library_identity match the type and threat by normalized name, and a type or threat
    the library does not hold is PROPOSED to the curators by name (dal.upsert_threat_type /
    upsert_threat_catalogue need a name to write). Handing ids into that path would need a second
    answer to "does this row exist" beside the one those functions already give — the ids are a new
    door into the same room, not a second room.

    The attribute names are deliberately `threat_category` / `threat_type` / `threat`: the fields
    ManualScenarioIn carried before the ids existed, so sessions._library_identity reads this object
    unchanged and its library-combination rules keep working on both doors.

    `threat_category` is None when the request named no category at all: the save then derives it
    from the resolved type/threat (sessions._write_manual_scenario) rather than refusing.
    """

    threat_category: str | None
    threat_type: str
    threat: str


#: One row of the triple: (id field, name field, model, pk column, name column, what it is called in
#: a 422, and whether a PENDING (IsActive=False) row still counts as "the library holds this").
#:
#: The IsActive rules are copied from the readers the save already trusts, NOT chosen here: a
#: category must be live (grounding.find_category filters IsActive AND IsDeleted — the six STRIDE
#: categories are never minted, so an inactive one is not a category), while a type or threat is
#: gone only when IsDeleted (dal.find_type_id_by_norm_name: "a PENDING (IsActive=False) row from an
#: earlier AI promotion still counts as 'this type exists'"). An id that resolved here but not
#: there would propose a duplicate of the very row the caller pointed at.
_THREAT_LIBRARY_ROWS = (
    ("threat_category_id", "threat_category_name", m.Threat_Category,
     m.Threat_Category.ThreatCategoryID, m.Threat_Category.ThreatCategoryName,
     "threat-library category", True),
    ("threat_type_id", "threat_type_name", m.Threat_Type,
     m.Threat_Type.ThreatTypeID, m.Threat_Type.ThreatTypeName, "threat-library type", False),
    ("threat_id", "threat_name", m.Threat_Catalogue,
     m.Threat_Catalogue.ThreatCatalogueID, m.Threat_Catalogue.ThreatName,
     "threat-library threat", False),
)


def resolve_manual_threat_identity(sess: Session, identity: Any) -> ManualThreatNames:
    """The category / type / threat a hand-written scenario names, resolved to NAMES.

    The type and the threat arrive as an id, a name, or both (ManualThreatIdentity guarantees at
    least one of each pair); the category may be absent altogether, and then comes back as None
    for the save to derive. The id WINS, and when both arrive they must agree: id 5 sent with the name
    "Spoofing" while the library files 5 as "Tampering" is a caller mistake that only the library
    can see, so refusing it is this function's job and not the schema's. Agreement is judged by
    `normalize_name`, the library's own identity key, so "Malware / Ransomware" and
    "malware/ransomware" agree here exactly as they are one row there.

    One indexed read per id actually sent — at most three, and none at all for the name-only payload
    every caller shipped before the ids existed.
    """
    resolved: dict[str, str] = {}
    for id_field, name_field, model, pk, name_column, called, must_be_active in _THREAT_LIBRARY_ROWS:
        sent_id = getattr(identity, id_field, None)
        sent_name = getattr(identity, name_field, None)
        if sent_id is None:
            resolved[name_field] = sent_name
            continue
        conditions = [pk == sent_id, model.IsDeleted == False]
        if must_be_active:
            conditions.append(model.IsActive == True)
        library_name = sess.execute(select(name_column).where(*conditions)).scalar()
        if library_name is None:
            raise _validation_error(
                ("body", "manual_scenario", id_field),
                [{"msg": f"{sent_id} is not a {called} id", "input": sent_id}])
        if sent_name and normalize_name(sent_name) != normalize_name(library_name):
            # The NAME field is the loc: the id is authoritative, so the name is the half the
            # caller has to change (or drop). Both values are in the message — a 422 that said
            # only "they disagree" leaves the caller unable to see which one the library holds.
            raise _validation_error(
                ("body", "manual_scenario", name_field),
                [{"msg": f"{id_field} {sent_id} is {library_name!r} in the threat library, "
                         f"not {sent_name!r}", "input": sent_name}])
        resolved[name_field] = str(library_name)
    return ManualThreatNames(threat_category=resolved["threat_category_name"],
                             threat_type=resolved["threat_type_name"],
                             threat=resolved["threat_name"])
