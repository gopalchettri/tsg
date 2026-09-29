"""How a REQUEST names a row that already exists in TSG's libraries — control rows and the
threat-library triple — for the remediation surface (`app/api/schemas_treatment.py`).

Why these models exist at all. Until 2026-09 a request named a control with a bare string and the
threat with three bare names, so the only handle a caller had was the one spelling TSG happened to
index on: `mapped_controls` took Control Library CODES, `existing_controls` took free text, and the
threat triple took names. A caller holding the library's integer ids — which is what a UI that
rendered a picker from the library actually holds — had to translate them back into text and hope
the spelling matched. The approved payload therefore lets every reference carry an id, a code, a
name, or any combination, and the server resolves whichever keys arrived.

Why they live in their OWN module rather than beside the bodies that use them:
schemas_treatment.py was already 942 lines of wire contract, and these models are referenced from
two different bodies (TreatmentPlanBody.existing_controls and ManualScenarioIn.mapped_controls),
so a shared home is where they belong even before the size argument.

NOTHING HERE TOUCHES THE DATABASE, on purpose and permanently. These models police SHAPE and
INTERNAL consistency only — "did you name anything at all", "is that id a possible id", "have you
named one control twice in one list". Whether id 1483 really is `CII-CID-195`, and whether
`threat_category_id` 5 really is named "Tampering", needs the library and is resolved by the route
(`app/api/sessions.py`) inside the same transaction that writes the scenario. Putting a lookup in
a pydantic validator would put a query on the request-parsing path, outside that transaction, and
give a second place where "does this control exist" is answered — two answers that can disagree.
"""
from __future__ import annotations

import re
from typing import Annotated, Any

from pydantic import AfterValidator, BeforeValidator, ConfigDict, Field, field_validator, model_validator

from app.api.schemas import _MAX_BATCH, ApiModel
from app.core.naming import normalize_name

# Control_Library.ControlCode is Unicode(100) ('CII-CID-001'..'CII-CID-1288'); 500 is the cap the
# register's free-text controls have always carried (TreatmentPlanBody._cap_control_text, now here).
_CONTROL_CODE_MAX = 100
_CONTROL_TEXT_MAX = 500

# What a Control Library code LOOKS like, without asking the library: alphanumeric groups joined by
# separators, at least one separator, at least one digit. It exists only to route a bare JSON
# string (see ControlReference._accept_a_plain_string) and is deliberately not a validation rule —
# nothing is ever rejected for failing to look like a code.
_LIBRARY_CODE_SHAPE = re.compile(r"[A-Za-z0-9]+(?:[-_./][A-Za-z0-9]+)+")

#: A control reference's keys, STRONGEST FIRST — the resolution order the approved contract names
#: ("id first, then code, then name"). Duplicate detection reads the same order, so the two can
#: never disagree about which key identifies an entry.
_CONTROL_KEYS_STRONGEST_FIRST = ("control_id", "control_code", "control_name")


def _looks_like_a_library_code(text: str) -> bool:
    """Is `text` shaped like 'CII-CID-195' rather than like 'Quarterly phishing simulation'?

    A digit is required so that hyphenated PROSE ("anti-malware", "e-mail gateway") stays prose,
    and the length bound keeps a long free-text entry that happens to contain a hyphen and a digit
    from being routed at the 100-character code cap and rejected — it stays free text, under the
    500-character text cap, exactly as it was accepted before this model existed.
    """
    return (len(text) <= _CONTROL_CODE_MAX
            and _LIBRARY_CODE_SHAPE.fullmatch(text) is not None
            and any(character.isdigit() for character in text))


def _blank_is_absent(value: Any) -> Any:
    """An empty or whitespace-only value means "this key was not filled in", not a failure.

    Same rule and same reason as TreatmentPlanBody._blank_is_absent: the UI sends "" for a control
    the user left blank, and a typed field ("control_id": "") would otherwise 422 the whole request
    — the caller gets no plan at all rather than a plan without that one value.
    """
    return None if isinstance(value, str) and not value.strip() else value


class ControlReference(ApiModel):
    """One control, named by its library id, its library code, its name, or any mix of the three.

    At least one key must be present and non-blank. A reference that names nothing cannot be
    resolved, cannot be stored and cannot be reported back, so accepting it would mean silently
    dropping a control the caller believes they sent — the 422 names all three keys so the caller
    can see which ones it had to choose from.

    `extra="forbid"` for the reason TreatmentPlanBody documents: a misspelled key is a 422 naming
    it, never a silent drop. `"control_code_"` accepted-and-ignored would look exactly like a
    control the caller sent and TSG lost, which is the failure mode that flag exists to prevent.

    A BARE JSON STRING is also a valid entry (see _accept_a_plain_string) — every caller shipped
    before this model sent lists of strings, and both published payload forms still do.

    NOT VALIDATED HERE, deliberately: whether the id exists, whether the code exists, and whether
    an id and a code that arrive together name the SAME control. All three need the library; the
    route resolves them and raises the 422 that names the mismatch. This model never guesses.
    """
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    control_id: int | None = Field(
        default=None, gt=0,
        description=("Control_Library.ControlLibraryID — the library's INTERNAL id, not the number "
                     "inside the code (CII-CID-089 is id 1377). Must be positive: 0 and negative "
                     "ids are no row at all, and accepting one would turn a caller's arithmetic "
                     "slip into 'control not found' much later, or into no control at all."))
    control_code: str | None = Field(
        default=None, max_length=_CONTROL_CODE_MAX,
        description=("Control_Library.ControlCode, e.g. 'CII-CID-195'. Matched case-insensitively, "
                     "the same way the library lookup matches it."))
    control_name: str | None = Field(
        default=None, max_length=_CONTROL_TEXT_MAX,
        description=("The control's library name, e.g. 'Mobile Code'. In `existing_controls` this "
                     "field doubles as the register's FREE TEXT: an entry that matches no library "
                     "row is kept verbatim as the gap-analysis baseline, never rejected — that is "
                     "what this field was before it had a name of its own."))

    @model_validator(mode="before")
    @classmethod
    def _accept_a_plain_string(cls, value: Any) -> Any:
        """A bare string is a reference too: `"CII-CID-220"` and `"Quarterly phishing simulation"`.

        The string ALWAYS lands in `control_name`, and ADDITIONALLY in `control_code` when it is
        shaped like a library code. Filling both is what makes the guess harmless: if
        _looks_like_a_library_code is wrong about a free-text entry ("ISO-27001 gap review"), the
        exact text the caller sent is still in `control_name`, so the register's baseline cannot
        lose an entry to a heuristic. Resolution reads the code first (contract: id, then code,
        then name), so a real code is still resolved as a code.

        Consequence the resolver must know: `control_code == control_name` is normal for an entry
        that arrived as a string, and is not a caller mistake.
        """
        if not isinstance(value, str):
            return value
        text = value.strip()
        return {"control_code": text if _looks_like_a_library_code(text) else None,
                "control_name": text}

    _blank_is_absent = field_validator(*_CONTROL_KEYS_STRONGEST_FIRST,
                                      mode="before")(_blank_is_absent)

    @classmethod
    def __get_pydantic_json_schema__(cls, core_schema, handler):
        """Publish the string form too: `anyOf[ControlReference, string]` wherever a request takes
        one of these.

        Load-bearing, not cosmetic — the same argument the _RATING annotation makes in
        schemas_treatment.py. _accept_a_plain_string means the SERVER takes a bare string, but the
        generated schema would say object-only, and a client generated from /openapi.json builds a
        class where a string used to go. Every caller shipped before this model sends strings, and
        the approved contract says they still work; publishing object-only would tell exactly those
        callers to migrate, in the one document they are entitled to trust.

        Serialization schemas are left alone (nothing serializes a ControlReference today, and a
        RESPONSE that ever does should say `object`, because that is all it would ever emit).
        """
        published = handler(core_schema)
        if handler.mode != "validation":
            return published
        return {"anyOf": [published,
                          {"type": "string", "maxLength": _CONTROL_TEXT_MAX,
                           "description": "A Control Library code ('CII-CID-220'), or free text "
                                          "for a control the library does not hold."}]}

    @model_validator(mode="after")
    def _names_at_least_one_control(self) -> ControlReference:
        if self.control_id is None and not self.control_code and not self.control_name:
            raise ValueError("a control entry must name the control: send at least one of "
                             "control_id, control_code or control_name")
        return self

    def identity_keys(self) -> dict[str, Any]:
        """The comparison keys this entry carries, strongest first — `{key_name: value}`.

        Strings compare through `normalize_name`, the identity key the library's own upserts use,
        so 'cii-cid-195', 'CII-CID-195' and 'Mobile  Code' vs 'Mobile Code' are ONE control here
        exactly as they are one row there.
        """
        carried = {}
        for key in _CONTROL_KEYS_STRONGEST_FIRST:
            value = getattr(self, key)
            if value is not None:
                carried[key] = normalize_name(value) if isinstance(value, str) else value
        return carried


def _control_named_twice(first: ControlReference, second: ControlReference) -> str | None:
    """`"control_code=CII-CID-195"` when these two entries visibly name ONE control, else None.

    Only the STRONGEST key the two entries SHARE is compared. Two entries that both carry ids and
    whose ids differ are two different controls, full stop — even if their names happen to match,
    which is why a name is never compared once both sides carry something stronger. And entries
    with no shared key (`{"control_id": 1483}` vs `{"control_code": "CII-CID-195"}`) are NOT judged
    here at all: they may well be the same control, but only the library can say so, and the route
    refuses that collision when it resolves them.
    """
    left, right = first.identity_keys(), second.identity_keys()
    for key in _CONTROL_KEYS_STRONGEST_FIRST:
        if key in left and key in right:
            return f"{key}={getattr(first, key)!r}" if left[key] == right[key] else None
    return None


def _drop_entries_naming_nothing(value: Any) -> Any:
    """Drop `""` and `"   "` LIST ENTRIES before they are parsed as references.

    Not the same rule as ControlReference's own "name at least one key" 422, and the difference is
    deliberate. A shipped UI sends `["", ""]` for a form whose control rows are empty — the
    documented "an empty list means a risk with no controls" semantics has to survive that, and it
    did survive it (TreatmentPlanBody._cap_control_text dropped blanks for exactly this reason).
    An OBJECT that names nothing, `{}` or `{"control_code": ""}`, is a different thing: the caller
    built an entry, so losing it silently would lose a control they believe they sent — that is the
    422. Blank strings in, blank strings dropped; empty objects in, 422 naming the three keys.
    """
    if not isinstance(value, list):
        return value
    return [entry for entry in value if not (isinstance(entry, str) and not entry.strip())]


def _reject_controls_named_twice(entries: list[ControlReference]) -> list[ControlReference]:
    """One entry per control — a repeat is a 422 naming the key that gave it away.

    Inherited unchanged in spirit from ManualScenarioIn._distinct_codes, which compared codes
    case-insensitively because the control-map table's key is (scenario, control): a repeat wrote
    one row and silently lost the other, so the scenario ended up with fewer controls than the
    caller listed and nothing said so. Now that one control can be named through three different
    keys, the comparison follows — `{"control_id": 1483}` twice is the same duplicate that
    `"CII-CID-195"` twice always was.

    Pairwise, which is O(n^2) on a list `_MAX_BATCH` (50) caps — 1,225 comparisons at the very
    worst, all in memory, no IO. A keyed set would be linear but would have to pick ONE key per
    entry in advance, which is precisely the mistake _control_named_twice exists to avoid. If that
    cap ever rises past a few hundred, index by key type instead (three dicts, one per key).
    """
    for index, entry in enumerate(entries):
        for earlier in entries[:index]:
            named_twice = _control_named_twice(entry, earlier)
            if named_twice:
                raise ValueError(f"the same control is named twice ({named_twice}) — one entry "
                                 f"per control")
    return entries


def _collapse_controls_named_twice(entries: list[ControlReference]) -> list[ControlReference]:
    """One entry per control, the FIRST one kept and the repeat dropped, order preserved.

    Why this list drops what the other one refuses: the register's `existing_controls` is a
    gap-analysis BASELINE, not a set of rows to write. A control listed twice covers exactly what
    it covered once, so TreatmentPlanBody._cap_control_text has always collapsed repeats silently,
    and the snapshot builder collapses them AGAIN downstream (treatment_input.build_existing_
    controls_block) because the regenerate path never re-enters this schema. Turning that into a
    422 would start rejecting requests that have been valid — and correct — since the endpoint
    shipped, over something the pipeline is already designed to tolerate.

    What it fixes rather than preserves: the old collapse compared the raw strings, so
    ["CII-CID-213", "cii-cid-213"] put ONE control into the baseline twice and the model was shown
    the same control as two. Sharing _control_named_twice with the strict list is what makes the
    two fields agree on what "the same control" means, which is the half that was really wrong.
    """
    kept: list[ControlReference] = []
    for entry in entries:
        if not any(_control_named_twice(entry, earlier) for earlier in kept):
            kept.append(entry)
    return kept


#: The register's existing controls: blank entries dropped, repeats COLLAPSED, order preserved, at
#: most _MAX_BATCH entries, each string capped by ControlReference's own field limits.
RegisterControlReferenceList = Annotated[
    list[ControlReference],
    BeforeValidator(_drop_entries_naming_nothing),
    AfterValidator(_collapse_controls_named_twice),
    Field(max_length=_MAX_BATCH),
]

#: A scenario's own controls: the same rules, except that a repeat is REFUSED rather than
#: collapsed — see _reject_controls_named_twice for why the two differ.
ScenarioControlReferenceList = Annotated[
    list[ControlReference],
    BeforeValidator(_drop_entries_naming_nothing),
    AfterValidator(_reject_controls_named_twice),
    Field(max_length=_MAX_BATCH),
]

#: The threat-library rows a manual scenario names, and the two keys each may be named by.
_THREAT_IDENTITY_PAIRS = (("threat_category_id", "threat_category_name"),
                          ("threat_type_id", "threat_type_name"),
                          ("threat_id", "threat_name"))


class ManualThreatIdentity(ApiModel):
    """The threat a hand-written scenario is about: a library CATEGORY, TYPE and THREAT, each
    named by its integer id, its name, or both. A base of ManualScenarioIn — the six fields are
    flat on the wire, as the approved payload has them, and live here so their rules do not add a
    seventh screen to schemas_treatment.py.

    The TYPE and the THREAT must be named SOMEHOW: id or name, or both. A row named by neither
    cannot be resolved or proposed. The CATEGORY is optional: the library files every type under a
    category, so when neither category field arrives the route derives it from the resolved
    type/threat (sessions._write_manual_scenario), and saves the scenario without one when the
    library records none.

    BOTH VALUES ARE CARRIED THROUGH when both arrive, and neither is ever dropped because the
    other is present. The id is authoritative and the name is what the 422 message has to be able
    to quote back; more importantly, id 5 sent with name "Spoofing" when the library files 5 as
    "Tampering" is a caller mistake that MUST be refused rather than silently resolved by id — and
    only the library can see it, so this model has to hand the route both halves to compare.

    What is refused here: a pair that names nothing, and an id that cannot be a row (0, negative)
    or a name that is punctuation only. What is deliberately left to the route: existence, the
    id-vs-name mismatch above, and the combination rules (a threat must arrive with the type the
    library files it under, and a type with one of its categories).
    """

    threat_category_id: int | None = Field(
        default=None, gt=0,
        description="Threat_Category.ThreatCategoryID. Optional: when neither category field is "
                    "sent, the category is derived from the threat type (the one the library files "
                    "it under), or left unset when the library records none. One of the six STRIDE "
                    "categories; they are never minted, so an id or name the library does not hold "
                    "is a 422 listing the six.")
    threat_category_name: str | None = Field(
        default=None, max_length=200,
        description="The category's name, e.g. 'Tampering'. Optional, derived from the threat type "
                    "when omitted. Interchangeable with threat_category_id; send both and they "
                    "must agree.")
    threat_type_id: int | None = Field(
        default=None, gt=0,
        description="Threat_Type.ThreatTypeID. A type the library does not hold is PROPOSED to the "
                    "curators as a pending row stamped 'manual' with you as its creator — which "
                    "needs a name, so propose by name, not by an id nobody issued.")
    threat_type_name: str | None = Field(
        default=None, max_length=300,
        description="The type's name, e.g. 'Engineering Workstation Compromise'. Interchangeable "
                    "with threat_type_id; send both and they must agree. A threat the library "
                    "files under another type is a 422 on this field naming that type.")
    threat_id: int | None = Field(
        default=None, gt=0,
        description="Threat_Catalogue.ThreatCatalogueID — the LIBRARY threat's integer id (126), "
                    "never the per-session scenario uuid the results endpoints show.")
    threat_name: str | None = Field(
        default=None, max_length=500,
        description="The threat's name, e.g. 'Engineering workstation compromise'. Interchangeable "
                    "with threat_id; send both and they must agree. Proposed to the curators like "
                    "the type when the library does not hold it.")

    _blank_is_absent = field_validator(
        *(field for pair in _THREAT_IDENTITY_PAIRS for field in pair),
        mode="before")(_blank_is_absent)

    @field_validator("threat_category_name", "threat_type_name", "threat_name")
    @classmethod
    def _names_a_real_row(cls, value: str | None) -> str | None:
        """Letters or digits required — punctuation alone would name a library row nothing.

        Kept verbatim from ManualScenarioIn._real_name, which exists because a pending curator row
        called '---' is a row no curator can act on and no caller can find again.
        """
        if value is not None and not normalize_name(value):
            raise ValueError("must contain letters or digits")
        return value

    @model_validator(mode="after")
    def _every_library_row_is_named(self) -> ManualThreatIdentity:
        # The category pair is skipped: absent means "derive it from the type" (class docstring).
        unnamed = [f"{id_field} or {name_field}"
                   for id_field, name_field in _THREAT_IDENTITY_PAIRS
                   if id_field != "threat_category_id"
                   and getattr(self, id_field) is None and not getattr(self, name_field)]
        if unnamed:
            raise ValueError("name each threat-library row by id, by name, or both: "
                             + "; ".join(unnamed))
        return self
