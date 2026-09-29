"""The frozen treatment-plan LLM context, one block at a time: plain data in, plain data out.

WHY THIS MODULE EXISTS. This was one 173-line function (treatment.build_treatment_input) doing
seven jobs in a single pass: asset/base context, the threat block, the scenario block, the
library-controls read with its degrade-to-empty fallback, the register's existing-controls block,
three register-consistency advisories, and the final snapshot assembly. Not one of them could be
tested piecewise — a check on the rating arithmetic had to build a whole session row, a whole
scenario row and a fake Session, call the whole builder, and read the answer back out of a nested
dict. Split here as functions over already-parsed data (a Session only where a DB read is genuinely
required) so each job unit-tests on its own, with plain dicts and no fixtures.
treatment.build_treatment_input remains the one orchestrator that calls these and assembles the
snapshot; it alone owns the KEY ORDER.

WHY THE SPLIT CANNOT CHANGE BEHAVIOUR. InputSnapshotJSON is a persisted record format: the
regenerate route reads it back (treatment.regen_risk_input_from_snapshot) and the evidence endpoint
serves it verbatim. A snapshot key, a key's ORDER, a warning's wording or a warning's POSITION in
the list is therefore data, not presentation — every function here reproduces its original exactly,
and the `warnings` list is assembled in the original order by the orchestrator.

IMPORT DIRECTION. This module must never import app.pipeline.treatment (which imports it, and
imports treatment_schedule): the shared date helper `as_date` comes from treatment_schedule, which
imports neither.
"""
from __future__ import annotations

from datetime import datetime
from decimal import MAX_PREC, ROUND_HALF_UP, Decimal, InvalidOperation, localcontext
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import ContentSource
from app.core.logging import get_logger
from app.core.security import redact
from app.db import dal
from app.db import models as m
from app.pipeline import grounding
from app.pipeline.treatment_schedule import as_date

log = get_logger(__name__)


def _clip(text: str | None) -> str | None:
    """redact() + length cap for one free-text value crossing into the snapshot.

    THE ONE DOOR: every free-text value in every block below enters through this function, never
    through a bare redact(). It was applied per call site until 2026-09 — the register's controls and
    the library's control descriptions — while the scenario block (title, statement, risk statement,
    each involved system's justification), the threat block (category, type, name, actors) and
    impacted_business_division went through redact() alone, so the claim two paragraphs down
    ("every free-text value entering the snapshot goes through the same cap") was false of four
    paths. The uncapped ones were the AI-authored scenario text, which has NO length bound anywhere
    (ScenarioNarrative is extra="allow" and tasks._scrub_model_output only redacts), so an oversized
    value was frozen into InputSnapshotJSON, re-sent on every regeneration, and crowded the
    register's own controls out of the context window — with no truncation log, which is what made a
    degraded run indistinguishable from a clean one.

    Per-field cap applied to free text at snapshot time (house analog: intel items truncate before
    entering the prompt). Pydantic max_length bounds reject oversized fields at the boundary; this is
    defense-in-depth for anything that slips a path around them. The cap lives in
    Settings.treatment_free_text_cap (default 2000)."""
    cleaned = redact(text)
    cap = get_settings().treatment_free_text_cap
    if cleaned and len(cleaned) > cap:
        # Marked and logged, never silent: an unmarked mid-word cut can invert the meaning of a
        # control description the model then gap-analyses against.
        log.warning("treatment.free_text_truncated", cap=cap, length=len(cleaned))
        return cleaned[:cap] + " [truncated]"
    return cleaned


# ---------------------------------------------------------------------------
# Library-controls read (TSG's own tables).
#
# Every multi-table statement is built by a module-level `_*_stmt` function so treatment.py's
# __main__ self-check can .compile() each one WITHOUT a database — plain Select.compile() raises
# InvalidRequestError on a malformed join and CompileError on a bad column, which is exactly
# the bug class that once shipped here as an accidental self-join. New statements MUST
# follow this pattern and be added to that self-check list.
# ---------------------------------------------------------------------------
def _library_map_stmt(scenario_id: str):
    cmap, lib = m.Threat_Scenario_Control_Map, m.Control_Library
    return (
        select(cmap.MapRank, cmap.Score, lib.ControlLibraryID, lib.ControlCode, lib.ITOT,
            lib.Domain, lib.ControlName, lib.ControlDescription)
        .join(lib, lib.ControlLibraryID == cmap.ControlLibraryID)
        .where(cmap.ScenarioID == scenario_id,
            lib.IsActive == True, lib.IsDeleted == False)
        .order_by(cmap.MapRank)
    )


def _standards_stmt(control_library_ids: list[int]):
    smap, std = m.Control_Library_Standard_Map, m.Control_Standard
    return (
        select(smap.ControlLibraryID, std.StandardName)
        .join(std, std.StandardID == smap.StandardID)
        .where(smap.ControlLibraryID.in_(control_library_ids),
            std.IsActive == True, std.IsDeleted == False)
        .order_by(std.StandardName)
    )


def _standards_by_control(sess: Session,
                        control_library_ids: list[int]) -> tuple[dict[int, list[str]], list[str]]:
    """{ControlLibraryID: [standard names]} for the mapped controls — WITH ITS OWN failure boundary.

    Its own try, not the caller's, because this is the DECORATION and the map/library join above is
    the payload. Sharing one boundary meant a broken Control_Standard pair — a database carrying
    Control_Library and Threat_Scenario_Control_Map from a revision before the standards tables
    existed, a SELECT grant that omits them, or a timeout or deadlock hitting only this second
    statement — threw away a control map that had ALREADY read fine, and then reported "library
    control lookup failed", a fact about the whole map, for a failure of its garnish. The
    consequences were not cosmetic: prompts.treatment_prompt rule 2 turns an empty library_mapped
    into control_coverage "gaps" with NO recommended controls, so such a plan recommended nothing at
    all, and on regenerate the caller's lookup_failed flag additionally suppressed the
    dropped-control comparison (treatment._dropped_control_warnings), so the reasons vanished too.

    The rollback is required rather than tidy: after a DBAPI error SQLAlchemy refuses further use of
    the transaction, and this POST still has reads and an INSERT ahead of it. It is safe at this
    point for the reason the caller's own except documents — no uncommitted writes exist yet — and
    the already-materialized map rows are plain values, so they survive it.
    """
    try:
        rows = sess.execute(_standards_stmt(control_library_ids)).all()
    except Exception:
        sess.rollback()
        log.warning("treatment.control_standards_read_failed", exc_info=True)
        return {}, ["control standards could not be read — mapped controls are listed without "
                    "their standards"]
    standards: dict[int, list[str]] = {}
    for control_library_id, standard_name in rows:
        standards.setdefault(control_library_id, []).append(standard_name)
    return standards, []


def _library_controls(sess: Session, scenario_id: str) -> tuple[list[dict[str, Any]], list[str]]:
    """The scenario's Step-4 grounded Control_Library rows, as plain dicts. Same join shape as
    sessions._query_controls, deliberately re-issued here rather than imported — API→pipeline
    is the only allowed import direction, and pulling the session router in would drag the
    whole API layer into every worker.

    control_description and mapping_relevance are here because the plan's whole first job is
    deciding whether a mapped control is ALREADY COVERED by the register's controls. With only the
    code, domain and name the model had to judge that from a title — it could not read what the
    control actually requires, nor see how well Step 4 thought it matched the scenario (Score, the
    raw rerank 0-100; None on rows mapped before scoring existed). itot travels for the same
    reason: an IT control offered against an OT scenario is a mapping the reviewer must see.

    _clip, not the raw text: this is curated library text, not user input, so redaction is
    incidental — but InputSnapshotJSON is frozen into the row and re-sent to the model on every
    regeneration, and ControlDescription is UnicodeText with no length bound of its own. One
    unusually long description across ~20 mapped controls would crowd the prompt (and the
    register's own controls) out of the context window, so every free-text value entering the
    snapshot goes through the same cap.

    Returns (controls, warnings): the warnings are the STANDARDS sub-read's, which degrades on its
    own — see _standards_by_control for the plan this once silently emptied."""
    rows = sess.execute(_library_map_stmt(scenario_id)).mappings().all()
    std_names, warnings = ({}, [])
    if rows:
        std_names, warnings = _standards_by_control(
            sess, sorted({r["ControlLibraryID"] for r in rows}))
    return [
        {"control_library_id": r["ControlLibraryID"], "control_code": r["ControlCode"],
        "itot": r["ITOT"], "domain": r["Domain"], "control_name": r["ControlName"],
        "control_description": _clip(r["ControlDescription"]),
        "mapping_relevance": r["Score"],
        "standards": std_names.get(r["ControlLibraryID"], [])}
        for r in rows
    ], warnings


def read_library_controls_for_snapshot(
        sess: Session, scenario_row: dict) -> tuple[list[dict[str, Any]], list[str], bool]:
    """The snapshot's library-mapped controls, the warnings they earn, and whether the READ FAILED.

    Degrade-to-empty, same rationale as sessions._controls_by_output: a DB where
    Control_library.sql hasn't run yet must not 500 the POST. The warnings are deliberately
    DISTINCT — a hard lookup failure must never masquerade as an empty map, because "no controls
    exist for this scenario" is a reviewable fact about the scenario while "we could not look" is a
    fact about the database, and a reviewer acting on the wrong one draws the wrong conclusion. A
    THIRD wording belongs to the standards sub-read (_standards_by_control), for the same reason
    one step smaller: controls listed without their standards is not a map that could not be read.

    `lookup_failed` is RETURNED, not just warned about: the caller's dropped-control comparison is
    only meaningful against a map that was actually read (a failed read makes every previous
    control look dropped), so that third value is the guard on a rule this function does not own.

    Takes the whole `scenario_row`, not just its id: the top-up floor warning needs ScenarioSource
    to tell an AI scenario (which the top-up was supposed to fill) from a manual one (which it
    never touches)."""
    warnings: list[str] = []
    lookup_failed = False
    try:
        library_mapped, standards_warnings = _library_controls(sess, scenario_row["ScenarioID"])
        warnings += standards_warnings
    except Exception:
        sess.rollback()  # no uncommitted writes exist at this point in the POST
        log.warning("treatment.library_controls_read_failed", exc_info=True)
        library_mapped, lookup_failed = [], True
        warnings.append("library control lookup failed — plan generated without mapped controls")
    if not library_mapped and not lookup_failed:
        warnings.append("no library-mapped controls for this scenario (Step-4 map is empty)")
    # An AI scenario can reach a plan short of the mapping floor — say so, or 2-of-5 reads like a
    # full plan.
    settings = get_settings()
    # control_map_min_count, NOT the deprecated remediation_control_min_count: the minimum is now
    # one number applied at MAPPING time and again by the top-up, so a reviewer reading this warning
    # sees the shortfall against the floor the pipeline really used. Reading the deprecated spelling
    # meant an operator who raised the live setting got a warning measured against the old default.
    floor = settings.control_map_min_count
    # NOT gated on remediation_control_top_up_enabled. Being under the floor is ARITHMETIC about
    # this scenario's map; whether the top-up feature is switched on is configuration. The gate used
    # to ask the second question, so a deployment that turned the top-up off lost the signal
    # entirely and a 2-of-5 map generated a plan that read exactly like a full one — the very
    # symptom this warning exists to prevent. The flag decides the WORDING instead, so the sentence
    # stays true either way: a disabled top-up never ran and must not be blamed for not reaching a
    # floor it was never asked to reach.
    if (0 < len(library_mapped) < floor
            and str(scenario_row.get("ScenarioSource") or "") != str(ContentSource.manual)):
        why = ("top-up could not reach the floor" if settings.remediation_control_top_up_enabled
            else "control top-up is switched off for this deployment")
        warnings.append(f"only {len(library_mapped)} of the minimum {floor} library-mapped "
                        f"controls — {why}")
    return library_mapped, warnings, lookup_failed


# ---------------------------------------------------------------------------
# TSG-derived blocks (pure: already-parsed rows and JSON blobs in, dicts out)
# ---------------------------------------------------------------------------
def build_threat_block(scenario_row: dict) -> tuple[dict[str, Any] | None, list[str]]:
    """The snapshot's `threat` block, or None plus one warning when the linkage is broken.

    Both hops to Identified_Threat are OUTER joins, so a broken linkage nulls the columns; an
    explicit null + warning beats a silently empty block.

    Actors come through the ONE shared reader (the stored blob is a dict, not a list), and
    deliberately through the RAW one: this plan treats a scenario the model ALREADY wrote from
    that same raw list (dal.active_threats feeds scenario_prompt stored_actors), so a
    validated_actors gate would hand the treatment [] for every unverified threat and plan
    against adversaries the scenario it is treating names out loud."""
    threat_fields: dict[str, Any] = {
        "category": _clip(scenario_row.get("ThreatCategory")),
        "type": _clip(scenario_row.get("LibraryThreatType") or scenario_row.get("ThreatType")),
        "name": _clip(scenario_row.get("LibraryThreatName") or scenario_row.get("ThreatName")),
        "actors": [_clip(a) for a in grounding.stored_actors(scenario_row.get("ThreatActorsJSON")) if a],
    }
    if not threat_fields["type"] and not threat_fields["name"]:
        return None, ["threat join returned no rows — plan generated without threat identity"]
    return threat_fields, []


def build_scenario_block(scenario_json: dict[str, Any]) -> dict[str, Any]:
    """The snapshot's `scenario` block from the stored ScenarioJSON.

    `scenario_suggested` is GONE from the snapshot: the LLM no longer proposes controls
    (library-first redesign), so library_mapped is the whole TSG-derived control input.
    Legacy snapshots still carrying the key are inert — nothing reads it back."""
    return {
        # _clip, not redact: this is the model's OWN text, which carries no length bound anywhere
        # upstream (ScenarioNarrative is extra="allow"), so it is the main path an oversized value
        # used to enter the frozen snapshot through. See _clip's "THE ONE DOOR".
        "scenario_title": _clip(scenario_json.get("scenario_title")),
        "scenario_statement": _clip(scenario_json.get("scenario_statement")),
        "risk_statement": _clip(scenario_json.get("risk_statement")),
        # The scenario's OWN involved systems. Without these the model must judge
        # applicable_to_all_subsystems against `supporting_systems` — the session's whole
        # raw scope — and so is asked to cover systems this scenario already ruled out.
        # Empty for pre-rename scenarios and for sessions with no supporting systems; the
        # prompt names that fallback explicitly, so no warning is warranted. A system absent
        # here is out of scope for this scenario — there is no separate "applicable: false"
        # entry any more (tasks.py::_ground_entry_points only ever records involvement).
        "supporting_systems_involved": [
            {"supporting_system": _clip((a or {}).get("supporting_system")),
            "is_entry_point": bool((a or {}).get("is_entry_point")),
            "justification": _clip((a or {}).get("justification"))}
            for a in scenario_json.get("supporting_systems_involved") or []
            if isinstance(a, dict)],
    }


def register_control_text(entry: Any) -> str | None:
    """ONE register `existing_controls` entry as the ONE line the model gap-analyses against, or
    None when it names nothing a model could read.

    WHAT AN ENTRY CAN BE, and why this function exists. Since 2026-09 the request's list holds
    library REFERENCES as well as free text (app/api/schemas_references.ControlReference), and
    app/api/library_references resolves the references against the library before the snapshot is
    built. A RESOLVED reference (a dict carrying `control_id`) is kept as an OBJECT by
    build_existing_controls_block and never reaches here; this renders everything else — a plain
    string, an unresolved dumped ControlReference (free text in `control_name`), or a reference
    MODEL a caller handed in without resolving. It takes every shape because the assumption that
    the list was `list[str]` is what crashed the live POST: the old comprehension called `.strip()`
    on each entry, and a dict has no `.strip()`. The REGENERATE path legitimately hands it plain
    strings read back out of a legacy snapshot.

    A code AND a name (an unresolved entry that carries both, or a caller's unresolved reference)
    render as "<code> — <name>": this list is the gap-analysis BASELINE, and prompts.treatment_prompt
    rule 2 tells the model to compare BY MEANING, so a bare 'CII-CID-198' would be worse than the
    free text it replaced.
    """
    if isinstance(entry, str):
        return entry.strip() or None
    # A dict on both live paths (the route dumps the body with mode="json", and a stored snapshot
    # holds JSON), but read by duck typing rather than by type test: an unresolved entry is handed
    # back to the caller AS IT ARRIVED, so a caller that passes the ControlReference MODELS instead
    # of their dump must not have its baseline entries silently dropped. Returning None for an
    # object it did not recognise is the same class of bug as the `.strip()` this function replaced —
    # one shape assumed, every other shape lost — and this list is the only record of what the
    # register already has in place.
    read = entry.get if isinstance(entry, dict) else lambda key: getattr(entry, key, None)
    code = str(read("control_code") or "").strip()
    name = str(read("control_name") or "").strip()
    if code and name and code != name:
        return f"{code} — {name}"
    # code == name is NORMAL, not a caller mistake: ControlReference._accept_a_plain_string fills
    # both keys from one code-shaped string, so 'CII-CID-220' arrives twice over. One copy is enough.
    if name or code:
        return name or code
    control_id = read("control_id")
    # An id-only entry reaches here ONLY if it never met the resolver (which refuses an id no active
    # row has). It is still the register's claim about its own risk, so it is reported rather than
    # dropped: a reviewer seeing "control_id 1483" can look it up, where a silently missing baseline
    # entry would make the gap analysis recommend a control the register already has.
    return f"control_id {control_id}" if control_id is not None else None


def build_existing_controls_block(risk_input: dict[str, Any],
                                library_mapped: list[dict[str, Any]]) -> dict[str, Any]:
    """The snapshot's `existing_controls` block — TSG's mapped controls beside the register's own.

    This block MIXES the two halves of the context on purpose (it is the gap-analysis input), which
    is why regen_risk_input_from_snapshot names its register-sourced keys exhaustively rather than
    carrying the block wholesale.

    THE REGISTER MATCH IS DECIDED HERE, IN CODE. A register entry that resolved to a library row
    (a dict with `control_id`, from library_references.resolve_register_control_references) stays an
    OBJECT — id, code, name, and the domain/description the resolver fetched — and every
    library_mapped row whose control_library_id is among those ids is flagged `covered_by_register`.
    Until 2026-09 the resolved id was flattened into a "CODE — NAME" string, so whether a mapped
    control the register already named was covered was left to the model's reading of two strings;
    the flag makes it a fact the worker enforces (treatment._register_covered_warnings) and the model
    only judges the FREE-TEXT entries by meaning. `control_id` is kept in the stored snapshot (the
    regenerate path feeds these objects straight back) and stripped from the prompt by
    prompts._scrub_db_keys. Free text renders through register_control_text as before.

    Blank-stripped AND deduped HERE (by id for objects, by text for strings), not only in the schema
    validator: the regenerate path rebuilds risk_input from the stored snapshot and never re-enters
    the schema, so a legacy snapshot's blanks/dupes would otherwise re-enter the baseline forever."""
    register: list[Any] = []
    seen: set[tuple[str, Any]] = set()
    for entry in risk_input.get("existing_controls") or []:
        if isinstance(entry, dict) and entry.get("control_id") is not None:
            item: Any = {k: v for k, v in {
                "control_id": entry["control_id"], "control_code": entry.get("control_code"),
                "control_name": entry.get("control_name"), "domain": entry.get("domain"),
                "control_description": _clip(entry.get("control_description"))}.items()
                if v is not None}
            key = ("id", entry["control_id"])
        else:
            item = _clip(register_control_text(entry))
            key = ("text", item)
        if not item or key in seen:
            continue
        seen.add(key)
        register.append(item)
    register_ids = {e["control_id"] for e in register if isinstance(e, dict)}
    library_mapped = [{**c, "covered_by_register": c.get("control_library_id") in register_ids}
                      for c in library_mapped]
    return {
        "library_mapped": library_mapped,
        "library_mapped_count": len(library_mapped),
        "register_controls": register,
        # How many MAPPED controls the register already names — the count the reviewer reads against
        # library_mapped_count, and the number of recommendations the worker will refuse.
        "register_matched_count": sum(1 for c in library_mapped if c["covered_by_register"]),
        "applied_to_all_subsystems": risk_input.get("existing_controls_all_subsystems"),
        # A justification whose Yes/No answer is absent justifies nothing — dropped rather
        # than handed to the model as an orphan (the schema does not pair-validate the two).
        "applied_to_all_subsystems_justification":
            _clip(risk_input.get("existing_controls_all_subsystems_justification"))
            if risk_input.get("existing_controls_all_subsystems") is not None else None,
    }


# ---------------------------------------------------------------------------
# The register's numbers: normalization, the assessment window, the advisories
# ---------------------------------------------------------------------------
def _dec(v: Any) -> Decimal | None:
    """A Decimal from an int, float, Decimal or numeric string — None if it is none of those.

    The numeric twin of treatment_schedule.as_date, and for the same reason: api/treatment.py dumps the body
    with mode="json", which serializes pydantic's Decimal fields to STRINGS, while regenerate feeds
    back whatever JSON the snapshot holds (int on legacy rows, float on newer ones). Normalizing
    every accepted shape HERE — rather than making one producer emit a tidier type — is what stops
    a future caller reintroducing the bug by choosing a different dump mode.

    str() FIRST: Decimal(3.3) is 3.2999999999999998…, Decimal('3.3') is exactly 3.3. Returning None
    on a malformed legacy blob is deliberate — it folds into collect_register_consistency_warnings'
    existing "no scores" guard instead of adding a branch, and instead of raising inside a POST.
    """
    try:
        d = Decimal(str(v))
        if not d.is_finite():
            return None
        # Canonical scale, taken from the VALUE and never from how the caller spelled it. pydantic
        # keeps a string Decimal's exponent, so "0E+5", "1E+1" and "20.00" all reach here as
        # written, and the consistency check compares at _fr's OWN scale: "1E+1" silently
        # hid a 10.56 mismatch that "10" reports, and "0E+1000000" made quantize() raise (a 500).
        # Integral values get scale 0; the rest drop trailing zeros. quantize(1) on an integral
        # value, NOT normalize() - normalize turns 20 into 2E+1, which would compare to the
        # nearest ten. A corrupt huge exponent overflows here and becomes None, like any junk.
        return d.quantize(Decimal(1)) if d == d.to_integral_value() else d.normalize()
    except (InvalidOperation, ValueError, TypeError):
        return None


def _num(d: Decimal | None) -> int | float | None:
    """A Decimal back to a JSON-native number for the snapshot — int when integral.

    The int branch is not tidiness: prompts.treatment_prompt rule 6 orders the model to cite
    final_risk_rating VERBATIM, so storing 20.0 where every previous row stored 20 would silently
    reword every plan an all-integer register generates.

    float is exact ONLY because the schema caps a rating at 15 significant digits (a float's exact
    limit — see schemas_treatment._RATING); raise that cap and this silently stores other numbers.
    """
    if d is None:
        return None
    return int(d) if d == d.to_integral_value() else float(d)


def _register_ratings(risk_input: dict[str, Any]
                    ) -> tuple[Decimal | None, Decimal | None, Decimal | None]:
    """(likelihood, impact, final) normalized through _dec — the ONE reader of the three scores.

    Both the consistency advisory and the stored risk_assessment block go through here, so the
    value that gets CHECKED and the value that gets STORED can never disagree about what the
    register said. (In the old god function this was one shared local triple; _dec is pure, so
    two calls of this reader are exactly equivalent to reusing one triple.)"""
    return (_dec(risk_input.get("likelihood_rating")),
            _dec(risk_input.get("impact_rating")),
            _dec(risk_input.get("final_risk_rating")))


def _assessment_window(risk_input: dict[str, Any]) -> dict[str, Any] | None:
    """{timeline_start_date, timeline_end_date, total_days} from the request pair, or None.
    total_days is computed server-side so the model reasons over one unambiguous number and
    the post-generation check compares against the same one.

    STORED KEY NAMES STAY timeline_* while the REQUEST fields are mitigation_*, deliberately: the
    snapshot is a persisted record format — read back by regenerate and served verbatim by the
    evidence endpoint — so renaming the request contract must not rewrite the shape of every row
    already in the table. regen_risk_input_from_snapshot translates between the two.
    """
    raw_start = risk_input.get("mitigation_start_date")
    raw_end = risk_input.get("mitigation_end_date")
    if not raw_start or not raw_end:   # both-or-neither is enforced by the request model
        return None
    start, end = as_date(raw_start), as_date(raw_end)
    if start is None or end is None:
        # Both values were supplied but at least one will not parse — a corrupted snapshot, or a
        # caller passing a shape as_date does not know. Say so out loud: returning a silent None
        # is precisely what hid the original bug, and it disables the window check for the whole
        # plan rather than for one field.
        log.warning("treatment.assessment_window_unparseable",
                    start=repr(raw_start), end=repr(raw_end))
        return None
    return {"timeline_start_date": start.isoformat(), "timeline_end_date": end.isoformat(),
            # INCLUSIVE: 1 Oct..31 Dec is 92 days of work, and a same-day window is 1 day, not 0.
            "total_days": (end - start).days + 1}


def collect_register_consistency_warnings(risk_input: dict[str, Any],
                                        assessment_window: dict[str, Any] | None) -> list[str]:
    """The three register-consistency advisories — flag, never block: the register owns its
    numbers, but a contradiction the model will cite verbatim (rule 6) must reach the reviewer's
    warnings.

    Comparing at `final`'s OWN scale (quantize) rather than exactly: two 4-dp scores multiply to up
    to 8 dp, which the register cannot express, so an exact != would flag every correctly-rounded
    decimal plan. MAX_PREC: multiply and quantize are exact operations, so in this context the
    product is never rounded and quantize can never overflow — whatever size the schema allows.
    (The default 28-digit context rounded two 11-digit scores' 30-digit product before comparing.)
    """
    warnings: list[str] = []
    likelihood, impact, final = _register_ratings(risk_input)
    # Three explicit `is not None`, not `None not in (...)`: identical semantics (the membership
    # test already falls back to identity, since Decimal.__eq__(None) returns NotImplemented) but
    # mypy cannot narrow through a tuple membership test — so this sound guard still read as four
    # "Decimal * None" errors on the very arithmetic it protects.
    if likelihood is not None and impact is not None and final is not None:
        with localcontext(prec=MAX_PREC):
            product = likelihood * impact
            mismatch = final != product.quantize(final, rounding=ROUND_HALF_UP)
        if mismatch:
            warnings.append(f"final_risk_rating {final} does not equal likelihood x impact "
                            f"({likelihood}x{impact}={product}); register values taken as-is")
    # NO USABLE URGENCY SIGNAL — not "no values at all", which is what this asked until 2026-09.
    # The old condition needed all three scores AND the level to be absent, so a register that sent
    # one surviving likelihood and nothing else satisfied it and drew no warning: the prompt's rule 4
    # ladder has no risk_level to climb, rule 8 has no final_risk_rating to cite verbatim, and
    # treatment._risk_alignment_warnings stands down the moment risk_level is None — an uncalibrated
    # plan with zero trace, indistinguishable from a calibrated one. The approved payload made every
    # one of these fields optional, so partially-scored registers are now ordinary input rather than
    # a legacy-snapshot curiosity, which is why the wording no longer blames a legacy row.
    #
    # DELIBERATELY NOT WARNED: a register that sends a level and/or a final rating but no
    # likelihood/impact PAIR. That plan is calibrated — rule 4 branches on the pair's presence
    # ("If likelihood_rating and impact_rating both exist") and rule 8 cites what it is given — so
    # warning would put an advisory on supported input, which is how a warnings list stops being read.
    if final is None and not risk_input.get("risk_level"):
        warnings.append("risk_assessment carries no risk level and no final risk rating — "
                        "the plan is NOT risk-calibrated")
    window_end = as_date((assessment_window or {}).get("timeline_end_date"))
    if window_end is not None and window_end < dal.now().date():
        warnings.append(f"mitigation window ended {window_end.isoformat()} — already in the past "
                        "at plan creation")
    return warnings


def build_risk_assessment_block(risk_input: dict[str, Any],
                            assessment_window: dict[str, Any] | None) -> dict[str, Any]:
    """The snapshot's prompt-visible `risk_assessment` block.

    _num, not the raw value: regenerate rebuilds risk_input from this very blob and never
    re-enters the schema, so storing whatever shape arrived would let a bad one re-enter the
    baseline on every later regeneration. Normalizing on the way OUT too heals it instead, and is
    idempotent, so the stored bytes survive the round trip."""
    likelihood, impact, final = _register_ratings(risk_input)
    return {
        "likelihood_rating": _num(likelihood),
        "impact_rating": _num(impact),
        "final_risk_rating": _num(final),
        "risk_level": risk_input.get("risk_level"),
        "impacted_business_division": _clip(risk_input.get("impacted_business_division")),
        # The window the ENTIRE assessment must complete within (request pair, validated
        # both-or-neither). PROMPT-VISIBLE on purpose: the model sizes its critical path
        # against total_days; the scheduler then checks the planned end against it.
        "assessment_window": assessment_window,
    }


def build_register_echo_block(risk_input: dict[str, Any]) -> dict[str, Any]:
    """The snapshot's echo-only `register` block — STRIPPED from the prompt
    (prompts.treatment_prompt), injected into PlanJSON at finish (_inject_reserved).

    Stripped because risk_owner is a person's name the model must never see, and
    risk_identification_date is banned from generation anyway. `impacted_business_division`
    additionally rides the prompt-visible risk_assessment block as org context, which is why it
    appears in both. (The local is named `date` and this module imports only `datetime` from
    `datetime` — importing the `date` class here would shadow it; see treatment_schedule.as_date.)
    """
    date = risk_input.get("risk_identification_date")
    return {
        "risk_identification_date": date.isoformat() if isinstance(date, datetime) else date,
        "risk_owner": _clip(risk_input.get("risk_owner")),
        "impacted_business_division": _clip(risk_input.get("impacted_business_division")),
    }
