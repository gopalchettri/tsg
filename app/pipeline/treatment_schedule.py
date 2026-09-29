"""Remediation-schedule arithmetic: durations and depends_on IN, dates, timelines and warnings OUT.

WHY THIS MODULE EXISTS. This was one 149-line function (treatment._schedule_actions) doing six
jobs in a single pass: clamping durations, repairing depends_on, computing chain offsets, resolving
the critical path, rendering timelines/dates, and collecting consistency warnings. Not one of them
could be tested piecewise — a check on the critical-path walk had to build a whole plan AND a whole
snapshot, call the whole function, and read the answer back out of a mutated dict. Split here as
pure functions over already-parsed plan data (no Session, no LLM, no IO) so each job unit-tests on
its own, with plain lists and dicts and no fixtures.

WHY THE ARITHMETIC IS SERVER-SIDE AT ALL. Remediation timelines are a DEPENDENCY CHAIN OF
DURATIONS that TSG schedules — never dates the model writes. The model used to write each action's
timeline as an ISO date inside the mitigation window; with no window it had no anchor (and must not
use "today"), so it guessed dates or durations and nothing checked them. Now the model supplies
only judgement — duration_days and depends_on (earlier actions only) — and every date, total and
timeline sentence is arithmetic done here, which cannot contradict itself.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import date, datetime, timedelta
from typing import Any

from app.core.enums import ActionPriority, ControlCoverage

#: Upper bound on one action's duration — ten years. A larger value is a model slip (a date read
#: as a number, a stray zero), and letting it through would push every dependent date off the page.
_MAX_DURATION_DAYS = 3650
#: Critical=0 … Low=3, from the enum's own order — the one ranking the prompt advertises.
_PRIORITY_RANK = {str(p): i for i, p in enumerate(ActionPriority)}
_URGENT = {str(ActionPriority.critical), str(ActionPriority.high)}
_ACTION_REF = re.compile(r"\bA\d+\b")
_STATED_DAYS = re.compile(r"(?<![\d.])(\d+)[\s-]*(?:calendar[\s-]+)?days?\b", re.IGNORECASE)


def as_date(v: Any) -> date | None:
    """A `date` from a date, a datetime, or an ISO string — None if it is none of those.

    The request path hands ISO STRINGS here: api/treatment.py dumps the body with
    mode="json", which serializes pydantic's `date` fields to "YYYY-MM-DD". The old code only
    handled real date objects, so on the ONLY path that actually runs it computed no day count at
    all (see treatment._assessment_window). Normalizing every accepted shape HERE — rather than
    changing the one caller's dump mode — is what stops a future caller reintroducing it by
    choosing a different mode. datetime.fromisoformat (not date.fromisoformat) so a full ISO
    timestamp parses too. (In treatment.py this helper is also imported under the same name
    rather than re-implemented; that module deliberately keeps no module-level `date` import,
    which would shadow build_treatment_input's own local named `date`.)
    """
    if isinstance(v, datetime):
        return v.date()
    if hasattr(v, "toordinal"):   # a real date; datetime is already handled above
        return v
    if isinstance(v, str):
        try:
            return datetime.fromisoformat(v).date()
        except ValueError:
            return None
    return None


def _whole_days(value: Any) -> int | None:
    """A duration as whole days, or None when it is not one (bool, text, fraction, blank)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _joined(ids: list[str]) -> str:
    return ids[0] if len(ids) == 1 else ", ".join(ids[:-1]) + f" and {ids[-1]}"


def _shift_days(anchor: date, offset: int) -> date:
    """`anchor + offset` days, CLAMPED to the last representable date instead of raising.

    `_MAX_DURATION_DAYS` bounds ONE action; nothing bounds the chain total, and this module's stated
    posture is "repairs, never blocks". Without the clamp, an anchor near the end of the calendar
    plus a long chain raised `OverflowError: date value out of range` straight out of
    `schedule_remediation_actions` — reproduced with a 9999-10-01 window start and two chained
    3650-day actions. `mitigation_start_date` is an unbounded pydantic `date`, so a schema-valid
    request reached it; the exception then landed in `treatment.run_treatment_generation`'s broad
    handler, which parks the row ERROR **after the LLM spend is already committed**, and a
    regenerate on the same snapshot overflowed identically — an unrecoverable plan, and the reviewer
    saw a generic failure instead of the schedule plus a warning.

    Clamping is visible, not silent: `plan_runs_past_the_calendar` reports it once, naming the
    anchor and the offset, exactly as the duration cap reports its own repair."""
    try:
        return anchor + timedelta(days=offset)
    except OverflowError:
        return date.max


def plan_runs_past_the_calendar(anchor: date | None, total: int) -> list[str]:
    """One warning when the plan's span cannot be represented as calendar dates, so the clamp
    `_shift_days` applies is never silent. Empty list in the ordinary case."""
    if anchor is None or total <= 0:
        return []
    representable = (date.max - anchor).days
    if total - 1 <= representable:
        return []
    return [f"the {total}-day schedule runs past the last representable date: from "
            f"{anchor.isoformat()} only {representable + 1} days fit, so the dates at and beyond "
            f"{date.max.isoformat()} are clamped and no longer reflect the durations"]


def normalize_action_durations(actions: list[dict[str, Any]],
                            ids: list[str]) -> tuple[list[int], list[str]]:
    """Each action's duration as whole days in 1.._MAX_DURATION_DAYS, written back onto the action,
    plus one warning per repair. `ids` is the display id per action, positionally aligned.

    Repairs, never blocks (same posture as _validate_plan): a duration that is not a whole number
    of days of at least 1 is scheduled as 1 day, and anything above the cap is capped. Each repair
    is reported, because a silently invented duration is a plan length nobody agreed to.
    """
    durations: list[int] = []
    warnings: list[str] = []
    for act, aid in zip(actions, ids):
        days = _whole_days(act.get("duration_days"))
        if days is None or days < 1:
            warnings.append(f"{aid}.duration_days {act.get('duration_days')!r} is not a whole "
                            "number of days of at least 1 — scheduled as 1 day")
            days = 1
        elif days > _MAX_DURATION_DAYS:
            warnings.append(f"{aid}.duration_days {days} exceeds {_MAX_DURATION_DAYS} — capped")
            days = _MAX_DURATION_DAYS
        act["duration_days"] = days
        durations.append(days)
    return durations, warnings


def normalize_action_dependencies(
    actions: list[dict[str, Any]], ids: list[str], action_ids: list[str],
) -> tuple[list[list[int]], list[str]]:
    """Each action's depends_on reduced to EARLIER actions only, written back onto the action, plus
    warnings. Returns the accepted prerequisites as POSITIONS, positionally aligned with `ids`.

    POSITIONS, NOT IDS — and that is the whole point of this signature. `action_id` is a string the
    MODEL writes, and nothing in the request path makes it unique: `_GeneratedAction.action_id` is a
    plain `str`, JSON-schema strict mode cannot express cross-item uniqueness, and
    `treatment._validate_plan` checks table presence and vocabularies only. When two actions shared
    an id, keying the schedule by that id produced two separate defects, both confirmed by
    reproduction:

      * the second A1's reference to "A1" passed the "is it an earlier action" test — because the
        set held ids, not positions — so the action became its OWN prerequisite, and the
        critical-path walk, which had no cycle guard, SPUN FOREVER. That spin is inside
        `treatment.run_treatment_generation`'s try, so no `except` ever ran: the LLM spend was
        already committed and the Celery worker slot and Session were held until the lease expired
        and the reaper stepped in, with memory climbing the whole time.
      * without the self-reference, the duplicate simply OVERWROTE the first action's finish offset,
        so every later dependent was scheduled off the wrong date and the stored critical path was
        understated (15 days for a plan whose longest chain is 19). The only warning was the
        cosmetic "action ids are not A1..An in order", so corrupted arithmetic read as a naming nit.

    A position cannot collide, cannot be forward (only earlier indices are ever offered) and cannot
    be self, so the one forward pass in `compute_dependency_chain_offsets` is sound by construction
    rather than by a docstring promise. The wire contract is unchanged: `act["depends_on"]` is still
    written as the list of accepted action-id STRINGS, which is what a reviewer and the prose read.

    A repeated action_id is treated as a repair like any other: the FIRST action to carry an id owns
    it, the duplicate is unreferenceable, and both facts are reported. Resolving a reference to a
    repeated id to "whichever one" would be a guess, and this module never guesses silently.

    A reference that is not an earlier action — forward, self, unknown, or a duplicate id's second
    holder — is dropped with one warning PER DISTINCT REFERENCE, however many times the model
    repeats it: the warning list is persisted into ValidationJSON and its LENGTH is what the audit
    row records, so N copies of one slip inflated the reviewer's warning count N-fold.

    A depends_on that is not a list is REPORTED rather than read as []: plain-JSON mode does not
    force the field, and read silently as empty it would schedule a dependent action in parallel and
    understate the whole plan. "Absent" and "present but not a list" get DIFFERENT messages — one
    message for both sent a reviewer hunting for an omitted field when a stated prerequisite had in
    fact been thrown away.

    The prose and the ids must tell the same story: the ids drive the schedule, the `dependencies`
    sentence is what a reviewer reads, so a disagreement either way is flagged.
    """
    dependency_positions: list[list[int]] = []
    warnings: list[str] = []
    #: id -> the position of the FIRST action carrying it. Only non-blank ids are referenceable: a
    #: blank one names nothing, and registering it would make two blank-id actions "duplicates".
    position_of_id: dict[str, int] = {}
    for index, (act, aid, raw_id) in enumerate(zip(actions, ids, action_ids)):
        raw = act.get("depends_on")
        if "depends_on" not in act:
            warnings.append(f"{aid}.depends_on is missing — scheduled with no prerequisites")
        elif not isinstance(raw, list):
            warnings.append(f"{aid}.depends_on {raw!r} is not a list of action ids — scheduled "
                            "with no prerequisites")
        positions: list[int] = []
        seen_references: set[str] = set()
        for entry in raw if isinstance(raw, list) else []:
            ref = str(entry).strip()
            if ref in seen_references:
                continue            # one warning per distinct reference, not per repetition
            seen_references.add(ref)
            # A reference to the action's OWN id is self-referential nonsense whatever else is in
            # the plan, and it must be dropped BEFORE the id lookup. With a repeated action_id the
            # lookup would otherwise resolve it to the OTHER action of the same name — an earlier
            # position, so the schedule terminates, but the resulting total is a guess at what the
            # model meant. Dropping it keeps the documented rule ("forward, self, unknown -> dropped")
            # literally true and leaves the reviewer one unambiguous warning instead of an invented
            # dependency.
            earlier = None if ref and ref == raw_id else position_of_id.get(ref)
            if earlier is not None:
                positions.append(earlier)
            else:
                warnings.append(f"{aid}.depends_on {ref!r} is not an earlier action — ignored")
        accepted_ids = [action_ids[p] for p in positions]
        prose = str(act.get("dependencies") or "").strip()
        for named in dict.fromkeys(_ACTION_REF.findall(prose)):
            if named != raw_id and named not in accepted_ids:
                warnings.append(f"{aid}.dependencies mentions {named} but depends_on does not "
                                "include it")
        if positions and prose.casefold().rstrip(".") == "none":
            warnings.append(f"{aid}.dependencies says None but it waits for {_joined(accepted_ids)}")
        act["depends_on"] = accepted_ids
        dependency_positions.append(positions)
        if raw_id and raw_id in position_of_id:
            warnings.append(f"{aid}.action_id {raw_id!r} is already used by "
                            f"remediation_action_plan[{position_of_id[raw_id]}] — this action "
                            "cannot be named as a prerequisite")
        elif raw_id:
            position_of_id[raw_id] = index
    return dependency_positions, warnings


def compute_dependency_chain_offsets(
    durations: list[int], dependency_positions: list[list[int]],
) -> tuple[list[int], list[int], list[int | None]]:
    """(start offset per action, finish offset per action, the prerequisite POSITION that SETS each
    start). All three are positionally aligned with the action list.

    Offsets are days from the plan's start and stay EXCLUSIVE: an action starting at offset 0 for
    14 days finishes at offset 14, and whatever waits on it starts at 14. Only the calendar
    rendering subtracts a day, which is what makes the DATES inclusive — see
    render_action_timelines.

    Keyed by POSITION, so a repeated action_id cannot make one action's finish overwrite another's
    (see normalize_action_dependencies for the two defects that caused). One forward pass is enough
    because every offered prerequisite position is strictly smaller than the action's own.
    """
    starts: list[int] = []
    finish: list[int] = []
    via: list[int | None] = []
    for index, (days, deps) in enumerate(zip(durations, dependency_positions)):
        start = max((finish[d] for d in deps), default=0)
        starts.append(start)
        finish.append(start + days)
        via.append(max(deps, key=lambda d: finish[d]) if deps else None)
        assert all(d < index for d in deps), (           # by construction; see the docstring
            f"action {index} depends on a position that is not earlier: {deps}")
    return starts, finish, via


def resolve_critical_path(finish: list[int], via: list[int | None]) -> list[int]:
    """The longest chain through the plan, as an ordered list of action POSITIONS.

    The plan's length is the LONGEST chain, never the sum of its actions: work with no unmet
    prerequisite runs in parallel and must not be added in. Walk back from the last-finishing
    action through the prerequisite that set each start.

    The walk is bounded because every `via` entry is a STRICTLY SMALLER position, which the
    assertion below enforces rather than assumes. The previous version walked an id-keyed map with
    no guard at all, and a self-referencing entry — which a repeated action_id produced — made it
    spin forever inside a worker. A wrong answer is recoverable; a hung worker holding a Session
    and a paid-for LLM result is not, so a future keying mistake must crash here instead.
    """
    if not finish:
        return []
    total = max(finish)
    node: int | None = finish.index(total)
    path: list[int] = []
    while node is not None:
        path.append(node)
        nxt = via[node]
        assert nxt is None or nxt < node, (
            f"critical path would not terminate: {node} -> {nxt}")
        node = nxt
    return list(reversed(path))


def render_action_timelines(actions: list[dict[str, Any]], durations: list[int],
                        dependency_ids: list[list[str]], starts: list[int],
                        anchor: date | None) -> None:
    """Write each action's `timeline` sentence and start_date/end_date IN PLACE.

    ONE output shape whether or not the register sent a mitigation window: with a window the dates
    are ISO strings counted from `anchor`, without one they are None and the sentence carries the
    duration alone. Today's date is never used — with no window there is no calendar anchor, only
    durations — and a client never branches on which case it got.

    INCLUSIVE dates: a 14-day action starting 10-01 ends 10-14, and its dependent starts 10-15.
    The offsets stay exclusive (see compute_dependency_chain_offsets); only this rendering
    subtracts the day.
    """
    for act, days, deps, start in zip(actions, durations, dependency_ids, starts):
        span = f"{days} day{'s' if days != 1 else ''}"
        after = (f", after {_joined(deps)} complete{'s' if len(deps) == 1 else ''}"
                 if deps else "")
        if anchor is not None:
            s, e = _shift_days(anchor, start), _shift_days(anchor, start + days - 1)
            act["start_date"], act["end_date"] = s.isoformat(), e.isoformat()
            act["timeline"] = f"{s.isoformat()} → {e.isoformat()} ({span}{after})"
        else:
            act["start_date"] = act["end_date"] = None
            act["timeline"] = f"{span}{after}"


def _control_delivery_warnings(parsed: dict[str, Any], snapshot: dict[str, Any],
                            actions: list[dict[str, Any]], ids: list[str]) -> list[str]:
    """Every recommended control must be delivered by some action, and an action may only name a
    control the plan recommends or — ONLY when coverage is 'covered' — one it verifies from
    library_mapped.

    THE COVERAGE GATE IS NOW ENFORCED, not merely described. `known` used to union the library_mapped
    codes in unconditionally while this docstring stated the parenthetical rule, so on a 'gaps' plan
    an action claiming to deliver an EXISTING control instead of the recommended new one shipped in
    silence — reproduced with coverage 'gaps', recommended [C1], library_mapped [LIB1] and an action
    implementing both: no warning at all. A 'gaps' plan exists precisely because something is NOT
    covered, so an action pointing at an already-mapped control is the defect the reviewer needs to
    see. A future reader citing the docstring as evidence the gate ran would have been wrong.

    `ids` carries the positional placeholder for a blank action_id and is what EVERY warning names.
    This function used to be handed the RAW ids and fall back to a bare integer, so one row was
    called `remediation_action_plan[0]` by the duration and dependency warnings and `0` here — a
    reviewer could not tie the two warnings to the same action, and `0.` reads like a code prefix
    rather than a row number.

    A library_mapped control flagged `covered_by_register` (the register already holds it, matched by
    library id — treatment_input.build_existing_controls_block) is known on a 'gaps' plan too: the
    prompt tells the model it is covered, so an action VERIFYING it is exactly right, not a defect.

    Also normalizes implements_controls to a list of stripped strings in place, in the plan's own
    spelling: codes are matched FOLDED (strip + casefold), mirroring treatment
    ._resolve_control_library_ids, which folds the same model-echoed codes when it stamps the
    recommended controls. Exact matching here while the recommendation was folded there meant one
    lower-cased echo drew two false "not a control of this plan" warnings and persisted the
    non-canonical spelling; a folded match writes the canonical code back instead. A missing field
    is reported, not read as []: an action that delivers no control is a claim, not a default.
    """
    warnings: list[str] = []
    to_implement = parsed.get("controls_to_be_implemented") or {}
    recommended = [str(c.get("control_code")) for c in (to_implement.get("controls") or [])
                if isinstance(c, dict) and c.get("control_code")]
    #: folded code -> the canonical spelling written back onto the action
    known = {code.strip().casefold(): code for code in recommended}
    verifies_mapped = (str(to_implement.get("control_coverage") or "")
                       == str(ControlCoverage.covered))
    for c in (snapshot.get("existing_controls") or {}).get("library_mapped") or []:
        if (isinstance(c, dict) and c.get("control_code")
                and (verifies_mapped or c.get("covered_by_register"))):
            known.setdefault(str(c["control_code"]).strip().casefold(), str(c["control_code"]))
    delivered: set[str] = set()
    for i, act in enumerate(actions):
        raw = act.get("implements_controls")
        if not isinstance(raw, list):
            warnings.append(f"{ids[i]}.implements_controls is missing — treated as delivering "
                            "no control")
        codes: list[str] = []
        for c in raw if isinstance(raw, list) else []:
            echoed = str(c).strip()
            canonical = known.get(echoed.casefold())
            if canonical is None:
                warnings.append(f"{ids[i]}.implements_controls names {echoed!r}, which is not "
                                "a control of this plan")
            codes.append(canonical if canonical is not None else echoed)
        act["implements_controls"] = codes
        delivered.update(codes)
    for code in recommended:
        if code not in delivered:
            warnings.append(f"recommended control {code} is not implemented by any action")
    return warnings


def collect_schedule_consistency_warnings(
    parsed: dict[str, Any], snapshot: dict[str, Any], *, actions: list[dict[str, Any]],
    action_ids: list[str], ids: list[str], dependency_positions: list[list[int]],
    starts: list[int], total: int, planned_end: date | None, deadline: date | None,
    window_sent: bool,
) -> list[str]:
    """Every rule the prompt states that only the FINISHED plan can show, reported so the reviewer
    sees exactly where the plan and the rules part ways: ids in sequence, start order, urgent work
    not waiting on less urgent prerequisites, the action_plan paragraph agreeing with the computed
    total, every recommended control delivered, and the plan fitting the mitigation window.

    `action_ids` is the raw action_id per action (the A1..An check reads it); `ids` is the same list
    with a positional placeholder where an id was blank, which is what warnings name.

    A plan with no mitigation window warns once, here: an unbounded schedule is not a defect in the
    plan, it is a register deadline nobody supplied, and the reviewer has to know which they are
    looking at.
    """
    warnings: list[str] = []
    if action_ids != [f"A{i}" for i in range(1, len(action_ids) + 1)]:
        warnings.append(f"action ids are not A1..A{len(action_ids)} in order: {action_ids}")

    latest_start = 0
    #: Priority per POSITION, not per id — a repeated action_id would otherwise make one action's
    #: priority stand in for another's in the urgency check below.
    priority_at: list[str] = []
    for index, (act, aid, deps, start) in enumerate(zip(actions, ids, dependency_positions, starts)):
        if start < latest_start:
            warnings.append(f"{aid} is listed after work that starts later (day {latest_start}) "
                            f"although it can start on day {start} — the sequence is out of order")
        latest_start = max(latest_start, start)
        # A prerequisite blocks this action, so it is on this action's critical path.
        priority_at.append(str(act.get("priority") or ""))
        rank = _PRIORITY_RANK.get(priority_at[index])
        if priority_at[index] in _URGENT and rank is not None:
            for d in deps:
                if _PRIORITY_RANK.get(priority_at[d], rank) > rank:
                    warnings.append(f"{ids[d]} ({priority_at[d]}) is a prerequisite of {aid} "
                                    f"({priority_at[index]}) but is less urgent than the work it "
                                    "blocks")

    # `window_sent` separates "the register sent no window at all" from "it sent one whose halves we
    # could not use". Claiming the former when the latter happened contradicts the register, and
    # every unusable half now has its own warning from collect_window_gap_warnings — so this branch
    # is only for the genuinely empty window.
    if actions and planned_end is None and not window_sent:
        warnings.append(f"no mitigation window supplied — the {total}-day schedule is not "
                        "bounded by a register deadline")
    elif actions and planned_end is not None and deadline is not None and planned_end > deadline:
        warnings.append(f"the plan finishes {planned_end.isoformat()}, "
                        f"{(planned_end - deadline).days} days after the mitigation window "
                        f"closes ({deadline.isoformat()})")

    # The paragraph is model prose and may do its own arithmetic: if it names day counts and none
    # of them is the computed critical path, the plan contradicts itself — say so.
    stated = {int(n) for n in _STATED_DAYS.findall(str(parsed.get("action_plan") or ""))}
    if actions and stated and total not in stated:
        warnings.append(f"action_plan states {', '.join(str(n) for n in sorted(stated))} days but "
                        f"the computed critical path is {total} days")
    return warnings + _control_delivery_warnings(parsed, snapshot, actions, ids)


def collect_window_gap_warnings(window: Mapping[str, Any], anchor: date | None,
                                deadline: date | None) -> list[str]:
    """One warning per window half that is NOT USABLE, whenever the register sent any window at all.

    This is derived from which half is usable, not from a single boolean over the two keys, and that
    is the fix: the previous split — one `window_was_sent` OR for the "no window" branch, and this
    function only for a value that was PRESENT and MALFORMED — left a HALF-SENT window falling
    through every reporting path. Reproduced both ways:

      * `{"timeline_end_date": "2026-12-31"}` with a 400-day plan returned warnings `[]` — the same
        empty list a clean 40-day plan inside its window returns. Every action's dates were null,
        `mitigation_end_date_planned` was null, and the register's deadline was never compared to
        anything, with nothing to tell the reviewer which of those two situations they had.
      * `{"timeline_start_date": "2026-10-01"}` with a 400-day plan returned warnings `[]` and a
        fully dated timeline that no deadline was ever checked against.

    `as_date` answers None for "absent" and for "present but malformed" alike, which is right for the
    arithmetic and wrong for the reporting — so the message names the raw value when there was one
    and says "no ... supplied" when there was not. Either way a None anchor or deadline now has
    exactly one warning, which is what let `window_was_sent` be deleted.

    `treatment._assessment_window` already logs and collapses an unparseable PAIR before the snapshot
    is built, so the malformed-pair case does not fire through that path today. This function is
    caller-independent on purpose: a legacy or hand-edited snapshot row reaching the scheduler
    directly would otherwise degrade with no trace — which is precisely what the half-sent window
    did.
    """
    if not (window.get("timeline_start_date") or window.get("timeline_end_date")):
        return []       # nothing sent at all: that is the caller's own "unbounded plan" warning
    out: list[str] = []
    if anchor is None:
        raw = window.get("timeline_start_date")
        out.append((f"mitigation window start {raw!r} is not a date" if raw else
                    "the mitigation window has no start date")
                + " — the schedule could not be anchored to the register's window")
    if deadline is None:
        raw = window.get("timeline_end_date")
        out.append((f"mitigation window end {raw!r} is not a date" if raw else
                    "the mitigation window has no end date")
                + " — the plan's finish could not be checked against a register deadline")
    return out


def schedule_remediation_actions(parsed: dict[str, Any], snapshot: dict[str, Any]) -> list[str]:
    """Turn the model's judgement (duration_days + depends_on per action) into the schedule, IN
    PLACE, and return advisory warnings. The one entry point; the helpers above are the six jobs.

    Each action gets start_date/end_date (ISO from the window's start, or None with no window) and
    a `timeline` sentence; the plan gets mitigation_timeline, mitigation_timeline_days (the critical
    path, NOT the sum) and mitigation_end_date_planned (ISO or None). One output shape either way —
    see render_action_timelines for why, and for the inclusive-date rule.

    Repairs, never blocks (same posture as _validate_plan): see normalize_action_durations and
    normalize_action_dependencies for what is repaired and why each repair is reported.
    """
    window = (snapshot.get("risk_assessment") or {}).get("assessment_window") or {}
    anchor = as_date(window.get("timeline_start_date"))
    deadline = as_date(window.get("timeline_end_date"))
    actions = [a for a in parsed.get("remediation_action_plan") or [] if isinstance(a, dict)]
    action_ids = [str(a.get("action_id") or "").strip() for a in actions]
    ids = [aid or f"remediation_action_plan[{i}]" for i, aid in enumerate(action_ids)]

    durations, warnings = normalize_action_durations(actions, ids)
    warnings = collect_window_gap_warnings(window, anchor, deadline) + warnings
    dependency_positions, dep_warnings = normalize_action_dependencies(actions, ids, action_ids)
    warnings += dep_warnings
    starts, finish, via = compute_dependency_chain_offsets(durations, dependency_positions)
    # The prose renders prerequisite IDS; the arithmetic ran on positions. Resolving here keeps the
    # id strings out of every keyed structure — see normalize_action_dependencies.
    dependency_ids = [[action_ids[p] or ids[p] for p in deps] for deps in dependency_positions]
    render_action_timelines(actions, durations, dependency_ids, starts, anchor)

    total = max(finish, default=0)
    warnings += plan_runs_past_the_calendar(anchor, total)
    chain = " → ".join(action_ids[p] or ids[p] for p in resolve_critical_path(finish, via))
    planned_end = _shift_days(anchor, total - 1) if anchor is not None and actions else None
    parsed["mitigation_timeline_days"] = total if actions else None
    parsed["mitigation_end_date_planned"] = (planned_end.isoformat()
                                            if planned_end is not None else None)
    if not actions:
        parsed["mitigation_timeline"] = None
    elif anchor is not None and planned_end is not None:
        parsed["mitigation_timeline"] = (f"{anchor.isoformat()} → {planned_end.isoformat()} "
                                        f"({total} days, critical path {chain})")
    else:
        parsed["mitigation_timeline"] = f"{total} days in total (critical path {chain})"
    return warnings + collect_schedule_consistency_warnings(
        parsed, snapshot, actions=actions, action_ids=action_ids, ids=ids,
        dependency_positions=dependency_positions, starts=starts, total=total,
        planned_end=planned_end, deadline=deadline,
        window_sent=bool(window.get("timeline_start_date")
                         or window.get("timeline_end_date")))


if __name__ == "__main__":  # self-check: pure logic, no DB, no LLM (SDD §13.3)
    # The owner-approved example: A1 and A2 start together, A3 waits for A1, A4 for A2 and A3.
    # 40 days on the critical path A1 → A3 → A4; the parallel A2 is NOT added in.
    def _act(aid: str, days: int, deps: tuple[str, ...] = ()) -> dict[str, Any]:
        return {"action_id": aid, "priority": "High", "depends_on": list(deps),
                "duration_days": days, "implements_controls": []}

    _plan = {"controls_to_be_implemented": {"control_coverage": "gaps", "controls": []},
            "remediation_action_plan": [_act("A1", 14), _act("A2", 10), _act("A3", 21, ("A1",)),
                                        _act("A4", 5, ("A2", "A3"))]}
    _warns = schedule_remediation_actions(
        _plan, {"risk_assessment": {"assessment_window": {
            "timeline_start_date": "2026-10-01", "timeline_end_date": "2026-12-31",
            "total_days": 92}}})
    assert _warns == [], _warns
    assert _plan["mitigation_timeline_days"] == 40
    assert _plan["mitigation_end_date_planned"] == "2026-11-09"
    _rows = _plan["remediation_action_plan"]
    # INCLUSIVE: 10-01..10-14 is 14 days, and A3 starts the day AFTER A1 ends.
    assert (_rows[0]["start_date"], _rows[0]["end_date"]) == ("2026-10-01", "2026-10-14")
    assert _rows[2]["timeline"] == "2026-10-15 → 2026-11-04 (21 days, after A1 completes)"
    # No window: identical key set, null dates, and one warning saying the plan is unbounded.
    _bare = {"controls_to_be_implemented": {"control_coverage": "gaps", "controls": []},
            "remediation_action_plan": [_act("A1", 14), _act("A2", 10), _act("A3", 21, ("A1",)),
                                        _act("A4", 5, ("A2", "A3"))]}
    _bare_warns = schedule_remediation_actions(_bare, {})
    assert _bare_warns == ["no mitigation window supplied — the 40-day schedule is not bounded "
                        "by a register deadline"], _bare_warns
    assert set(_bare) == set(_plan)
    assert all(r["start_date"] is None for r in _bare["remediation_action_plan"])
    assert _bare["remediation_action_plan"][3]["timeline"] == "5 days, after A2 and A3 complete"
    # implements_controls is matched FOLDED and written back canonical; a covered_by_register
    # control is known on a 'gaps' plan, an unflagged mapped one is not.
    _gap = {"controls_to_be_implemented": {"control_coverage": "gaps",
                                           "controls": [{"control_code": "CII-CID-195"}]},
            "remediation_action_plan": [_act("A1", 3), _act("A2", 2, ("A1",))]}
    _gap["remediation_action_plan"][0]["implements_controls"] = [" cii-cid-195 ", "cii-cid-220"]
    _gap["remediation_action_plan"][1]["implements_controls"] = ["CII-CID-198"]
    _gap_warns = schedule_remediation_actions(_gap, {"existing_controls": {"library_mapped": [
        {"control_code": "CII-CID-220", "covered_by_register": True},
        {"control_code": "CII-CID-198", "covered_by_register": False}]}})
    assert _gap["remediation_action_plan"][0]["implements_controls"] == ["CII-CID-195", "CII-CID-220"]
    assert [w for w in _gap_warns if "not a control of this plan" in w] == [
        "A2.implements_controls names 'CII-CID-198', which is not a control of this plan"], _gap_warns
    assert not any("not implemented by any action" in w for w in _gap_warns), _gap_warns
    print("treatment_schedule self-check ok")
