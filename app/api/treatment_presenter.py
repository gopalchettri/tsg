"""The treatment-plan presenter: one plan row → the wire model, plus the pure folds and trims it
uses. Split out of treatment.py in 2026-09 as a PURE move so the route module holds routes. Shared
by the single-plan GET, its history entries, the session board and the entity register — ONE
projection, so no two surfaces can disagree about the same plan. Never imports treatment.py.
"""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.engine import RowMapping

from app.api.schemas import (
    TreatmentBoardRow,
    TreatmentPlanDocument,
    TreatmentPlanProgress,
    TreatmentPlanStatus,
)
from app.api.sessions import (
    _actor_block,
    _Controls,
    _scenario_narrative,
    _threat_block,
)
from app.core.enums import (
    StageStatus,
    TreatmentOutcomeReason,
    TreatmentProgress,
    TreatmentReviewStatus,
    TreatmentStageStatus,
)
from app.db import dal

_TIMED_OUT_MESSAGE = "generation timed out — regenerate it (POST .../treatment-plan/regenerate)"


#: DERIVED from TreatmentPlanDocument, not restated beside it. These ten names used to live in a
#: tuple here AND as the model that defines the plan shape — so a prompt change that added a key
#: would have it silently trimmed away by a list nobody remembered to update. One declaration now.
#: (The AI's own schema was narrowed to exactly this set; see prompts.treatment_prompt.)
_VISIBLE_PLAN_KEYS = tuple(TreatmentPlanDocument.model_fields)


#: The VERSION-INDEPENDENT columns of a plan row: they hang off ScenarioID, so every version of
#: one plan carries the identical values. dal.superseded_plan_rows deliberately does not re-haul
#: them per history row (multi-KB ScenarioJSON, N times, for zero new information) — the routes
#: overlay the active row's single copy onto each history row instead. DERIVED from the same
#: dal.scenario_threat_columns() the selects unpack, never restated: a hand-copied name list that
#: silently stops matching its query is exactly the drift that left history rows blank.
_SCENARIO_ECHO_KEYS = ("ScenarioJSON", "Score", "ScopeRank",
                       *(c.key for c in dal.scenario_threat_columns()))


def _scenario_echo(row: RowMapping) -> dict:
    """The version-independent columns of a row that carries the scenario/threat join, ready to
    overlay UNDER a history row as `{**echo, **history_row}` — the history row's own keys win, so
    per-version fields (created_by, cancelled_*, warnings, ...) are never clobbered. One helper
    for the single-plan GET and the board so the two cannot disagree on what gets echoed."""
    return {k: row[k] for k in _SCENARIO_ECHO_KEYS if k in row}


def _board_progress(plans: list[TreatmentBoardRow]) -> TreatmentPlanProgress:
    """The board's rows -> the shared fold. Thin adapter; the logic lives in _progress_of."""
    return _progress_of([(p.plan_id, p.status, p.review_status) for p in plans])


def _progress_of(rows: list[tuple[str | None, str | None, str | None]]) -> TreatmentPlanProgress:
    """Fold (plan_id, status, review_status) triples into REMEDIATION's own two stages plus a
    rolled-up lifecycle status.

    ONE fold for BOTH endpoints — the session board (many scenarios) and the single-plan GET
    (a list of one). Triples rather than a model type because the two callers build different
    response objects; duplicating the priority order into each is exactly how two screens end up
    disagreeing about the same plan.

    PURE, so it costs no query and needs no database to test. It reads the PRESENTED status,
    not the stored one: _present_status
    projects a stale RUNNING to ERROR before the row is built, and folding
    Risk_Treatment_Plan.Status directly would report a dead plan as generating forever.

    The two stages are the plan's own lifecycle — a machine writes it, then a person decides on
    it — NOT a copy of the generation board's threats/scenarios/controls. They answer different
    questions and a client needs both: "still being written" and "written, waiting on me" look
    identical if you only have one.

    A scenario with NO plan requested counts against GENERATION, not review: the work is
    outstanding, and reporting generation COMPLETE while a scenario has nothing would tell a UI
    to stop offering Generate.
    """
    total = len(rows)
    requested = [r for r in rows if r[0] is not None and r[1] is not None]
    errored = [r for r in requested if r[1] == str(StageStatus.ERROR)]
    running = [r for r in requested if r[1] == str(StageStatus.RUNNING)]
    generated = [r for r in requested if r[1] == str(StageStatus.COMPLETE)]
    undecided = [r for r in generated if r[2] not in
                 (str(TreatmentReviewStatus.approved), str(TreatmentReviewStatus.rejected))]

    if errored:
        generation = TreatmentStageStatus.ERROR
    elif not requested:
        # Nothing requested at all — including a session with nothing accepted, where PENDING is
        # the honest answer rather than the vacuous COMPLETE an empty board would fold to.
        generation = TreatmentStageStatus.PENDING
    elif running or len(generated) < total:
        # Still running, OR some accepted scenario has no plan at all. Both mean generation is
        # unfinished; calling it COMPLETE would tell the UI to stop offering Generate.
        generation = TreatmentStageStatus.RUNNING
    else:
        generation = TreatmentStageStatus.COMPLETE

    # Never RUNNING: a person either has decided or has not. PENDING while generation is still
    # in flight too — there is nothing to review yet.
    review = (TreatmentStageStatus.COMPLETE
              if generation is TreatmentStageStatus.COMPLETE and not undecided
              else TreatmentStageStatus.PENDING)

    # The lifecycle rollup. Order is priority, first match wins — see TreatmentProgress.
    if errored:
        overall = TreatmentProgress.error
    elif generation is TreatmentStageStatus.PENDING:
        overall = TreatmentProgress.pending
    elif generation is not TreatmentStageStatus.COMPLETE:
        overall = TreatmentProgress.generating
    elif undecided:
        overall = TreatmentProgress.awaiting_review
    elif any(r[2] == str(TreatmentReviewStatus.rejected) for r in generated):
        # Everyone has decided and someone said no. NOT terminal: regenerate operates on the
        # active version whatever its verdict, so this is work still outstanding — folding it
        # into `approved` would hide the one state that needs a person to act.
        overall = TreatmentProgress.rejected
    else:
        overall = TreatmentProgress.approved
    return TreatmentPlanProgress(generation=generation, review=review, overall=overall)


def _plan_status_from_row(row: RowMapping, stale_cutoff: datetime,
                          actor_ids: dict[str, int] | None = None,
                          controls: _Controls | None = None,
                          superseded_row: bool = False,
                        superseded: list[TreatmentPlanStatus] | None = None) -> TreatmentPlanStatus:
    """One plan row -> the wire model. Shared by the single-plan GET, the Excel export, the
    versions history (?include_superseded) and the detailed register (?include_plan), so no
    two views can ever disagree — the guarantee the export used to buy by re-entering the GET
    per scenario, now held by construction. `stale_cutoff` is the CALLER's single instant
    (_present_status's contract): batch routes pass one cutoff for every row of a response.
    Blob columns are read with .get because not every feeding select carries them: ReviewComment
    is wire-hidden (exclude=True) and only active_plan_row hauls it; ValidationJSON feeds the
    wire-VISIBLE warnings/moderation_flagged and is selected wherever those are published
    (active_plan_row, superseded_plan_rows) — the register omits it only because
    TreatmentRegisterRow does not publish them.

    `controls` is the WHOLE _controls_by_output result, never a pre-split list: it reports whether
    the read happened (`unavailable`) beside what it found, and two callers used to keep the list
    and drop the flag — so a transient DB error published `controls: []`, which the schema
    documents as a genuine library-gap signal. Deriving list and flag HERE from one object means
    no caller can separate them again."""
    status, error_message, reason = _present_status(
        row["Status"], row["ErrorMessage"], row["UpdatedAt"], stale_cutoff, row["ErrorReason"])

    plan = _visible_plan(row["PlanJSON"], row["PlanID"])
    # .get, not []: not every feeding select carries these. History rows (superseded_plan_rows)
    # have no scenario/threat join of their own — the routes overlay the scenario's single copy
    # before calling in (_scenario_echo) — and a select that lacks a column must publish null
    # rather than KeyError the whole response.
    # THE SAME BUILDER /results USES, not a narrower local copy. This used to whitelist six
    # keys, so a reviewer approving a remediation plan saw strictly LESS about the scenario than
    # the results screen showed — no assumptions, no supporting_systems_involved, no threat ids.
    # _scenario_narrative merges the threat's display wording through the same shared coalesce,
    # so the two screens cannot disagree on a name.
    scenario = _scenario_narrative(row.get("ScenarioJSON"), row if row.get("ScenarioJSON") else None)
    validation = _safe_json_dict(row.get("ValidationJSON"), row["PlanID"]) or {}
    moderation = validation.get("moderation") or {}
    # Keyed by the row's own ScenarioID — canonical from the GUID type, the same keys that
    # _query_controls builds — never by a URL parameter a client may have sent in another case.
    ctl_list = controls.by_output.get(str(row["ScenarioID"]), []) if controls else []
    return TreatmentPlanStatus(
        plan_id=row["PlanID"], session_id=row["SessionID"], scenario_id=row["ScenarioID"],
        status=status, treatment_strategy=row["TreatmentStrategy"],
        # THE SAME fold the board uses, over a list of one — so the per-scenario screen and the
        # board cannot report different lifecycle states for the same plan. `superseded` is the
        # one exception: a retired version is history, not a live lifecycle, and the caller
        # passes is_superseded=True to null it out.
        progress=(None if superseded_row
                  else _progress_of([(row["PlanID"], status, row["ReviewStatus"])])),
        scenario=scenario,
        # SIBLINGS of `scenario`, never inside it — the same four-block shape /results publishes
        # (scenario / threat / actors / controls). Every one of these reads the row with .get()
        # or tolerates a missing ThreatID, so a superseded-version row (which carries no
        # scenario/threat join at all) yields null/[] rather than raising KeyError.
        threat=_threat_block(row),
        actors=_actor_block(row, actor_ids),
        controls=ctl_list,
        controls_unavailable=bool(controls and controls.unavailable),
        risk_level=row["RiskLevel"], review_status=row["ReviewStatus"],
        review_comment=row.get("ReviewComment"), reviewed_by=row["ReviewedBy"],
        reviewed_at=row["ReviewedAt"],
        # .get(): this presenter is fed by more than one select, and a row missing the column must
        # publish null rather than KeyError the whole poll.
        created_by=row.get("UserID"),
        cancelled_by=row.get("CancelledBy"), cancelled_at=row.get("CancelledAt"),
        risk_identification_date=row["RiskIdentificationDate"],
        plan=plan,
        warnings=[w for w in validation.get("warnings") or [] if isinstance(w, str)],
        moderation_flagged=bool(moderation.get("flagged")),
        error_message=error_message, reason=reason, superseded=superseded,
        created_at=row["CreatedAt"], completed_at=row["CompletedAt"])


def _safe_json_dict(blob: str | None, plan_id: str) -> dict | None:
    """Defensive PlanJSON/ValidationJSON parse — one corrupt blob must degrade to None with a
    log line, never 500 the poll. Binds dal.safe_json_dict (THE shared implementation, which
    sessions.py uses silently) to this module's warning event, so the 7 call sites below keep
    their signature and the log line stays byte-identical."""
    return dal.safe_json_dict(blob, warn_event="treatment.stored_json_unparseable",
                            plan_id=plan_id)


def _normalize_plan_shape(plan: dict | None) -> dict | None:
    """Read-time projection for pre-v0.12 PlanJSON rows — stored rows are never rewritten (same
    posture as _present_status). The old contract stored controls_to_be_implemented as a bare
    array with control_coverage as a top-level sibling; the current contract nests both as
    {control_coverage, controls[]}. Lifting old rows here — the ONE place PlanJSON is served
    (the board and register never select the column; the Excel export consumes this GET) —
    means every consumer sees one shape regardless of when the plan was generated.

    ANY non-dict value is coerced (list rows kept, junk dropped), so a corrupt or hand-edited
    blob can never 500 the poll or the workbook — same defensive posture as _safe_json_dict.
    Rows from the short-lived pre-v0.5 shape (AI table under `recommended_controls`) coerce to
    an empty controls list rather than being recovered; the evidence endpoint still serves
    their raw snapshot if that history is ever needed."""
    if plan is None:
        return None
    cti = plan.get("controls_to_be_implemented")
    if not isinstance(cti, dict):
        plan["controls_to_be_implemented"] = {
            "control_coverage": plan.get("control_coverage"),
            "controls": [c for c in cti if isinstance(c, dict)] if isinstance(cti, list) else [],
        }
    return plan


def _visible_plan(plan_json: str | None, plan_id: str) -> dict | None:
    """Stored PlanJSON -> the served plan object: defensive parse, legacy-shape lift, then the
    _VISIBLE_PLAN_KEYS trim. THE one projection — the poll GET (via _plan_status_from_row) and
    the register's ?include_plan=true both serve exactly this, so the two views can never
    disagree on what a plan looks like."""
    plan = _normalize_plan_shape(_safe_json_dict(plan_json, plan_id))
    if plan is not None:
        plan = {k: plan[k] for k in _VISIBLE_PLAN_KEYS if k in plan}
    return plan


def _naive_utc(dt: datetime) -> datetime:
    """Normalize to naive UTC. MSSQL datetime2 stores naive-UTC wall time and pyodbc silently
    drops tzinfo on bind (the documented reason TreatmentPlanBody._utc_naive exists), so an
    aware value must be CONVERTED to UTC before the offset is stripped — a bare
    replace(tzinfo=None) on a +05:30 timestamp would shift every comparison by 5.5 hours.
    Naive input is trusted as UTC already (that is what the DB hands back)."""
    return dt.astimezone(UTC).replace(tzinfo=None) if dt.tzinfo else dt


def _present_status(status: str, error_message: str | None, updated_at: datetime | None,
                    stale_cutoff: datetime,
                    error_reason: str | None = None) -> tuple[str, str | None, str | None]:
    """Read-time staleness projection shared by the single-plan GET, the board and the
    register: a RUNNING row whose progress clock stopped past treatment_stale_seconds
    presents as ERROR/timed-out; the stored row is never rewritten (the next POST
    supersedes it, and a late finish still lands).

    Returns (status, message, reason). The reason is the projection's whole point on this path:
    `timed_out` has NO writer — it exists only here — so a client can distinguish a timeout from a
    real failure without matching the English sentence. For a stored ERROR the row's own
    ErrorReason passes through; NULL (a row that failed before the column existed) reads as
    generation_failed, the historical catch-all.

    `stale_cutoff` is the CALLER's instant, not recomputed here — `treatment._stale_cutoff()`
    returns `now() - treatment_stale_seconds` at call time, so calling it fresh per row (the
    board loops over several) or a second time after an earlier SQL-side filter already used one
    (the register) drifts the two apart by however long the round trip took. A row can then pass
    one check and fail the other on the exact same request."""
    if status == str(StageStatus.RUNNING) and updated_at is not None \
            and _naive_utc(updated_at) < _naive_utc(stale_cutoff):
        return str(StageStatus.ERROR), _TIMED_OUT_MESSAGE, str(TreatmentOutcomeReason.timed_out)
    if status == str(StageStatus.ERROR):
        return status, error_message, error_reason or str(TreatmentOutcomeReason.generation_failed)
    return status, error_message, None  # RUNNING / COMPLETE carry no reason
