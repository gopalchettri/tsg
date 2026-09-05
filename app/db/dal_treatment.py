"""Data-access layer, treatment-plan slice: the Risk_Treatment_Plan lifecycle (generate →
supersede → review/adopt), its readers for the poll GET, the session board and the entity register,
and its audit readers. Split out of dal.py in 2026-09 as a PURE move — every function is reachable
as before through `dal.<name>` (dal.py resolves this slice lazily, so neither import order cycles),
and the shared predicates/helpers (`active`, `accepted`, `execute_dml`, `now`, `_valid_guid`,
`scenario_threat_columns`, `_scenario_read_select`) still live in dal.py and are imported here.

plan_presenter_columns() is THE list every presenter-fed select unpacks — see its docstring.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    RowMapping,
    and_,
    bindparam,
    func,
    or_,
    select,
    update,
)
from sqlalchemy.orm import Session

from app.core.enums import (
    AuditEventType,
    StageStatus,
    TreatmentOutcomeReason,
)
from app.db import models as m
from app.db.dal import (  # shared helpers stay in the parent
    _scenario_read_select,
    _valid_guid,
    accepted,
    active,
    execute_dml,
    now,
    scenario_threat_columns,
)


# ---------------------------------------------------------------------------
# Risk Treatment Plan rows (docs/RISK_TREATMENT_PLAN_SDD.md §6). The plan row IS the state — no
# Subsystem_Stage_State involvement, since accepted scenarios live on completed sessions where
# acquire_lock refuses to run. Every conditional-UPDATE fence lives here; treatment.py and
# api/treatment.py never build their own SQL.
# ---------------------------------------------------------------------------
def plan_presenter_columns():
    """The plan-table columns api.treatment._plan_status_from_row reads — ONE list, unpacked by
    every select that feeds it (active_plan_row, superseded_plan_rows, entity_plan_rows under
    include_plan). Sibling of scenario_threat_columns(), for the same reason: the treatment
    response used to be fed by two hand-maintained column lists, and three schema changes
    (created_by, Cancelled*, warnings/moderation_flagged) each reached one and missed the other —
    the presenter's defensive .get published null/false instead of raising, so superseded versions
    reported wrong attribution and a clean moderation verdict for months. A test pins the
    presenter's reads to this list: a row["New"] read without a column here fails the suite.
    NOT used by plan_status_row — the cheap poll is deliberately narrow. ReviewComment is absent
    on purpose: wire-hidden, hauled by active_plan_row alone."""
    p = m.Risk_Treatment_Plan
    return (p.PlanID, p.SessionID, p.ScenarioID, p.Status, p.TreatmentStrategy,
            p.RiskIdentificationDate, p.PlanJSON, p.ValidationJSON, p.ErrorMessage, p.ErrorReason,
            p.RiskLevel, p.ReviewStatus, p.ReviewedBy, p.ReviewedAt,
            p.UserID, p.CancelledBy, p.CancelledAt, p.CreatedAt, p.UpdatedAt, p.CompletedAt)


def supersede_active_plan(sess: Session, output_id: str, stale_cutoff: datetime,
                          plan_id: str | None = None) -> int:
    """Retire the scenario's active plan row so a new attempt can insert; returns rowcount. Matches
    only replaceable rows: finished, or a RUNNING claim stalled before `stale_cutoff`. A FRESH
    RUNNING row matches nothing, so the insert hits UX_TreatmentPlan_ActiveScenario → 409.

    `plan_id` is a TOCTOU fence for callers that first READ the active row (regenerate carries its
    snapshot; the review swap branches on it): the retire then targets exactly the row that was
    read — a racing swap/regenerate that changed the active row in between misses the CAS
    (rowcount 0 → the caller 409s) instead of retiring, and acting on, the wrong version."""
    p = m.Risk_Treatment_Plan
    where = [p.ScenarioID == output_id, active(p.Superseded),
             or_(p.Status.in_([StageStatus.COMPLETE, StageStatus.ERROR]),
                 and_(p.Status == StageStatus.RUNNING, p.UpdatedAt < stale_cutoff))]
    if plan_id is not None:
        where.append(p.PlanID == plan_id)
    return execute_dml(sess, update(p).where(*where)
                       .values(Superseded=1, UpdatedAt=now())).rowcount


def active_plan_baseline(sess: Session, session_id: str, output_id: str) -> RowMapping | None:
    """Regenerate's one-read baseline: the ACTIVE row's id, the two column stamps the new
    version copies, and the frozen snapshot — exactly the four fields needed, in ONE query.
    Replaces the active_plan_row + plan_row_by_id pair, which hauled the scenario/threat joins
    and ValidationJSON this path never uses."""
    if not _valid_guid(output_id):
        return None
    p = m.Risk_Treatment_Plan
    return sess.execute(
        select(p.PlanID, p.RiskLevel, p.RiskIdentificationDate, p.InputSnapshotJSON)
        .where(p.SessionID == session_id, p.ScenarioID == output_id, active(p.Superseded))
    ).mappings().first()


def plan_version_exists(sess: Session, session_id: str, output_id: str, plan_id: str) -> bool:
    """Tenant-fenced existence probe for the review swap's 404 — a bare SELECT of the PK,
    because plan_row_by_id would haul InputSnapshotJSON (tens of KB) for a pure `is None` test."""
    if not (_valid_guid(output_id) and _valid_guid(plan_id)):
        return False
    p = m.Risk_Treatment_Plan
    return sess.execute(select(p.PlanID).where(
        p.PlanID == plan_id, p.SessionID == session_id, p.ScenarioID == output_id)).first() is not None


def reactivate_plan_version(sess: Session, session_id: str, output_id: str, plan_id: str) -> bool:
    """Make a historical COMPLETE plan version the active one; True iff exactly this row flipped.
    CAS-fenced on (Superseded=1, COMPLETE): a non-COMPLETE historical row must never come back —
    a reactivated RUNNING row would be zombie-claimable via claim_plan's stale branch. The
    session/output predicates keep a foreign plan id a no-op (caller 404s), not a leak. The caller
    MUST have retired the current active row in the SAME transaction first (supersede_active_plan
    with its plan_id fence) and must roll everything back unless BOTH rowcounts are 1 — this pair
    is the only writer that could otherwise leave a scenario with zero active plan rows."""
    p = m.Risk_Treatment_Plan
    return execute_dml(sess, update(p).where(
        p.PlanID == plan_id, p.SessionID == session_id, p.ScenarioID == output_id,
        p.Superseded == 1, p.Status == StageStatus.COMPLETE,
    ).values(Superseded=0, UpdatedAt=now())).rowcount == 1


def claim_plan(sess: Session, plan_id: str, task_id: str, stale_cutoff: datetime) -> bool:
    """Worker claim CAS; True iff we hold it. Admits unclaimed, the SAME task id (acks_late and
    autoretry_for both re-run with it unchanged — without this branch every retry no-ops and wedges
    the row), or a stale claim. False = someone else holds it, or the row is finished/superseded."""
    p = m.Risk_Treatment_Plan
    return execute_dml(sess, update(p).where(
        p.PlanID == plan_id, p.Superseded == 0, p.Status == StageStatus.RUNNING,
        or_(p.ActiveTaskID.is_(None), p.ActiveTaskID == task_id, p.UpdatedAt < stale_cutoff),
    ).values(ActiveTaskID=task_id, UpdatedAt=now())).rowcount == 1


def touch_plan(sess: Session, plan_id: str) -> None:
    """Bump the progress clock before each LLM attempt, so treatment_stale_seconds measures "no
    progress", not wall time. Fenced on (RUNNING, not superseded) — a zombie must not smudge a
    retired row's stop timestamp, which is what a post-mortem reads.
    # ponytail: one UPDATE per attempt, not a heartbeat thread."""
    p = m.Risk_Treatment_Plan
    execute_dml(sess, update(p).where(
        p.PlanID == plan_id, p.Superseded == 0, p.Status == StageStatus.RUNNING,
    ).values(UpdatedAt=now()))


def finish_plan(sess: Session, plan_id: str, *, status: StageStatus, task_id: str | None,
                plan_json: str | None = None, validation_json: str | None = None,
                error_message: str | None = None,
                error_reason: TreatmentOutcomeReason | None = None,
                cancelled_by: str | None = None) -> bool:
    """Terminal CAS to COMPLETE or ERROR. Fenced on (RUNNING, not superseded), so a superseded or
    already-finished row matches 0 rows and the caller drops its result instead of resurrecting a
    retired plan. ALSO fenced on ActiveTaskID — a zombie worker's late result must not clobber a
    claim that has since been taken over (claim_plan's stale-claim branch is what makes a
    takeover possible). Required, not defaulted: every caller must consciously state who they
    are, same discipline as claim_stage/finish_stage. `task_id=None` means "only if still
    unclaimed" (ActiveTaskID IS NULL) — for a freshly-inserted row nothing has claimed yet, or a
    caller re-asserting a value it just read off the row itself; a real task_id must match
    exactly.

    `error_reason` is the machine-readable half of an ERROR (TreatmentOutcomeReason) so no client
    ever parses `error_message`. Pass it on EVERY ERROR path; leave it None for COMPLETE, where the
    column is meaningless. It is deliberately not defaulted per-status — a silent NULL on a failure
    is exactly the ambiguity this column exists to remove.

    `cancelled_by` is set ONLY by the cancel route. This function is also the normal-completion and
    generic-failure writer, so the cancellation columns must not be touched on those paths — a
    CancelledBy stamped on an ordinary ERROR would claim a human stopped something that simply
    failed. Passing it is what makes the write a cancellation."""
    p = m.Risk_Treatment_Plan
    _now = now()
    values: dict = {"Status": status, "PlanJSON": plan_json, "ValidationJSON": validation_json,
                    "ErrorMessage": error_message, "ErrorReason": error_reason,
                    "UpdatedAt": _now, "CompletedAt": _now}
    if cancelled_by is not None:
        values |= {"CancelledAt": _now, "CancelledBy": cancelled_by}
    return execute_dml(sess, update(p).where(
        p.PlanID == plan_id, p.Superseded == 0, p.Status == StageStatus.RUNNING,
        p.ActiveTaskID.is_(None) if task_id is None else p.ActiveTaskID == task_id,
    ).values(**values)).rowcount == 1


def plan_status_row(sess: Session, session_id: str, output_id: str) -> RowMapping | None:
    """STATUS ONLY for the poll endpoint — deliberately NOT active_plan_row.

    A status poll is hit repeatedly while a plan generates, and active_plan_row hauls PlanJSON,
    ScenarioJSON and the whole threat join: tens of KB per call for a caller that wants three
    strings. This selects the plan-table columns the lifecycle is derived from and nothing else,
    so polling stays cheap no matter how large the plan grows.

    Same SessionID predicate as active_plan_row, for the same reason: it keeps a foreign
    ScenarioID a 404 rather than a cross-tenant leak. None on a malformed GUID.
    """
    if not _valid_guid(output_id):
        return None
    p = m.Risk_Treatment_Plan
    return sess.execute(
        select(p.PlanID, p.SessionID, p.ScenarioID, p.Status, p.ErrorMessage, p.ErrorReason,
            p.ReviewStatus, p.ReviewedBy, p.ReviewedAt, p.UserID,
            p.CreatedAt, p.UpdatedAt, p.CompletedAt)
        .where(p.SessionID == session_id, p.ScenarioID == output_id, active(p.Superseded))
    ).mappings().first()


def active_plan_row(sess: Session, session_id: str, output_id: str) -> RowMapping | None:
    """The scenario's one active plan row for the GET poll, with its scenario JSON alongside. The
    SessionID predicate keeps a foreign ScenarioID a 404, not a leak; None on a malformed GUID.
    Explicit columns, NOT the whole table — InputSnapshotJSON is tens of KB this poll never returns."""
    if not _valid_guid(output_id):
        return None
    p, out = m.Risk_Treatment_Plan, m.Threat_Scenario
    st, it = m.Scoped_Threat, m.Identified_Threat
    return sess.execute(
        # THE shared presenter list (plan_presenter_columns) plus this select's route-only
        # extras: TenantID/EntityID for audit rows, ActiveTaskID for the cancel fence, and
        # ReviewComment — wire-hidden, hauled only here so the poll GET keeps its
        # one-flag-unhide contract.
        select(*plan_presenter_columns(), p.TenantID, p.EntityID, p.ActiveTaskID, p.ReviewComment,
               out.ScenarioJSON,
            # The threat's own identity — NOT part of the LLM's scenario JSON (same split as
            # sessions._build_scenario). OUTER for the same reason as _scenario_read_select:
            # no enforced FKs, so a broken linkage must null these, never drop the plan row.
            #
            # THE SHARED LIST, not a hand-rolled subset. This used to select six columns by
            # hand, which is exactly the drift scenario_threat_columns() exists to prevent —
            # and its own docstring names "the treatment presenters" as a consumer. The plan
            # response could therefore answer null where /results carried a value, on the very
            # screen a reviewer signs off. Widening it here is what lets the presenter reuse
            # sessions._threat_block instead of reimplementing a narrower one.
            *scenario_threat_columns(),
            # Score/ScopeRank live on Scoped_Threat, NOT Identified_Threat, so the shared list
            # cannot carry them — and _threat_block reads both. Without them the plan's threat
            # block answered null for two fields /results populates, which is the drift this
            # whole change removes. Verified by diffing the two blocks on a real row.
            st.Score, st.ScopeRank)
        .select_from(p.__table__.outerjoin(out, out.ScenarioID == p.ScenarioID)
                    .outerjoin(st, out.ScopedThreatID == st.ScopedThreatID)
                    .outerjoin(it, st.ThreatID == it.ThreatID))
        .where(p.SessionID == session_id, p.ScenarioID == output_id, active(p.Superseded))
    ).mappings().first()


def review_plan(sess: Session, plan_id: str, *, status: str, comment: str | None,
                reviewer: str | None, reviewed_at: datetime) -> bool:
    """Record the human adoption decision, CAS-fenced on (COMPLETE, not superseded): only a
    finished, current plan is adoptable, a re-review overwrites, and a regenerated plan is a NEW
    row so approval never carries across versions. `reviewed_at` comes from the caller so the
    response echoes the exact stored instant."""
    p = m.Risk_Treatment_Plan
    return execute_dml(sess, update(p).where(
        p.PlanID == plan_id, p.Superseded == 0, p.Status == StageStatus.COMPLETE,
    ).values(ReviewStatus=status, ReviewComment=comment, ReviewedBy=reviewer,
            ReviewedAt=reviewed_at, UpdatedAt=reviewed_at)).rowcount == 1


def session_plan_board(sess: Session, session_id: str, *,
                       include_plan: bool = False) -> list[RowMapping]:
    """One row per accepted scenario of the session (whichever version was accepted — possibly a
    superseded one), LEFT-joined to its active plan (NULL plan columns = never requested).
    Excludes PlanJSON by default — the board is a glance, the single-plan GET is the document;
    `include_plan` appends it, the same opt-in blob haul as entity_plan_rows. The scenario title comes from JSON_VALUE server-side (entity_plan_rows
    precedent) — the board is polled, and hauling every multi-KB ScenarioJSON per cycle to keep
    one short string was the query's whole IO cost."""
    out, p = m.Threat_Scenario, m.Risk_Treatment_Plan
    cols = [out.ScenarioID,
            func.json_value(out.ScenarioJSON, "$.scenario_title").label("ScenarioTitle"),
            p.PlanID, p.Status, p.RiskLevel, p.ReviewStatus, p.ErrorMessage, p.ErrorReason,
            p.CreatedAt.label("PlanCreatedAt"), p.UpdatedAt.label("PlanUpdatedAt"),
            p.CompletedAt.label("PlanCompletedAt")]
    if include_plan:
        cols.append(p.PlanJSON)
    return list(sess.execute(
        select(*cols)
        .select_from(out.__table__.outerjoin(
            p, and_(p.ScenarioID == out.ScenarioID, active(p.Superseded))))
        # Accepted alone — the accepted version may be superseded (decoupled flags).
        .where(out.SessionID == session_id, accepted(out.Accepted))
        .order_by(out.CreatedAt, out.ScenarioID)
    ).mappings().all())


def entity_plan_rows(sess: Session, entity_id: str, *, stale_cutoff: datetime,
                    status: str | None = None, review_status: str | None = None,
                    risk_level: str | None = None, include_plan: bool = False,
                    limit: int = 100, offset: int = 0) -> list[RowMapping]:
    """Entity-wide remediation register: every active plan across the entity's sessions, newest
    first. Filters Scenario_Session.EntityID — the NOT NULL authz truth, never the nullable copy.

    `status` matches the PRESENTED status: a stale RUNNING row projects to ERROR at read time, so it
    must surface under status=ERROR and stay out of status=RUNNING. Branched in SQL, not
    post-filtered in Python, which would under-fill pages. ScenarioTitle comes from JSON_VALUE
    server-side rather than hauling every multi-KB blob; malformed JSON yields NULL.
    `include_plan` widens the select to everything _plan_status_from_row reads —
    plan_presenter_columns() plus the scenario/threat join — so the detailed register
    row is rendered by the poll GET's own presenter — a deliberate, opt-in haul
    (?include_plan=true), bounded by the page limit, and NOT redundant here: every register row
    is a different scenario. Off keeps today's byte-stable SQL."""
    p, ss, out = m.Risk_Treatment_Plan, m.Scenario_Session, m.Threat_Scenario
    context = [ss.AssetName,
               func.json_value(out.ScenarioJSON, "$.scenario_title").label("ScenarioTitle")]
    cols = [p.PlanID, p.SessionID, p.ScenarioID, p.Status, p.RiskLevel, p.ReviewStatus,
            p.ReviewedBy, p.ReviewedAt, p.ErrorMessage, p.ErrorReason, p.CreatedAt, p.UpdatedAt,
            p.CompletedAt, *context]
    joined = (p.__table__
              .join(ss, ss.SessionID == p.SessionID)
              .outerjoin(out, out.ScenarioID == p.ScenarioID))
    if include_plan:
        st, it = m.Scoped_Threat, m.Identified_Threat
        # The detail view renders through the poll GET's own presenter, so it selects THE shared
        # presenter list — plan_presenter_columns() — not a hand-picked subset: two such subsets
        # are how the treatment response drifted three times. That includes ValidationJSON
        # (sub-KB) although TreatmentRegisterRow publishes no warnings today: structural parity
        # beats a per-row micro-saving, and the field can be published later without a query
        # change. ReviewComment stays out — wire-hidden, active_plan_row only. Same shared threat
        # list as active_plan_row; Score/ScopeRank live on Scoped_Threat and are added explicitly.
        cols = [*plan_presenter_columns(), *context,
                out.ScenarioJSON, *scenario_threat_columns(), st.Score, st.ScopeRank]
        joined = (joined
                  .outerjoin(st, out.ScopedThreatID == st.ScopedThreatID)
                  .outerjoin(it, st.ThreatID == it.ThreatID))
    stmt = (
        select(*cols)
        .select_from(joined)
        .where(ss.EntityID == entity_id, active(p.Superseded)))
    if status == str(StageStatus.ERROR):
        stmt = stmt.where(or_(p.Status == StageStatus.ERROR,
                            and_(p.Status == StageStatus.RUNNING,
                                p.UpdatedAt < stale_cutoff)))
    elif status == str(StageStatus.RUNNING):
        stmt = stmt.where(p.Status == StageStatus.RUNNING, p.UpdatedAt >= stale_cutoff)
    elif status is not None:
        stmt = stmt.where(p.Status == status)
    if review_status is not None:
        stmt = stmt.where(p.ReviewStatus == review_status)
    if risk_level is not None:
        stmt = stmt.where(p.RiskLevel == risk_level)
    return list(sess.execute(
        stmt.order_by(p.CreatedAt.desc(), p.PlanID).limit(limit).offset(offset)
    ).mappings().all())


def plan_history_rows(sess: Session, session_id: str, output_id: str) -> list[RowMapping]:
    """Every version (active and superseded) of one scenario's plan, oldest first. Rows are never
    deleted, so this IS the complete history."""
    if not _valid_guid(output_id):
        return []
    p = m.Risk_Treatment_Plan
    return list(sess.execute(
        select(p.PlanID, p.Status, p.Superseded, p.ErrorMessage, p.RiskLevel, p.ReviewStatus,
            p.ReviewedBy, p.ReviewedAt, p.CreatedAt, p.UpdatedAt, p.CompletedAt)
        .where(p.SessionID == session_id, p.ScenarioID == output_id)
        .order_by(p.CreatedAt)
    ).mappings().all())


def superseded_plan_rows(sess: Session, session_id: str,
                         output_id: str | None = None) -> list[RowMapping]:
    """The regeneration history behind the poll GET's ?include_superseded=true: every RETIRED
    version of one scenario's plan — or, with output_id=None, of the WHOLE session in one round
    trip (the board's ?include_superseded=true; global newest-first order keeps each scenario's
    group newest-first after the caller buckets by ScenarioID). Both forms seek
    IX_TreatmentPlan_SessionHistory — the table's other two indexes are filtered Superseded = 0
    and serve no history predicate (the sessions._ancestry trap).

    NO scenario/threat joins, deliberately: those hang off the ScenarioID and are identical for
    every version, so re-hauling the same multi-KB ScenarioJSON per history row would multiply the
    DB read for zero information. The ROUTES overlay the active row's single copy instead
    (api.treatment._SCENARIO_ECHO_KEYS), so a history row still publishes scenario/threat/actors —
    this query just does not pay for them N times.

    Selects THE shared presenter list, plan_presenter_columns(): every per-version column the
    presenter reads (UserID/Cancelled*/ValidationJSON included — they describe THIS attempt and
    cannot be echoed from the active row). This query used to hand-list its columns and missed
    three schema changes; the presenter's defensive .get then published created_by=null and
    moderation_flagged=false for versions that had recorded otherwise. One list, pinned by a
    test, is what stops a fourth.

    InputSnapshotJSON stays excluded — tens of KB per version; that is the evidence endpoint's
    job. ReviewComment stays excluded — it is genuinely exclude=True on the model and never
    reaches the wire."""
    if output_id is not None and not _valid_guid(output_id):
        return []
    p = m.Risk_Treatment_Plan
    stmt = (
        select(*plan_presenter_columns())
        # literal_execute renders `Superseded = 1` INLINE: SQL Server cannot match a
        # parameterized predicate against the filtered IX_TreatmentPlan_SessionHistory (the
        # cached plan must hold for every parameter value — FORCESEEK errors 8622 on the
        # bound form), so `== 1` as a normal bind would silently scan the whole plan table.
        # The ids stay bound — the literal is a constant, so plans still cache and reuse.
        .where(p.SessionID == session_id,
               p.Superseded == bindparam("hist", 1, literal_execute=True))
        .order_by(p.CreatedAt.desc(), p.PlanID))
    if output_id is not None:
        stmt = stmt.where(p.ScenarioID == output_id)
    else:
        # Board form: gate on board-visible scenarios. A scenario superseded AFTER its plan was
        # generated leaves retired plan rows no board row can attach to — without this PK-hop
        # join their PlanJSON blobs would be hauled and rendered only to be thrown away.
        out = m.Threat_Scenario
        # Accepted alone — board visibility follows acceptance, not generation recency.
        stmt = (stmt.join(out, out.ScenarioID == p.ScenarioID)
                    .where(accepted(out.Accepted)))
    return list(sess.execute(stmt).mappings().all())


def scenario_echo_rows(sess: Session, session_id: str, scenario_ids: list[str]) -> list[RowMapping]:
    """The version-independent scenario/threat blocks for a SET of scenarios — the board's echo
    source under ?include_superseded=true. Targeted at the scenarios that actually have history
    (typically a few of many), so the bytes hauled scale with regenerations, not with the board.
    The canonical _scenario_read_select, so the echo is column-for-column what the single-plan
    GET overlays from active_plan_row. Empty ids is a no-query []."""
    if not scenario_ids:
        return []
    out = m.Threat_Scenario
    return list(sess.execute(
        _scenario_read_select().where(out.SessionID == session_id,
                                      out.ScenarioID.in_(scenario_ids))
    ).mappings().all())


def plan_row_by_id(sess: Session, session_id: str, output_id: str, plan_id: str) -> RowMapping | None:
    """One specific plan version for the evidence endpoint. The session/output predicates keep a
    foreign plan id a 404 rather than a leak; superseded versions are deliberately readable.
    Explicit columns — PlanJSON and ReviewComment are blobs this endpoint never returns."""
    if not (_valid_guid(output_id) and _valid_guid(plan_id)):
        return None
    p = m.Risk_Treatment_Plan
    return sess.execute(
        select(p.PlanID, p.Status, p.InputSnapshotJSON, p.ValidationJSON).where(
            p.PlanID == plan_id, p.SessionID == session_id, p.ScenarioID == output_id)
    ).mappings().first()


#: The treatment-plan lifecycle events. A tuple, not a set — byte-stable SQL for the plan cache.
#: Derived from the enum, not restated beside it. A hand-maintained copy of a vocabulary that
#: lives somewhere else is the drift this codebase keeps paying for — a new treatment_plan_* event
#: would join the enum and silently miss the audit feed. The prefix IS the membership rule, and
#: `test_treatment_events_match_the_enum_prefix` pins that the derivation still yields exactly the
#: five members this tuple used to list by hand.
_TREATMENT_EVENTS = tuple(e for e in AuditEventType if e.name.startswith("treatment_plan_"))


def treatment_audit_rows(sess: Session, session_id: str,
                        output_id: str | None = None) -> list[RowMapping]:
    """Treatment-plan audit events, oldest first. `output_id` narrows to ONE scenario IN SQL.

    It used to be impossible to narrow here: these events left the indexed `ScenarioID` column NULL
    and buried the id in DetailJSON, which is opaque to SQL — so the endpoint fetched EVERY plan
    event for the whole session and discarded the other scenarios' rows in Python, unbounded. The
    writers now set the column, so the predicate is a seek on IX_ScenarioAudit_Scenario
    (ScenarioID, CreatedAt DESC) WHERE ScenarioID IS NOT NULL.

    Rows written before that change keep ScenarioID NULL and are therefore invisible to the filtered
    form — correct for a filtered read, and harmless here because the un-narrowed call (no
    output_id) still returns them."""
    a = m.Scenario_Audit
    where = [a.SessionID == session_id, a.EventType.in_(_TREATMENT_EVENTS)]
    if output_id is not None:
        where.append(a.ScenarioID == output_id)
    return list(sess.execute(
        select(a.EventType, a.ActorUserID, a.ActorType, a.DetailJSON, a.CreatedAt)
        .where(*where)
        .order_by(a.CreatedAt, a.AuditID)
    ).mappings().all())


def entity_treatment_audit_rows(sess: Session, entity_id: str, *, since=None, until=None,
                                actor: str | None = None, limit: int = 200,
                                offset: int = 0) -> list[RowMapping]:
    """The entity-wide treatment audit feed (compliance export), newest first. Filters the audit
    rows' own EntityID, always server-written from the session row at event time."""
    a = m.Scenario_Audit
    stmt = (
        select(a.SessionID, a.EventType, a.ActorUserID, a.ActorType, a.DetailJSON, a.CreatedAt)
        .where(a.EntityID == entity_id, a.EventType.in_(_TREATMENT_EVENTS)))
    if since is not None:
        stmt = stmt.where(a.CreatedAt >= since)
    if until is not None:
        stmt = stmt.where(a.CreatedAt <= until)
    if actor is not None:
        stmt = stmt.where(a.ActorUserID == actor)
    return list(sess.execute(
        stmt.order_by(a.CreatedAt.desc(), a.AuditID.desc()).limit(limit).offset(offset)
    ).mappings().all())


def prompt_logs_for_plan(sess: Session, plan_id: str) -> list[RowMapping]:
    """Every AI-call receipt for one plan version, oldest first, joined on Prompt_Log.CorrelationID
    (stamped by the worker), never by time-window guessing. Rows predating that column do not
    appear."""
    if not _valid_guid(plan_id):
        return []
    pl = m.Prompt_Log
    return list(sess.execute(
        select(pl.Prompt, pl.ResponseText, pl.Model, pl.ModelVersion, pl.PromptVersion,
            pl.ParseSucceeded, pl.CreatedAt)
        .where(pl.CorrelationID == plan_id)
        .order_by(pl.CreatedAt)
    ).mappings().all())
