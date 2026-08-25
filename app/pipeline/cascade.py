"""Create or replace scenarios for one session and subsystem.

The public functions take a SQLAlchemy session, session data, subsystem and epoch identifiers,
target IDs when regenerating, and an LLM client. They write scenario, stage, audit, and SSE
records, then return the session outcome. Reused epochs make redelivery idempotent. Invalid or
stale target IDs raise a conflict; LLM capacity errors are re-raised for task retry handling.
"""
from __future__ import annotations

import json
from collections.abc import Generator
from contextlib import contextmanager

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import tuning
from app.core.config import get_settings
from app.core.enums import (
    AuditEventType,
    NextSetOutcome,
    RegenGranularity,
    SSEEventType,
    StageStatus,
    SubsystemLevel,
    WorkflowStage,
)
from app.core.logging import get_logger
from app.core.security import redact
from app.db import dal
from app.db import models as m
from app.db.dal import RegenerateConflict, guid, now
from app.pipeline import control_mapping, tasks
from app.pipeline.llm import LLMClient, LLMSlotUnavailable
from app.sse import bus

log = get_logger(__name__)

# Regeneration resets this level before dispatch.
LEVELS_BY_GRANULARITY = {
    RegenGranularity.scenario: (SubsystemLevel.SCENARIOS,),
}

# Next-set requests reset scenarios; additive threat generation also resets threats.
NEXT_SET_LEVELS = (SubsystemLevel.SCENARIOS,)

# Maps a reason code to audit detail and the client message.
_REASON_INFO: dict[str, dict[str, str]] = {
    "no_new_threats_found": {
        "detail": "Every threat identified for this asset already has an active scenario "
                "(including the ones just regenerated). 'Generate next set' only creates "
                "scenarios for threats that don't have one yet, and the one attempt to find "
                "a genuinely new threat found none.",
        "message": "There's nothing new to add. We've already created a scenario for every "
                "threat we know about for this asset.",
    },
    "new_threat_did_not_qualify": {
        "detail": "A candidate threat with no active scenario was found, but it failed "
                "re-scoring before a scenario could be generated for it (its score fell "
                "below the configured threshold, or its threat type is currently excluded).",
        "message": "We found something new, but it didn't meet our criteria for this "
                "asset, so we didn't create a scenario for it.",
    },
    "generation_failed": {
        "detail": "The AI call that writes the scenario failed (provider error or timeout) — "
                "not a scoping rejection. The affected threat(s) remain selected and "
                "re-servable, so this is transient by construction.",
        "message": "We hit a temporary problem generating the scenario(s). Nothing was lost — "
                "click 'generate next set' again to retry.",
    },
    "no_target_ids": {
        "detail": "The regenerate request specified zero target ids after canonicalization — "
                "normally rejected by the request schema itself (output_ids requires at least "
                "one item), so only reachable via a direct/internal caller that bypasses it.",
        "message": "Please select at least one scenario to regenerate.",
    },
    "output_not_found_or_superseded": {
        "detail": "One or more requested OutputIDs did not resolve to an active "
                "(non-superseded) Threat_Scenario_Output row for this session/subsystem — "
                "most often stale ids captured before a prior regeneration already replaced "
                "them, or ids that belong to a different session.",
        "message": "One or more of the scenarios you tried to regenerate have already been "
                "updated or no longer exist — refresh the results and try again with the "
                "current list.",
    },
}

@contextmanager
def _subsystem_lock(sess: Session, sid: str, subsystem_id: int, task_id: str, kind: str) -> Generator[bool]:
    """Yield whether the per-subsystem lock was acquired.

    Commit acquisition before work so a later rollback cannot release it. Release failures are
    logged and do not replace an exception from the wrapped work.
    """
    # acquire_execution_lock, not acquire_lock: every caller here is a regenerate/next-set
    # execution, which runs on a session already completed at its review barrier.
    # acquire_lock's SessionStatus == active fence would CAS-fail on all of them.
    acquired = dal.acquire_execution_lock(sess, sid, subsystem_id, task_id)
    if acquired:
        sess.commit()
    try:
        yield acquired
    finally:
        if acquired:
            try:
                if not dal.release_lock(sess, sid, subsystem_id, task_id):
                    log.warning(f"{kind}.lock_lost", session_id=sid, subsystem=subsystem_id, task_id=task_id)  # noqa: G004
                sess.commit()
            except Exception:  # noqa: BLE001
                log.warning(f"{kind}.lock_release_failed", session_id=sid, subsystem=subsystem_id)  # noqa: G004


def _settle_or_raise(sess: Session, sid: str, subsystem_id: int, epoch: int,
                    level: SubsystemLevel, kind: str) -> None:
    """Verify that this epoch completed, or raise if its stage claim was lost.

    An empty write is valid when the same epoch already completed. A reaped or superseded claim
    raises `RuntimeError`.
    """
    if not dal.stage_settled_at_epoch(sess, sid, subsystem_id, level, epoch):
        raise RuntimeError(f"{kind} claim lost mid-flight (stage reaped or superseded)")
    log.info(f"{kind}.redelivery_already_landed", session_id=sid, subsystem=subsystem_id, epoch=epoch)  # noqa: G004


def _reason_info(reason: str | None) -> dict[str, str | None]:
    """Return the audit detail and client message for `reason`.

    Unknown or missing reason codes return `None` for both values.
    """
    info = _REASON_INFO.get(reason or "", {})
    return {"detail": info.get("detail"), "message": info.get("message")}


def _next_set_outcome(requested: int, made: int, variants: int, pool_size: int, *,
                    top_up_failed: bool = False) -> NextSetOutcome:
    """Classify a next-set result from its requested, created, and failed counts.

    `made + variants >= requested` is complete. A shortfall in the selected threat pool or a
    failed top-up is retryable; otherwise the eligible work is exhausted.
    """
    if made + variants >= requested:
        return NextSetOutcome.complete
    if made < pool_size or top_up_failed:  # actionable case wins when both apply
        return NextSetOutcome.partial_retryable
    return NextSetOutcome.exhausted

def _settle_next_set_click(sess: Session, scenario_session: dict, subsystem_id: int, epoch: int, *,
                        requested: int, made: int, variants: int, pool_size: int,
                        reason: str | None = None,
                        top_up_failed: bool = False) -> NextSetOutcome:
    """Commit an audit row and publish a next-set result.

    The audit row is committed before the best-effort SSE event. Return the classified outcome;
    include reason details only when `made + variants == 0`.
    """
    sid = scenario_session["SessionID"]
    delivered = made + variants
    outcome = _next_set_outcome(requested, made, variants, pool_size, top_up_failed=top_up_failed)
    detail = json.dumps({"outcome": str(outcome), "requested": requested, "delivered": delivered,
                        "variants": variants, "reason": reason, "epoch": epoch,
                        "subsystem_id": subsystem_id})
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"],
                    EntityID=scenario_session["EntityID"], SubsystemID=subsystem_id,
                    Stage=WorkflowStage.SCENARIO_GENERATION,
                    EventType=AuditEventType.next_set_outcome, DetailJSON=detail)
    sess.commit()

    no_new = delivered == 0
    info = _reason_info(reason) if no_new else {"detail": None, "message": None}
    bus.publish(sid, {"type": str(SSEEventType.next_set_result), "session_id": sid,
                    "subsystem_id": subsystem_id, "new_scenarios": delivered, "no_new": no_new,
                    "new_variants": variants,
                    "outcome": str(outcome), "requested": requested, "epoch": epoch,
                    "reason": reason, **info,
                    "ts": now().isoformat()})
    return outcome


def _publish_regen_result(sid: str, subsystem_id: int, requested_ids: list[str] | list[int] | None,
                        new_output_ids: list[str], *, reason: str | None = None,
                        replacements: list[dict] | None = None,
                        failed_threat_ids: set[str] | None = None,
                        rescored_threat_ids: set[str] | None = None) -> None:
    """Publish an advisory regeneration result for committed output IDs.

    `replacements` maps old output IDs to new ones. Failed and rescored threat IDs describe
    partial results. The event is advisory; database rows remain the source of record.
    """
    bus.publish(sid, {"type": str(SSEEventType.regen_result), "session_id": sid,
                    "subsystem_id": subsystem_id, "reason": reason, **_reason_info(reason),
                    "requested_output_ids": [str(i) for i in (requested_ids or [])],
                    "new_output_ids": new_output_ids,
                    "replacements": replacements or [],
                    "failed_threat_ids": sorted(failed_threat_ids or ()),
                    "rescored_threat_ids": sorted(rescored_threat_ids or ()),
                    "ts": now().isoformat()})

def _regen_replacements(sess: Session, sid: str, subsystem_id: int, epoch: int) -> list[dict]:
    """Return active output replacements committed at `epoch`.

    Each item has `old` and `new` IDs. A retained row has `old=None`, which lets callers derive
    all new output IDs from the same result.
    """
    out = m.Threat_Scenario_Output
    return [{"old": str(old) if old else None, "new": str(new)} for new, old in sess.execute(
        select(out.OutputID, out.ReplacesOutputID).where(
            out.SessionID == sid, out.SubsystemID == subsystem_id,
            dal.active(out.Superseded), out.GenerationEpoch == epoch)
    ).all()]

def _publish_regen_result_after_commit(sess: Session, sid: str, subsystem_id: int,
                                    target_ids: list[str] | list[int] | None, epoch: int,
                                    failed_threat_ids: set[str] | None = None,
                                    rescored_threat_ids: set[str] | None = None) -> None:
    """Publish a committed regeneration result without raising.

    The threat-ID sets describe partial-batch failures and rescoring exclusions. If querying or
    publishing fails, roll back the SQLAlchemy session when possible and log the failure.
    """
    try:
        pairs = _regen_replacements(sess, sid, subsystem_id, epoch)
        _publish_regen_result(sid, subsystem_id, target_ids, [p["new"] for p in pairs],
                            replacements=[p for p in pairs if p["old"]],
                            failed_threat_ids=failed_threat_ids,
                            rescored_threat_ids=rescored_threat_ids)
    except Exception:
        # A disconnected session can reject rollback, so log that failure separately.
        try:
            sess.rollback()
        except Exception:
            log.warning("regen.result_rollback_failed", session_id=sid, subsystem=subsystem_id, exc_info=True)
        log.warning("regen.result_publish_failed", session_id=sid, subsystem=subsystem_id, exc_info=True)


def _split_target_ids(target_ids) -> tuple[list[str], list[str]]:
    """Canonicalize and deduplicate requested IDs for reporting and SQL lookup.

    Return `(seen, lookup)`: `seen` keeps every unique spelling for conflict reporting, while
    `lookup` contains only valid canonical IDs. For example, a malformed ID is reported in
    `seen` but excluded from the database query.
    """
    seen: list[str] = []
    lookup: list[str] = []
    for raw in dict.fromkeys(target_ids or []):
        try:
            canonical = dal.canonical_guid(raw)
        except (ValueError, AttributeError, TypeError):
            # Exclude malformed IDs from SQL but retain their spelling for the conflict.
            if raw not in seen:
                seen.append(raw)
            continue
        if canonical not in seen:
            seen.append(canonical)
            lookup.append(canonical)
    return seen, lookup


def get_threat_id_to_redo(sess: Session, session_id: str, subsystem_id: int,
                granularity: RegenGranularity,
                target_ids: list[str] | list[int] | None) -> dict[str, tasks.RegenTarget]:
    """Resolve active output IDs to regeneration targets.

    Return `{OutputID: RegenTarget}` for this session and subsystem. Raise `RegenerateConflict`
    when no IDs are supplied or any requested ID is missing, malformed, or superseded.
    """
    ids, lookup_ids = _split_target_ids(target_ids)
    if not ids:
        raise RegenerateConflict(f"{granularity} regeneration requires at least one target id",
                                reason="no_target_ids")
    out = m.Threat_Scenario_Output
    rows = sess.execute(
        select(out.OutputID, m.Scoped_Threat.ThreatID, out.ScopedThreatID,
            out.ScenarioNumber, out.IdentityHash)
        .select_from(out.__table__.join(
            m.Scoped_Threat, out.ScopedThreatID == m.Scoped_Threat.ScopedThreatID))
        .where(out.OutputID.in_(lookup_ids),
            out.SessionID == session_id,
            out.SubsystemID == subsystem_id,
            out.Superseded == 0)
    ).all()
    found = {r.OutputID: tasks.RegenTarget(output_id=r.OutputID, threat_id=r.ThreatID,
                                        scoped_threat_id=r.ScopedThreatID,
                                        scenario_number=r.ScenarioNumber,
                                        identity_hash=r.IdentityHash)
            for r in rows}
    missing = set(ids) - found.keys()
    if missing:
        # String sorting keeps conflict reporting valid when ID types are mixed.
        raise RegenerateConflict(f"scenario output(s) not found or not active: {sorted(missing, key=str)}",
                                reason="output_not_found_or_superseded")
    return found


def _resolve_regen_context(scenario_session: dict) -> tuple[list[dict], dict]:
    """Parse `SubsystemsJSON` and `AssetContextJSON` from a session record.

    Return the subsystem list and asset-context mapping. Invalid JSON raises the decoder error;
    a missing or empty asset context becomes `{}`.
    """
    subsystems = json.loads(scenario_session["SubsystemsJSON"])
    asset_context = json.loads(scenario_session.get("AssetContextJSON") or "{}")
    return subsystems, asset_context


def _build_regen_audit_detail(threat_ids: set[str] | None, target_ids: list[str] | list[int] | None,
                            epoch: int, user_note: str | None,
                            replacements: list[dict] | None = None,
                            failed_threat_ids: set[str] | None = None,
                            rescored_threat_ids: set[str] | None = None) -> str:
    """Build audit JSON for a completed regeneration.

    Include target and requested IDs, replacements, failed and rescored threat IDs, the epoch,
    and a redacted user note. Return the JSON string.
    """
    return json.dumps({
        "target_ids": sorted(threat_ids) if threat_ids else None,
        "requested_ids": list(target_ids) if target_ids else None,
        "replacements": replacements or [],
        "failed_threat_ids": sorted(failed_threat_ids) if failed_threat_ids else [],
        "rescored_threat_ids": sorted(rescored_threat_ids) if rescored_threat_ids else [],
        "epoch": epoch, "user_note": redact(user_note)})

def run_regeneration(sess: Session, scenario_session: dict, subsystem_id: int, granularity: RegenGranularity,
                    target_ids: list[str] | list[int] | None, epoch: int, llm: LLMClient, task_id: str,
                    user_note: str | None = None) -> str | None:
    """Regenerate selected scenarios for one subsystem.

    Validate target outputs, write replacements, record failures, publish advisory events, and
    return the session outcome. A capacity error is re-raised for task retry; stale targets are
    reported as conflicts without failing the stage.
    """
    sid = scenario_session["SessionID"]
    subsystems, asset_context = _resolve_regen_context(scenario_session)

    try:
        targets = get_threat_id_to_redo(sess, sid, subsystem_id, granularity, target_ids)
    except RegenerateConflict as exc:
        log.info("regen.target_conflict", session_id=sid, subsystem=subsystem_id, reason=str(exc))
        # Finish the reset stage so a rejected request does not leave the session in IDLE.
        if dal.claim_stage(sess, sid, subsystem_id, SubsystemLevel.SCENARIOS, epoch, task_id):
            dal.finish_stage(sess, sid, subsystem_id, SubsystemLevel.SCENARIOS,
                            StageStatus.AWAITING_DECISION, epoch, task_id)
            sess.commit()
        _publish_regen_result(sid, subsystem_id, target_ids, [], reason=exc.reason)
        return tasks.decide_session_outcome(sess, scenario_session)
    except Exception as exc:  # noqa: BLE001
        log.error("regen.pre_lock_error", session_id=sid, subsystem=subsystem_id, error=repr(exc))
        # Record this failure directly because no stage claim exists yet.
        tasks._record_failure(sess, scenario_session, subsystem_id, exc, epoch,
                            extra={"user_note": redact(user_note)} if user_note else None)
        sess.commit()
        return tasks.decide_session_outcome(sess, scenario_session)

    with _subsystem_lock(sess, sid, subsystem_id, task_id, "regen") as acquired:
        if not acquired:
            log.warning("regen.locked", session_id=sid, subsystem=subsystem_id)
            return tasks.decide_session_outcome(sess, scenario_session)
        try:
            targets = get_threat_id_to_redo(sess, sid, subsystem_id, granularity, target_ids)
            threats = dal.active_threats(sess, sid, subsystem_id)
            unresolved: dict = {}

            # Commit the audit row with the scenario transaction.
            def _stage_regen_audit(_provs) -> None:
                dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"],
                                EntityID=scenario_session["EntityID"], SubsystemID=subsystem_id,
                                Stage=WorkflowStage.SCENARIO_GENERATION,
                                EventType=AuditEventType.regeneration_completed, Granularity=str(granularity),
                                DetailJSON=_build_regen_audit_detail(
                                    {t.threat_id for t in targets.values()}, target_ids, epoch, user_note,
                                    replacements=[p for p in _regen_replacements(sess, sid, subsystem_id, epoch)
                                                if p["old"]],
                                    failed_threat_ids=unresolved.get("failed_ids"),
                                    rescored_threat_ids=unresolved.get("rescored_ids")))

            scen_provs = tasks.write_scenarios(sess, scenario_session, subsystems, asset_context, threats, llm, task_id,
                                            epoch=epoch, regen_targets=targets, require_lock=True,
                                            on_before_commit=_stage_regen_audit,
                                            unresolved_targets=unresolved)
            if not scen_provs:
                _settle_or_raise(sess, sid, subsystem_id, epoch, SubsystemLevel.SCENARIOS, "regen")
            else:
                _publish_regen_result_after_commit(sess, sid, subsystem_id, target_ids, epoch,
                                                failed_threat_ids=unresolved.get("failed_ids"),
                                                rescored_threat_ids=unresolved.get("rescored_ids"))
        except RegenerateConflict as exc:
            # A concurrent update can stale a target; report it without failing the stage.
            log.info("regen.target_conflict", session_id=sid, subsystem=subsystem_id, reason=str(exc))
            _publish_regen_result(sid, subsystem_id, target_ids, [], reason=exc.reason)
        except LLMSlotUnavailable:
            # Let task retry handling process this transient capacity error.
            raise
        except Exception as exc:  # noqa: BLE001
            tasks._record_failure(sess, scenario_session, subsystem_id, exc, epoch,
                                extra={"user_note": redact(user_note)} if user_note else None)
            sess.commit()

    return tasks.decide_session_outcome(sess, scenario_session)



def _coverage_exclusions(threats: list[dict]) -> list[str]:
    """Return distinct, non-empty prior threat labels within the prompt budget.

    Preserve `active_threats` order, so newer labels appear first. Stop before adding a label
    that would exceed the configured character budget.
    """
    out: list[str] = []
    seen: set[str] = set()
    used = 0
    budget = get_settings().exclusions_char_budget
    for t in threats:
        lbl = tasks.threat_label(t)
        if not lbl or lbl in seen:
            continue
        used += len(lbl) + 2
        if used > budget:
            break
        seen.add(lbl)
        out.append(lbl)
    return out


def _buffered_ask(shortfall: int, cap: int) -> int:
    """Return a bounded request count for a shortfall.

    The result is twice `shortfall`, capped at `cap`, and never below `shortfall`.
    """
    return max(shortfall, min(shortfall * 2, cap))

def _top_up_with_variants(sess: Session, scenario_session: dict, subsystem_id: int, epoch: int,
                        subsystems: list[dict], asset_context: dict, llm: LLMClient, task_id: str,
                        shortfall: int, *, exclude: set[str] | None = None) -> tuple[int, bool]:
    """Create alternate scenarios for unserved next-set slots.

    Return `(created, failed)` and never raise. `failed=True` marks an exception, while
    `(0, False)` means the fallback completed with no rows. `shortfall` is the number of slots.
    """
    if shortfall <= 0:
        return 0, False
    sid = scenario_session["SessionID"]
    try:
        created = tasks.write_variant_scenarios(sess, scenario_session, subsystem_id, subsystems,
                                                asset_context, llm, task_id, epoch,
                                                max_variants=shortfall, exclude_threat_ids=exclude)
        if created:
            dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"],
                            EntityID=scenario_session["EntityID"], SubsystemID=subsystem_id,
                            Stage=WorkflowStage.SCENARIO_GENERATION,
                            EventType=AuditEventType.generation_complete,
                            DetailJSON=json.dumps({"next_set": True, "subsystem_id": subsystem_id,
                                                "new_scenarios": created, "variants_generated": created}))
            sess.commit()
        return created, False
    except Exception as exc:  # noqa: BLE001
        # A rollback failure must not escape from this fallback.
        try:
            sess.rollback()
        except Exception:
            log.warning("next_set.variant_top_up_rollback_failed", session_id=sid,
                        subsystem=subsystem_id, exc_info=True)
        transient = isinstance(exc, LLMSlotUnavailable)
        (log.warning if transient else log.error)(
            "next_set.variant_top_up_failed", session_id=sid, subsystem=subsystem_id,
            shortfall=shortfall, transient=transient, exc_info=True)
        return 0, True

def _settle_next_set_conflict(sess: Session, scenario_session: dict, subsystem_id: int, epoch: int,
                            exc: RegenerateConflict, subsystems: list[dict], asset_context: dict,
                            llm: LLMClient, task_id: str, next_set_size: int,
                            additive_failed: bool = False) -> str:
    """Finish a next-set request when additive threat generation returns no usable result.

    Try variant scenarios, record the result, and return a client signal. No fresh scenarios
    were committed on this path; the threats stage is already terminal.
    """
    sid = scenario_session["SessionID"]
    created, top_up_failed = _top_up_with_variants(sess, scenario_session, subsystem_id, epoch,
                                                subsystems, asset_context, llm, task_id,
                                                next_set_size)
    if not created:
        dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"],
                        EntityID=scenario_session["EntityID"], SubsystemID=subsystem_id,
                        Stage=WorkflowStage.SCENARIO_GENERATION,
                        EventType=AuditEventType.generation_complete,
                        DetailJSON=json.dumps({"next_set": True, "subsystem_id": subsystem_id,
                                            "new_scenarios": 0, "no_new": True,
                                            "reason": exc.reason, **_reason_info(exc.reason)}))
        sess.commit()
    # Keep the request retryable when either generation step failed without rows.
    retryable = exc.reason == "generation_failed" or additive_failed
    _settle_next_set_click(sess, scenario_session, subsystem_id, epoch,
                        requested=next_set_size, made=0, variants=created,
                        pool_size=0, reason=exc.reason,
                        top_up_failed=top_up_failed or retryable)
    return "generated" if created else "no_new_threats_this_round"

def run_next_set(sess: Session, scenario_session: dict, subsystem_id: int, epoch: int,
                threats_epoch: int, llm: LLMClient, task_id: str) -> str | None:
    """Add up to the configured number of new scenarios for one subsystem.

    Use unserved threats first, then make one additive threat-generation call if needed. New
    scenarios accumulate without replacing unrelated outputs. Return the session outcome or a
    no-new-threats signal. Reused epochs prevent duplicate threat generation.
    """
    sid = scenario_session["SessionID"]
    subsystems, asset_context = _resolve_regen_context(scenario_session)

    signal: str | None = None
    with _subsystem_lock(sess, sid, subsystem_id, task_id, "next_set") as acquired:
        if not acquired:
            # Serialize concurrent clicks for this session and subsystem.
            log.warning("next_set.locked", session_id=sid, subsystem=subsystem_id)
            return tasks.decide_session_outcome(sess, scenario_session)
        next_set_size = get_settings().next_set_size
        additive_failed = False
        try:
            tn = tuning.from_session(scenario_session)  # Use the session's frozen rulebook.
            next_set_size = tn.next_set_size

            fresh = dal.next_unserved_unique_threats(sess, sid, subsystem_id, next_set_size)

            if len(fresh) < next_set_size and not dal.stage_completed_at_epoch_or_newer(
                    sess, sid, subsystem_id, SubsystemLevel.THREATS, threats_epoch):
                
                prior_threats = dal.active_threats(sess, sid, subsystem_id)
                exclude = _coverage_exclusions(prior_threats)

                dal.reset_stage_for_regen(sess, sid, subsystem_id, (SubsystemLevel.THREATS,), threats_epoch)
                new_threats: list[dict] = []
                try:
                    new_threats, _prov = tasks.find_threats(sess, scenario_session, subsystems, asset_context, llm, task_id,
                                                        epoch=threats_epoch, supersede=False, exclude=exclude,
                                                        prior_threats=prior_threats,
                                                        max_threats=_buffered_ask(next_set_size - len(fresh),
                                                                                tn.max_threats_per_asset))
                except LLMSlotUnavailable:
                    raise
                except Exception as exc:  # noqa: BLE001
                    # Finish the stage below so this failure does not block the session.
                    log.error("next_set.additive_find_threats_failed", session_id=sid, subsystem=subsystem_id, error=repr(exc))
                    sess.rollback()
                    additive_failed = True
                # A running threats stage would block the session outcome.
                dal.finish_stage(sess, sid, subsystem_id, SubsystemLevel.THREATS, StageStatus.COMPLETE,
                                threats_epoch, task_id)
                sess.commit()
                log.info("next_set.additive_threats", session_id=sid, subsystem=subsystem_id, added=len(new_threats))
                fresh = dal.next_unserved_unique_threats(sess, sid, subsystem_id, next_set_size)

            threats = dal.active_threats(sess, sid, subsystem_id)

            # Commit the audit row with the scenario transaction.
            def _stage_next_set_audit(provs) -> None:
                dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"],
                                EntityID=scenario_session["EntityID"], SubsystemID=subsystem_id,
                                Stage=WorkflowStage.SCENARIO_GENERATION,
                                EventType=AuditEventType.generation_complete,
                                DetailJSON=json.dumps({"next_set": True, "subsystem_id": subsystem_id,
                                                    "new_scenarios": len(provs)}))
                
            scen_provs = tasks.write_scenarios(sess, scenario_session, subsystems, asset_context, threats, llm, task_id,
                                            epoch=epoch, target_threat_ids=set(fresh), require_lock=True,
                                            on_before_commit=_stage_next_set_audit)
            if not scen_provs:
                _settle_or_raise(sess, sid, subsystem_id, epoch, SubsystemLevel.SCENARIOS, "next_set")
            else:
                signal = "generated"
                made = len(scen_provs)
                variants, top_up_failed = _top_up_with_variants(
                    sess, scenario_session, subsystem_id, epoch, subsystems, asset_context, llm,
                    task_id, next_set_size - len(fresh), exclude=set(fresh))
                _settle_next_set_click(sess, scenario_session, subsystem_id, epoch,
                                    requested=next_set_size, made=made, variants=variants,
                                    pool_size=len(fresh), top_up_failed=top_up_failed or additive_failed)
        except RegenerateConflict as exc:
            # An empty additive result ends this round without failing the stage.
            log.info("next_set.no_new_threats", session_id=sid, subsystem=subsystem_id, reason=str(exc))
            signal = _settle_next_set_conflict(sess, scenario_session, subsystem_id, epoch, exc,
                                            subsystems, asset_context, llm, task_id, next_set_size,
                                            additive_failed=additive_failed)
        except LLMSlotUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001
            tasks._record_failure(sess, scenario_session, subsystem_id, exc, epoch)
            sess.commit()
            # Record a durable retryable outcome even when the main operation fails.
            try:
                _settle_next_set_click(sess, scenario_session, subsystem_id, epoch,
                                    requested=next_set_size, made=0, variants=0, pool_size=0,
                                    reason="generation_failed", top_up_failed=True)
            except Exception:
                log.warning("next_set.failure_outcome_record_failed", session_id=sid,
                            subsystem=subsystem_id, exc_info=True)

    # Recompute session state after every path.
    outcome = tasks.decide_session_outcome(sess, scenario_session)
    return "no_new_threats_this_round" if signal == "no_new_threats_this_round" else outcome


def _sweep_one_session(sess: Session, llm: LLMClient, sid: str, subsystem_id: int,
                    epoch: int) -> bool:
    """Map one queued session's controls under the per-subsystem lock. True if mapping ran.

    Split out of run_control_map_sweep so that ONE session's failure is contained to that session:
    the caller wraps this call, not the loop. Everything that can raise for session-specific
    reasons — the lock, the row read, the JSON blobs, the mapping itself — is inside here.
    """
    task_id = guid()
    with _subsystem_lock(sess, sid, subsystem_id, task_id, "control_map_sweep") as acquired:
        if not acquired:
            # A live regenerate/next-set/accept owns this session. Correct to skip — but SAY so.
            # A session losing this race every tick would otherwise be indistinguishable from one
            # that was never queued, which is the silent-degradation class this whole effort
            # exists to remove. The reaper reclaims expired _LOCK rows, so this cannot wedge.
            log.info("control_map_sweep.deferred", session_id=sid, subsystem=subsystem_id)
            return False
        row = dal.load_session(sess, sid)
        if row is None:                      # deleted between the queue read and here
            return False
        scenario_session = dict(row)
        subsystems, asset_context = _resolve_regen_context(scenario_session)
        # durable=True: the sweep owns its transaction outright, unlike the in-pipeline caller
        # which may still hold uncommitted scenario rows.
        # task_id/epoch are the lease fence. The sweep holds no SCENARIOS claim, so map_controls'
        # renew_lease correctly fails and its stage_settled_at_epoch fallback is what authorises
        # the run — which is why the epoch comes from that settled row.
        control_mapping.map_controls(sess, scenario_session, asset_context, subsystems, llm,
                                    subsystem_id, task_id, epoch, durable=True)
        return True


def run_control_map_sweep(sess: Session, llm: LLMClient) -> list[str]:
    """Drain the control-mapping retry queue. Returns the session ids actually mapped.

    THE QUEUE'S MISSING CONSUMER. See `control_mapping.sessions_awaiting_control_mapping` for why
    it had none and what that cost: three `map_controls` paths return without stamping
    `ControlsMappedAt` on the documented promise that "the next run retries it", but the only
    caller is the tail of a scenario batch, so for a finished session there was no next run and
    every transient failure became a permanent, authoritative-looking `controls: []`.

    It lives HERE rather than in control_mapping because this is the module that owns
    session-level execution: `_subsystem_lock` is the codebase's one-writer-per-subsystem fence
    ([R5]) and the sweep needs exactly it. `write_scenarios` settles the SCENARIOS stage before it
    maps, so "settled" alone cannot prove the pipeline has finished with the session — the lock
    closes that race against a concurrent regenerate/next-set, which would otherwise both map the
    same outputs and lose the whole batch to one duplicate-key IntegrityError.

    `map_controls` is reused UNCHANGED and deliberately: `no_candidates`, `lease_lost` and
    per-output `unanswered` are then all retried by one consumer instead of needing a guard each.
    """
    swept: list[str] = []
    for sid, subsystem_id, epoch in control_mapping.sessions_awaiting_control_mapping(sess):
        try:
            if _sweep_one_session(sess, llm, sid, subsystem_id, epoch):
                swept.append(sid)
        except Exception:  # [R8] one session must never stall the whole queue
            # Without this the first raising session killed the entire tick, and since the queue
            # is now ordered oldest-first that same session would head every subsequent tick —
            # a permanent block on everything behind it. Roll back so the next iteration starts
            # on a clean session rather than inheriting a failed transaction.
            sess.rollback()
            log.warning("control_map_sweep.session_failed", session_id=sid, exc_info=True)
    if swept:
        log.info("control_map_sweep.ran", sessions=len(swept))
    return swept
