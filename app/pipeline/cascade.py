"""Regeneration cascade — redo a subsystem's scenario(s) without re-running the whole
pipeline. Row-scoped, so redoing one bad item doesn't discard its siblings.

Reuses tasks.py's CAS/lock/epoch machinery: `dal.acquire_lock` for the `_LOCK` mutex,
`dal.claim_stage`'s `epoch`, and `decide_session_outcome` to re-enter REVIEW.

The epoch is reserved by the CALLER (the endpoint's session-level CAS, once per logical
request) and passed in — never minted here. A Celery redelivery (acks_late) re-executes at
the SAME epoch, so claim_stage's CAS no-ops a level that already landed; a freshly-minted
epoch would destructively re-run the whole hop.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import tuning
from app.core.config import get_settings
from app.core.enums import (
    AuditEventType, NextSetOutcome, RegenGranularity, SSEEventType, StageStatus, SubsystemLevel,
    WorkflowStage,
)
from app.core.logging import get_logger
from app.core.security import redact
from app.db import dal
from app.db import models as m
from app.db.dal import RegenerateConflict, guid, now
from app.pipeline import tasks
from app.pipeline.llm import LLMClient, LLMSlotUnavailable
from app.sse import bus

log = get_logger(__name__)

# sessions.py::post_regenerate resets exactly these levels to IDLE before dispatching;
# run_regeneration MUST regenerate the same set, or the endpoint resets a stage nothing
# regenerates (stuck IDLE → reaper).
LEVELS_BY_GRANULARITY = {
    RegenGranularity.scenario: (SubsystemLevel.SCENARIOS,),
}

# The endpoint resets ONLY SCENARIOS for a next-set click; an additive find_threats, when
# needed, resets THREATS itself (see run_next_set).
NEXT_SET_LEVELS = (SubsystemLevel.SCENARIOS,)


@contextmanager
def _subsystem_lock(sess: Session, sid: str, subsystem_id: int, task_id: str, kind: str) -> Iterator[bool]:
    """Acquire the per-subsystem `_LOCK` and commit it durable BEFORE any work: a body exception
    routes through tasks._record_failure's unconditional rollback, which would otherwise undo an
    uncommitted acquire and make the release spuriously fail. Always releases + commits on exit,
    logging (never raising) a release failure so it can't mask the body's own error. A
    not-acquired body must bail without doing work — the caller checks the yielded flag."""
    acquired = dal.acquire_lock(sess, sid, subsystem_id, task_id)
    if acquired:
        sess.commit()
    try:
        yield acquired
    finally:
        if acquired:
            try:
                if not dal.release_lock(sess, sid, subsystem_id, task_id):
                    log.warning(f"{kind}.lock_lost", session_id=sid, subsystem=subsystem_id, task_id=task_id)
                sess.commit()
            except Exception:
                log.warning(f"{kind}.lock_release_failed", session_id=sid, subsystem=subsystem_id)


def _settle_or_raise(sess: Session, sid: str, subsystem_id: int, epoch: int,
                    level: SubsystemLevel, kind: str) -> None:
    """Shared 'write_scenarios returned [] without raising' check: a batch already landed at this
    epoch (stage AWAITING_DECISION/COMPLETE) is a benign idempotent redelivery — log and fall
    through; anything else is a genuine lost claim (reaped or superseded) — raise."""
    if not dal.stage_settled_at_epoch(sess, sid, subsystem_id, level, epoch):
        raise RuntimeError(f"{kind} claim lost mid-flight (stage reaped or superseded)")
    log.info(f"{kind}.redelivery_already_landed", session_id=sid, subsystem=subsystem_id, epoch=epoch)


# reason code -> (log-facing detail, end-user-facing message). ONE copy so the SSE payload, the
# audit DetailJSON and every consumer say the same thing.
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


def _reason_info(reason: str | None) -> dict[str, str | None]:
    """detail + message for an advisory SSE/audit reason code. An unrecognized or absent code
    returns both as None rather than raising, so a caller can always spread this in."""
    info = _REASON_INFO.get(reason or "", {})  # None → "" (not a key): same {} result, typed str
    return {"detail": info.get("detail"), "message": info.get("message")}


def _next_set_outcome(requested: int, made: int, variants: int, pool_size: int, *,
                    top_up_failed: bool = False) -> NextSetOutcome:
    """Classify what a click ACHIEVED. `made` is fresh-threat scenarios committed, `variants` the
    alternate takes topped up, `pool_size` how many unserved threats the click actually targeted.

    `made < pool_size` is the retryable signal: the pool handed over N threats and fewer came
    back, so generation(s) failed. Those targets keep Selected=1 and stay re-servable, making the
    next click a genuine retry. Anything else short means nothing further EXISTS — a correct
    terminal answer, not a deficiency, which is exactly the distinction a bare shortfall count
    cannot express.

    `top_up_failed` closes the one hole in that reasoning. `_top_up_with_variants` MUST NEVER
    RAISE, so it reports every failure — a dropped connection, a malformed ScenarioJSON, a bug —
    as `created=0`, which is byte-identical to "nothing was eligible". On the conflict path
    (made=0, pool_size=0) that lands on `exhausted`, which schemas.py publishes to the client as
    "nothing further exists for this asset; clicking again changes nothing" and greys the button.
    A transient error must never present as a terminal state, so a FAILED top-up is
    partial_retryable — the one outcome that tells the user to click again."""
    if made + variants >= requested:
        return NextSetOutcome.complete
    if made < pool_size or top_up_failed:  # actionable case wins when both apply
        return NextSetOutcome.partial_retryable
    return NextSetOutcome.exhausted


def _settle_next_set_click(sess: Session, scenario_session: dict, subsystem_id: int, epoch: int, *,
                        requested: int, made: int, variants: int, pool_size: int,
                        reason: str | None = None,
                        top_up_failed: bool = False) -> NextSetOutcome:
    """The ONE place a "generate next set" click reports itself. Records the durable audit row
    FIRST, then mirrors it to the advisory SSE, and returns the outcome.

    Order is load-bearing. `bus.publish` is best-effort behind a circuit breaker with NO replay
    log (see app/sse/bus.py) — a client that never connected, or whose connection dropped, learns
    nothing from it. The audit row is what the status board serves as `last_next_set`, so it must
    be committed before the hint goes out; then a dropped event costs nothing, because the next
    board poll (or the reconcile snapshot on SSE reconnect) still carries the outcome. Writing
    both here means an outcome can never be published without also being recorded.

    `reason` is the ClickOutcomeReason that made the click fall back or come up empty. It rides
    the payload as provenance whatever happened, but its detail/message pair is spread ONLY when
    the click was fruitless — those sentences are phrased "nothing was added" and would flatly
    contradict a payload reporting five new scenarios."""
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
                        replacements: list[dict] | None = None) -> None:
    """Advisory SSE naming exactly which outputs a regeneration replaced. `replacements` carries
    the old→new PAIRS — the two flat lists beside it cannot express a mapping (three targets give
    three old and three new ids with no way to pair them) and stay only for back-compat.
    new_output_ids=[] means the click was fruitless. Purely informational, same contract as
    _publish_next_set_result; the authoritative record is generation_epoch on the /results rows."""
    bus.publish(sid, {"type": str(SSEEventType.regen_result), "session_id": sid,
                    "subsystem_id": subsystem_id, "reason": reason, **_reason_info(reason),
                    "requested_output_ids": [str(i) for i in (requested_ids or [])],
                    "new_output_ids": new_output_ids,
                    "replacements": replacements or [],
                    "ts": now().isoformat()})


def _regen_replacements(sess: Session, sid: str, subsystem_id: int, epoch: int) -> list[dict]:
    """`[{"old", "new"}]` for the rows this epoch committed. The epoch is unique per hop
    (dal.next_epoch), so the active rows at it are exactly this call's replacements. ONE query
    shared by the SSE tail and the audit row so they cannot disagree. Indexed seek — never a
    `Superseded = 1` scan (no index serves it).

    Rows with `old` None are RETAINED so the caller can still derive the full new_output_ids list
    from this one query; callers wanting only true replacements filter on `old`."""
    out = m.Threat_Scenario_Output
    return [{"old": str(old) if old else None, "new": str(new)} for new, old in sess.execute(
        select(out.OutputID, out.ReplacesOutputID).where(
            out.SessionID == sid, out.SubsystemID == subsystem_id,
            out.Superseded == 0, out.GenerationEpoch == epoch)
    ).all()]


def _publish_regen_result_after_commit(sess: Session, sid: str, subsystem_id: int,
                                    target_ids: list[str] | list[int] | None, epoch: int) -> None:
    """Advisory tail of a SUCCESSFUL regen: publish regen_result for the rows this epoch committed.

    MUST NEVER RAISE. It runs after the success commit, so an escape into run_regeneration's
    generic handler would route a committed success through tasks._record_failure — whose
    stage_error audit row and error SSE are unconditional — telling the client a success failed.
    Losing the hint costs nothing (the client recovers via generation_epoch on /results)."""
    try:
        pairs = _regen_replacements(sess, sid, subsystem_id, epoch)
        _publish_regen_result(sid, subsystem_id, target_ids, [p["new"] for p in pairs],
                            replacements=[p for p in pairs if p["old"]])
    except Exception:  # noqa: BLE001 — advisory-only tail; must never poison a committed success
        # The rollback needs its own guard: on a broken connection whose SQLSTATE isn't in the
        # dialect's is_disconnect set, ROLLBACK itself re-raises — recreating the exact
        # spurious-failure bug above.
        try:
            sess.rollback()
        except Exception:  # noqa: BLE001
            log.warning("regen.result_rollback_failed", session_id=sid, subsystem=subsystem_id, exc_info=True)
        log.warning("regen.result_publish_failed", session_id=sid, subsystem=subsystem_id, exc_info=True)


def _split_target_ids(target_ids) -> tuple[list[str], list[str]]:
    """Split the caller's requested ids into (all, well-formed-only), canonicalizing and deduping
    in one pass. Returns the full list for the caller-facing "missing" report and the subset safe
    to put in a WHERE clause."""
    seen: list[str] = []
    lookup: list[str] = []
    for raw in dict.fromkeys(target_ids or []):
        try:
            canonical = dal.canonical_guid(raw)
        except (ValueError, AttributeError, TypeError):
            # malformed: never sent to SQL (GUID.bind_processor would raise → 500); still
            # reported, by its original spelling, through the normal not-found path
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
    """Turn the caller's requested target ids into {OutputID: RegenTarget} — the exact ROWS to
    redo, never a bare set of ThreatIDs. With multiple coexisting scenarios per threat
    (ScenarioNumber), a ThreatID collapses regen of #1 and #2 into one indistinguishable target.

    Raises RegenerateConflict if none were given, or if any id doesn't resolve to an active
    (non-superseded) output for this session/subsystem.
    """
    # Canonicalize BEFORE the `missing` comparison: `found` is keyed by OutputIDs that
    # GUID.result_processor already canonicalized, so comparing raw client spellings (uppercase,
    # dashless, braced) reports matched rows as missing — a false regenerate_conflict on a valid
    # request. A malformed id is left as-is so the not-found path names it, instead of
    # GUID.bind_processor raising and surfacing as a 500.
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
        # key=str: ids are str|int depending on caller, no single orderable type across the union
        raise RegenerateConflict(f"scenario output(s) not found or not active: {sorted(missing, key=str)}",
                                reason="output_not_found_or_superseded")
    return found


def _resolve_regen_context(scenario_session: dict) -> tuple[list[dict], dict]:
    """Parse the session's supporting-systems list and asset-context JSON for the asset-level
    cascade — the asset is the unit, so there is no single subsystem to look up."""
    subsystems = json.loads(scenario_session["SubsystemsJSON"])
    asset_context = json.loads(scenario_session.get("AssetContextJSON") or "{}")
    return subsystems, asset_context


def _build_regen_audit_detail(threat_ids: set[str] | None, target_ids: list[str] | list[int] | None,
                            epoch: int, user_note: str | None,
                            replacements: list[dict] | None = None) -> str:
    """DetailJSON for the regeneration-completed audit record. user_note is raw client free text
    going to a persistent audit trail — redact() before it lands, same as every other free-text
    value in this codebase."""
    return json.dumps({
        "target_ids": sorted(threat_ids) if threat_ids else None,
        # what the caller ASKED to replace, vs. `replacements` = what actually happened, old→new
        "requested_ids": list(target_ids) if target_ids else None,
        "replacements": replacements or [],
        "epoch": epoch, "user_note": redact(user_note)})


def run_regeneration(sess: Session, scenario_session: dict, subsystem_id: int, granularity: RegenGranularity,
                    target_ids: list[str] | list[int] | None, epoch: int, llm: LLMClient, task_id: str,
                    user_note: str | None = None) -> str | None:
    """Redo scenario generation for one subsystem's targeted threat(s) instead of the whole
    pipeline. Any failure is recorded rather than raised, and the function always falls through
    to decide_session_outcome."""
    sid = scenario_session["SessionID"]
    subsystems, asset_context = _resolve_regen_context(scenario_session)

    try:
        # fail fast, before taking the lock, if the requested target ids don't resolve to real rows
        targets = get_threat_id_to_redo(sess, sid, subsystem_id, granularity, target_ids)
    except RegenerateConflict as exc:
        log.info("regen.target_conflict", session_id=sid, subsystem=subsystem_id, reason=str(exc))
        return tasks.decide_session_outcome(sess, scenario_session)
    except Exception as exc:  # noqa: BLE001 — a transient DB/driver error here must not escape
        log.error("regen.pre_lock_error", session_id=sid, subsystem=subsystem_id, error=repr(exc))
        return tasks.decide_session_outcome(sess, scenario_session)

    with _subsystem_lock(sess, sid, subsystem_id, task_id, "regen") as acquired:
        if not acquired:
            log.warning("regen.locked", session_id=sid, subsystem=subsystem_id)
            return tasks.decide_session_outcome(sess, scenario_session)
        try:
            # re-check under the lock, in case state changed since the pre-check above
            targets = get_threat_id_to_redo(sess, sid, subsystem_id, granularity, target_ids)
            threats = dal.active_threats(sess, sid, subsystem_id)
            # asset_active_fields/sub_active_fields deliberately NOT passed — a regeneration must
            # reflect the CURRENT Context_Field_Config policy, not whatever was active when the
            # session first ran, so a field a curator has since disabled stays disabled.
            # The audit row is staged INSIDE write_scenarios' transaction, so the regeneration and
            # its record land together or not at all; written afterwards, a failure there would
            # report a committed success as failed via the generic handler below.
            def _stage_regen_audit(_provs) -> None:
                dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"],
                                EntityID=scenario_session["EntityID"], SubsystemID=subsystem_id,
                                # Stage must be set: a NULL here drops regenerations from every
                                # audit query filtered by Stage.
                                Stage=WorkflowStage.SCENARIO_GENERATION,
                                EventType=AuditEventType.regeneration_completed, Granularity=str(granularity),
                                # Reads the pairs itself — this hook runs inside write_scenarios'
                                # transaction, after the rows are inserted.
                                DetailJSON=_build_regen_audit_detail(
                                    {t.threat_id for t in targets.values()}, target_ids, epoch, user_note,
                                    replacements=[p for p in _regen_replacements(sess, sid, subsystem_id, epoch)
                                                if p["old"]]))

            scen_provs = tasks.write_scenarios(sess, scenario_session, subsystems, asset_context, threats, llm, task_id,
                                            epoch=epoch, regen_targets=targets, require_lock=True,
                                            on_before_commit=_stage_regen_audit)
            if not scen_provs:
                # Idempotent redelivery (batch already landed at this epoch) vs. genuine lost claim.
                # The hook never ran on this path — no commit happened — so there is no audit row.
                _settle_or_raise(sess, sid, subsystem_id, epoch, SubsystemLevel.SCENARIOS, "regen")
            else:
                _publish_regen_result_after_commit(sess, sid, subsystem_id, target_ids, epoch)
        except RegenerateConflict as exc:
            # Benign race (a concurrent regen/accept superseded the target in the gap), not a
            # pipeline failure: no ERROR state, no audit row, no error SSE. exc.reason is None for
            # the stale-target race; only the all-targets-rescored-out path sets a real code.
            log.info("regen.target_conflict", session_id=sid, subsystem=subsystem_id, reason=str(exc))
            _publish_regen_result(sid, subsystem_id, target_ids, [], reason=exc.reason)
        except LLMSlotUnavailable:
            # Transient capacity squeeze, not a bug — re-raise past _record_failure so Celery's
            # autoretry_for retries instead of recording a permanent ERROR.
            raise
        except Exception as exc:  # noqa: BLE001 — capture, don't swallow ([R8], same discipline as _process_all_supporting_systems)
            tasks._record_failure(sess, scenario_session, subsystem_id, exc, epoch)
            sess.commit()

    return tasks.decide_session_outcome(sess, scenario_session)


def _coverage_exclusions(threats: list[dict], cap: int | None = None) -> list[str]:
    """Distinct labels of the threats already proposed for this subsystem, fed to the
    coverage-aware prompt so an additive round asks for genuinely NEW ones. Prefer the grounded
    library label, fall back to the raw proposal; drop blanks.

    Capped by `coverage_exclusions_max` — the one prompt input that GROWS with every accumulated
    next-set round. Truncation keeps the MOST RECENT labels: `dal.active_threats` returns newest
    first and the fold below preserves that order, so a session past the cap drops the threats
    least likely to be re-proposed. This previously sorted ALPHABETICALLY before truncating, which
    froze the list on an arbitrary prefix — past the cap the newest threats never reached the
    prompt at all, and the additive round kept re-proposing exactly the ones it had just found.
    # ponytail: the exclusion list is steering, not enforcement — tasks.py's identity-fold dedup
    # silently drops any re-proposed already-active threat, so truncation can only ever cost one
    # wasted proposal, never a duplicate row. Configurable so a long-running session that starts
    # burning proposals on threats it already has can be tuned without a code change."""
    # tasks.threat_label is THE definition — the semantic near-duplicate scan measures against
    # the same string this list steers away from, so the two can never drift apart.
    if cap is None:  # session-tuned when the caller carries a snapshot; config otherwise
        cap = get_settings().coverage_exclusions_max
    labels = (tasks.threat_label(t) for t in threats)
    # dict.fromkeys, not set(): dedup while PRESERVING the newest-first order the cap slices.
    return list(dict.fromkeys(lbl for lbl in labels if lbl))[:cap]


def _top_up_with_variants(sess: Session, scenario_session: dict, subsystem_id: int, epoch: int,
                        subsystems: list[dict], asset_context: dict, llm: LLMClient, task_id: str,
                        shortfall: int, *, exclude: set[str] | None = None) -> tuple[int, bool]:
    """Fill the slots a next-set click could NOT fill from the unserved pool, with one alternate
    scenario per already-covered threat. Returns (how many landed, whether it FAILED).

    The bool is the whole point of the tuple: because this never raises, a caller reading only
    the count cannot tell "nothing was eligible" (a true terminal answer) from "the attempt blew
    up" (retry me). `_next_set_outcome` needs that distinction or a transient error reports as
    `exhausted` and permanently greys the client's button.

    `shortfall` is what the POOL came up short by, never `next_set_size - committed`: a generation
    that FAILED already reports itself via the stage row's partial_error, and filling its slot
    would hide that.

    MUST NEVER RAISE. Both callers run after the stage is terminal and (for the partial caller)
    after the scenarios are committed, so an escape into run_next_set's generic handler would
    route a committed success through _record_failure — whose stage_error audit row and error SSE
    are unconditional. LLMSlotUnavailable is swallowed too: the redelivery's claim_stage no-ops
    against an AWAITING_DECISION stage, so re-raising loses the SSE and buys no retry."""
    if shortfall <= 0:
        return 0, False  # nothing was asked for — not a failure
    sid = scenario_session["SessionID"]
    try:
        created = tasks.write_variant_scenarios(sess, scenario_session, subsystem_id, subsystems,
                                                asset_context, llm, task_id, epoch,
                                                max_variants=shortfall, exclude_threat_ids=exclude)
        if created:
            # Same row shape the productive path stages, so a click that both served and topped
            # up leaves two rows that SUM to the click total.
            dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"],
                            EntityID=scenario_session["EntityID"], SubsystemID=subsystem_id,
                            Stage=WorkflowStage.SCENARIO_GENERATION,
                            EventType=AuditEventType.generation_complete,
                            DetailJSON=json.dumps({"next_set": True, "subsystem_id": subsystem_id,
                                                "new_scenarios": created, "variants_generated": created}))
            sess.commit()
        return created, False
    except Exception as exc:  # noqa: BLE001 — see docstring; a committed batch must never report failure
        # ROLLBACK needs its own guard: on a broken connection whose SQLSTATE isn't in the
        # dialect's is_disconnect set it re-raises, and an escape from HERE recreates the exact
        # spurious-failure bug this guard exists to prevent.
        try:
            sess.rollback()
        except Exception:  # noqa: BLE001
            log.warning("next_set.variant_top_up_rollback_failed", session_id=sid,
                        subsystem=subsystem_id, exc_info=True)
        # Level tracks the exception, not the call site: capacity pressure is routine and would
        # drown a real signal at ERROR, while anything else here is systematic and silent —
        # swallowed at WARNING it would hide a top-up that fails on EVERY click.
        transient = isinstance(exc, LLMSlotUnavailable)
        (log.warning if transient else log.error)(
            "next_set.variant_top_up_failed", session_id=sid, subsystem=subsystem_id,
            shortfall=shortfall, transient=transient, exc_info=True)
        return 0, True


def _settle_next_set_conflict(sess: Session, scenario_session: dict, subsystem_id: int, epoch: int,
                            exc: RegenerateConflict, subsystems: list[dict], asset_context: dict,
                            llm: LLMClient, task_id: str, next_set_size: int) -> str:
    """`run_next_set`'s `except RegenerateConflict` body. write_scenarios already returned the
    stage to AWAITING_DECISION and mutated nothing before raising — this only decides what to do
    about it and reports the outcome; it never re-raises.

    The variant fallback runs for EVERY reason code. Whether it can help depends only on whether
    some already-covered threat still has an uncovered plausible entry point —
    dal.variant_eligible_primaries answers that on its own and yields 0 when it can't. The old
    `if exc.reason == "no_new_threats_found"` allowlist answered a DIFFERENT question ("why was
    the batch empty") and so suppressed a working fallback whenever a candidate was found and
    rescored out, leaving the click with 0 scenarios while eligible primaries sat unused — and
    any reason code added later would have inherited the same hole by default.

    Nothing was committed on this path, so the whole batch is the shortfall and there is no
    just-served threat to exclude. The stage is already terminal and the subsystem lock is still
    held, so this is a plain side write — no claim/epoch dance."""
    sid = scenario_session["SessionID"]
    created, top_up_failed = _top_up_with_variants(sess, scenario_session, subsystem_id, epoch,
                                                subsystems, asset_context, llm, task_id,
                                                next_set_size)
    if not created:
        # Deliberately NOT routed through _record_failure — that avoidance is what keeps a
        # transient additive failure from wedging or cancelling the session.
        dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"],
                        EntityID=scenario_session["EntityID"], SubsystemID=subsystem_id,
                        Stage=WorkflowStage.SCENARIO_GENERATION,
                        EventType=AuditEventType.generation_complete,
                        DetailJSON=json.dumps({"next_set": True, "subsystem_id": subsystem_id,
                                            "new_scenarios": 0, "no_new": True,
                                            "reason": exc.reason, **_reason_info(exc.reason)}))
        sess.commit()
    # Both branches report through the same call, so the durable row and the SSE can never
    # disagree about what this click did. `made=0` (nothing fresh was committed on this path) and
    # `pool_size=0` (the pool is what came up empty), so `made < pool_size` can never fire here —
    # which is exactly why `top_up_failed` has to be threaded: without it this path reports a
    # blown-up top-up as `exhausted` ("nothing further exists"), the single most misleading
    # answer available. `exc.reason` rides along even when variants SUCCEEDED — that provenance
    # ("a candidate was found and rejected") used to reach the client via the fruitless path and
    # would otherwise be lost now that the fallback usually rescues the click.
    _settle_next_set_click(sess, scenario_session, subsystem_id, epoch,
                        requested=next_set_size, made=0, variants=created,
                        pool_size=0, reason=exc.reason, top_up_failed=top_up_failed)
    return "generated" if created else "no_new_threats_this_round"


def run_next_set(sess: Session, scenario_session: dict, subsystem_id: int, epoch: int,
                threats_epoch: int, llm: LLMClient, task_id: str) -> str | None:
    """"Generate next set": add up to `next_set_size` MORE unique scenarios that ACCUMULATE onto
    the existing ones — nothing prior is superseded or dropped. Serves already-scored-but-unserved
    threats first (no AI call); only when that pool can't fill the batch does it run ONE additive,
    coverage-aware find_threats. Never hard-stops: a round that turns up nothing new returns
    "no_new_threats_this_round" and leaves the session reviewable.

    `epoch` is the SCENARIOS epoch, `threats_epoch` the THREATS epoch — BOTH reserved once by the
    endpoint and threaded through so a Celery redelivery re-executes at the SAME epochs: the
    additive find_threats is skipped when THREATS is already COMPLETE at threats_epoch, instead of
    firing a second AI call and a duplicate Identified_Threat batch. Accumulation rides on
    write_scenarios' target mode only superseding outputs whose IdentityHash matches — a new
    identity has no active match."""
    sid = scenario_session["SessionID"]
    subsystems, asset_context = _resolve_regen_context(scenario_session)

    signal: str | None = None
    with _subsystem_lock(sess, sid, subsystem_id, task_id, "next_set") as acquired:
        if not acquired:
            # the per-(session,subsystem) mutex serialises concurrent clicks so two can't double-generate
            log.warning("next_set.locked", session_id=sid, subsystem=subsystem_id)
            return tasks.decide_session_outcome(sess, scenario_session)
        try:
            tn = tuning.from_session(scenario_session)  # the session's frozen rulebook
            next_set_size = tn.next_set_size
            fresh = dal.next_unserved_unique_threats(sess, sid, subsystem_id, next_set_size)
            if len(fresh) < next_set_size and not dal.stage_completed_at_epoch_or_newer(
                    sess, sid, subsystem_id, SubsystemLevel.THREATS, threats_epoch):
                # Pool can't fill the batch and this reserved THREATS epoch hasn't COMPLETED — ask
                # the model for more, ONCE. supersede=False keeps every prior threat active (the
                # accumulation invariant). The stage_completed_at_epoch_or_newer guard skips this
                # branch on a redelivery whose THREATS actually COMPLETED at this epoch or has
                # advanced past it, but deliberately does NOT skip a row left RUNNING by a prior
                # failed attempt — the retry must re-enter so find_threats resumes it and drives it
                # terminal, or THREATS stays RUNNING and decide_session_outcome wedges the session.
                # The endpoint reserved the epoch but did NOT reset THREATS (an IDLE row would
                # wedge decide_session_outcome), so the reset lives here, guarded.
                # Read ONCE, used twice: the labels steer the prompt, and the rows themselves
                # carry each threat's category so the semantic near-duplicate scan can gate on
                # impact class rather than on similarity alone.
                prior_threats = dal.active_threats(sess, sid, subsystem_id)
                exclude = _coverage_exclusions(prior_threats, cap=tn.coverage_exclusions_max)
                dal.reset_stage_for_regen(sess, sid, subsystem_id, (SubsystemLevel.THREATS,), threats_epoch)
                new_threats: list[dict] = []
                try:
                    new_threats, _prov = tasks.find_threats(sess, scenario_session, subsystems, asset_context, llm, task_id,
                                                        epoch=threats_epoch, supersede=False, exclude=exclude,
                                                        prior_threats=prior_threats)
                except LLMSlotUnavailable:
                    raise  # retryable capacity squeeze — leave THREATS reclaimable so the retry re-runs it
                except Exception as exc:  # noqa: BLE001 — a transient additive-threats failure must not wedge/cancel
                    # find_threats commits THREATS=RUNNING@threats_epoch before its LLM call. Do NOT
                    # route a non-slot error through _record_failure: it fences on the SCENARIOS
                    # epoch, can't match the THREATS row, so THREATS stays RUNNING →
                    # decide_session_outcome returns None → the session wedges → the reaper cancels
                    # it and destroys the accumulated scenarios. Drive THREATS terminal below
                    # instead and fall through to serve whatever pool we already had.
                    log.error("next_set.additive_find_threats_failed", session_id=sid, subsystem=subsystem_id, error=repr(exc))
                    sess.rollback()
                # Never leave THREATS RUNNING at this epoch (a RUNNING row makes
                # decide_session_outcome return None → wedge). A no-op if find_threats already
                # finished COMPLETE — finish_stage only matches a still-RUNNING row.
                dal.finish_stage(sess, sid, subsystem_id, SubsystemLevel.THREATS, StageStatus.COMPLETE,
                                threats_epoch, task_id)
                sess.commit()
                log.info("next_set.additive_threats", session_id=sid, subsystem=subsystem_id, added=len(new_threats))
                fresh = dal.next_unserved_unique_threats(sess, sid, subsystem_id, next_set_size)

            threats = dal.active_threats(sess, sid, subsystem_id)

            # Same atomicity as the regen path above: staged inside write_scenarios' transaction,
            # so a failure writing it rolls the batch back instead of leaving committed scenarios
            # the handler below reports as failed.
            def _stage_next_set_audit(provs) -> None:
                dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"],
                                EntityID=scenario_session["EntityID"], SubsystemID=subsystem_id,
                                # one event type must not mean two row shapes — tasks.py's first-run
                                # generation_complete also carries SCENARIO_GENERATION
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
                # Top up when the POOL came up short — see _top_up_with_variants for why the
                # shortfall is `fresh`-derived, not `next_set_size - committed`.
                variants, top_up_failed = _top_up_with_variants(
                    sess, scenario_session, subsystem_id, epoch, subsystems, asset_context, llm,
                    task_id, next_set_size - len(fresh), exclude=set(fresh))
                # `pool_size=len(fresh)` is what makes a FAILED generation distinguishable from an
                # exhausted library: fewer scenarios back than threats handed over means the
                # targets are still Selected=1 and re-servable, so the next click retries them.
                # `top_up_failed` covers the other half — a pool that delivered in full while the
                # variant top-up blew up would otherwise round to `exhausted`.
                _settle_next_set_click(sess, scenario_session, subsystem_id, epoch,
                                    requested=next_set_size, made=made, variants=variants,
                                    pool_size=len(fresh), top_up_failed=top_up_failed)
        except RegenerateConflict as exc:
            # No new unique threats this round. write_scenarios already returned the stage to
            # AWAITING_DECISION and mutated nothing — benign: no ERROR, no error SSE, click again.
            log.info("next_set.no_new_threats", session_id=sid, subsystem=subsystem_id, reason=str(exc))
            signal = _settle_next_set_conflict(sess, scenario_session, subsystem_id, epoch, exc,
                                            subsystems, asset_context, llm, task_id, next_set_size)
        except LLMSlotUnavailable:
            raise  # retryable capacity squeeze — let Celery autoretry, same as run_regeneration
        except Exception as exc:  # noqa: BLE001 — capture, don't swallow ([R8], same as run_regeneration)
            tasks._record_failure(sess, scenario_session, subsystem_id, exc, epoch)
            sess.commit()

    # decide_session_outcome runs either way so the session re-enters REVIEW; the signal only
    # changes what the caller is told.
    outcome = tasks.decide_session_outcome(sess, scenario_session)
    return "no_new_threats_this_round" if signal == "no_new_threats_this_round" else outcome
