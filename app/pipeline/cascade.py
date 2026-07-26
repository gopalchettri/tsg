""" handles "regenerate" requests — redoing just one or more scenarios
of a session instead of starting the entire subsystem over from scratch.

Regeneration cascade  — redo a subsystem's
scenario(s) without re-running the whole pipeline.

Row-scoped so redoing one bad item doesn't discard its siblings (the actual
point of the feature).

Reuses the exact CAS/lock/epoch machinery `tasks.py` uses for the initial run:
`dal.acquire_lock` for the `_LOCK` mutex, mutual exclusion with accept),
`dal.claim_stage`'s existing `epoch` parameter, and the unmodified
`decide_session_outcome` to re-enter REVIEW once the board shows `AWAITING_DECISION`
again.

The epoch is reserved by the CALLER (the API endpoint's session-level CAS, exactly
once per logical request) and passed in — NOT computed here. A Celery task can be
redelivered (acks_late) and re-execute this whole function with the SAME epoch; at
that fixed epoch, `claim_stage`'s CAS correctly no-ops once a level is already
COMPLETE/AWAITING_DECISION, exactly like the initial pipeline's fixed `_EPOCH`. If
epoch were minted fresh on every call (as an earlier version of this module did),
a redelivery would compute a NEW epoch and destructively re-run the whole hop.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.enums import (
    AuditEventType, RegenGranularity, SSEEventType, StageStatus, SubsystemLevel, WorkflowStage,
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

# The endpoint (sessions.py::post_regenerate) resets exactly these levels to IDLE before
# dispatching the task; run_regeneration below MUST regenerate the same set. These two are
# the sole sources of truth for "what a granularity touches" — add a level here and you
# must add it to run_regeneration too, or the endpoint resets a stage nothing regenerates
# (stuck IDLE → reaper).
LEVELS_BY_GRANULARITY = {
    RegenGranularity.scenario: (SubsystemLevel.SCENARIOS,),
}

# "Generate next set" adds this many MORE unique scenarios per click; they accumulate
# (5 → 10 → 15 → …), never superseding a prior batch. The endpoint resets ONLY the SCENARIOS
# level (same as a scenario regen); an additive find_threats, when needed, resets THREATS itself.
NEXT_SET_LEVELS = (SubsystemLevel.SCENARIOS,)
_NEXT_SET_SIZE = 5


@contextmanager
def _subsystem_lock(sess: Session, sid: str, subsystem_id: int, task_id: str, kind: str) -> Iterator[bool]:
    """Acquire the per-subsystem `_LOCK`, commit it durable BEFORE any work (an exception in the body
    routes through tasks._record_failure's unconditional rollback, which would otherwise undo an
    uncommitted acquire and make the release spuriously fail — same invariant tasks.py's own
    claim/acquire sites keep), yield whether it was acquired, and ALWAYS release + commit on exit,
    logging (never raising) a release failure so it can't mask the body's own error or break the
    caller's contract of always falling through to decide_session_outcome. A not-acquired body must
    bail without doing work — the caller checks the yielded flag. `kind` ('regen'/'next_set') only
    prefixes the log keys."""
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
    """Shared 'write_scenarios returned [] without raising' check: a batch already landed at this epoch
    (stage AWAITING_DECISION/COMPLETE) is a benign idempotent redelivery — log and fall through; anything
    else is a genuine lost claim (stage reaped or superseded) — raise so the caller records the failure."""
    if not dal.stage_settled_at_epoch(sess, sid, subsystem_id, level, epoch):
        raise RuntimeError(f"{kind} claim lost mid-flight (stage reaped or superseded)")
    log.info(f"{kind}.redelivery_already_landed", session_id=sid, subsystem=subsystem_id, epoch=epoch)


def _publish_next_set_result(sid: str, subsystem_id: int, new_scenarios: int, *, no_new: bool) -> None:
    """Advisory SSE so the reviewer UI can tell a fruitful next-set click (new_scenarios>0) from a
    fruitless one (no_new). Purely informational — not a stage/status transition, never an error."""
    bus.publish(sid, {"type": str(SSEEventType.next_set_result), "session_id": sid,
                    "subsystem_id": subsystem_id, "new_scenarios": new_scenarios, "no_new": no_new,
                    "ts": now().isoformat()})


def _publish_regen_result(sid: str, subsystem_id: int, requested_ids: list[str] | list[int] | None,
                        new_output_ids: list[str]) -> None:
    """Advisory SSE naming exactly which outputs a regeneration replaced — the requested ids vs
    the fresh OutputIDs that superseded them — so the UI can highlight the changed cards instead
    of diffing /results. new_output_ids=[] means the click was fruitless (every target rescored
    out). Purely informational, same contract as _publish_next_set_result above; the authoritative
    record is generation_epoch on the /results rows, so a lost event costs nothing."""
    bus.publish(sid, {"type": str(SSEEventType.regen_result), "session_id": sid,
                    "subsystem_id": subsystem_id,
                    "requested_output_ids": [str(i) for i in (requested_ids or [])],
                    "new_output_ids": new_output_ids,
                    "ts": now().isoformat()})


def _publish_regen_result_after_commit(sess: Session, sid: str, subsystem_id: int,
                                    target_ids: list[str] | list[int] | None, epoch: int) -> None:
    """Advisory tail of a SUCCESSFUL regen: look up the fresh OutputIDs this epoch just committed
    (the epoch is unique to this hop — dal.next_epoch — so the active rows at it are exactly the
    replacements) and publish regen_result. Called only AFTER the success commit, and it must
    NEVER raise: an exception escaping into run_regeneration's generic handler would route a
    regen that already succeeded through tasks._record_failure, whose stage-ERROR update is
    epoch-fenced to IDLE/RUNNING rows (harmless here) but whose stage_error audit row + error SSE
    are unconditional — the client would be told a committed success failed. A failure here can
    only lose the hint, never the data (the client recovers via generation_epoch on /results), so
    swallow + warn; rollback first so a failed SELECT can't leave the session un-commitable for
    _subsystem_lock's release."""
    try:
        new_output_ids = list(sess.execute(
            select(m.Threat_Scenario_Output.OutputID).where(
                m.Threat_Scenario_Output.SessionID == sid,
                m.Threat_Scenario_Output.SubsystemID == subsystem_id,
                m.Threat_Scenario_Output.Superseded == 0,
                m.Threat_Scenario_Output.GenerationEpoch == epoch)
        ).scalars())
        _publish_regen_result(sid, subsystem_id, target_ids, new_output_ids)
    except Exception:  # noqa: BLE001 — advisory-only tail; must never poison a committed success
        # The rollback itself must be guarded too: on a broken connection whose SQLSTATE isn't in
        # the dialect's is_disconnect set, ROLLBACK re-raises — and an exception escaping THIS
        # handler lands in run_regeneration's generic except, recreating the exact spurious-failure
        # bug this helper exists to prevent. Same guarded-cleanup discipline as _subsystem_lock
        # above. A failed rollback still invalidates the connection, so the session recovers on a
        # fresh pooled connection for the lock release / decide_session_outcome that follow.
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
                granularity: RegenGranularity, target_ids: list[str] | list[int] | None) -> set[str] | None:
    """Turn the caller's requested target ids into the set of ThreatIDs to redo.

    Checks that every requested id still points to an active (non-superseded)
    scenario output for this session/subsystem, and raises RegenerateConflict if
    none were given or if any id doesn't resolve to a real, active row.
    """
    # Canonicalize BEFORE dedupe and before the `missing` comparison below. `found` is keyed by
    # OutputIDs that GUID.result_processor already canonicalized, so comparing raw client
    # spellings (uppercase from SSMS/.NET, dashless, braced) against those keys reports matched
    # rows as missing — the false `regenerate_conflict` on a valid request. The API layer
    # normalizes too (schemas._canonical_output_ids); this covers direct/internal callers and
    # the async post-lock re-check. A malformed id is left as-is so the not-found path below
    # names it, instead of GUID.bind_processor raising and surfacing as a 500.
    ids, lookup_ids = _split_target_ids(target_ids)
    if not ids:
        raise RegenerateConflict(f"{granularity} regeneration requires at least one target id")
    rows = sess.execute(
        select(m.Threat_Scenario_Output.OutputID, m.Scoped_Threat.ThreatID)
        .select_from(m.Threat_Scenario_Output.__table__.join(
            m.Scoped_Threat, m.Threat_Scenario_Output.ScopedThreatID == m.Scoped_Threat.ScopedThreatID))
        .where(m.Threat_Scenario_Output.OutputID.in_(lookup_ids),
            m.Threat_Scenario_Output.SessionID == session_id,
            m.Threat_Scenario_Output.SubsystemID == subsystem_id,
            m.Threat_Scenario_Output.Superseded == 0)
    ).all()
    found = {r.OutputID: r.ThreatID for r in rows}
    # any requested id that the query above didn't return is stale, superseded, or doesn't belong here
    missing = set(ids) - found.keys()
    if missing:
        # key=str: target_ids/ids are str|int depending on caller, so there's no single type
        # mypy can prove orderable across the union — sort by string form instead.
        raise RegenerateConflict(f"scenario output(s) not found or not active: {sorted(missing, key=str)}")
    return set(found.values())


def _resolve_regen_context(scenario_session: dict) -> tuple[list[dict], dict]:
    """Parse the session's supporting-systems list and asset-context JSON for the asset-level
    cascade — the asset is the unit, so there is no single subsystem to look up."""
    subsystems = json.loads(scenario_session["SubsystemsJSON"])
    asset_context = json.loads(scenario_session.get("AssetContextJSON") or "{}")
    return subsystems, asset_context


def _build_regen_audit_detail(threat_ids: set[str] | None, target_ids: list[str] | list[int] | None,
                            epoch: int, user_note: str | None) -> str:
    """Build the DetailJSON payload for the regeneration-completed audit record.

    [REVIEW-FIX] user_note is raw, unvalidated client free text (never reaches an LLM prompt —
    confirmed, this isn't a prompt-injection path) but was previously written to the persistent
    audit trail verbatim. redact() here matches the treatment every other free-text value in this
    codebase gets before being persisted or logged."""
    return json.dumps({
        "target_ids": sorted(threat_ids) if threat_ids else None,
        "requested_ids": list(target_ids) if target_ids else None,
        "epoch": epoch, "user_note": redact(user_note)})


def run_regeneration(sess: Session, scenario_session: dict, subsystem_id: int, granularity: RegenGranularity,
                    target_ids: list[str] | list[int] | None, epoch: int, llm: LLMClient, task_id: str,
                    user_note: str | None = None) -> str | None:
    """Redo scenario generation for one subsystem's targeted threat(s) instead of the whole pipeline.

    Validates the request, takes the per-subsystem lock, re-runs scenario generation
    for just the requested threats, writes an audit record, and always releases the
    lock afterwards. Any failure along the way is recorded rather than raised, and
    the function falls back to the normal session-outcome decision either way.
    """
    sid = scenario_session["SessionID"]
    subsystems, asset_context = _resolve_regen_context(scenario_session)

    try:
        # fail fast, before taking the lock, if the requested target ids don't resolve to real threats
        threat_ids = get_threat_id_to_redo(sess, sid, subsystem_id, granularity, target_ids)
    except RegenerateConflict as exc:
        log.info("regen.target_conflict", session_id=sid, subsystem=subsystem_id, reason=str(exc))
        return tasks.decide_session_outcome(sess, scenario_session)
    except Exception as exc:  # noqa: BLE001 — a transient DB/driver error here must not escape
        log.error("regen.pre_lock_error", session_id=sid, subsystem=subsystem_id, error=repr(exc))
        return tasks.decide_session_outcome(sess, scenario_session)

    with _subsystem_lock(sess, sid, subsystem_id, task_id, "regen") as acquired:
        if not acquired:
            # someone else holds the lock (another regen/pipeline run in flight) — bail out without changing anything
            log.warning("regen.locked", session_id=sid, subsystem=subsystem_id)
            return tasks.decide_session_outcome(sess, scenario_session)
        try:
            # re-check target ids now that we hold the lock, in case state changed between the pre-check above and here
            threat_ids = get_threat_id_to_redo(sess, sid, subsystem_id, granularity, target_ids)
            threats = dal.active_threats(sess, sid, subsystem_id)
            # asset_active_fields/sub_active_fields deliberately NOT passed — a regeneration
            # intentionally reflects the CURRENT Context_Field_Config policy, not whatever was active
            # when the session originally ran. If a curator has since turned a field off (e.g. for a
            # compliance reason), a freshly regenerated scenario should honor that, not keep sending
            # a field the curator explicitly disabled. write_scenarios resolves this once for the
            # whole call (not once per threat) when left unset — see its own comment.
            # The audit row is staged INSIDE write_scenarios' own transaction (see its
            # on_before_commit), so the regeneration and its "regeneration_completed" record land
            # together or not at all. Written afterwards, in a second transaction, a failure there
            # left the work committed while the generic handler below reported the whole hop as
            # failed — a stage_error audit row and an error SSE for a regeneration that succeeded.
            def _stage_regen_audit(_provs) -> None:
                dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"],
                                EntityID=scenario_session["EntityID"], SubsystemID=subsystem_id,
                                # Stage: a regeneration only ever touches SCENARIOS. Omitting it
                                # left this row NULL while the scoping_complete row written by the
                                # SAME regeneration carried SCENARIO_GENERATION — so any audit
                                # query filtered by Stage silently dropped regenerations.
                                Stage=WorkflowStage.SCENARIO_GENERATION,
                                EventType=AuditEventType.regeneration_completed, Granularity=str(granularity),
                                DetailJSON=_build_regen_audit_detail(threat_ids, target_ids, epoch, user_note))

            scen_provs = tasks.write_scenarios(sess, scenario_session, subsystems, asset_context, threats, llm, task_id,
                                            epoch=epoch, target_threat_ids=threat_ids, require_lock=True,
                                            on_before_commit=_stage_regen_audit)
            if not scen_provs:
                # Idempotent redelivery (batch already landed at this epoch) vs. genuine lost claim.
                # The hook never ran on this path — no commit happened — so there is no audit row.
                _settle_or_raise(sess, sid, subsystem_id, epoch, SubsystemLevel.SCENARIOS, "regen")
            else:
                _publish_regen_result_after_commit(sess, sid, subsystem_id, target_ids, epoch)
        except RegenerateConflict as exc:
            # same benign race as the pre-lock check above (the target became stale between
            # acquiring the lock and re-checking it — a concurrent regen/accept superseded it
            # in the gap). Not a real pipeline failure: no ERROR state, no audit row, no SSE
            # error event — just report the outcome as-is, same as the pre-lock check does.
            log.info("regen.target_conflict", session_id=sid, subsystem=subsystem_id, reason=str(exc))
            # fruitless click made observable: same advisory event, empty new_output_ids (mirrors
            # next-set's no_new pair).
            _publish_regen_result(sid, subsystem_id, target_ids, [])
        except LLMSlotUnavailable:
            # Same treatment as _process_all_supporting_systems: a temporary "system was busy"
            # condition, not a bug — re-raise past _record_failure so Celery's autoretry_for
            # (celery_app.py) retries this regeneration shortly instead of recording a permanent
            # ERROR.
            raise
        except Exception as exc:  # noqa: BLE001 — capture, don't swallow ([R8], same discipline as _process_all_supporting_systems)
            tasks._record_failure(sess, scenario_session, subsystem_id, exc, epoch)
            sess.commit()

    return tasks.decide_session_outcome(sess, scenario_session)


def _coverage_exclusions(threats: list[dict]) -> list[str]:
    """Distinct, human-meaningful labels of the threats already proposed for this subsystem —
    fed to the coverage-aware prompt so an additive round asks for genuinely NEW threats instead
    of repeating the obvious few. Prefer the grounded library label, fall back to the raw
    proposal; drop blanks."""
    labels = {(t.get("library_threat_name") or t.get("threat_name")
            or t.get("library_threat_type") or t.get("threat_type") or "") for t in threats}
    return sorted(lbl for lbl in labels if lbl)


def run_next_set(sess: Session, scenario_session: dict, subsystem_id: int, epoch: int,
                threats_epoch: int, llm: LLMClient, task_id: str) -> str | None:
    """"Generate next set": add up to 5 MORE unique scenarios that ACCUMULATE onto the existing
    ones (5 → 10 → 15 → …) — nothing prior is superseded or dropped, every earlier scenario stays
    active and returned. Serves already-scored-but-unserved threats first (no AI call); only when
    that pool can't fill the batch does it run ONE additive, coverage-aware find_threats and serve
    whatever new, unique threats it yields. Never hard-stops: a round that turns up nothing new
    returns "no_new_threats_this_round", supersedes nothing, and leaves the session reviewable so
    the reviewer can simply click again.

    Mirrors run_regeneration's lock / epoch / decide_session_outcome machinery. `epoch` is the
    SCENARIOS epoch and `threats_epoch` the THREATS epoch — BOTH reserved once by the endpoint
    (_do_next_set) and threaded through so a Celery redelivery/retry re-executes at the SAME epochs:
    the additive find_threats is skipped when THREATS is already COMPLETE at threats_epoch (its
    idempotency guard), instead of re-minting an epoch and firing a second AI call + duplicate
    Identified_Threat batch. Accumulation rides entirely on write_scenarios' target-mode being
    additive for genuinely-new identities (it only supersedes outputs whose IdentityHash matches,
    and a new identity has no active match)."""
    sid = scenario_session["SessionID"]
    subsystems, asset_context = _resolve_regen_context(scenario_session)

    signal: str | None = None
    with _subsystem_lock(sess, sid, subsystem_id, task_id, "next_set") as acquired:
        if not acquired:
            # another regen/next-set/pipeline run holds the lock — the per-(session,subsystem) mutex
            # serialises concurrent "next set" clicks so two can't double-generate.
            log.warning("next_set.locked", session_id=sid, subsystem=subsystem_id)
            return tasks.decide_session_outcome(sess, scenario_session)
        try:
            fresh = dal.next_unserved_unique_threats(sess, sid, subsystem_id, _NEXT_SET_SIZE)
            if len(fresh) < _NEXT_SET_SIZE and not dal.stage_completed_at_epoch_or_newer(
                    sess, sid, subsystem_id, SubsystemLevel.THREATS, threats_epoch):
                # Pool can't fill the batch AND this reserved THREATS epoch hasn't COMPLETED yet — ask
                # the model for MORE, ONCE, telling it what's already covered, then re-query. One
                # find_threats per call (no unbounded generate-until-5 loop); supersede=False keeps every
                # prior threat active (the accumulation invariant). The stage_completed_at_epoch_or_newer
                # guard makes a redelivery/retry skip this branch when THREATS actually COMPLETED at THIS
                # epoch, or has since advanced to a NEWER one (a stale redelivery whose reserved epoch is
                # BEHIND the live epoch). Crucially it does NOT skip a THREATS row left RUNNING at this
                # epoch by a prior attempt that FAILED before finish_stage (e.g. an LLMSlotUnavailable
                # capacity squeeze): the retry re-enters so find_threats' claim_stage resumes that row and
                # finish_stage drives it terminal — otherwise THREATS stays RUNNING and
                # decide_session_outcome wedges the session until the reaper. The endpoint reserved the
                # epoch but deliberately did NOT reset THREATS (an IDLE row would wedge
                # decide_session_outcome), so the reset lives here, guarded.
                exclude = _coverage_exclusions(dal.active_threats(sess, sid, subsystem_id))
                dal.reset_stage_for_regen(sess, sid, subsystem_id, (SubsystemLevel.THREATS,), threats_epoch)
                new_threats: list[dict] = []
                try:
                    new_threats, _prov = tasks.find_threats(sess, scenario_session, subsystems, asset_context, llm, task_id,
                                                        epoch=threats_epoch, supersede=False, exclude=exclude)
                except LLMSlotUnavailable:
                    raise  # retryable capacity squeeze — leave THREATS reclaimable so the retry re-runs it
                except Exception as exc:  # noqa: BLE001 — a transient additive-threats failure must not wedge/cancel
                    # find_threats commits THREATS=RUNNING@threats_epoch before its LLM call; on a
                    # non-slot error (e.g. LLMResponseParseError) do NOT route through _record_failure —
                    # it fences on the SCENARIOS epoch and can't match the THREATS row, so THREATS would
                    # stay RUNNING → decide_session_outcome returns None → session wedges → the reaper
                    # cancels a single-subsystem session and destroys the accumulated scenarios. Instead
                    # drive THREATS to a TERMINAL COMPLETE (below), then fall through to serve whatever
                    # pool we already had (empty → write_scenarios raises RegenerateConflict →
                    # no_new_threats_this_round). log.error (not warning): this only ever fires on a real
                    # additive breakage, never on legitimate exhaustion.
                    log.error("next_set.additive_find_threats_failed", session_id=sid, subsystem=subsystem_id, error=repr(exc))
                    sess.rollback()
                # Never leave THREATS RUNNING at this epoch (a RUNNING row makes decide_session_outcome
                # return None → wedge). Whether find_threats raised, silently lost its claim, or simply
                # returned, force the row it committed RUNNING to COMPLETE — a true no-op if it already
                # finished COMPLETE on its own (finish_stage only matches a still-RUNNING row).
                dal.finish_stage(sess, sid, subsystem_id, SubsystemLevel.THREATS, StageStatus.COMPLETE,
                                threats_epoch, task_id)
                sess.commit()
                log.info("next_set.additive_threats", session_id=sid, subsystem=subsystem_id, added=len(new_threats))
                fresh = dal.next_unserved_unique_threats(sess, sid, subsystem_id, _NEXT_SET_SIZE)

            threats = dal.active_threats(sess, sid, subsystem_id)

            # Same atomicity as the regen path above: the generation_complete record is staged
            # inside write_scenarios' transaction, so a failure writing it rolls the batch back
            # instead of leaving committed scenarios that the handler below reports as failed.
            def _stage_next_set_audit(provs) -> None:
                dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"],
                                EntityID=scenario_session["EntityID"], SubsystemID=subsystem_id,
                                # Stage: same event type tasks.py writes for a first run, where it
                                # DOES carry SCENARIO_GENERATION. One event must not mean two
                                # different row shapes depending on which path produced it.
                                Stage=WorkflowStage.SCENARIO_GENERATION,
                                EventType=AuditEventType.generation_complete,
                                DetailJSON=json.dumps({"next_set": True, "subsystem_id": subsystem_id,
                                                    "new_scenarios": len(provs)}))

            scen_provs = tasks.write_scenarios(sess, scenario_session, subsystems, asset_context, threats, llm, task_id,
                                            epoch=epoch, target_threat_ids=set(fresh), require_lock=True,
                                            on_before_commit=_stage_next_set_audit)
            if not scen_provs:
                # Idempotent redelivery (SCENARIOS batch already landed at this epoch) vs. genuine
                # lost claim — the former falls through with no error SSE, the latter raises.
                _settle_or_raise(sess, sid, subsystem_id, epoch, SubsystemLevel.SCENARIOS, "next_set")
            else:
                signal = "generated"
                _publish_next_set_result(sid, subsystem_id, len(scen_provs), no_new=False)
        except RegenerateConflict as exc:
            # No new unique threats this round (the pool was empty and the fresh AI batch only repeated
            # already-served threats, or every target rescored out). write_scenarios already returned
            # the stage to AWAITING_DECISION and mutated nothing — benign, exactly as run_regeneration
            # treats it: no ERROR, no error SSE, the reviewer can click again.
            log.info("next_set.no_new_threats", session_id=sid, subsystem=subsystem_id, reason=str(exc))
            signal = "no_new_threats_this_round"
            # PR-1: mirror the productive generation_complete audit + emit an advisory SSE on the no_new
            # / downgraded-additive-failure branch, so a fruitless click is observable in the audit trail
            # and the reviewer UI. Deliberately NOT routed through _record_failure — that avoidance is the
            # correctness choice that keeps a transient additive failure from wedging/cancelling.
            dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"],
                            EntityID=scenario_session["EntityID"], SubsystemID=subsystem_id,
                            Stage=WorkflowStage.SCENARIO_GENERATION,  # same row shape as its productive twin above
                            EventType=AuditEventType.generation_complete,
                            DetailJSON=json.dumps({"next_set": True, "subsystem_id": subsystem_id,
                                                "new_scenarios": 0, "no_new": True}))
            sess.commit()
            _publish_next_set_result(sid, subsystem_id, 0, no_new=True)
        except LLMSlotUnavailable:
            raise  # retryable capacity squeeze — let Celery autoretry, same as run_regeneration
        except Exception as exc:  # noqa: BLE001 — capture, don't swallow ([R8], same as run_regeneration)
            tasks._record_failure(sess, scenario_session, subsystem_id, exc, epoch)
            sess.commit()

    outcome = tasks.decide_session_outcome(sess, scenario_session)
    # "no_new_threats_this_round" is the caller-facing signal; decide_session_outcome still runs
    # (above) so the session re-enters REVIEW either way.
    return "no_new_threats_this_round" if signal == "no_new_threats_this_round" else outcome
