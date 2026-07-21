"""Enumerations — the single source of truth for every literal stored in the DB. 
Rule: application code, query builders, and serializers
reference an enum **member**, never a bare string literal. Each member's *value*
is the exact string in the existing `TSG` schema (casing verbatim, mixed by
column). `StrEnum` members are `str` subclasses, so they bind directly as SQL
parameters and compare equal to the stored text.
"""
from __future__ import annotations

from enum import StrEnum


class SessionStatus(StrEnum):
    """The only authoritative liveness signal for a session. `WorkflowStage`/`StageStatus`
    track pipeline *progress*, not liveness — a cancelled session keeps its last real
    progress values everywhere except here, by design (history, not a status)."""
    active = "active"        # holds the one-active-session-per-asset lock
    completed = "completed"  # human accepted (all or partial) — terminal, M4 lock released
    cancelled = "cancelled"  # user cancel, fatal error, or reaper gave up — terminal, M4 lock released


class SessionMode(StrEnum):
    """The pipeline's run mode. Only one is built."""
    AUTO = "AUTO"   # the only mode implemented: both stages run back-to-back per subsystem,
                    # stopping only at the single REVIEW gate. A future step-by-step MANUAL
                    # mode is reserved but has no code path today.


class WorkflowStage(StrEnum):
    """THREAT_IDENTIFICATION through APPROVED are ordered forward steps of the pipeline.
    CANCELLED is not a step — it's a terminal exit from any of them."""
    THREAT_IDENTIFICATION = "THREAT_IDENTIFICATION"  # Stage 1: AI proposes STRIDE threats, each grounded against the library
    SCENARIO_GENERATION = "SCENARIO_GENERATION"      # Stage 2: AI narrates one scenario per selected threat; ends at AWAITING_DECISION
    REVIEW = "REVIEW"                                # every subsystem reached its review barrier; session waits on the one human decision
    APPROVED = "APPROVED"                            # the human accepted (all or partial) — terminal, pairs with SessionStatus.completed
    CANCELLED = "CANCELLED"                          # terminal exit from any stage above — user cancel, fatal error, or reaper


class StageStatus(StrEnum):
    """One (session, subsystem, level) cell's own status — not the session-wide `WorkflowStage`."""
    IDLE = "IDLE"                          # not yet claimed by any worker — the default/reset state
    RUNNING = "RUNNING"                    # a worker holds this claim right now (ActiveTaskID + LeaseExpiresAt set)
    AWAITING_DECISION = "AWAITING_DECISION"  # SCENARIOS level only — deliberately NOT COMPLETE; this state IS the review barrier
    COMPLETE = "COMPLETE"                  # stage finished successfully; a Celery redelivery treats this as a no-op, never re-runs it
    ERROR = "ERROR"                        # stage failed (or was reaped); re-claimable up to stage_max_attempts, then poison-terminal
    CANCELLED = "CANCELLED"   # Scenario_Session-level only — never written to a
                            # Subsystem_Stage_State row; per-stage history survives a cancel


#  labels which of a subsystem's work stages (or its lock row) one
# Subsystem_Stage_State row represents.
class SubsystemLevel(StrEnum):
    """One work cell within a subsystem — NOT a one-to-one mirror of `WorkflowStage`:
    only 2 of its 3 real-work members correspond (with different names: THREATS vs
    THREAT_IDENTIFICATION, SCENARIOS vs SCENARIO_GENERATION), `LOCK` has no
    `WorkflowStage` counterpart at all, and `WorkflowStage`'s REVIEW/APPROVED/CANCELLED
    have no `SubsystemLevel` counterpart. Different enum on a different column
    (`Subsystem_Stage_State.Level` vs `Scenario_Session.CurrentStage`); never conflate
    the two, a mistake this codebase's own docs warn against repeatedly."""
    THREATS = "THREATS"      # this subsystem's Stage-1 row — mirrors WorkflowStage.THREAT_IDENTIFICATION
    SCENARIOS = "SCENARIOS"  # this subsystem's Stage-2 row — mirrors WorkflowStage.SCENARIO_GENERATION
    LOCK = "_LOCK"          # member named LOCK; DB value is the literal "_LOCK". A per-subsystem
                            # mutex sentinel row (acquired/released as a CAS lock) — not a fourth
                            # real work stage, which is why code filters `Level != LOCK` so often.


#  how confidently an AI-suggested threat matches a known threat type
# in the library — grounded (strong match), confirm (maybe), or flagged (no good match).
class GroundingStatus(StrEnum):
    """`Identified_Threat.GroundingStatus` — how confidently an AI-proposed threat matched
    an existing library master (SDD §8.4 two-band reranker score, default thresholds 75/60)."""
    grounded = "grounded"   # >=75 — confident match; ThreatTypeID/ThreatCatalogueID set to the matched master
    confirm = "confirm"     # 60-75 — plausible match, same master ids set, lower-confidence band than grounded
    flagged = "flagged"     # <60 — no confident match; the ONLY status eligible for library promotion on accept ([R10])


#  what kind of scoping rule this is — a pass/fail gate, or one of two
# ways to add points toward a threat's relevance score.
class ThreatRuleType(StrEnum):
    """`Config_Threat_Rule.RuleType` — the three scoping rule families.
    `tech_gate` is a hard include/exclude (a failed gate forces `Selected=0`); the two
    relevance families are additive weights on `Score`. Any other value in the column is
    ignored by the engine (logged, no effect) — same never-silently-false rule as an
    unknown RuleKey."""
    tech_gate = "tech_gate"                              # pass/fail gate — failing it excludes the threat outright
    relevance_flag = "relevance_flag"                    # adds/subtracts score points based on a yes/no flag
    relevance_context_value = "relevance_context_value"  # adds/subtracts score points based on a specific context value


class ScenarioStatus(StrEnum):
    """`Threat_Scenario_Output.Status` — one generated scenario row's own outcome. Easy to
    confuse with the similarly-named StageStatus (the *stage's* status); unrelated columns
    on different tables."""
    complete = "complete"  # the scenario narrative was generated and persisted
    error = "error"        # defined for the column's shape; today a scenario-generation failure
                            # instead routes the whole SCENARIOS stage to StageStatus.ERROR (no
                            # per-scenario-row error state is currently written by the pipeline)


class CandidateStatus(StrEnum):
    """`Threat_Candidate_Review.Status` — backs the curator/candidate-promotion workflow.
    Ahead of its consumer: that workflow is a later milestone, not built in this M1 slice."""
    pending = "pending"    # meant as "awaiting curator review", but no code path writes this today either —
                            # accept.py inserts every row directly as `accepted` (an audit ledger of promotions,
                            # not an actual review queue yet); reserved for R11's curator gate
    accepted = "accepted"  # the ONLY value the app currently writes — set the moment accept.py promotes the row ([R10])
    rejected = "rejected"  # defined for the curator workflow; no code path writes this yet (R11, not built)


class ValidationStatus(StrEnum):
    """Deterministic output-validation result. These checks FLAG,
    never block — a parse failure is a stage ERROR upstream and never reaches them,
    so no `error` member exists (it would have no producer)."""
    ok = "ok"            # the structural/consistency checks found nothing to flag
    warning = "warning"  # at least one check flagged something — recorded for the reviewer, never blocks accept


#  the fixed list of event names that can appear in the session's audit trail.
class AuditEventType(StrEnum):
    """`Scenario_Audit.EventType` — the append-only trail of everything that happens to a
    session. Every member below is written from exactly one place; where noted, a member
    is defined but has no current producer (reserved for a later milestone)."""
    session_started = "session_started"                # written once, in POST /sessions, right after the pipeline's stage rows are seeded
    auto_run_enqueued = "auto_run_enqueued"             # defined, but no code writes it today — reserved, no current producer
    grounding_summary = "grounding_summary"             # written once per subsystem after Stage 1 (THREATS); DetailJSON carries the threat count
    scoping_complete = "scoping_complete"               # written once per subsystem after Stage 2 scoring; DetailJSON carries scoped/selected counts
    generation_complete = "generation_complete"         # written once per subsystem after both stages finish; DetailJSON carries full LLM provenance
    entered_review = "entered_review"                   # written once per session when every subsystem reaches the review barrier
    review_decision = "review_decision"                 # the human's verdict at the single review gate (accept/partial)
    scenarios_accepted = "scenarios_accepted"           # Stage-2 outputs (Threat_Scenario_Output) flipped Accepted=1
    regeneration_completed = "regeneration_completed"   # one regenerate request finished its stage re-runs
    threat_regrounded = "threat_regrounded"             # a threat was re-matched to the library during threat-granularity regen —
                                                        # defined, but no code path writes this today (only `scenario` regen is
                                                        # implemented, see RegenGranularity); reserved, no current producer
    subsystem_advanced = "subsystem_advanced"           # written once per subsystem at the START of its work, not on completion
                                                        # (its SSE sibling was renamed to `subsystem_started` for the same reason;
                                                        # this audit value keeps its own name — it was never part of that rename)
    auto_fanout_review = "auto_fanout_review"           # defined, but no code writes it today — reserved, no current producer
    library_promoted = "library_promoted"               # written on accept, once per NEW master (Type/Catalogue/Actor) created from a flagged threat ([R10])
    candidate_reconciled = "candidate_reconciled"       # written on accept, once per Threat_Candidate_Review row closed as accepted ([R10])
    session_cancelled = "session_cancelled"             # written by the explicit cancel route, or by `_mark_session_failed`'s
                                                        # total-failure path (shared by the live pipeline's own end-of-loop
                                                        # check AND the reaper's sweep) — either way, releases the M4 lock (`[R1]`)
    stage_error = "stage_error"                         # a stage failed after retries (production error capture)


class AuditDecision(StrEnum):
    """`Scenario_Audit.Decision` — the human verdict recorded alongside a `review_decision`
    event. Only `accept`/`partial` are currently written (`accept.py::accept_session`'s
    `decision = partial if subset is not None else accept`); `reject`/`regenerate` are
    defined for the column's full vocabulary but have no current writer."""
    accept = "accept"            # "accept all" — subset was None
    partial = "partial"          # only a subset of subsystems accepted (AcceptBody.subset), not the whole session
    reject = "reject"            # defined; no code path writes this today
    regenerate = "regenerate"    # defined; no code path writes this today (regeneration is audited via `regeneration_completed`/`threat_regrounded` instead)


class RegenGranularity(StrEnum):
    """Only `scenario` regen is implemented — see cascade.py's LEVELS_BY_GRANULARITY for
    exactly which stage levels it resets."""
    scenario = "scenario"                  # rebuild one or more scenarios' narratives only


#  a computed summary of how one subsystem is doing overall, for display
# only — it is never stored in the DB, just worked out fresh each time it's requested.
class SubsystemProgress(StrEnum):
    """Fully derived (`get_overall_status()` in app/api/sessions.py) — never a stored column. The
    status board's `overall` field is built fresh on every read, not persisted.
    Evaluated top-to-bottom, first match wins: any stage ERROR -> error; the session
    itself completed (accepted) -> complete; the session itself cancelled -> cancelled;
    SCENARIOS = AWAITING_DECISION -> awaiting_review; both IDLE -> pending; otherwise -> in_progress."""
    pending = "pending"                # nothing started yet — both stage rows are IDLE
    in_progress = "in_progress"        # the fallback/default rollup — some stage work is underway
    awaiting_review = "awaiting_review"  # SCENARIOS reached AWAITING_DECISION — this subsystem's part of the review barrier
    complete = "complete"              # the session itself was accepted (SessionStatus.completed) — accept_session()
                                        # never rewrites Subsystem_Stage_State, so this is derived from session
                                        # status, not from a stored per-stage COMPLETE (SCENARIOS never reaches it)
    error = "error"                    # either stage is StageStatus.ERROR — takes priority over every other rollup
    cancelled = "cancelled"            # the session itself was cancelled while this subsystem had no more specific outcome


#  the event names sent to the browser over the live server-sent-events
# (SSE) stream, so the UI can update as the pipeline progresses.
class SSEEventType(StrEnum):
    """Three real scopes, not two — `stage_started`/`stage_completed` are scoped to one
    SubsystemLevel cell (carry subsystem_id + stage); `subsystem_started` is scoped to one
    subsystem, all its stages (carries subsystem_id, no stage); `session_entered_review` and
    `heartbeat` are genuinely session-wide (no subsystem_id ever). `error` is DUAL-scope by
    design: it carries subsystem_id when one stage failed, and omits it when the whole
    session died (all subsystems errored) — the same subsystem_id-presence convention
    `stage_started`/`stage_completed` already rely on to disambiguate, not a special case."""
    stage_started = "stage_started"                    # one (subsystem, stage) cell began running
    stage_completed = "stage_completed"                # that same cell finished (success — a failure routes to `error` instead)
    subsystem_started = "subsystem_started"            # the pipeline began work on this subsystem (fires BEFORE its stages run, not after)
    session_entered_review = "session_entered_review"  # every subsystem is done; the whole session now waits on the one human decision
    error = "error"                                    # a stage failed (carries subsystem_id) or the whole session died (omits it)
    next_set_result = "next_set_result"                # advisory: one "generate next set" click landed (carries subsystem_id +
                                                        # new_scenarios/no_new) so the UI can tell a fruitful click from a fruitless one
    heartbeat = "heartbeat"                             # periodic keep-alive so proxies don't drop an idle SSE connection


if __name__ == "__main__":  # self-check: values must equal the DB strings verbatim
    assert SubsystemLevel.LOCK == "_LOCK"
    assert WorkflowStage.THREAT_IDENTIFICATION == "THREAT_IDENTIFICATION"
    assert GroundingStatus.confirm == "confirm"
    assert AuditEventType.session_cancelled == "session_cancelled"
    assert str(SessionStatus.active) == "active"
    assert ValidationStatus.warning == "warning"
    print("enums self-check ok")
