"""Enumerations — the single source of truth for every literal stored in the DB.

Application code, query builders and serializers reference a member, never a bare
string. Each member's *value* is the exact string in the `TSG` schema (casing
verbatim, mixed by column). `StrEnum` members are `str`, so they bind directly as
SQL parameters and compare equal to the stored text.
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
    AUTO = "AUTO"   # the only mode implemented: both stages run back-to-back per subsystem,
                    # stopping only at the single REVIEW gate. A MANUAL mode is reserved,
                    # with no code path today.


class WorkflowStage(StrEnum):
    """THREAT_IDENTIFICATION through APPROVED are ordered forward steps of the pipeline.
    CANCELLED is not a step — it's a terminal exit from any of them."""
    THREAT_IDENTIFICATION = "THREAT_IDENTIFICATION"  # Stage 1: AI proposes STRIDE threats, each grounded against the library
    SCENARIO_GENERATION = "SCENARIO_GENERATION"      # Stage 2: one scenario per selected threat; ends at AWAITING_DECISION
    REVIEW = "REVIEW"                                # every subsystem reached its review barrier; waiting on the one human decision
    APPROVED = "APPROVED"                            # accepted (all or partial) — terminal, pairs with SessionStatus.completed
    CANCELLED = "CANCELLED"                          # terminal exit from any stage above


class StageStatus(StrEnum):
    """One (session, subsystem, level) cell's own status — not the session-wide `WorkflowStage`."""
    IDLE = "IDLE"                          # not yet claimed by any worker — the default/reset state
    RUNNING = "RUNNING"                    # a worker holds this claim right now (ActiveTaskID + LeaseExpiresAt set)
    AWAITING_DECISION = "AWAITING_DECISION"  # SCENARIOS level only — deliberately NOT COMPLETE; this state IS the review barrier
    COMPLETE = "COMPLETE"                  # finished; a Celery redelivery treats this as a no-op, never re-runs it
    ERROR = "ERROR"                        # failed (or was reaped); re-claimable up to stage_max_attempts, then poison-terminal
    CANCELLED = "CANCELLED"   # Scenario_Session-level only — never written to a
                            # Subsystem_Stage_State row; per-stage history survives a cancel


class SubsystemLevel(StrEnum):
    """One work cell within a subsystem — NOT a mirror of `WorkflowStage`: different enum on a
    different column (`Subsystem_Stage_State.Level` vs `Scenario_Session.CurrentStage`), only two
    members correspond, and under different names. Never conflate the two."""
    THREATS = "THREATS"      # this subsystem's Stage-1 row — mirrors WorkflowStage.THREAT_IDENTIFICATION
    SCENARIOS = "SCENARIOS"  # this subsystem's Stage-2 row — mirrors WorkflowStage.SCENARIO_GENERATION
    LOCK = "_LOCK"          # member named LOCK; DB value is the literal "_LOCK". A per-subsystem
                            # mutex sentinel row (CAS lock), not a work stage — hence the
                            # `Level != LOCK` filter on every stage query.


class GroundingStatus(StrEnum):
    """`Identified_Threat.GroundingStatus` — how confidently an AI-proposed threat matched
    an existing library master (two-band reranker score, default thresholds 75/60)."""
    grounded = "grounded"   # >=75 — confident match; ThreatTypeID/ThreatCatalogueID set to the matched master
    confirm = "confirm"     # 60-75 — plausible match, same master ids set, lower-confidence band
    flagged = "flagged"     # <60 — no confident match; the ONLY status eligible for library promotion on accept


class ThreatRuleType(StrEnum):
    """`Config_Threat_Rule.RuleType`. `tech_gate` is a hard include/exclude (a failed gate forces
    `Selected=0`); the other two are additive weights on `Score`. Any other value in the column is
    ignored by the engine (logged, no effect) — same never-silently-false rule as an unknown RuleKey."""
    tech_gate = "tech_gate"                              # pass/fail gate — failing it excludes the threat outright
    relevance_flag = "relevance_flag"                    # score points from a yes/no flag
    relevance_context_value = "relevance_context_value"  # score points from a specific context value


class ScenarioStatus(StrEnum):
    """`Threat_Scenario_Output.Status` — one generated scenario row's own outcome. Not
    StageStatus (the *stage's* status); unrelated columns on different tables."""
    complete = "complete"  # the scenario narrative was generated and persisted
    error = "error"        # FAILURE CARD: a full-run threat whose generation failed keeps a row
                            # (null scenario + ErrorMessage) so /regenerate/scenarios can retry it
                            # individually. Excluded from accept/salvage/resume by the
                            # ScenarioStatus.complete filters in dal.py.


class ActorType(StrEnum):
    """`Scenario_Audit.ActorType` — WHO PERFORMED the event, kept separate from ActorUserID's
    "who is ACCOUNTABLE". Worker rows are back-filled with the session owner, so ActorUserID
    alone cannot distinguish "gopal did this" from "gopal is answerable for what the pipeline
    did". NULL on rows written before this column existed."""
    user = "user"      # a human performed it: session_started, session_cancelled, the accept family
    system = "system"  # a worker/the pipeline performed it; ActorUserID names who is answerable


class CandidateStatus(StrEnum):
    """`Threat_Candidate_Review.Status` — ahead of its consumer; the curator workflow is a
    later milestone."""
    pending = "pending"    # no writer: accept.py inserts every row directly as `accepted`
    accepted = "accepted"  # the ONLY value the app currently writes — set when accept.py promotes the row
    rejected = "rejected"  # no writer yet (curator workflow)


class ValidationStatus(StrEnum):
    """Deterministic output-validation result. These checks FLAG, never block — a parse failure
    is a stage ERROR upstream and never reaches them, so no `error` member exists."""
    ok = "ok"            # nothing to flag
    warning = "warning"  # at least one check flagged something — recorded for the reviewer, never blocks accept


class AuditEventType(StrEnum):
    """`Scenario_Audit.EventType` — the append-only trail. Every member is written from exactly
    one place; some are defined with no current producer (reserved for a later milestone)."""
    session_started = "session_started"                # POST /sessions, right after the stage rows are seeded
    auto_run_enqueued = "auto_run_enqueued"             # reserved — no current producer
    grounding_summary = "grounding_summary"             # once per subsystem after Stage 1; DetailJSON carries the threat count
    scoping_complete = "scoping_complete"               # once per subsystem after Stage 2 scoring; DetailJSON carries scoped/selected counts
    controls_mapped = "controls_mapped"                 # once per write_scenarios run after Step-4 control mapping;
                                                        # DetailJSON carries outputs/mapped/dropped/fallback counts
    generation_complete = "generation_complete"         # once per subsystem after both stages; DetailJSON carries LLM provenance
    entered_review = "entered_review"                   # once per session when every subsystem reaches the review barrier
    review_decision = "review_decision"                 # the human's verdict at the single review gate
    scenarios_accepted = "scenarios_accepted"           # Stage-2 outputs flipped Accepted=1 — deliberately NOT
                                                        # written on a mode="none" reject (nothing flipped)
    regeneration_completed = "regeneration_completed"   # one regenerate request finished its stage re-runs
    threat_regrounded = "threat_regrounded"             # reserved — only `scenario` regen is implemented
    subsystem_advanced = "subsystem_advanced"           # written at the START of a subsystem's work, not on completion
    auto_fanout_review = "auto_fanout_review"           # reserved — no current producer
    library_promoted = "library_promoted"               # on accept, once per NEW master created from a flagged threat
    candidate_reconciled = "candidate_reconciled"       # on accept, once per Threat_Candidate_Review row closed as accepted
    session_cancelled = "session_cancelled"             # explicit cancel route, or `_mark_session_failed`'s total-failure
                                                        # path (live pipeline + reaper) — either way releases the M4 lock
    stage_error = "stage_error"                         # a stage failed after retries


class AuditDecision(StrEnum):
    """`Scenario_Audit.Decision` — written by `accept.py::accept_session` from its `subset` param:
    None -> accept, a populated list -> partial, an explicit empty list -> reject."""
    accept = "accept"            # "accept all" — subset was None
    partial = "partial"          # AcceptBody mode="subset"
    reject = "reject"            # "accept none" — AcceptBody mode="none"
    regenerate = "regenerate"    # no writer (regeneration is audited via regeneration_completed)


class RegenGranularity(StrEnum):
    """Only `scenario` regen is implemented — see cascade.py's LEVELS_BY_GRANULARITY for
    exactly which stage levels it resets."""
    scenario = "scenario"                  # rebuild one or more scenarios' narratives only


class SubsystemProgress(StrEnum):
    """Fully derived (`get_overall_status()` in app/api/sessions.py) — never a stored column.
    Evaluated top-to-bottom, first match wins: any stage ERROR -> error; session completed
    -> complete; session cancelled -> cancelled; SCENARIOS = AWAITING_DECISION ->
    awaiting_review; both IDLE -> pending; otherwise -> in_progress."""
    pending = "pending"                # nothing started yet — both stage rows are IDLE
    in_progress = "in_progress"        # the fallback rollup — some stage work is underway
    awaiting_review = "awaiting_review"  # SCENARIOS reached AWAITING_DECISION
    complete = "complete"              # derived from SessionStatus.completed — accept_session() never
                                        # rewrites Subsystem_Stage_State, so SCENARIOS never reaches COMPLETE
    error = "error"                    # either stage is StageStatus.ERROR — takes priority over every other rollup
    cancelled = "cancelled"            # the session was cancelled with no more specific outcome here


class SSEEventType(StrEnum):
    """Three scopes, not two: `stage_started`/`stage_completed` are one SubsystemLevel cell
    (subsystem_id + stage); `subsystem_started` is one subsystem (subsystem_id, no stage);
    `session_entered_review`/`heartbeat` are session-wide (never a subsystem_id). `error` is
    DUAL-scope by design — subsystem_id present when one stage failed, omitted when the whole
    session died — reusing the same presence convention, not a special case."""
    stage_started = "stage_started"                    # one (subsystem, stage) cell began running
    stage_completed = "stage_completed"                # that same cell finished (a failure routes to `error` instead)
    subsystem_started = "subsystem_started"            # fires BEFORE this subsystem's stages run, not after
    session_entered_review = "session_entered_review"  # every subsystem is done; waiting on the one human decision
    error = "error"                                    # a stage failed (carries subsystem_id) or the session died (omits it)
    next_set_result = "next_set_result"                # advisory: one "generate next set" click landed (subsystem_id +
                                                        # new_scenarios/no_new, plus reason/detail/message when no_new —
                                                        # reason is a stable code, detail is log-facing, message is the
                                                        # end-user sentence; see cascade.py::_REASON_INFO)
    regen_result = "regen_result"                       # advisory: one regenerate click landed (subsystem_id +
                                                        # requested_output_ids/new_output_ids, same reason/detail/message
                                                        # shape, though reason is None for the target-went-stale race).
                                                        # new_output_ids=[] means every target rescored out (or that race)
    heartbeat = "heartbeat"                             # periodic keep-alive so proxies don't drop an idle SSE connection


if __name__ == "__main__":  # self-check: values must equal the DB strings verbatim
    assert SubsystemLevel.LOCK == "_LOCK"
    assert WorkflowStage.THREAT_IDENTIFICATION == "THREAT_IDENTIFICATION"
    assert GroundingStatus.confirm == "confirm"
    assert AuditEventType.session_cancelled == "session_cancelled"
    assert str(SessionStatus.active) == "active"
    assert ValidationStatus.warning == "warning"
    print("enums self-check ok")
