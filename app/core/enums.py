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
    completed = "completed"  # human accepted (all or partial) — terminal, lock released
    cancelled = "cancelled"  # user cancel, fatal error, or reaper gave up — terminal, lock released


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
    """`Identified_Threat.GroundingStatus` — did an AI-proposed threat match an approved library
    master? TWO bands, split by one cutoff (grounding_match_threshold, default 75).

    Deliberately not three: a middle "plausible, look at it" band read as a confidence gradient
    but was consumed as a boolean everywhere (promote / don't promote, trust the master ids /
    don't), so the extra band only ever moved which side of a line a threat fell on. One cutoff,
    one meaning."""
    verified = "verified"       # >= threshold — matched an approved entry; ThreatTypeID/ThreatCatalogueID set to that master
    unverified = "unverified"   # <  threshold — no confident match. Still gets a scenario, and is what
                                # library promotion feeds on (accept.py) — "novel", not "rejected".


class ThreatRuleType(StrEnum):
    """`Config_Threat_Rule.RuleType`. `tech_gate` is a hard include/exclude (a failed gate forces
    `Selected=0`); the other two are additive weights on `Score`. Any other value in the column is
    ignored by the engine (logged, no effect) — same never-silently-false rule as an unknown RuleKey."""
    tech_gate = "tech_gate"                              # pass/fail gate — failing it excludes the threat outright
    relevance_flag = "relevance_flag"                    # score points from a yes/no flag
    relevance_context_value = "relevance_context_value"  # score points from a specific context value


class ScopingRejection(StrEnum):
    """`Scoped_Threat.RejectionKind` — WHY a threat was not selected, as a value code may branch on.

    `Reason` stays free prose for the reviewer; this is the machine half. The two are written
    together and must never be derived from each other: "generate next set" decides re-servability
    from THIS column, and before it existed that decision was `Reason LIKE 'beyond top-%'` —
    rewording the sentence would have silently emptied the pool forever, with no error. Prose is
    allowed to change; a rejection KIND is a contract.

    NULL on a selected row (nothing rejected it). Only `top_n_cutoff` is re-servable — the other
    three fail re-scoring identically, so re-serving one churns a Selected=0 row that
    write_scenarios keeps refusing: the "no new threats" wedge. See RESERVABLE_REJECTIONS."""
    top_n_cutoff = "top_n_cutoff"       # above the bar, just outside this round's top-N —
                                        # target-mode re-scoring WILL re-select it
    duplicate = "duplicate"             # same catalogue identity as a higher-ranked threat, whose
                                        # scenario already covers it
    tech_gate = "tech_gate"             # a required-technology gate failed — permanent
    below_threshold = "below_threshold" # score under the configured floor — permanent


# The ONLY rejections dal.next_unserved_unique_threats may re-serve. A tuple, not a set: the SQL
# text stays byte-stable so the plan cache isn't churned by set-iteration order.
RESERVABLE_REJECTIONS: tuple[ScopingRejection, ...] = (ScopingRejection.top_n_cutoff,)


class TriageVerdict(StrEnum):
    """Library-promotion triage outcome for one candidate generic name (accept.py's banded
    triage). Stored in Scenario_Audit DetailJSON (`promotion_triage` / `library_promoted`
    rows), so the values are a persistence contract — code branches on the MEMBER, never on a
    bare string, and the wording is maintained here in one place."""
    auto_reject = "auto_reject"    # >= reject band: same idea reworded — link to the existing entry
    auto_approve = "auto_approve"  # < approve band vs everything: genuinely novel — insert active
    review = "review"              # between the bands, or any doubt — the curator decides


class SelectionReason(StrEnum):
    """`Scoped_Threat.SelectionKind` — WHY a threat WAS selected, as a value code may branch on.
    The selection-side twin of ScopingRejection: set on every Selected=1 row, NULL on rejected
    rows (and on rows written before the column existed). `Reason` prose is DERIVED from this +
    FactorsJSON, never typed freehand — the same discipline ScopingRejection documents.

    Deliberately only the two members that have a producer, mapped 1:1 from GroundingStatus at
    scoring time. No `flagged_match`: GroundingStatus is deliberately two-band (see its
    docstring) and no code path can produce a third value. No `rule_boosted`: boosts are
    orthogonal to the grounding basis (a verified AND boosted row would force a precedence
    choice) and are already machine-readable as non-empty relevance_* entries in FactorsJSON."""
    verified_match = "verified_match"       # grounding matched an approved library entry
    unverified_match = "unverified_match"   # no confident library match — AI wording kept


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
    """`Threat_Candidate_Review.Status`. The READ side (a curator queue UI/API) is still a later
    milestone, but the write side is live: accept.py queues every AI-proposed threat NAME here
    instead of auto-creating a Threat_Catalogue row for it, because prompts.py requires that name
    to embed the asset's own name and so it is never library-shaped."""
    pending = "pending"    # what accept.py writes — awaiting a curator to generalize the name
    accepted = "accepted"  # no writer: set by the curator workflow when it lands
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
    library_promoted = "library_promoted"               # on accept, once per NEW master created from an unverified
                                                        # threat. Only Threat_Type masters now — catalogue names go
                                                        # through the banded triage instead of unconditional curation
    promotion_triage = "promotion_triage"               # on accept, ONE row per accept listing every candidate's
                                                        # {generic_name, cosine, matched catalogue id, band verdict} —
                                                        # the calibration record the triage bands are tightened from
    candidate_reconciled = "candidate_reconciled"       # reserved — means "a Threat_Candidate_Review row was CLOSED as
                                                        # accepted", which only the curator workflow can do; accept.py
                                                        # writes those rows as `pending` and closes nothing
    session_cancelled = "session_cancelled"             # explicit cancel route, or `_mark_session_failed`'s total-failure
                                                        # path (live pipeline + reaper) — either way releases the M4 lock
    stage_error = "stage_error"                         # a stage failed after retries
    next_set_outcome = "next_set_outcome"               # once per "generate next set" click, at the very end —
                                                        # DetailJSON carries {outcome, requested, delivered,
                                                        # variants, reason, epoch}. Deliberately a SEPARATE row
                                                        # from the two generation_complete rows one click can
                                                        # write (those must be SUMMED); this is the single
                                                        # authoritative summary the status board reads.
    treatment_plan_requested = "treatment_plan_requested"  # POST .../treatment-plan accepted a request; DetailJSON
                                                        # carries {plan_id, output_id}. ActorUserID set ->
                                                        # ActorType=user (a human clicked).
    treatment_plan_outcome = "treatment_plan_outcome"   # the worker finished one plan attempt (COMPLETE or ERROR);
                                                        # DetailJSON carries {plan_id, status}. ActorType=system.
    treatment_plan_cancelled = "treatment_plan_cancelled"  # a human stopped a RUNNING generation; DetailJSON
                                                        # carries {plan_id}. ActorUserID set -> ActorType=user.
    treatment_plan_reviewed = "treatment_plan_reviewed"  # a human recorded the adoption decision; DetailJSON
                                                        # carries {plan_id, decision, comment?}. ActorType=user.


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


class NextSetOutcome(StrEnum):
    """What one "generate next set" click ACHIEVED — the single field a client switches on.

    Deliberately not a shortfall count: `complete` vs `partial_retryable` vs `exhausted` demand
    DIFFERENT user actions, and a bare "you are 2 short" cannot express that a short result is
    sometimes the correct terminal answer. Retryability is stated, never inferred."""
    complete = "complete"                    # delivered the full next_set_size
    partial_retryable = "partial_retryable"  # short because generation(s) FAILED. A failed target keeps
                                            # Selected=1 (tasks.py::_mark_next_set_targets_rescored_out), so
                                            # dal.next_unserved_unique_threats re-serves it — clicking again
                                            # IS the retry, and telling the user so is the whole point.
    exhausted = "exhausted"                  # short (possibly zero) because nothing further EXISTS: the pool is
                                            # empty AND every identity already has a scenario through every
                                            # plausible entry point it declared (dal.variant_eligible_primaries).
                                            # Coverage-derived: an evidenced terminal answer, not a counter
                                            # running out. delivered==0 + exhausted is the old "no_new" case.


class ClickOutcomeReason(StrEnum):
    """Why an accepted click RAN and produced nothing. Rides the next_set_result / regen_result SSE
    `reason` field, the audit DetailJSON, and — for the two regen-target codes — HTTP 409
    `details.reason`. cascade.py::_REASON_INFO maps every member to its detail/message pair.
    NOTHING PINS THAT MAPPING ANY MORE — the consistency test that did lived in tests/, which was
    removed — so a member added here without its _REASON_INFO entry now surfaces only at runtime,
    as a reason code whose detail and message come back None.

    Values are verbatim the strings already published in the API guide and on the live wire — a
    rename here is a breaking API change, not a refactor."""
    no_new_threats_found = "no_new_threats_found"                    # tasks.py: empty candidate pool from the start
    new_threat_did_not_qualify = "new_threat_did_not_qualify"        # tasks.py: candidate found, rescored out
    no_target_ids = "no_target_ids"                                  # cascade.py: regen request with zero targets
    output_not_found_or_superseded = "output_not_found_or_superseded"  # cascade.py: stale/foreign OutputIDs


class ReviewGateReason(StrEnum):
    """Why a review action (accept / regenerate / next-set) is refused OUTRIGHT — HTTP 409
    `details.reason`. Produced in exactly one place, accept.py::review_gate_reason, which the accept
    gate and the regenerate/next-set gate share so the two can never drift.

    Distinct from ClickOutcomeReason: this means "your request never ran", not "it ran and found
    nothing". Deliberately absent from cascade.py::_REASON_INFO — gate 409s carry `reason` plus the
    exception's own message and no detail/message pair, and adding entries would silently reshape
    every gate 409 body."""
    session_completed = "session_completed"              # terminal: the review decision is already final
    session_cancelled = "session_cancelled"              # terminal: start a new session for the asset
    generation_in_progress = "generation_in_progress"    # transient: not at the REVIEW barrier yet


class TreatmentGateReason(StrEnum):
    """Why a treatment-plan request is refused — HTTP 409 `details.reason` on
    POST .../treatment-plan (docs/RISK_TREATMENT_PLAN_SDD.md §5.3). Produced only by
    app/pipeline/treatment.py / app/api/treatment.py; a separate enum from ReviewGateReason
    because treatment runs on COMPLETED sessions, after the review gate is history.

    `generation_in_progress` deliberately shares its value with
    ReviewGateReason.generation_in_progress — same meaning ("wait, then retry"), different
    route family; clients may switch on the string without caring which gate said it."""
    scenario_not_accepted = "scenario_not_accepted"      # only accepted scenarios get treatment plans
    scenario_superseded = "scenario_superseded"          # target scenario was replaced by a regeneration
    generation_in_progress = "generation_in_progress"    # a fresh RUNNING plan row exists for this scenario
    not_in_progress = "not_in_progress"                  # cancel refused: no RUNNING generation to stop
    not_complete = "not_complete"                        # review refused: only a COMPLETE plan can be adopted


# --- Risk Treatment Plan vocabularies (docs/RISK_TREATMENT_PLAN_SDD.md) -------------------
# One source of truth per closed vocabulary, consumed three ways: Pydantic wire fields (422s +
# /openapi.json literal unions), treatment._validate_plan's advisory clamps, and
# prompts.treatment_prompt's FIELDS lines (built FROM these members, so the words the model is
# allowed to use can never drift from the words the API accepts).

class TreatmentStrategy(StrEnum):
    """The register's chosen treatment for a risk. Only Mitigate is implemented — the endpoint
    IS the Mitigate generator and stamps this server-side (never a request field in v1);
    Accept/Transfer/Avoid become members when their flows ship."""
    mitigate = "Mitigate"


class RiskLevel(StrEnum):
    """Register risk level — request field `risk_level`, verbatim toolkit vocabulary."""
    low = "Low"
    medium = "Medium"
    high = "High"
    critical = "Critical"


class YesNo(StrEnum):
    """Toolkit boolean-as-text — request `existing_controls_all_subsystems` and plan output
    `applicable_to_all_subsystems`. Kept as Yes/No (not bool) because the toolkit columns and
    the spec's output format say Yes/No verbatim."""
    yes = "Yes"
    no = "No"


class TreatmentReviewStatus(StrEnum):
    """`Risk_Treatment_Plan.ReviewStatus` — the human adoption decision on a COMPLETE plan
    (POST .../treatment-plan/review). NULL on the column = not reviewed yet; a re-review
    overwrites (latest decision wins); a regenerate supersedes the row, so the NEW version
    starts unreviewed — approval never silently carries across versions."""
    approved = "approved"                      # the organization adopted this plan
    changes_requested = "changes_requested"    # reviewer wants a different plan (regenerate with a note)


class ControlCoverage(StrEnum):
    """Gap-analysis outcome on the generated plan (`plan.control_coverage`): did the request's
    existing controls already cover every control identified at scenario generation?"""
    gaps = "gaps"          # at least one identified control is uncovered -> controls to implement
    covered = "covered"    # fully covered -> empty to-implement list; action plan pivots to verification


class ControlType(StrEnum):
    """`plan.controls_to_be_implemented[].control_type` — the four classic control functions
    the spec's instructions name."""
    preventive = "preventive"
    detective = "detective"
    corrective = "corrective"
    compensating = "compensating"


class ActionPriority(StrEnum):
    """Priority vocabulary for recommended controls and action-plan rows — the spec's
    instruction list (Critical/High/Medium/Low)."""
    critical = "Critical"
    high = "High"
    medium = "Medium"
    low = "Low"
