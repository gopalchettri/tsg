"""Enumerations — the single source of truth for every literal stored in the DB.

Each member's *value* is the exact string in the `TSG` schema (casing verbatim, mixed by
column). `StrEnum` members are `str`, so they bind directly as SQL parameters and compare
equal to the stored text. Never write a bare string at a call site.
"""
from __future__ import annotations

from enum import StrEnum


class SessionStatus(StrEnum):
    """The only authoritative liveness signal for a session. `WorkflowStage`/`StageStatus`
    track pipeline progress, not liveness."""
    active = "active"        # holds the one-active-session-per-asset lock
    completed = "completed"  # human accepted (all or partial) — terminal, lock released
    cancelled = "cancelled"  # user cancel, fatal error, or reaper gave up — terminal, lock released


class SessionMode(StrEnum):
    AUTO = "AUTO"   # the only implemented mode: both stages run back-to-back per subsystem,
                    # stopping only at the single REVIEW gate. MANUAL is reserved, no code path


class WorkflowStage(StrEnum):
    """`Scenario_Session.CurrentStage`. THREAT_IDENTIFICATION through APPROVED are ordered
    forward steps; CANCELLED is a terminal exit from any of them, not a step."""
    THREAT_IDENTIFICATION = "THREAT_IDENTIFICATION"  # Stage 1: AI proposes STRIDE threats, grounded against the library
    SCENARIO_GENERATION = "SCENARIO_GENERATION"      # Stage 2: scenario per selected threat
    REVIEW = "REVIEW"                                # every subsystem hit its review barrier; waiting on the human
    APPROVED = "APPROVED"                            # accepted — terminal, pairs with SessionStatus.completed
    CANCELLED = "CANCELLED"


class StageStatus(StrEnum):
    """One (session, subsystem, level) cell's own status — not the session-wide `WorkflowStage`."""
    IDLE = "IDLE"
    RUNNING = "RUNNING"                       # a worker holds this claim (ActiveTaskID + LeaseExpiresAt set)
    AWAITING_DECISION = "SCENARIOS_AWAITING_DECISION"   # SCENARIOS only — NOT COMPLETE; this state IS the review barrier
    COMPLETE = "COMPLETE"                     # a Celery redelivery treats this as a no-op
    ERROR = "ERROR"                           # re-claimable up to stage_max_attempts, then poison-terminal
    CANCELLED = "CANCELLED"                   # Scenario_Session-level only — never written to a
                                        # Subsystem_Stage_State row


class SubsystemLevel(StrEnum):
    """One work cell within a subsystem (`Subsystem_Stage_State.Level`) — NOT a mirror of
    `WorkflowStage`, which is a different enum on a different column. Never conflate the two."""
    THREATS = "THREATS"      # mirrors WorkflowStage.THREAT_IDENTIFICATION
    SCENARIOS = "SCENARIOS"  # mirrors WorkflowStage.SCENARIO_GENERATION
    LOCK = "_LOCK"           # DB value is the literal "_LOCK". A per-subsystem CAS mutex sentinel
                            # row, not a work stage — hence the `Level != LOCK` filter on every
                            # stage query


class GroundingStatus(StrEnum):
    """`Identified_Threat.GroundingStatus` — did an AI-proposed threat match an approved library
    master? Two bands, split by grounding_match_threshold (default 75)."""
    verified = "verified"       # >= threshold — ThreatTypeID/ThreatCatalogueID set to that master
    unverified = "unverified"   # < threshold — "novel", not "rejected": still gets a scenario, and
                                # is what library promotion feeds on (accept.py)


class DuplicateReason(StrEnum):
    """`Identified_Duplicate_Threat.DuplicateReason` — why a proposed threat was diverted there
    instead of Identified_Threat. See tasks.py::find_threats/_semantic_duplicates."""
    identity = "identity"                                  # exact identity-hash match
    semantic_same_category = "semantic_same_category"      # >= semantic_near_duplicate_threshold, same category
    semantic_cross_category = "semantic_cross_category"    # >= semantic_cross_category_threshold, different category


class ThreatRuleType(StrEnum):
    """`Config_Threat_Rule.RuleType`. Any other value in the column is ignored by the engine
    (logged, no effect) — same never-silently-false rule as an unknown RuleKey."""
    tech_gate = "tech_gate"                              # hard gate — failing it forces Selected=0
    relevance_flag = "relevance_flag"                    # additive score from a yes/no flag
    relevance_context_value = "relevance_context_value"  # additive score from a specific context value


class ScopingRejection(StrEnum):
    """`Scoped_Threat.RejectionKind` — WHY a threat was not selected, as a value code may branch
    on. `Reason` is the free-prose half for reviewers; prose may change, a kind is a contract.
    NULL on a selected row. See RESERVABLE_REJECTIONS."""
    top_n_cutoff = "top_n_cutoff"       # above the bar, outside this round's top-N — re-scoring re-selects it
    duplicate = "duplicate"             # same catalogue identity as a higher-ranked threat
    tech_gate = "tech_gate"             # a required-technology gate failed — permanent
    below_threshold = "below_threshold" # score under the configured floor — permanent


# The ONLY rejections dal.next_unserved_unique_threats may re-serve: the other three fail
# re-scoring identically, so re-serving one churns a Selected=0 row write_scenarios keeps
# refusing (the "no new threats" wedge). A tuple, not a set — the SQL text stays byte-stable
# so the plan cache isn't churned by set-iteration order.
RESERVABLE_REJECTIONS: tuple[ScopingRejection, ...] = (ScopingRejection.top_n_cutoff,)


class TriageVerdict(StrEnum):
    """Library-promotion triage outcome for one candidate generic name (accept.py). Stored in
    Scenario_Audit DetailJSON, so the values are a persistence contract."""
    auto_reject = "auto_reject"    # >= reject band: same idea reworded — link to the existing entry
    auto_approve = "auto_approve"  # < approve band vs everything: genuinely novel — insert active
    review = "review"              # between the bands, or any doubt — the curator decides


class SelectionReason(StrEnum):
    """`Scoped_Threat.SelectionKind` — the selection-side twin of ScopingRejection. Set on every
    Selected=1 row, NULL on rejected rows. Mapped 1:1 from GroundingStatus at scoring time, so it
    has exactly two members. `Reason` prose is DERIVED from this + FactorsJSON, never freehand."""
    verified_match = "verified_match"       # grounding matched an approved library entry
    unverified_match = "unverified_match"   # no confident library match — AI wording kept


class ScenarioStatus(StrEnum):
    """`Threat_Scenario_Output.Status` — one generated scenario row's outcome. Not StageStatus."""
    complete = "complete"
    error = "error"        # FAILURE CARD: a failed generation keeps a row (null scenario +
                        # ErrorMessage) so /regenerate/scenarios can retry it individually.
                        # Excluded from accept/salvage/resume by dal.py's `complete` filters


class ActorType(StrEnum):
    """`Scenario_Audit.ActorType` — who PERFORMED the event, kept separate from ActorUserID's
    "who is ACCOUNTABLE". Worker rows are back-filled with the session owner, so ActorUserID
    alone cannot distinguish the two. NULL on rows written before this column existed."""
    user = "user"      # a human performed it
    system = "system"  # a worker/the pipeline performed it; ActorUserID names who is answerable


class CandidateStatus(StrEnum):
    """`Threat_Candidate_Review.Status`. accept.py queues every AI-proposed threat NAME here
    rather than auto-creating a Threat_Catalogue row: prompts.py requires that name to embed the
    asset's own name, so it is never library-shaped."""
    pending = "pending"    # what accept.py writes — awaiting a curator to generalize the name
    accepted = "accepted"  # no writer: set by the curator workflow when it lands
    rejected = "rejected"  # no writer yet (curator workflow)


class RetryOutcome(StrEnum):
    """Result of one library-promotion retry or dismiss attempt (reaper.py's
    retry_one_promotion/dismiss_promotion), surfaced verbatim on the admin API's
    PromotionRetryResult.outcome."""
    succeeded = "succeeded"  # the promotion attempt ran and committed cleanly
    failed = "failed"        # the attempt ran but raised — see the session's PromotionError
    skipped = "skipped"      # a live worker or another retry already holds this session's lock


class ValidationStatus(StrEnum):
    """Deterministic output-validation result. These checks FLAG, never block — a parse failure
    is a stage ERROR upstream and never reaches them, so there is no `error` member."""
    ok = "ok"
    warning = "warning"  # recorded for the reviewer, never blocks accept


class AuditEventType(StrEnum):
    """`Scenario_Audit.EventType` — the append-only trail. Every member is written from exactly
    one place; some are defined with no current producer (reserved for a later milestone)."""
    session_started = "session_started"                # POST /sessions, after the stage rows are seeded
    auto_run_enqueued = "auto_run_enqueued"            # reserved — no current producer
    grounding_summary = "grounding_summary"            # per subsystem after Stage 1; DetailJSON: threat count
    scoping_complete = "scoping_complete"              # per subsystem after Stage 2 scoring; scoped/selected counts
    controls_mapped = "controls_mapped"                # per write_scenarios run; outputs/mapped/dropped/fallback counts
    generation_complete = "generation_complete"        # per subsystem after both stages; LLM provenance
    entered_review = "entered_review"                  # once, when every subsystem reaches the review barrier
    review_decision = "review_decision"                # the human's verdict at the review gate
    scenarios_accepted = "scenarios_accepted"          # Stage-2 outputs flipped Accepted=1 — NOT written on a
                                                    # mode="none" reject (nothing flipped)
    regeneration_completed = "regeneration_completed"  # one regenerate request finished its stage re-runs
    threat_regrounded = "threat_regrounded"            # reserved — only `scenario` regen is implemented
    subsystem_advanced = "subsystem_advanced"          # written at the START of a subsystem's work
    auto_fanout_review = "auto_fanout_review"          # reserved — no current producer
    library_promoted = "library_promoted"              # on accept, per NEW Threat_Type master created from an
                                                    # unverified threat (catalogue names go through triage)
    promotion_triage = "promotion_triage"              # on accept, ONE row listing every candidate's
                                                    # {generic_name, cosine, matched id, verdict} — the record
                                                    # the triage bands are tightened from
    candidate_reconciled = "candidate_reconciled"      # reserved — means a Threat_Candidate_Review row was CLOSED
                                                    # as accepted, which only the curator workflow can do
    session_cancelled = "session_cancelled"            # explicit cancel, or _mark_session_failed's total-failure
                                                    # path — either way releases the M4 lock
    stage_error = "stage_error"                        # a stage failed after retries
    next_set_outcome = "next_set_outcome"              # per "generate next set" click; DetailJSON: {outcome,
                                                    # requested, delivered, variants, reason, epoch}. A SEPARATE
                                                    # row from the generation_complete rows one click can write
                                                    # (those must be SUMMED); this is the authoritative summary
    treatment_plan_requested = "treatment_plan_requested"  # {plan_id, output_id}; ActorType=user
    treatment_plan_outcome = "treatment_plan_outcome"      # one plan attempt finished; {plan_id, status}; system
    treatment_plan_cancelled = "treatment_plan_cancelled"  # {plan_id}; ActorType=user
    treatment_plan_reviewed = "treatment_plan_reviewed"    # {plan_id, decision, comment?}; ActorType=user


class AuditDecision(StrEnum):
    """`Scenario_Audit.Decision` — written by accept.py::accept_session from its `subset` param."""
    accept = "accept"          # subset was None ("accept all")
    partial = "partial"        # AcceptBody mode="subset"
    reject = "reject"          # AcceptBody mode="none"
    regenerate = "regenerate"  # no writer (regeneration is audited via regeneration_completed)


class RegenGranularity(StrEnum):
    """Which stage levels a regenerate resets — see cascade.py's LEVELS_BY_GRANULARITY."""
    scenario = "scenario"   # rebuild one or more scenarios' narratives only


class SubsystemProgress(StrEnum):
    """Fully derived by `get_overall_status()` in app/api/sessions.py — never a stored column.
    Evaluated top-to-bottom, FIRST MATCH WINS: any stage ERROR -> error; session completed ->
    complete; session cancelled -> cancelled; SCENARIOS = AWAITING_DECISION -> awaiting_review;
    both IDLE -> pending; otherwise -> in_progress."""
    pending = "pending"
    in_progress = "in_progress"          # the fallback rollup
    awaiting_review = "awaiting_review"
    complete = "complete"                # from SessionStatus.completed — accept_session() never rewrites
                                        # Subsystem_Stage_State, so SCENARIOS never reaches COMPLETE
    error = "error"
    cancelled = "cancelled"


class SSEEventType(StrEnum):
    """Three scopes: `stage_started`/`stage_completed` are one SubsystemLevel cell (subsystem_id
    + stage); `subsystem_started` is one subsystem (no stage); `session_entered_review`/
    `heartbeat`/`reconcile` are session-wide (never a subsystem_id). `error` is DUAL-scope by
    design — an explicit `scope` field ("stage"/"session") says which, rather than relying on
    whether subsystem_id is present."""
    reconcile = "reconcile"                            # the one-time snapshot sent on (re)connect,
                                                    # before live deltas — the full SessionBoard,
                                                    # not a delta. Never published via bus.publish;
                                                    # sessions.py::stream_events sends it directly.
    stage_started = "stage_started"
    stage_completed = "stage_completed"                # a failure routes to `error` instead
    subsystem_started = "subsystem_started"            # fires BEFORE this subsystem's stages run
    session_entered_review = "session_entered_review"
    error = "error"                                    # DUAL-scope: carries an explicit "stage"/"session"
                                                    # `scope` field (tasks.py) — never tear down UI on
                                                    # this alone; wait for session_entered_review or a
                                                    # terminal session status (see the typed ErrorEvent)
    next_set_result = "next_set_result"                # advisory: subsystem_id + new_scenarios/no_new, plus
                                                    # reason/detail/message when no_new — reason is a stable
                                                    # code, detail is log-facing, message is the user sentence
                                                    # (cascade.py::_REASON_INFO)
    regen_result = "regen_result"                      # advisory: subsystem_id + requested_output_ids/
                                                    # new_output_ids, same reason/detail/message shape.
                                                    # new_output_ids=[] means every target rescored out
    treatment_plan_result = "treatment_plan_result"    # advisory: one treatment plan reached a committed
                                                    # COMPLETE/ERROR — carries output_id + plan_id + status,
                                                    # no subsystem_id (plans are per-scenario) and no
                                                    # error_message (the refetch carries it). A refetch HINT,
                                                    # never a completion contract: a dead worker, an
                                                    # LLMSlotUnavailable autoretry, and cancel/review (written
                                                    # in the API process) never publish, so a client must keep
                                                    # a slow backstop poll
    heartbeat = "heartbeat"                            # keep-alive so proxies don't drop an idle SSE connection


class NextSetOutcome(StrEnum):
    """What one "generate next set" click ACHIEVED — the single field a client switches on.
    Retryability is stated, never inferred from a shortfall count."""
    complete = "complete"                    # delivered the full next_set_size
    partial_retryable = "partial_retryable"  # short because generation(s) FAILED. A failed target keeps
                                            # Selected=1, so dal.next_unserved_unique_threats re-serves it —
                                            # clicking again IS the retry
    exhausted = "exhausted"                  # short (possibly zero) because nothing further EXISTS: the pool is
                                            # empty AND every identity has a scenario through every plausible
                                            # entry point it declared (dal.variant_eligible_primaries)


class ClickOutcomeReason(StrEnum):
    """Why an accepted click RAN and produced nothing. Rides the next_set_result / regen_result
    SSE `reason` field, the audit DetailJSON, and — for the two regen-target codes — HTTP 409
    `details.reason`.

    A member added here needs its cascade.py::_REASON_INFO entry; nothing pins that mapping, so a
    missing one surfaces only at runtime as a reason code with null detail and message.

    Values are verbatim the strings published in the API guide and on the live wire — a rename
    here is a breaking API change, not a refactor."""
    no_new_threats_found = "no_new_threats_found"                      # tasks.py: empty candidate pool from the start
    new_threat_did_not_qualify = "new_threat_did_not_qualify"          # tasks.py: candidate found, rescored out
    no_target_ids = "no_target_ids"                                    # cascade.py: regen request with zero targets
    output_not_found_or_superseded = "output_not_found_or_superseded"  # cascade.py: stale/foreign OutputIDs
    generation_failed = "generation_failed"                            # the LLM call itself failed — targets stay
                                                                    # Selected=1, the next click retries. A
                                                                    # transient provider error is NOT a scoping
                                                                    # rejection; reporting it as one sends
                                                                    # support down the wrong path


class ReviewGateReason(StrEnum):
    """Why a review action (accept / regenerate / next-set) is refused OUTRIGHT — HTTP 409
    `details.reason`. Produced in exactly one place, accept.py::review_gate_reason, shared by the
    accept gate and the regenerate/next-set gate so the two cannot drift.

    Means "your request never ran", not "it ran and found nothing" (ClickOutcomeReason).
    Deliberately absent from cascade.py::_REASON_INFO — gate 409s carry `reason` plus the
    exception's own message, and adding entries would reshape every gate 409 body."""
    session_completed = "session_completed"              # terminal: the review decision is already final
    session_cancelled = "session_cancelled"              # terminal: start a new session for the asset
    generation_in_progress = "generation_in_progress"    # transient: not at the REVIEW barrier yet


class TreatmentGateReason(StrEnum):
    """Why a treatment-plan request is refused — HTTP 409 `details.reason` (see
    docs/RISK_TREATMENT_PLAN_SDD.md §5.3). Separate from ReviewGateReason because treatment runs
    on COMPLETED sessions, after the review gate is history.

    `generation_in_progress` deliberately shares its value with the ReviewGateReason member —
    same meaning, different route family; clients may switch on the string either way."""
    scenario_not_accepted = "scenario_not_accepted"      # only accepted scenarios get treatment plans
    scenario_superseded = "scenario_superseded"          # target scenario was replaced by a regeneration
    generation_in_progress = "generation_in_progress"    # a fresh RUNNING plan row exists for this scenario
    not_in_progress = "not_in_progress"                  # cancel refused: no RUNNING generation to stop
    not_complete = "not_complete"                        # review refused: only a COMPLETE plan can be adopted


# --- Risk Treatment Plan vocabularies (docs/RISK_TREATMENT_PLAN_SDD.md) -------------------
# One source of truth per closed vocabulary, consumed three ways: Pydantic wire fields (422s +
# /openapi.json literal unions), treatment._validate_plan's advisory clamps, and
# prompts.treatment_prompt's FIELDS lines — built FROM these members, so the words the model may
# use can never drift from the words the API accepts.

class TreatmentStrategy(StrEnum):
    """The register's chosen treatment. Only Mitigate is implemented — the endpoint IS the
    Mitigate generator and stamps this server-side (never a request field in v1)."""
    mitigate = "Mitigate"


class RiskLevel(StrEnum):
    """Register risk level — request field `risk_level`, verbatim toolkit vocabulary."""
    low = "Low"
    medium = "Medium"
    high = "High"
    critical = "Critical"


class YesNo(StrEnum):
    """Toolkit boolean-as-text — request `existing_controls_all_subsystems` and plan output
    `applicable_to_all_subsystems`. Not bool: the toolkit columns say Yes/No verbatim."""
    yes = "Yes"
    no = "No"


class TreatmentOutcomeReason(StrEnum):
    """WHY a treatment plan ended the way it did — the machine-readable half of a terminal
    outcome, so a client never has to match an English sentence to decide what to offer next.

    `Status` alone is a seven-way overload: cancel, timeout, LLM failure, an unusable document, a
    guardrail block and a dead broker ALL store `ERROR`. Same split as TreatmentGateReason
    ("message for the human, reason for the client switch") and the NextSetOutcome/
    ClickOutcomeReason pair — the English is DERIVED from the code, never parsed back out of it.

    WIRE vocabulary, not a column domain: `Risk_Treatment_Plan.ErrorReason` can only ever hold
    FIVE of these six. `timed_out` is computed by api.treatment._present_status at read time from
    a RUNNING row whose progress clock stopped — there is no writer for it and no reaper to make
    one (SDD D10). Do NOT add a CHECK constraint for all six, and do NOT "fix" its absence by
    adding a sweeper. NULL on a COMPLETE row, and on ERROR rows written before the column existed
    (read those as generation_failed — the historical catch-all).

    Values are lowercase snake_case (name == value) because this is a switch code, not a label:
    the display vocabularies (RiskLevel, TreatmentStrategy, ActionPriority) capitalize because the
    toolkit renders them verbatim."""
    generation_failed = "generation_failed"  # LLM/pipeline failure — retryable as-is
    invalid_plan = "invalid_plan"            # model returned a document missing a required table —
                                            # retryable; a fresh generation may well parse
    content_blocked = "content_blocked"      # a configured safety guardrail refused it — the ONE
                                            # reason a client must NOT auto-retry unchanged
    cancelled = "cancelled"                  # a human stopped it (POST .../cancel), not a failure
    timed_out = "timed_out"                  # PROJECTION ONLY, never stored — see the docstring
    enqueue_failed = "enqueue_failed"        # the broker was unreachable; nothing ever ran, so
                                            # retrying immediately is the right move


class TreatmentReviewStatus(StrEnum):
    """`Risk_Treatment_Plan.ReviewStatus` — the human adoption decision on a COMPLETE plan. NULL
    = not reviewed; a re-review overwrites (latest wins); a regenerate supersedes the row, so the
    new version starts unreviewed — approval never silently carries across versions."""
    approved = "approved"
    changes_requested = "changes_requested"    # reviewer wants a different plan (regenerate with a note)


class ControlCoverage(StrEnum):
    """`plan.control_coverage` — did the request's existing controls already cover every control
    identified at scenario generation?"""
    gaps = "gaps"          # at least one identified control is uncovered -> controls to implement
    covered = "covered"    # fully covered -> empty to-implement list; action plan pivots to verification


class ControlType(StrEnum):
    """`plan.controls_to_be_implemented[].control_type`."""
    preventive = "preventive"
    detective = "detective"
    corrective = "corrective"
    compensating = "compensating"


class ActionPriority(StrEnum):
    """Priority vocabulary for recommended controls and action-plan rows."""
    critical = "Critical"
    high = "High"
    medium = "Medium"
    low = "Low"
