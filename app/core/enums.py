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
    APPROVED = "APPROVED"                            # HISTORICAL: written by the pre-lifecycle accept path,
                                                     # which completed the session on the first accept. Nothing
                                                     # produces it now — generation completes the session AT
                                                     # REVIEW so scenarios stay individually decidable — but
                                                     # rows created before that change still carry it
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
    # HISTORICAL, no longer written: rows from before the drop rule went category-blind split
    # the reason by category. Kept so existing Identified_Duplicate_Threat rows stay readable.
    semantic_same_category = "semantic_same_category"
    semantic_cross_category = "semantic_cross_category"
    semantic_similarity = "semantic_same_threat"           # THE reason for every semantic drop now:
                                                        # cosine >= max(semantic_cross_category_threshold,
                                                        # session threshold), whatever the categories
    # A Stage-1b GENERATED proposal regrounded to a library row this round's VALIDATOR already
    # rejected as NOT_RELEVANT for this asset. The validator's drop is a hard drop (GAP-B) — a
    # proposal reaching the same catalogue row by a different path must not silently reverse it.
    validator_rejected = "validator_rejected"
                                                        # (tasks.py::_semantic_duplicates)


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


class ValidationStatus(StrEnum):
    """Deterministic output-validation result. These checks FLAG, never block — a parse failure
    is a stage ERROR upstream and never reaches them, so there is no `error` member."""
    ok = "ok"
    warning = "warning"  # recorded for the reviewer, never blocks accept


class AuditEventType(StrEnum):
    """`Scenario_Audit.EventType` — the append-only trail. Every member is written from exactly
    one place; some are defined with no current producer (reserved for a later milestone)."""
    session_started = "session_started"                # POST /sessions, after the stage rows are seeded
    grounding_summary = "grounding_summary"            # per subsystem after Stage 1; DetailJSON: threat count
    scoping_complete = "scoping_complete"              # per subsystem after Stage 2 scoring; scoped/selected counts
    controls_mapped = "controls_mapped"                # per write_scenarios run; outputs/mapped/dropped/fallback counts
    generation_complete = "generation_complete"        # per subsystem after both stages; LLM provenance
    entered_review = "entered_review"                  # once, when every subsystem reaches the review barrier
    review_decision = "review_decision"                # the human's verdict at the review gate
    scenarios_accepted = "scenarios_accepted"          # Stage-2 outputs flipped Accepted=1 — NOT written on a
                                                    # mode="none" reject (nothing flipped)
    scenario_accepted = "scenario_accepted"            # ONE row per scenario accepted, carrying scenario id. The
                                                    # session-scoped rows above say a review action happened;
                                                    # these say WHICH scenario, by WHOM, WHEN — the question a
                                                    # GRC reviewer asks, now that decisions land days apart
    scenario_rejected = "scenario_rejected"            # ONE row per scenario explicitly declined, carrying
                                                    # scenario id. Written by the same dal.decide_scenarios call
                                                    # that sets RejectedAt, so the two cannot diverge
    regeneration_completed = "regeneration_completed"  # one regenerate request finished its stage re-runs
    subsystem_advanced = "subsystem_advanced"          # written at the START of a subsystem's work
    library_promoted = "library_promoted"              # on accept, per threat whose library resolution CHANGED —
                                                    # a minted type/name (auto mode) or a link/adoption of an
                                                    # existing entry (the only form under switch OFF);
                                                    # DetailJSON.triage_verdict tells which
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
    treatment_plan_version_restored = "treatment_plan_version_restored"  # approve-swap made a historical
                                                           # version active; {plan_id: restored id,
                                                           # retired_plan_id, output_id}; ActorType=user.
                                                           # plan_id key REQUIRED — the per-scenario trail
                                                           # filters on it (api/treatment.py)
    scenario_unaccepted = "scenario_unaccepted"            # (forthcoming — no route writes this yet)
                                                           # per-scenario accept UNDONE post-completion;
                                                           # {output_id}; ActorType=user. The accept's own
                                                           # rows stay — the ledger shows both decisions


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
    whether subsystem_id is present. `embedding_job_update` is the one ADMIN-scope member:
    published on a per-job admin channel (admin_jobs.py::emb_job_channel_key), never on a
    session channel, so a session subscriber can never receive it."""
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
                                                    # LLMSlotUnavailable autoretry, and cancel plus a plain
                                                    # review verdict never publish (an approve that SWITCHES
                                                    # the active version does, post-commit, from the API
                                                    # process), so a client must keep a slow backstop poll
    heartbeat = "heartbeat"                            # keep-alive so proxies don't drop an idle SSE connection
    embedding_job_update = "embedding_job_update"      # ADMIN-scope: one embeddings job's state change on its
                                                    # own job channel — payload carries job_id + a
                                                    # CeleryJobState `state`, per-group progress
                                                    # (group/rows), and the terminal result fields
                                                    # (rows_processed/vectors_deleted or error)
    grounding_job_update = "grounding_job_update"      # ADMIN-scope: one grounding-calibration job's state
                                                    # change on its own job channel (admin_jobs.py::
                                                    # grounding_job_channel_key) — payload carries job_id +
                                                    # a CeleryJobState `state`, sweep progress (phase
                                                    # "negatives"/"positives" with done/total), and the
                                                    # terminal result (match_th/quality/...) or error
    intel_job_update = "intel_job_update"              # ADMIN-scope: one threat-intel feed-refresh job's state
                                                    # change on its own job channel (admin_jobs.py::
                                                    # intel_job_channel_key) — payload carries job_id + feed +
                                                    # a CeleryJobState `state` (RETRY is non-terminal, since
                                                    # this task retries on any exception up to max_retries),
                                                    # item_count on SUCCESS or error on terminal FAILURE


class CalibrationStatus(StrEnum):
    """`Grounding_Calibration_Run.Status` — one calibration sweep's lifecycle. (Reconstructed
    2026-08-28 after an editing accident removed the uncommitted original; the members are the
    exact set the code reads.)"""
    running = "running"      # in flight — UX_GroundingCalibration_Running admits one per model pair
    success = "success"      # measured and stored
    no_signal = "no_signal"  # ran, but the two classes did not separate — nothing stored
    skipped = "skipped"      # declined to re-measure; the value already in force stands
    failed = "failed"        # crashed; ErrorMessage carries why


class CeleryJobState(StrEnum):
    """Celery's own AsyncResult.state vocabulary — the one enum here that is NOT DB-stored.
    Exists so the admin job-status routes (embeddings + library import) and the job SSE events
    never compare or emit a bare state string (this module's own rule). Members are the complete
    set Celery reports, so `CeleryJobState(result.state)` is total — no fallback branch. With
    `task_track_started` on (celery_app.py) a picked-up task reports STARTED, so PENDING means
    "queued (or unknown id)", never "running"."""
    PENDING = "PENDING"      # queued, not yet picked up — or an id the result backend never saw
    RECEIVED = "RECEIVED"
    STARTED = "STARTED"      # a worker is executing it right now (requires task_track_started)
    RETRY = "RETRY"          # autoretry scheduled (e.g. LLMSlotUnavailable) — it WILL run again
    SUCCESS = "SUCCESS"      # terminal
    FAILURE = "FAILURE"      # terminal
    REVOKED = "REVOKED"      # terminal
    REJECTED = "REJECTED"
    IGNORED = "IGNORED"

    @property
    def is_terminal(self) -> bool:
        """True once the state can never change again — the SSE job stream closes on these."""
        return self in (CeleryJobState.SUCCESS, CeleryJobState.FAILURE, CeleryJobState.REVOKED)


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
    output_not_found_or_superseded = "output_not_found_or_superseded"  # cascade.py: stale/foreign scenario ids
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
    session_completed = "session_completed"              # terminal: the session is not at a review barrier
    session_cancelled = "session_cancelled"              # terminal: start a new session for the asset
    generation_in_progress = "generation_in_progress"    # transient: not at the REVIEW barrier yet
    asset_busy = "asset_busy"                            # transient: next-set could not re-reserve the
                                                         # asset — another execution holds it right now.
                                                         # The one member NOT produced by
                                                         # review_gate_reason (sessions.py::_do_next_set
                                                         # raises it from dal.reserve_session's CAS)


class ScenarioDecisionReason(StrEnum):
    """Why one scenario id could not be DECIDED — accepted or rejected. Per-id codes inside the
    404's `details.unacceptable` (produced by dal.undecidable_subset_reasons);
    `duplicate_identity` instead rides the accept 409's `details.reason`, raised pre-flight by
    accept.py::_assert_one_version_per_scenario — ClickOutcomeReason-style, one vocabulary across
    two channels. All are worded for humans by accept.py::_REASON_TEXT (a test pins the two in
    step). Formerly bare string literals, contrary to this module's one-source-of-truth rule.

    Covers BOTH decisions on purpose. It was `ScenarioDecisionReason` while accept was the only
    decision a reviewer could make; keeping that name once reject shipped is precisely how a
    second, near-identical enum gets started. Wire values are unchanged by the rename — this
    enum is not an OpenAPI Literal, only its strings travel.

    No `superseded` member: since Accepted was decoupled from Superseded, naming an older
    version is a legitimate accept, not a rejection cause."""
    unknown = "unknown"                                                # not a scenario in this session
    failure_card = "failure_card"                                      # generation failed; no content to decide
    subsystem_not_awaiting_decision = "subsystem_not_awaiting_decision"  # its stage isn't at the review barrier
    duplicate_identity = "duplicate_identity"                          # subset names 2+ versions of ONE scenario
    already_accepted = "already_accepted"                              # reject refused: accepting is the standing
                                                                    # decision on this scenario
    already_rejected = "already_rejected"                              # accept refused: rejecting is the standing
                                                                    # decision on this scenario


class UnacceptGateReason(StrEnum):
    """(Forthcoming) Why POST .../scenarios/{output_id}/unaccept would be refused — HTTP 409
    `details.reason`. Reserved for the paused per-scenario unaccept feature; NO route raises
    these yet."""
    not_accepted = "not_accepted"                        # the scenario isn't accepted (or a racing
                                                         # unaccept already flipped it)
    treatment_plan_exists = "treatment_plan_exists"      # a plan was generated FROM this acceptance —
                                                         # undoing beneath it would orphan the plan


class TreatmentGateReason(StrEnum):
    """Why a treatment-plan request is refused — HTTP 409 `details.reason` (see
    docs/RISK_TREATMENT_PLAN_SDD.md §5.3). Separate from ReviewGateReason because treatment runs
    on COMPLETED sessions, after the review gate is history.

    `generation_in_progress` deliberately shares its value with the ReviewGateReason member —
    same meaning, different route family; clients may switch on the string either way."""
    scenario_not_accepted = "scenario_not_accepted"      # only accepted scenarios get treatment plans
    scenario_superseded = "scenario_superseded"          # HISTORICAL, never raised since Accepted was
                                                         # decoupled from Superseded; kept for wire-compat
    generation_in_progress = "generation_in_progress"    # a fresh RUNNING plan row exists for this scenario
    not_in_progress = "not_in_progress"                  # cancel refused: no RUNNING generation to stop
    not_complete = "not_complete"                        # review refused: only a COMPLETE plan can be adopted
    plan_already_exists = "plan_already_exists"          # create refused: a plan exists — use /regenerate
    version_not_active = "version_not_active"            # reject refused: target is a history version,
                                                         # already not the plan — rejecting it is meaningless


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
    rejected = "rejected"    # reviewer rejected the plan — regenerate with a note. Renamed from
                             # 'changes_requested' (v0.13); stored rows backfilled in 1. TSG_Core.sql.


class ControlCoverage(StrEnum):
    """`plan.controls_to_be_implemented.control_coverage` — did the request's existing controls
    already cover every control identified at scenario generation?"""
    gaps = "gaps"          # at least one identified control is uncovered -> controls to implement
    covered = "covered"    # fully covered -> empty to-implement list; action plan pivots to verification


class ControlType(StrEnum):
    """`plan.controls_to_be_implemented.controls[].control_type`."""
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
