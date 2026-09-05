"""SQLAlchemy 2.0 typed ORM table definitions — a database-first mirror of the live schema.
NOT used to create tables; they describe the real columns so we can query/bind against them.
Types are portable (Unicode→NVARCHAR/TEXT, GUID→UNIQUEIDENTIFIER/Unicode(36)) so pure-logic
unit tests run on SQLite while integration runs on MSSQL.

Each class's `__table__` is still a plain Core `Table`, for the few call sites needing a
whole-row Core select (`select(m.Table.__table__)`) instead of an ORM entity load.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    Integer,
    MetaData,
    TypeDecorator,
    Unicode,
    UnicodeText,
)
from sqlalchemy.dialects import mssql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

metadata = MetaData()

class Base(DeclarativeBase):
    metadata = metadata

class GUID(TypeDecorator):
    impl = Unicode(36)
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "mssql":
            return dialect.type_descriptor(mssql.UNIQUEIDENTIFIER())
        return dialect.type_descriptor(Unicode(36))

    def bind_processor(self, dialect):
        def process(value):
            if value is None:
                return None
            if isinstance(value, uuid.UUID):
                return str(value)
            # Round-trip a plain string through uuid.UUID() to validate and normalize it.
            return str(uuid.UUID(str(value)))
        return process

    def result_processor(self, dialect, coltype):
        def process(value):
            if value is None:
                return None
            if isinstance(value, uuid.UUID):
                return str(value)
            # Normalize whatever the driver returned into a canonical UUID string.
            return str(uuid.UUID(str(value)))
        return process

# ---------------------------------------------------------------------------
# Session & state
# ---------------------------------------------------------------------------
class Scenario_Session(Base):
    __tablename__ = "Scenario_Session"
    SessionID: Mapped[str] = mapped_column(GUID, primary_key=True)
    TenantID: Mapped[str] = mapped_column(Unicode(200))
    EntityID: Mapped[str] = mapped_column(Unicode(200))         
    UserID: Mapped[str | None] = mapped_column(Unicode(200))
    AssetName: Mapped[str] = mapped_column(Unicode(300))
    AssetID: Mapped[str] = mapped_column(Unicode(200))  
    SessionStatus: Mapped[str] = mapped_column(Unicode(100))
    CurrentStage: Mapped[str] = mapped_column(Unicode(100))
    StageStatus: Mapped[str] = mapped_column(Unicode(100))
    Mode: Mapped[str] = mapped_column(Unicode(100))
    CurrentSubsystemIndex: Mapped[int | None] = mapped_column(Integer)
    SubsystemsJSON: Mapped[str] = mapped_column(UnicodeText)
    IdempotencyKey: Mapped[str | None] = mapped_column(Unicode(200))
    SectorIDsJSON: Mapped[str | None] = mapped_column(UnicodeText)
    AssetContextJSON: Mapped[str | None] = mapped_column(UnicodeText)
    # The session's frozen tuning rulebook (core.tuning.resolve_snapshot), written once at
    # creation. NULL = pre-feature session: workers resolve from config instead.
    # Renamed from TuningJSON: the value is a SNAPSHOT, frozen at session creation, and that
    # is the load-bearing part - every later stage reads it so a mid-run Config_Tuning edit
    # cannot change how a session already in flight scores. The old name read as "the tuning
    # config", which is what it deliberately is NOT.
    ScoringRulesSnapshotJSON: Mapped[str | None] = mapped_column(UnicodeText)
    CreatedAt: Mapped[datetime | None] = mapped_column(DateTime)
    UpdatedAt: Mapped[datetime | None] = mapped_column(DateTime)
    CompletedAt: Mapped[datetime | None] = mapped_column(DateTime)
    # Cancellation attribution. CompletedAt covers the SUCCESS path only — a cancelled session had
    # no row-level record of who stopped it or when, only a session_cancelled ledger event.
    # NULL on sessions cancelled before these columns existed.
    CancelledAt: Mapped[datetime | None] = mapped_column(DateTime)
    CancelledBy: Mapped[str | None] = mapped_column(Unicode(200))
    # Step-4 control mapping is the only reported step that is NOT a plain wall-clock span:
    # it can resume across several tsg.map_controls_sweep ticks 300s apart, so a StartedAt/
    # FinishedAt pair would report mostly WAITING. This is the seconds actually spent mapping,
    # accumulated (+=) once per pass by dal.accumulate_control_map_seconds.
    ControlMapSeconds: Mapped[float | None] = mapped_column(Float)


class Subsystem_Stage_State(Base):
    __tablename__ = "Subsystem_Stage_State"
    StateID: Mapped[str] = mapped_column(GUID, primary_key=True)
    SessionID: Mapped[str] = mapped_column(GUID)
    TenantID: Mapped[str | None] = mapped_column(Unicode(200))
    EntityID: Mapped[str | None] = mapped_column(Unicode(200))
    SubsystemID: Mapped[int] = mapped_column(Integer)
    Level: Mapped[str] = mapped_column(Unicode(100))
    Status: Mapped[str] = mapped_column(Unicode(100))
    GenerationEpoch: Mapped[int] = mapped_column(Integer)
    ActiveTaskID: Mapped[str | None] = mapped_column(GUID)
    LeaseExpiresAt: Mapped[datetime | None] = mapped_column(DateTime)
    HeartbeatAt: Mapped[datetime | None] = mapped_column(DateTime)
    AttemptCount: Mapped[int] = mapped_column(Integer, default=0)
    ErrorMessage: Mapped[str | None] = mapped_column(UnicodeText)
    UpdatedAt: Mapped[datetime] = mapped_column(DateTime)
    # Nullable so the seeds' explicit column lists stay valid; the DDL defaults it.
    CreatedAt: Mapped[datetime | None] = mapped_column(DateTime)
    # The stage's wall-clock span, and the ONLY source the API uses for per-stage duration.
    # UpdatedAt cannot substitute: claim_stage, renew_lease, renew_lock_lease, release_lock AND
    # finish_stage all overwrite it. CreatedAt cannot either: pipeline_common.set_up_progress_
    # tracking stamps every level at once, so it is a session-creation time.
    # StartedAt is the start of the attempt that produced the CURRENT result, not a first-attempt
    # stamp - claim_stage overwrites it on a re-claim, in step with AttemptCount, and clears
    # FinishedAt at the same time; reset_stage_for_regen clears both. EVERY terminal write stamps
    # FinishedAt (finish_stage; _record_failure; the reaper uses HeartbeatAt, the last proof of
    # life) - a static test enforces it, so a stage can never end without an end.
    StartedAt: Mapped[datetime | None] = mapped_column(DateTime)
    FinishedAt: Mapped[datetime | None] = mapped_column(DateTime)

# ---------------------------------------------------------------------------
# Pipeline outputs (entity resolved via the session; carry TenantID+SubsystemID)
#
# `UserID` here is PROVENANCE inherited from Scenario_Session.UserID — the accountable session
# owner, never the author: every row is worker-written from LLM output. Hence no ActorType
# companion; it would read 'system' on 100% of rows. Scenario_Audit needs one because it is the
# only table where human- and worker-written rows share a column.
# ---------------------------------------------------------------------------
class Identified_Threat(Base):
    __tablename__ = "Identified_Threat"
    ThreatID: Mapped[str] = mapped_column(GUID, primary_key=True)
    SessionID: Mapped[str] = mapped_column(GUID)
    TenantID: Mapped[str | None] = mapped_column(Unicode(200))
    EntityID: Mapped[str | None] = mapped_column(Unicode(200))
    UserID: Mapped[str | None] = mapped_column(Unicode(200))
    # 0 = the asset itself (tasks.ASSET_UNIT_ID); >= 1 = one supporting system.
    # ONE threat produces SEVERAL rows: the asset row plus a copy, with its own ThreatID, on
    # every supporting system a tech_gate does not rule out. The asset row is the WORKING row
    # — scoping, scenario generation, next-set and accept all read subsystem 0 and are blind
    # to the copies. The copies exist so the coverage grid has real (system x STRIDE) cells
    # and a reviewer can see a threat's blast radius. Do not "deduplicate" them.
    SubsystemID: Mapped[int] = mapped_column(Integer)
    ThreatCategory: Mapped[str] = mapped_column(Unicode(200))
    ThreatType: Mapped[str] = mapped_column(Unicode(300))
    ThreatName: Mapped[str | None] = mapped_column(Unicode(500))
    # ThreatName's library-shaped form (no asset/product names) — the AI's own generalization,
    # validated server-side. Persisted at Stage 1 because accept-time triage runs days later;
    # NULL on legacy rows, where triage falls back to the string-strip.
    GenericName: Mapped[str | None] = mapped_column(Unicode(500))
    # Description was DROPPED 2026-09-05 (user instruction) - the last of the three, after
    # Threat_Type's and Threat_Catalogue's went on 2026-08-30. Nothing consumed it: promotion
    # had already stopped copying it when Threat_Catalogue.Description went, leaving the
    # /results payload as its only reader. The model is no longer asked for it (prompts.py).
    # The category id grounding.find_threat_in_library ALREADY resolves to narrow its type search
    # and used to discard, forcing accept.py to re-derive it from text three separate times.
    # Persisted so every later consumer reads an id instead of matching a string. NULL when the
    # AI's category text matched no master row — previously silent, now visible.
    ThreatCategoryID: Mapped[int | None] = mapped_column(Integer)
    ThreatActorsJSON: Mapped[str | None] = mapped_column(UnicodeText)
    LibraryThreatType: Mapped[str | None] = mapped_column(Unicode(300))
    LibraryThreatName: Mapped[str | None] = mapped_column(Unicode(500))
    ThreatTypeID: Mapped[int | None] = mapped_column(Integer)
    # Threat_Catalogue.ThreatCatalogueID when this threat came from / verified against the
    # library. Set ⟺ GroundingStatus == 'verified' — the invariant every "is it a library
    # threat?" gate relies on (dedup's cat: rung, accept's liveness gate, promote's reuse gate).
    ThreatCatalogueID: Mapped[int | None] = mapped_column(Integer)
    # Immutable provenance, set ONCE by tasks._build_threat_records (the only threat-row
    # writer): True <=> the threat was NOT in the catalogue at identification time. Retrieved
    # and grounding-verified rows are library threats -> False. Promotion later stamps
    # ThreatCatalogueID but must NOT touch this -- it answers "was this invented by the
    # AI?", which promotion doesn't change.
    IsThreatAIGenerated: Mapped[bool] = mapped_column(Boolean, default=False)
    # SAME rule, one level up: True <=> ThreatTypeID was NOT a library match at identification
    # time. A SEPARATE fact from IsThreatAIGenerated above -- a threat can invent a new catalogue
    # entry under an EXISTING, already-curated type (IsThreatAIGenerated True, this False). Without
    # its own column this would have to be derived from live ThreatTypeID, which promotion DOES
    # mutate (mints a new Threat_Type and stamps its id here) -- exactly the trap this column
    # exists to avoid, mirroring IsThreatAIGenerated's own reasoning above.
    IsThreatTypeAIGenerated: Mapped[bool] = mapped_column(Boolean, default=False)
    GroundingStatus: Mapped[str] = mapped_column(Unicode(100))
    GroundingScore: Mapped[float | None] = mapped_column(Float)
    # WHICH cutoff judged this row: 'calibrated' (measured for this exact model pair),
    # 'static_default' (the built-in 75.0, tuned for a DIFFERENT pair — provisional),
    # 'env_pinned', or 'not_applicable' (library-first identity match — no cutoff was consulted). The score alone cannot answer it, and the three collide numerically, so
    # after a deployment finally calibrates there is otherwise NO way to find the threats that
    # were graded on the wrong number. Same reasoning and same shape as
    # Threat_Scenario_Control_Map's min_score_origin. NULL ONLY on rows written before this column.
    GroundingThresholdOrigin: Mapped[str | None] = mapped_column(Unicode(100))
    Superseded: Mapped[int] = mapped_column(Integer, default=0)
    CreatedAt: Mapped[datetime | None] = mapped_column(DateTime)


class Identified_Duplicate_Threat(Base):
    """Audit-only trail of AI-proposed threats DROPPED as duplicates during find_threats — never
    read by scoping/scenario generation/next-set. See scripts/TSG_Core.sql for the full rationale;
    Identified_Threat itself is untouched by this table's existence."""
    __tablename__ = "Identified_Duplicate_Threat"
    DuplicateThreatID: Mapped[str] = mapped_column(GUID, primary_key=True)
    SessionID: Mapped[str] = mapped_column(GUID)
    TenantID: Mapped[str | None] = mapped_column(Unicode(200))
    EntityID: Mapped[str | None] = mapped_column(Unicode(200))
    UserID: Mapped[str | None] = mapped_column(Unicode(200))
    SubsystemID: Mapped[int] = mapped_column(Integer)
    ThreatCategory: Mapped[str] = mapped_column(Unicode(200))
    ThreatType: Mapped[str] = mapped_column(Unicode(300))
    ThreatName: Mapped[str | None] = mapped_column(Unicode(500))
    GenericName: Mapped[str | None] = mapped_column(Unicode(500))
    ThreatActorsJSON: Mapped[str | None] = mapped_column(UnicodeText)
    # Identified_Threat.ThreatID it matched, when known — best-effort, see the SQL comment.
    DuplicateOfThreatID: Mapped[str | None] = mapped_column(GUID)
    DuplicateReason: Mapped[str] = mapped_column(Unicode(100))  # DuplicateReason enum (app/core/enums.py)
    SimilarityScore: Mapped[float | None] = mapped_column(Float)
    CreatedAt: Mapped[datetime | None] = mapped_column(DateTime)


class Scoped_Threat(Base):
    __tablename__ = "Scoped_Threat"
    ScopedThreatID: Mapped[str] = mapped_column(GUID, primary_key=True)
    SessionID: Mapped[str] = mapped_column(GUID)
    TenantID: Mapped[str | None] = mapped_column(Unicode(200))
    EntityID: Mapped[str | None] = mapped_column(Unicode(200))
    UserID: Mapped[str | None] = mapped_column(Unicode(200))
    SubsystemID: Mapped[int] = mapped_column(Integer)
    ThreatID: Mapped[str] = mapped_column(GUID)
    Score: Mapped[float] = mapped_column(Float)
    ScopeRank: Mapped[int] = mapped_column(Integer)
    Selected: Mapped[int] = mapped_column(Integer, default=0)
    Reason: Mapped[str | None] = mapped_column(Unicode(500))
    # ScopingRejection, or NULL when Selected=1. The machine-readable twin of Reason: next-set
    # re-servability branches on THIS, so rewording Reason can never change behaviour.
    RejectionKind: Mapped[str | None] = mapped_column(Unicode(100))
    # SelectionReason, or NULL when Selected=0 (and on rows written before the column existed —
    # readers must treat NULL as "unknown", never re-derive it from Reason prose).
    SelectionKind: Mapped[str | None] = mapped_column(Unicode(100))
    FactorsJSON: Mapped[str | None] = mapped_column(UnicodeText)
    Superseded: Mapped[int] = mapped_column(Integer, default=0)
    CreatedAt: Mapped[datetime | None] = mapped_column(DateTime)


class Threat_Scenario(Base):
    __tablename__ = "Threat_Scenario"
    # Declared here as well as in TSG_Core.sql, and NOT redundantly: the app never runs
    # create_all (db/engine.py forbids it), so this materialises only where tables are built
    # FROM the models — the SQLite test engines. Without it a test can assert that accept and
    # reject are mutually exclusive against a shim that would happily store both, which is
    # passing for the wrong reason. Same reasoning as the filtered unique indexes those engines
    # create by hand, but declared once here so every present and future test file inherits it
    # instead of each one remembering.
    __table_args__ = (
        CheckConstraint("RejectedAt IS NULL OR Accepted = 0",
                        name="CK_Scenario_DecisionExclusive"),
    )
    ScenarioID: Mapped[str] = mapped_column(GUID, primary_key=True)
    SessionID: Mapped[str] = mapped_column(GUID)
    TenantID: Mapped[str | None] = mapped_column(Unicode(200))
    EntityID: Mapped[str | None] = mapped_column(Unicode(200))
    UserID: Mapped[str | None] = mapped_column(Unicode(200))
    SubsystemID: Mapped[int] = mapped_column(Integer)
    ScopedThreatID: Mapped[str] = mapped_column(GUID)
    Status: Mapped[str] = mapped_column(Unicode(100))
    ScenarioJSON: Mapped[str | None] = mapped_column(UnicodeText)
    ValidationJSON: Mapped[str | None] = mapped_column(UnicodeText)
    AcceptedSubsetJSON: Mapped[str | None] = mapped_column(UnicodeText)
    Accepted: Mapped[int] = mapped_column(Integer, default=0)
    Superseded: Mapped[int] = mapped_column(Integer, default=0)
    IdentityHash: Mapped[str | None] = mapped_column(Unicode(100))     #sha256(SessionID|SubsystemID|dedup_key) — dedup_key = cat:/type:/txt: (tasks._dedup_key); UX_Scenario_ActiveIdentity blocks a 2nd active row per (key, ScenarioNumber)
    # Which of the threat's coexisting scenarios this is: 1 = the original, 2+ = alternates
    # ("generate next set" variant fallback). How many a threat accumulates is NOT capped by a
    # setting: dal.variant_eligible_primaries derives it from that threat's own plausible entry
    # points — no other code path assigns a number.
    ScenarioNumber: Mapped[int] = mapped_column(Integer, default=1)
    # The ScenarioID this row replaced; NULL for first-run, next-set and variant rows. Backward-
    # linked, so following it yields the revision chain. Stamped from what the supersede actually
    # retired, never the requested target — the two are keyed differently. Not indexed by design.
    ReplacesScenarioID: Mapped[str | None] = mapped_column(GUID, nullable=True)
    GenerationEpoch: Mapped[int] = mapped_column(Integer, default=1)
    ErrorMessage: Mapped[str | None] = mapped_column(UnicodeText)
    CreatedAt: Mapped[datetime | None] = mapped_column(DateTime)
    # Step-4 attempt stamp (control_mapping.map_controls): NULL = mapping not yet attempted for
    # this output; set on every attempt EVEN when zero controls matched, so an output is never
    # re-scanned/re-reranked on later runs. Regen mints a new ScenarioID (stamp NULL) naturally.
    ControlsMappedAt: Mapped[datetime | None] = mapped_column(DateTime)
    # How many mapping passes this row has survived without a ControlsMappedAt stamp. Same shape
    # as Subsystem_Stage_State.AttemptCount, applied per-scenario: once >= control_map_max_attempts
    # control_mapping._under_attempt_limit permanently excludes the row from every future
    # eligible_outputs/sessions_awaiting_control_mapping call — a HARD CUTOFF by explicit owner
    # instruction, not a backoff. Recovering a row past the limit needs a regenerate (which mints a
    # new ScenarioID, so a fresh row starts at 0) — nothing resets this on its own.
    ControlMapAttempts: Mapped[int] = mapped_column(Integer, default=0)
    # Per-scenario generation span. The duration is DERIVED (finish - start) and never stored,
    # so no second number can drift out of agreement with these two.
    # These OVERLAP across rows: generation fans out scenario_generation_concurrency (default 5)
    # at a time, so several rows share a GenStartedAt and summing their durations exceeds the
    # stage's wall clock. That is why no scenario-total field is published anywhere - use the
    # SCENARIOS stage span for "how long the stage took".
    GenStartedAt: Mapped[datetime | None] = mapped_column(DateTime)
    GenFinishedAt: Mapped[datetime | None] = mapped_column(DateTime)
    # Per-scenario review decision, independent of the session that produced the row: a reviewer
    # decides each scenario on their own schedule, so the verdict lives here, not on the session.
    # Both NULL = pending (nobody has looked) — which is what makes "seen and not chosen"
    # distinguishable from "not yet seen", a pair Accepted alone can never express.
    # Deliberately NOT folded into Status: that is the GENERATION outcome (complete|error) and is
    # load-bearing in the accept and promotion predicates (dal.mark_scenarios_accepted,
    # accept._promotion_candidates), so overloading it would couple a human decision to them.
    # Mutually exclusive with Accepted=1, enforced in the DATABASE by
    # CK_Scenario_DecisionExclusive — accept and reject are independent routes reachable in
    # either order, so the row itself is the one place both orderings must meet.
    # WHERE THE TEXT CAME FROM. Always "generated" now — the cross-tenant scenario-reuse
    # feature (Scenario_Library, "library" values) was removed 2026-08-29. Column kept, not
    # dropped: existing rows written before the removal may still say "library", and that's
    # real history a reviewer signing a risk register can still rely on.
    ScenarioSource: Mapped[str | None] = mapped_column(Unicode(100))
    RejectedAt: Mapped[datetime | None] = mapped_column(DateTime)
    RejectedBy: Mapped[str | None] = mapped_column(Unicode(200))
    # The ACCEPT half of the same fact. Reject recorded who/when from the start; accept recorded
    # neither, so the acceptor was answerable only from the Scenario_Audit ledger while the
    # rejecter was a column read — one class of fact in two places. Written by dal.decide_scenarios
    # ONLY, alongside Accepted, using the same coalesce(first-decider-wins) idiom as the pair above.
    # NULL on rows decided before these columns existed; no backfill runs.
    AcceptedAt: Mapped[datetime | None] = mapped_column(DateTime)
    AcceptedBy: Mapped[str | None] = mapped_column(Unicode(200))


class Grounding_Calibration_Run(Base):
    """One row per grounding-threshold calibration sweep (celery_app.calibrate_grounding_task),
    so "when was this calibrated, by whom, and did it pass?" survives the Celery result expiring
    after an hour. The terminal row is
    likewise committed in its own transaction so a FAILED sweep still leaves a record.

    THIS TABLE IS ALSO THE THRESHOLD ITSELF. `MatchTh` on the latest `success` row for a model
    pair is what grounding.resolve_thresholds reads — there is no second store. That is
    deliberate: the value used to live only in Mongo, written by a separate best-effort call that
    swallowed its own failures, so a 15-minute sweep could finish, lose its answer to a Mongo
    blip, and leave nothing but a log line. Making the measurement a COLUMN of the record of the
    measurement removes "measured but not saved" as a reachable state.

    Keyed by model pair because the cutoff is model-specific: a different embedding+reranker
    scores the same threat pair differently, so a calibration is only valid for the pair that
    produced it. A new pair simply has no successful row and falls back to the static default."""
    __tablename__ = "Grounding_Calibration_Run"
    RunID: Mapped[str] = mapped_column(GUID, primary_key=True)
    JobID: Mapped[str | None] = mapped_column(Unicode(100))        # Celery task id
    Status: Mapped[str] = mapped_column(Unicode(100))              # core.enums.CalibrationStatus
    # WHO ASKED, in two halves, because only one of them is proof. StartedBy is the X-User-Id
    # header: on admin routes it is trusted, never verified (deps.get_admin_principal), exactly
    # like every other CreatedBy/StartedBy column here. StartedByClient is the API_Client the
    # request authenticated as — that one IS verified. Recording both stops the claimed id from
    # reading as though it were established.
    StartedBy: Mapped[str | None] = mapped_column(Unicode(200))
    StartedByClient: Mapped[str | None] = mapped_column(Unicode(200))
    StartedAt: Mapped[datetime | None] = mapped_column(DateTime)
    FinishedAt: Mapped[datetime | None] = mapped_column(DateTime)
    EmbeddingModel: Mapped[str | None] = mapped_column(Unicode(500))
    RerankerModel: Mapped[str | None] = mapped_column(Unicode(500))
    Forced: Mapped[bool] = mapped_column(Boolean, default=False)   # re-measured over an existing run
    MatchTh: Mapped[float | None] = mapped_column(Float)           # the cutoff; NULL unless success
    Quality: Mapped[float | None] = mapped_column(Float)           # Youden's J at MatchTh, 0-1
    NegativesCount: Mapped[int | None] = mapped_column(Integer)
    PositivesCount: Mapped[int | None] = mapped_column(Integer)
    HighestNegative: Mapped[float | None] = mapped_column(Float)
    LowestPositive: Mapped[float | None] = mapped_column(Float)
    NearDuplicatesJSON: Mapped[str | None] = mapped_column(UnicodeText)  # curation to-do, not an error
    ErrorMessage: Mapped[str | None] = mapped_column(UnicodeText)


class Threat_Scenario_Control_Map(Base):
    """Step 4: which Control_Library rows mitigate one generated scenario (control_mapping.map_controls).
    No Superseded/epoch columns — visibility follows the parent Threat_Scenario row,
    same posture as Scoped_Threat. Composite PK doubles as the dedup guard."""
    __tablename__ = "Threat_Scenario_Control_Map"
    ScenarioID: Mapped[str] = mapped_column(GUID, primary_key=True)
    ControlLibraryID: Mapped[int] = mapped_column(Integer, primary_key=True)
    SessionID: Mapped[str] = mapped_column(GUID)
    MapRank: Mapped[int] = mapped_column(Integer)             # 1 = best match
    Score: Mapped[float | None] = mapped_column(Float)        # raw rerank 0-100
    SuggestedControl: Mapped[str | None] = mapped_column(Unicode(500))  # LLM's free-text suggestion; NULL on scenario-text fallback
    CreatedAt: Mapped[datetime | None] = mapped_column(DateTime)


class Risk_Treatment_Plan(Base):
    """One LLM-generated Risk Treatment Plan attempt for an ACCEPTED scenario
    (docs/RISK_TREATMENT_PLAN_SDD.md). At most one active (Superseded=0) row per ScenarioID —
    UX_TreatmentPlan_ActiveScenario is the concurrent-POST race arbiter. Deliberately OUTSIDE the
    Subsystem_Stage_State machinery: accepted scenarios live on completed sessions, where
    acquire_lock/claim_stage refuse to run, so this row's own Status column is the state.
    Regenerate = supersede + new row; rows are never reused, so no GenerationEpoch."""
    __tablename__ = "Risk_Treatment_Plan"
    PlanID: Mapped[str] = mapped_column(GUID, primary_key=True)
    SessionID: Mapped[str] = mapped_column(GUID)
    ScenarioID: Mapped[str] = mapped_column(GUID)               # the accepted Threat_Scenario
    TenantID: Mapped[str | None] = mapped_column(Unicode(200))
    EntityID: Mapped[str | None] = mapped_column(Unicode(200))  # copied from the session (authz boundary)
    UserID: Mapped[str | None] = mapped_column(Unicode(200))    # requesting principal (provenance)
    CrmRiskIdentificationID: Mapped[int | None] = mapped_column(Integer)  # reserved; unused — the register sends risk data in the request body, no lookup
    TreatmentStrategy: Mapped[str] = mapped_column(Unicode(100))   # 'Mitigate' only in v1
    Status: Mapped[str] = mapped_column(Unicode(100))         # StageStatus subset: RUNNING | COMPLETE | ERROR
    ActiveTaskID: Mapped[str | None] = mapped_column(Unicode(100))  # Celery claim / redelivery fence
    RiskIdentificationDate: Mapped[datetime | None] = mapped_column(DateTime)  # crm creation_date; never AI-generated
    InputSnapshotJSON: Mapped[str | None] = mapped_column(UnicodeText)  # exact redacted context sent to the LLM
    PlanJSON: Mapped[str | None] = mapped_column(UnicodeText)
    ValidationJSON: Mapped[str | None] = mapped_column(UnicodeText)  # advisory: moderation + vocabulary warnings
    ErrorMessage: Mapped[str | None] = mapped_column(UnicodeText)    # client-safe only; raw text lives in Prompt_Log
    Superseded: Mapped[int] = mapped_column(Integer, default=0)
    CreatedAt: Mapped[datetime | None] = mapped_column(DateTime)
    UpdatedAt: Mapped[datetime | None] = mapped_column(DateTime)  # progress clock: claim + each LLM attempt bump it
    CompletedAt: Mapped[datetime | None] = mapped_column(DateTime)
    RiskLevel: Mapped[str | None] = mapped_column(Unicode(100))   # register risk level from the request (filterable)
    ReviewStatus: Mapped[str | None] = mapped_column(Unicode(100))  # TreatmentReviewStatus; NULL = not reviewed
    ReviewComment: Mapped[str | None] = mapped_column(UnicodeText)
    ReviewedBy: Mapped[str | None] = mapped_column(Unicode(200))  # from the reviewer's login token
    ReviewedAt: Mapped[datetime | None] = mapped_column(DateTime)
    # Cancellation attribution. /treatment-plan/cancel and the treatment_plan_cancelled audit event
    # both predate these columns; the row itself recorded neither who nor when, so a cancelled plan
    # could not say who stopped it without reading the ledger. NULL on plans cancelled earlier.
    CancelledAt: Mapped[datetime | None] = mapped_column(DateTime)
    CancelledBy: Mapped[str | None] = mapped_column(Unicode(200))
    # TreatmentOutcomeReason — WHY a terminal row ended that way, so a client never parses
    # ErrorMessage. NULL on COMPLETE and on rows that failed before the column existed (read those
    # as generation_failed). Holds 5 of the enum's 6 values: 'timed_out' is projected at read time
    # by api.treatment._present_status and has no writer.
    ErrorReason: Mapped[str | None] = mapped_column(UnicodeText)

# ---------------------------------------------------------------------------
# Threat library masters (seeded; grown ONLY via POST .../promote-to-library, or curated
# directly in the database — the admin CRUD API for this was removed 2026-08 as unused
# complexity; see git history for app/api/library_crud.py if it's ever needed again). The
# threat LIST itself is Threat_Catalogue (below).
#
# All four carry the same audit quartet:
#   CreatedAt/CreatedBy — every insert path. CreatedBy holds the caller's user id, or an
#                         'auto:<source>' / 'cli:<user>' literal when there was no logged-in caller.
#   UpdatedAt/UpdatedBy — CRUD update/delete ONLY. The promote API's upserts leave an existing
#                         row untouched (provenance is first-writer — dal.upsert_threat_type),
#                         so a re-promotion never restamps a row a curator has since edited.
# A soft delete IS an update (IsDeleted=1 plus the Updated* stamp) — hence no DeletedBy column.
# ---------------------------------------------------------------------------
class Threat_Category(Base):
    __tablename__ = "Threat_Category"
    # autoincrement=False is load-bearing: this PK is a plain caller-supplied int, not IDENTITY.
    # Without it SQLAlchemy infers autoincrement and MSSQL emits SET IDENTITY_INSERT, which SQL
    # Server rejects (Msg 8106) -> 500 on every create. SQLite has no such logic, so CI can't see it.
    ThreatCategoryID: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    ThreatCategoryName: Mapped[str] = mapped_column(Unicode(200))
    ThreatCategoryCode: Mapped[str | None] = mapped_column(Unicode(100))
    IsActive: Mapped[bool] = mapped_column(Boolean, default=True)
    IsDeleted: Mapped[bool] = mapped_column(Boolean, default=False)
    CreatedAt: Mapped[datetime | None] = mapped_column(DateTime)
    CreatedBy: Mapped[str | None] = mapped_column(Unicode(200))
    UpdatedAt: Mapped[datetime | None] = mapped_column(DateTime)
    UpdatedBy: Mapped[str | None] = mapped_column(Unicode(200))


class Threat_Type(Base):
    __tablename__ = "Threat_Type"
    ThreatTypeID: Mapped[int] = mapped_column(Integer, primary_key=True)
    ThreatTypeName: Mapped[str] = mapped_column(Unicode(300))
    # SectorID and Description were both DROPPED 2026-08-30 as unused (sector logic was removed
    # 2026-08 per user instruction; nothing read Description either).
    ThreatCategoryID: Mapped[int | None] = mapped_column(Integer)
    IsActive: Mapped[bool] = mapped_column(Boolean, default=True)
    IsDeleted: Mapped[bool] = mapped_column(Boolean, default=False)
    # Provenance: 'functional_team_excel' (curated) | 'ai_auto_promoted' | an import tag
    # (threat_library_import.SOURCE_TAGS) | 'manual' (CRUD API). Added by a separate ALTER
    # further down scripts/Threat_library.sql, not this table's own CREATE block (which also
    # lives there, moved from scripts/TSG_Core.sql 2026-08-04) — see test_schema_sync's
    # _COLUMN_DEPLOYED_SEPARATELY.
    Source: Mapped[str | None] = mapped_column(Unicode(50))
    CreatedAt: Mapped[datetime | None] = mapped_column(DateTime)
    CreatedBy: Mapped[str | None] = mapped_column(Unicode(200))
    UpdatedAt: Mapped[datetime | None] = mapped_column(DateTime)
    UpdatedBy: Mapped[str | None] = mapped_column(Unicode(200))


class Threat_Actor(Base):
    __tablename__ = "Threat_Actor"
    ThreatActorID: Mapped[int] = mapped_column(Integer, primary_key=True)
    ThreatActorName: Mapped[str] = mapped_column(Unicode(200))
    IsCapable: Mapped[int] = mapped_column(Integer, default=1)
    IsActive: Mapped[bool] = mapped_column(Boolean, default=True)
    IsDeleted: Mapped[bool] = mapped_column(Boolean, default=False)
    # Same provenance vocabulary as Threat_Type.Source, but declared directly in this table's own
    # CREATE block in scripts/Threat_library.sql (moved from scripts/TSG_Core.sql 2026-08-04) —
    # so unlike the other two it needs no _COLUMN_DEPLOYED_SEPARATELY entry.
    Source: Mapped[str | None] = mapped_column(Unicode(100))
    CreatedAt: Mapped[datetime | None] = mapped_column(DateTime)
    CreatedBy: Mapped[str | None] = mapped_column(Unicode(200))
    UpdatedAt: Mapped[datetime | None] = mapped_column(DateTime)
    UpdatedBy: Mapped[str | None] = mapped_column(Unicode(200))


class Threat_Catalogue(Base):
    __tablename__ = "Threat_Catalogue"
    ThreatCatalogueID: Mapped[int] = mapped_column(Integer, primary_key=True)
    ThreatTypeID: Mapped[int] = mapped_column(Integer)
    ThreatName: Mapped[str] = mapped_column(Unicode(500))
    # Description was DROPPED 2026-08-30. It had fed the embedded passage
    # (embeddings.catalogue_passage_text) and the since-removed LLM validator prompt;
    # the passage is now name-only.
    # SectorID was DROPPED the same day — same rule as Threat_Type.SectorID above
    # (sector logic removed 2026-08, user instruction).
    IsActive: Mapped[bool] = mapped_column(Boolean, default=True)
    IsDeleted: Mapped[bool] = mapped_column(Boolean, default=False)
    # See Threat_Type.Source above — same provenance tracking, same script adds it.
    Source: Mapped[str | None] = mapped_column(Unicode(100))
    CreatedAt: Mapped[datetime | None] = mapped_column(DateTime)
    CreatedBy: Mapped[str | None] = mapped_column(Unicode(200))
    UpdatedAt: Mapped[datetime | None] = mapped_column(DateTime)
    UpdatedBy: Mapped[str | None] = mapped_column(Unicode(200))


class ThreatType_ThreatActor_Map(Base):
    __tablename__ = "ThreatType_ThreatActor_Map"
    ThreatTypeID: Mapped[int] = mapped_column(Integer, primary_key=True)
    ThreatActorID: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Nullable so the seeds' explicit column lists stay valid; the DDL defaults it.
    CreatedAt: Mapped[datetime | None] = mapped_column(DateTime)


class Threat_Catalogue_Category_Map(Base):
    __tablename__ = "Threat_Catalogue_Category_Map"
    # Declared CATEGORY-first to match the DDL's PK_Threat_Catalogue_Category_Map
    # (ThreatCategoryID, ThreatCatalogueID) — the order is load-bearing for
    # get_possible_types' category seek, and SQLAlchemy derives composite-PK order
    # from declaration order (the SQLite test schema must agree with MSSQL's).
    ThreatCategoryID: Mapped[int] = mapped_column(Integer, primary_key=True)
    ThreatCatalogueID: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Nullable so the seeds' explicit column lists stay valid; the DDL defaults it.
    CreatedAt: Mapped[datetime | None] = mapped_column(DateTime)


# ---------------------------------------------------------------------------
# Control library masters (seeded from functional-team Control_Library.xlsx). Created by
# scripts/Control_library.sql (run manually — see test_schema_sync's
# _DEPLOYED_SEPARATELY). IDENTITY PKs — never inserted by app code (the admin CRUD API that
# used to stamp these was removed 2026-08 as unused complexity). Same audit quartet as the
# threat masters.
class Control_Standard(Base):
    __tablename__ = "Control_Standard"
    StandardID: Mapped[int] = mapped_column(Integer, primary_key=True)
    StandardName: Mapped[str] = mapped_column(Unicode(200))
    Source: Mapped[str | None] = mapped_column(Unicode(100))
    CreatedAt: Mapped[datetime | None] = mapped_column(DateTime)
    CreatedBy: Mapped[str | None] = mapped_column(Unicode(200))
    UpdatedAt: Mapped[datetime | None] = mapped_column(DateTime)
    UpdatedBy: Mapped[str | None] = mapped_column(Unicode(200))
    IsActive: Mapped[bool] = mapped_column(Boolean, default=True)
    IsDeleted: Mapped[bool] = mapped_column(Boolean, default=False)


class Control_Library(Base):
    __tablename__ = "Control_Library"
    ControlLibraryID: Mapped[int] = mapped_column(Integer, primary_key=True)
    ControlCode: Mapped[str] = mapped_column(Unicode(100))     # 'CII-CID-001'..'CII-CID-1288', unique
    ITOT: Mapped[str] = mapped_column(Unicode(100))            # 'IT' | 'OT' — grounding's tolerant asset_type pre-filter
    Domain: Mapped[str] = mapped_column(Unicode(200))         # un-normalized vocabulary (96 distinct values) — report as-is, never join on it
    ControlName: Mapped[str] = mapped_column(Unicode(500))
    ControlDescription: Mapped[str] = mapped_column(UnicodeText)
    SampleEvidence: Mapped[str | None] = mapped_column(UnicodeText)
    Source: Mapped[str | None] = mapped_column(Unicode(100))
    CreatedAt: Mapped[datetime | None] = mapped_column(DateTime)
    CreatedBy: Mapped[str | None] = mapped_column(Unicode(200))
    UpdatedAt: Mapped[datetime | None] = mapped_column(DateTime)
    UpdatedBy: Mapped[str | None] = mapped_column(Unicode(200))
    IsActive: Mapped[bool] = mapped_column(Boolean, default=True)
    IsDeleted: Mapped[bool] = mapped_column(Boolean, default=False)


class Control_Library_Standard_Map(Base):
    __tablename__ = "Control_Library_Standard_Map"
    ControlLibraryID: Mapped[int] = mapped_column(Integer, primary_key=True)
    StandardID: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Nullable so the seeds' explicit column lists stay valid; the DDL defaults it.
    CreatedAt: Mapped[datetime | None] = mapped_column(DateTime)



class Config_Tuning(Base):
    """Business-calibration overrides, editable at runtime (admin/DBA insert; no restart).
    An active row overrides the matching Settings field for every session created AFTER the
    edit — never a running one, which keeps its Scenario_Session.ScoringRulesSnapshotJSON snapshot. Only
    keys in core.tuning.TUNABLE_KEYS have effect; unknown keys are skipped with a warning.
    EmbeddingModel names the model an embedding-coupled value was tuned on — on mismatch with
    the running model the row is skipped (config default applies)."""
    __tablename__ = "Config_Tuning"
    TuningID: Mapped[int] = mapped_column(Integer, primary_key=True)
    TuningKey: Mapped[str] = mapped_column(Unicode(100), unique=True)
    TuningValue: Mapped[str] = mapped_column(Unicode(100))
    ValueType: Mapped[str] = mapped_column(Unicode(100))  # 'float' | 'int'
    EmbeddingModel: Mapped[str | None] = mapped_column(Unicode(200))
    CreateDate: Mapped[datetime | None] = mapped_column(DateTime)
    CreatedBy: Mapped[str | None] = mapped_column(Unicode(200))
    UpdateDate: Mapped[datetime | None] = mapped_column(DateTime)
    UpdatedBy: Mapped[str | None] = mapped_column(Unicode(200))
    IsActive: Mapped[bool] = mapped_column(Boolean, default=True)
    IsDeleted: Mapped[bool] = mapped_column(Boolean, default=False)


# Context_Field_Config (the per-field AI-prompt allowlist) was removed: prompts.build_base_context
# now sends every context field the context layer assembled, filtered only by redaction and the
# no-value scrub in core.security.scrub_context. The SQL table and its seed are gone too.

# One row per LLM call (exact prompt + raw response, success or failure). Raw model output is
# NEVER put in ErrorMessage/audit/SSE (all client-visible) — only here.
class Prompt_Log(Base):
    __tablename__ = "Prompt_Log"
    LogID: Mapped[str] = mapped_column(GUID, primary_key=True)
    SessionID: Mapped[str] = mapped_column(GUID)
    TenantID: Mapped[str | None] = mapped_column(Unicode(200))
    EntityID: Mapped[str | None] = mapped_column(Unicode(200))
    UserID: Mapped[str | None] = mapped_column(Unicode(200))  # provenance — see pipeline outputs above
    SubsystemID: Mapped[int] = mapped_column(Integer)
    Stage: Mapped[str] = mapped_column(Unicode(100))           # 'threats' | 'scenario'
    PromptVersion: Mapped[str] = mapped_column(Unicode(100))
    Messages: Mapped[str] = mapped_column(UnicodeText)        # exact prompt sent, as the wire JSON structure
    # The same prompt flattened to one readable string. Nullable: rows written before this column
    # existed have no value, and TSG_Core.sql never backfills row data.
    Prompt: Mapped[str | None] = mapped_column(UnicodeText)
    ResponseText: Mapped[str | None] = mapped_column(UnicodeText)                    # raw LLM reply, including malformed ones
    Model: Mapped[str | None] = mapped_column(Unicode(200))
    ModelVersion: Mapped[str | None] = mapped_column(Unicode(100))
    ParseSucceeded: Mapped[bool] = mapped_column(Boolean)
    CreatedAt: Mapped[datetime] = mapped_column(DateTime)
    # Per-item id of the work this call served (treatment: PlanID) — the audit/evidence join.
    CorrelationID: Mapped[str | None] = mapped_column(GUID)

# ---------------------------------------------------------------------------
# Audit (append-only)
# ---------------------------------------------------------------------------
class Scenario_Audit(Base):
    __tablename__ = "Scenario_Audit"
    AuditID: Mapped[str] = mapped_column(GUID, primary_key=True)
    SessionID: Mapped[str] = mapped_column(GUID)
    TenantID: Mapped[str | None] = mapped_column(Unicode(200))
    EntityID: Mapped[str | None] = mapped_column(Unicode(200))
    # WorkflowStage this event belongs to. NULL on events that are not a stage transition
    # (session_started, subsystem_advanced) and on stage_error, which cannot know which of the
    # in-flight work levels failed.
    Stage: Mapped[str | None] = mapped_column(Unicode(100))
    # NOT a plain foreign key — three distinct meanings, none of them a broken reference:
    #   0    = THE ASSET ITSELF (tasks.ASSET_UNIT_ID). The pipeline is asset-centric, so almost
    #          every worker-written row carries 0; real supporting-system ids are >= 1.
    #   NULL = session-wide, belonging to no unit of work (session_started, entered_review,
    #          session_cancelled, the accept family).
    #   >= 1 = a specific supporting system. Historical rows only.
    SubsystemID: Mapped[int | None] = mapped_column(Integer)
    EventType: Mapped[str] = mapped_column(Unicode(100))
    # The scenario this event is ABOUT — set only on the per-scenario decision rows
    # (scenario_accepted / scenario_rejected), NULL on every session- or subsystem-scoped event.
    # A real column rather than a DetailJSON key: IX_ScenarioAudit_Scenario makes "the decision
    # history of this scenario" a seek, which is the query a GRC reviewer actually runs.
    ScenarioID: Mapped[str | None] = mapped_column(GUID)
    # The plan a treatment event concerns — a real column for the same reason as ScenarioID above:
    # IX_ScenarioAudit_Plan makes "this plan's history" a seek, where a DetailJSON key forced the
    # caller to fetch a whole session and filter in Python. NULL on every non-plan event.
    PlanID: Mapped[str | None] = mapped_column(GUID)
    Decision: Mapped[str | None] = mapped_column(Unicode(100))  # accept only — AuditDecision; NULL elsewhere
    Granularity: Mapped[str | None] = mapped_column(Unicode(100))  # regeneration_completed only
    ThreatTypeRefID: Mapped[int | None] = mapped_column(Integer)  # library_promoted +
    # candidate_reconciled (approvals: the minted/linked type)
    # WHO ACTUALLY DID IT: the authenticated principal on human actions, NULL on worker-written
    # rows. NULL is INFORMATION, not missing data — read ActorType beside it. This used to be
    # back-filled from Scenario_Session.UserID, which stamped every pipeline step with the session
    # owner's name and made the timeline unreadable; audit_row no longer does that.
    ActorUserID: Mapped[str | None] = mapped_column(Unicode(200))
    # WHO PERFORMED it, stated outright so a consumer never has to infer that a NULL ActorUserID
    # means the pipeline. NULL on rows predating the column — never back-filled,
    # since rewriting an append-only ledger would falsify records that were true when written.
    ActorType: Mapped[str | None] = mapped_column(Unicode(100))
    DetailJSON: Mapped[str | None] = mapped_column(UnicodeText)
    CreatedAt: Mapped[datetime] = mapped_column(DateTime)

# ---------------------------------------------------------------------------
# Context (platform-owned, read-only )
# ---------------------------------------------------------------------------
class user_table(Base):
    __tablename__ = "user"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(Unicode(255))
    email: Mapped[str] = mapped_column(Unicode(255))

# Read-only mirror of the platform's user->scope table (owned by Shield, we never write it).
# ref_id is polymorphic across scope levels; scope_type decodes via option_value group 1010
# (Sector/Sub-Sector/Service/Entity/Asset). For entity membership, ref_id = group.id = the
# EntityID TSG uses as its tenant key. Which scope_type value means "Entity" is resolved from
# the DB at runtime, not hardcoded — see dal.resolve_scope_type_entity_id/user_has_entity.
class user_scope_assignment(Base):
    __tablename__ = "user_scope_assignment"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer)
    scope_type: Mapped[int] = mapped_column(Integer)
    ref_id: Mapped[int] = mapped_column(BigInteger)
    is_active: Mapped[bool] = mapped_column(Boolean)

# TSG-owned. One row per API caller (today: the Shield backend). The secret is never stored;
# only its SHA-256 hex. Several Active rows may coexist for make-before-break key rotation.
class API_Client(Base):
    __tablename__ = "API_Client"
    ClientID: Mapped[str] = mapped_column(Unicode(100), primary_key=True)
    KeyHash: Mapped[str] = mapped_column(Unicode(100))          # SHA-256 hex of the 32-byte secret
    Name: Mapped[str] = mapped_column(Unicode(200))
    # Which module this key may authenticate ('tsg', 'chatbot', ...). A key is valid ONLY for its
    # own Module, so one leaked key is contained to a single module. See dal.api_client_id_for_key_hash.
    Module: Mapped[str] = mapped_column(Unicode(100), default="tsg")
    Active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Audit trail — who provisioned / revoked this key. NOT read by the auth path
    # (verify_api_key uses only KeyHash/Module/Active); these exist for provenance in the register.
    # No Updated* pair: there is no update route — Name/Module are immutable and rotation is
    # create-new + revoke-old, so the only mutation of an existing row is revoke.
    CreatedAt: Mapped[datetime] = mapped_column(DateTime)
    CreatedBy: Mapped[str | None] = mapped_column(Unicode(200))
    RevokedAt: Mapped[datetime | None] = mapped_column(DateTime)
    RevokedBy: Mapped[str | None] = mapped_column(Unicode(200))

class onboarding_sectors(Base):
    __tablename__ = "onboarding_sectors"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str | None] = mapped_column(Unicode(300))
    parent_id: Mapped[int | None] = mapped_column(Integer)
    definition: Mapped[str | None] = mapped_column(UnicodeText)

# saving the asset
class ctm_scan_entity(Base):
    __tablename__ = "ctm_scan_entity"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[str | None] = mapped_column(Unicode(200))
    name: Mapped[str | None] = mapped_column(Unicode(300))
    description: Mapped[str | None] = mapped_column(UnicodeText)
    criticality: Mapped[int | None] = mapped_column(Integer)
    # ctm_scan_category.id — the ASSET's own category (IT/OT/Physical/...). Unioned with each
    # supporting system's asset_type into the session's asset_category_ids (context.py).
    ctm_category_id: Mapped[int | None] = mapped_column(Integer)
    operating_system: Mapped[str | None] = mapped_column(Unicode(200))
    location: Mapped[str | None] = mapped_column(Unicode(200))
    owner_custodian: Mapped[str | None] = mapped_column(Unicode(200))
    target_rto_hours: Mapped[int | None] = mapped_column(Integer)
    target_rpo_hours: Mapped[int | None] = mapped_column(Integer)
    tier1_critical_service_id: Mapped[int | None] = mapped_column(Integer)
    priority: Mapped[int | None] = mapped_column(Integer)
    data_handled: Mapped[str | None] = mapped_column(UnicodeText)  # types of data this asset processes/stores
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)  # soft-delete flag — real queries filter WHERE is_deleted = 0

# The real, direct asset->entity link, and the ONLY one: ctm_scan_entity itself carries no group
# or entity column. Also the asset->service link — both foreign keys live on the same row, so the
# entity is NOT reached by traversing the service (services 336 and 494 are each shared by two
# entities, so that traversal is ambiguous anyway).
#
# tier1_critical_service_id above is NOT the ownership path: it is populated on 1 of 36 assets.
class ctm_scan_entity_bu(Base):
    __tablename__ = "ctm_scan_entity_bu"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ctm_scan_entity_id: Mapped[int] = mapped_column(Integer)  # FK to ctm_scan_entity.id
    group_id: Mapped[int] = mapped_column(Integer)  # FK to group.id — the owning entity
    service_id: Mapped[int | None] = mapped_column(Integer)  # FK to onboarding_services.id — an asset can link to more than one


# Two service->sector tables are deliberately UNMODELLED, both removed 2026-08-09:
#
#   onboarding_sector_services (service_id, sector_id) — the platform's authoritative
#     service -> sub-sector map.
#   onboarding_service_entity  (sector_id, service_id, group_id) — the same fact denormalised
#     onto the entity mapping. Was modelled but referenced by no file in app/.
#
# TSG reads NEITHER: the client supplies subsector_id directly on the session-create request,
# and an id that resolves to nothing is a caller error (_load_sector raises NotFoundError).
# Every mapped column is a column TSG demands of a database it does not own, so an ORM class
# for a table nothing queries is a liability, not documentation. Model onboarding_sector_services
# only if TSG ever needs to derive the sub-sector itself; prefer it over the denormalised copy.

# asset <-> onboarding_supporting_systems junction (many-to-many)
class ctm_scan_entity_supporting_system(Base):
    __tablename__ = "ctm_scan_entity_supporting_system"
    ctm_scan_entity_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    onboarding_supporting_system_id: Mapped[int] = mapped_column(Integer, primary_key=True)


class onboarding_supporting_systems(Base):
    __tablename__ = "onboarding_supporting_systems"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str | None] = mapped_column(Unicode(300))
    asset_type: Mapped[int | None] = mapped_column(Integer)
    min_no_of_transactions: Mapped[int | None] = mapped_column(Integer)
    max_no_of_transactions: Mapped[int | None] = mapped_column(Integer)
    url: Mapped[str | None] = mapped_column(Unicode(500))
    accessability_channel: Mapped[int | None] = mapped_column(Integer)  # single option_value code (option code 'acc-channel')
    technology_used: Mapped[str | None] = mapped_column(UnicodeText)
    user_base_count: Mapped[int | None] = mapped_column(Integer)
    targeted_users: Mapped[str | None] = mapped_column(UnicodeText)  # JSON array of option_value codes, e.g. "[6]" — see option/option_value
    managed_by: Mapped[int | None] = mapped_column(Integer)  # single option_value code (option code 'managed-by'), not free text
    vendor_name: Mapped[str | None] = mapped_column(Unicode(200))
    maintenance_contract_exists: Mapped[bool | None] = mapped_column(Boolean)
    hosting_location: Mapped[int | None] = mapped_column(Integer)  # single option_value code (option code 'hosting-location')
    dr_location: Mapped[str | None] = mapped_column(Unicode(300))
    network_connectivity_primary_dr: Mapped[int | None] = mapped_column(Integer)  # single option_value code (option code 'network-connectivity')
    last_dr_test_date: Mapped[datetime | None] = mapped_column(DateTime)
    backup_multi_site: Mapped[bool | None] = mapped_column(Boolean)
    backup_retention_period_days: Mapped[int | None] = mapped_column(Integer)
    backup_tested: Mapped[bool | None] = mapped_column(Boolean)
    offsite_air_gapped_backup: Mapped[bool | None] = mapped_column(Boolean)
    data_residency_restrictions: Mapped[bool | None] = mapped_column(Boolean)
    data_residency_restriction_justification: Mapped[str | None] = mapped_column(UnicodeText)
    document_drp_exists: Mapped[bool | None] = mapped_column(Boolean)
    dr_drill_frequency: Mapped[int | None] = mapped_column(Integer)  # single option_value code (option code 'dr-drill')
    database_platforms: Mapped[str | None] = mapped_column(Unicode(300))
    saas_backup_required: Mapped[bool | None] = mapped_column(Boolean)
    saas_platform_list: Mapped[str | None] = mapped_column(UnicodeText)  # JSON array of option_value codes (option code 'saas-platforms')
    public_cloud_platforms: Mapped[str | None] = mapped_column(UnicodeText)  # JSON array of option_value codes (option code 'pub-c-platforms')
    rto_target_mins: Mapped[float | None] = mapped_column(Float)
    rpo_target_mins: Mapped[float | None] = mapped_column(Float)
    data_loss_incident_last_3_years: Mapped[bool | None] = mapped_column(Boolean)
    incident_description: Mapped[str | None] = mapped_column(UnicodeText)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)  # soft-delete flag — real queries filter WHERE is_deleted = 0
    delete_reason: Mapped[str | None] = mapped_column(UnicodeText)
    creation_date: Mapped[datetime | None] = mapped_column(DateTime)
    date_updated: Mapped[datetime | None] = mapped_column(DateTime)
    created_by: Mapped[str | None] = mapped_column(Unicode(200))
    updated_by: Mapped[str | None] = mapped_column(Unicode(200))

# Read-only platform mirrors used by gather_asset_details (app/pipeline/context.py)
# to resolve every session-creation context field authoritatively from the real DB.
class onboarding_services(Base):
    __tablename__ = "onboarding_services"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str | None] = mapped_column(Unicode(255))
    description: Mapped[str | None] = mapped_column(UnicodeText)
    sector_id: Mapped[int | None] = mapped_column(Integer)  # FK to onboarding_sectors.id


# The curator's named option GROUP (e.g. "Accessibility Channel", id 1012); option_value below
# holds its members.
class option(Base):
    __tablename__ = "option"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    option: Mapped[str | None] = mapped_column(Unicode(255))
    code: Mapped[str | None] = mapped_column(Unicode(100))


class option_value(Base):
    __tablename__ = "option_value"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str | None] = mapped_column(Unicode(50))
    value: Mapped[int | None] = mapped_column(Integer)
    option_id: Mapped[int | None] = mapped_column(Integer)
    description: Mapped[str | None] = mapped_column(Unicode(255))

# asset_type FK target — 7 curator-seeded rows (ids 1-6, 1004);
# onboarding_supporting_systems.asset_type -> ctm_scan_category.id.
class ctm_scan_category(Base):
    __tablename__ = "ctm_scan_category"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    parent_id: Mapped[int | None] = mapped_column(Integer)
    code: Mapped[str | None] = mapped_column(Unicode(100))
    name: Mapped[str | None] = mapped_column(Unicode(255))
