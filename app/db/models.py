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
    # Library-promotion retry tracking (accept.py's isolated Phase 2). NULL = never failed, or
    # already resolved by a successful attempt/retry — this is the ONLY state a fresh session has.
    PromotionFailedAt: Mapped[datetime | None] = mapped_column(DateTime)
    PromotionAttempts: Mapped[int] = mapped_column(Integer, default=0)
    PromotionError: Mapped[str | None] = mapped_column(UnicodeText)
    # The accepting user at the moment promotion first failed, so a later retry (automatic or
    # admin-triggered) attributes promoted threats to that SAME person, never to a system identity.
    PromotionUserID: Mapped[str | None] = mapped_column(Unicode(200))


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
    SubsystemID: Mapped[int] = mapped_column(Integer)
    ThreatCategory: Mapped[str] = mapped_column(Unicode(200))
    ThreatType: Mapped[str] = mapped_column(Unicode(300))
    ThreatName: Mapped[str | None] = mapped_column(Unicode(500))
    # ThreatName's library-shaped form (no asset/product names) — the AI's own generalization,
    # validated server-side. Persisted at Stage 1 because accept-time triage runs days later;
    # NULL on legacy rows, where triage falls back to the string-strip.
    GenericName: Mapped[str | None] = mapped_column(Unicode(500))
    ThreatActorsJSON: Mapped[str | None] = mapped_column(UnicodeText)
    LibraryThreatType: Mapped[str | None] = mapped_column(Unicode(300))
    LibraryThreatName: Mapped[str | None] = mapped_column(Unicode(500))
    ThreatTypeID: Mapped[int | None] = mapped_column(Integer)
    ThreatCatalogueID: Mapped[int | None] = mapped_column(Integer)
    GroundingStatus: Mapped[str] = mapped_column(Unicode(100))
    GroundingScore: Mapped[float | None] = mapped_column(Float)
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


class Threat_Scenario_Output(Base):
    __tablename__ = "Threat_Scenario_Output"
    # Declared here as well as in TSG_Core.sql, and NOT redundantly: the app never runs
    # create_all (db/engine.py forbids it), so this materialises only where tables are built
    # FROM the models — the SQLite test engines. Without it a test can assert that accept and
    # reject are mutually exclusive against a shim that would happily store both, which is
    # passing for the wrong reason. Same reasoning as the filtered unique indexes those engines
    # create by hand, but declared once here so every present and future test file inherits it
    # instead of each one remembering.
    __table_args__ = (
        CheckConstraint("RejectedAt IS NULL OR Accepted = 0",
                        name="CK_ScenarioOutput_DecisionExclusive"),
    )
    OutputID: Mapped[str] = mapped_column(GUID, primary_key=True)
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
    # The OutputID this row replaced; NULL for first-run, next-set and variant rows. Backward-
    # linked, so following it yields the revision chain. Stamped from what the supersede actually
    # retired, never the requested target — the two are keyed differently. Not indexed by design.
    ReplacesOutputID: Mapped[str | None] = mapped_column(GUID, nullable=True)
    GenerationEpoch: Mapped[int] = mapped_column(Integer, default=1)
    ErrorMessage: Mapped[str | None] = mapped_column(UnicodeText)
    CreatedAt: Mapped[datetime | None] = mapped_column(DateTime)
    # Step-4 attempt stamp (control_mapping.map_controls): NULL = mapping not yet attempted for
    # this output; set on every attempt EVEN when zero controls matched, so an output is never
    # re-scanned/re-reranked on later runs. Regen mints a new OutputID (stamp NULL) naturally.
    ControlsMappedAt: Mapped[datetime | None] = mapped_column(DateTime)
    # Per-scenario review decision, independent of the session that produced the row: a reviewer
    # decides each scenario on their own schedule, so the verdict lives here, not on the session.
    # Both NULL = pending (nobody has looked) — which is what makes "seen and not chosen"
    # distinguishable from "not yet seen", a pair Accepted alone can never express.
    # Deliberately NOT folded into Status: that is the GENERATION outcome (complete|error) and is
    # load-bearing in the accept and promotion predicates (dal.mark_scenarios_accepted,
    # accept._promotion_candidates), so overloading it would couple a human decision to them.
    # Mutually exclusive with Accepted=1, enforced in the DATABASE by
    # CK_ScenarioOutput_DecisionExclusive — accept and reject are independent routes reachable in
    # either order, so the row itself is the one place both orderings must meet.
    RejectedAt: Mapped[datetime | None] = mapped_column(DateTime)
    RejectedBy: Mapped[str | None] = mapped_column(Unicode(200))


class Threat_Library_Import_Run(Base):
    """One row per threat-library import attempt (celery_app.import_threat_library_task), so
    "which sources imported, when, and did any fail?" survives the Celery result expiring. The
    terminal row is committed in its own transaction so a FAILED import still leaves a record."""
    __tablename__ = "Threat_Library_Import_Run"
    RunID: Mapped[str] = mapped_column(GUID, primary_key=True)
    Source: Mapped[str] = mapped_column(Unicode(100))              # API source name
    SourceTag: Mapped[str | None] = mapped_column(Unicode(100))    # provenance tag on the imported rows
    DryRun: Mapped[bool] = mapped_column(Boolean, default=False)
    Status: Mapped[str] = mapped_column(Unicode(100))              # running | success | failed
    JobID: Mapped[str | None] = mapped_column(Unicode(100))
    StartedBy: Mapped[str | None] = mapped_column(Unicode(200))
    StartedAt: Mapped[datetime | None] = mapped_column(DateTime)
    FinishedAt: Mapped[datetime | None] = mapped_column(DateTime)
    TypesImported: Mapped[int | None] = mapped_column(Integer)
    ThreatsImported: Mapped[int | None] = mapped_column(Integer)
    ActorsUpserted: Mapped[int | None] = mapped_column(Integer)
    OtRules: Mapped[int | None] = mapped_column(Integer)
    SkippedCount: Mapped[int | None] = mapped_column(Integer)
    ErrorMessage: Mapped[str | None] = mapped_column(UnicodeText)


class Threat_Scenario_Control_Map(Base):
    """Step 4: which Control_Library rows mitigate one generated scenario (control_mapping.map_controls).
    No Superseded/epoch columns — visibility follows the parent Threat_Scenario_Output row,
    same posture as Scoped_Threat. Composite PK doubles as the dedup guard."""
    __tablename__ = "Threat_Scenario_Control_Map"
    OutputID: Mapped[str] = mapped_column(GUID, primary_key=True)
    ControlLibraryID: Mapped[int] = mapped_column(Integer, primary_key=True)
    SessionID: Mapped[str] = mapped_column(GUID)
    MapRank: Mapped[int] = mapped_column(Integer)             # 1 = best match
    Score: Mapped[float | None] = mapped_column(Float)        # raw rerank 0-100
    SuggestedControl: Mapped[str | None] = mapped_column(Unicode(500))  # LLM's free-text suggestion; NULL on scenario-text fallback
    CreatedAt: Mapped[datetime | None] = mapped_column(DateTime)


class Risk_Treatment_Plan(Base):
    """One LLM-generated Risk Treatment Plan attempt for an ACCEPTED scenario
    (docs/RISK_TREATMENT_PLAN_SDD.md). At most one active (Superseded=0) row per OutputID —
    UX_TreatmentPlan_ActiveOutput is the concurrent-POST race arbiter. Deliberately OUTSIDE the
    Subsystem_Stage_State machinery: accepted scenarios live on completed sessions, where
    acquire_lock/claim_stage refuse to run, so this row's own Status column is the state.
    Regenerate = supersede + new row; rows are never reused, so no GenerationEpoch."""
    __tablename__ = "Risk_Treatment_Plan"
    PlanID: Mapped[str] = mapped_column(GUID, primary_key=True)
    SessionID: Mapped[str] = mapped_column(GUID)
    OutputID: Mapped[str] = mapped_column(GUID)               # the accepted Threat_Scenario_Output
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
    # TreatmentOutcomeReason — WHY a terminal row ended that way, so a client never parses
    # ErrorMessage. NULL on COMPLETE and on rows that failed before the column existed (read those
    # as generation_failed). Holds 5 of the enum's 6 values: 'timed_out' is projected at read time
    # by api.treatment._present_status and has no writer.
    ErrorReason: Mapped[str | None] = mapped_column(UnicodeText)

# ---------------------------------------------------------------------------
# Threat library masters (seeded; imported, promoted on accept, or curated via
# app/api/library_crud.py)
#
# All four carry the same audit quartet:
#   CreatedAt/CreatedBy — every insert path. CreatedBy holds the caller's user id, or an
#                         'auto:<source>' / 'cli:<user>' literal when there was no logged-in caller.
#   UpdatedAt/UpdatedBy — CRUD update/delete ONLY. Importer and promote-on-accept upserts leave an
#                         existing row untouched (provenance is first-writer — dal.upsert_threat_type),
#                         so a re-import never restamps a row a curator has since edited.
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
    SecurityObjective: Mapped[str | None] = mapped_column(Unicode(200))
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
    Description: Mapped[str | None] = mapped_column(UnicodeText)
    SectorID: Mapped[int | None] = mapped_column(Integer)
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


class Threat_Catalogue(Base):
    __tablename__ = "Threat_Catalogue"
    ThreatCatalogueID: Mapped[int] = mapped_column(Integer, primary_key=True)
    ThreatTypeID: Mapped[int] = mapped_column(Integer)
    ThreatName: Mapped[str] = mapped_column(Unicode(500))
    Description: Mapped[str | None] = mapped_column(UnicodeText)
    SectorID: Mapped[int | None] = mapped_column(Integer)
    IsActive: Mapped[bool] = mapped_column(Boolean, default=True)
    IsDeleted: Mapped[bool] = mapped_column(Boolean, default=False)
    # See Threat_Type.Source above — same provenance tracking, same script adds it.
    Source: Mapped[str | None] = mapped_column(Unicode(100))
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


class ThreatType_ThreatActor_Map(Base):
    __tablename__ = "ThreatType_ThreatActor_Map"
    ThreatTypeID: Mapped[int] = mapped_column(Integer, primary_key=True)
    ThreatActorID: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Nullable so the seeds' explicit column lists stay valid; the DDL defaults it.
    CreatedAt: Mapped[datetime | None] = mapped_column(DateTime)


# ---------------------------------------------------------------------------
# Control library masters (seeded from functional-team Control_Library.xlsx). Created by
# scripts/Control_library.sql (run manually — see test_schema_sync's _DEPLOYED_SEPARATELY,
# same pattern as Config_Threat_Rule). IDENTITY PKs — never inserted by app code. Same audit
# quartet as the threat masters, stamped only by app/api/control_library_crud.py.
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


# The authoritative per-threat category source (see grounding.get_possible_types):
# Threat_Type.ThreatCategoryID is only a rough default — 74 of 75 curated Threat_Catalogue rows
# carry a different/additional STRIDE category than their Type's. Created by
# scripts/Threat_library.sql (run manually — see test_schema_sync's _DEPLOYED_SEPARATELY).
class Threat_Catalogue_Category_Map(Base):
    __tablename__ = "Threat_Catalogue_Category_Map"
    ThreatCatalogueID: Mapped[int] = mapped_column(Integer, primary_key=True)
    ThreatCategoryID: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Nullable so the seeds' explicit column lists stay valid; the DDL defaults it.
    CreatedAt: Mapped[datetime | None] = mapped_column(DateTime)


class Config_Threat_Rule(Base):
    __tablename__ = "Config_Threat_Rule"
    ThreatRuleID: Mapped[int] = mapped_column(Integer, primary_key=True)
    RuleType: Mapped[str] = mapped_column(Unicode(100))       # enums.ThreatRuleType
    ThreatTypeID: Mapped[int] = mapped_column(Integer)        # app-enforced FK → Threat_Type
    # One of scoping._RULE_KEY_FIELDS — currently exactly: criticality, subsystem_name,
    # asset_type, past_incidents. This example used to read "internet_facing", a key REMOVED on
    # 2026-07-12 because gather_asset_details never produced it. An unknown key here is a silent
    # no-op (scoping._apply_rules logs and continues), so a stale example invites dead rules.
    RuleKey: Mapped[str] = mapped_column(Unicode(200))
    RuleValue: Mapped[str | None] = mapped_column(Unicode(450))                    # optional expected value
    Metadata: Mapped[str | None] = mapped_column(UnicodeText)                      # extra rule config (JSON), e.g. {"weight": 15}
    CreateDate: Mapped[datetime | None] = mapped_column(DateTime)
    CreatedBy: Mapped[str | None] = mapped_column(Unicode(200))
    UpdateDate: Mapped[datetime | None] = mapped_column(DateTime)
    UpdatedBy: Mapped[str | None] = mapped_column(Unicode(200))
    IsActive: Mapped[bool] = mapped_column(Boolean, default=True)
    IsDeleted: Mapped[bool] = mapped_column(Boolean, default=False)


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

# TSG-owned (not seeded like the masters above): one row per AI-proposed threat NAME reaching
# accept. Now genuinely a pending-review queue — accept.py writes `pending` and does NOT create a
# Threat_Catalogue row from the name, because prompts.py requires that name to embed the asset's
# own name and so it is never library-shaped. A curator generalizes it and creates the real entry.
# The queue holds BOTH kinds of admin-gated proposals: threats (name+type) and actors
# (name only) — CandidateKind tells them apart (NULL = legacy 'threat' rows).
class Threat_Candidate_Review(Base):
    __tablename__ = "Threat_Candidate_Review"
    CandidateID: Mapped[str] = mapped_column(GUID, primary_key=True)
    TenantID: Mapped[str] = mapped_column(Unicode(200))
    EntityID: Mapped[str | None] = mapped_column(Unicode(200))
    SessionID: Mapped[str] = mapped_column(GUID)
    ProposedCategory: Mapped[str | None] = mapped_column(Unicode(200))  # NULL on actor candidates
    ProposedType: Mapped[str | None] = mapped_column(Unicode(300))      # on actor candidates: the
    # threat type the actor was proposed FOR (approval's link target); NULL only on legacy rows
    ProposedName: Mapped[str] = mapped_column(Unicode(500))  # threat name, or the actor name
    # The candidate's library-shaped name — what the curator actually generalizes toward.
    # NULL on rows queued before the column existed.
    ProposedGenericName: Mapped[str | None] = mapped_column(Unicode(500))
    Status: Mapped[str] = mapped_column(Unicode(100))
    ThreatTypeID: Mapped[int | None] = mapped_column(Integer)
    ThreatCatalogueID: Mapped[int | None] = mapped_column(Integer)
    ReviewedBy: Mapped[str | None] = mapped_column(Unicode(200))
    ReviewedAt: Mapped[datetime | None] = mapped_column(DateTime)
    CreatedAt: Mapped[datetime] = mapped_column(DateTime)
    CandidateKind: Mapped[str | None] = mapped_column(Unicode(100))  # CandidateKind enum; NULL = 'threat'
    CreatedBy: Mapped[str | None] = mapped_column(Unicode(200))     # ORIGINAL proposer, never the admin

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
    # A real column rather than a DetailJSON key: IX_ScenarioAudit_Output makes "the decision
    # history of this scenario" a seek, which is the query a GRC reviewer actually runs.
    OutputID: Mapped[str | None] = mapped_column(GUID)
    Decision: Mapped[str | None] = mapped_column(Unicode(100))  # accept only — AuditDecision; NULL elsewhere
    Granularity: Mapped[str | None] = mapped_column(Unicode(100))  # regeneration_completed only
    ThreatTypeRefID: Mapped[int | None] = mapped_column(Integer)  # library_promoted +
    # candidate_reconciled (approvals: the minted/linked type)
    # WHO IS ACCOUNTABLE, not who typed the command: human actions record the authenticated
    # principal, worker rows are back-filled from Scenario_Session.UserID by dal.append_audit.
    ActorUserID: Mapped[str | None] = mapped_column(Unicode(200))
    # WHO PERFORMED it, which ActorUserID above deliberately cannot answer once worker rows are
    # back-filled with the session owner. NULL on rows predating the column — never back-filled,
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
# ref_id is polymorphic across scope levels; scope_type decodes via option_value group 1010:
# 1=Sector 2=Sub-Sector 3=Service 4=Entity 5=Asset. For entity membership we read scope_type=4,
# where ref_id = group.id = the EntityID TSG uses as its tenant key. See dal.user_has_entity.
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

