"""SQLAlchemy 2.0 typed ORM table definitions — database-first mirror of the existing
`EYShield DB`. These are NOT used to create tables; they
describe the real columns so we can query/bind against them. Types are portable
(Unicode→NVARCHAR on MSSQL, TEXT on SQLite; GUID→UNIQUEIDENTIFIER on MSSQL,
Unicode(36) on SQLite) so pure-logic unit tests can run on SQLite while
integration runs on MSSQL.

Columns reflect the baseline schema **plus the slice migrations** applied in M1
(match-by-id cols), NOT NULL keys),  (lease cols),  (AttemptCount,
IdempotencyKey). Columns from later migrations are added with their milestone.

Declarative `Mapped[T]`/`mapped_column()` style (not plain Core `Table()`) so every
`m.Table.Column` access is statically typed — `m.Table.Column` replaces the old
`m.Table.c.Column`; call sites drop the `.c` accessor. Each class's `__table__` is
still a plain Core `Table` (accessible via `.__table__`) for the handful of call
sites that need a whole-row Core-style select (`select(m.Table.__table__)`) instead
of an ORM entity load — see dal.py's `load_session`/`get_session`/`latest_completed_session`.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, MetaData, TypeDecorator, Unicode, UnicodeText
from sqlalchemy.dialects import mssql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

metadata = MetaData()


class Base(DeclarativeBase):
    metadata = metadata


class GUID(TypeDecorator):
    impl = Unicode(36)
    cache_ok = True

    def load_dialect_impl(self, dialect):
        """Pick the real database column type for a GUID: MSSQL's native
        UNIQUEIDENTIFIER type, or a plain 36-character string on any other
        database (e.g. SQLite)."""
        if dialect.name == "mssql":
            return dialect.type_descriptor(mssql.UNIQUEIDENTIFIER())
        return dialect.type_descriptor(Unicode(36))

    def bind_processor(self, dialect):
        """Return a function that converts a Python value into the string form
        to send to the database when writing a GUID column."""
        def process(value):
            if value is None:
                return None
            if isinstance(value, uuid.UUID):
                return str(value)
            # Value isn't already a UUID object (e.g. it's a plain string) —
            # round-trip it through uuid.UUID() to validate and normalize its
            # format before storing it as a string.
            return str(uuid.UUID(str(value)))
        return process

    def result_processor(self, dialect, coltype):
        """Return a function that converts a raw value read back from the
        database into the string form the rest of the app expects for a GUID
        column."""
        def process(value):
            if value is None:
                return None
            if isinstance(value, uuid.UUID):
                return str(value)
            # Normalize whatever the driver returned (e.g. a raw string) into
            # a canonical UUID string.
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
    SessionStatus: Mapped[str] = mapped_column(Unicode(20))
    CurrentStage: Mapped[str] = mapped_column(Unicode(32))
    StageStatus: Mapped[str] = mapped_column(Unicode(20))
    Mode: Mapped[str] = mapped_column(Unicode(20))
    CurrentSubsystemIndex: Mapped[int | None] = mapped_column(Integer)
    SubsystemsJSON: Mapped[str] = mapped_column(UnicodeText)
    IdempotencyKey: Mapped[str | None] = mapped_column(Unicode(200))
    SectorIDsJSON: Mapped[str | None] = mapped_column(UnicodeText)
    AssetContextJSON: Mapped[str | None] = mapped_column(UnicodeText)
    CreatedAt: Mapped[datetime | None] = mapped_column(DateTime)
    UpdatedAt: Mapped[datetime | None] = mapped_column(DateTime)
    CompletedAt: Mapped[datetime | None] = mapped_column(DateTime)


class Subsystem_Stage_State(Base):
    __tablename__ = "Subsystem_Stage_State"
    StateID: Mapped[str] = mapped_column(GUID, primary_key=True)
    SessionID: Mapped[str] = mapped_column(GUID)
    TenantID: Mapped[str | None] = mapped_column(Unicode(200))
    EntityID: Mapped[str | None] = mapped_column(Unicode(200))
    SubsystemID: Mapped[int] = mapped_column(Integer)
    Level: Mapped[str] = mapped_column(Unicode(20))
    Status: Mapped[str] = mapped_column(Unicode(20))
    GenerationEpoch: Mapped[int] = mapped_column(Integer)
    ActiveTaskID: Mapped[str | None] = mapped_column(GUID)
    LeaseExpiresAt: Mapped[datetime | None] = mapped_column(DateTime)
    HeartbeatAt: Mapped[datetime | None] = mapped_column(DateTime)
    AttemptCount: Mapped[int] = mapped_column(Integer, default=0)
    ErrorMessage: Mapped[str | None] = mapped_column(UnicodeText)
    UpdatedAt: Mapped[datetime] = mapped_column(DateTime)

# ---------------------------------------------------------------------------
# Pipeline outputs (entity resolved via the session; carry TenantID+SubsystemID)
#
# `UserID` on all three tables below is PROVENANCE, inherited from Scenario_Session.UserID — it
# is the accountable session owner, NEVER the author. Every row here is produced by a background
# worker from LLM output; no human writes one. That is why they take no ActorType companion the
# way Scenario_Audit does: the column would read 'system' on 100% of rows and carry no
# information. Scenario_Audit needs it precisely because it is the ONE table where human-written
# and worker-written rows share a column.
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
    ThreatActorsJSON: Mapped[str | None] = mapped_column(UnicodeText)
    LibraryThreatType: Mapped[str | None] = mapped_column(Unicode(300))
    LibraryThreatName: Mapped[str | None] = mapped_column(Unicode(500))
    ThreatTypeID: Mapped[int | None] = mapped_column(Integer)
    ThreatCatalogueID: Mapped[int | None] = mapped_column(Integer)
    GroundingStatus: Mapped[str] = mapped_column(Unicode(20))
    GroundingScore: Mapped[float | None] = mapped_column(Float)
    Superseded: Mapped[int] = mapped_column(Integer, default=0)
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
    FactorsJSON: Mapped[str | None] = mapped_column(UnicodeText)
    Superseded: Mapped[int] = mapped_column(Integer, default=0)
    CreatedAt: Mapped[datetime | None] = mapped_column(DateTime)


class Threat_Scenario_Output(Base):
    __tablename__ = "Threat_Scenario_Output"
    OutputID: Mapped[str] = mapped_column(GUID, primary_key=True)
    SessionID: Mapped[str] = mapped_column(GUID)
    TenantID: Mapped[str | None] = mapped_column(Unicode(200))
    EntityID: Mapped[str | None] = mapped_column(Unicode(200))
    UserID: Mapped[str | None] = mapped_column(Unicode(200))
    SubsystemID: Mapped[int] = mapped_column(Integer)
    ScopedThreatID: Mapped[str] = mapped_column(GUID)
    Status: Mapped[str] = mapped_column(Unicode(20))
    ScenarioJSON: Mapped[str | None] = mapped_column(UnicodeText)
    ValidationJSON: Mapped[str | None] = mapped_column(UnicodeText)
    AcceptedSubsetJSON: Mapped[str | None] = mapped_column(UnicodeText)
    Accepted: Mapped[int] = mapped_column(Integer, default=0)
    Superseded: Mapped[int] = mapped_column(Integer, default=0)
    IdentityHash: Mapped[str | None] = mapped_column(Unicode(64))     #sha256(SessionID|SubsystemID|dedup_key) — dedup_key = cat:/type:/txt: (tasks._dedup_key); UX_Scenario_ActiveIdentity blocks a 2nd active row per key
    GenerationEpoch: Mapped[int] = mapped_column(Integer, default=1)
    ErrorMessage: Mapped[str | None] = mapped_column(UnicodeText)
    CreatedAt: Mapped[datetime | None] = mapped_column(DateTime)
    # Step-4 attempt stamp (control_mapping.map_controls): NULL = mapping not yet attempted for
    # this output; set on every attempt EVEN when zero controls matched, so an output is never
    # re-scanned/re-reranked on later runs. Regen mints a new OutputID (stamp NULL) naturally.
    ControlsMappedAt: Mapped[datetime | None] = mapped_column(DateTime)


class Threat_Library_Import_Run(Base):
    """One row per threat-library import attempt (celery_app.import_threat_library_task).

    Exists so "which sources are imported, when, and did any fail?" survives the Celery
    result expiring — the inventory API (GET /v1/tsg/threat-library/sources) joins the
    latest run per source onto the row counts. The terminal row is committed in its own
    transaction so a FAILED import still leaves a record."""
    __tablename__ = "Threat_Library_Import_Run"
    RunID: Mapped[str] = mapped_column(GUID, primary_key=True)
    Source: Mapped[str] = mapped_column(Unicode(50))              # API source name
    SourceTag: Mapped[str | None] = mapped_column(Unicode(50))    # provenance tag on the imported rows
    DryRun: Mapped[bool] = mapped_column(Boolean, default=False)
    Status: Mapped[str] = mapped_column(Unicode(20))              # running | success | failed
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

# ---------------------------------------------------------------------------
# Threat library masters (seeded; read now, promote later)
# ---------------------------------------------------------------------------
class Threat_Category(Base):
    __tablename__ = "Threat_Category"
    ThreatCategoryID: Mapped[int] = mapped_column(Integer, primary_key=True)
    ThreatCategoryName: Mapped[str] = mapped_column(Unicode(200))
    ThreatCategoryCode: Mapped[str | None] = mapped_column(Unicode(20))
    SecurityObjective: Mapped[str | None] = mapped_column(Unicode(200))
    IsActive: Mapped[bool] = mapped_column(Boolean, default=True)
    IsDeleted: Mapped[bool] = mapped_column(Boolean, default=False)


class Threat_Type(Base):
    __tablename__ = "Threat_Type"
    ThreatTypeID: Mapped[int] = mapped_column(Integer, primary_key=True)
    ThreatTypeName: Mapped[str] = mapped_column(Unicode(300))
    Description: Mapped[str | None] = mapped_column(UnicodeText)
    SectorID: Mapped[int | None] = mapped_column(Integer)
    ThreatCategoryID: Mapped[int | None] = mapped_column(Integer)
    IsActive: Mapped[bool] = mapped_column(Boolean, default=True)
    IsDeleted: Mapped[bool] = mapped_column(Boolean, default=False)
    # Provenance: 'functional_team_excel' (curated) vs 'ai_auto_promoted' (R10) vs a future
    # MITRE import. Column added by scripts/Threat_library.sql, not the
    # CREATE TABLE this table otherwise gets — see test_schema_sync's _COLUMN_DEPLOYED_SEPARATELY.
    Source: Mapped[str | None] = mapped_column(Unicode(50))


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
    Source: Mapped[str | None] = mapped_column(Unicode(50))


class Threat_Actor(Base):
    __tablename__ = "Threat_Actor"
    ThreatActorID: Mapped[int] = mapped_column(Integer, primary_key=True)
    ThreatActorName: Mapped[str] = mapped_column(Unicode(200))
    IsCapable: Mapped[int] = mapped_column(Integer, default=1)
    IsActive: Mapped[bool] = mapped_column(Boolean, default=True)
    IsDeleted: Mapped[bool] = mapped_column(Boolean, default=False)


class ThreatType_ThreatActor_Map(Base):
    __tablename__ = "ThreatType_ThreatActor_Map"
    ThreatTypeID: Mapped[int] = mapped_column(Integer, primary_key=True)
    ThreatActorID: Mapped[int] = mapped_column(Integer, primary_key=True)


# ---------------------------------------------------------------------------
# Control library masters (seeded from functional-team Control_Library.xlsx).
# Created by scripts/Control_library.sql (run manually — see test_schema_sync's
# _DEPLOYED_SEPARATELY, same pattern as Config_Threat_Rule). Read-only to the app:
# grounding.ground_control retrieves candidates; sessions.py joins standards into
# the results payload. IDENTITY PKs — never inserted by app code.
# ---------------------------------------------------------------------------
class Control_Standard(Base):
    __tablename__ = "Control_Standard"
    StandardID: Mapped[int] = mapped_column(Integer, primary_key=True)
    StandardName: Mapped[str] = mapped_column(Unicode(200))
    CreateDate: Mapped[datetime | None] = mapped_column(DateTime)
    CreatedBy: Mapped[str | None] = mapped_column(Unicode(55))
    UpdateDate: Mapped[datetime | None] = mapped_column(DateTime)
    UpdatedBy: Mapped[str | None] = mapped_column(Unicode(55))
    IsActive: Mapped[bool] = mapped_column(Boolean, default=True)
    IsDeleted: Mapped[bool] = mapped_column(Boolean, default=False)


class Control_Library(Base):
    __tablename__ = "Control_Library"
    ControlLibraryID: Mapped[int] = mapped_column(Integer, primary_key=True)
    ControlCode: Mapped[str] = mapped_column(Unicode(20))     # 'CII-CID-001'..'CII-CID-1288', unique
    ITOT: Mapped[str] = mapped_column(Unicode(10))            # 'IT' | 'OT' — grounding's tolerant asset_type pre-filter
    Domain: Mapped[str] = mapped_column(Unicode(200))         # un-normalized vocabulary (96 distinct values) — report as-is, never join on it
    ControlName: Mapped[str] = mapped_column(Unicode(500))
    ControlDescription: Mapped[str] = mapped_column(UnicodeText)
    SampleEvidence: Mapped[str | None] = mapped_column(UnicodeText)
    CreateDate: Mapped[datetime | None] = mapped_column(DateTime)
    CreatedBy: Mapped[str | None] = mapped_column(Unicode(55))
    UpdateDate: Mapped[datetime | None] = mapped_column(DateTime)
    UpdatedBy: Mapped[str | None] = mapped_column(Unicode(55))
    IsActive: Mapped[bool] = mapped_column(Boolean, default=True)
    IsDeleted: Mapped[bool] = mapped_column(Boolean, default=False)


class Control_Library_Standard_Map(Base):
    __tablename__ = "Control_Library_Standard_Map"
    ControlLibraryID: Mapped[int] = mapped_column(Integer, primary_key=True)
    StandardID: Mapped[int] = mapped_column(Integer, primary_key=True)


# [A2] Threat_Type.ThreatCategoryID is only a rough single default — real curated data
# (75-threat functional-team Excel review) shows 74/75 individual Threat_Catalogue rows
# carry a DIFFERENT/additional STRIDE category than their Type's default. This many-to-many
# map is the authoritative per-threat category source; see grounding.get_possible_types.
# Created by scripts/Threat_library.sql (run manually — see test_schema_sync's
# _DEPLOYED_SEPARATELY, same pattern as Config_Threat_Rule).
class Threat_Catalogue_Category_Map(Base):
    __tablename__ = "Threat_Catalogue_Category_Map"
    ThreatCatalogueID: Mapped[int] = mapped_column(Integer, primary_key=True)
    ThreatCategoryID: Mapped[int] = mapped_column(Integer, primary_key=True)


class Config_Threat_Rule(Base):
    __tablename__ = "Config_Threat_Rule"
    ThreatRuleID: Mapped[int] = mapped_column(Integer, primary_key=True)
    RuleType: Mapped[str] = mapped_column(Unicode(50))       # enums.ThreatRuleType
    ThreatTypeID: Mapped[int] = mapped_column(Integer)        # app-enforced FK → Threat_Type
    RuleKey: Mapped[str] = mapped_column(Unicode(200))        # e.g. "internet_facing" — scoping._RULE_KEY_FIELDS allowlist
    RuleValue: Mapped[str | None] = mapped_column(Unicode(450))                    # optional expected value
    Metadata: Mapped[str | None] = mapped_column(UnicodeText)                      # extra rule config (JSON), e.g. {"weight": 15}
    CreateDate: Mapped[datetime | None] = mapped_column(DateTime)
    CreatedBy: Mapped[str | None] = mapped_column(Unicode(200))
    UpdateDate: Mapped[datetime | None] = mapped_column(DateTime)
    UpdatedBy: Mapped[str | None] = mapped_column(Unicode(200))
    IsActive: Mapped[bool] = mapped_column(Boolean, default=True)
    IsDeleted: Mapped[bool] = mapped_column(Boolean, default=False)


class Context_Field_Config(Base):
    """Which asset/subsystem fields are currently turned on for the AI prompt (see
    scripts/Threat_library.sql). This table can only narrow prompts.py's hardcoded
    _ASSET_CONTEXT_ALLOWED/_SUB_ALLOWED ceiling — it can never add a field name outside it."""
    __tablename__ = "Context_Field_Config"
    ContextFieldConfigID: Mapped[int] = mapped_column(Integer, primary_key=True)
    ContextGroup: Mapped[str] = mapped_column(Unicode(20))    # 'asset' | 'subsystem'
    FieldName: Mapped[str] = mapped_column(Unicode(100))
    IsActive: Mapped[bool] = mapped_column(Boolean, default=True)
    IsDeleted: Mapped[bool] = mapped_column(Boolean, default=False)

# TSG-owned (not seeded like the masters above): one row per threat promoted
# into the library on accept. An audit ledger of promotion
# events, not a pending-review queue
class Threat_Candidate_Review(Base):
    __tablename__ = "Threat_Candidate_Review"
    CandidateID: Mapped[str] = mapped_column(GUID, primary_key=True)
    TenantID: Mapped[str] = mapped_column(Unicode(200))
    EntityID: Mapped[str | None] = mapped_column(Unicode(200))
    SessionID: Mapped[str] = mapped_column(GUID)
    ProposedCategory: Mapped[str] = mapped_column(Unicode(200))
    ProposedType: Mapped[str] = mapped_column(Unicode(300))
    ProposedName: Mapped[str] = mapped_column(Unicode(500))
    Status: Mapped[str] = mapped_column(Unicode(20))
    ThreatTypeID: Mapped[int | None] = mapped_column(Integer)
    ThreatCatalogueID: Mapped[int | None] = mapped_column(Integer)
    ReviewedBy: Mapped[str | None] = mapped_column(Unicode(200))
    ReviewedAt: Mapped[datetime | None] = mapped_column(DateTime)
    CreatedAt: Mapped[datetime] = mapped_column(DateTime)

# One row per LLM call (the exact prompt + raw response, success or
# failure). The dev/ops diagnostic record for parse failures: raw model output is
# NEVER put in ErrorMessage/audit/SSE (client-visible), only here (internal DB).
class Prompt_Log(Base):
    __tablename__ = "Prompt_Log"
    LogID: Mapped[str] = mapped_column(GUID, primary_key=True)
    SessionID: Mapped[str] = mapped_column(GUID)
    TenantID: Mapped[str | None] = mapped_column(Unicode(200))
    EntityID: Mapped[str | None] = mapped_column(Unicode(200))
    # Provenance, same as the pipeline-output tables above: the accountable session owner, never
    # the author — a row exists only because a worker called an LLM. No ActorType needed.
    UserID: Mapped[str | None] = mapped_column(Unicode(200))
    SubsystemID: Mapped[int] = mapped_column(Integer)
    Stage: Mapped[str] = mapped_column(Unicode(20))           # 'threats' | 'scenario'
    PromptVersion: Mapped[str] = mapped_column(Unicode(20))
    Messages: Mapped[str] = mapped_column(UnicodeText)        # exact prompt sent (already redacted/allowlisted)
    ResponseText: Mapped[str | None] = mapped_column(UnicodeText)                    # raw LLM reply, including malformed ones
    Model: Mapped[str | None] = mapped_column(Unicode(200))
    ModelVersion: Mapped[str | None] = mapped_column(Unicode(100))
    ParseSucceeded: Mapped[bool] = mapped_column(Boolean)
    CreatedAt: Mapped[datetime] = mapped_column(DateTime)

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
    Stage: Mapped[str | None] = mapped_column(Unicode(32))
    # NOT a plain foreign key — read the values before treating one as a broken reference:
    #   0    = THE ASSET ITSELF (tasks.ASSET_UNIT_ID). This pipeline is asset-centric: supporting
    #          systems are context inside ONE analysis, never separate units of work, so almost
    #          every worker-written row carries 0. Real supporting-system ids are DB keys >= 1,
    #          so 0 can never collide with one.
    #   NULL = genuinely session-wide, belonging to no unit of work (session_started,
    #          entered_review, session_cancelled, and the accept-family rows).
    #   >= 1 = a specific supporting system. Not produced by the current asset-centric pipeline;
    #          retained because historical rows may hold it.
    SubsystemID: Mapped[int | None] = mapped_column(Integer)
    EventType: Mapped[str] = mapped_column(Unicode(40))
    # accept only — AuditDecision accept/reject/partial. NULL on every other event: nothing else
    # represents a human decision.
    Decision: Mapped[str | None] = mapped_column(Unicode(30))
    Granularity: Mapped[str | None] = mapped_column(Unicode(20))  # regeneration_completed only
    ThreatTypeRefID: Mapped[int | None] = mapped_column(Integer)  # library_promoted only
    # WHO IS ACCOUNTABLE for this session — not "who typed the command". Human actions
    # (session_started/cancel/accept) record the authenticated principal; worker-written rows are
    # back-filled from Scenario_Session.UserID by dal.append_audit, so an auditor never has to
    # join to answer "who is answerable for this event".
    ActorUserID: Mapped[str | None] = mapped_column(Unicode(200))
    # WHO PERFORMED the event, which ActorUserID above deliberately does NOT answer. Because
    # worker rows are back-filled with the session owner, `ActorUserID = gopal` alone cannot
    # distinguish "gopal clicked accept" from "the pipeline ran and gopal is answerable for it".
    # enums.ActorType: user = a human did it; system = a worker did it. NULL only on rows written
    # before migration 0028 — never back-filled, because rewriting an append-only ledger would
    # falsify records that were true when written.
    ActorType: Mapped[str | None] = mapped_column(Unicode(20))
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

class onboarding_sectors(Base):
    __tablename__ = "onboarding_sectors"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str | None] = mapped_column(Unicode(300))
    sector_code: Mapped[str | None] = mapped_column(Unicode(100))
    parent_id: Mapped[int | None] = mapped_column(Integer)
    definition: Mapped[str | None] = mapped_column(UnicodeText)

# saving the asset
class ctm_scan_entity(Base):
    __tablename__ = "ctm_scan_entity"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[str | None] = mapped_column(Unicode(200))
    name: Mapped[str | None] = mapped_column(Unicode(300))
    ctm_category_id: Mapped[int | None] = mapped_column(Integer) # FK to ctm_scan_category.id
    description: Mapped[str | None] = mapped_column(UnicodeText)
    criticality: Mapped[int | None] = mapped_column(Integer)
    operating_system: Mapped[str | None] = mapped_column(Unicode(200))
    location: Mapped[str | None] = mapped_column(Unicode(200))
    owner_custodian: Mapped[str | None] = mapped_column(Unicode(200))
    target_rto_hours: Mapped[int | None] = mapped_column(Integer)
    target_rpo_hours: Mapped[int | None] = mapped_column(Integer)
    tier1_critical_service_id: Mapped[int | None] = mapped_column(Integer)
    data_handled: Mapped[str | None] = mapped_column(UnicodeText)  # types of data this asset processes/stores


# The real, direct asset->entity link (per CII Onboarding DDD) — one row per asset per
# owning business unit, so an asset can have more than one row. tier1_critical_service_id
# above is NOT the ownership path: it's no longer populated on any current asset, and even
# when it was, onboarding_service_entity below was only ever a service->entity mapping, one
# indirection removed from the asset itself.
class ctm_scan_entity_bu(Base):
    __tablename__ = "ctm_scan_entity_bu"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ctm_scan_entity_id: Mapped[int] = mapped_column(Integer)  # FK to ctm_scan_entity.id
    group_id: Mapped[int] = mapped_column(Integer)  # FK to group.id — the owning entity
    service_id: Mapped[int | None] = mapped_column(Integer)  # FK to onboarding_services.id — an asset can link to more than one


class onboarding_service_entity(Base):  # maps a service to its owning entity/group
    __tablename__ = "onboarding_service_entity"
    sector_id: Mapped[int] = mapped_column(Integer, primary_key=True) # FK to onboarding_sectors.id
    service_id: Mapped[int] = mapped_column(Integer, primary_key=True) # FK to onboarding_services.id
    group_id: Mapped[int] = mapped_column(Integer, primary_key=True) # FK to group.id

# asset and onboarding_supporting_systems junction table (many-to-many). The "supporting system" is a platform-owned
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
    accessability_channel: Mapped[int | None] = mapped_column(Integer)  # single option_value code (option code 'acc-channel')
    technology_used: Mapped[str | None] = mapped_column(UnicodeText)
    user_base_count: Mapped[int | None] = mapped_column(Integer)
    url: Mapped[str | None] = mapped_column(Unicode(500))
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
    targeted_users: Mapped[str | None] = mapped_column(UnicodeText)  # JSON array of option_value codes, e.g. "[6]" — see option/option_value
    managed_by: Mapped[int | None] = mapped_column(Integer)  # single option_value code (option code 'managed-by'), not free text
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)  # soft-delete flag — real queries filter WHERE is_deleted = 0

# Read-only platform mirrors used by gather_asset_details (app/pipeline/context.py)
# to resolve every session-creation context field authoritatively from the real DB.
class onboarding_services(Base):
    __tablename__ = "onboarding_services"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str | None] = mapped_column(Unicode(255))
    description: Mapped[str | None] = mapped_column(UnicodeText)
    sector_id: Mapped[int | None] = mapped_column(Integer)  # FK to onboarding_sectors.id


# "option" is a plain word but shares a name pattern with option_value below — the curator's
# named option GROUP (e.g. "Accessibility Channel", id 1012; "Hosting Environment", id 1015).
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

# asset_type FK target — 7 curator-seeded rows (real ids 1-6, 1004); onboarding_supporting_systems.asset_type
# -> ctm_scan_category.id via FK_OnboardingSupportingSystem_CTMScanCategory (confirmed live).
class ctm_scan_category(Base):
    __tablename__ = "ctm_scan_category"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    parent_id: Mapped[int | None] = mapped_column(Integer)
    code: Mapped[str | None] = mapped_column(Unicode(100))
    name: Mapped[str | None] = mapped_column(Unicode(255))

