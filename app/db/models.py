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

from sqlalchemy import Boolean, DateTime, Float, Integer, MetaData, Numeric, TypeDecorator, Unicode, UnicodeText
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
# ---------------------------------------------------------------------------
class Identified_Threat(Base):
    __tablename__ = "Identified_Threat"
    ThreatID: Mapped[str] = mapped_column(GUID, primary_key=True)
    SessionID: Mapped[str] = mapped_column(GUID)
    TenantID: Mapped[str | None] = mapped_column(Unicode(200))
    EntityID: Mapped[str | None] = mapped_column(Unicode(200))
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
    SubsystemID: Mapped[int] = mapped_column(Integer)
    ScopedThreatID: Mapped[str] = mapped_column(GUID)
    Status: Mapped[str] = mapped_column(Unicode(20))
    ScenarioJSON: Mapped[str | None] = mapped_column(UnicodeText)
    ValidationJSON: Mapped[str | None] = mapped_column(UnicodeText)
    AcceptedSubsetJSON: Mapped[str | None] = mapped_column(UnicodeText)
    Accepted: Mapped[int] = mapped_column(Integer, default=0)
    Superseded: Mapped[int] = mapped_column(Integer, default=0)
    IdentityHash: Mapped[str | None] = mapped_column(Unicode(64))     #sha256(SessionID|ScopedThreatID)
    GenerationEpoch: Mapped[int] = mapped_column(Integer, default=1)
    ErrorMessage: Mapped[str | None] = mapped_column(UnicodeText)
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
    PrimaryThreatCategoryID: Mapped[int | None] = mapped_column(Integer)
    IsActive: Mapped[bool] = mapped_column(Boolean, default=True)
    IsDeleted: Mapped[bool] = mapped_column(Boolean, default=False)


class Threat_Catalogue(Base):
    __tablename__ = "Threat_Catalogue"
    ThreatCatalogueID: Mapped[int] = mapped_column(Integer, primary_key=True)
    ThreatTypeID: Mapped[int] = mapped_column(Integer)
    ThreatName: Mapped[str] = mapped_column(Unicode(500))
    Description: Mapped[str | None] = mapped_column(UnicodeText)
    SectorID: Mapped[int | None] = mapped_column(Integer)
    IsActive: Mapped[bool] = mapped_column(Boolean, default=True)
    IsDeleted: Mapped[bool] = mapped_column(Boolean, default=False)


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
    Stage: Mapped[str | None] = mapped_column(Unicode(32))
    SubsystemID: Mapped[int | None] = mapped_column(Integer)
    EventType: Mapped[str] = mapped_column(Unicode(40))
    Decision: Mapped[str | None] = mapped_column(Unicode(30))
    Granularity: Mapped[str | None] = mapped_column(Unicode(20))
    ThreatTypeRefID: Mapped[int | None] = mapped_column(Integer)
    ActorUserID: Mapped[str | None] = mapped_column(Unicode(200))
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

class group_table(Base):  # "group" is a reserved word; SQLAlchemy quotes it
    __tablename__ = "group"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    parent_id: Mapped[int | None] = mapped_column(Integer)  # self-ref FK to group.id; NULL = top-level group
    country_id: Mapped[int | None] = mapped_column(Integer)  # FK to country reference table
    name: Mapped[str] = mapped_column(Unicode(255))
    code: Mapped[str] = mapped_column(Unicode(55))
    manager_id: Mapped[int | None] = mapped_column(Integer) # FK to user.id; the group's manager (not the same as the entity's owner)
    address1: Mapped[str | None] = mapped_column(Unicode(255))
    address2: Mapped[str | None] = mapped_column(Unicode(255))
    state: Mapped[str | None] = mapped_column(Unicode(55))
    zip_code: Mapped[str | None] = mapped_column(Unicode(55))
    creation_date: Mapped[datetime | None] = mapped_column(DateTime)
    created_by: Mapped[str | None] = mapped_column(Unicode(55))
    updated_by: Mapped[str | None] = mapped_column(Unicode(5))
    date_updated: Mapped[datetime | None] = mapped_column(DateTime)
    weightage: Mapped[float | None] = mapped_column(Numeric(10, 4, asdecimal=False))
    type: Mapped[int | None] = mapped_column(Integer)  # FK to option_value.id
    org_business_line: Mapped[str | None] = mapped_column(Unicode(10))
    org_type: Mapped[str | None] = mapped_column(Unicode(10))
    isAssessmentAllowed: Mapped[bool | None] = mapped_column(Boolean)
    scoring_methodology: Mapped[str | None] = mapped_column(Unicode(10))
    sequence: Mapped[int | None] = mapped_column(Integer)
    status_id: Mapped[int | None] = mapped_column(Integer)  # FK to option_value.id
    priority_id: Mapped[int | None] = mapped_column(Integer)  # FK to option_value.id
    nature_of_involvement_id: Mapped[int | None] = mapped_column(Integer)  # FK to option_value.id
    cascading_impact_id: Mapped[int | None] = mapped_column(Integer)  # FK to option_value.id
    role_summary: Mapped[str | None] = mapped_column(Unicode(500))
    candidate_justification: Mapped[str | None] = mapped_column(UnicodeText)
    impact_on_tier1_services: Mapped[str | None] = mapped_column(UnicodeText)
    is_non_substitutable: Mapped[bool | None] = mapped_column(Boolean)
    recovery_coordination_role: Mapped[str | None] = mapped_column(Unicode(500))
    key_dependencies: Mapped[str | None] = mapped_column(UnicodeText)
    remarks: Mapped[str | None] = mapped_column(UnicodeText)

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
    # system_managed_by: Mapped[str | None] = mapped_column(Unicode(100))  # confirmed live: nvarchar(100), nullable, no FK — asset-level free text


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
    technology_used: Mapped[str | None] = mapped_column(UnicodeText)    
    url: Mapped[str | None] = mapped_column(Unicode(500))
    vendor_name: Mapped[str | None] = mapped_column(Unicode(200))
    database_platforms: Mapped[str | None] = mapped_column(Unicode(300))
    incident_description: Mapped[str | None] = mapped_column(UnicodeText)
    system_managed_by: Mapped[str | None] = mapped_column(Unicode(100))

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

