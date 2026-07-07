"""SQLAlchemy Core table definitions — database-first mirror of the existing
`EYShield DB`. These are NOT used to create tables; they
describe the real columns so we can query/bind against them. Types are portable
(Unicode→NVARCHAR on MSSQL, TEXT on SQLite) so pure-logic unit tests can run on
SQLite while integration runs on MSSQL.

Columns reflect the baseline schema **plus the slice migrations** applied in M1
(match-by-id cols), M3 (NOT NULL keys), M7 (lease cols), M8 (AttemptCount,
IdempotencyKey). Columns from later migrations are added with their milestone.
"""
from __future__ import annotations

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    MetaData,
    Table,
    Unicode,
    UnicodeText,
)

metadata = MetaData()

GUID = Unicode(36)

# ---------------------------------------------------------------------------
# Session & state
# ---------------------------------------------------------------------------
Scenario_Session = Table(
    "Scenario_Session", metadata,
    Column("SessionID", GUID, primary_key=True),
    Column("TenantID", Unicode(200), nullable=False),
    Column("EntityID", Unicode(200), nullable=False),         # M3 [R7]
    Column("UserID", Unicode(200)),
    Column("AssetName", Unicode(300), nullable=False),
    Column("AssetExternalID", Unicode(200), nullable=False),  # M3 [R7]
    Column("SessionStatus", Unicode(20), nullable=False),
    Column("CurrentStage", Unicode(32), nullable=False),
    Column("StageStatus", Unicode(20), nullable=False),
    Column("Mode", Unicode(20), nullable=False),
    Column("CurrentSubsystemIndex", Integer),
    Column("SubsystemsJSON", UnicodeText, nullable=False),
    Column("ActiveTaskID", GUID),
    Column("ErrorMessage", UnicodeText),
    Column("IdempotencyKey", Unicode(200)),  # M8 — dedup key for POST /v1/sessions
    Column("SectorIDsJSON", UnicodeText),  # R6 — [sector_id, parent_sector_id] from gather_asset_details; NULL = [] (global-only masters)
    Column("CreatedAt", DateTime),
    Column("UpdatedAt", DateTime),
    Column("CompletedAt", DateTime),
)

Subsystem_Stage_State = Table(
    "Subsystem_Stage_State", metadata,
    Column("StateID", GUID, primary_key=True),
    Column("SessionID", GUID, nullable=False),
    Column("TenantID", Unicode(200)),
    Column("EntityID", Unicode(200)),
    Column("SubsystemID", Integer, nullable=False),
    Column("Level", Unicode(20), nullable=False),
    Column("Status", Unicode(20), nullable=False),
    Column("GenerationEpoch", Integer, nullable=False),
    Column("ActiveTaskID", GUID),
    Column("LeaseExpiresAt", DateTime),   
    Column("HeartbeatAt", DateTime),      
    Column("AttemptCount", Integer, nullable=False, default=0), 
    Column("ErrorMessage", UnicodeText),
    Column("UpdatedAt", DateTime, nullable=False),
)

# ---------------------------------------------------------------------------
# Pipeline outputs (entity resolved via the session; carry TenantID+SubsystemID)
# ---------------------------------------------------------------------------
Subsystem_Profile = Table(
    "Subsystem_Profile", metadata,
    Column("ProfileID", GUID, primary_key=True),
    Column("SessionID", GUID, nullable=False),
    Column("TenantID", Unicode(200)),
    Column("EntityID", Unicode(200)),
    Column("SubsystemID", Integer, nullable=False),
    Column("ProfileJSON", UnicodeText, nullable=False),
    Column("ValidationJSON", UnicodeText),  #  deterministic structural/consistency result
    Column("Accepted", Integer, nullable=False, default=0),
    Column("Superseded", Integer, nullable=False, default=0),
    Column("CreatedAt", DateTime),
)

Identified_Threat = Table(
    "Identified_Threat", metadata,
    Column("ThreatID", GUID, primary_key=True),
    Column("SessionID", GUID, nullable=False),
    Column("TenantID", Unicode(200)),
    Column("EntityID", Unicode(200)),
    Column("SubsystemID", Integer, nullable=False),
    Column("ThreatCategory", Unicode(200), nullable=False),
    Column("ThreatType", Unicode(300), nullable=False),
    Column("ThreatName", Unicode(500)),
    Column("ThreatActorsJSON", UnicodeText),
    Column("LibraryThreatType", Unicode(300)),
    Column("LibraryThreatName", Unicode(500)),
    Column("ThreatTypeID", Integer),        
    Column("ThreatCatalogueID", Integer),    
    Column("GroundingStatus", Unicode(20), nullable=False),
    Column("GroundingScore", Float),
    Column("Superseded", Integer, nullable=False, default=0),
    Column("CreatedAt", DateTime),
)

Scoped_Threat = Table(
    "Scoped_Threat", metadata,
    Column("ScopedThreatID", GUID, primary_key=True),
    Column("SessionID", GUID, nullable=False),
    Column("TenantID", Unicode(200)),
    Column("SubsystemID", Integer, nullable=False),
    Column("ThreatID", GUID, nullable=False),
    Column("Score", Float, nullable=False),
    Column("ScopeRank", Integer, nullable=False),
    Column("Selected", Integer, nullable=False, default=0),
    Column("Reason", Unicode(500)),
    Column("FactorsJSON", UnicodeText),
    Column("Superseded", Integer, nullable=False, default=0),
    Column("CreatedAt", DateTime),
)

Threat_Scenario_Output = Table(
    "Threat_Scenario_Output", metadata,
    Column("OutputID", GUID, primary_key=True),
    Column("SessionID", GUID, nullable=False),
    Column("TenantID", Unicode(200)),
    Column("EntityID", Unicode(200)),
    Column("SubsystemID", Integer, nullable=False),
    Column("ScopedThreatID", GUID, nullable=False),
    Column("Status", Unicode(20), nullable=False),
    Column("ScenarioJSON", UnicodeText),
    Column("ValidationJSON", UnicodeText),
    Column("AcceptedSubsetJSON", UnicodeText),
    Column("Accepted", Integer, nullable=False, default=0),
    Column("Superseded", Integer, nullable=False, default=0),
    Column("IdentityHash", Unicode(64)),     #sha256(SessionID|ScopedThreatID)
    Column("GenerationEpoch", Integer, nullable=False, default=1),
    Column("ErrorMessage", UnicodeText),
    Column("CreatedAt", DateTime),
)

# ---------------------------------------------------------------------------
# Threat library masters (seeded; read now, promote later)
# ---------------------------------------------------------------------------
Threat_Category = Table(
    "Threat_Category", metadata,
    Column("ThreatCategoryID", Integer, primary_key=True),
    Column("ThreatCategoryName", Unicode(200), nullable=False),
    Column("ThreatCategoryCode", Unicode(20)),
    Column("SecurityObjective", Unicode(200)),
    Column("IsActive", Boolean, nullable=False, default=True),
    Column("IsDeleted", Boolean, nullable=False, default=False),
)

Threat_Type = Table(
    "Threat_Type", metadata,
    Column("ThreatTypeID", Integer, primary_key=True),
    Column("ThreatTypeName", Unicode(300), nullable=False),
    Column("Description", UnicodeText),
    Column("SectorID", Integer),
    Column("PrimaryThreatCategoryID", Integer),
    Column("IsActive", Boolean, nullable=False, default=True),
    Column("IsDeleted", Boolean, nullable=False, default=False),
)

Threat_Catalogue = Table(
    "Threat_Catalogue", metadata,
    Column("ThreatCatalogueID", Integer, primary_key=True),
    Column("ThreatTypeID", Integer, nullable=False),
    Column("ThreatName", Unicode(500), nullable=False),
    Column("Description", UnicodeText),
    Column("SectorID", Integer),
    Column("IsActive", Boolean, nullable=False, default=True),
    Column("IsDeleted", Boolean, nullable=False, default=False),
)

Threat_Actor = Table(
    "Threat_Actor", metadata,
    Column("ThreatActorID", Integer, primary_key=True),
    Column("ThreatActorName", Unicode(200), nullable=False),
    Column("IsCapable", Integer, nullable=False, default=1),
    Column("IsActive", Boolean, nullable=False, default=True),
    Column("IsDeleted", Boolean, nullable=False, default=False),
)

ThreatType_ThreatActor_Map = Table(
    "ThreatType_ThreatActor_Map", metadata,
    Column("ThreatTypeID", Integer, primary_key=True),
    Column("ThreatActorID", Integer, primary_key=True),
)

# [R12] Scoping rules (SDD §5.4 / Appendix A.1) — curator-seeded config, read-only to the
# app (like the masters above; plain int PK, the app never inserts rules). One rule per
# (RuleType, ThreatTypeID, RuleKey): tech_gate = hard include/exclude, relevance_* = score
# weights. Consumed by scoping.score_threats via dal.active_threat_rules.
Config_Threat_Rule = Table(
    "Config_Threat_Rule", metadata,
    Column("ThreatRuleID", Integer, primary_key=True),
    Column("RuleType", Unicode(50), nullable=False),      # enums.ThreatRuleType
    Column("ThreatTypeID", Integer, nullable=False),      # app-enforced FK → Threat_Type
    Column("RuleKey", Unicode(200), nullable=False),      # e.g. "internet_facing" — scoping._RULE_KEY_FIELDS allowlist
    Column("RuleValue", Unicode(450)),                    # optional expected value
    Column("Metadata", UnicodeText),                      # extra rule config (JSON), e.g. {"weight": 15}
    Column("CreateDate", DateTime),
    Column("CreatedBy", Unicode(200)),
    Column("UpdateDate", DateTime),
    Column("UpdatedBy", Unicode(200)),
    Column("IsActive", Boolean, nullable=False, default=True),
    Column("IsDeleted", Boolean, nullable=False, default=False),
)

# M9 — TSG-owned (not seeded like the masters above): one row per threat promoted
# into the library on accept. An audit ledger of promotion
# events, not a pending-review queue — see
# migrations/versions/0014_m9_threat_candidate_review.py for the full scope note.
Threat_Candidate_Review = Table(
    "Threat_Candidate_Review", metadata,
    Column("CandidateID", GUID, primary_key=True),
    Column("TenantID", Unicode(200), nullable=False),
    Column("EntityID", Unicode(200)),
    Column("SessionID", GUID, nullable=False),
    Column("ProposedCategory", Unicode(200), nullable=False),
    Column("ProposedType", Unicode(300), nullable=False),
    Column("ProposedName", Unicode(500), nullable=False),
    Column("Status", Unicode(20), nullable=False),
    Column("ThreatTypeID", Integer),
    Column("ThreatCatalogueID", Integer),
    Column("ReviewedBy", Unicode(200)),
    Column("ReviewedAt", DateTime),
    Column("CreatedAt", DateTime, nullable=False),
)

# One row per LLM call (the exact prompt + raw response, success or
# failure). The dev/ops diagnostic record for parse failures: raw model output is
# NEVER put in ErrorMessage/audit/SSE (client-visible), only here (internal DB).
Prompt_Log = Table(
    "Prompt_Log", metadata,
    Column("LogID", GUID, primary_key=True),
    Column("SessionID", GUID, nullable=False),
    Column("TenantID", Unicode(200)),
    Column("EntityID", Unicode(200)),
    Column("UserID", Unicode(200)),
    Column("SubsystemID", Integer, nullable=False),
    Column("Stage", Unicode(20), nullable=False),          # 'profile' | 'threats' | 'scenario'
    Column("PromptVersion", Unicode(20), nullable=False),
    Column("Messages", UnicodeText, nullable=False),        # exact prompt sent (already redacted/allowlisted)
    Column("ResponseText", UnicodeText),                    # raw LLM reply, including malformed ones
    Column("Model", Unicode(200)),
    Column("ModelVersion", Unicode(100)),
    Column("ParseSucceeded", Boolean, nullable=False),
    Column("CreatedAt", DateTime, nullable=False),
)

# ---------------------------------------------------------------------------
# Audit (append-only)
# ---------------------------------------------------------------------------
Scenario_Audit = Table(
    "Scenario_Audit", metadata,
    Column("AuditID", GUID, primary_key=True),
    Column("SessionID", GUID, nullable=False),
    Column("TenantID", Unicode(200)),    
    Column("EntityID", Unicode(200)),
    Column("Stage", Unicode(32)),
    Column("SubsystemID", Integer),
    Column("EventType", Unicode(40), nullable=False),
    Column("Decision", Unicode(30)),
    Column("Granularity", Unicode(20)),
    Column("ThreatTypeRefID", Integer),
    Column("ActorUserID", Unicode(200)),
    Column("TaskID", GUID),
    Column("DetailJSON", UnicodeText),
    Column("CreatedAt", DateTime, nullable=False),
)

# ---------------------------------------------------------------------------
# Context (platform-owned, read-only — minimal columns used by §5.1)
# ---------------------------------------------------------------------------
group_table = Table(  # "group" is a reserved word; SQLAlchemy quotes it
    "group", metadata,
    Column("id", Integer, primary_key=True),
    Column("name", Unicode(300)),
    Column("code", Unicode(100)),
)

onboarding_sectors = Table(
    "onboarding_sectors", metadata,
    Column("id", Integer, primary_key=True),
    Column("name", Unicode(300)),
    Column("sector_code", Unicode(100)),
    Column("parent_id", Integer),
)

ctm_scan_entity = Table(
    "ctm_scan_entity", metadata,
    Column("id", Integer, primary_key=True),
    Column("name", Unicode(300)),
    Column("type", Unicode(200)),
    Column("description", UnicodeText),
    Column("criticality", Integer),
    Column("operating_system", Unicode(200)),
    Column("location", Unicode(200)),
    Column("owner_custodian", Unicode(200)),
    Column("target_rto_hours", Integer),
    Column("target_rpo_hours", Integer),
    Column("tier1_critical_service_id", Integer), 
    Column("group_id", Integer),                  
)

onboarding_service_entity = Table(  # maps a service to its owning entity/group
    "onboarding_service_entity", metadata,
    Column("service_id", Integer, primary_key=True),
    Column("group_id", Integer, primary_key=True),
)

ctm_scan_entity_supporting_system = Table(
    "ctm_scan_entity_supporting_system", metadata,
    Column("ctm_scan_entity_id", Integer, primary_key=True),
    Column("onboarding_supporting_system_id", Integer, primary_key=True),
)

onboarding_supporting_systems = Table(
    "onboarding_supporting_systems", metadata,
    Column("id", Integer, primary_key=True),
    Column("name", Unicode(300)),
    Column("asset_type", Unicode(200)),
    Column("technology_used", UnicodeText),
    Column("hosting_location", Unicode(200)),
    Column("url", Unicode(500)),
    Column("user_base_count", Integer),
    Column("vendor_name", Unicode(200)),
    Column("database_platforms", Unicode(300)),
)

# Tables that carry EntityID directly (DAL filters these by EntityID).
# Pipeline-output tables resolve entity via the session and are always
# accessed through an already entity-authorized SessionID.
ENTITY_SCOPED_DIRECT = {Scenario_Session, Subsystem_Stage_State, Scenario_Audit, Prompt_Log}
