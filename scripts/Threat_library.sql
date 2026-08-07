-- ============================================================================
-- Threat_library — TSG-owned threat-library schema. Creates the threat-library
-- MASTER tables (Threat_Category/Type/Catalogue/Actor + the type-actor map —
-- moved here from scripts/TSG_Core.sql on 2026-08-04 so each script owns its
-- own domain instead of splitting "masters" from "extras" across files) plus
-- what TSG_Core.sql never created: Threat_Catalogue_Category_Map, Threat_Type/
-- Catalogue's Source provenance columns, and Config_Threat_Rule. Formerly two
-- separate files (add_threat_catalogue_category_map.sql + seed_threat_rules_asset_type.sql),
-- merged 2026-07-19. Schema only — real row content lives in
-- scripts/Seed_to_Threat_library.sql.
--
-- Run with SSMS or sqlcmd against the TSG database, after TSG_Core.sql.
-- ============================================================================

-- ============================================================
-- Threat-library MASTER tables (moved from scripts/TSG_Core.sql 2026-08-04).
-- Type/Catalogue/Actor PKs are IDENTITY (R10 promote-on-accept inserts new
-- masters and reads the generated key back). Threat_Category stays a plain
-- int PK (fixed STRIDE set, app never inserts it).
-- ============================================================

-- Audit quartet on all four masters (CreatedAt/CreatedBy/UpdatedAt/UpdatedBy): all NULL and
-- DEFAULT-less on purpose. Seed_to_Threat_library.sql inserts with explicit column lists, so a
-- NOT NULL column without a default would break every one of its ~120 statements; NULL also reads
-- honestly as "row predates the audit columns" rather than a fabricated timestamp. CreatedBy /
-- UpdatedBy hold the caller's user id (Principal.user_id / JWT sub) — the same identity
-- Scenario_Audit.ActorUserID records — or an 'auto:<source>' / 'cli:<user>' literal when a
-- background import had no logged-in caller. Updated* are written ONLY by the CRUD endpoints
-- (app/api/threat_library_crud.py): the importer and promote-on-accept upserts deliberately leave
-- an existing row untouched, because provenance is first-writer (dal.upsert_threat_type).
IF OBJECT_ID('dbo.Threat_Category', 'U') IS NULL
CREATE TABLE Threat_Category (
    ThreatCategoryID    int            NOT NULL CONSTRAINT PK_Threat_Category PRIMARY KEY,
    ThreatCategoryName  nvarchar(200)  NOT NULL,
    ThreatCategoryCode  nvarchar(20)   NULL,
    SecurityObjective   nvarchar(200)  NULL,
    IsActive            bit            NOT NULL,
    IsDeleted           bit            NOT NULL,
    CreatedAt           datetime2      NULL,
    CreatedBy           nvarchar(200)  NULL,
    UpdatedAt           datetime2      NULL,
    UpdatedBy           nvarchar(200)  NULL
);

IF OBJECT_ID('dbo.Threat_Type', 'U') IS NULL
CREATE TABLE Threat_Type (
    ThreatTypeID             int            IDENTITY(1,1) NOT NULL CONSTRAINT PK_Threat_Type PRIMARY KEY,
    ThreatTypeName           nvarchar(300)  NOT NULL,
    Description              nvarchar(max)  NULL,
    SectorID                 int            NULL,
    ThreatCategoryID  int            NULL,
    IsActive                 bit            NOT NULL,
    IsDeleted                bit            NOT NULL,
    CreatedAt                datetime2      NULL,
    CreatedBy                nvarchar(200)  NULL,
    UpdatedAt                datetime2      NULL,
    UpdatedBy                nvarchar(200)  NULL
);

IF OBJECT_ID('dbo.Threat_Catalogue', 'U') IS NULL
CREATE TABLE Threat_Catalogue (
    ThreatCatalogueID  int            IDENTITY(1,1) NOT NULL CONSTRAINT PK_Threat_Catalogue PRIMARY KEY,
    ThreatTypeID       int            NOT NULL,
    ThreatName         nvarchar(500)  NOT NULL,
    Description        nvarchar(max)  NULL,
    SectorID           int            NULL,
    IsActive           bit            NOT NULL,
    IsDeleted          bit            NOT NULL,
    CreatedAt          datetime2      NULL,
    CreatedBy          nvarchar(200)  NULL,
    UpdatedAt          datetime2      NULL,
    UpdatedBy          nvarchar(200)  NULL
);

-- Source mirrors Threat_Type.Source/Threat_Catalogue.Source (added by the guarded ALTERs below) so
-- an imported actor is distinguishable from an AI-promoted or hand-curated one. Declared directly
-- in this CREATE block (unlike the other two, which get it via ALTER) because the column was new
-- at the same time this table was — see test_schema_sync's _COLUMN_DEPLOYED_SEPARATELY allowlist.
IF OBJECT_ID('dbo.Threat_Actor', 'U') IS NULL
CREATE TABLE Threat_Actor (
    ThreatActorID    int            IDENTITY(1,1) NOT NULL CONSTRAINT PK_Threat_Actor PRIMARY KEY,
    ThreatActorName  nvarchar(200)  NOT NULL,
    IsCapable        int            NOT NULL,
    IsActive         bit            NOT NULL,
    IsDeleted        bit            NOT NULL,
    Source           nvarchar(50)   NULL,
    CreatedAt        datetime2      NULL,
    CreatedBy        nvarchar(200)  NULL,
    UpdatedAt        datetime2      NULL,
    UpdatedBy        nvarchar(200)  NULL
);

-- Existing databases: every CREATE above is IF OBJECT_ID(...) IS NULL guarded, so it is a no-op
-- once the table exists and the new columns would never arrive. Guarded on one column per table —
-- the four are always added together, so the first one's absence proves none of them are there.
IF OBJECT_ID('dbo.Threat_Actor', 'U') IS NOT NULL AND COL_LENGTH('dbo.Threat_Actor', 'Source') IS NULL
    ALTER TABLE Threat_Actor ADD Source nvarchar(50) NULL;

IF OBJECT_ID('dbo.Threat_Category', 'U') IS NOT NULL AND COL_LENGTH('dbo.Threat_Category', 'CreatedAt') IS NULL
    ALTER TABLE Threat_Category ADD CreatedAt datetime2 NULL, CreatedBy nvarchar(200) NULL, UpdatedAt datetime2 NULL, UpdatedBy nvarchar(200) NULL;

IF OBJECT_ID('dbo.Threat_Type', 'U') IS NOT NULL AND COL_LENGTH('dbo.Threat_Type', 'CreatedAt') IS NULL
    ALTER TABLE Threat_Type ADD CreatedAt datetime2 NULL, CreatedBy nvarchar(200) NULL, UpdatedAt datetime2 NULL, UpdatedBy nvarchar(200) NULL;

IF OBJECT_ID('dbo.Threat_Catalogue', 'U') IS NOT NULL AND COL_LENGTH('dbo.Threat_Catalogue', 'CreatedAt') IS NULL
    ALTER TABLE Threat_Catalogue ADD CreatedAt datetime2 NULL, CreatedBy nvarchar(200) NULL, UpdatedAt datetime2 NULL, UpdatedBy nvarchar(200) NULL;

IF OBJECT_ID('dbo.Threat_Actor', 'U') IS NOT NULL AND COL_LENGTH('dbo.Threat_Actor', 'CreatedAt') IS NULL
    ALTER TABLE Threat_Actor ADD CreatedAt datetime2 NULL, CreatedBy nvarchar(200) NULL, UpdatedAt datetime2 NULL, UpdatedBy nvarchar(200) NULL;

IF OBJECT_ID('dbo.ThreatType_ThreatActor_Map', 'U') IS NULL
CREATE TABLE ThreatType_ThreatActor_Map (
    ThreatTypeID   int NOT NULL,
    ThreatActorID  int NOT NULL,
    CreatedAt datetime2 NULL CONSTRAINT DF_TypeActorMap_CreatedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_ThreatType_ThreatActor_Map PRIMARY KEY (ThreatTypeID, ThreatActorID)
);

-- Existing databases created before the CreatedAt stamp (2026-07-30): add it in place.
IF OBJECT_ID('dbo.ThreatType_ThreatActor_Map', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.ThreatType_ThreatActor_Map', 'CreatedAt') IS NULL
    ALTER TABLE ThreatType_ThreatActor_Map ADD CreatedAt datetime2 NULL CONSTRAINT DF_TypeActorMap_CreatedAt DEFAULT SYSUTCDATETIME();

-- Natural-key guard indexes on the threat-library masters (moved from scripts/TSG_Core.sql
-- 2026-08-04). Makes concurrent promote-on-accept safe: two sessions accepting at once can't
-- both create the same library master. Boot-asserted in app/db/invariants.REQUIRED_INDEXES.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatType_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Type'))
CREATE UNIQUE INDEX UX_ThreatType_NaturalKey ON Threat_Type(ThreatTypeName, ThreatCategoryID, SectorID) WHERE IsActive = 1 AND IsDeleted = 0;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatCatalogue_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Catalogue'))
CREATE UNIQUE INDEX UX_ThreatCatalogue_NaturalKey ON Threat_Catalogue(ThreatTypeID, ThreatName, SectorID) WHERE IsActive = 1 AND IsDeleted = 0;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatActor_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Actor'))
CREATE UNIQUE INDEX UX_ThreatActor_NaturalKey ON Threat_Actor(ThreatActorName) WHERE IsActive = 1 AND IsDeleted = 0;

-- Threat_Category was the ONLY CRUD-writable master without one (2026-07-30). The shared CRUD
-- create/update path turns a clash into a 409 purely by catching the IntegrityError this index
-- raises (app/api/library_crud.py) — with no index there is no error, so a duplicate name was
-- accepted silently, and the two consumers then disagreed about which id it means:
-- grounding.find_category orders by ThreatCategoryID and takes the LOWEST, while the library
-- importer builds its own name->id map. Same filtered shape as its three siblings above, so a
-- soft-deleted category frees its name for reuse.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatCategory_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Category'))
CREATE UNIQUE INDEX UX_ThreatCategory_NaturalKey ON Threat_Category(ThreatCategoryName) WHERE IsActive = 1 AND IsDeleted = 0;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ThreatType_Category_Active' AND object_id = OBJECT_ID('dbo.Threat_Type'))
CREATE INDEX IX_ThreatType_Category_Active ON Threat_Type(ThreatCategoryID, SectorID) WHERE IsActive = 1 AND IsDeleted = 0;
-- supports grounding.get_possible_types()'s category+sector filter.

-- Threat_Catalogue <-> Threat_Category many-to-many: 74/75 real threats
-- (functional-team Excel review) carry more than one STRIDE category at
-- once, which Threat_Type.ThreatCategoryID (a single FK) can't represent.
-- Source tracks provenance (functional-team-curated vs AI-auto-promoted vs
-- future MITRE-imported).

IF OBJECT_ID('dbo.Threat_Catalogue_Category_Map', 'U') IS NULL
CREATE TABLE Threat_Catalogue_Category_Map (
    ThreatCatalogueID INT NOT NULL,
    ThreatCategoryID  INT NOT NULL,
    -- PK leads on ThreatCategoryID (2026-07-30, was ThreatCatalogueID-first). A composite PK is
    -- also the clustered index, so only its LEADING column can be seeked, and the one query that
    -- FILTERS this table — grounding.get_possible_types()'s mapped_type_ids subquery — filters on
    -- ThreatCategoryID and merely joins on ThreatCatalogueID. Leading on the catalogue id meant
    -- that filter could never seek. Uniqueness enforced is identical either way, and the other
    -- consumer (dal.link_catalogue_category's existence check) supplies BOTH columns so it seeks
    -- regardless. Honest scale note: 346 seeded rows, so the old scan cost a couple of pages —
    -- this is correctness of intent, not a measurable win. Deliberately NOT given a guarded
    -- in-place migration: rebuilding a clustered PK is real churn for zero measured gain, and a
    -- database recreated from these scripts gets the right order for free.
    CreatedAt datetime2 NULL CONSTRAINT DF_CatCategoryMap_CreatedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_Threat_Catalogue_Category_Map PRIMARY KEY (ThreatCategoryID, ThreatCatalogueID)
);

-- Existing databases created before the CreatedAt stamp (2026-07-30): add it in place.
IF OBJECT_ID('dbo.Threat_Catalogue_Category_Map', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Catalogue_Category_Map', 'CreatedAt') IS NULL
    ALTER TABLE Threat_Catalogue_Category_Map ADD CreatedAt datetime2 NULL CONSTRAINT DF_CatCategoryMap_CreatedAt DEFAULT SYSUTCDATETIME();

IF OBJECT_ID('dbo.Threat_Type', 'U') IS NOT NULL
BEGIN
    IF COL_LENGTH('dbo.Threat_Type', 'Source') IS NULL
        ALTER TABLE Threat_Type ADD Source nvarchar(50) NULL;
END

IF OBJECT_ID('dbo.Threat_Catalogue', 'U') IS NOT NULL
BEGIN
    IF COL_LENGTH('dbo.Threat_Catalogue', 'Source') IS NULL
        ALTER TABLE Threat_Catalogue ADD Source nvarchar(50) NULL;
END

-- Config_Threat_Rule (R12: scoping rules, SDD §5.4). ThreatRuleID is IDENTITY since
-- the threat-library import (CLI + POST /v1/tsg/threat-library/sources/{source}/import) auto-writes
-- boost-only rules via dal.upsert_threat_rule — the DB assigns ids, exactly like the
-- three master tables above. Seed starts at 22 so the hand-seeded rows 1-21 in
-- Seed_to_Threat_library.sql keep their ids (that script INSERTs explicit ids and
-- must run under SET IDENTITY_INSERT Config_Threat_Rule ON on a fresh install).
-- UX_ConfigThreatRule_NaturalKey makes concurrent/redelivered auto-writes collapse to
-- one row — without it a duplicate relevance_flag row would silently DOUBLE a threat's
-- score boost (scoping._apply_rules sums fired weights additively).
-- Existing DBs are converted by migration 0027_config_threat_rule_identity.

IF OBJECT_ID('dbo.Config_Threat_Rule', 'U') IS NULL
CREATE TABLE Config_Threat_Rule (
    ThreatRuleID  int            IDENTITY(22,1) NOT NULL CONSTRAINT PK_Config_Threat_Rule PRIMARY KEY,
    RuleType      nvarchar(50)   NOT NULL,               -- tech_gate | relevance_flag | relevance_context_value
    ThreatTypeID  int            NOT NULL,               -- app-enforced FK -> Threat_Type
    RuleKey       nvarchar(200)  NOT NULL,               -- e.g. 'asset_type' (scoping.py allowlist)
    RuleValue     nvarchar(450)  NULL,
    Metadata      nvarchar(max)  NULL,                   -- JSON, e.g. {"weight": 15}
    CreateDate    datetime2      NULL,
    CreatedBy     nvarchar(200)  NULL,
    UpdateDate    datetime2      NULL,
    UpdatedBy     nvarchar(200)  NULL,
    IsActive      bit            NOT NULL,
    IsDeleted     bit            NOT NULL
);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ConfigThreatRule_NaturalKey'
               AND object_id = OBJECT_ID('dbo.Config_Threat_Rule'))
CREATE UNIQUE INDEX UX_ConfigThreatRule_NaturalKey
    ON Config_Threat_Rule(ThreatTypeID, RuleType, RuleKey, RuleValue)
    WHERE IsActive = 1 AND IsDeleted = 0;

-- Context_Field_Config: which asset/subsystem fields are currently turned on for the AI prompt.
-- This table is the ONLY allowlist: app/pipeline/prompts.py holds no hardcoded set of field
-- names, so an active row here is exactly what gets sent to the external AI, and adding or
-- removing a field is a curator edit rather than a deploy. Treat INSERTs here as a data-exposure
-- change and review them accordingly. No active rows for a group = no context sent for that
-- group (fail closed); prompts.py never falls back to "send everything". critical_service is
-- governed by this table like every other field — no forced override — so toggling its row off
-- genuinely removes it from the prompt; validate_scenario's critical-service check is skipped
-- whenever the field wasn't sent (app/pipeline/tasks.py), so this cannot produce a false warning.

IF OBJECT_ID('dbo.Context_Field_Config', 'U') IS NULL
CREATE TABLE Context_Field_Config (
    ContextFieldConfigID INT IDENTITY NOT NULL CONSTRAINT PK_Context_Field_Config PRIMARY KEY,
    ContextGroup          nvarchar(20)   NOT NULL,          -- 'asset' | 'subsystem'
    FieldName             nvarchar(100)  NOT NULL,
    IsActive              bit            NOT NULL,
    IsDeleted             bit            NOT NULL,
    CreatedAt datetime2 NULL CONSTRAINT DF_ContextFieldConfig_CreatedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT UQ_Context_Field_Config UNIQUE (ContextGroup, FieldName)
);

-- Existing databases created before the CreatedAt stamp (2026-07-30): add it in place.
IF OBJECT_ID('dbo.Context_Field_Config', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Context_Field_Config', 'CreatedAt') IS NULL
    ALTER TABLE Context_Field_Config ADD CreatedAt datetime2 NULL CONSTRAINT DF_ContextFieldConfig_CreatedAt DEFAULT SYSUTCDATETIME();

-- Seed: every field currently sent to the AI, all turned on. A curator can flip IsActive to 0
-- for any row to stop sending that field, without touching code.
IF NOT EXISTS (SELECT 1 FROM Context_Field_Config)
INSERT INTO Context_Field_Config (ContextGroup, FieldName, IsActive, IsDeleted) VALUES
    (N'asset', N'cii_asset_description', 1, 0),
    (N'asset', N'critical_service', 1, 0),
    (N'asset', N'sector', 1, 0),
    (N'asset', N'sub_sector', 1, 0),
    (N'asset', N'data_handled', 1, 0),
    (N'asset', N'asset_type', 1, 0),
    (N'asset', N'operating_system', 1, 0),
    (N'asset', N'location', 1, 0),
    (N'asset', N'target_rto_hours', 1, 0),
    (N'asset', N'target_rpo_hours', 1, 0),
    (N'subsystem', N'name', 1, 0),
    (N'subsystem', N'asset_type', 1, 0),
    (N'subsystem', N'past_incidents', 1, 0),
    (N'subsystem', N'technology_used', 1, 0),
    (N'subsystem', N'vendor_name', 1, 0),
    (N'subsystem', N'database_platforms', 1, 0),
    (N'subsystem', N'targeted_users', 1, 0),
    (N'subsystem', N'saas_platform_list', 1, 0),
    (N'subsystem', N'public_cloud_platforms', 1, 0);

-- New subsystem fields added in a later session (usage scale, accessibility/hosting/network
-- exposure, DR/backup posture, data-residency, RTO/RPO targets).
-- Guarded per-row via an anti-join, not per-table like the block above: on a database that
-- already ran the block above (so Context_Field_Config is non-empty), the `IF NOT EXISTS
-- (SELECT 1 FROM Context_Field_Config)` guard on that block would skip an INSERT entirely,
-- silently leaving these 21 fields off — and since this table is now the only allowlist, a
-- missing row means the field simply never reaches the AI.
INSERT INTO Context_Field_Config (ContextGroup, FieldName, IsActive, IsDeleted)
SELECT v.ContextGroup, v.FieldName, 1, 0
FROM (VALUES
    (N'subsystem', N'min_no_of_transactions'),
    (N'subsystem', N'max_no_of_transactions'),
    (N'subsystem', N'user_base_count'),
    (N'subsystem', N'accessability_channel'),
    (N'subsystem', N'hosting_location'),
    (N'subsystem', N'dr_location'),
    (N'subsystem', N'network_connectivity_primary_dr'),
    (N'subsystem', N'dr_drill_frequency'),
    (N'subsystem', N'maintenance_contract_exists'),
    (N'subsystem', N'last_dr_test_date'),
    (N'subsystem', N'backup_multi_site'),
    (N'subsystem', N'backup_retention_period_days'),
    (N'subsystem', N'backup_tested'),
    (N'subsystem', N'offsite_air_gapped_backup'),
    (N'subsystem', N'data_residency_restrictions'),
    (N'subsystem', N'data_residency_restriction_justification'),
    (N'subsystem', N'document_drp_exists'),
    (N'subsystem', N'saas_backup_required'),
    (N'subsystem', N'rto_target_mins'),
    (N'subsystem', N'rpo_target_mins'),
    (N'subsystem', N'data_loss_incident_last_3_years')
) AS v(ContextGroup, FieldName)
WHERE NOT EXISTS (
    SELECT 1 FROM Context_Field_Config c
    WHERE c.ContextGroup = v.ContextGroup AND c.FieldName = v.FieldName
);

-- Verify
SELECT 'Threat_Category' AS what, OBJECT_ID('dbo.Threat_Category', 'U') AS exists_check
UNION ALL
SELECT 'Threat_Type', OBJECT_ID('dbo.Threat_Type', 'U')
UNION ALL
SELECT 'Threat_Catalogue', OBJECT_ID('dbo.Threat_Catalogue', 'U')
UNION ALL
SELECT 'Threat_Actor', OBJECT_ID('dbo.Threat_Actor', 'U')
UNION ALL
SELECT 'ThreatType_ThreatActor_Map', OBJECT_ID('dbo.ThreatType_ThreatActor_Map', 'U')
UNION ALL
SELECT 'Threat_Catalogue_Category_Map', OBJECT_ID('dbo.Threat_Catalogue_Category_Map', 'U')
UNION ALL
SELECT 'Threat_Type.Source', COL_LENGTH('dbo.Threat_Type', 'Source')
UNION ALL
SELECT 'Threat_Catalogue.Source', COL_LENGTH('dbo.Threat_Catalogue', 'Source')
UNION ALL
SELECT 'Config_Threat_Rule', OBJECT_ID('dbo.Config_Threat_Rule', 'U')
UNION ALL
SELECT 'Context_Field_Config', OBJECT_ID('dbo.Context_Field_Config', 'U');
