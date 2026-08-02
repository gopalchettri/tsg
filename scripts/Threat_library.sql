-- ============================================================================
-- Threat_library — TSG-owned threat-library schema NOT created by
-- scripts/TSG_Core.sql: Threat_Catalogue_Category_Map, Threat_Type/Catalogue's
-- Source provenance columns, and Config_Threat_Rule. Formerly two separate
-- files (add_threat_catalogue_category_map.sql + seed_threat_rules_asset_type.sql),
-- merged 2026-07-19. Schema only — real row content lives in
-- scripts/Seed_to_Threat_library.sql.
--
-- Run with SSMS or sqlcmd against the TSG database, after TSG_Core.sql.
-- ============================================================================

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
-- A curator can switch a field off here without a deploy — but this table can only narrow which
-- of a fixed, code-reviewed set of field names get sent (app/pipeline/prompts.py's
-- _ASSET_CONTEXT_ALLOWED/_SUB_ALLOWED); it can never add a brand-new field name outside that set.
-- Adding a field to what's ever eligible to reach an external AI call still requires a code change.

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

-- New subsystem fields (added to prompts.py::_SUB_ALLOWED in a later session — usage scale,
-- accessibility/hosting/network exposure, DR/backup posture, data-residency, RTO/RPO targets).
-- Guarded per-row via an anti-join, not per-table like the block above: on a database that
-- already ran the block above (so Context_Field_Config is non-empty), the `IF NOT EXISTS
-- (SELECT 1 FROM Context_Field_Config)` guard on that block would skip an INSERT entirely,
-- silently leaving these 21 fields off — _resolve_allowed's DB-active intersection (prompts.py)
-- would then drop them even though the code ceiling now allows them.
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
SELECT 'Threat_Catalogue_Category_Map' AS what, OBJECT_ID('dbo.Threat_Catalogue_Category_Map', 'U') AS exists_check
UNION ALL
SELECT 'Threat_Type.Source', COL_LENGTH('dbo.Threat_Type', 'Source')
UNION ALL
SELECT 'Threat_Catalogue.Source', COL_LENGTH('dbo.Threat_Catalogue', 'Source')
UNION ALL
SELECT 'Config_Threat_Rule', OBJECT_ID('dbo.Config_Threat_Rule', 'U')
UNION ALL
SELECT 'Context_Field_Config', OBJECT_ID('dbo.Context_Field_Config', 'U');
