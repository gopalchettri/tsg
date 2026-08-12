-- ============================================================================
-- Threat_library — creates the threat-library MASTER tables (Category/Type/
-- Catalogue/Actor + type-actor map), Threat_Catalogue_Category_Map, Source
-- provenance columns, and Config_Threat_Rule. Schema only — row content
-- lives in Seed_to_Threat_library.sql. Run after TSG_Core.sql.
-- ============================================================================

-- REQUIRED: this script creates FILTERED indexes (WHERE IsActive=1 AND
-- IsDeleted=0), which SQL Server refuses unless QUOTED_IDENTIFIER is ON.
-- sqlcmd defaults it OFF (SSMS defaults ON) — without this line the script
-- aborts partway, and Seed_to_Threat_library.sql then fails on every INSERT.
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
GO

-- ============================================================
-- Threat-library MASTER tables. Type/Catalogue/Actor use IDENTITY PKs
-- (promote-on-accept inserts and reads back the key); Category stays a
-- plain int PK (fixed STRIDE set).
-- ============================================================

-- Audit columns (CreatedAt/By, UpdatedAt/By) are nullable with no DEFAULT:
-- Seed_to_Threat_library.sql inserts explicit column lists, so a NOT NULL
-- column would break every statement. Updated* is written only by the CRUD
-- API — importer/promote-on-accept leave existing rows untouched (first-writer wins).
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

-- Source declared directly here (Type/Catalogue get it via the guarded ALTERs
-- below) since the column was new when this table was created.
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

-- No-op once these columns exist — all four are always added together.
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

-- Adds CreatedAt for pre-2026-07-30 databases.
IF OBJECT_ID('dbo.ThreatType_ThreatActor_Map', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.ThreatType_ThreatActor_Map', 'CreatedAt') IS NULL
    ALTER TABLE ThreatType_ThreatActor_Map ADD CreatedAt datetime2 NULL CONSTRAINT DF_TypeActorMap_CreatedAt DEFAULT SYSUTCDATETIME();

-- Natural-key guard indexes. Makes concurrent promote-on-accept safe: two
-- sessions accepting at once can't both create the same library master.
-- Boot-asserted in app/db/invariants.REQUIRED_INDEXES.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatType_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Type'))
CREATE UNIQUE INDEX UX_ThreatType_NaturalKey ON Threat_Type(ThreatTypeName, ThreatCategoryID, SectorID) WHERE IsActive = 1 AND IsDeleted = 0;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatCatalogue_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Catalogue'))
CREATE UNIQUE INDEX UX_ThreatCatalogue_NaturalKey ON Threat_Catalogue(ThreatTypeID, ThreatName, SectorID) WHERE IsActive = 1 AND IsDeleted = 0;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatActor_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Actor'))
CREATE UNIQUE INDEX UX_ThreatActor_NaturalKey ON Threat_Actor(ThreatActorName) WHERE IsActive = 1 AND IsDeleted = 0;

-- Threat_Category was the only CRUD-writable master without this guard
-- (2026-07-30) — without it a duplicate category name was accepted silently,
-- and grounding vs. the importer disagreed on which id it meant.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatCategory_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Category'))
CREATE UNIQUE INDEX UX_ThreatCategory_NaturalKey ON Threat_Category(ThreatCategoryName) WHERE IsActive = 1 AND IsDeleted = 0;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ThreatType_Category_Active' AND object_id = OBJECT_ID('dbo.Threat_Type'))
CREATE INDEX IX_ThreatType_Category_Active ON Threat_Type(ThreatCategoryID, SectorID) WHERE IsActive = 1 AND IsDeleted = 0;
-- Supports grounding.get_possible_types()'s category+sector filter.

-- Threat_Catalogue <-> Threat_Category many-to-many: most real threats carry
-- more than one STRIDE category, which a single FK can't represent. Source
-- tracks provenance (curated / AI-promoted / imported).

IF OBJECT_ID('dbo.Threat_Catalogue_Category_Map', 'U') IS NULL
CREATE TABLE Threat_Catalogue_Category_Map (
    ThreatCatalogueID INT NOT NULL,
    ThreatCategoryID  INT NOT NULL,
    -- PK leads on ThreatCategoryID (not ThreatCatalogueID): the composite PK is
    -- also the clustered index, and the one query that filters this table
    -- (grounding.get_possible_types) filters on category, so it needs to seek
    -- on that column first.
    CreatedAt datetime2 NULL CONSTRAINT DF_CatCategoryMap_CreatedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_Threat_Catalogue_Category_Map PRIMARY KEY (ThreatCategoryID, ThreatCatalogueID)
);

-- Adds CreatedAt for pre-2026-07-30 databases.
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

-- Config_Threat_Rule (R12 scoping rules). IDENTITY starts at 22 so the
-- hand-seeded rows 1-21 in Seed_to_Threat_library.sql keep their ids.
-- UX_ConfigThreatRule_NaturalKey collapses duplicate auto-writes — without it
-- a duplicate relevance_flag row would silently double a threat's score boost.

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

-- Context_Field_Config (the per-field AI-prompt allowlist) REMOVED. Nothing
-- reads it anymore — context.py decides what fields are assembled,
-- security.redact()/scrub_context() strip secrets/PII, and
-- prompts._EXCLUDE_DB_KEY_TO_PROMPT drops primary keys. If the table still
-- exists in a deployed database it's inert; drop it when convenient.


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
SELECT 'Config_Threat_Rule', OBJECT_ID('dbo.Config_Threat_Rule', 'U');
