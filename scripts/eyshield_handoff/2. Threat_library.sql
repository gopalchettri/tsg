-- ============================================================================
-- Threat_library — the threat-library MASTER tables (Category/Type/Catalogue/
-- Actor), their two junction maps, and the Source provenance columns. Schema
-- only; rows live in Seed_to_Threat_library.sql. Run after TSG_Core.sql.
-- ============================================================================

-- REQUIRED: the filtered indexes below need QUOTED_IDENTIFIER ON, and sqlcmd
-- defaults it OFF. Without this the script aborts partway (Msg 1934) and the
-- seed then fails on every INSERT.
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
GO

-- ============================================================
-- MASTER tables. Type/Catalogue/Actor use IDENTITY PKs (promote-on-accept
-- reads the key back); Category is a plain int PK (fixed STRIDE set).
-- ============================================================

-- Audit columns are nullable with no DEFAULT: the seed inserts explicit column
-- lists, so NOT NULL would break every statement. Updated* is written by the
-- CRUD API only.
IF OBJECT_ID('dbo.Threat_Category', 'U') IS NULL
CREATE TABLE Threat_Category (
    ThreatCategoryID    int            NOT NULL CONSTRAINT PK_Threat_Category PRIMARY KEY,
    ThreatCategoryName  nvarchar(200)  NOT NULL,
    ThreatCategoryCode  nvarchar(100)   NULL,
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
    IsActive           bit            NOT NULL,
    IsDeleted          bit            NOT NULL,
    CreatedAt          datetime2      NULL,
    CreatedBy          nvarchar(200)  NULL,
    UpdatedAt          datetime2      NULL,
    UpdatedBy          nvarchar(200)  NULL
);

-- Source is declared inline here; Type/Catalogue get it from the ALTERs below.
IF OBJECT_ID('dbo.Threat_Actor', 'U') IS NULL
CREATE TABLE Threat_Actor (
    ThreatActorID    int            IDENTITY(1,1) NOT NULL CONSTRAINT PK_Threat_Actor PRIMARY KEY,
    ThreatActorName  nvarchar(200)  NOT NULL,
    IsCapable        int            NOT NULL,
    IsActive         bit            NOT NULL,
    IsDeleted        bit            NOT NULL,
    Source           nvarchar(100)   NULL,
    CreatedAt        datetime2      NULL,
    CreatedBy        nvarchar(200)  NULL,
    UpdatedAt        datetime2      NULL,
    UpdatedBy        nvarchar(200)  NULL
);

-- No-op once these columns exist — all four are always added together.
IF OBJECT_ID('dbo.Threat_Actor', 'U') IS NOT NULL AND COL_LENGTH('dbo.Threat_Actor', 'Source') IS NULL
    ALTER TABLE Threat_Actor ADD Source nvarchar(100) NULL;

IF OBJECT_ID('dbo.Threat_Category', 'U') IS NOT NULL AND COL_LENGTH('dbo.Threat_Category', 'CreatedAt') IS NULL
    ALTER TABLE Threat_Category ADD CreatedAt datetime2 NULL, CreatedBy nvarchar(200) NULL, UpdatedAt datetime2 NULL, UpdatedBy nvarchar(200) NULL;

IF OBJECT_ID('dbo.Threat_Type', 'U') IS NOT NULL AND COL_LENGTH('dbo.Threat_Type', 'CreatedAt') IS NULL
    ALTER TABLE Threat_Type ADD CreatedAt datetime2 NULL, CreatedBy nvarchar(200) NULL, UpdatedAt datetime2 NULL, UpdatedBy nvarchar(200) NULL;

IF OBJECT_ID('dbo.Threat_Catalogue', 'U') IS NOT NULL AND COL_LENGTH('dbo.Threat_Catalogue', 'CreatedAt') IS NULL
    ALTER TABLE Threat_Catalogue ADD CreatedAt datetime2 NULL, CreatedBy nvarchar(200) NULL, UpdatedAt datetime2 NULL, UpdatedBy nvarchar(200) NULL;

IF OBJECT_ID('dbo.Threat_Actor', 'U') IS NOT NULL AND COL_LENGTH('dbo.Threat_Actor', 'CreatedAt') IS NULL
    ALTER TABLE Threat_Actor ADD CreatedAt datetime2 NULL, CreatedBy nvarchar(200) NULL, UpdatedAt datetime2 NULL, UpdatedBy nvarchar(200) NULL;

-- ---------------------------------------------------------------------------
-- REMOVED COLUMNS: Threat_Category.SecurityObjective, Threat_Type.Description,
-- Threat_Catalogue.Description, Threat_Type.SectorID, Threat_Catalogue.SectorID
-- ---------------------------------------------------------------------------
-- SecurityObjective was never read. Threat_Type.Description was never embedded or shown.
-- Threat_Catalogue.Description WAS load-bearing until 2026-08-30: it fed the embedded passage
-- (embeddings.catalogue_passage_text) and the validator prompt. Catalogue matching is name-only
-- from here — RE-RUN POST /v1/tsg/grounding/calibrate after this upgrade, or the stored
-- threshold judges text it was never measured against.
-- SectorID was already unmapped and unread (sector logic removed 2026-08, per user instruction)
-- before this drop, so removing it has NO functional impact — unlike Description above.
--
-- THE ONLY DROPS IN ANY OF THESE SCRIPTS, and a sanctioned exception to the frozen-master-table
-- rule enforced by tests/test_schema_sync.py. Each guarded on the column still existing, so it
-- fires once and no-ops afterwards; placed AFTER every CREATE/ADD above so an earlier failure
-- stops the script before it can reach here.
IF OBJECT_ID('dbo.Threat_Category', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Category', 'SecurityObjective') IS NOT NULL
    ALTER TABLE Threat_Category DROP COLUMN SecurityObjective;

IF OBJECT_ID('dbo.Threat_Type', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Type', 'Description') IS NOT NULL
    ALTER TABLE Threat_Type DROP COLUMN Description;

IF OBJECT_ID('dbo.Threat_Catalogue', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Catalogue', 'Description') IS NOT NULL
    ALTER TABLE Threat_Catalogue DROP COLUMN Description;

IF OBJECT_ID('dbo.Threat_Type', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Type', 'SectorID') IS NOT NULL
    ALTER TABLE Threat_Type DROP COLUMN SectorID;

IF OBJECT_ID('dbo.Threat_Catalogue', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Catalogue', 'SectorID') IS NOT NULL
    ALTER TABLE Threat_Catalogue DROP COLUMN SectorID;
GO


-- Natural-key guard indexes, NAME-ONLY. A concurrency backstop, not the dedup
-- mechanism: dedup is app-side (dal.upsert_threat_* via normalize_name), and
-- this only arbitrates two writers committing the same new name at once.
-- Boot-asserted in app/db/invariants.REQUIRED_INDEXES, and dal's IntegrityError
-- recovery selects on these exact columns — change both together, or a duplicate
-- turns into a 500.
-- Guarded CREATE, never DROP-then-CREATE: a DROP followed by a CREATE UNIQUE
-- that fails on existing duplicates (Msg 1505) would leave NO unique index at
-- all. On a database still holding the old 3-column index, drop it by hand.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatType_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Type'))
CREATE UNIQUE INDEX UX_ThreatType_NaturalKey ON Threat_Type(ThreatTypeName) WHERE IsActive = 1 AND IsDeleted = 0;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatCatalogue_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Catalogue'))
CREATE UNIQUE INDEX UX_ThreatCatalogue_NaturalKey ON Threat_Catalogue(ThreatName) WHERE IsActive = 1 AND IsDeleted = 0;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatActor_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Actor'))
CREATE UNIQUE INDEX UX_ThreatActor_NaturalKey ON Threat_Actor(ThreatActorName) WHERE IsActive = 1 AND IsDeleted = 0;

-- Without this a duplicate category name is accepted silently, and grounding
-- and the importer disagree on which id it means.
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatCategory_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Category'))
CREATE UNIQUE INDEX UX_ThreatCategory_NaturalKey ON Threat_Category(ThreatCategoryName) WHERE IsActive = 1 AND IsDeleted = 0;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ThreatType_Category_Active' AND object_id = OBJECT_ID('dbo.Threat_Type'))
CREATE INDEX IX_ThreatType_Category_Active ON Threat_Type(ThreatCategoryID) WHERE IsActive = 1 AND IsDeleted = 0;
-- Supports grounding.get_possible_types()'s category filter. SectorID was removed from this
-- index's key (and from the table, above) 2026-08-30 — it was already unused.

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


-- Threat_Catalogue <-> Threat_Category many-to-many: most threats carry more
-- than one STRIDE category, which a single FK cannot represent.

IF OBJECT_ID('dbo.Threat_Catalogue_Category_Map', 'U') IS NULL
CREATE TABLE Threat_Catalogue_Category_Map (
    ThreatCatalogueID INT NOT NULL,
    ThreatCategoryID  INT NOT NULL,
    -- PK leads on ThreatCategoryID: it is also the clustered index, and the one
    -- query that filters this table (grounding.get_possible_types) seeks on category.
    CreatedAt datetime2 NULL CONSTRAINT DF_CatCategoryMap_CreatedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_Threat_Catalogue_Category_Map PRIMARY KEY (ThreatCategoryID, ThreatCatalogueID)
);

-- Adds CreatedAt for pre-2026-07-30 databases.
IF OBJECT_ID('dbo.Threat_Catalogue_Category_Map', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Catalogue_Category_Map', 'CreatedAt') IS NULL
    ALTER TABLE Threat_Catalogue_Category_Map ADD CreatedAt datetime2 NULL CONSTRAINT DF_CatCategoryMap_CreatedAt DEFAULT SYSUTCDATETIME();


-- Context_Field_Config REMOVED — nothing reads it. If a deployed database still
-- has the table it is inert; drop it when convenient.


-- Verify
SELECT 'Threat_Category' AS what, OBJECT_ID('dbo.Threat_Category', 'U') AS exists_check
UNION ALL
SELECT 'Threat_Type', OBJECT_ID('dbo.Threat_Type', 'U')
UNION ALL
SELECT 'Threat_Catalogue', OBJECT_ID('dbo.Threat_Catalogue', 'U')
UNION ALL
SELECT 'Threat_Actor', OBJECT_ID('dbo.Threat_Actor', 'U')
UNION ALL
SELECT 'Threat_Type.Source', COL_LENGTH('dbo.Threat_Type', 'Source')
UNION ALL
SELECT 'Threat_Catalogue.Source', COL_LENGTH('dbo.Threat_Catalogue', 'Source')
UNION ALL
SELECT 'ThreatType_ThreatActor_Map', OBJECT_ID('dbo.ThreatType_ThreatActor_Map', 'U')
UNION ALL
SELECT 'Threat_Catalogue_Category_Map', OBJECT_ID('dbo.Threat_Catalogue_Category_Map', 'U')
;


-- ---------------------------------------------------------------------------
-- Widen every remaining short nvarchar column to nvarchar(100)
-- ---------------------------------------------------------------------------
-- A blanket floor. A value that outgrows its column fails only on that one value,
-- so the application looks healthy until the first write of it. nvarchar is
-- variable-length, so the headroom costs nothing. Each guarded on the CURRENT
-- width, so re-running is a no-op.

IF OBJECT_ID('dbo.Threat_Category', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Category', 'ThreatCategoryCode') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Threat_Category'), 'ThreatCategoryCode', 'CharMaxLen') < 100
    ALTER TABLE Threat_Category ALTER COLUMN ThreatCategoryCode nvarchar(100) NULL;
IF OBJECT_ID('dbo.Threat_Actor', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Actor', 'Source') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Threat_Actor'), 'Source', 'CharMaxLen') < 100
    ALTER TABLE Threat_Actor ALTER COLUMN Source nvarchar(100) NULL;
