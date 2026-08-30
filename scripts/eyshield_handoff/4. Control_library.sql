-- ============================================================================
-- Control Library — Standard + Control + their many-to-many map (1,288 controls,
-- 30 standards). IDENTITY PKs, no physical FOREIGN KEYs (this DB's convention,
-- enforced app-side). Idempotent, safe to re-run. Run after TSG_Core.sql.
-- ============================================================================

-- REQUIRED for the filtered unique indexes below; sqlcmd defaults it OFF, so
-- this failure only shows up from the command line.
SET QUOTED_IDENTIFIER ON;
GO

-- Natural keys are FILTERED unique indexes so a soft-deleted control frees its
-- code for reuse. Existing databases are migrated in place by the guarded block
-- below the CREATEs.
IF OBJECT_ID('dbo.Control_Standard', 'U') IS NULL
CREATE TABLE Control_Standard (
    StandardID     int            IDENTITY(1,1) NOT NULL CONSTRAINT PK_Control_Standard PRIMARY KEY,
    StandardName   nvarchar(200)  NOT NULL,
    Source         nvarchar(100)   NULL,
    CreatedAt      datetime       NOT NULL CONSTRAINT DF_Control_Standard_CreatedAt DEFAULT SYSUTCDATETIME(),
    CreatedBy      nvarchar(200)   NULL,
    UpdatedAt      datetime       NULL,
    UpdatedBy      nvarchar(200)   NULL,
    IsActive       bit            NOT NULL CONSTRAINT DF_Control_Standard_IsActive DEFAULT (1),
    IsDeleted      bit            NOT NULL CONSTRAINT DF_Control_Standard_IsDeleted DEFAULT (0)
);

-- OutputID -> ScenarioID (matching block in `1. TSG_Core.sql`). sp_rename keeps
-- the data in place and the PK follows automatically. Guarded both ways: runs
-- once on an existing database, no-op on a fresh one.
IF OBJECT_ID('dbo.Threat_Scenario_Control_Map', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario_Control_Map', 'OutputID') IS NOT NULL
    AND COL_LENGTH('dbo.Threat_Scenario_Control_Map', 'ScenarioID') IS NULL
    EXEC sp_rename 'dbo.Threat_Scenario_Control_Map.OutputID', 'ScenarioID', 'COLUMN';

IF OBJECT_ID('dbo.Control_Library', 'U') IS NULL
CREATE TABLE Control_Library (
    ControlLibraryID    int            IDENTITY(1,1) NOT NULL CONSTRAINT PK_Control_Library PRIMARY KEY,
    ControlCode          nvarchar(100)   NOT NULL,
    ITOT                  nvarchar(100)   NOT NULL,
    Domain                nvarchar(200)  NOT NULL,
    ControlName            nvarchar(500)  NOT NULL,
    ControlDescription     nvarchar(max)  NOT NULL,
    SampleEvidence          nvarchar(max)  NULL,
    Source                  nvarchar(100)   NULL,
    CreatedAt               datetime       NOT NULL CONSTRAINT DF_Control_Library_CreatedAt DEFAULT SYSUTCDATETIME(),
    CreatedBy                nvarchar(200)   NULL,
    UpdatedAt                 datetime       NULL,
    UpdatedBy                  nvarchar(200)   NULL,
    IsActive                    bit            NOT NULL CONSTRAINT DF_Control_Library_IsActive DEFAULT (1),
    IsDeleted                    bit            NOT NULL CONSTRAINT DF_Control_Library_IsDeleted DEFAULT (0)
);

IF OBJECT_ID('dbo.Control_Library_Standard_Map', 'U') IS NULL
CREATE TABLE Control_Library_Standard_Map (
    ControlLibraryID  int NOT NULL,
    StandardID        int NOT NULL,
    CreatedAt datetime2 NULL CONSTRAINT DF_ControlStdMap_CreatedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_Control_Library_Standard_Map PRIMARY KEY (ControlLibraryID, StandardID)
);

-- Adds CreatedAt for pre-2026-07-30 databases.
IF OBJECT_ID('dbo.Control_Library_Standard_Map', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Control_Library_Standard_Map', 'CreatedAt') IS NULL
    ALTER TABLE Control_Library_Standard_Map ADD CreatedAt datetime2 NULL CONSTRAINT DF_ControlStdMap_CreatedAt DEFAULT SYSUTCDATETIME();

-- Threat_Scenario_Control_Map (Step-4 mapping). Runs after TSG_Core.sql, so
-- Threat_Scenario already exists.
IF OBJECT_ID('dbo.Threat_Scenario_Control_Map', 'U') IS NULL
CREATE TABLE Threat_Scenario_Control_Map (
    ScenarioID        uniqueidentifier NOT NULL,
    ControlLibraryID  int           NOT NULL,
    SessionID         uniqueidentifier NOT NULL,
    MapRank           int           NOT NULL,   -- 1 = best match for this scenario
    Score             float         NULL,       -- raw rerank 0-100
    SuggestedControl  nvarchar(500) NULL,       -- the LLM's free-text suggestion this grounded from (NULL on scenario-text fallback)
    CreatedAt         datetime2     NULL,
    CONSTRAINT PK_Threat_Scenario_Control_Map PRIMARY KEY (ScenarioID, ControlLibraryID)
);

-- ---------------------------------------------------------------------------
-- In-place migration for pre-existing databases. Every step guarded.
-- ---------------------------------------------------------------------------

-- 1. Column renames (metadata only). Also renames the DEFAULT constraint so its
--    name still matches the column.
IF COL_LENGTH('dbo.Control_Standard', 'CreateDate') IS NOT NULL
BEGIN
    EXEC sp_rename 'dbo.Control_Standard.CreateDate', 'CreatedAt', 'COLUMN';
    IF OBJECT_ID('DF_Control_Standard_CreateDate', 'D') IS NOT NULL
        EXEC sp_rename 'DF_Control_Standard_CreateDate', 'DF_Control_Standard_CreatedAt', 'OBJECT';
END
IF COL_LENGTH('dbo.Control_Standard', 'UpdateDate') IS NOT NULL
    EXEC sp_rename 'dbo.Control_Standard.UpdateDate', 'UpdatedAt', 'COLUMN';

IF COL_LENGTH('dbo.Control_Library', 'CreateDate') IS NOT NULL
BEGIN
    EXEC sp_rename 'dbo.Control_Library.CreateDate', 'CreatedAt', 'COLUMN';
    IF OBJECT_ID('DF_Control_Library_CreateDate', 'D') IS NOT NULL
        EXEC sp_rename 'DF_Control_Library_CreateDate', 'DF_Control_Library_CreatedAt', 'OBJECT';
END
IF COL_LENGTH('dbo.Control_Library', 'UpdateDate') IS NOT NULL
    EXEC sp_rename 'dbo.Control_Library.UpdateDate', 'UpdatedAt', 'COLUMN';

-- 2. Provenance column.
IF OBJECT_ID('dbo.Control_Standard', 'U') IS NOT NULL AND COL_LENGTH('dbo.Control_Standard', 'Source') IS NULL
    ALTER TABLE Control_Standard ADD Source nvarchar(50) NULL;
IF OBJECT_ID('dbo.Control_Library', 'U') IS NOT NULL AND COL_LENGTH('dbo.Control_Library', 'Source') IS NULL
    ALTER TABLE Control_Library ADD Source nvarchar(50) NULL;

-- 3. UNIQUE constraint -> FILTERED unique index (a constraint cannot carry a
--    WHERE clause). Without the filter a soft-deleted control would reserve its
--    ControlCode forever.
IF EXISTS (SELECT 1 FROM sys.key_constraints WHERE name = 'UX_Control_Standard_Name')
    ALTER TABLE Control_Standard DROP CONSTRAINT UX_Control_Standard_Name;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Control_Standard_Name' AND object_id = OBJECT_ID('dbo.Control_Standard'))
    CREATE UNIQUE INDEX UX_Control_Standard_Name ON Control_Standard(StandardName) WHERE IsActive = 1 AND IsDeleted = 0;

IF EXISTS (SELECT 1 FROM sys.key_constraints WHERE name = 'UX_Control_Library_Code')
    ALTER TABLE Control_Library DROP CONSTRAINT UX_Control_Library_Code;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Control_Library_Code' AND object_id = OBJECT_ID('dbo.Control_Library'))
    CREATE UNIQUE INDEX UX_Control_Library_Code ON Control_Library(ControlCode) WHERE IsActive = 1 AND IsDeleted = 0;

-- Verify
SELECT 'Control_Standard' AS what, OBJECT_ID('dbo.Control_Standard', 'U') AS exists_check
UNION ALL
SELECT 'Control_Library', OBJECT_ID('dbo.Control_Library', 'U')
UNION ALL
SELECT 'Control_Library_Standard_Map', OBJECT_ID('dbo.Control_Library_Standard_Map', 'U')
UNION ALL
SELECT 'Threat_Scenario_Control_Map', OBJECT_ID('dbo.Threat_Scenario_Control_Map', 'U');

-- ============================================================================
-- More in-place migration. Both steps safe to re-run.
-- ============================================================================

-- Identity columns 55 -> 200, matching every other CreatedBy/UpdatedBy.
-- COL_LENGTH counts BYTES: nvarchar(55)=110. Compare against 110, not 55 — a
-- bare "= 55" never matches and the widen silently never runs. Not `< 400`
-- either: COL_LENGTH returns -1 for nvarchar(max), which would narrow it.
IF COL_LENGTH('dbo.Control_Standard', 'CreatedBy') = 110
    ALTER TABLE Control_Standard ALTER COLUMN CreatedBy nvarchar(200) NULL;
IF COL_LENGTH('dbo.Control_Standard', 'UpdatedBy') = 110
    ALTER TABLE Control_Standard ALTER COLUMN UpdatedBy nvarchar(200) NULL;
IF COL_LENGTH('dbo.Control_Library', 'CreatedBy') = 110
    ALTER TABLE Control_Library ALTER COLUMN CreatedBy nvarchar(200) NULL;
IF COL_LENGTH('dbo.Control_Library', 'UpdatedBy') = 110
    ALTER TABLE Control_Library ALTER COLUMN UpdatedBy nvarchar(200) NULL;

-- Re-points CreatedAt defaults from local getdate() to UTC. Existing rows are
-- NOT rewritten — treat pre-migration Control_* timestamps as approximate.
IF EXISTS (SELECT 1 FROM sys.default_constraints d
           JOIN sys.columns c ON c.object_id = d.parent_object_id AND c.column_id = d.parent_column_id
           WHERE d.parent_object_id = OBJECT_ID('dbo.Control_Standard') AND c.name = 'CreatedAt'
             AND d.definition LIKE '%getdate%')
BEGIN
    ALTER TABLE Control_Standard DROP CONSTRAINT DF_Control_Standard_CreatedAt;
    ALTER TABLE Control_Standard ADD CONSTRAINT DF_Control_Standard_CreatedAt
        DEFAULT SYSUTCDATETIME() FOR CreatedAt;
END

IF EXISTS (SELECT 1 FROM sys.default_constraints d
           JOIN sys.columns c ON c.object_id = d.parent_object_id AND c.column_id = d.parent_column_id
           WHERE d.parent_object_id = OBJECT_ID('dbo.Control_Library') AND c.name = 'CreatedAt'
             AND d.definition LIKE '%getdate%')
BEGIN
    ALTER TABLE Control_Library DROP CONSTRAINT DF_Control_Library_CreatedAt;
    ALTER TABLE Control_Library ADD CONSTRAINT DF_Control_Library_CreatedAt
        DEFAULT SYSUTCDATETIME() FOR CreatedAt;
END


-- ---------------------------------------------------------------------------
-- Widen every remaining short nvarchar column to nvarchar(100)
-- ---------------------------------------------------------------------------
-- A blanket floor. A value that outgrows its column fails only on that one value,
-- so the application looks healthy until the first write of it. nvarchar is
-- variable-length, so the headroom costs nothing. Each guarded on the CURRENT
-- width, so re-running is a no-op.

IF OBJECT_ID('dbo.Control_Standard', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Control_Standard', 'Source') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Control_Standard'), 'Source', 'CharMaxLen') < 100
    ALTER TABLE Control_Standard ALTER COLUMN Source nvarchar(100) NULL;
IF OBJECT_ID('dbo.Control_Library', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Control_Library', 'ControlCode') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Control_Library'), 'ControlCode', 'CharMaxLen') < 100
    ALTER TABLE Control_Library ALTER COLUMN ControlCode nvarchar(100) NOT NULL;
IF OBJECT_ID('dbo.Control_Library', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Control_Library', 'ITOT') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Control_Library'), 'ITOT', 'CharMaxLen') < 100
    ALTER TABLE Control_Library ALTER COLUMN ITOT nvarchar(100) NOT NULL;
IF OBJECT_ID('dbo.Control_Library', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Control_Library', 'Source') IS NOT NULL
    AND COLUMNPROPERTY(OBJECT_ID('dbo.Control_Library'), 'Source', 'CharMaxLen') < 100
    ALTER TABLE Control_Library ALTER COLUMN Source nvarchar(100) NULL;
