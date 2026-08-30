-- ============================================================================
-- Control Library — Standard + Control + many-to-many map (1,288 controls,
-- 30 standards; most controls reference 2+ standards at once). IDENTITY PKs,
-- no physical FOREIGN KEYs (this DB's convention, enforced app-side).
-- Idempotent, safe to re-run. Run with SSMS or sqlcmd against the TSG database.
-- ============================================================================

-- REQUIRED for the filtered unique indexes below — sqlcmd defaults this OFF
-- (SSMS defaults ON), which is why the failure only shows up from the command line.
SET QUOTED_IDENTIFIER ON;
GO

-- 2026-07-27: renamed CreateDate/UpdateDate -> CreatedAt/UpdatedAt to match the
-- threat masters; added Source (provenance); switched the two natural keys to
-- FILTERED unique indexes so a soft-deleted control frees its code for reuse.
-- 2026-07-30: CreatedAt now defaults SYSUTCDATETIME() (was local getdate()).
-- CreatedBy/UpdatedBy widened 55->200 to match every other identity column —
-- they hold the JWT `sub`, and an over-long one used to raise an unhandled 500.
-- Existing databases: migrated in place by the guarded block below the CREATEs.
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

-- OutputID -> ScenarioID (see the matching block in `1. TSG_Core.sql`). sp_rename preserves the
-- data in place and the PRIMARY KEY follows automatically — SQL Server stores key columns by ID,
-- not by name. Guarded both ways: runs once on an existing database, no-op on a fresh one where
-- the CREATE TABLE above already declares ScenarioID.
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
-- Threat_Scenario already exists by the time this CREATE runs.
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
-- In-place migration for pre-existing databases. Every step guarded — no-op
-- on a fresh database, safe to re-run on an old one.
-- ---------------------------------------------------------------------------

-- 1. Column renames (metadata only — does not rewrite rows). Also renames the
--    DEFAULT constraint so its name still matches the column.
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

-- 3. UNIQUE constraint -> FILTERED unique index (a constraint can't carry a
--    WHERE clause). Without the filter, a soft-deleted control would reserve
--    its ControlCode forever.
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
-- In-place migration for pre-fix databases. Both steps safe to re-run.
-- ============================================================================

-- Identity columns: 55 -> 200, matching every other CreatedBy/UpdatedBy in the
-- schema (unbounded JWT `sub`).
--
-- COL_LENGTH counts BYTES, not characters: nvarchar(55)=110, nvarchar(200)=400.
-- Compare against 110, not 55 — a bare "= 55" is unsatisfiable and the widen
-- silently never runs. Not `< 400` either: COL_LENGTH returns -1 for
-- nvarchar(max), which would narrow a max column to 200.
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
-- A blanket floor, not a per-column judgement. Narrow columns sized to today's longest value are
-- a standing trap: the value that outgrows one is usually a one-line enum or vocabulary change,
-- and the failure is invisible because every SHORTER value still inserts - the application looks
-- healthy until the first write of the new value fails, mid-workflow, with no obvious cause.
--
-- nvarchar is variable-length, so this costs nothing: a 12-character value occupies 12 characters
-- whatever the declared maximum. Index keys are unaffected in practice - the widest key here
-- reaches 220 bytes against a 1700-byte limit.
--
-- Each is guarded on the CURRENT width, so re-running is a no-op and a site already at 100 skips.

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
