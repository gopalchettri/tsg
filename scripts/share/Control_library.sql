-- ============================================================================
-- Control Library — Standard + Control + many-to-many map.
--
-- Source: functional-team Control_Library.xlsx (1,288 controls, 30 standards;
-- 99% reference 2+ standards at once, up to 9 on one — genuine many-to-many,
-- not a single FK). IDENTITY PKs (one-time bulk load, auto-increment beats
-- hand-numbering). No physical FOREIGN KEYs, matching this DB's convention
-- (enforced app-side).
--
-- Idempotent (IF OBJECT_ID guards), safe to re-run.
-- Run with SSMS or sqlcmd against the TSG database.
-- ============================================================================

-- REQUIRED for the filtered unique indexes at the bottom of this file: SQL Server refuses to
-- CREATE (or later write through) a filtered index unless QUOTED_IDENTIFIER is ON, and sqlcmd
-- defaults it OFF — SSMS defaults it ON, which is why this only bites from the command line.
SET QUOTED_IDENTIFIER ON;
GO

-- 2026-07-27: the audit columns are CreatedAt/UpdatedAt (they were CreateDate/UpdateDate) so the
-- control library and the threat masters spell them the same way; Source records provenance the
-- way Threat_Type.Source does ('functional_team_excel' seed vs 'manual' via the CRUD API); and
-- the two natural keys are FILTERED unique indexes rather than UNIQUE constraints, so a
-- soft-deleted control frees its code for reuse. Existing databases are migrated by the guarded
-- block below the CREATEs.
-- 2026-07-30: CreatedAt defaults SYSUTCDATETIME(), not getdate() (UpdatedAt has no default at
-- all -- dal.update_library_row / soft_delete_library_row stamp it). getdate() is server LOCAL
-- time while every app writer stamps dal.now() (UTC), so one column held two clocks and no two
-- rows were comparable across a seed/CRUD boundary. CreatedBy/UpdatedBy widened 55 -> 200 to
-- match every other identity column in the schema: they receive the same JWT `sub`, which is
-- unbounded, and at 55 an over-long subject does NOT truncate -- SQL Server raises 22001/8152,
-- which pyodbc surfaces as DataError, a type library_crud only translates for IntegrityError,
-- so it escapes as a 500 rather than a handled response.
IF OBJECT_ID('dbo.Control_Standard', 'U') IS NULL
CREATE TABLE Control_Standard (
    StandardID     int            IDENTITY(1,1) NOT NULL CONSTRAINT PK_Control_Standard PRIMARY KEY,
    StandardName   nvarchar(200)  NOT NULL,
    Source         nvarchar(50)   NULL,
    CreatedAt      datetime       NOT NULL CONSTRAINT DF_Control_Standard_CreatedAt DEFAULT SYSUTCDATETIME(),
    CreatedBy      nvarchar(200)   NULL,
    UpdatedAt      datetime       NULL,
    UpdatedBy      nvarchar(200)   NULL,
    IsActive       bit            NOT NULL CONSTRAINT DF_Control_Standard_IsActive DEFAULT (1),
    IsDeleted      bit            NOT NULL CONSTRAINT DF_Control_Standard_IsDeleted DEFAULT (0)
);

IF OBJECT_ID('dbo.Control_Library', 'U') IS NULL
CREATE TABLE Control_Library (
    ControlLibraryID    int            IDENTITY(1,1) NOT NULL CONSTRAINT PK_Control_Library PRIMARY KEY,
    ControlCode          nvarchar(20)   NOT NULL,
    ITOT                  nvarchar(10)   NOT NULL,
    Domain                nvarchar(200)  NOT NULL,
    ControlName            nvarchar(500)  NOT NULL,
    ControlDescription     nvarchar(max)  NOT NULL,
    SampleEvidence          nvarchar(max)  NULL,
    Source                  nvarchar(50)   NULL,
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

-- Existing databases created before the CreatedAt stamp (2026-07-30): add it in place.
IF OBJECT_ID('dbo.Control_Library_Standard_Map', 'U') IS NOT NULL
    AND COL_LENGTH('dbo.Control_Library_Standard_Map', 'CreatedAt') IS NULL
    ALTER TABLE Control_Library_Standard_Map ADD CreatedAt datetime2 NULL CONSTRAINT DF_ControlStdMap_CreatedAt DEFAULT SYSUTCDATETIME();

-- Threat_Scenario_Control_Map (Step-4 threat->control mapping): moved here from
-- scripts/TSG_Core.sql on 2026-08-04 so it lives next to the Control_Library it
-- references (still no physical FK, matching this DB's no-FK convention). This
-- script runs after TSG_Core.sql in the install order, so Threat_Scenario_Output
-- already exists by the time this CREATE runs.
IF OBJECT_ID('dbo.Threat_Scenario_Control_Map', 'U') IS NULL
CREATE TABLE Threat_Scenario_Control_Map (
    OutputID          uniqueidentifier NOT NULL,
    ControlLibraryID  int           NOT NULL,
    SessionID         uniqueidentifier NOT NULL,
    MapRank           int           NOT NULL,   -- 1 = best match for this scenario
    Score             float         NULL,       -- raw rerank 0-100
    SuggestedControl  nvarchar(500) NULL,       -- the LLM's free-text suggestion this grounded from (NULL on scenario-text fallback)
    CreatedAt         datetime2     NULL,
    CONSTRAINT PK_Threat_Scenario_Control_Map PRIMARY KEY (OutputID, ControlLibraryID)
);

-- ---------------------------------------------------------------------------
-- In-place migration for databases created before the above. Every step is guarded, so this
-- block is a no-op on a fresh database and safe to re-run on an old one. The CREATEs are
-- IF OBJECT_ID(...) IS NULL guarded, so on an existing DB they do nothing at all.
-- ---------------------------------------------------------------------------

-- 1. Column renames (metadata-only; sp_rename does not rewrite the 1,318 rows). It leaves the
--    DEFAULT constraint attached but keeps its old NAME, so rename that too — a constraint
--    called DF_..._CreateDate sitting on a column called CreatedAt misleads the next reader.
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

-- 3. UNIQUE constraint -> FILTERED unique index. A constraint cannot carry a WHERE clause, so
--    this is a drop + create, not an alter. Without the filter a soft-deleted control would
--    reserve its ControlCode forever and re-creating it could never succeed — the threat masters
--    have used filtered indexes for exactly this reason since TSG_Core.sql section 4.
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
-- 2026-07-30 in-place migration for databases created before the fixes above.
-- Both are safe to re-run: the widen is idempotent, and re-pointing a default only fires while
-- the old definition is still present.
-- ============================================================================

-- Identity columns: 55 -> 200, matching every other CreatedBy/UpdatedBy in the schema. They hold
-- the JWT `sub`, which is unbounded; at 55 an over-long subject raises 22001/8152 (a DataError,
-- which library_crud does not translate) and the write 500s.
--
-- COL_LENGTH counts BYTES, not characters: nvarchar(55) is 110 and nvarchar(200) is 400. An
-- earlier version of this block compared against 55, which is unsatisfiable for ANY nvarchar
-- column -- the widen silently never ran, on precisely the pre-existing databases it was written
-- for, and the dev DB hid it by being built fresh at 200 already. Not `< 400` either:
-- COL_LENGTH returns -1 for nvarchar(max), and -1 < 400 would NARROW a max column to 200.
IF COL_LENGTH('dbo.Control_Standard', 'CreatedBy') = 110
    ALTER TABLE Control_Standard ALTER COLUMN CreatedBy nvarchar(200) NULL;
IF COL_LENGTH('dbo.Control_Standard', 'UpdatedBy') = 110
    ALTER TABLE Control_Standard ALTER COLUMN UpdatedBy nvarchar(200) NULL;
IF COL_LENGTH('dbo.Control_Library', 'CreatedBy') = 110
    ALTER TABLE Control_Library ALTER COLUMN CreatedBy nvarchar(200) NULL;
IF COL_LENGTH('dbo.Control_Library', 'UpdatedBy') = 110
    ALTER TABLE Control_Library ALTER COLUMN UpdatedBy nvarchar(200) NULL;

-- Re-point the CreatedAt defaults from server-LOCAL getdate() to SYSUTCDATETIME(). Existing rows
-- keep whatever they were stamped with -- they are NOT rewritten, because there is no way to tell
-- a local-time row from a UTC one after the fact. Only new rows become comparable with the UTC
-- the app writes; treat pre-migration Control_* timestamps as approximate.
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
