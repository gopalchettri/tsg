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

IF OBJECT_ID('dbo.Control_Standard', 'U') IS NULL
CREATE TABLE Control_Standard (
    StandardID     int            IDENTITY(1,1) NOT NULL CONSTRAINT PK_Control_Standard PRIMARY KEY,
    StandardName   nvarchar(200)  NOT NULL,
    CreateDate     datetime       NOT NULL CONSTRAINT DF_Control_Standard_CreateDate DEFAULT (getdate()),
    CreatedBy      nvarchar(55)   NULL,
    UpdateDate     datetime       NULL,
    UpdatedBy      nvarchar(55)   NULL,
    IsActive       bit            NOT NULL CONSTRAINT DF_Control_Standard_IsActive DEFAULT (1),
    IsDeleted      bit            NOT NULL CONSTRAINT DF_Control_Standard_IsDeleted DEFAULT (0),
    CONSTRAINT UX_Control_Standard_Name UNIQUE (StandardName)
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
    CreateDate              datetime       NOT NULL CONSTRAINT DF_Control_Library_CreateDate DEFAULT (getdate()),
    CreatedBy                nvarchar(55)   NULL,
    UpdateDate                datetime       NULL,
    UpdatedBy                  nvarchar(55)   NULL,
    IsActive                    bit            NOT NULL CONSTRAINT DF_Control_Library_IsActive DEFAULT (1),
    IsDeleted                    bit            NOT NULL CONSTRAINT DF_Control_Library_IsDeleted DEFAULT (0),
    CONSTRAINT UX_Control_Library_Code UNIQUE (ControlCode)
);

IF OBJECT_ID('dbo.Control_Library_Standard_Map', 'U') IS NULL
CREATE TABLE Control_Library_Standard_Map (
    ControlLibraryID  int NOT NULL,
    StandardID        int NOT NULL,
    CONSTRAINT PK_Control_Library_Standard_Map PRIMARY KEY (ControlLibraryID, StandardID)
);

-- Verify
SELECT 'Control_Standard' AS what, OBJECT_ID('dbo.Control_Standard', 'U') AS exists_check
UNION ALL
SELECT 'Control_Library', OBJECT_ID('dbo.Control_Library', 'U')
UNION ALL
SELECT 'Control_Library_Standard_Map', OBJECT_ID('dbo.Control_Library_Standard_Map', 'U');
