-- ============================================================================
-- TSG_Fix_NaturalKeys — narrows UX_ThreatType_NaturalKey and
-- UX_ThreatCatalogue_NaturalKey from their old multi-column form to the
-- name-only key the application boot-asserts (app/db/invariants.REQUIRED_INDEXES).
--
-- WHY THIS IS A SEPARATE SCRIPT. 2. Threat_library.sql guards these CREATEs on the
-- index NAME only, and says so: "Guarded CREATE, never DROP-then-CREATE: a DROP
-- followed by a CREATE UNIQUE that fails on existing duplicates (Msg 1505) would
-- leave NO unique index at all. On a database still holding the old 3-column
-- index, drop it by hand." This script IS that by-hand step, made safe:
--   * it refuses to drop anything unless the narrow index is provably creatable
--     (zero duplicate active names), so Msg 1505 cannot happen; and
--   * the drop and create run inside one transaction, so even an unforeseen
--     failure rolls back to the old index rather than to none.
--
-- IDEMPOTENT and READ-ONLY on a database that is already correct.
-- NEVER deletes or edits a library row: if duplicates block the narrowing it
-- lists them and stops, because choosing which duplicate survives is a data
-- decision, not a schema one.
--
-- RUN: sqlcmd -b -I -S <server> -d <database> -E -i TSG_Fix_NaturalKeys.sql
-- (-I is required: filtered indexes cannot be created with QUOTED_IDENTIFIER OFF.)
-- AFTERWARDS: re-run "6. TSG_Verify.sql".
-- ============================================================================

SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET NOCOUNT ON;

IF OBJECT_ID('tempdb..#nk') IS NOT NULL DROP TABLE #nk;
CREATE TABLE #nk (Seq int IDENTITY(1,1), Target nvarchar(40), Status nvarchar(10), Detail nvarchar(1000));

-- ---------------------------------------------------------------------------
-- Threat_Type
-- ---------------------------------------------------------------------------
DECLARE @wide bit = 0, @dupes int = 0, @rows int = 0;

-- "Wide" = the index carries any KEY column other than the one the app asserts.
-- Included columns are ignored: they are not part of the uniqueness.
SELECT @wide = 1
FROM   sys.indexes i
WHERE  i.object_id = OBJECT_ID('dbo.Threat_Type') AND i.name = 'UX_ThreatType_NaturalKey'
  AND  EXISTS (SELECT 1 FROM sys.index_columns ic
               JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
               WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id
                 AND ic.is_included_column = 0 AND c.name <> N'ThreatTypeName');

-- Counted with the index's own semantics -- same filter, same column collation --
-- so this is exactly what CREATE UNIQUE would reject, not a stricter guess.
SELECT @dupes = COUNT(*), @rows = ISNULL(SUM(n), 0) FROM (
    SELECT COUNT(*) AS n FROM dbo.Threat_Type
    WHERE IsActive = 1 AND IsDeleted = 0
    GROUP BY ThreatTypeName HAVING COUNT(*) > 1) d;

IF OBJECT_ID('dbo.Threat_Type', 'U') IS NULL
    INSERT #nk (Target, Status, Detail) VALUES (N'Threat_Type', N'SKIP', N'Table does not exist.');
ELSE IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'UX_ThreatType_NaturalKey'
                    AND object_id = OBJECT_ID('dbo.Threat_Type'))
    INSERT #nk (Target, Status, Detail) VALUES (N'Threat_Type', N'SKIP',
        N'UX_ThreatType_NaturalKey does not exist. Run "2. Threat_library.sql" -- its guarded CREATE builds it correctly.');
ELSE IF @wide = 0
    INSERT #nk (Target, Status, Detail) VALUES (N'Threat_Type', N'OK',
        N'UX_ThreatType_NaturalKey already keys ThreatTypeName alone. Nothing to do.');
ELSE IF @dupes > 0
    INSERT #nk (Target, Status, Detail) VALUES (N'Threat_Type', N'BLOCKED',
        N'Cannot narrow: ' + CAST(@dupes AS nvarchar(10)) + N' duplicate active ThreatTypeName value(s) across '
      + CAST(@rows AS nvarchar(10)) + N' rows. The old index tolerated them because its key also carried '
      + N'ThreatCategoryID/SectorID. Merge them first -- keep the LOWEST ThreatTypeID (dal.find_type_id_by_norm_name '
      + N'already resolves to min(id), so keeping it changes nothing the app sees), repoint '
      + N'Threat_Catalogue.ThreatTypeID / ThreatType_ThreatActor_Map.ThreatTypeID / Identified_Threat.ThreatTypeID '
      + N'at the survivor, then set the losers IsActive=0. The full list is printed below. NOTHING WAS CHANGED.');
ELSE
BEGIN
    -- One transaction: the author's stated worry is a DROP that succeeds followed by a
    -- CREATE that fails, leaving no unique index. The @dupes check above makes that
    -- practically impossible; this makes it impossible.
    BEGIN TRY
        BEGIN TRAN;
            DROP INDEX UX_ThreatType_NaturalKey ON dbo.Threat_Type;
            CREATE UNIQUE INDEX UX_ThreatType_NaturalKey ON dbo.Threat_Type(ThreatTypeName)
                WHERE IsActive = 1 AND IsDeleted = 0;
        COMMIT;
        INSERT #nk (Target, Status, Detail) VALUES (N'Threat_Type', N'FIXED',
            N'UX_ThreatType_NaturalKey narrowed to (ThreatTypeName) WHERE IsActive = 1 AND IsDeleted = 0.');
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK;
        INSERT #nk (Target, Status, Detail) VALUES (N'Threat_Type', N'ERROR',
            N'Rolled back, old index intact: ' + ERROR_MESSAGE());
    END CATCH
END

-- ---------------------------------------------------------------------------
-- Threat_Catalogue -- same shape, same reasoning
-- ---------------------------------------------------------------------------
SET @wide = 0; SET @dupes = 0; SET @rows = 0;

SELECT @wide = 1
FROM   sys.indexes i
WHERE  i.object_id = OBJECT_ID('dbo.Threat_Catalogue') AND i.name = 'UX_ThreatCatalogue_NaturalKey'
  AND  EXISTS (SELECT 1 FROM sys.index_columns ic
               JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
               WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id
                 AND ic.is_included_column = 0 AND c.name <> N'ThreatName');

SELECT @dupes = COUNT(*), @rows = ISNULL(SUM(n), 0) FROM (
    SELECT COUNT(*) AS n FROM dbo.Threat_Catalogue
    WHERE IsActive = 1 AND IsDeleted = 0
    GROUP BY ThreatName HAVING COUNT(*) > 1) d;

IF OBJECT_ID('dbo.Threat_Catalogue', 'U') IS NULL
    INSERT #nk (Target, Status, Detail) VALUES (N'Threat_Catalogue', N'SKIP', N'Table does not exist.');
ELSE IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'UX_ThreatCatalogue_NaturalKey'
                    AND object_id = OBJECT_ID('dbo.Threat_Catalogue'))
    INSERT #nk (Target, Status, Detail) VALUES (N'Threat_Catalogue', N'SKIP',
        N'UX_ThreatCatalogue_NaturalKey does not exist. Run "2. Threat_library.sql".');
ELSE IF @wide = 0
    INSERT #nk (Target, Status, Detail) VALUES (N'Threat_Catalogue', N'OK',
        N'UX_ThreatCatalogue_NaturalKey already keys ThreatName alone. Nothing to do.');
ELSE IF @dupes > 0
    INSERT #nk (Target, Status, Detail) VALUES (N'Threat_Catalogue', N'BLOCKED',
        N'Cannot narrow: ' + CAST(@dupes AS nvarchar(10)) + N' duplicate active ThreatName value(s) across '
      + CAST(@rows AS nvarchar(10)) + N' rows. Merge first -- keep the LOWEST ThreatCatalogueID '
      + N'(dal.find_catalogue_id_by_norm_name already returns min(id)), repoint '
      + N'Threat_Catalogue_Category_Map.ThreatCatalogueID / Identified_Threat.ThreatCatalogueID / '
      + N'Scenario_Library.ThreatCatalogueID at the survivor, then set the losers IsActive=0. '
      + N'The full list is printed below. NOTHING WAS CHANGED.');
ELSE
BEGIN
    BEGIN TRY
        BEGIN TRAN;
            DROP INDEX UX_ThreatCatalogue_NaturalKey ON dbo.Threat_Catalogue;
            CREATE UNIQUE INDEX UX_ThreatCatalogue_NaturalKey ON dbo.Threat_Catalogue(ThreatName)
                WHERE IsActive = 1 AND IsDeleted = 0;
        COMMIT;
        INSERT #nk (Target, Status, Detail) VALUES (N'Threat_Catalogue', N'FIXED',
            N'UX_ThreatCatalogue_NaturalKey narrowed to (ThreatName) WHERE IsActive = 1 AND IsDeleted = 0.');
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK;
        INSERT #nk (Target, Status, Detail) VALUES (N'Threat_Catalogue', N'ERROR',
            N'Rolled back, old index intact: ' + ERROR_MESSAGE());
    END CATCH
END

-- ---------------------------------------------------------------------------
-- Result
-- ---------------------------------------------------------------------------
SELECT Target, Status, Detail FROM #nk ORDER BY Seq;

-- The duplicates that block a narrowing, if any. Send this result set back if it
-- is non-empty -- the merge needs a decision per group, and the survivor is the
-- lowest id in each.
SELECT N'Threat_Type' AS TableName, t.ThreatTypeName AS DuplicateName, t.ThreatTypeID AS Id,
       t.ThreatCategoryID AS ParentId, t.Source, t.CreatedAt,
       CASE WHEN t.ThreatTypeID = MIN(t.ThreatTypeID) OVER (PARTITION BY t.ThreatTypeName)
            THEN N'SURVIVOR' ELSE N'merge into survivor' END AS Action
FROM   dbo.Threat_Type t
WHERE  t.IsActive = 1 AND t.IsDeleted = 0
  AND  t.ThreatTypeName IN (SELECT ThreatTypeName FROM dbo.Threat_Type
                            WHERE IsActive = 1 AND IsDeleted = 0
                            GROUP BY ThreatTypeName HAVING COUNT(*) > 1)
UNION ALL
SELECT N'Threat_Catalogue', c.ThreatName, c.ThreatCatalogueID,
       c.ThreatTypeID, c.Source, c.CreatedAt,
       CASE WHEN c.ThreatCatalogueID = MIN(c.ThreatCatalogueID) OVER (PARTITION BY c.ThreatName)
            THEN N'SURVIVOR' ELSE N'merge into survivor' END
FROM   dbo.Threat_Catalogue c
WHERE  c.IsActive = 1 AND c.IsDeleted = 0
  AND  c.ThreatName IN (SELECT ThreatName FROM dbo.Threat_Catalogue
                        WHERE IsActive = 1 AND IsDeleted = 0
                        GROUP BY ThreatName HAVING COUNT(*) > 1)
ORDER BY TableName, DuplicateName, Id;

IF EXISTS (SELECT 1 FROM #nk WHERE Status IN (N'BLOCKED', N'ERROR'))
    RAISERROR('TSG_Fix_NaturalKeys did NOT complete -- see the BLOCKED/ERROR rows above. No data or index was changed for those targets.', 16, 1);

DROP TABLE #nk;
