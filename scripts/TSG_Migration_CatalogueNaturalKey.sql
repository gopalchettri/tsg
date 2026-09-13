/* ===========================================================================
   TSG_Migration_CatalogueNaturalKey.sql

   Creates UX_ThreatCatalogue_NaturalKey on Threat_Catalogue(ThreatName)
   WHERE IsDeleted = 0 -- the index app/db/invariants.REQUIRED_INDEXES asserts
   at boot, and without which the API and the Celery workers refuse to start.

   WHY THIS EXISTS SEPARATELY from '2. Threat_library.sql': that script's
   guarded CREATE (line 143) terminates with Msg 1505 when the table already
   holds duplicate live ThreatName rows, and deliberately leaves NO index
   rather than dropping one. Until 2026-09-04 the filter was
   WHERE IsActive = 1 AND IsDeleted = 0; promote-to-library inserts
   IsActive = 0, so promoted rows were never covered and duplicates could
   accumulate unseen. Widening the filter is what surfaced them.

   SAFE TO RE-RUN: every statement is guarded, a second run changes nothing.
   It NEVER drops an index and NEVER hard-deletes a row.

   RUN WITH QUOTED_IDENTIFIER ON -- a FILTERED index cannot be created without
   it (Msg 1934). sqlcmd: pass -I. SSMS: on by default.
   =========================================================================== */
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
GO

PRINT '--- 1. Duplicate live ThreatName values --------------------------------';

SELECT ThreatName, COUNT(*) AS Rows_
FROM dbo.Threat_Catalogue
WHERE IsDeleted = 0
GROUP BY ThreatName
HAVING COUNT(*) > 1
ORDER BY COUNT(*) DESC, ThreatName;

PRINT '--- 1b. Each row involved, and what still points at it ------------------';

SELECT c.ThreatCatalogueID, c.ThreatName, c.ThreatTypeID, c.IsActive, c.Source,
       c.CreatedAt, c.CreatedBy,
       (SELECT COUNT(*) FROM dbo.Identified_Threat it
          WHERE it.ThreatCatalogueID = c.ThreatCatalogueID)  AS IdentifiedRefs,
       (SELECT COUNT(*) FROM dbo.Threat_Catalogue_Category_Map m
          WHERE m.ThreatCatalogueID = c.ThreatCatalogueID)   AS CategoryRefs,
       (SELECT COUNT(*) FROM dbo.Scenario_Library sl
          WHERE sl.ThreatCatalogueID = c.ThreatCatalogueID)  AS LibraryRefs
FROM dbo.Threat_Catalogue c
WHERE c.IsDeleted = 0
  AND c.ThreatName IN (SELECT ThreatName FROM dbo.Threat_Catalogue
                       WHERE IsDeleted = 0 GROUP BY ThreatName HAVING COUNT(*) > 1)
ORDER BY c.ThreatName, c.ThreatCatalogueID;
GO

PRINT '--- 2. Soft-deleting UNREFERENCED duplicate rows ------------------------';

BEGIN TRAN;
BEGIN TRY
    -- Survivor per name: a REFERENCED row first (never delete data something points
    -- at), then an ACTIVE row over a pending one, then the oldest id. Only rows with
    -- zero references anywhere are soft-deleted; a name whose duplicates are ALL
    -- referenced is left alone and reported by step 3.
    ;WITH dupes AS (
        SELECT ThreatName
        FROM dbo.Threat_Catalogue
        WHERE IsDeleted = 0
        GROUP BY ThreatName
        HAVING COUNT(*) > 1
    ),
    ranked AS (
        SELECT c.ThreatCatalogueID,
               ROW_NUMBER() OVER (
                   PARTITION BY c.ThreatName
                   ORDER BY
                       CASE WHEN EXISTS (SELECT 1 FROM dbo.Identified_Threat it
                                         WHERE it.ThreatCatalogueID = c.ThreatCatalogueID)
                              OR EXISTS (SELECT 1 FROM dbo.Threat_Catalogue_Category_Map m
                                         WHERE m.ThreatCatalogueID = c.ThreatCatalogueID)
                              OR EXISTS (SELECT 1 FROM dbo.Scenario_Library sl
                                         WHERE sl.ThreatCatalogueID = c.ThreatCatalogueID)
                            THEN 0 ELSE 1 END,
                       CASE WHEN c.IsActive = 1 THEN 0 ELSE 1 END,
                       c.ThreatCatalogueID) AS rn
        FROM dbo.Threat_Catalogue c
        JOIN dupes d ON d.ThreatName = c.ThreatName
        WHERE c.IsDeleted = 0
    )
    UPDATE tc
       SET IsDeleted = 1,
           UpdatedAt = SYSUTCDATETIME(),
           UpdatedBy = 'TSG_Migration_CatalogueNaturalKey'
    FROM dbo.Threat_Catalogue tc
    JOIN ranked r ON r.ThreatCatalogueID = tc.ThreatCatalogueID
    WHERE r.rn > 1
      AND NOT EXISTS (SELECT 1 FROM dbo.Identified_Threat it
                      WHERE it.ThreatCatalogueID = tc.ThreatCatalogueID)
      AND NOT EXISTS (SELECT 1 FROM dbo.Threat_Catalogue_Category_Map m
                      WHERE m.ThreatCatalogueID = tc.ThreatCatalogueID)
      AND NOT EXISTS (SELECT 1 FROM dbo.Scenario_Library sl
                      WHERE sl.ThreatCatalogueID = tc.ThreatCatalogueID);

    PRINT '    rows soft-deleted: ' + CAST(@@ROWCOUNT AS varchar(10));
    COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT '    FAILED, rolled back: ' + ERROR_MESSAGE();
    THROW;
END CATCH
GO

PRINT '--- 3. Creating UX_ThreatCatalogue_NaturalKey ---------------------------';

IF EXISTS (SELECT 1 FROM dbo.Threat_Catalogue WHERE IsDeleted = 0
           GROUP BY ThreatName HAVING COUNT(*) > 1)
BEGIN
    PRINT '    NOT CREATED: duplicate live ThreatName rows REMAIN. Every surviving';
    PRINT '    duplicate is referenced by Identified_Threat, Threat_Catalogue_Category_Map';
    PRINT '    or Scenario_Library, so none could be removed automatically. Merge them';
    PRINT '    by hand (see the block at the end of this file), then re-run.';
    PRINT '    The application will NOT boot until this index exists.';

    SELECT ThreatName, COUNT(*) AS Rows_
    FROM dbo.Threat_Catalogue WHERE IsDeleted = 0
    GROUP BY ThreatName HAVING COUNT(*) > 1 ORDER BY ThreatName;
END
ELSE IF NOT EXISTS (SELECT 1 FROM sys.indexes
                    WHERE name = 'UX_ThreatCatalogue_NaturalKey'
                      AND object_id = OBJECT_ID('dbo.Threat_Catalogue'))
BEGIN
    CREATE UNIQUE INDEX UX_ThreatCatalogue_NaturalKey
        ON dbo.Threat_Catalogue(ThreatName) WHERE IsDeleted = 0;
    PRINT '    CREATED.';
END
ELSE
    PRINT '    already present - nothing to do.';
GO

PRINT '--- 4. Final state ------------------------------------------------------';

SELECT i.name, i.is_unique, i.is_disabled, i.filter_definition,
       STRING_AGG(c.name, ',') WITHIN GROUP (ORDER BY ic.key_ordinal) AS Cols
FROM sys.indexes i
JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
WHERE i.object_id = OBJECT_ID('dbo.Threat_Catalogue') AND i.name IS NOT NULL
GROUP BY i.name, i.is_unique, i.is_disabled, i.filter_definition;
GO

/* ---------------------------------------------------------------------------
   MANUAL MERGE -- only needed if step 3 reported rows it could not remove.
   Read it, set @Keep and @Drop from the step-1b report, then run it.
   Commented out deliberately: re-pointing real references is a decision, and
   there are no foreign keys here to catch a wrong one.

   DECLARE @Keep int = <winner ThreatCatalogueID>;
   DECLARE @Drop int = <loser  ThreatCatalogueID>;

   BEGIN TRAN;
   BEGIN TRY
       UPDATE dbo.Identified_Threat SET ThreatCatalogueID = @Keep
        WHERE ThreatCatalogueID = @Drop;

       DELETE m FROM dbo.Threat_Catalogue_Category_Map m
        WHERE m.ThreatCatalogueID = @Drop
          AND EXISTS (SELECT 1 FROM dbo.Threat_Catalogue_Category_Map k
                      WHERE k.ThreatCatalogueID = @Keep
                        AND k.ThreatCategoryID = m.ThreatCategoryID);
       UPDATE dbo.Threat_Catalogue_Category_Map SET ThreatCatalogueID = @Keep
        WHERE ThreatCatalogueID = @Drop;

       UPDATE dbo.Scenario_Library SET ThreatCatalogueID = @Keep
        WHERE ThreatCatalogueID = @Drop;

       UPDATE dbo.Threat_Catalogue
          SET IsDeleted = 1, UpdatedAt = SYSUTCDATETIME(),
              UpdatedBy = 'TSG_Migration_CatalogueNaturalKey/merge'
        WHERE ThreatCatalogueID = @Drop;
       COMMIT;
   END TRY
   BEGIN CATCH
       IF @@TRANCOUNT > 0 ROLLBACK;
       THROW;
   END CATCH
   --------------------------------------------------------------------------- */
