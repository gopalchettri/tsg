/* ===========================================================================
   TSG_Migration_CatalogueNaturalKey_Merge.sql

   STEP 2 of the catalogue natural-key repair. Run this ONLY when
   TSG_Migration_CatalogueNaturalKey.sql reported "NOT CREATED" -- meaning every
   surviving duplicate ThreatName is referenced, so none could be soft-deleted
   without orphaning a reference. Run that script again afterwards to create
   the index.

   WHAT IT DOES. For each duplicated live ThreatName it picks ONE survivor --
   an IsActive row ahead of a pending one, then the lowest ThreatCatalogueID --
   re-points every reference from the losers onto it, then soft-deletes the
   losers. Nothing is hard-deleted from Threat_Catalogue and no reference is
   left dangling.

   WHY MERGING IS CORRECT, not a compromise. ThreatName IS the catalogue's
   natural key: that is exactly what UX_ThreatCatalogue_NaturalKey asserts, and
   what dal.upsert_threat_catalogue's IntegrityError recovery selects on. Two
   live rows sharing a name are the same threat by that definition, and the
   application already cannot tell them apart. Note the collision is
   CASE-INSENSITIVE under the server's default collation, so 'Test' and 'test'
   are one key -- a pair that differs only in case is still a duplicate here.

   TWO REFERENCING TABLES CARRY THEIR OWN UNIQUE KEYS that a naive re-point
   would violate, so the loser's colliding row is removed FIRST in each case:
     * Threat_Catalogue_Category_Map  PK (ThreatCategoryID, ThreatCatalogueID)
     * Scenario_Library               UX_ScenarioLibrary_Natural
                                      (ProfileKey, ThreatCatalogueID, ScenarioNumber)
   Discarding a duplicate Scenario_Library row is the behaviour that table's own
   DDL comment already prescribes ("the loser's INSERT fails and is discarded,
   which is correct -- either text was valid").

   ONE TRANSACTION: it commits fully or rolls back fully. Safe to re-run -- a
   second run finds no duplicates and does nothing.

   RUN WITH QUOTED_IDENTIFIER ON. sqlcmd: pass -I. SSMS: on by default.
   =========================================================================== */
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
SET XACT_ABORT ON;
GO

BEGIN TRAN;
BEGIN TRY
    IF OBJECT_ID('tempdb..#merge_map') IS NOT NULL DROP TABLE #merge_map;

    -- Survivor per name: IsActive first, then the lowest id. Every other live
    -- row of that name is a loser and folds into it.
    ;WITH ranked AS (
        SELECT ThreatCatalogueID, ThreatName,
               ROW_NUMBER() OVER (
                   PARTITION BY ThreatName
                   ORDER BY CASE WHEN IsActive = 1 THEN 0 ELSE 1 END,
                            ThreatCatalogueID) AS rn
          FROM dbo.Threat_Catalogue
         WHERE IsDeleted = 0
           AND ThreatName IN (SELECT ThreatName FROM dbo.Threat_Catalogue
                              WHERE IsDeleted = 0
                              GROUP BY ThreatName HAVING COUNT(*) > 1)
    )
    SELECT loser.ThreatCatalogueID AS DropID,
           keep.ThreatCatalogueID  AS KeepID,
           loser.ThreatName        AS LoserName,
           keep.ThreatName         AS KeeperName
      INTO #merge_map
      FROM ranked loser
      JOIN ranked keep ON keep.ThreatName = loser.ThreatName AND keep.rn = 1
     WHERE loser.rn > 1;

    PRINT '--- rows about to be merged away (DropID -> KeepID) --------------------';
    SELECT DropID, LoserName, KeepID, KeeperName FROM #merge_map ORDER BY KeepID, DropID;

    -- 1. Identified_Threat -- no unique key on the column, straight re-point.
    UPDATE it SET it.ThreatCatalogueID = m.KeepID
      FROM dbo.Identified_Threat it
      JOIN #merge_map m ON m.DropID = it.ThreatCatalogueID;
    PRINT '    Identified_Threat re-pointed:         ' + CAST(@@ROWCOUNT AS varchar(10));

    -- 2. Category map -- drop the loser's row where the keeper already holds
    --    that category, otherwise the re-point would violate the PK.
    DELETE cm
      FROM dbo.Threat_Catalogue_Category_Map cm
      JOIN #merge_map m ON m.DropID = cm.ThreatCatalogueID
     WHERE EXISTS (SELECT 1 FROM dbo.Threat_Catalogue_Category_Map k
                    WHERE k.ThreatCatalogueID = m.KeepID
                      AND k.ThreatCategoryID  = cm.ThreatCategoryID);
    PRINT '    Category_Map collisions discarded:    ' + CAST(@@ROWCOUNT AS varchar(10));

    UPDATE cm SET cm.ThreatCatalogueID = m.KeepID
      FROM dbo.Threat_Catalogue_Category_Map cm
      JOIN #merge_map m ON m.DropID = cm.ThreatCatalogueID;
    PRINT '    Category_Map re-pointed:              ' + CAST(@@ROWCOUNT AS varchar(10));

    -- 3. Scenario_Library -- same treatment against UX_ScenarioLibrary_Natural.
    DELETE sl
      FROM dbo.Scenario_Library sl
      JOIN #merge_map m ON m.DropID = sl.ThreatCatalogueID
     WHERE EXISTS (SELECT 1 FROM dbo.Scenario_Library k
                    WHERE k.ThreatCatalogueID = m.KeepID
                      AND k.ProfileKey        = sl.ProfileKey
                      AND k.ScenarioNumber    = sl.ScenarioNumber);
    PRINT '    Scenario_Library collisions discarded:' + CAST(@@ROWCOUNT AS varchar(10));

    UPDATE sl SET sl.ThreatCatalogueID = m.KeepID
      FROM dbo.Scenario_Library sl
      JOIN #merge_map m ON m.DropID = sl.ThreatCatalogueID;
    PRINT '    Scenario_Library re-pointed:          ' + CAST(@@ROWCOUNT AS varchar(10));

    -- 4. Retire the losers. Soft delete only -- reversible.
    UPDATE tc
       SET IsDeleted = 1,
           UpdatedAt = SYSUTCDATETIME(),
           UpdatedBy = 'TSG_Migration_CatalogueNaturalKey/merge'
      FROM dbo.Threat_Catalogue tc
      JOIN #merge_map m ON m.DropID = tc.ThreatCatalogueID;
    PRINT '    catalogue rows soft-deleted:          ' + CAST(@@ROWCOUNT AS varchar(10));

    DROP TABLE #merge_map;
    COMMIT;
    PRINT 'MERGE COMMITTED. Now re-run TSG_Migration_CatalogueNaturalKey.sql to';
    PRINT 'create the index, then restart the API and the workers.';
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT 'MERGE FAILED, rolled back -- nothing changed: ' + ERROR_MESSAGE();
    THROW;
END CATCH
GO

PRINT '--- remaining duplicates (expect none) ---------------------------------';
SELECT ThreatName, COUNT(*) AS Rows_
FROM dbo.Threat_Catalogue WHERE IsDeleted = 0
GROUP BY ThreatName HAVING COUNT(*) > 1 ORDER BY ThreatName;
GO
