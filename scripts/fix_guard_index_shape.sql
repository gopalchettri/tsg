/* ============================================================================
   TSG — repair guard indexes whose SHAPE has drifted
   ----------------------------------------------------------------------------
   Fixes:  StartupInvariantError: required indexes exist under the right name
           but on the wrong table/columns

   Run the whole file in ONE SSMS window against the TSG database (the steps
   share a temp table). Read STEP 1's output before running STEP 4.

   Safe to re-run: STEP 4 only touches indexes that are actually wrong, and
   does nothing at all once they are right. It drops and rebuilds INDEXES only
   — never a table, a column or a row.

   This is the hand-run equivalent of migration 0019 / bootstrap_schema.sql
   Section 3b, for a database not managed by alembic.
   ============================================================================ */

USE TSG;    -- <<< change if your database is named differently
GO

/* ---------------------------------------------------------------------------
   STEP 0 — what each guard index is SUPPOSED to be.
   COLLATE DATABASE_DEFAULT: a temp table inherits tempdb's collation, and
   joining that to sys.indexes fails on any server where the two differ.
   --------------------------------------------------------------------------- */
IF OBJECT_ID('tempdb..#GuardIndex') IS NOT NULL DROP TABLE #GuardIndex;
CREATE TABLE #GuardIndex (
    IndexName  sysname        COLLATE DATABASE_DEFAULT NOT NULL PRIMARY KEY,
    TableName  sysname        COLLATE DATABASE_DEFAULT NOT NULL,
    KeyColumns nvarchar(1000) COLLATE DATABASE_DEFAULT NOT NULL,  -- comma-separated, IN ORDER
    FilterSql  nvarchar(1000) COLLATE DATABASE_DEFAULT NOT NULL
);
INSERT INTO #GuardIndex (IndexName, TableName, KeyColumns, FilterSql) VALUES
    ('UX_Session_ActiveAsset',        'Scenario_Session',       'EntityID,AssetExternalID',                        'SessionStatus = ''active'''),
    ('UX_Profile_Active',             'Subsystem_Profile',      'SessionID,SubsystemID',                           'Superseded = 0'),
    ('UX_Scenario_ActiveIdentity',    'Threat_Scenario_Output', 'SessionID,IdentityHash',                          'Superseded = 0'),
    ('UX_ThreatType_NaturalKey',      'Threat_Type',            'ThreatTypeName,PrimaryThreatCategoryID,SectorID', 'IsActive = 1 AND IsDeleted = 0'),
    ('UX_ThreatCatalogue_NaturalKey', 'Threat_Catalogue',       'ThreatTypeID,ThreatName,SectorID',                'IsActive = 1 AND IsDeleted = 0'),
    ('UX_ThreatActor_NaturalKey',     'Threat_Actor',           'ThreatActorName',                                 'IsActive = 1 AND IsDeleted = 0');
GO

/* ---------------------------------------------------------------------------
   STEP 1 — DIAGNOSE. Run this first and read it.

   `Actual` is what your database really has. key_ordinal > 0 keeps this to the
   index KEY: SQL Server also lists INCLUDE columns, and silently appends the
   clustering key to a UNIQUE nonclustered index with key_ordinal = 0, neither
   of which is part of the rule the index enforces.
   --------------------------------------------------------------------------- */
SELECT  g.IndexName,
        Expected = g.TableName + '(' + g.KeyColumns + ')',
        Actual   = ISNULL(t.name + '(' + ISNULL(ac.Cols, '') + ')', '*** NOT PRESENT ***'),
        IsUnique = CASE WHEN i.index_id IS NULL THEN NULL WHEN i.is_unique = 1 THEN 'YES' ELSE 'NO -- enforces nothing' END,
        Filter   = ISNULL(i.filter_definition, ''),
        Verdict  = CASE
                     WHEN i.index_id IS NULL                       THEN 'MISSING       -> will be created'
                     WHEN t.name <> g.TableName                    THEN 'WRONG TABLE   -> will be rebuilt'
                     WHEN ISNULL(ac.Cols, '') <> g.KeyColumns      THEN 'WRONG COLUMNS -> will be rebuilt'
                     WHEN i.is_unique = 0                          THEN 'NOT UNIQUE    -> will be rebuilt'
                     ELSE                                               'OK            -> left alone'
                   END
FROM #GuardIndex g
LEFT JOIN sys.indexes i ON i.name = g.IndexName
LEFT JOIN sys.tables  t ON t.object_id = i.object_id
OUTER APPLY (
    SELECT Cols = STUFF((SELECT ',' + c.name
                         FROM sys.index_columns ic
                         JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
                         WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id
                           AND ic.is_included_column = 0 AND ic.key_ordinal > 0
                         ORDER BY ic.key_ordinal
                         FOR XML PATH('')), 1, 1, '')
) ac
ORDER BY g.IndexName;
GO

/* ---------------------------------------------------------------------------
   STEP 2 — add the master-library columns the natural keys are keyed on.

   The threat-library masters are seeded externally, so a database that already
   had its own Threat_Type / Threat_Catalogue may never have received these.
   Each ALTER is skipped when the column is already there. Adding a NULLable
   column changes no existing row.
   --------------------------------------------------------------------------- */
IF COL_LENGTH('dbo.Threat_Type', 'PrimaryThreatCategoryID') IS NULL
    ALTER TABLE Threat_Type ADD PrimaryThreatCategoryID int NULL;
IF COL_LENGTH('dbo.Threat_Type', 'SectorID') IS NULL
    ALTER TABLE Threat_Type ADD SectorID int NULL;
IF COL_LENGTH('dbo.Threat_Catalogue', 'SectorID') IS NULL
    ALTER TABLE Threat_Catalogue ADD SectorID int NULL;
GO

/* ---------------------------------------------------------------------------
   STEP 2b — OPTIONAL, YOUR CALL, READ BEFORE RUNNING.

   Only relevant if STEP 1 showed UX_ThreatType_NaturalKey keyed on a legacy
   `ThreatCategoryID` column AND STEP 2 just added PrimaryThreatCategoryID as a
   brand-new empty column. Your category data is then still in the old column,
   and the rebuilt index would treat every row as category NULL — so two threat
   types sharing a name and sector would collide even though their categories
   differ.

   Check first:
       SELECT TOP 20 ThreatTypeID, ThreatTypeName, ThreatCategoryID, PrimaryThreatCategoryID
       FROM Threat_Type;

   If PrimaryThreatCategoryID is empty and ThreatCategoryID holds the real
   values, uncomment this to copy them across. It writes to existing rows, so it
   is deliberately left commented out.

   -- UPDATE Threat_Type
   --    SET PrimaryThreatCategoryID = ThreatCategoryID
   --  WHERE PrimaryThreatCategoryID IS NULL AND ThreatCategoryID IS NOT NULL;
   --------------------------------------------------------------------------- */

/* ---------------------------------------------------------------------------
   STEP 3 — will the rebuild succeed? A drifted index may have been letting
   duplicate rows in that the CORRECT index rejects. Any non-zero count here
   blocks STEP 4 — de-duplicate those rows first. Where the index is filtered,
   soft-deleting the losers (IsDeleted = 1) is enough; they drop out of the
   index without losing history.
   --------------------------------------------------------------------------- */
DECLARE @check nvarchar(max) = N'';
SELECT @check = @check + CASE WHEN @check = N'' THEN N'' ELSE N' UNION ALL ' END
     + N'SELECT IndexName = ''' + g.IndexName + N''', BlockingDuplicateGroups = (SELECT COUNT(*) FROM (SELECT '
     + g.KeyColumns + N' FROM ' + QUOTENAME(g.TableName) + N' WHERE ' + g.FilterSql
     + N' GROUP BY ' + g.KeyColumns + N' HAVING COUNT(*) > 1) d)'
FROM #GuardIndex g
WHERE OBJECT_ID(g.TableName) IS NOT NULL;
EXEC sp_executesql @check;
GO

/* ---------------------------------------------------------------------------
   STEP 4 — THE REPAIR. Drops only indexes carrying a guard name whose shape is
   wrong, then creates every guard index that is not already present and
   correct. All in one transaction: if a CREATE fails, the DROP is rolled back
   and your database is left exactly as it was.
   --------------------------------------------------------------------------- */
SET XACT_ABORT ON;
BEGIN TRY
    BEGIN TRANSACTION;

    DECLARE @drop nvarchar(max) = N'';
    SELECT @drop = @drop + N'DROP INDEX ' + QUOTENAME(i.name) + N' ON '
                         + QUOTENAME(SCHEMA_NAME(t.schema_id)) + N'.' + QUOTENAME(t.name) + N';'
    FROM sys.indexes i
    JOIN sys.tables t  ON t.object_id = i.object_id
    JOIN #GuardIndex g ON g.IndexName = i.name
    WHERE i.is_unique = 0
       OR t.name <> g.TableName
       OR ISNULL(STUFF((SELECT N',' + c.name
                        FROM sys.index_columns ic
                        JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
                        WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id
                          AND ic.is_included_column = 0 AND ic.key_ordinal > 0
                        ORDER BY ic.key_ordinal
                        FOR XML PATH('')), 1, 1, N''), N'') <> g.KeyColumns;

    IF @drop <> N'' BEGIN PRINT 'dropping drifted indexes:'; PRINT @drop; EXEC sp_executesql @drop; END

    DECLARE @create nvarchar(max) = N'';
    SELECT @create = @create + N'CREATE UNIQUE INDEX ' + QUOTENAME(g.IndexName)
                             + N' ON ' + QUOTENAME(g.TableName) + N'(' + g.KeyColumns + N')'
                             + N' WHERE ' + g.FilterSql + N';'
    FROM #GuardIndex g
    WHERE OBJECT_ID(g.TableName) IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM sys.indexes i2
                      JOIN sys.tables t2 ON t2.object_id = i2.object_id
                      WHERE i2.name = g.IndexName AND t2.name = g.TableName);

    IF @create <> N'' BEGIN PRINT 'creating correct indexes:'; PRINT @create; EXEC sp_executesql @create; END

    COMMIT TRANSACTION;
    PRINT 'guard indexes repaired.';
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
    PRINT 'REPAIR ROLLED BACK — nothing was changed. See the error below;';
    PRINT 'a duplicate-key error means STEP 3 still has rows to de-duplicate.';
    THROW;
END CATCH
GO

/* ---------------------------------------------------------------------------
   STEP 5 — confirm. Re-run STEP 1's query; every Verdict should read OK.
   Then restart the API and the Celery worker.
   --------------------------------------------------------------------------- */
SELECT  g.IndexName,
        Expected = g.TableName + '(' + g.KeyColumns + ')',
        Actual   = ISNULL(t.name + '(' + ISNULL(ac.Cols, '') + ')', '*** NOT PRESENT ***'),
        Verdict  = CASE
                     WHEN i.index_id IS NULL                  THEN 'STILL MISSING'
                     WHEN t.name <> g.TableName               THEN 'STILL WRONG TABLE'
                     WHEN ISNULL(ac.Cols, '') <> g.KeyColumns THEN 'STILL WRONG COLUMNS'
                     WHEN i.is_unique = 0                     THEN 'STILL NOT UNIQUE'
                     ELSE                                          'OK'
                   END
FROM #GuardIndex g
LEFT JOIN sys.indexes i ON i.name = g.IndexName
LEFT JOIN sys.tables  t ON t.object_id = i.object_id
OUTER APPLY (
    SELECT Cols = STUFF((SELECT ',' + c.name
                         FROM sys.index_columns ic
                         JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
                         WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id
                           AND ic.is_included_column = 0 AND ic.key_ordinal > 0
                         ORDER BY ic.key_ordinal
                         FOR XML PATH('')), 1, 1, '')
) ac
ORDER BY g.IndexName;

DROP TABLE #GuardIndex;
GO
