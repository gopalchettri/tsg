/*==============================================================================
  TSG — Threat Scenario Generator: complete schema creation script.

  Creates every table, constraint and index the TSG application owns, in one
  file. Consolidates what "1. TSG_Core.sql", "2. Threat_library.sql" and
  "4. Control_library.sql" create.

  SAFE TO RE-RUN. Every statement is guarded by an existence check, so a second
  run is a no-op and a run that fails partway can simply be run again.

  DRY RUN: set PreviewOnly to 1 in Section 0 and the whole script only prints what
  it would do. Nothing is created, altered, renamed, dropped or updated.

  Contents: legacy-name migration, 22 tables, 291 reconciled columns,
  21 default constraints,
  3 check constraints, 29 indexes.

  ---------------------------------------------------------------------------
  BEFORE YOU RUN
  ---------------------------------------------------------------------------
  * Select the target database first (USE [<database>]), or connect to it.
  * SET QUOTED_IDENTIFIER ON is set below and is REQUIRED. Many indexes here
    are FILTERED (they carry a WHERE clause), and SQL Server refuses to create a
    filtered index unless it is on. SSMS defaults it on; sqlcmd defaults it OFF,
    which makes the run abort partway with Msg 1934.
  * Section 0 briefly puts the database in SINGLE_USER to enable Read-Committed
    Snapshot Isolation. Run it when nobody else is connected. It is skipped
    entirely if RCSI is already on.

  ---------------------------------------------------------------------------
  TWO THINGS THAT LOOK LIKE MISTAKES AND ARE NOT
  ---------------------------------------------------------------------------
  1. NO FOREIGN KEYS, deliberately. Rows are retired by setting Superseded = 1
     rather than deleted, several columns reference tables in a schema TSG does
     not own, and Scenario_Audit.SubsystemID uses 0 and NULL as meaningful
     values rather than references. Referential integrity is enforced in the
     application. Please do not add FK constraints.

  2. Config_Tuning uses CreateDate / UpdateDate where every other table uses
     CreatedAt / UpdatedAt. That is intentional and the application depends on
     it. Please do not rename them for consistency.

  ---------------------------------------------------------------------------
  THE INDEXES ARE NOT OPTIONAL
  ---------------------------------------------------------------------------
  The application verifies 14 of the indexes in Section 6 at start-up and
  refuses to boot if any is missing, on the wrong columns, or not unique.

  Many of the rest are unique indexes that arbitrate concurrent writes. The
  application deliberately does not read-then-check before inserting, because
  two requests arriving together would both read "nothing there" before either
  wrote. It attempts the insert and turns the resulting violation into a
  rejection. Drop one of those indexes and no violation occurs, so the
  duplicate is accepted and no error is raised anywhere.

  Index names, column order, the UNIQUE keyword and the exact text of each
  WHERE clause all matter. Please create them exactly as written.

  ---------------------------------------------------------------------------
  TWO MESSAGES YOU WILL SEE, BOTH EXPECTED
  ---------------------------------------------------------------------------
  1. "Warning! The maximum key length for a nonclustered index is 1700 bytes.
      The index 'UX_GroundingCalibration_Running' has maximum length of 2000
      bytes."
     Expected, and safe to ignore. That index keys two nvarchar(500) model-name
     columns. An insert only fails if the two names together exceed roughly 850
     characters; real model names run 30 to 60. The same definition is in
     "1. TSG_Core.sql". The index is created and works.

  2. Running "6. TSG_Verify.sql" afterwards reports "Table missing:
     Scenario_Library" as a blocking failure.
     Expected. Scenario_Library backed a cross-tenant scenario-reuse feature
     that was removed in August 2026. No application code reads or writes it,
     and it is absent from the object model, so this script does not create it.
     The verify script's list has not caught up. Every OTHER check it reports
     is real, including its seed-data checks.

  ---------------------------------------------------------------------------
  AFTER YOU RUN
  ---------------------------------------------------------------------------
  Section 7 lists every finding, and anything still missing.
  Both result sets should be empty.

  This script creates SCHEMA ONLY. The application still needs reference data
  loaded before it will run correctly, from the seed scripts in the parent
  folder, plus one API_Client row whose key hash is generated outside SQL.
==============================================================================*/

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO


/*==============================================================================
  SECTION 0 — Read-Committed Snapshot Isolation

  The application's locking model assumes a plain read never waits behind a
  concurrent writer. It checks this at start-up and refuses to boot without it.
  Skipped when already enabled, so re-running never takes the database
  single-user a second time.
==============================================================================*/
IF NOT EXISTS (SELECT 1 FROM sys.databases
               WHERE database_id = DB_ID() AND is_read_committed_snapshot_on = 1)
BEGIN
    PRINT 'Enabling READ_COMMITTED_SNAPSHOT...';
    ALTER DATABASE CURRENT SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    ALTER DATABASE CURRENT SET READ_COMMITTED_SNAPSHOT ON;
    ALTER DATABASE CURRENT SET MULTI_USER;
END
ELSE
    PRINT 'READ_COMMITTED_SNAPSHOT already on - skipped.';
GO

-- Findings collect here from Sections 1 and 3; Section 7 lists them at the end.
IF OBJECT_ID('tempdb..#report') IS NOT NULL DROP TABLE #report;
CREATE TABLE #report (Finding nvarchar(40), ObjectName nvarchar(300), Detail nvarchar(600));
GO

/* ###########################################################################
   ###                                                                     ###
   ###                  CHANGE THESE TWO NUMBERS                           ###
   ###                                                                     ###
   ###########################################################################

   This is the ONLY line in this whole script you ever need to edit. It is the
   line a few rows below, the one ending in an arrow.

        VALUES ( A , B )
                 |   |
                 |   +---- B is DropRemovedColumns
                 |           0 = keep the five removed columns, only list them
                 |           1 = DELETE them for good. This cannot be undone.
                 |
                 +-------- A is PreviewOnly
                             1 = DRY RUN. Prints everything, changes nothing.
                             0 = actually do the work.

   The only four combinations you need:

        VALUES (1, 0)   Dry run. Nothing is changed. START HERE.
        VALUES (0, 0)   Do the work, but keep the five columns.
        VALUES (0, 1)   Do the work AND delete the five columns for good.
        VALUES (1, 1)   Dry run that also shows the deletions it would make.

   Every section of this script reads these two numbers from here.
   ########################################################################### */
IF OBJECT_ID('tempdb..#opt') IS NOT NULL DROP TABLE #opt;
CREATE TABLE #opt (PreviewOnly bit NOT NULL, DropRemovedColumns bit NOT NULL);

INSERT INTO #opt (PreviewOnly, DropRemovedColumns) VALUES (0, 1);  -- <<< EDIT THIS LINE

GO


/*==============================================================================
  SECTION 1 — Legacy names (existing databases only)

  Older TSG databases use earlier names: a Threat_Scenario_Output table, OutputID
  columns, CreateDate instead of CreatedAt. Everything after this section is
  written against the CURRENT names, so this has to run first. If it did not, each
  guard below would find its object missing and CREATE A SECOND ONE beside the
  populated original, leaving the real data orphaned.

  Four parts, in order:
    1a  repair a database where both the old and the new name already exist
    1b  drop the one index whose filter blocks a column rename
    1c  rename every old object to its current name
    1d  drop the five columns the product no longer has

  Every guard tests only its own object, so a partially migrated database is fine:
  whatever is already current is left alone.

  A column holding data is NEVER dropped here. Where the right answer is not
  certain this section reports and changes nothing.

  Honours PreviewOnly: with it set, everything below is printed and nothing runs.
==============================================================================*/

DECLARE @preview bit, @dropRemoved bit;
SELECT @preview = PreviewOnly, @dropRemoved = DropRemovedColumns FROM #opt;

DECLARE @sql nvarchar(max), @rows int, @ixname sysname, @tbl sysname,
        @oldcol sysname, @newcol sysname, @newIsNullable bit,
        @kind varchar(10), @objtype varchar(2), @oldname sysname, @newname sysname,
        @blockingUx sysname;

PRINT 'Section 1: checking for legacy names...'
    + CASE WHEN @preview = 1 THEN '  [PREVIEW - nothing will be changed]' ELSE '' END;

/*----------------------------------------------------------------------------
  1a. Repair a half-migrated database.

  Both names existing means the new one was created in error, because a correct
  migration renames and leaves only the new name. The old column holds the data
  and is never dropped.

  Only the unambiguous case is repaired automatically: the new column is nullable
  and completely empty, so nothing can be lost. A new column that is NOT NULL was
  created with a default, and every row carries that backfilled value, which cannot
  be told apart from real data - those are reported for a person to decide.
----------------------------------------------------------------------------*/
/* A temp table, not a variable: Section 3 reads it too, so that a preview run does
   not report a column as missing when Section 1 would rename one into its place. */
IF OBJECT_ID('tempdb..#pairs') IS NOT NULL DROP TABLE #pairs;
CREATE TABLE #pairs (TableName sysname, OldCol sysname, NewCol sysname);
INSERT INTO #pairs (TableName, OldCol, NewCol) VALUES
  ('Threat_Scenario',             'OutputID',           'ScenarioID'),
  ('Threat_Scenario',             'ReplacesOutputID',   'ReplacesScenarioID'),
  ('Scenario_Audit',              'OutputID',           'ScenarioID'),
  ('Risk_Treatment_Plan',         'OutputID',           'ScenarioID'),
  ('Threat_Scenario_Control_Map', 'OutputID',           'ScenarioID'),
  ('Scenario_Session',            'TuningJSON',         'ScoringRulesSnapshotJSON'),
  ('Scenario_Session',            'TuningSnapshotJSON', 'ScoringRulesSnapshotJSON'),
  ('Identified_Threat',           'IsAIGenerated',      'IsThreatAIGenerated'),
  ('Control_Standard',            'CreateDate',         'CreatedAt'),
  ('Control_Standard',            'UpdateDate',         'UpdatedAt'),
  ('Control_Library',             'CreateDate',         'CreatedAt'),
  ('Control_Library',             'UpdateDate',         'UpdatedAt');

DECLARE pair CURSOR LOCAL FAST_FORWARD FOR SELECT TableName, OldCol, NewCol FROM #pairs;
OPEN pair;
FETCH NEXT FROM pair INTO @tbl, @oldcol, @newcol;
WHILE @@FETCH_STATUS = 0
BEGIN
    IF OBJECT_ID('dbo.' + QUOTENAME(@tbl), 'U') IS NOT NULL
       AND COL_LENGTH('dbo.' + QUOTENAME(@tbl), @oldcol) IS NOT NULL
       AND COL_LENGTH('dbo.' + QUOTENAME(@tbl), @newcol) IS NOT NULL
    BEGIN
        SELECT @newIsNullable = c.is_nullable
        FROM sys.columns c
        WHERE c.object_id = OBJECT_ID('dbo.' + QUOTENAME(@tbl)) AND c.name = @newcol;

        SET @rows = NULL;
        IF @newIsNullable = 1
        BEGIN
            SET @sql = N'SELECT @n = COUNT(*) FROM dbo.' + QUOTENAME(@tbl)
                     + N' WHERE ' + QUOTENAME(@newcol) + N' IS NOT NULL;';
            EXEC sys.sp_executesql @sql, N'@n int OUTPUT', @n = @rows OUTPUT;
        END

        IF @newIsNullable = 1 AND @rows = 0
        BEGIN
            /* Drop anything built over the empty column first, or DROP COLUMN is
               refused. Section 6 recreates these against the real column. */
            DECLARE dep CURSOR LOCAL FAST_FORWARD FOR
                SELECT DISTINCT i.name
                FROM sys.indexes i
                LEFT JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
                LEFT JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
                WHERE i.object_id = OBJECT_ID('dbo.' + QUOTENAME(@tbl))
                  AND i.name IS NOT NULL AND i.is_primary_key = 0
                  AND (c.name = @newcol
                       OR (i.has_filter = 1 AND CHARINDEX(QUOTENAME(@newcol), i.filter_definition) > 0));
            OPEN dep;
            FETCH NEXT FROM dep INTO @ixname;
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @sql = N'DROP INDEX ' + QUOTENAME(@ixname) + N' ON dbo.' + QUOTENAME(@tbl) + N';';
                IF @preview = 1 PRINT '  would run: ' + @sql;
                ELSE
                BEGIN TRY EXEC sys.sp_executesql @sql; PRINT '  applied: ' + @sql; END TRY
                BEGIN CATCH INSERT #report VALUES ('REPAIR FAILED', @tbl + '.' + @newcol, ERROR_MESSAGE()); END CATCH
                FETCH NEXT FROM dep INTO @ixname;
            END
            CLOSE dep; DEALLOCATE dep;

            SET @sql = N'ALTER TABLE dbo.' + QUOTENAME(@tbl) + N' DROP COLUMN ' + QUOTENAME(@newcol) + N';';
            IF @preview = 1
                PRINT '  would repair: drop the empty ' + @tbl + '.' + @newcol
                    + ', then rename ' + @oldcol + ' into its place.';
            ELSE
            BEGIN TRY
                EXEC sys.sp_executesql @sql;
                PRINT '  repaired: dropped the empty ' + @tbl + '.' + @newcol
                    + ' so ' + @oldcol + ' can take its name.';
            END TRY
            BEGIN CATCH INSERT #report VALUES ('REPAIR FAILED', @tbl + '.' + @newcol, ERROR_MESSAGE()); END CATCH
        END
        ELSE
            INSERT #report VALUES ('TWO COLUMNS FOR ONE VALUE', @tbl + '.' + @newcol,
                'Both ' + @oldcol + ' and ' + @newcol + ' exist. ' + @oldcol + ' holds the data; '
                + @newcol + ' was added in error but is not empty, so it was left alone. '
                + 'Decide which is authoritative, then drop the other and rename.');
    END
    FETCH NEXT FROM pair INTO @tbl, @oldcol, @newcol;
END
CLOSE pair; DEALLOCATE pair;

-- The same duplication one level up: an empty new table beside the populated original.
IF OBJECT_ID('dbo.Threat_Scenario_Output', 'U') IS NOT NULL
   AND OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL
BEGIN
    SELECT @rows = COUNT(*) FROM dbo.Threat_Scenario;
    IF @rows = 0
    BEGIN
        IF @preview = 1
            PRINT '  would repair: drop the empty Threat_Scenario, then rename Threat_Scenario_Output.';
        ELSE
        BEGIN
            DROP TABLE dbo.Threat_Scenario;   -- takes its indexes and constraints with it
            PRINT '  repaired: dropped the empty Threat_Scenario so Threat_Scenario_Output can take its name.';
        END
    END
    ELSE
        INSERT #report VALUES ('TWO TABLES FOR ONE THING', 'Threat_Scenario',
            'Threat_Scenario_Output and Threat_Scenario both hold rows. Nothing was changed. '
            + 'Decide which is authoritative before running this script again.');
END

/*----------------------------------------------------------------------------
  1b. One index has to go before the renames.

  IX_ScenarioAudit_Output is filtered on OutputID, and a filtered predicate stores
  the column name as text, so it blocks the rename however the index is named.
  Section 6 recreates it as IX_ScenarioAudit_Scenario.
----------------------------------------------------------------------------*/
IF EXISTS (SELECT 1 FROM sys.indexes
           WHERE name = 'IX_ScenarioAudit_Output' AND object_id = OBJECT_ID('dbo.Scenario_Audit'))
BEGIN
    IF @preview = 1
        PRINT '  would run: DROP INDEX IX_ScenarioAudit_Output ON dbo.Scenario_Audit;';
    ELSE
    BEGIN
        DROP INDEX IX_ScenarioAudit_Output ON dbo.Scenario_Audit;
        PRINT '  dropped IX_ScenarioAudit_Output; Section 6 recreates it on ScenarioID.';
    END
END

/*----------------------------------------------------------------------------
  1c. Renames, driven from the table below so every one is guarded and previewed
  the same way. Each guard tests both names, so a rename fires once and is a no-op
  on a fresh install. sp_rename is metadata only and keeps the data in place.

  Kind tells the guard how to look the object up:
    OBJECT  a table or a constraint, found by OBJECT_ID with ObjType
    INDEX   found in sys.indexes, whose names are unique per table only
    COLUMN  found by COL_LENGTH on its table
----------------------------------------------------------------------------*/
DECLARE @renames TABLE (Seq int IDENTITY(1,1), Kind varchar(10), TableName sysname NULL,
                        OldName sysname, NewName sysname, ObjType varchar(2) NULL);
INSERT INTO @renames (Kind, TableName, OldName, NewName, ObjType) VALUES
  -- the table first, so every guard after it has one address to test
  ('OBJECT', NULL, 'Threat_Scenario_Output',              'Threat_Scenario',                'U'),
  -- its constraints. Renaming the PK renames its backing index with it.
  ('OBJECT', NULL, 'PK_Threat_Scenario_Output',           'PK_Threat_Scenario',             'PK'),
  ('OBJECT', NULL, 'CK_ScenarioOutput_DecisionExclusive', 'CK_Scenario_DecisionExclusive',  'C'),
  ('OBJECT', NULL, 'DF_ScenarioOutput_ScenarioNumber',    'DF_Scenario_ScenarioNumber',     'D'),
  ('OBJECT', NULL, 'DF_Control_Standard_CreateDate',      'DF_Control_Standard_CreatedAt',  'D'),
  ('OBJECT', NULL, 'DF_Control_Library_CreateDate',       'DF_Control_Library_CreatedAt',   'D'),
  -- indexes
  ('INDEX', 'Threat_Scenario',     'IX_ScenarioOutput_SessionSubActive', 'IX_Scenario_SessionSubActive',    NULL),
  ('INDEX', 'Risk_Treatment_Plan', 'UX_TreatmentPlan_ActiveOutput',      'UX_TreatmentPlan_ActiveScenario', NULL),
  -- columns. OutputID named the table it lived in, not the thing it identifies.
  ('COLUMN', 'Threat_Scenario',             'OutputID',           'ScenarioID',               NULL),
  ('COLUMN', 'Threat_Scenario',             'ReplacesOutputID',   'ReplacesScenarioID',       NULL),
  ('COLUMN', 'Scenario_Audit',              'OutputID',           'ScenarioID',               NULL),
  ('COLUMN', 'Risk_Treatment_Plan',         'OutputID',           'ScenarioID',               NULL),
  ('COLUMN', 'Threat_Scenario_Control_Map', 'OutputID',           'ScenarioID',               NULL),
  -- the value is a snapshot frozen at session creation, not the live tuning config
  ('COLUMN', 'Scenario_Session',            'TuningJSON',         'ScoringRulesSnapshotJSON', NULL),
  ('COLUMN', 'Scenario_Session',            'TuningSnapshotJSON', 'ScoringRulesSnapshotJSON', NULL),
  ('COLUMN', 'Identified_Threat',           'IsAIGenerated',      'IsThreatAIGenerated',      NULL),
  -- control tables predate the CreatedAt/UpdatedAt convention
  ('COLUMN', 'Control_Standard',            'CreateDate',         'CreatedAt',                NULL),
  ('COLUMN', 'Control_Standard',            'UpdateDate',         'UpdatedAt',                NULL),
  ('COLUMN', 'Control_Library',             'CreateDate',         'CreatedAt',                NULL),
  ('COLUMN', 'Control_Library',             'UpdateDate',         'UpdatedAt',                NULL);

DECLARE ren CURSOR LOCAL FAST_FORWARD FOR
    SELECT Kind, TableName, OldName, NewName, ObjType FROM @renames ORDER BY Seq;
OPEN ren;
FETCH NEXT FROM ren INTO @kind, @tbl, @oldname, @newname, @objtype;
WHILE @@FETCH_STATUS = 0
BEGIN
    SET @sql = NULL;

    IF @kind = 'OBJECT'
       AND OBJECT_ID('dbo.' + QUOTENAME(@oldname), @objtype) IS NOT NULL
       AND OBJECT_ID('dbo.' + QUOTENAME(@newname), @objtype) IS NULL
        SET @sql = N'EXEC sp_rename ''dbo.' + @oldname + N''', ''' + @newname + N''', ''OBJECT'';';

    ELSE IF @kind = 'INDEX'
       AND EXISTS (SELECT 1 FROM sys.indexes
                   WHERE name = @oldname AND object_id = OBJECT_ID('dbo.' + QUOTENAME(@tbl)))
       AND NOT EXISTS (SELECT 1 FROM sys.indexes
                       WHERE name = @newname AND object_id = OBJECT_ID('dbo.' + QUOTENAME(@tbl)))
        SET @sql = N'EXEC sp_rename ''dbo.' + @tbl + N'.' + @oldname + N''', '''
                 + @newname + N''', ''INDEX'';';

    ELSE IF @kind = 'COLUMN'
       AND OBJECT_ID('dbo.' + QUOTENAME(@tbl), 'U') IS NOT NULL
       AND COL_LENGTH('dbo.' + QUOTENAME(@tbl), @oldname) IS NOT NULL
       AND COL_LENGTH('dbo.' + QUOTENAME(@tbl), @newname) IS NULL
        SET @sql = N'EXEC sp_rename ''dbo.' + @tbl + N'.' + @oldname + N''', '''
                 + @newname + N''', ''COLUMN'';';

    IF @sql IS NOT NULL
    BEGIN
        IF @preview = 1 PRINT '  would rename: ' + @oldname + ' -> ' + @newname;
        ELSE
        BEGIN TRY
            EXEC sys.sp_executesql @sql;
            PRINT '  renamed: ' + @oldname + ' -> ' + @newname;
        END TRY
        BEGIN CATCH
            INSERT #report VALUES ('RENAME FAILED', ISNULL(@tbl + '.', '') + @oldname, ERROR_MESSAGE());
        END CATCH
    END

    FETCH NEXT FROM ren INTO @kind, @tbl, @oldname, @newname, @objtype;
END
CLOSE ren; DEALLOCATE ren;

/*----------------------------------------------------------------------------
  1d. Drop the five columns the product no longer has.

  The only drops in this script, and the only thing here that cannot be undone.
  Each is guarded on the column still existing, so it fires once. An index over one
  of them is dropped first, or the column drop is refused; Section 6 recreates the
  index in its current shape.

  Threat_Catalogue.Description is not cosmetic: threat matching becomes name-only
  once it is gone, so grounding calibration has to be re-run afterwards.
----------------------------------------------------------------------------*/
IF @dropRemoved = 1
BEGIN
    DECLARE @dead TABLE (TableName sysname, ColumnName sysname);
    INSERT INTO @dead (TableName, ColumnName) VALUES
      ('Threat_Category',  'SecurityObjective'),
      ('Threat_Type',      'Description'),
      ('Threat_Type',      'SectorID'),
      ('Threat_Catalogue', 'Description'),
      ('Threat_Catalogue', 'SectorID'),
      -- 2026-09-05: the last of the three threat descriptions. Nothing read it (promotion had
      -- stopped copying it when Threat_Catalogue.Description went) and the model is no longer
      -- asked for one, so it leaves the product the same way the other two did.
      ('Identified_Threat', 'Description');

    DECLARE dead CURSOR LOCAL FAST_FORWARD FOR SELECT TableName, ColumnName FROM @dead;
    OPEN dead;
    FETCH NEXT FROM dead INTO @tbl, @oldcol;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        IF OBJECT_ID('dbo.' + QUOTENAME(@tbl), 'U') IS NOT NULL
           AND COL_LENGTH('dbo.' + QUOTENAME(@tbl), @oldcol) IS NOT NULL
        BEGIN
            /* A UNIQUE index over this column is NEVER dropped. Older databases
               carry wider natural keys that included this column, and the narrower
               replacement often cannot be created because the data holds duplicates
               that the wider key allowed. Dropping it and failing to recreate it
               would leave the table with no unique guard at all, and several of
               these are checked when the application starts. Report and keep the
               column instead; the operator resolves the duplicates first. */
            SET @blockingUx = NULL;
            SELECT TOP 1 @blockingUx = i.name
            FROM sys.indexes i
            JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
            JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
            WHERE i.object_id = OBJECT_ID('dbo.' + QUOTENAME(@tbl))
              AND i.name IS NOT NULL AND i.is_primary_key = 0 AND i.is_unique = 1
              AND c.name = @oldcol
            ORDER BY i.name;
        END

        IF @blockingUx IS NOT NULL
        BEGIN
            INSERT #report VALUES ('COLUMN KEPT, IN A UNIQUE INDEX', @tbl + '.' + @oldcol,
                'Not dropped. It is part of the unique index ' + @blockingUx
                + ', whose narrower replacement may not be creatable if the data holds '
                + 'duplicates the wider key allowed. Check for duplicates, resolve them, '
                + 'drop that index by hand, then re-run this script.');
            SET @blockingUx = NULL;
        END
        ELSE IF OBJECT_ID('dbo.' + QUOTENAME(@tbl), 'U') IS NOT NULL
           AND COL_LENGTH('dbo.' + QUOTENAME(@tbl), @oldcol) IS NOT NULL
        BEGIN
            -- Only non-unique indexes are dropped here; Section 6 rebuilds them.
            DECLARE deadix CURSOR LOCAL FAST_FORWARD FOR
                SELECT DISTINCT i.name
                FROM sys.indexes i
                LEFT JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
                LEFT JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
                WHERE i.object_id = OBJECT_ID('dbo.' + QUOTENAME(@tbl))
                  AND i.name IS NOT NULL AND i.is_primary_key = 0 AND i.is_unique = 0
                  AND (c.name = @oldcol
                       OR (i.has_filter = 1 AND CHARINDEX(QUOTENAME(@oldcol), i.filter_definition) > 0));
            OPEN deadix;
            FETCH NEXT FROM deadix INTO @ixname;
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @sql = N'DROP INDEX ' + QUOTENAME(@ixname) + N' ON dbo.' + QUOTENAME(@tbl) + N';';
                IF @preview = 1 PRINT '  would run: ' + @sql;
                ELSE
                BEGIN TRY EXEC sys.sp_executesql @sql; PRINT '  applied: ' + @sql; END TRY
                BEGIN CATCH INSERT #report VALUES ('DROP FAILED', @tbl + '.' + @oldcol, ERROR_MESSAGE()); END CATCH
                FETCH NEXT FROM deadix INTO @ixname;
            END
            CLOSE deadix; DEALLOCATE deadix;

            SET @sql = N'ALTER TABLE dbo.' + QUOTENAME(@tbl) + N' DROP COLUMN ' + QUOTENAME(@oldcol) + N';';
            IF @preview = 1
                PRINT '  would PERMANENTLY DELETE column ' + @tbl + '.' + @oldcol + '.';
            ELSE
            BEGIN TRY
                EXEC sys.sp_executesql @sql;
                PRINT '  removed column ' + @tbl + '.' + @oldcol + ' (no longer part of the product).';
                IF @tbl = 'Threat_Catalogue' AND @oldcol = 'Description'
                    PRINT '  *** RE-RUN GROUNDING CALIBRATION: threat matching is now name-only, and the stored threshold was measured against the text just removed. ***';
            END TRY
            BEGIN CATCH INSERT #report VALUES ('DROP FAILED', @tbl + '.' + @oldcol, ERROR_MESSAGE()); END CATCH
        END
        FETCH NEXT FROM dead INTO @tbl, @oldcol;
    END
    CLOSE dead; DEALLOCATE dead;
END
ELSE
    PRINT '  DropRemovedColumns = 0: the five removed columns are left in place.';
GO


/*==============================================================================
  SECTION 2 — Tables
==============================================================================*/

/****** Table: API_Client — one row per calling system; stores only the SHA-256
        hash of the key, never the key itself. ******/
IF OBJECT_ID('dbo.API_Client', 'U') IS NULL
CREATE TABLE [dbo].[API_Client](
	[ClientID] [nvarchar](100) NOT NULL,
	[KeyHash] [nvarchar](100) NOT NULL,
	[Name] [nvarchar](200) NOT NULL,
	[Module] [nvarchar](100) NOT NULL,
	[Active] [bit] NOT NULL,
	[CreatedAt] [datetime2](3) NOT NULL,
	[CreatedBy] [nvarchar](200) NULL,
	[RevokedAt] [datetime2](3) NULL,
	[RevokedBy] [nvarchar](200) NULL,
 CONSTRAINT [PK_API_Client] PRIMARY KEY CLUSTERED
(
	[ClientID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO

/****** Table: Config_Tuning — runtime business-calibration overrides.
        CreateDate/UpdateDate are deliberate; see the header. ******/
IF OBJECT_ID('dbo.Config_Tuning', 'U') IS NULL
CREATE TABLE [dbo].[Config_Tuning](
	[TuningID] [int] IDENTITY(1,1) NOT NULL,
	[TuningKey] [nvarchar](100) NOT NULL,
	[TuningValue] [nvarchar](100) NOT NULL,
	[ValueType] [nvarchar](100) NOT NULL,
	[EmbeddingModel] [nvarchar](200) NULL,
	[CreateDate] [datetime2](7) NULL,
	[CreatedBy] [nvarchar](200) NULL,
	[UpdateDate] [datetime2](7) NULL,
	[UpdatedBy] [nvarchar](200) NULL,
	[IsActive] [bit] NOT NULL,
	[IsDeleted] [bit] NOT NULL,
 CONSTRAINT [PK_Config_Tuning] PRIMARY KEY CLUSTERED
(
	[TuningID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY],
 CONSTRAINT [UQ_Config_Tuning_Key] UNIQUE NONCLUSTERED
(
	[TuningKey] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO

/****** Table: Control_Library — the approved control catalogue. ******/
IF OBJECT_ID('dbo.Control_Library', 'U') IS NULL
CREATE TABLE [dbo].[Control_Library](
	[ControlLibraryID] [int] IDENTITY(1,1) NOT NULL,
	[ControlCode] [nvarchar](100) NOT NULL,
	[ITOT] [nvarchar](100) NOT NULL,
	[Domain] [nvarchar](200) NOT NULL,
	[ControlName] [nvarchar](500) NOT NULL,
	[ControlDescription] [nvarchar](max) NOT NULL,
	[SampleEvidence] [nvarchar](max) NULL,
	[Source] [nvarchar](100) NULL,
	[CreatedAt] [datetime] NOT NULL,
	[CreatedBy] [nvarchar](200) NULL,
	[UpdatedAt] [datetime] NULL,
	[UpdatedBy] [nvarchar](200) NULL,
	[IsActive] [bit] NOT NULL,
	[IsDeleted] [bit] NOT NULL,
 CONSTRAINT [PK_Control_Library] PRIMARY KEY CLUSTERED
(
	[ControlLibraryID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO

/****** Table: Control_Library_Standard_Map — control to standard, many-to-many. ******/
IF OBJECT_ID('dbo.Control_Library_Standard_Map', 'U') IS NULL
CREATE TABLE [dbo].[Control_Library_Standard_Map](
	[ControlLibraryID] [int] NOT NULL,
	[StandardID] [int] NOT NULL,
	[CreatedAt] [datetime2](7) NULL,
 CONSTRAINT [PK_Control_Library_Standard_Map] PRIMARY KEY CLUSTERED
(
	[ControlLibraryID] ASC,
	[StandardID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO

/****** Table: Control_Standard — the standards controls are attributed to. ******/
IF OBJECT_ID('dbo.Control_Standard', 'U') IS NULL
CREATE TABLE [dbo].[Control_Standard](
	[StandardID] [int] IDENTITY(1,1) NOT NULL,
	[StandardName] [nvarchar](200) NOT NULL,
	[Source] [nvarchar](100) NULL,
	[CreatedAt] [datetime] NOT NULL,
	[CreatedBy] [nvarchar](200) NULL,
	[UpdatedAt] [datetime] NULL,
	[UpdatedBy] [nvarchar](200) NULL,
	[IsActive] [bit] NOT NULL,
	[IsDeleted] [bit] NOT NULL,
 CONSTRAINT [PK_Control_Standard] PRIMARY KEY CLUSTERED
(
	[StandardID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO

/****** Table: Grounding_Calibration_Run — one row per calibration sweep. The
        MatchTh column on the latest successful row IS the live threshold. ******/
IF OBJECT_ID('dbo.Grounding_Calibration_Run', 'U') IS NULL
CREATE TABLE [dbo].[Grounding_Calibration_Run](
	[RunID] [uniqueidentifier] NOT NULL,
	[JobID] [nvarchar](100) NULL,
	[Status] [nvarchar](100) NOT NULL,
	[StartedBy] [nvarchar](200) NULL,
	[StartedByClient] [nvarchar](200) NULL,
	[StartedAt] [datetime2](7) NULL,
	[FinishedAt] [datetime2](7) NULL,
	[EmbeddingModel] [nvarchar](500) NULL,
	[RerankerModel] [nvarchar](500) NULL,
	[Forced] [bit] NOT NULL,
	[MatchTh] [float] NULL,
	[Quality] [float] NULL,
	[NegativesCount] [int] NULL,
	[PositivesCount] [int] NULL,
	[HighestNegative] [float] NULL,
	[LowestPositive] [float] NULL,
	[NearDuplicatesJSON] [nvarchar](max) NULL,
	[ErrorMessage] [nvarchar](max) NULL,
 CONSTRAINT [PK_Grounding_Calibration_Run] PRIMARY KEY CLUSTERED
(
	[RunID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO

/****** Table: Identified_Duplicate_Threat — audit trail of proposals dropped as
        duplicates. Written during identification and never read back. ******/
IF OBJECT_ID('dbo.Identified_Duplicate_Threat', 'U') IS NULL
CREATE TABLE [dbo].[Identified_Duplicate_Threat](
	[DuplicateThreatID] [uniqueidentifier] NOT NULL,
	[SessionID] [uniqueidentifier] NOT NULL,
	[TenantID] [nvarchar](200) NULL,
	[EntityID] [nvarchar](200) NULL,
	[UserID] [nvarchar](200) NULL,
	[SubsystemID] [int] NOT NULL,
	[ThreatCategory] [nvarchar](200) NOT NULL,
	[ThreatType] [nvarchar](300) NOT NULL,
	[ThreatName] [nvarchar](500) NULL,
	[GenericName] [nvarchar](500) NULL,
	[ThreatActorsJSON] [nvarchar](max) NULL,
	[DuplicateOfThreatID] [uniqueidentifier] NULL,
	[DuplicateReason] [nvarchar](100) NOT NULL,
	[SimilarityScore] [float] NULL,
	[CreatedAt] [datetime2](7) NULL,
 CONSTRAINT [PK_Identified_Duplicate_Threat] PRIMARY KEY CLUSTERED
(
	[DuplicateThreatID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO

/****** Table: Identified_Threat — one row per threat per unit of work.
        SubsystemID 0 is the asset itself; values of 1 and above are supporting
        systems. One threat legitimately produces several rows. ******/
IF OBJECT_ID('dbo.Identified_Threat', 'U') IS NULL
CREATE TABLE [dbo].[Identified_Threat](
	[ThreatID] [uniqueidentifier] NOT NULL,
	[SessionID] [uniqueidentifier] NOT NULL,
	[TenantID] [nvarchar](200) NULL,
	[EntityID] [nvarchar](200) NULL,
	[UserID] [nvarchar](200) NULL,
	[SubsystemID] [int] NOT NULL,
	[ThreatCategory] [nvarchar](200) NOT NULL,
	[ThreatType] [nvarchar](300) NOT NULL,
	[ThreatName] [nvarchar](500) NULL,
	[GenericName] [nvarchar](500) NULL,
	[ThreatCategoryID] [int] NULL,
	[ThreatActorsJSON] [nvarchar](max) NULL,
	[LibraryThreatType] [nvarchar](300) NULL,
	[LibraryThreatName] [nvarchar](500) NULL,
	[ThreatTypeID] [int] NULL,
	[ThreatCatalogueID] [int] NULL,
	[IsThreatAIGenerated] [bit] NOT NULL,
	[IsThreatTypeAIGenerated] [bit] NOT NULL,
	[GroundingStatus] [nvarchar](100) NOT NULL,
	[GroundingScore] [float] NULL,
	[Superseded] [int] NOT NULL,
	[CreatedAt] [datetime2](7) NULL,
	[GroundingThresholdOrigin] [nvarchar](100) NULL,
 CONSTRAINT [PK_Identified_Threat] PRIMARY KEY CLUSTERED
(
	[ThreatID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO

/****** Table: Prompt_Log — one row per model call, prompt and raw reply. The
        only place raw model output is stored, and the fastest-growing table
        here. Read back only through CorrelationID. ******/
IF OBJECT_ID('dbo.Prompt_Log', 'U') IS NULL
CREATE TABLE [dbo].[Prompt_Log](
	[LogID] [uniqueidentifier] NOT NULL,
	[SessionID] [uniqueidentifier] NOT NULL,
	[TenantID] [nvarchar](200) NULL,
	[EntityID] [nvarchar](200) NULL,
	[UserID] [nvarchar](200) NULL,
	[SubsystemID] [int] NOT NULL,
	[Stage] [nvarchar](100) NOT NULL,
	[PromptVersion] [nvarchar](100) NOT NULL,
	[Messages] [nvarchar](max) NOT NULL,
	[Prompt] [nvarchar](max) NULL,
	[ResponseText] [nvarchar](max) NULL,
	[Model] [nvarchar](200) NULL,
	[ModelVersion] [nvarchar](100) NULL,
	[ParseSucceeded] [bit] NOT NULL,
	[CreatedAt] [datetime2](7) NOT NULL,
	[CorrelationID] [uniqueidentifier] NULL,
 CONSTRAINT [PK_Prompt_Log] PRIMARY KEY CLUSTERED
(
	[LogID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO

/****** Table: Risk_Treatment_Plan — one remediation plan attempt per accepted
        scenario. At most one active row per scenario. ******/
IF OBJECT_ID('dbo.Risk_Treatment_Plan', 'U') IS NULL
CREATE TABLE [dbo].[Risk_Treatment_Plan](
	[PlanID] [uniqueidentifier] NOT NULL,
	[SessionID] [uniqueidentifier] NOT NULL,
	[ScenarioID] [uniqueidentifier] NOT NULL,
	[TenantID] [nvarchar](200) NULL,
	[EntityID] [nvarchar](200) NULL,
	[UserID] [nvarchar](200) NULL,
	[CrmRiskIdentificationID] [int] NULL,
	[TreatmentStrategy] [nvarchar](100) NOT NULL,
	[Status] [nvarchar](100) NOT NULL,
	[ActiveTaskID] [nvarchar](100) NULL,
	[RiskIdentificationDate] [datetime2](7) NULL,
	[InputSnapshotJSON] [nvarchar](max) NULL,
	[PlanJSON] [nvarchar](max) NULL,
	[ValidationJSON] [nvarchar](max) NULL,
	[ErrorMessage] [nvarchar](max) NULL,
	[Superseded] [int] NOT NULL,
	[CreatedAt] [datetime2](7) NULL,
	[UpdatedAt] [datetime2](7) NULL,
	[CompletedAt] [datetime2](7) NULL,
	[RiskLevel] [nvarchar](100) NULL,
	[ReviewStatus] [nvarchar](100) NULL,
	[ReviewComment] [nvarchar](max) NULL,
	[ReviewedBy] [nvarchar](200) NULL,
	[ReviewedAt] [datetime2](7) NULL,
	[ErrorReason] [nvarchar](max) NULL,
	[CancelledAt] [datetime2](7) NULL,
	[CancelledBy] [nvarchar](200) NULL,
 CONSTRAINT [PK_Risk_Treatment_Plan] PRIMARY KEY CLUSTERED
(
	[PlanID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO

/****** Table: Scenario_Audit — append-only ledger. SubsystemID 0 means the
        asset, NULL means session-wide; neither is a broken reference. ******/
IF OBJECT_ID('dbo.Scenario_Audit', 'U') IS NULL
CREATE TABLE [dbo].[Scenario_Audit](
	[AuditID] [uniqueidentifier] NOT NULL,
	[SessionID] [uniqueidentifier] NOT NULL,
	[TenantID] [nvarchar](200) NULL,
	[EntityID] [nvarchar](200) NULL,
	[Stage] [nvarchar](100) NULL,
	[SubsystemID] [int] NULL,
	[EventType] [nvarchar](100) NOT NULL,
	[ScenarioID] [uniqueidentifier] NULL,
	[PlanID] [uniqueidentifier] NULL,
	[Decision] [nvarchar](100) NULL,
	[Granularity] [nvarchar](100) NULL,
	[ThreatTypeRefID] [int] NULL,
	[ActorUserID] [nvarchar](200) NULL,
	[ActorType] [nvarchar](100) NULL,
	[DetailJSON] [nvarchar](max) NULL,
	[CreatedAt] [datetime2](7) NOT NULL,
 CONSTRAINT [PK_Scenario_Audit] PRIMARY KEY CLUSTERED
(
	[AuditID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO

/****** Table: Scenario_Session — one assessment run for one asset. ******/
IF OBJECT_ID('dbo.Scenario_Session', 'U') IS NULL
CREATE TABLE [dbo].[Scenario_Session](
	[SessionID] [uniqueidentifier] NOT NULL,
	[TenantID] [nvarchar](200) NOT NULL,
	[EntityID] [nvarchar](200) NOT NULL,
	[UserID] [nvarchar](200) NULL,
	[AssetName] [nvarchar](300) NOT NULL,
	[AssetID] [nvarchar](200) NOT NULL,
	[SessionStatus] [nvarchar](100) NOT NULL,
	[CurrentStage] [nvarchar](100) NOT NULL,
	[StageStatus] [nvarchar](100) NOT NULL,
	[Mode] [nvarchar](100) NOT NULL,
	[CurrentSubsystemIndex] [int] NULL,
	[SubsystemsJSON] [nvarchar](max) NOT NULL,
	[IdempotencyKey] [nvarchar](200) NULL,
	[SectorIDsJSON] [nvarchar](max) NULL,
	[AssetContextJSON] [nvarchar](max) NULL,
	[ScoringRulesSnapshotJSON] [nvarchar](max) NULL,
	[CreatedAt] [datetime2](7) NULL,
	[UpdatedAt] [datetime2](7) NULL,
	[CompletedAt] [datetime2](7) NULL,
	[CancelledAt] [datetime2](7) NULL,
	[CancelledBy] [nvarchar](200) NULL,
 CONSTRAINT [PK_Scenario_Session] PRIMARY KEY CLUSTERED
(
	[SessionID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO

/****** Table: Scoped_Threat — the scoring and selection decision per threat. ******/
IF OBJECT_ID('dbo.Scoped_Threat', 'U') IS NULL
CREATE TABLE [dbo].[Scoped_Threat](
	[ScopedThreatID] [uniqueidentifier] NOT NULL,
	[SessionID] [uniqueidentifier] NOT NULL,
	[TenantID] [nvarchar](200) NULL,
	[EntityID] [nvarchar](200) NULL,
	[UserID] [nvarchar](200) NULL,
	[SubsystemID] [int] NOT NULL,
	[ThreatID] [uniqueidentifier] NOT NULL,
	[Score] [float] NOT NULL,
	[ScopeRank] [int] NOT NULL,
	[Selected] [int] NOT NULL,
	[Reason] [nvarchar](500) NULL,
	[RejectionKind] [nvarchar](100) NULL,
	[SelectionKind] [nvarchar](100) NULL,
	[FactorsJSON] [nvarchar](max) NULL,
	[Superseded] [int] NOT NULL,
	[CreatedAt] [datetime2](7) NULL,
 CONSTRAINT [PK_Scoped_Threat] PRIMARY KEY CLUSTERED
(
	[ScopedThreatID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO

/****** Table: Subsystem_Stage_State — the pipeline state machine. One row per
        (session, unit, level). Level '_LOCK' rows are mutexes, not work. ******/
IF OBJECT_ID('dbo.Subsystem_Stage_State', 'U') IS NULL
CREATE TABLE [dbo].[Subsystem_Stage_State](
	[StateID] [uniqueidentifier] NOT NULL,
	[SessionID] [uniqueidentifier] NOT NULL,
	[TenantID] [nvarchar](200) NULL,
	[EntityID] [nvarchar](200) NULL,
	[SubsystemID] [int] NOT NULL,
	[Level] [nvarchar](100) NOT NULL,
	[Status] [nvarchar](100) NOT NULL,
	[GenerationEpoch] [int] NOT NULL,
	[ActiveTaskID] [uniqueidentifier] NULL,
	[LeaseExpiresAt] [datetime2](7) NULL,
	[HeartbeatAt] [datetime2](7) NULL,
	[AttemptCount] [int] NOT NULL,
	[ErrorMessage] [nvarchar](max) NULL,
	[UpdatedAt] [datetime2](7) NOT NULL,
	[CreatedAt] [datetime2](7) NULL,
 CONSTRAINT [PK_Subsystem_Stage_State] PRIMARY KEY CLUSTERED
(
	[StateID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO

/****** Table: Threat_Actor — library master. ******/
IF OBJECT_ID('dbo.Threat_Actor', 'U') IS NULL
CREATE TABLE [dbo].[Threat_Actor](
	[ThreatActorID] [int] IDENTITY(1,1) NOT NULL,
	[ThreatActorName] [nvarchar](200) NOT NULL,
	[IsCapable] [int] NOT NULL,
	[IsActive] [bit] NOT NULL,
	[IsDeleted] [bit] NOT NULL,
	[Source] [nvarchar](100) NULL,
	[CreatedAt] [datetime2](7) NULL,
	[CreatedBy] [nvarchar](200) NULL,
	[UpdatedAt] [datetime2](7) NULL,
	[UpdatedBy] [nvarchar](200) NULL,
 CONSTRAINT [PK_Threat_Actor] PRIMARY KEY CLUSTERED
(
	[ThreatActorID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO

/****** Table: Threat_Catalogue — library master, the named threats. ******/
IF OBJECT_ID('dbo.Threat_Catalogue', 'U') IS NULL
CREATE TABLE [dbo].[Threat_Catalogue](
	[ThreatCatalogueID] [int] IDENTITY(1,1) NOT NULL,
	[ThreatTypeID] [int] NOT NULL,
	[ThreatName] [nvarchar](500) NOT NULL,
	[IsActive] [bit] NOT NULL,
	[IsDeleted] [bit] NOT NULL,
	[CreatedAt] [datetime2](7) NULL,
	[CreatedBy] [nvarchar](200) NULL,
	[UpdatedAt] [datetime2](7) NULL,
	[UpdatedBy] [nvarchar](200) NULL,
	[Source] [nvarchar](100) NULL,
 CONSTRAINT [PK_Threat_Catalogue] PRIMARY KEY CLUSTERED
(
	[ThreatCatalogueID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO

/* Widen Source to match the application, for databases created before this
   script where the column was nvarchar(50). No-op otherwise. */
IF COLUMNPROPERTY(OBJECT_ID('dbo.Threat_Catalogue'), 'Source', 'CharMaxLen') < 100
    ALTER TABLE [dbo].[Threat_Catalogue] ALTER COLUMN [Source] [nvarchar](100) NULL;
GO

/****** Table: Threat_Catalogue_Category_Map — threat to STRIDE category.
        Category leads the key; the order is load-bearing for the lookup. ******/
IF OBJECT_ID('dbo.Threat_Catalogue_Category_Map', 'U') IS NULL
CREATE TABLE [dbo].[Threat_Catalogue_Category_Map](
	[ThreatCatalogueID] [int] NOT NULL,
	[ThreatCategoryID] [int] NOT NULL,
	[CreatedAt] [datetime2](7) NULL,
 CONSTRAINT [PK_Threat_Catalogue_Category_Map] PRIMARY KEY CLUSTERED
(
	[ThreatCategoryID] ASC,
	[ThreatCatalogueID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO

/****** Table: Threat_Category — the six STRIDE categories. Plain int primary
        key, NOT an identity: the ids are fixed and supplied by the seed. ******/
IF OBJECT_ID('dbo.Threat_Category', 'U') IS NULL
CREATE TABLE [dbo].[Threat_Category](
	[ThreatCategoryID] [int] NOT NULL,
	[ThreatCategoryName] [nvarchar](200) NOT NULL,
	[ThreatCategoryCode] [nvarchar](100) NULL,
	[IsActive] [bit] NOT NULL,
	[IsDeleted] [bit] NOT NULL,
	[CreatedAt] [datetime2](7) NULL,
	[CreatedBy] [nvarchar](200) NULL,
	[UpdatedAt] [datetime2](7) NULL,
	[UpdatedBy] [nvarchar](200) NULL,
 CONSTRAINT [PK_Threat_Category] PRIMARY KEY CLUSTERED
(
	[ThreatCategoryID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO

/****** Table: Threat_Scenario — the generated narratives and the review
        decision on each. Versions are retired, never deleted. ******/
IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NULL
CREATE TABLE [dbo].[Threat_Scenario](
	[ScenarioID] [uniqueidentifier] NOT NULL,
	[SessionID] [uniqueidentifier] NOT NULL,
	[TenantID] [nvarchar](200) NULL,
	[EntityID] [nvarchar](200) NULL,
	[UserID] [nvarchar](200) NULL,
	[SubsystemID] [int] NOT NULL,
	[ScopedThreatID] [uniqueidentifier] NOT NULL,
	[Status] [nvarchar](100) NOT NULL,
	[ScenarioJSON] [nvarchar](max) NULL,
	[ValidationJSON] [nvarchar](max) NULL,
	[AcceptedSubsetJSON] [nvarchar](max) NULL,
	[Accepted] [int] NOT NULL,
	[Superseded] [int] NOT NULL,
	[IdentityHash] [nvarchar](100) NULL,
	[ScenarioNumber] [int] NOT NULL,
	[ReplacesScenarioID] [uniqueidentifier] NULL,
	[GenerationEpoch] [int] NOT NULL,
	[ErrorMessage] [nvarchar](max) NULL,
	[CreatedAt] [datetime2](7) NULL,
	[ControlsMappedAt] [datetime2](7) NULL,
	[RejectedAt] [datetime2](7) NULL,
	[RejectedBy] [nvarchar](200) NULL,
	[AcceptedAt] [datetime2](7) NULL,
	[AcceptedBy] [nvarchar](200) NULL,
	[ScenarioSource] [nvarchar](100) NULL,
 CONSTRAINT [PK_Threat_Scenario] PRIMARY KEY CLUSTERED
(
	[ScenarioID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO

/****** Table: Threat_Scenario_Control_Map — which controls mitigate a
        scenario. The composite key doubles as the duplicate guard. ******/
IF OBJECT_ID('dbo.Threat_Scenario_Control_Map', 'U') IS NULL
CREATE TABLE [dbo].[Threat_Scenario_Control_Map](
	[ScenarioID] [uniqueidentifier] NOT NULL,
	[ControlLibraryID] [int] NOT NULL,
	[SessionID] [uniqueidentifier] NOT NULL,
	[MapRank] [int] NOT NULL,
	[Score] [float] NULL,
	[SuggestedControl] [nvarchar](500) NULL,
	[CreatedAt] [datetime2](7) NULL,
 CONSTRAINT [PK_Threat_Scenario_Control_Map] PRIMARY KEY CLUSTERED
(
	[ScenarioID] ASC,
	[ControlLibraryID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO

/****** Table: Threat_Type — library master, the type above each threat. ******/
IF OBJECT_ID('dbo.Threat_Type', 'U') IS NULL
CREATE TABLE [dbo].[Threat_Type](
	[ThreatTypeID] [int] IDENTITY(1,1) NOT NULL,
	[ThreatTypeName] [nvarchar](300) NOT NULL,
	[ThreatCategoryID] [int] NULL,
	[IsActive] [bit] NOT NULL,
	[IsDeleted] [bit] NOT NULL,
	[CreatedAt] [datetime2](7) NULL,
	[CreatedBy] [nvarchar](200) NULL,
	[UpdatedAt] [datetime2](7) NULL,
	[UpdatedBy] [nvarchar](200) NULL,
	[Source] [nvarchar](50) NULL,
 CONSTRAINT [PK_Threat_Type] PRIMARY KEY CLUSTERED
(
	[ThreatTypeID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO

/****** Table: ThreatType_ThreatActor_Map — type to actor, many-to-many. ******/
IF OBJECT_ID('dbo.ThreatType_ThreatActor_Map', 'U') IS NULL
CREATE TABLE [dbo].[ThreatType_ThreatActor_Map](
	[ThreatTypeID] [int] NOT NULL,
	[ThreatActorID] [int] NOT NULL,
	[CreatedAt] [datetime2](7) NULL,
 CONSTRAINT [PK_ThreatType_ThreatActor_Map] PRIMARY KEY CLUSTERED
(
	[ThreatTypeID] ASC,
	[ThreatActorID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO


/*==============================================================================
  SECTION 3 — Column reconciliation and one-time data fixes

  Section 2 creates a table only when it is absent. This section handles the other
  case: the table is already there but its columns have drifted from what the
  application expects. It compares every column against the manifest below and
  closes the gaps it can close safely.

  FIXED AUTOMATICALLY
    * a missing column is added
    * a text column narrower than required is widened
    * a column marked NOT NULL that should allow NULL is relaxed

  REPORTED, NEVER CHANGED
    * a different base datatype, because converting rewrites the data
    * a column that should be NOT NULL but currently allows NULL, because the
      tightening fails if any row holds NULL
    * a change blocked by an index or a check constraint over the column
    * a column present in the database but absent from the manifest

  A column is never narrowed and never dropped.

  WHY THIS SECTION RUNS HERE: it must follow Section 2, which creates absent
  tables, and precede the sections that add defaults, check constraints and
  indexes. A check constraint or an index over a column blocks ALTER COLUMN with
  Msg 5074, so creating them first would make a needed widening impossible.

  NOT RECONCILED, by design: primary key shape, collation and computed columns.
  Missing indexes are reported by Section 7.
==============================================================================*/

-- The preview switch is set once, in Section 0.
DECLARE @PreviewOnly bit = (SELECT PreviewOnly FROM #opt);

/* What every column should be. Generated from the CREATE TABLE statements above and
   checked against them, so the two cannot drift apart.
     MaxLen  - characters for text types, -1 for max, NULL for other types
     Scale   - datetime2 precision, NULL for other types
     DefName - the default constraint this script defines, when it has one. A NOT NULL
               column can only be added to a populated table if it has one.            */
IF OBJECT_ID('tempdb..#want') IS NOT NULL DROP TABLE #want;
CREATE TABLE #want (
    TableName  sysname,
    ColumnName sysname,
    TypeName   sysname,
    MaxLen     int           NULL,
    Scale      int           NULL,
    IsNullable bit           NOT NULL,
    IsIdentity bit           NOT NULL,
    DefName    sysname       NULL,
    DefExpr    nvarchar(200) NULL
);

INSERT INTO #want
    (TableName, ColumnName, TypeName, MaxLen, Scale, IsNullable, IsIdentity, DefName, DefExpr)
VALUES
  -- API_Client
  ('API_Client','ClientID','nvarchar',100,NULL,0,0,NULL,NULL),
  ('API_Client','KeyHash','nvarchar',100,NULL,0,0,NULL,NULL),
  ('API_Client','Name','nvarchar',200,NULL,0,0,NULL,NULL),
  ('API_Client','Module','nvarchar',100,NULL,0,0,'DF_API_Client_Module','''tsg'''),
  ('API_Client','Active','bit',NULL,NULL,0,0,'DF_API_Client_Active','(1)'),
  ('API_Client','CreatedAt','datetime2',NULL,3,0,0,'DF_API_Client_CreatedAt','sysutcdatetime()'),
  ('API_Client','CreatedBy','nvarchar',200,NULL,1,0,NULL,NULL),
  ('API_Client','RevokedAt','datetime2',NULL,3,1,0,NULL,NULL),
  ('API_Client','RevokedBy','nvarchar',200,NULL,1,0,NULL,NULL),
  -- Config_Tuning
  ('Config_Tuning','TuningID','int',NULL,NULL,0,1,NULL,NULL),
  ('Config_Tuning','TuningKey','nvarchar',100,NULL,0,0,NULL,NULL),
  ('Config_Tuning','TuningValue','nvarchar',100,NULL,0,0,NULL,NULL),
  ('Config_Tuning','ValueType','nvarchar',100,NULL,0,0,NULL,NULL),
  ('Config_Tuning','EmbeddingModel','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Config_Tuning','CreateDate','datetime2',NULL,7,1,0,NULL,NULL),
  ('Config_Tuning','CreatedBy','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Config_Tuning','UpdateDate','datetime2',NULL,7,1,0,NULL,NULL),
  ('Config_Tuning','UpdatedBy','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Config_Tuning','IsActive','bit',NULL,NULL,0,0,'DF_Config_Tuning_IsActive','(1)'),
  ('Config_Tuning','IsDeleted','bit',NULL,NULL,0,0,'DF_Config_Tuning_IsDeleted','(0)'),
  -- Control_Library
  ('Control_Library','ControlLibraryID','int',NULL,NULL,0,1,NULL,NULL),
  ('Control_Library','ControlCode','nvarchar',100,NULL,0,0,NULL,NULL),
  ('Control_Library','ITOT','nvarchar',100,NULL,0,0,NULL,NULL),
  ('Control_Library','Domain','nvarchar',200,NULL,0,0,NULL,NULL),
  ('Control_Library','ControlName','nvarchar',500,NULL,0,0,NULL,NULL),
  ('Control_Library','ControlDescription','nvarchar',-1,NULL,0,0,NULL,NULL),
  ('Control_Library','SampleEvidence','nvarchar',-1,NULL,1,0,NULL,NULL),
  ('Control_Library','Source','nvarchar',100,NULL,1,0,NULL,NULL),
  ('Control_Library','CreatedAt','datetime',NULL,NULL,0,0,'DF_Control_Library_CreatedAt','sysutcdatetime()'),
  ('Control_Library','CreatedBy','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Control_Library','UpdatedAt','datetime',NULL,NULL,1,0,NULL,NULL),
  ('Control_Library','UpdatedBy','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Control_Library','IsActive','bit',NULL,NULL,0,0,'DF_Control_Library_IsActive','(1)'),
  ('Control_Library','IsDeleted','bit',NULL,NULL,0,0,'DF_Control_Library_IsDeleted','(0)'),
  -- Control_Library_Standard_Map
  ('Control_Library_Standard_Map','ControlLibraryID','int',NULL,NULL,0,0,NULL,NULL),
  ('Control_Library_Standard_Map','StandardID','int',NULL,NULL,0,0,NULL,NULL),
  ('Control_Library_Standard_Map','CreatedAt','datetime2',NULL,7,1,0,'DF_ControlStdMap_CreatedAt','sysutcdatetime()'),
  -- Control_Standard
  ('Control_Standard','StandardID','int',NULL,NULL,0,1,NULL,NULL),
  ('Control_Standard','StandardName','nvarchar',200,NULL,0,0,NULL,NULL),
  ('Control_Standard','Source','nvarchar',100,NULL,1,0,NULL,NULL),
  ('Control_Standard','CreatedAt','datetime',NULL,NULL,0,0,'DF_Control_Standard_CreatedAt','sysutcdatetime()'),
  ('Control_Standard','CreatedBy','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Control_Standard','UpdatedAt','datetime',NULL,NULL,1,0,NULL,NULL),
  ('Control_Standard','UpdatedBy','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Control_Standard','IsActive','bit',NULL,NULL,0,0,'DF_Control_Standard_IsActive','(1)'),
  ('Control_Standard','IsDeleted','bit',NULL,NULL,0,0,'DF_Control_Standard_IsDeleted','(0)'),
  -- Grounding_Calibration_Run
  ('Grounding_Calibration_Run','RunID','uniqueidentifier',NULL,NULL,0,0,NULL,NULL),
  ('Grounding_Calibration_Run','JobID','nvarchar',100,NULL,1,0,NULL,NULL),
  ('Grounding_Calibration_Run','Status','nvarchar',100,NULL,0,0,NULL,NULL),
  ('Grounding_Calibration_Run','StartedBy','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Grounding_Calibration_Run','StartedByClient','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Grounding_Calibration_Run','StartedAt','datetime2',NULL,7,1,0,NULL,NULL),
  ('Grounding_Calibration_Run','FinishedAt','datetime2',NULL,7,1,0,NULL,NULL),
  ('Grounding_Calibration_Run','EmbeddingModel','nvarchar',500,NULL,1,0,NULL,NULL),
  ('Grounding_Calibration_Run','RerankerModel','nvarchar',500,NULL,1,0,NULL,NULL),
  ('Grounding_Calibration_Run','Forced','bit',NULL,NULL,0,0,'DF_GroundingCalibration_Forced','(0)'),
  ('Grounding_Calibration_Run','MatchTh','float',NULL,NULL,1,0,NULL,NULL),
  ('Grounding_Calibration_Run','Quality','float',NULL,NULL,1,0,NULL,NULL),
  ('Grounding_Calibration_Run','NegativesCount','int',NULL,NULL,1,0,NULL,NULL),
  ('Grounding_Calibration_Run','PositivesCount','int',NULL,NULL,1,0,NULL,NULL),
  ('Grounding_Calibration_Run','HighestNegative','float',NULL,NULL,1,0,NULL,NULL),
  ('Grounding_Calibration_Run','LowestPositive','float',NULL,NULL,1,0,NULL,NULL),
  ('Grounding_Calibration_Run','NearDuplicatesJSON','nvarchar',-1,NULL,1,0,NULL,NULL),
  ('Grounding_Calibration_Run','ErrorMessage','nvarchar',-1,NULL,1,0,NULL,NULL),
  -- Identified_Duplicate_Threat
  ('Identified_Duplicate_Threat','DuplicateThreatID','uniqueidentifier',NULL,NULL,0,0,NULL,NULL),
  ('Identified_Duplicate_Threat','SessionID','uniqueidentifier',NULL,NULL,0,0,NULL,NULL),
  ('Identified_Duplicate_Threat','TenantID','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Identified_Duplicate_Threat','EntityID','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Identified_Duplicate_Threat','UserID','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Identified_Duplicate_Threat','SubsystemID','int',NULL,NULL,0,0,NULL,NULL),
  ('Identified_Duplicate_Threat','ThreatCategory','nvarchar',200,NULL,0,0,NULL,NULL),
  ('Identified_Duplicate_Threat','ThreatType','nvarchar',300,NULL,0,0,NULL,NULL),
  ('Identified_Duplicate_Threat','ThreatName','nvarchar',500,NULL,1,0,NULL,NULL),
  ('Identified_Duplicate_Threat','GenericName','nvarchar',500,NULL,1,0,NULL,NULL),
  ('Identified_Duplicate_Threat','ThreatActorsJSON','nvarchar',-1,NULL,1,0,NULL,NULL),
  ('Identified_Duplicate_Threat','DuplicateOfThreatID','uniqueidentifier',NULL,NULL,1,0,NULL,NULL),
  ('Identified_Duplicate_Threat','DuplicateReason','nvarchar',100,NULL,0,0,NULL,NULL),
  ('Identified_Duplicate_Threat','SimilarityScore','float',NULL,NULL,1,0,NULL,NULL),
  ('Identified_Duplicate_Threat','CreatedAt','datetime2',NULL,7,1,0,NULL,NULL),
  -- Identified_Threat
  ('Identified_Threat','ThreatID','uniqueidentifier',NULL,NULL,0,0,NULL,NULL),
  ('Identified_Threat','SessionID','uniqueidentifier',NULL,NULL,0,0,NULL,NULL),
  ('Identified_Threat','TenantID','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Identified_Threat','EntityID','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Identified_Threat','UserID','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Identified_Threat','SubsystemID','int',NULL,NULL,0,0,NULL,NULL),
  ('Identified_Threat','ThreatCategory','nvarchar',200,NULL,0,0,NULL,NULL),
  ('Identified_Threat','ThreatType','nvarchar',300,NULL,0,0,NULL,NULL),
  ('Identified_Threat','ThreatName','nvarchar',500,NULL,1,0,NULL,NULL),
  ('Identified_Threat','GenericName','nvarchar',500,NULL,1,0,NULL,NULL),
  ('Identified_Threat','ThreatCategoryID','int',NULL,NULL,1,0,NULL,NULL),
  ('Identified_Threat','ThreatActorsJSON','nvarchar',-1,NULL,1,0,NULL,NULL),
  ('Identified_Threat','LibraryThreatType','nvarchar',300,NULL,1,0,NULL,NULL),
  ('Identified_Threat','LibraryThreatName','nvarchar',500,NULL,1,0,NULL,NULL),
  ('Identified_Threat','ThreatTypeID','int',NULL,NULL,1,0,NULL,NULL),
  ('Identified_Threat','ThreatCatalogueID','int',NULL,NULL,1,0,NULL,NULL),
  ('Identified_Threat','IsThreatAIGenerated','bit',NULL,NULL,0,0,'DF_IdentifiedThreat_IsThreatAIGenerated','(0)'),
  ('Identified_Threat','IsThreatTypeAIGenerated','bit',NULL,NULL,0,0,'DF_IdentifiedThreat_IsThreatTypeAIGenerated','(0)'),
  ('Identified_Threat','GroundingStatus','nvarchar',100,NULL,0,0,NULL,NULL),
  ('Identified_Threat','GroundingScore','float',NULL,NULL,1,0,NULL,NULL),
  ('Identified_Threat','Superseded','int',NULL,NULL,0,0,NULL,NULL),
  ('Identified_Threat','CreatedAt','datetime2',NULL,7,1,0,NULL,NULL),
  ('Identified_Threat','GroundingThresholdOrigin','nvarchar',100,NULL,1,0,NULL,NULL),
  -- Prompt_Log
  ('Prompt_Log','LogID','uniqueidentifier',NULL,NULL,0,0,NULL,NULL),
  ('Prompt_Log','SessionID','uniqueidentifier',NULL,NULL,0,0,NULL,NULL),
  ('Prompt_Log','TenantID','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Prompt_Log','EntityID','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Prompt_Log','UserID','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Prompt_Log','SubsystemID','int',NULL,NULL,0,0,NULL,NULL),
  ('Prompt_Log','Stage','nvarchar',100,NULL,0,0,NULL,NULL),
  ('Prompt_Log','PromptVersion','nvarchar',100,NULL,0,0,NULL,NULL),
  ('Prompt_Log','Messages','nvarchar',-1,NULL,0,0,NULL,NULL),
  ('Prompt_Log','Prompt','nvarchar',-1,NULL,1,0,NULL,NULL),
  ('Prompt_Log','ResponseText','nvarchar',-1,NULL,1,0,NULL,NULL),
  ('Prompt_Log','Model','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Prompt_Log','ModelVersion','nvarchar',100,NULL,1,0,NULL,NULL),
  ('Prompt_Log','ParseSucceeded','bit',NULL,NULL,0,0,NULL,NULL),
  ('Prompt_Log','CreatedAt','datetime2',NULL,7,0,0,NULL,NULL),
  ('Prompt_Log','CorrelationID','uniqueidentifier',NULL,NULL,1,0,NULL,NULL),
  -- Risk_Treatment_Plan
  ('Risk_Treatment_Plan','PlanID','uniqueidentifier',NULL,NULL,0,0,NULL,NULL),
  ('Risk_Treatment_Plan','SessionID','uniqueidentifier',NULL,NULL,0,0,NULL,NULL),
  ('Risk_Treatment_Plan','ScenarioID','uniqueidentifier',NULL,NULL,0,0,NULL,NULL),
  ('Risk_Treatment_Plan','TenantID','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Risk_Treatment_Plan','EntityID','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Risk_Treatment_Plan','UserID','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Risk_Treatment_Plan','CrmRiskIdentificationID','int',NULL,NULL,1,0,NULL,NULL),
  ('Risk_Treatment_Plan','TreatmentStrategy','nvarchar',100,NULL,0,0,NULL,NULL),
  ('Risk_Treatment_Plan','Status','nvarchar',100,NULL,0,0,NULL,NULL),
  ('Risk_Treatment_Plan','ActiveTaskID','nvarchar',100,NULL,1,0,NULL,NULL),
  ('Risk_Treatment_Plan','RiskIdentificationDate','datetime2',NULL,7,1,0,NULL,NULL),
  ('Risk_Treatment_Plan','InputSnapshotJSON','nvarchar',-1,NULL,1,0,NULL,NULL),
  ('Risk_Treatment_Plan','PlanJSON','nvarchar',-1,NULL,1,0,NULL,NULL),
  ('Risk_Treatment_Plan','ValidationJSON','nvarchar',-1,NULL,1,0,NULL,NULL),
  ('Risk_Treatment_Plan','ErrorMessage','nvarchar',-1,NULL,1,0,NULL,NULL),
  ('Risk_Treatment_Plan','Superseded','int',NULL,NULL,0,0,'DF_TreatmentPlan_Superseded','(0)'),
  ('Risk_Treatment_Plan','CreatedAt','datetime2',NULL,7,1,0,NULL,NULL),
  ('Risk_Treatment_Plan','UpdatedAt','datetime2',NULL,7,1,0,NULL,NULL),
  ('Risk_Treatment_Plan','CompletedAt','datetime2',NULL,7,1,0,NULL,NULL),
  ('Risk_Treatment_Plan','RiskLevel','nvarchar',100,NULL,1,0,NULL,NULL),
  ('Risk_Treatment_Plan','ReviewStatus','nvarchar',100,NULL,1,0,NULL,NULL),
  ('Risk_Treatment_Plan','ReviewComment','nvarchar',-1,NULL,1,0,NULL,NULL),
  ('Risk_Treatment_Plan','ReviewedBy','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Risk_Treatment_Plan','ReviewedAt','datetime2',NULL,7,1,0,NULL,NULL),
  ('Risk_Treatment_Plan','ErrorReason','nvarchar',-1,NULL,1,0,NULL,NULL),
  ('Risk_Treatment_Plan','CancelledAt','datetime2',NULL,7,1,0,NULL,NULL),
  ('Risk_Treatment_Plan','CancelledBy','nvarchar',200,NULL,1,0,NULL,NULL),
  -- Scenario_Audit
  ('Scenario_Audit','AuditID','uniqueidentifier',NULL,NULL,0,0,NULL,NULL),
  ('Scenario_Audit','SessionID','uniqueidentifier',NULL,NULL,0,0,NULL,NULL),
  ('Scenario_Audit','TenantID','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Scenario_Audit','EntityID','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Scenario_Audit','Stage','nvarchar',100,NULL,1,0,NULL,NULL),
  ('Scenario_Audit','SubsystemID','int',NULL,NULL,1,0,NULL,NULL),
  ('Scenario_Audit','EventType','nvarchar',100,NULL,0,0,NULL,NULL),
  ('Scenario_Audit','ScenarioID','uniqueidentifier',NULL,NULL,1,0,NULL,NULL),
  ('Scenario_Audit','PlanID','uniqueidentifier',NULL,NULL,1,0,NULL,NULL),
  ('Scenario_Audit','Decision','nvarchar',100,NULL,1,0,NULL,NULL),
  ('Scenario_Audit','Granularity','nvarchar',100,NULL,1,0,NULL,NULL),
  ('Scenario_Audit','ThreatTypeRefID','int',NULL,NULL,1,0,NULL,NULL),
  ('Scenario_Audit','ActorUserID','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Scenario_Audit','ActorType','nvarchar',100,NULL,1,0,NULL,NULL),
  ('Scenario_Audit','DetailJSON','nvarchar',-1,NULL,1,0,NULL,NULL),
  ('Scenario_Audit','CreatedAt','datetime2',NULL,7,0,0,NULL,NULL),
  -- Scenario_Session
  ('Scenario_Session','SessionID','uniqueidentifier',NULL,NULL,0,0,NULL,NULL),
  ('Scenario_Session','TenantID','nvarchar',200,NULL,0,0,NULL,NULL),
  ('Scenario_Session','EntityID','nvarchar',200,NULL,0,0,NULL,NULL),
  ('Scenario_Session','UserID','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Scenario_Session','AssetName','nvarchar',300,NULL,0,0,NULL,NULL),
  ('Scenario_Session','AssetID','nvarchar',200,NULL,0,0,NULL,NULL),
  ('Scenario_Session','SessionStatus','nvarchar',100,NULL,0,0,NULL,NULL),
  ('Scenario_Session','CurrentStage','nvarchar',100,NULL,0,0,NULL,NULL),
  ('Scenario_Session','StageStatus','nvarchar',100,NULL,0,0,NULL,NULL),
  ('Scenario_Session','Mode','nvarchar',100,NULL,0,0,NULL,NULL),
  ('Scenario_Session','CurrentSubsystemIndex','int',NULL,NULL,1,0,NULL,NULL),
  ('Scenario_Session','SubsystemsJSON','nvarchar',-1,NULL,0,0,NULL,NULL),
  ('Scenario_Session','IdempotencyKey','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Scenario_Session','SectorIDsJSON','nvarchar',-1,NULL,1,0,NULL,NULL),
  ('Scenario_Session','AssetContextJSON','nvarchar',-1,NULL,1,0,NULL,NULL),
  ('Scenario_Session','ScoringRulesSnapshotJSON','nvarchar',-1,NULL,1,0,NULL,NULL),
  ('Scenario_Session','CreatedAt','datetime2',NULL,7,1,0,NULL,NULL),
  ('Scenario_Session','UpdatedAt','datetime2',NULL,7,1,0,NULL,NULL),
  ('Scenario_Session','CompletedAt','datetime2',NULL,7,1,0,NULL,NULL),
  ('Scenario_Session','CancelledAt','datetime2',NULL,7,1,0,NULL,NULL),
  ('Scenario_Session','CancelledBy','nvarchar',200,NULL,1,0,NULL,NULL),
  -- Scoped_Threat
  ('Scoped_Threat','ScopedThreatID','uniqueidentifier',NULL,NULL,0,0,NULL,NULL),
  ('Scoped_Threat','SessionID','uniqueidentifier',NULL,NULL,0,0,NULL,NULL),
  ('Scoped_Threat','TenantID','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Scoped_Threat','EntityID','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Scoped_Threat','UserID','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Scoped_Threat','SubsystemID','int',NULL,NULL,0,0,NULL,NULL),
  ('Scoped_Threat','ThreatID','uniqueidentifier',NULL,NULL,0,0,NULL,NULL),
  ('Scoped_Threat','Score','float',NULL,NULL,0,0,NULL,NULL),
  ('Scoped_Threat','ScopeRank','int',NULL,NULL,0,0,NULL,NULL),
  ('Scoped_Threat','Selected','int',NULL,NULL,0,0,NULL,NULL),
  ('Scoped_Threat','Reason','nvarchar',500,NULL,1,0,NULL,NULL),
  ('Scoped_Threat','RejectionKind','nvarchar',100,NULL,1,0,NULL,NULL),
  ('Scoped_Threat','SelectionKind','nvarchar',100,NULL,1,0,NULL,NULL),
  ('Scoped_Threat','FactorsJSON','nvarchar',-1,NULL,1,0,NULL,NULL),
  ('Scoped_Threat','Superseded','int',NULL,NULL,0,0,NULL,NULL),
  ('Scoped_Threat','CreatedAt','datetime2',NULL,7,1,0,NULL,NULL),
  -- Subsystem_Stage_State
  ('Subsystem_Stage_State','StateID','uniqueidentifier',NULL,NULL,0,0,NULL,NULL),
  ('Subsystem_Stage_State','SessionID','uniqueidentifier',NULL,NULL,0,0,NULL,NULL),
  ('Subsystem_Stage_State','TenantID','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Subsystem_Stage_State','EntityID','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Subsystem_Stage_State','SubsystemID','int',NULL,NULL,0,0,NULL,NULL),
  ('Subsystem_Stage_State','Level','nvarchar',100,NULL,0,0,NULL,NULL),
  ('Subsystem_Stage_State','Status','nvarchar',100,NULL,0,0,NULL,NULL),
  ('Subsystem_Stage_State','GenerationEpoch','int',NULL,NULL,0,0,NULL,NULL),
  ('Subsystem_Stage_State','ActiveTaskID','uniqueidentifier',NULL,NULL,1,0,NULL,NULL),
  ('Subsystem_Stage_State','LeaseExpiresAt','datetime2',NULL,7,1,0,NULL,NULL),
  ('Subsystem_Stage_State','HeartbeatAt','datetime2',NULL,7,1,0,NULL,NULL),
  ('Subsystem_Stage_State','AttemptCount','int',NULL,NULL,0,0,'DF_SSS_AttemptCount','(0)'),
  ('Subsystem_Stage_State','ErrorMessage','nvarchar',-1,NULL,1,0,NULL,NULL),
  ('Subsystem_Stage_State','UpdatedAt','datetime2',NULL,7,0,0,NULL,NULL),
  ('Subsystem_Stage_State','CreatedAt','datetime2',NULL,7,1,0,'DF_StageState_CreatedAt','sysutcdatetime()'),
  -- Threat_Actor
  ('Threat_Actor','ThreatActorID','int',NULL,NULL,0,1,NULL,NULL),
  ('Threat_Actor','ThreatActorName','nvarchar',200,NULL,0,0,NULL,NULL),
  ('Threat_Actor','IsCapable','int',NULL,NULL,0,0,NULL,NULL),
  ('Threat_Actor','IsActive','bit',NULL,NULL,0,0,NULL,NULL),
  ('Threat_Actor','IsDeleted','bit',NULL,NULL,0,0,NULL,NULL),
  ('Threat_Actor','Source','nvarchar',100,NULL,1,0,NULL,NULL),
  ('Threat_Actor','CreatedAt','datetime2',NULL,7,1,0,NULL,NULL),
  ('Threat_Actor','CreatedBy','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Threat_Actor','UpdatedAt','datetime2',NULL,7,1,0,NULL,NULL),
  ('Threat_Actor','UpdatedBy','nvarchar',200,NULL,1,0,NULL,NULL),
  -- Threat_Catalogue
  ('Threat_Catalogue','ThreatCatalogueID','int',NULL,NULL,0,1,NULL,NULL),
  ('Threat_Catalogue','ThreatTypeID','int',NULL,NULL,0,0,NULL,NULL),
  ('Threat_Catalogue','ThreatName','nvarchar',500,NULL,0,0,NULL,NULL),
  ('Threat_Catalogue','IsActive','bit',NULL,NULL,0,0,NULL,NULL),
  ('Threat_Catalogue','IsDeleted','bit',NULL,NULL,0,0,NULL,NULL),
  ('Threat_Catalogue','CreatedAt','datetime2',NULL,7,1,0,NULL,NULL),
  ('Threat_Catalogue','CreatedBy','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Threat_Catalogue','UpdatedAt','datetime2',NULL,7,1,0,NULL,NULL),
  ('Threat_Catalogue','UpdatedBy','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Threat_Catalogue','Source','nvarchar',100,NULL,1,0,NULL,NULL),
  -- Threat_Catalogue_Category_Map
  ('Threat_Catalogue_Category_Map','ThreatCatalogueID','int',NULL,NULL,0,0,NULL,NULL),
  ('Threat_Catalogue_Category_Map','ThreatCategoryID','int',NULL,NULL,0,0,NULL,NULL),
  ('Threat_Catalogue_Category_Map','CreatedAt','datetime2',NULL,7,1,0,'DF_CatCategoryMap_CreatedAt','sysutcdatetime()'),
  -- Threat_Category
  ('Threat_Category','ThreatCategoryID','int',NULL,NULL,0,0,NULL,NULL),
  ('Threat_Category','ThreatCategoryName','nvarchar',200,NULL,0,0,NULL,NULL),
  ('Threat_Category','ThreatCategoryCode','nvarchar',100,NULL,1,0,NULL,NULL),
  ('Threat_Category','IsActive','bit',NULL,NULL,0,0,NULL,NULL),
  ('Threat_Category','IsDeleted','bit',NULL,NULL,0,0,NULL,NULL),
  ('Threat_Category','CreatedAt','datetime2',NULL,7,1,0,NULL,NULL),
  ('Threat_Category','CreatedBy','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Threat_Category','UpdatedAt','datetime2',NULL,7,1,0,NULL,NULL),
  ('Threat_Category','UpdatedBy','nvarchar',200,NULL,1,0,NULL,NULL),
  -- Threat_Scenario
  ('Threat_Scenario','ScenarioID','uniqueidentifier',NULL,NULL,0,0,NULL,NULL),
  ('Threat_Scenario','SessionID','uniqueidentifier',NULL,NULL,0,0,NULL,NULL),
  ('Threat_Scenario','TenantID','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Threat_Scenario','EntityID','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Threat_Scenario','UserID','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Threat_Scenario','SubsystemID','int',NULL,NULL,0,0,NULL,NULL),
  ('Threat_Scenario','ScopedThreatID','uniqueidentifier',NULL,NULL,0,0,NULL,NULL),
  ('Threat_Scenario','Status','nvarchar',100,NULL,0,0,NULL,NULL),
  ('Threat_Scenario','ScenarioJSON','nvarchar',-1,NULL,1,0,NULL,NULL),
  ('Threat_Scenario','ValidationJSON','nvarchar',-1,NULL,1,0,NULL,NULL),
  ('Threat_Scenario','AcceptedSubsetJSON','nvarchar',-1,NULL,1,0,NULL,NULL),
  ('Threat_Scenario','Accepted','int',NULL,NULL,0,0,NULL,NULL),
  ('Threat_Scenario','Superseded','int',NULL,NULL,0,0,NULL,NULL),
  ('Threat_Scenario','IdentityHash','nvarchar',100,NULL,1,0,NULL,NULL),
  ('Threat_Scenario','ScenarioNumber','int',NULL,NULL,0,0,'DF_Scenario_ScenarioNumber','(1)'),
  ('Threat_Scenario','ReplacesScenarioID','uniqueidentifier',NULL,NULL,1,0,NULL,NULL),
  ('Threat_Scenario','GenerationEpoch','int',NULL,NULL,0,0,NULL,NULL),
  ('Threat_Scenario','ErrorMessage','nvarchar',-1,NULL,1,0,NULL,NULL),
  ('Threat_Scenario','CreatedAt','datetime2',NULL,7,1,0,NULL,NULL),
  ('Threat_Scenario','ControlsMappedAt','datetime2',NULL,7,1,0,NULL,NULL),
  ('Threat_Scenario','RejectedAt','datetime2',NULL,7,1,0,NULL,NULL),
  ('Threat_Scenario','RejectedBy','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Threat_Scenario','AcceptedAt','datetime2',NULL,7,1,0,NULL,NULL),
  ('Threat_Scenario','AcceptedBy','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Threat_Scenario','ScenarioSource','nvarchar',100,NULL,1,0,NULL,NULL),
  -- Threat_Scenario_Control_Map
  ('Threat_Scenario_Control_Map','ScenarioID','uniqueidentifier',NULL,NULL,0,0,NULL,NULL),
  ('Threat_Scenario_Control_Map','ControlLibraryID','int',NULL,NULL,0,0,NULL,NULL),
  ('Threat_Scenario_Control_Map','SessionID','uniqueidentifier',NULL,NULL,0,0,NULL,NULL),
  ('Threat_Scenario_Control_Map','MapRank','int',NULL,NULL,0,0,NULL,NULL),
  ('Threat_Scenario_Control_Map','Score','float',NULL,NULL,1,0,NULL,NULL),
  ('Threat_Scenario_Control_Map','SuggestedControl','nvarchar',500,NULL,1,0,NULL,NULL),
  ('Threat_Scenario_Control_Map','CreatedAt','datetime2',NULL,7,1,0,NULL,NULL),
  -- Threat_Type
  ('Threat_Type','ThreatTypeID','int',NULL,NULL,0,1,NULL,NULL),
  ('Threat_Type','ThreatTypeName','nvarchar',300,NULL,0,0,NULL,NULL),
  ('Threat_Type','ThreatCategoryID','int',NULL,NULL,1,0,NULL,NULL),
  ('Threat_Type','IsActive','bit',NULL,NULL,0,0,NULL,NULL),
  ('Threat_Type','IsDeleted','bit',NULL,NULL,0,0,NULL,NULL),
  ('Threat_Type','CreatedAt','datetime2',NULL,7,1,0,NULL,NULL),
  ('Threat_Type','CreatedBy','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Threat_Type','UpdatedAt','datetime2',NULL,7,1,0,NULL,NULL),
  ('Threat_Type','UpdatedBy','nvarchar',200,NULL,1,0,NULL,NULL),
  ('Threat_Type','Source','nvarchar',50,NULL,1,0,NULL,NULL),
  -- ThreatType_ThreatActor_Map
  ('ThreatType_ThreatActor_Map','ThreatTypeID','int',NULL,NULL,0,0,NULL,NULL),
  ('ThreatType_ThreatActor_Map','ThreatActorID','int',NULL,NULL,0,0,NULL,NULL),
  ('ThreatType_ThreatActor_Map','CreatedAt','datetime2',NULL,7,1,0,'DF_TypeActorMap_CreatedAt','sysutcdatetime()');

-- Findings go to the #report table Section 0 created, alongside Section 1's.

DECLARE @tbl sysname, @col sysname, @type sysname, @len int, @scale int,
        @isnull bit, @ident bit, @dname sysname, @dexpr nvarchar(200),
        @objid int, @colid int, @sql nvarchar(max), @blocker sysname,
        @curType sysname, @curLen int, @curScale int, @curNull bit, @inPK bit,
        @fixed int = 0;

PRINT 'Section 3: reconciling columns against the manifest...';

DECLARE want CURSOR LOCAL FAST_FORWARD FOR
    SELECT TableName, ColumnName, TypeName, MaxLen, Scale, IsNullable, IsIdentity, DefName, DefExpr
    FROM #want ORDER BY TableName, ColumnName;
OPEN want;
FETCH NEXT FROM want INTO @tbl, @col, @type, @len, @scale, @isnull, @ident, @dname, @dexpr;

WHILE @@FETCH_STATUS = 0
BEGIN
    SET @objid = OBJECT_ID('dbo.' + QUOTENAME(@tbl), 'U');
    SET @sql = NULL;
    SET @blocker = NULL;

    -- Table absent: Section 2 creates it, and Section 7 reports it if that failed.
    IF @objid IS NOT NULL
    BEGIN
        SET @colid = NULL;
        SELECT @colid = c.column_id,
               @curType = t.name,
               @curLen = CASE WHEN c.max_length = -1 THEN -1
                              WHEN t.name IN ('nvarchar', 'nchar') THEN c.max_length / 2
                              ELSE c.max_length END,
               @curScale = c.scale,
               @curNull = c.is_nullable
        FROM sys.columns c
        JOIN sys.types t ON t.user_type_id = c.user_type_id
        WHERE c.object_id = @objid AND c.name = @col;

        IF @colid IS NULL
        BEGIN
            ------------------------------------------------------------------ column missing
            /* On a preview run Section 1's renames have not happened, so a column it
               would rename into place still looks absent here. Reporting an ADD for it
               would tell the operator this script is about to duplicate a column, which
               is exactly the fault it was changed to prevent. Skip those. */
            IF @PreviewOnly = 1
               AND EXISTS (SELECT 1 FROM #pairs p
                           WHERE p.TableName = @tbl AND p.NewCol = @col
                             AND COL_LENGTH('dbo.' + QUOTENAME(@tbl), p.OldCol) IS NOT NULL)
                PRINT '  (Section 1 would rename an existing column into ' + @tbl + '.' + @col + ')';
            ELSE IF @ident = 1
                INSERT #report VALUES ('IDENTITY COLUMN MISSING', @tbl + '.' + @col,
                    'An identity column cannot be added to an existing table. Recreate the table.');
            ELSE
            BEGIN
                SET @sql = 'ALTER TABLE dbo.' + QUOTENAME(@tbl) + ' ADD ' + QUOTENAME(@col)
                         + ' ' + @type
                         + CASE WHEN @len IS NULL THEN ''
                                WHEN @len = -1 THEN '(max)'
                                ELSE '(' + CAST(@len AS varchar(10)) + ')' END
                         + CASE WHEN @scale IS NULL THEN ''
                                ELSE '(' + CAST(@scale AS varchar(2)) + ')' END;

                IF @isnull = 0 AND @dname IS NOT NULL
                    -- NOT NULL is only safe with a default: it backfills the existing rows.
                    SET @sql = @sql + ' NOT NULL CONSTRAINT ' + QUOTENAME(@dname)
                             + ' DEFAULT ' + @dexpr + ';';
                ELSE
                BEGIN
                    SET @sql = @sql + ' NULL;';
                    IF @isnull = 0
                        INSERT #report VALUES ('ADDED AS NULL, WANTS NOT NULL', @tbl + '.' + @col,
                            'No default is defined, so existing rows cannot be backfilled. '
                            + 'Populate it, then ALTER COLUMN ... NOT NULL by hand.');
                END
            END
        END
        ELSE
        BEGIN
            ------------------------------------------------------------------ column present
            SET @inPK = CASE WHEN EXISTS (
                    SELECT 1 FROM sys.index_columns ic
                    JOIN sys.indexes i ON i.object_id = ic.object_id AND i.index_id = ic.index_id
                    WHERE ic.object_id = @objid AND ic.column_id = @colid AND i.is_primary_key = 1)
                THEN 1 ELSE 0 END;

            IF @curType <> @type
                INSERT #report VALUES ('DATATYPE DIFFERS', @tbl + '.' + @col,
                    'Database has ' + @curType + ', expected ' + @type
                    + '. Not changed: converting rewrites the stored data.');

            /* Text column too narrow. -1 is nvarchar(max) and is never narrowed.
               The widen is attempted rather than predicted: SQL Server allows it on a
               column an index uses as a key, so long as the size only grows. If it is
               genuinely blocked the error handler names what blocks it. */
            ELSE IF @len IS NOT NULL AND @curLen <> -1 AND (@len = -1 OR @curLen < @len)
                SET @sql = 'ALTER TABLE dbo.' + QUOTENAME(@tbl) + ' ALTER COLUMN '
                         + QUOTENAME(@col) + ' ' + @type
                         + CASE WHEN @len = -1 THEN '(max)'
                                ELSE '(' + CAST(@len AS varchar(10)) + ')' END
                         + CASE WHEN @isnull = 1 THEN ' NULL;' ELSE ' NOT NULL;' END;

            -- datetime2 precision. Reported only; the application does not depend on it.
            ELSE IF @scale IS NOT NULL AND @curScale <> @scale
                INSERT #report VALUES ('PRECISION DIFFERS', @tbl + '.' + @col,
                    'Is ' + CAST(@curScale AS varchar(2)) + ', expected '
                    + CAST(@scale AS varchar(2)) + '. Harmless unless it is lower.');

            -- Nullability. Tightening can fail on existing rows; relaxing never does.
            ELSE IF @curNull = 1 AND @isnull = 0
                INSERT #report VALUES ('SHOULD BE NOT NULL', @tbl + '.' + @col,
                    'Allows NULL. Not changed: the change fails if any row holds NULL. '
                    + 'Backfill, then ALTER COLUMN ... NOT NULL by hand.');

            ELSE IF @curNull = 0 AND @isnull = 1
            BEGIN
                -- A primary key column can never be nullable, so that one is certain.
                IF @inPK = 1
                    INSERT #report VALUES ('SHOULD ALLOW NULL, BLOCKED', @tbl + '.' + @col,
                        'Is NOT NULL and is part of the primary key, so it cannot be relaxed.');
                ELSE
                    -- Left as NOT NULL, the application's own NULL writes would fail.
                    SET @sql = 'ALTER TABLE dbo.' + QUOTENAME(@tbl) + ' ALTER COLUMN '
                             + QUOTENAME(@col) + ' ' + @type
                             + CASE WHEN @len IS NULL THEN ''
                                    WHEN @len = -1 THEN '(max)'
                                    ELSE '(' + CAST(@len AS varchar(10)) + ')' END
                             + CASE WHEN @scale IS NULL THEN ''
                                    ELSE '(' + CAST(@scale AS varchar(2)) + ')' END
                             + ' NULL;';
            END
        END
    END

    ---------------------------------------------------------------------- apply
    IF @sql IS NOT NULL
    BEGIN
        IF @PreviewOnly = 1
            PRINT '  would run: ' + @sql;
        ELSE
        BEGIN
            -- Each statement stands alone: one blocked column must not abandon the rest.
            BEGIN TRY
                EXEC sys.sp_executesql @sql;
                PRINT '  applied: ' + @sql;
                SET @fixed += 1;
            END TRY
            BEGIN CATCH
                /* Name whatever depends on the column, so the operator knows what to
                   drop and recreate. CHARINDEX, not LIKE: a LIKE pattern would read the
                   brackets round the column name as a character class and match almost
                   anything. */
                SET @blocker = NULL;
                SELECT TOP 1 @blocker = b.obj FROM (
                    SELECT i.name AS obj
                      FROM sys.index_columns ic
                      JOIN sys.indexes i ON i.object_id = ic.object_id AND i.index_id = ic.index_id
                     WHERE ic.object_id = @objid AND ic.column_id = @colid AND i.name IS NOT NULL
                    UNION ALL
                    SELECT i.name FROM sys.indexes i
                     WHERE i.object_id = @objid AND i.has_filter = 1
                       AND CHARINDEX(QUOTENAME(@col), i.filter_definition) > 0
                    UNION ALL
                    SELECT k.name FROM sys.check_constraints k
                     WHERE k.parent_object_id = @objid
                       AND CHARINDEX(QUOTENAME(@col), k.definition) > 0
                ) b
                ORDER BY b.obj;   -- deterministic, so the report reads the same each run

                INSERT #report VALUES ('CHANGE FAILED', @tbl + '.' + @col,
                    ERROR_MESSAGE()
                    + CASE WHEN @blocker IS NULL THEN ''
                           ELSE ' Depends on ' + @blocker + '; drop it, re-run, and Section 6 '
                              + 'recreates it.' END);
            END CATCH
        END
    END

    FETCH NEXT FROM want INTO @tbl, @col, @type, @len, @scale, @isnull, @ident, @dname, @dexpr;
END
CLOSE want;
DEALLOCATE want;

-- Columns the database has that the application does not know about. Never dropped.
INSERT #report
SELECT 'UNEXPECTED COLUMN', t.name + '.' + c.name,
       'Present in the database, absent from the manifest. Left alone.'
FROM sys.tables t
JOIN sys.columns c ON c.object_id = t.object_id
WHERE t.name IN (SELECT DISTINCT TableName FROM #want)
  AND NOT EXISTS (SELECT 1 FROM #want w
                  WHERE w.TableName = t.name AND w.ColumnName = c.name);

DECLARE @findings int = (SELECT COUNT(*) FROM #report);
PRINT '  columns changed: ' + CAST(@fixed AS varchar(10))
    + ', findings so far: ' + CAST(@findings AS varchar(10));
GO

/*----------------------------------------------------------------------------
  3b. One-time data fixes, ported from 1. TSG_Core.sql.

  These correct rows written by earlier versions of the application. Each is
  idempotent: its WHERE clause matches nothing on a second run. They run here,
  after the reconciliation above, so the columns they write to are guaranteed to
  exist.
----------------------------------------------------------------------------*/
DECLARE @pv bit = (SELECT PreviewOnly FROM #opt), @n int;

/* Generation now completes a session at its review barrier, and that completion is
   what releases the asset. Sessions created before that change sit at active plus
   REVIEW forever, holding their asset open and blocking every new assessment for
   it. TSG_Verify.sql fails while any remain. */
IF OBJECT_ID('dbo.Scenario_Session', 'U') IS NOT NULL
BEGIN
    SELECT @n = COUNT(*) FROM Scenario_Session WHERE SessionStatus = 'active' AND CurrentStage = 'REVIEW';
    IF @n > 0
    BEGIN
        IF @pv = 1
            PRINT '  would complete ' + CAST(@n AS varchar(10)) + ' session(s) stranded at active+REVIEW.';
        ELSE
        BEGIN
            UPDATE Scenario_Session
               SET SessionStatus = 'completed',
                   CompletedAt   = COALESCE(CompletedAt, SYSUTCDATETIME()),
                   UpdatedAt     = SYSUTCDATETIME()
             WHERE SessionStatus = 'active' AND CurrentStage = 'REVIEW';
            PRINT '  completed ' + CAST(@n AS varchar(10))
                + ' session(s) stranded at active+REVIEW, releasing their assets.';
        END
    END
END

/* ErrorReason is empty on plans that failed before the column existed, forcing a
   client to parse the free-text message instead. The enqueue match is a LIKE on the
   ASCII prefix: that message contains an em dash, which older tooling mangles, so an
   equality test would silently fall through to the catch-all. */
IF COL_LENGTH('dbo.Risk_Treatment_Plan', 'ErrorReason') IS NOT NULL
BEGIN
    SELECT @n = COUNT(*) FROM Risk_Treatment_Plan WHERE Status = 'ERROR' AND ErrorReason IS NULL;
    IF @n > 0
    BEGIN
        IF @pv = 1
            PRINT '  would set ErrorReason on ' + CAST(@n AS varchar(10)) + ' legacy failed plan(s).';
        ELSE
        BEGIN
            UPDATE Risk_Treatment_Plan
               SET ErrorReason = CASE
                       WHEN ErrorMessage = N'cancelled by user' THEN N'cancelled'
                       WHEN ErrorMessage LIKE N'failed to queue generation%' THEN N'enqueue_failed'
                       ELSE N'generation_failed'
                   END
             WHERE Status = 'ERROR' AND ErrorReason IS NULL;
            PRINT '  set ErrorReason on ' + CAST(@n AS varchar(10)) + ' legacy failed plan(s).';
        END
    END
END

/* The review verdict changes_requested was renamed to rejected. Rows written before
   the rename do not match the current filters. */
IF COL_LENGTH('dbo.Risk_Treatment_Plan', 'ReviewStatus') IS NOT NULL
BEGIN
    SELECT @n = COUNT(*) FROM Risk_Treatment_Plan WHERE ReviewStatus = N'changes_requested';
    IF @n > 0
    BEGIN
        IF @pv = 1
            PRINT '  would rename the verdict on ' + CAST(@n AS varchar(10)) + ' plan(s) to rejected.';
        ELSE
        BEGIN
            UPDATE Risk_Treatment_Plan SET ReviewStatus = N'rejected'
             WHERE ReviewStatus = N'changes_requested';
            PRINT '  renamed the verdict on ' + CAST(@n AS varchar(10)) + ' plan(s) to rejected.';
        END
    END
END
GO




/*==============================================================================
  SECTION 4 — Default constraints

  Named so a later script can reference or replace them. Every one is guarded,
  so this section is a no-op on a database that already has them.
==============================================================================*/

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints WHERE name = 'DF_API_Client_Module')
    ALTER TABLE [dbo].[API_Client] ADD CONSTRAINT [DF_API_Client_Module] DEFAULT ('tsg') FOR [Module];
GO
IF NOT EXISTS (SELECT 1 FROM sys.default_constraints WHERE name = 'DF_API_Client_Active')
    ALTER TABLE [dbo].[API_Client] ADD CONSTRAINT [DF_API_Client_Active] DEFAULT ((1)) FOR [Active];
GO
IF NOT EXISTS (SELECT 1 FROM sys.default_constraints WHERE name = 'DF_API_Client_CreatedAt')
    ALTER TABLE [dbo].[API_Client] ADD CONSTRAINT [DF_API_Client_CreatedAt] DEFAULT (sysutcdatetime()) FOR [CreatedAt];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints WHERE name = 'DF_Config_Tuning_IsActive')
    ALTER TABLE [dbo].[Config_Tuning] ADD CONSTRAINT [DF_Config_Tuning_IsActive] DEFAULT ((1)) FOR [IsActive];
GO
IF NOT EXISTS (SELECT 1 FROM sys.default_constraints WHERE name = 'DF_Config_Tuning_IsDeleted')
    ALTER TABLE [dbo].[Config_Tuning] ADD CONSTRAINT [DF_Config_Tuning_IsDeleted] DEFAULT ((0)) FOR [IsDeleted];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints WHERE name = 'DF_Control_Library_CreatedAt')
    ALTER TABLE [dbo].[Control_Library] ADD CONSTRAINT [DF_Control_Library_CreatedAt] DEFAULT (sysutcdatetime()) FOR [CreatedAt];
GO
IF NOT EXISTS (SELECT 1 FROM sys.default_constraints WHERE name = 'DF_Control_Library_IsActive')
    ALTER TABLE [dbo].[Control_Library] ADD CONSTRAINT [DF_Control_Library_IsActive] DEFAULT ((1)) FOR [IsActive];
GO
IF NOT EXISTS (SELECT 1 FROM sys.default_constraints WHERE name = 'DF_Control_Library_IsDeleted')
    ALTER TABLE [dbo].[Control_Library] ADD CONSTRAINT [DF_Control_Library_IsDeleted] DEFAULT ((0)) FOR [IsDeleted];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints WHERE name = 'DF_ControlStdMap_CreatedAt')
    ALTER TABLE [dbo].[Control_Library_Standard_Map] ADD CONSTRAINT [DF_ControlStdMap_CreatedAt] DEFAULT (sysutcdatetime()) FOR [CreatedAt];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints WHERE name = 'DF_Control_Standard_CreatedAt')
    ALTER TABLE [dbo].[Control_Standard] ADD CONSTRAINT [DF_Control_Standard_CreatedAt] DEFAULT (sysutcdatetime()) FOR [CreatedAt];
GO
IF NOT EXISTS (SELECT 1 FROM sys.default_constraints WHERE name = 'DF_Control_Standard_IsActive')
    ALTER TABLE [dbo].[Control_Standard] ADD CONSTRAINT [DF_Control_Standard_IsActive] DEFAULT ((1)) FOR [IsActive];
GO
IF NOT EXISTS (SELECT 1 FROM sys.default_constraints WHERE name = 'DF_Control_Standard_IsDeleted')
    ALTER TABLE [dbo].[Control_Standard] ADD CONSTRAINT [DF_Control_Standard_IsDeleted] DEFAULT ((0)) FOR [IsDeleted];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints WHERE name = 'DF_GroundingCalibration_Forced')
    ALTER TABLE [dbo].[Grounding_Calibration_Run] ADD CONSTRAINT [DF_GroundingCalibration_Forced] DEFAULT ((0)) FOR [Forced];
GO

/* Named, unlike the SSMS default. A system-generated name differs per database
   and cannot be scripted against later. */
IF NOT EXISTS (SELECT 1 FROM sys.default_constraints WHERE name = 'DF_IdentifiedThreat_IsThreatAIGenerated')
    ALTER TABLE [dbo].[Identified_Threat] ADD CONSTRAINT [DF_IdentifiedThreat_IsThreatAIGenerated] DEFAULT ((0)) FOR [IsThreatAIGenerated];
GO
IF NOT EXISTS (SELECT 1 FROM sys.default_constraints WHERE name = 'DF_IdentifiedThreat_IsThreatTypeAIGenerated')
    ALTER TABLE [dbo].[Identified_Threat] ADD CONSTRAINT [DF_IdentifiedThreat_IsThreatTypeAIGenerated] DEFAULT ((0)) FOR [IsThreatTypeAIGenerated];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints WHERE name = 'DF_TreatmentPlan_Superseded')
    ALTER TABLE [dbo].[Risk_Treatment_Plan] ADD CONSTRAINT [DF_TreatmentPlan_Superseded] DEFAULT ((0)) FOR [Superseded];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints WHERE name = 'DF_SSS_AttemptCount')
    ALTER TABLE [dbo].[Subsystem_Stage_State] ADD CONSTRAINT [DF_SSS_AttemptCount] DEFAULT ((0)) FOR [AttemptCount];
GO
IF NOT EXISTS (SELECT 1 FROM sys.default_constraints WHERE name = 'DF_StageState_CreatedAt')
    ALTER TABLE [dbo].[Subsystem_Stage_State] ADD CONSTRAINT [DF_StageState_CreatedAt] DEFAULT (sysutcdatetime()) FOR [CreatedAt];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints WHERE name = 'DF_CatCategoryMap_CreatedAt')
    ALTER TABLE [dbo].[Threat_Catalogue_Category_Map] ADD CONSTRAINT [DF_CatCategoryMap_CreatedAt] DEFAULT (sysutcdatetime()) FOR [CreatedAt];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints WHERE name = 'DF_Scenario_ScenarioNumber')
    ALTER TABLE [dbo].[Threat_Scenario] ADD CONSTRAINT [DF_Scenario_ScenarioNumber] DEFAULT ((1)) FOR [ScenarioNumber];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints WHERE name = 'DF_TypeActorMap_CreatedAt')
    ALTER TABLE [dbo].[ThreatType_ThreatActor_Map] ADD CONSTRAINT [DF_TypeActorMap_CreatedAt] DEFAULT (sysutcdatetime()) FOR [CreatedAt];
GO


/*==============================================================================
  SECTION 5 — Check constraints
==============================================================================*/

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_Config_Tuning_ValueType')
    ALTER TABLE [dbo].[Config_Tuning] WITH CHECK ADD CONSTRAINT [CK_Config_Tuning_ValueType]
        CHECK (([ValueType] = 'int' OR [ValueType] = 'float'));
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_Session_Status')
    ALTER TABLE [dbo].[Scenario_Session] WITH CHECK ADD CONSTRAINT [CK_Session_Status]
        CHECK (([SessionStatus] = 'cancelled' OR [SessionStatus] = 'completed' OR [SessionStatus] = 'active'));
GO

/* A scenario cannot be accepted and rejected at once. Accept and reject are
   separate routes reachable in either order, so the row is the only place both
   orderings meet. */
IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_Scenario_DecisionExclusive')
    ALTER TABLE [dbo].[Threat_Scenario] WITH CHECK ADD CONSTRAINT [CK_Scenario_DecisionExclusive]
        CHECK (([RejectedAt] IS NULL OR [Accepted] = (0)));
GO


/*==============================================================================
  SECTION 6 — Indexes (29)

  Please create all of them exactly as written. Index names, column order, the
  UNIQUE keyword and the text of each WHERE clause are all either checked by the
  application at start-up or relied on to reject duplicate concurrent writes.
==============================================================================*/

-------------------------------------------------------------------------------
-- 6a. Verified at application start-up (14). A missing, non-unique, disabled or
--     differently-shaped index here stops the API and the workers from booting.
-------------------------------------------------------------------------------

/* One active session per asset. Without it a retried request creates a second
   session for the same asset instead of returning the first. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Session_ActiveAsset' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_Session_ActiveAsset] ON [dbo].[Scenario_Session] ([EntityID], [AssetID])
        WHERE [SessionStatus] = 'active';
GO

/* Idempotency: a repeated request carrying the same key returns the original
   session rather than creating another. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Session_IdempotencyKey' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_Session_IdempotencyKey] ON [dbo].[Scenario_Session] ([EntityID], [IdempotencyKey])
        WHERE [IdempotencyKey] IS NOT NULL;
GO

/* One current version per scenario identity. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Scenario_ActiveIdentity' AND object_id = OBJECT_ID('dbo.Threat_Scenario'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_Scenario_ActiveIdentity] ON [dbo].[Threat_Scenario] ([SessionID], [IdentityHash], [ScenarioNumber])
        WHERE [Superseded] = 0;
GO

/* One ACCEPTED version per identity. Separate from the index above: a reviewer
   may accept an older version, so "current" and "accepted" are not the same row. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Scenario_ActiveAccepted' AND object_id = OBJECT_ID('dbo.Threat_Scenario'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_Scenario_ActiveAccepted] ON [dbo].[Threat_Scenario] ([SessionID], [IdentityHash], [ScenarioNumber])
        WHERE [Accepted] = 1 AND [IdentityHash] IS NOT NULL;
GO

/* The row identity the whole locking design depends on. A duplicate would let
   one claim match two rows and put two workers on the same unit of work. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_SubsystemStageState_SessionSubLevel' AND object_id = OBJECT_ID('dbo.Subsystem_Stage_State'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_SubsystemStageState_SessionSubLevel] ON [dbo].[Subsystem_Stage_State] ([SessionID], [SubsystemID], [Level]);
GO

/* One active remediation plan per scenario. This index is what arbitrates two
   simultaneous plan requests. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_TreatmentPlan_ActiveScenario' AND object_id = OBJECT_ID('dbo.Risk_Treatment_Plan'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_TreatmentPlan_ActiveScenario] ON [dbo].[Risk_Treatment_Plan] ([ScenarioID])
        WHERE [Superseded] = 0;
GO

/* One calibration sweep at a time per model pair. The route cannot prevent a
   double start on its own: two requests arriving together both read "nothing
   running" before either writes. Only this index closes that window, and a
   sweep costs 10 to 15 minutes of billed model calls. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_GroundingCalibration_Running' AND object_id = OBJECT_ID('dbo.Grounding_Calibration_Run'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_GroundingCalibration_Running] ON [dbo].[Grounding_Calibration_Run] ([EmbeddingModel], [RerankerModel])
        WHERE [Status] = 'running';
GO

/* Library natural keys. Two sessions promoting the same new name at once must
   not both create it. Filtered so a soft-deleted row releases its name. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatType_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Type'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_ThreatType_NaturalKey] ON [dbo].[Threat_Type] ([ThreatTypeName])
        WHERE [IsActive] = 1 AND [IsDeleted] = 0;
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatCatalogue_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Catalogue'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_ThreatCatalogue_NaturalKey] ON [dbo].[Threat_Catalogue] ([ThreatName])
        WHERE [IsActive] = 1 AND [IsDeleted] = 0;
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatActor_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Actor'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_ThreatActor_NaturalKey] ON [dbo].[Threat_Actor] ([ThreatActorName])
        WHERE [IsActive] = 1 AND [IsDeleted] = 0;
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatCategory_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Category'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_ThreatCategory_NaturalKey] ON [dbo].[Threat_Category] ([ThreatCategoryName])
        WHERE [IsActive] = 1 AND [IsDeleted] = 0;
GO

/* Control library natural keys. A duplicate control code would give the
   matching step a phantom control to choose. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Control_Standard_Name' AND object_id = OBJECT_ID('dbo.Control_Standard'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_Control_Standard_Name] ON [dbo].[Control_Standard] ([StandardName])
        WHERE [IsActive] = 1 AND [IsDeleted] = 0;
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Control_Library_Code' AND object_id = OBJECT_ID('dbo.Control_Library'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_Control_Library_Code] ON [dbo].[Control_Library] ([ControlCode])
        WHERE [IsActive] = 1 AND [IsDeleted] = 0;
GO

/* Not unique, but also verified at start-up: the application reads this index's
   WHERE clause to confirm the stored status wording still matches its own. It
   also makes the capacity count and the recovery sweep proportional to the
   number of ACTIVE sessions rather than to the whole table. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Session_Active' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
    CREATE NONCLUSTERED INDEX [IX_Session_Active] ON [dbo].[Scenario_Session] ([SessionStatus])
        WHERE [SessionStatus] = 'active';
GO

-------------------------------------------------------------------------------
-- 6b. Not checked at start-up, but required for correctness (1).
-------------------------------------------------------------------------------

/* Stops two active clients sharing one key hash, and turns every
   authentication from a table scan into a seek. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_API_Client_KeyHash' AND object_id = OBJECT_ID('dbo.API_Client'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_API_Client_KeyHash] ON [dbo].[API_Client] ([KeyHash])
        WHERE [Active] = 1;
GO

-------------------------------------------------------------------------------
-- 6c. Performance (11 with a known reader). Each of these backs a query the
--     application actually runs.
-------------------------------------------------------------------------------

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_IdentifiedThreat_SessionSubActive' AND object_id = OBJECT_ID('dbo.Identified_Threat'))
    CREATE NONCLUSTERED INDEX [IX_IdentifiedThreat_SessionSubActive] ON [dbo].[Identified_Threat] ([SessionID], [SubsystemID])
        WHERE [Superseded] = 0;
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScopedThreat_SessionSubActive' AND object_id = OBJECT_ID('dbo.Scoped_Threat'))
    CREATE NONCLUSTERED INDEX [IX_ScopedThreat_SessionSubActive] ON [dbo].[Scoped_Threat] ([SessionID], [SubsystemID])
        WHERE [Superseded] = 0;
GO

/* Deliberately NOT filtered, even though Superseded appears in it. SQL Server
   cannot match a filtered index against a parameterised predicate, so the
   column sits in the key instead of a WHERE clause. Backs the scoring read. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScopedThreat_SessionActiveScores' AND object_id = OBJECT_ID('dbo.Scoped_Threat'))
    CREATE NONCLUSTERED INDEX [IX_ScopedThreat_SessionActiveScores] ON [dbo].[Scoped_Threat] ([SessionID], [Superseded])
        INCLUDE ([ThreatID], [Score], [ScopeRank]);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Scenario_SessionSubActive' AND object_id = OBJECT_ID('dbo.Threat_Scenario'))
    CREATE NONCLUSTERED INDEX [IX_Scenario_SessionSubActive] ON [dbo].[Threat_Scenario] ([SessionID], [SubsystemID])
        WHERE [Superseded] = 0;
GO

/* Backs the cross-session scenario browse feed, which filters entity, then
   optionally user and session status. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Session_EntityUser' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
    CREATE NONCLUSTERED INDEX [IX_Session_EntityUser] ON [dbo].[Scenario_Session] ([EntityID], [UserID])
        INCLUDE ([SessionStatus]);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_TreatmentPlan_SessionActive' AND object_id = OBJECT_ID('dbo.Risk_Treatment_Plan'))
    CREATE NONCLUSTERED INDEX [IX_TreatmentPlan_SessionActive] ON [dbo].[Risk_Treatment_Plan] ([SessionID])
        WHERE [Superseded] = 0;
GO

/* Backs the plan version history, which reads only retired rows. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_TreatmentPlan_SessionHistory' AND object_id = OBJECT_ID('dbo.Risk_Treatment_Plan'))
    CREATE NONCLUSTERED INDEX [IX_TreatmentPlan_SessionHistory] ON [dbo].[Risk_Treatment_Plan] ([SessionID], [ScenarioID], [CreatedAt])
        WHERE [Superseded] = 1;
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioAudit_SessionSubEvent' AND object_id = OBJECT_ID('dbo.Scenario_Audit'))
    CREATE NONCLUSTERED INDEX [IX_ScenarioAudit_SessionSubEvent] ON [dbo].[Scenario_Audit] ([SessionID], [SubsystemID], [EventType], [CreatedAt] DESC);
GO

/* "The decision history of this scenario" is the query a reviewer actually
   runs; this makes it a seek. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioAudit_Scenario' AND object_id = OBJECT_ID('dbo.Scenario_Audit'))
    CREATE NONCLUSTERED INDEX [IX_ScenarioAudit_Scenario] ON [dbo].[Scenario_Audit] ([ScenarioID], [CreatedAt] DESC)
        WHERE [ScenarioID] IS NOT NULL;
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ThreatType_Category_Active' AND object_id = OBJECT_ID('dbo.Threat_Type'))
    CREATE NONCLUSTERED INDEX [IX_ThreatType_Category_Active] ON [dbo].[Threat_Type] ([ThreatCategoryID])
        WHERE [IsActive] = 1 AND [IsDeleted] = 0;
GO

/* The evidence endpoint reads the prompt log by correlation id and nothing
   else. Without this index that read scans the whole table, which grows by one
   row per model call. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_PromptLog_Correlation' AND object_id = OBJECT_ID('dbo.Prompt_Log'))
    CREATE NONCLUSTERED INDEX [IX_PromptLog_Correlation] ON [dbo].[Prompt_Log] ([CorrelationID], [CreatedAt])
        WHERE [CorrelationID] IS NOT NULL;
GO

-------------------------------------------------------------------------------
-- 6d. NO CURRENT READER (3). Kept so this database matches the ones already
--     deployed, and because a future query may want them. As of this script no
--     application query filters on their columns, so they cost write time
--     without saving read time. Review before adding more of the same shape.
-------------------------------------------------------------------------------

/* No reader: nothing selects from Identified_Duplicate_Threat at all. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_IdentifiedDuplicateThreat_Session' AND object_id = OBJECT_ID('dbo.Identified_Duplicate_Threat'))
    CREATE NONCLUSTERED INDEX [IX_IdentifiedDuplicateThreat_Session] ON [dbo].[Identified_Duplicate_Threat] ([SessionID]);
GO

/* No reader: the prompt log is only ever read by CorrelationID, which
   IX_PromptLog_Correlation above now serves. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_PromptLog_Session' AND object_id = OBJECT_ID('dbo.Prompt_Log'))
    CREATE NONCLUSTERED INDEX [IX_PromptLog_Session] ON [dbo].[Prompt_Log] ([SessionID], [SubsystemID]);
GO

/* No reader: the treatment audit feed filters session, event type and scenario.
   No query filters the audit table by PlanID; the column is output only. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioAudit_Plan' AND object_id = OBJECT_ID('dbo.Scenario_Audit'))
    CREATE NONCLUSTERED INDEX [IX_ScenarioAudit_Plan] ON [dbo].[Scenario_Audit] ([PlanID], [CreatedAt] DESC)
        WHERE [PlanID] IS NOT NULL;
GO


/*==============================================================================
  SECTION 7 — Verification

  Reports anything that did not get created. A successful run returns no rows.
==============================================================================*/

-- First result set: everything Sections 1 and 3 could not fix on their own.
SELECT Finding, ObjectName, Detail FROM #report ORDER BY Finding, ObjectName;
GO

-- This section reads the manifest from Section 3. Recreate it empty if that section
-- did not run, so the table and index checks below still report instead of failing.
IF OBJECT_ID('tempdb..#want') IS NULL
    CREATE TABLE #want (
        TableName  sysname,      ColumnName sysname,      TypeName sysname,
        MaxLen     int NULL,     Scale      int NULL,     IsNullable bit NOT NULL,
        IsIdentity bit NOT NULL, DefName    sysname NULL, DefExpr    nvarchar(200) NULL);
GO

;WITH required_table(tbl) AS (
    SELECT tbl FROM (VALUES
        ('API_Client'), ('Config_Tuning'), ('Control_Library'),
        ('Control_Library_Standard_Map'), ('Control_Standard'),
        ('Grounding_Calibration_Run'), ('Identified_Duplicate_Threat'),
        ('Identified_Threat'), ('Prompt_Log'), ('Risk_Treatment_Plan'),
        ('Scenario_Audit'), ('Scenario_Session'), ('Scoped_Threat'),
        ('Subsystem_Stage_State'), ('Threat_Actor'), ('Threat_Catalogue'),
        ('Threat_Catalogue_Category_Map'), ('Threat_Category'),
        ('Threat_Scenario'), ('Threat_Scenario_Control_Map'),
        ('Threat_Type'), ('ThreatType_ThreatActor_Map')
    ) v(tbl)
),
required_index(idx, tbl) AS (
    SELECT idx, tbl FROM (VALUES
        ('UX_Session_ActiveAsset',                 'Scenario_Session'),
        ('UX_Session_IdempotencyKey',              'Scenario_Session'),
        ('IX_Session_Active',                      'Scenario_Session'),
        ('IX_Session_EntityUser',                  'Scenario_Session'),
        ('UX_Scenario_ActiveIdentity',             'Threat_Scenario'),
        ('UX_Scenario_ActiveAccepted',             'Threat_Scenario'),
        ('IX_Scenario_SessionSubActive',           'Threat_Scenario'),
        ('UX_SubsystemStageState_SessionSubLevel', 'Subsystem_Stage_State'),
        ('UX_TreatmentPlan_ActiveScenario',        'Risk_Treatment_Plan'),
        ('IX_TreatmentPlan_SessionActive',         'Risk_Treatment_Plan'),
        ('IX_TreatmentPlan_SessionHistory',        'Risk_Treatment_Plan'),
        ('UX_GroundingCalibration_Running',        'Grounding_Calibration_Run'),
        ('UX_ThreatType_NaturalKey',               'Threat_Type'),
        ('IX_ThreatType_Category_Active',          'Threat_Type'),
        ('UX_ThreatCatalogue_NaturalKey',          'Threat_Catalogue'),
        ('UX_ThreatActor_NaturalKey',              'Threat_Actor'),
        ('UX_ThreatCategory_NaturalKey',           'Threat_Category'),
        ('UX_Control_Standard_Name',               'Control_Standard'),
        ('UX_Control_Library_Code',                'Control_Library'),
        ('UX_API_Client_KeyHash',                  'API_Client'),
        ('IX_IdentifiedThreat_SessionSubActive',   'Identified_Threat'),
        ('IX_IdentifiedDuplicateThreat_Session',   'Identified_Duplicate_Threat'),
        ('IX_ScopedThreat_SessionSubActive',       'Scoped_Threat'),
        ('IX_ScopedThreat_SessionActiveScores',    'Scoped_Threat'),
        ('IX_PromptLog_Correlation',               'Prompt_Log'),
        ('IX_PromptLog_Session',                   'Prompt_Log'),
        ('IX_ScenarioAudit_SessionSubEvent',       'Scenario_Audit'),
        ('IX_ScenarioAudit_Scenario',              'Scenario_Audit'),
        ('IX_ScenarioAudit_Plan',                  'Scenario_Audit')
    ) v(idx, tbl)
)
SELECT 'MISSING TABLE' AS Problem, tbl AS ObjectName
FROM required_table
WHERE OBJECT_ID('dbo.' + tbl, 'U') IS NULL
UNION ALL
SELECT 'MISSING INDEX', idx + ' on ' + tbl
FROM required_index
WHERE NOT EXISTS (SELECT 1 FROM sys.indexes
                  WHERE name = idx AND object_id = OBJECT_ID('dbo.' + tbl))
UNION ALL
SELECT 'INDEX NOT UNIQUE OR DISABLED', i.name + ' on ' + r.tbl
FROM required_index r
JOIN sys.indexes i ON i.name = r.idx AND i.object_id = OBJECT_ID('dbo.' + r.tbl)
WHERE r.idx LIKE 'UX[_]%' AND (i.is_unique = 0 OR i.is_disabled = 1)
UNION ALL
SELECT 'READ_COMMITTED_SNAPSHOT IS OFF', DB_NAME()
FROM sys.databases
WHERE database_id = DB_ID() AND is_read_committed_snapshot_on = 0
/* Columns still not matching the manifest after Section 3. Without this the query
   could return no rows on a database whose columns were never reconciled. */
UNION ALL
SELECT 'MISSING COLUMN', w.TableName + '.' + w.ColumnName
FROM #want w
WHERE OBJECT_ID('dbo.' + w.TableName, 'U') IS NOT NULL
  AND COL_LENGTH('dbo.' + w.TableName, w.ColumnName) IS NULL
UNION ALL
SELECT 'COLUMN TOO NARROW', w.TableName + '.' + w.ColumnName
FROM #want w
JOIN sys.columns c ON c.object_id = OBJECT_ID('dbo.' + w.TableName) AND c.name = w.ColumnName
JOIN sys.types t ON t.user_type_id = c.user_type_id
WHERE w.MaxLen IS NOT NULL AND c.max_length <> -1
  AND (w.MaxLen = -1
       OR CASE WHEN t.name IN ('nvarchar', 'nchar') THEN c.max_length / 2
               ELSE c.max_length END < w.MaxLen)
UNION ALL
SELECT 'COLUMN WRONG DATATYPE', w.TableName + '.' + w.ColumnName
FROM #want w
JOIN sys.columns c ON c.object_id = OBJECT_ID('dbo.' + w.TableName) AND c.name = w.ColumnName
JOIN sys.types t ON t.user_type_id = c.user_type_id
WHERE t.name <> w.TypeName;
GO

-- The manifest and the findings list are scratch state for this run only.
IF OBJECT_ID('tempdb..#want') IS NOT NULL DROP TABLE #want;
IF OBJECT_ID('tempdb..#report') IS NOT NULL DROP TABLE #report;
IF OBJECT_ID('tempdb..#pairs') IS NOT NULL DROP TABLE #pairs;
IF OBJECT_ID('tempdb..#opt') IS NOT NULL DROP TABLE #opt;
GO
