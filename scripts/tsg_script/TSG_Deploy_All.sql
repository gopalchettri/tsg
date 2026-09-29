/*==============================================================================
  TSG SCHEMA - COMPLETE DEPLOYMENT IN ONE FILE (51 scripts)

  Script:      TSG_Deploy_All.sql
  Order:       all 51 scripts of this package, in execution order
  Purpose:     Deploy or reconcile the entire TSG schema, then prove it.
  Depends on:  Nothing. It contains every script it needs.
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    Every TSG table, constraint and index, and the isolation level.

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

/*------------------------------------------------------------------------------
  HOW TO RUN IT

    sqlcmd -b -S <server> -d <database> -i TSG_Deploy_All.sql

  or open it in SSMS and press F5. No SQLCMD Mode, no folder, no other file.

  IT STOPS AT THE FIRST ERROR, in SSMS too. SSMS on its own does NOT stop at a
  failed batch, so a check follows every batch in this file: after an error it
  prints "!!! DEPLOYMENT STOPPED" and switches execution off (SET NOEXEC ON).
  The real error is the red message just above the !!! lines, and the last
  ">>> [n/total]" line above that names the script. Fix it, then run this WHOLE
  file again - it is re-runnable.

  READ THE END BEFORE YOU BELIEVE IT. A clean run ends with "Objects: PASS" and
  then "FINAL SIGN-OFF"; a stopped one ends with "DEPLOYMENT STOPPED".

  WHAT IT CHANGES BESIDES TABLES. It turns READ_COMMITTED_SNAPSHOT on, because
  the application does not start without it. On a database somebody else is
  using, that disconnects those sessions and rolls back their in-flight work.
  Deploy in a window if that matters.

  WHAT IT DOES NOT DO. It does not load the threat and control libraries. The
  schema is correct but empty until those are seeded, and an empty library
  returns empty results forever, which looks like a bug and is not one.
------------------------------------------------------------------------------*/
GO

SET NOEXEC OFF;
GO
SET XACT_ABORT ON;
EXEC sp_set_session_context N'tsg_deploy_failed', 0;
GO

/*============================================================================
  >>> 1 of 51   00_validation/000_helpers.sql
============================================================================*/
PRINT '';
PRINT '>>> [1/51] 00_validation/000_helpers.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  HELPER PROCEDURES

  Script:      000_helpers.sql
  Order:       00_validation / 000   (run FIRST - every table script calls these)
  Purpose:     Install the procedures that reconcile a column, reconcile a
               primary key, and report unknown columns.
  Depends on:  Nothing. Creates only its own procedures.
  Re-runnable: YES. CREATE OR ALTER, so a second run just refreshes them.
  Modifies:    dbo.tsg_reconcile_column, dbo.tsg_reconcile_primary_key,
               dbo.tsg_report_extra_columns

  WHY THESE EXIST
  ---------------------------------------------------------------------------
  The table scripts must work on an empty database AND on a database that has
  been live for a year. Writing that logic once, here, keeps 22 table scripts
  readable and stops them drifting apart in how they decide what is safe.

  THE SAFETY RULE, IN ONE LINE
  ---------------------------------------------------------------------------
  Widen freely. Narrow only after proving the data fits. Never drop anything.
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*----------------------------------------------------------------------------
  tsg_script_dependents   (used by the procedures below)

  The objects that must be set aside before @column can be ALTERed or renamed,
  each with the SQL to drop it and to recreate it exactly as it was:
    kind 0 = CHECK constraint, 1 = clustered index, 2 = nonclustered index.
  Primary keys and UNIQUE constraints are never returned - they are left alone.

  @rename_to        set -> the recreate SQL names the column by its NEW name
  @expressions_only 1   -> only objects naming the column in an EXPRESSION
                           (CHECK definitions, index filters). Those are what
                           block sp_rename; index KEY and INCLUDE columns follow
                           a rename by themselves.
----------------------------------------------------------------------------*/
CREATE OR ALTER PROCEDURE dbo.tsg_script_dependents
    @table            sysname,
    @column           sysname,
    @rename_to        sysname = NULL,
    @expressions_only bit     = 0
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @oid  int = OBJECT_ID('dbo.' + QUOTENAME(@table)),
            @cid  int,
            @from nvarchar(300) = QUOTENAME(@column),
            @to   nvarchar(300) = QUOTENAME(ISNULL(@rename_to, @column));
    SET @cid = COLUMNPROPERTY(@oid, @column, 'ColumnId');

    SELECT d.kind, d.name, d.drop_sql, REPLACE(d.create_sql, @from, @to) AS create_sql
    FROM (
        SELECT CAST(0 AS tinyint) AS kind, cc.name,
               N'ALTER TABLE dbo.' + QUOTENAME(@table) + N' DROP CONSTRAINT ' + QUOTENAME(cc.name) + N';'
                   AS drop_sql,
               N'ALTER TABLE dbo.' + QUOTENAME(@table) +
               CASE WHEN cc.is_not_trusted = 1 THEN N' WITH NOCHECK' ELSE N' WITH CHECK' END +
               N' ADD CONSTRAINT ' + QUOTENAME(cc.name) + N' CHECK ' + cc.definition + N';'
                   AS create_sql
        FROM   sys.check_constraints cc
        WHERE  cc.parent_object_id = @oid
          AND  CHARINDEX(@from, cc.definition) > 0

        UNION ALL

        SELECT CAST(i.type AS tinyint), i.name,
               N'DROP INDEX ' + QUOTENAME(i.name) + N' ON dbo.' + QUOTENAME(@table) + N';',
               N'CREATE ' + CASE WHEN i.is_unique = 1 THEN N'UNIQUE ' ELSE N'' END +
               CASE WHEN i.type = 1 THEN N'CLUSTERED' ELSE N'NONCLUSTERED' END +
               N' INDEX ' + QUOTENAME(i.name) + N' ON dbo.' + QUOTENAME(@table) + N' (' +
               STUFF((SELECT N', ' + QUOTENAME(c.name) +
                             CASE WHEN ic.is_descending_key = 1 THEN N' DESC' ELSE N'' END
                      FROM   sys.index_columns ic
                      JOIN   sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
                      WHERE  ic.object_id = i.object_id AND ic.index_id = i.index_id
                        AND  ic.key_ordinal > 0
                      ORDER  BY ic.key_ordinal
                      FOR XML PATH(''), TYPE).value('.', 'nvarchar(max)'), 1, 2, N'') + N')' +
               ISNULL(N' INCLUDE (' +
                      STUFF((SELECT N', ' + QUOTENAME(c.name)
                             FROM   sys.index_columns ic
                             JOIN   sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
                             WHERE  ic.object_id = i.object_id AND ic.index_id = i.index_id
                               AND  ic.is_included_column = 1
                             ORDER  BY ic.index_column_id
                             FOR XML PATH(''), TYPE).value('.', 'nvarchar(max)'), 1, 2, N'') + N')', N'') +
               ISNULL(N' WHERE ' + i.filter_definition, N'') + N';'
        FROM   sys.indexes i
        WHERE  i.object_id = @oid AND i.type IN (1, 2)
          AND  i.is_primary_key = 0 AND i.is_unique_constraint = 0
          AND  (CHARINDEX(@from, ISNULL(i.filter_definition, N'')) > 0
                OR (@expressions_only = 0
                    AND EXISTS (SELECT 1 FROM sys.index_columns ic
                                WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id
                                  AND ic.column_id = @cid)))
    ) d;
END;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO


/*----------------------------------------------------------------------------
  tsg_rename_column

  An older database can carry a column under the name an earlier release gave
  it (OutputID where the application now reads ScenarioID). Adding the new
  column beside it would strand every existing value in the old one, so:

    only the old name exists  -> RENAMED in place. The data moves with it, and
                                 the primary key and index keys follow. CHECK
                                 constraints and filtered indexes that name the
                                 column block a rename (Msg 15336), so they are
                                 set aside and recreated on the new name - all
                                 in ONE transaction.
    both names exist          -> old values COPIED into the new column where it
                                 is still empty. The old column is dropped later,
                                 by the table script, only once every one of its
                                 values is safely in the new one.
    old name absent           -> nothing to do.

  Nothing is ever lost: any failure rolls back and stops the run.
----------------------------------------------------------------------------*/
CREATE OR ALTER PROCEDURE dbo.tsg_rename_column
    @table sysname,
    @old   sysname,
    @new   sysname
AS
BEGIN
    SET NOCOUNT ON;

    IF OBJECT_ID('dbo.' + QUOTENAME(@table), 'U') IS NULL
       OR COL_LENGTH('dbo.' + QUOTENAME(@table), @old) IS NULL
        RETURN;

    DECLARE @sql nvarchar(max), @step nvarchar(max), @rows bigint, @names nvarchar(max);
    DECLARE @dep TABLE (n int IDENTITY, kind tinyint, name sysname,
                        drop_sql nvarchar(max), create_sql nvarchar(max));
    BEGIN TRY
        IF COL_LENGTH('dbo.' + QUOTENAME(@table), @new) IS NULL
        BEGIN
            BEGIN TRANSACTION;
            INSERT @dep (kind, name, drop_sql, create_sql)
                EXEC dbo.tsg_script_dependents @table, @old, @new, 1;

            DECLARE dropper CURSOR LOCAL STATIC READ_ONLY FOR
                SELECT drop_sql FROM @dep ORDER BY kind DESC, n;
            OPEN dropper; FETCH NEXT FROM dropper INTO @step;
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @sql = @step; EXEC sp_executesql @step;
                FETCH NEXT FROM dropper INTO @step;
            END;
            CLOSE dropper; DEALLOCATE dropper;

            SET @sql = N'dbo.' + QUOTENAME(@table) + N'.' + QUOTENAME(@old);
            EXEC sp_rename @sql, @new, 'COLUMN';

            DECLARE creator CURSOR LOCAL STATIC READ_ONLY FOR
                SELECT create_sql FROM @dep ORDER BY kind, n;
            OPEN creator; FETCH NEXT FROM creator INTO @step;
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @sql = @step; EXEC sp_executesql @step;
                FETCH NEXT FROM creator INTO @step;
            END;
            CLOSE creator; DEALLOCATE creator;
            COMMIT;

            SET @sql = N'SELECT @r = COUNT_BIG(*) FROM dbo.' + QUOTENAME(@table) + N';';
            EXEC sp_executesql @sql, N'@r bigint OUTPUT', @r = @rows OUTPUT;
            PRINT ' [RENAMED] ' + @table + '.' + @old + ' -> ' + @new + '  (' +
                  CAST(@rows AS varchar(20)) + ' row(s), data kept)';
            SET @names = STUFF((SELECT N', ' + name FROM @dep ORDER BY kind, n
                                FOR XML PATH(''), TYPE).value('.', 'nvarchar(max)'), 1, 2, N'');
            IF @names IS NOT NULL
                PRINT '          Set aside and recreated on the new name: ' + @names;
        END
        ELSE
        BEGIN
            SET @sql = N'UPDATE dbo.' + QUOTENAME(@table) + N' SET ' + QUOTENAME(@new) + N' = ' +
                       QUOTENAME(@old) + N' WHERE ' + QUOTENAME(@new) + N' IS NULL AND ' +
                       QUOTENAME(@old) + N' IS NOT NULL; SET @r = @@ROWCOUNT;';
            EXEC sp_executesql @sql, N'@r bigint OUTPUT', @r = @rows OUTPUT;
            IF @rows > 0
                PRINT ' [UPDATED] ' + @table + '.' + @new + ': copied ' + CAST(@rows AS varchar(20)) +
                      ' value(s) from the legacy column ' + @old + '.';
        END
    END TRY
    BEGIN CATCH
        DECLARE @err int = ERROR_NUMBER(), @errmsg nvarchar(4000) = ERROR_MESSAGE();
        IF @@TRANCOUNT > 0 ROLLBACK;
        PRINT ' [ERROR]   Could not move ' + @table + '.' + @old + ' to ' + @new + '.';
        PRINT '          Statement: ' + ISNULL(@sql, '(not built)');
        PRINT '          Database error ' + CAST(@err AS varchar(20)) + ': ' + @errmsg;
        PRINT '          Status: NOTHING was changed - the data is still in ' + @old + '.';
        EXEC sp_set_session_context N'tsg_deploy_failed', 1;   -- stops TSG_Deploy_All.sql
        RAISERROR('tsg_rename_column: could not move %s.%s to %s.', 16, 1, @table, @old, @new);
    END CATCH;
END;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO


/*----------------------------------------------------------------------------
  tsg_reconcile_column

  @table      table name, no schema prefix
  @column     column name
  @expected   the type the application needs, e.g. N'NVARCHAR(500)'
  @nullable   1 = the application allows NULL, 0 = it does not
  @fill       optional SQL literal - the value the application itself writes
              for a new row (its default). A NOT NULL column that has to be
              added to, or tightened on, a table that already holds rows uses
              it for those rows instead of being left NULL.

  Outcomes it prints:
    [EXISTS]   the column already matches
    [ADDED]    the column was missing and has been created
    [UPDATED]  a safe change was applied
    [BLOCKED]  a change is needed but would risk data - nothing was changed
    [WARNING]  applied, but a human still has work to do
    [ERROR]    the statement failed; the real database error is printed
----------------------------------------------------------------------------*/
CREATE OR ALTER PROCEDURE dbo.tsg_reconcile_column
    @table    sysname,
    @column   sysname,
    @expected nvarchar(200),
    @nullable bit,
    @fill     nvarchar(400) = NULL
AS
BEGIN
    SET NOCOUNT ON;

    IF OBJECT_ID('dbo.' + QUOTENAME(@table), 'U') IS NULL
    BEGIN
        PRINT ' [ERROR]   Table ' + @table + ' does not exist. Run its 01_tables script first.';
        EXEC sp_set_session_context N'tsg_deploy_failed', 1;   -- stops TSG_Deploy_All.sql
        RAISERROR('tsg_reconcile_column: table %s does not exist.', 16, 1, @table);
        RETURN;
    END;

    DECLARE @actual      nvarchar(200),
            @actual_null bit,
            @base        sysname,
            @maxlen      int,
            @prec        tinyint,
            @scale       tinyint,
            @sql         nvarchar(max),
            @rows        bigint,
            @toolong     bigint,
            @nulls       bigint;

    SELECT @base        = TYPE_NAME(c.user_type_id),
           @maxlen      = c.max_length,
           @prec        = c.precision,
           @scale       = c.scale,
           @actual_null = c.is_nullable
    FROM   sys.columns c
    WHERE  c.object_id = OBJECT_ID('dbo.' + QUOTENAME(@table))
      AND  c.name = @column;

    /*------------------------------------------------------------------
      MISSING COLUMN - add it.
      A NOT NULL column cannot be added to a table that already has rows
      without a default. Rather than invent a default the application
      never asked for, add it as NULL and say plainly what is left to do.
    ------------------------------------------------------------------*/
    IF @base IS NULL
    BEGIN
        SET @sql = N'SELECT @n = COUNT_BIG(*) FROM dbo.' + QUOTENAME(@table) + N';';
        EXEC sp_executesql @sql, N'@n bigint OUTPUT', @n = @rows OUTPUT;

        BEGIN TRY
            IF @nullable = 1 OR @rows = 0
            BEGIN
                SET @sql = N'ALTER TABLE dbo.' + QUOTENAME(@table) + N' ADD ' +
                           QUOTENAME(@column) + N' ' + @expected +
                           CASE WHEN @nullable = 1 THEN N' NULL' ELSE N' NOT NULL' END + N';';
                EXEC sp_executesql @sql;
                PRINT ' [ADDED]   ' + @table + '.' + @column + ' ' + @expected +
                      CASE WHEN @nullable = 1 THEN ' NULL' ELSE ' NOT NULL' END;
            END
            ELSE IF @fill IS NOT NULL
            BEGIN
                /* Rows exist and the application has a default: add, fill, tighten - one unit. */
                BEGIN TRANSACTION;
                SET @sql = N'ALTER TABLE dbo.' + QUOTENAME(@table) + N' ADD ' +
                           QUOTENAME(@column) + N' ' + @expected + N' NULL;';
                EXEC sp_executesql @sql;
                SET @sql = N'UPDATE dbo.' + QUOTENAME(@table) + N' SET ' + QUOTENAME(@column) +
                           N' = ' + @fill + N';';
                EXEC sp_executesql @sql;
                SET @sql = N'ALTER TABLE dbo.' + QUOTENAME(@table) + N' ALTER COLUMN ' +
                           QUOTENAME(@column) + N' ' + @expected + N' NOT NULL;';
                EXEC sp_executesql @sql;
                COMMIT;
                PRINT ' [ADDED]   ' + @table + '.' + @column + ' ' + @expected + ' NOT NULL';
                PRINT '          The ' + CAST(@rows AS varchar(20)) + ' existing row(s) were set to ' +
                      @fill + ', the application''s own default.';
            END
            ELSE
            BEGIN
                SET @sql = N'ALTER TABLE dbo.' + QUOTENAME(@table) + N' ADD ' +
                           QUOTENAME(@column) + N' ' + @expected + N' NULL;';
                EXEC sp_executesql @sql;
                PRINT ' [WARNING] ' + @table + '.' + @column + ' added as NULL because the table ' +
                      'already holds ' + CAST(@rows AS varchar(20)) + ' row(s).';
                PRINT '          The application expects NOT NULL. Backfill the column, then run:';
                PRINT '          ALTER TABLE dbo.' + @table + ' ALTER COLUMN ' + @column + ' ' +
                      @expected + ' NOT NULL;';
            END;
        END TRY
        BEGIN CATCH
            IF @@TRANCOUNT > 0 ROLLBACK;
            PRINT ' [ERROR]   Could not add ' + @table + '.' + @column;
            PRINT '          Statement: ' + ISNULL(@sql, '(not built)');
            PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' +
                  ERROR_MESSAGE();
            PRINT '          Status: column was NOT added.';
            EXEC sp_set_session_context N'tsg_deploy_failed', 1;   -- stops TSG_Deploy_All.sql
            RAISERROR('tsg_reconcile_column: could not add %s.%s.', 16, 1, @table, @column);
        END CATCH;
        RETURN;
    END;

    /*------------------------------------------------------------------
      COLUMN EXISTS - rebuild its real type so it can be compared with the
      expected one. max_length is in BYTES, and an nvarchar holds two bytes
      per character, which is why it is halved here.
    ------------------------------------------------------------------*/
    SET @actual =
        UPPER(@base) +
        CASE
            WHEN @base IN ('nvarchar','nchar')
                THEN '(' + CASE WHEN @maxlen = -1 THEN 'MAX'
                                ELSE CAST(@maxlen / 2 AS varchar(10)) END + ')'
            WHEN @base IN ('varchar','char','varbinary','binary')
                THEN '(' + CASE WHEN @maxlen = -1 THEN 'MAX'
                                ELSE CAST(@maxlen AS varchar(10)) END + ')'
            WHEN @base IN ('decimal','numeric')
                THEN '(' + CAST(@prec AS varchar(10)) + ', ' + CAST(@scale AS varchar(10)) + ')'
            WHEN @base IN ('datetime2','time','datetimeoffset')
                THEN '(' + CAST(@scale AS varchar(10)) + ')'
            ELSE ''
        END;

    DECLARE @want nvarchar(200) = UPPER(REPLACE(@expected, ' ', ''));
    DECLARE @have nvarchar(200) = UPPER(REPLACE(@actual,   ' ', ''));
    /* DATETIME2 with no precision IS DATETIME2(7), and sys.columns reports it as (7). Without
       this the two strings never match, so every run re-ALTERed the column and said [UPDATED]. */
    IF @want IN (N'DATETIME2', N'TIME', N'DATETIMEOFFSET') SET @want = @want + N'(7)';

    IF @want = @have AND @actual_null = @nullable
    BEGIN
        PRINT ' [EXISTS]  ' + @table + '.' + @column + ' ' + @actual;
        RETURN;
    END;

    /*------------------------------------------------------------------
      A DIFFERENCE. Decide whether changing it is safe.
    ------------------------------------------------------------------*/
    DECLARE @want_base nvarchar(50) =
        CASE WHEN CHARINDEX('(', @want) > 0
             THEN LEFT(@want, CHARINDEX('(', @want) - 1) ELSE @want END;

    IF @want_base <> UPPER(@base)
    BEGIN
        PRINT ' [BLOCKED] ' + @table + '.' + @column;
        PRINT '          Current:  ' + @actual;
        PRINT '          Expected: ' + @expected;
        PRINT '          Reason:   different type family. Converting could fail or change values.';
        PRINT '          Action:   review the data, then convert by hand.';
        RETURN;
    END;

    /* Same family, different size. Widening is safe; narrowing needs proof. */
    IF @want <> @have AND @base IN ('nvarchar','nchar','varchar','char')
    BEGIN
        DECLARE @want_len int =
            CASE WHEN CHARINDEX('MAX', @want) > 0 THEN -1
                 ELSE TRY_CAST(REPLACE(REPLACE(SUBSTRING(@want, CHARINDEX('(', @want) + 1, 20),
                      ')', ''), ' ', '') AS int) END;
        DECLARE @have_len int =
            CASE WHEN @maxlen = -1 THEN -1
                 WHEN @base IN ('nvarchar','nchar') THEN @maxlen / 2 ELSE @maxlen END;

        IF @want_len IS NOT NULL AND @want_len <> -1 AND @have_len <> -1 AND @want_len < @have_len
        BEGIN
            SET @sql = N'SELECT @n = COUNT_BIG(*) FROM dbo.' + QUOTENAME(@table) +
                       N' WHERE LEN(' + QUOTENAME(@column) + N') > @len;';
            EXEC sp_executesql @sql, N'@n bigint OUTPUT, @len int', @n = @toolong OUTPUT,
                 @len = @want_len;

            IF @toolong > 0
            BEGIN
                PRINT ' [BLOCKED] ' + @table + '.' + @column;
                PRINT '          Current:  ' + @actual;
                PRINT '          Expected: ' + @expected;
                PRINT '          Reason:   ' + CAST(@toolong AS varchar(20)) +
                      ' existing row(s) are longer than ' + CAST(@want_len AS varchar(10)) +
                      ' characters and would be truncated.';
                PRINT '          Action:   shorten or archive those rows, then re-run.';
                RETURN;
            END;

            PRINT ' [INFO]    Narrowing ' + @table + '.' + @column +
                  ' is safe - no row exceeds ' + CAST(@want_len AS varchar(10)) + ' characters.';
        END;
    END;

    /* NULL -> NOT NULL only when no NULL is stored. */
    IF @nullable = 0 AND @actual_null = 1
    BEGIN
        SET @sql = N'SELECT @n = COUNT_BIG(*) FROM dbo.' + QUOTENAME(@table) +
                   N' WHERE ' + QUOTENAME(@column) + N' IS NULL;';
        EXEC sp_executesql @sql, N'@n bigint OUTPUT', @n = @nulls OUTPUT;

        /* The application's own default for those rows, when it has one. (Also completes a
           column an earlier run could only add as NULL.) The ALTER below then tightens it. */
        IF @nulls > 0 AND @fill IS NOT NULL
        BEGIN
            SET @sql = N'UPDATE dbo.' + QUOTENAME(@table) + N' SET ' + QUOTENAME(@column) +
                       N' = ' + @fill + N' WHERE ' + QUOTENAME(@column) + N' IS NULL;';
            EXEC sp_executesql @sql;
            PRINT ' [UPDATED] ' + @table + '.' + @column + ': ' + CAST(@nulls AS varchar(20)) +
                  ' NULL(s) set to ' + @fill + ', the application''s own default.';
            SET @nulls = 0;
        END;

        IF @nulls > 0
        BEGIN
            PRINT ' [BLOCKED] ' + @table + '.' + @column;
            PRINT '          Current:  ' + @actual + ' NULL';
            PRINT '          Expected: ' + @expected + ' NOT NULL';
            PRINT '          Reason:   ' + CAST(@nulls AS varchar(20)) +
                  ' row(s) hold NULL, so the column cannot be made NOT NULL.';
            PRINT '          Action:   give those rows a value, then re-run.';
            RETURN;
        END;
    END;

    DECLARE @alter nvarchar(max) = N'ALTER TABLE dbo.' + QUOTENAME(@table) + N' ALTER COLUMN ' +
                   QUOTENAME(@column) + N' ' + @expected +
                   CASE WHEN @nullable = 1 THEN N' NULL' ELSE N' NOT NULL' END + N';',
            @rebuilt nvarchar(max) = NULL,
            @err int, @errmsg nvarchar(4000);
    SET @sql = @alter;

    BEGIN TRY
        EXEC sp_executesql @alter;
    END TRY
    BEGIN CATCH
        SELECT @err = ERROR_NUMBER(), @errmsg = ERROR_MESSAGE();
        IF @err NOT IN (4922, 5074)
            GOTO failed;

        /*--------------------------------------------------------------
          BLOCKED BY DEPENDENT OBJECTS (Msg 4922/5074). SQL Server will not
          alter a column that a CHECK constraint, a filtered index predicate
          or an index key/include refers to - even to WIDEN it. Seen on UAT:
          Scenario_Session.SessionStatus NVARCHAR(20) -> (100) was blocked by
          CK_Session_Status and four indexes.

          So: script each dependent from the catalog, drop it, alter the
          column, recreate it exactly as it was - ALL IN ONE TRANSACTION. If
          any step fails, everything rolls back and nothing has changed.
          Primary keys and UNIQUE constraints are not touched here; one of
          those makes the ALTER fail and roll back, and the run stops.
        --------------------------------------------------------------*/
        DECLARE @step nvarchar(max);
        DECLARE @dep TABLE (n int IDENTITY, kind tinyint, name sysname,
                            drop_sql nvarchar(max), create_sql nvarchar(max));
        INSERT @dep (kind, name, drop_sql, create_sql)
            EXEC dbo.tsg_script_dependents @table, @column;

        BEGIN TRY
            BEGIN TRANSACTION;
            /* Drop nonclustered, then clustered, then checks; recreate in the reverse order. */
            DECLARE dropper CURSOR LOCAL STATIC READ_ONLY FOR
                SELECT drop_sql FROM @dep ORDER BY kind DESC, n;
            OPEN dropper; FETCH NEXT FROM dropper INTO @step;
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @sql = @step; EXEC sp_executesql @step;
                FETCH NEXT FROM dropper INTO @step;
            END;
            CLOSE dropper; DEALLOCATE dropper;

            SET @sql = @alter; EXEC sp_executesql @alter;

            DECLARE creator CURSOR LOCAL STATIC READ_ONLY FOR
                SELECT create_sql FROM @dep ORDER BY kind, n;
            OPEN creator; FETCH NEXT FROM creator INTO @step;
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @sql = @step; EXEC sp_executesql @step;
                FETCH NEXT FROM creator INTO @step;
            END;
            CLOSE creator; DEALLOCATE creator;
            COMMIT;

            SET @rebuilt = ISNULL(STUFF((SELECT N', ' + name FROM @dep ORDER BY kind, n
                                         FOR XML PATH(''), TYPE).value('.', 'nvarchar(max)'),
                                        1, 2, N''), N'(none found)');
        END TRY
        BEGIN CATCH
            SELECT @err = ERROR_NUMBER(), @errmsg = ERROR_MESSAGE();
            IF @@TRANCOUNT > 0 ROLLBACK;
            GOTO failed;
        END CATCH;
    END CATCH;

    PRINT ' [UPDATED] ' + @table + '.' + @column;
    PRINT '          Was:  ' + @actual +
          CASE WHEN @actual_null = 1 THEN ' NULL' ELSE ' NOT NULL' END;
    PRINT '          Now:  ' + @expected +
          CASE WHEN @nullable = 1 THEN ' NULL' ELSE ' NOT NULL' END;
    IF @rebuilt IS NOT NULL
        PRINT '          Dropped and recreated unchanged around it: ' + @rebuilt;
    RETURN;

failed:
    PRINT ' [ERROR]   Could not alter ' + @table + '.' + @column;
    PRINT '          Statement: ' + ISNULL(@sql, '(not built)');
    PRINT '          Database error ' + CAST(@err AS varchar(20)) + ': ' + @errmsg;
    PRINT '          Status: NOTHING was changed (any rebuild was rolled back).';
    PRINT '          Likely cause: a primary key, UNIQUE constraint or other object depends';
    PRINT '          on this column.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;   -- stops TSG_Deploy_All.sql
    RAISERROR('tsg_reconcile_column: could not alter %s.%s.', 16, 1, @table, @column);
END;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO


/*----------------------------------------------------------------------------
  tsg_reconcile_primary_key

  @table     table name, no schema prefix
  @columns   the key the application expects, comma-separated, in key order,
             no spaces, e.g. N'ScenarioID,ControlLibraryID'

  The CREATE in each table script sets the key only for a NEW table. An older
  copy of a table can carry a different key - Threat_Scenario_Control_Map was
  once keyed on (OutputID, ControlLibraryID); the application now writes
  (ScenarioID, ControlLibraryID) and never supplies OutputID, so every insert
  failed. This brings the key to what the application expects.

  The drop and the add share ONE transaction: if the new key cannot be built
  (NULL or duplicate values, a referencing constraint, another clustered index) nothing
  changes, the old key stays, and the run stops with the database's reason.

    [EXISTS]   the key already matches
    [ADDED]    the table had no primary key; one was created
    [UPDATED]  the old key was replaced
    [ERROR]    the change failed and was rolled back; the real error is printed
----------------------------------------------------------------------------*/
CREATE OR ALTER PROCEDURE dbo.tsg_reconcile_primary_key
    @table   sysname,
    @columns nvarchar(max)
AS
BEGIN
    SET NOCOUNT ON;

    IF OBJECT_ID('dbo.' + QUOTENAME(@table), 'U') IS NULL
        RETURN;   -- tsg_reconcile_column has already reported and stopped on this

    DECLARE @pk   sysname,
            @have nvarchar(max),
            @want nvarchar(max) = REPLACE(@columns, N',', N', '),
            @sql  nvarchar(max);

    SELECT @pk = kc.name
    FROM   sys.key_constraints kc
    WHERE  kc.parent_object_id = OBJECT_ID('dbo.' + QUOTENAME(@table)) AND kc.type = 'PK';

    /* FOR XML PATH rather than STRING_AGG: the package supports SQL Server 2016. */
    SET @have = ISNULL(STUFF((
        SELECT N', ' + c.name
        FROM   sys.indexes i
        JOIN   sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
        JOIN   sys.columns c        ON c.object_id = ic.object_id AND c.column_id = ic.column_id
        WHERE  i.object_id = OBJECT_ID('dbo.' + QUOTENAME(@table))
          AND  i.is_primary_key = 1 AND ic.key_ordinal > 0
        ORDER  BY ic.key_ordinal
        FOR XML PATH(''), TYPE).value('.', 'nvarchar(max)'), 1, 2, N''), N'');

    IF @have = @want
    BEGIN
        PRINT ' [EXISTS]  ' + @table + ' primary key (' + @have + ')';
        RETURN;
    END;

    BEGIN TRY
        BEGIN TRANSACTION;
        IF @pk IS NOT NULL
        BEGIN
            SET @sql = N'ALTER TABLE dbo.' + QUOTENAME(@table) + N' DROP CONSTRAINT ' +
                       QUOTENAME(@pk) + N';';
            EXEC sp_executesql @sql;
        END;
        SET @sql = N'ALTER TABLE dbo.' + QUOTENAME(@table) + N' ADD CONSTRAINT ' +
                   QUOTENAME(N'PK_' + @table) + N' PRIMARY KEY CLUSTERED ([' +
                   REPLACE(@columns, N',', N'], [') + N']);';
        EXEC sp_executesql @sql;
        COMMIT;

        IF @pk IS NULL
            PRINT ' [ADDED]   ' + @table + ' primary key (' + @want + ')';
        ELSE
        BEGIN
            PRINT ' [UPDATED] ' + @table + ' primary key';
            PRINT '          Was:  (' + @have + ')';
            PRINT '          Now:  (' + @want + ')';
        END;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK;
        PRINT ' [ERROR]   Could not set the primary key of ' + @table + ' to (' + @want + ')';
        PRINT '          Statement: ' + ISNULL(@sql, '(not built)');
        PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' +
              ERROR_MESSAGE();
        PRINT '          Status: NOTHING was changed - the key is still (' + @have + ').';
        PRINT '          Likely cause: NULL or duplicate values in (' + @want + '). Fix those';
        PRINT '          rows, then re-run.';
        EXEC sp_set_session_context N'tsg_deploy_failed', 1;   -- stops TSG_Deploy_All.sql
        RAISERROR('tsg_reconcile_primary_key: could not set the primary key of %s.', 16, 1, @table);
    END CATCH;
END;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO


/*----------------------------------------------------------------------------
  tsg_report_extra_columns

  Lists columns the database has and the application does not use. It NEVER
  drops one: it may belong to another release, another team, or a column the
  application will need again.

  ONE change it does make: an unknown column that is NOT NULL with no default
  makes every insert the application does fail, because the application never
  supplies it (Threat_Scenario_Control_Map.OutputID did exactly that). Such a
  column is made NULL-able - same type, same data, nothing lost. If it is part
  of an index it cannot be altered safely here, so the run stops instead.
----------------------------------------------------------------------------*/
CREATE OR ALTER PROCEDURE dbo.tsg_report_extra_columns
    @table sysname,
    @known nvarchar(max)          -- comma-separated list of expected column names
AS
BEGIN
    SET NOCOUNT ON;

    IF OBJECT_ID('dbo.' + QUOTENAME(@table), 'U') IS NULL
        RETURN;

    DECLARE @name sysname, @blocks bit, @indexed bit, @type nvarchar(300), @sql nvarchar(max);
    /* STATIC: the loop may ALTER a column, and the cursor reads sys.columns. */
    DECLARE extra CURSOR LOCAL STATIC READ_ONLY FOR
        SELECT c.name,
               /* NOT NULL, no default, not identity, not computed = inserts must supply it */
               CASE WHEN c.is_nullable = 0 AND c.default_object_id = 0
                         AND c.is_identity = 0 AND c.is_computed = 0 THEN 1 ELSE 0 END,
               CASE WHEN EXISTS (SELECT 1 FROM sys.index_columns ic
                                 WHERE ic.object_id = c.object_id
                                   AND ic.column_id = c.column_id) THEN 1 ELSE 0 END,
               UPPER(TYPE_NAME(c.user_type_id)) +
               CASE
                   WHEN TYPE_NAME(c.user_type_id) IN ('nvarchar','nchar')
                       THEN '(' + CASE WHEN c.max_length = -1 THEN 'MAX'
                                       ELSE CAST(c.max_length / 2 AS varchar(10)) END + ')'
                   WHEN TYPE_NAME(c.user_type_id) IN ('varchar','char','varbinary','binary')
                       THEN '(' + CASE WHEN c.max_length = -1 THEN 'MAX'
                                       ELSE CAST(c.max_length AS varchar(10)) END + ')'
                   WHEN TYPE_NAME(c.user_type_id) IN ('decimal','numeric')
                       THEN '(' + CAST(c.precision AS varchar(10)) + ', ' +
                            CAST(c.scale AS varchar(10)) + ')'
                   WHEN TYPE_NAME(c.user_type_id) IN ('datetime2','time','datetimeoffset')
                       THEN '(' + CAST(c.scale AS varchar(10)) + ')'
                   ELSE ''
               END +
               ISNULL(' COLLATE ' + c.collation_name, '')
        FROM   sys.columns c
        WHERE  c.object_id = OBJECT_ID('dbo.' + QUOTENAME(@table))
          AND  c.name NOT IN (SELECT LTRIM(RTRIM(value)) FROM STRING_SPLIT(@known, ','));

    OPEN extra;
    FETCH NEXT FROM extra INTO @name, @blocks, @indexed, @type;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        IF @blocks = 0
            PRINT ' [INFO]    ' + @table + '.' + @name +
                  ' exists in the database but is not used by this application. No change made.';
        ELSE IF @indexed = 1
        BEGIN
            PRINT ' [ERROR]   ' + @table + '.' + @name + ' is NOT NULL, has no default and is not';
            PRINT '          used by this application, so every insert into ' + @table + ' fails.';
            PRINT '          It is part of an index, so it was NOT changed. Drop or rework that';
            PRINT '          index, or make the column NULL-able by hand, then re-run.';
            EXEC sp_set_session_context N'tsg_deploy_failed', 1;   -- stops TSG_Deploy_All.sql
            RAISERROR('tsg_report_extra_columns: %s.%s blocks every insert.', 16, 1, @table, @name);
        END
        ELSE
        BEGIN
            BEGIN TRY
                SET @sql = N'ALTER TABLE dbo.' + QUOTENAME(@table) + N' ALTER COLUMN ' +
                           QUOTENAME(@name) + N' ' + @type + N' NULL;';
                EXEC sp_executesql @sql;
                PRINT ' [UPDATED] ' + @table + '.' + @name + ' made NULL-able. The application never';
                PRINT '          writes it, so NOT NULL made every insert fail. No data changed.';
            END TRY
            BEGIN CATCH
                PRINT ' [ERROR]   Could not make ' + @table + '.' + @name + ' NULL-able.';
                PRINT '          Statement: ' + ISNULL(@sql, '(not built)');
                PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' +
                      ERROR_MESSAGE();
                EXEC sp_set_session_context N'tsg_deploy_failed', 1;   -- stops TSG_Deploy_All.sql
                RAISERROR('tsg_report_extra_columns: could not alter %s.%s.', 16, 1, @table, @name);
            END CATCH;
        END;
        FETCH NEXT FROM extra INTO @name, @blocks, @indexed, @type;
    END;
    CLOSE extra;
    DEALLOCATE extra;
END;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT ' [CREATED] Helper procedures ready: tsg_reconcile_column, tsg_reconcile_primary_key,';
PRINT '          tsg_report_extra_columns';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 2 of 51   00_validation/001_pre_deployment_validation.sql
============================================================================*/
PRINT '';
PRINT '>>> [2/51] 00_validation/001_pre_deployment_validation.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  PRE-DEPLOYMENT VALIDATION  (READ ONLY)

  Script:      001_pre_deployment_validation.sql
  Order:       00_validation / 001   (run after 000_helpers.sql, before 01_tables)
  Purpose:     Report what is already here and what the deployment will change.
  Depends on:  Nothing.
  Re-runnable: YES - it reads catalog views only.
  Modifies:    NOTHING. This script never writes, alters, creates or drops.

  READ THE OUTPUT BEFORE YOU DEPLOY. It tells you whether this is an empty
  database or an upgrade, whether the platform tables TSG depends on exist, and
  what data is present that could block a change.

  A [FAIL] here does not mean the deployment will fail. It means a human should
  look before running it.

  RELATED: "0. TSG_Preflight.sql" checks the platform tables column by column
  and is worth running too. This script does not repeat that depth; it answers
  the questions this package needs - fresh or upgrade, what data is at risk,
  and which boot-critical indexes are missing.
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '==============================================================';
PRINT ' TSG PRE-DEPLOYMENT VALIDATION';
PRINT ' Database: ' + DB_NAME() + '   Server: ' + @@SERVERNAME;
PRINT ' Run at:   ' + CONVERT(varchar(19), SYSUTCDATETIME(), 120) + ' UTC';
PRINT '==============================================================';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*--------------------------------------------------------------------------
  1. SQL Server version.
     The package uses STRING_SPLIT (2016+) and CREATE OR ALTER (2016 SP1+).
--------------------------------------------------------------------------*/
PRINT '';
PRINT '--- 1. Server ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO
DECLARE @major int = TRY_CAST(SERVERPROPERTY('ProductMajorVersion') AS int);
PRINT ' [INFO]    Version: ' + CAST(SERVERPROPERTY('ProductVersion') AS varchar(50)) +
      '  (' + CAST(SERVERPROPERTY('Edition') AS varchar(60)) + ')';
IF @major >= 13
    PRINT ' [PASS]    SQL Server 2016 or later - STRING_SPLIT and CREATE OR ALTER are available.';
ELSE
    PRINT ' [FAIL]    SQL Server 2016 or later is required by this package.';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*--------------------------------------------------------------------------
  2. Read-Committed Snapshot Isolation.
     The application relies on it: without RCSI, readers block writers and the
     pipeline's concurrent stages deadlock.

     READ sys.databases, NOT DATABASEPROPERTYEX. That property returned NULL on
     a SQL Server 2022 Express instance whose RCSI was demonstrably ON, and
     `NULL = 1` is UNKNOWN, so this section printed [FAIL] and told the operator
     to run ALTER DATABASE ... WITH ROLLBACK IMMEDIATE - a statement that kills
     every open connection - against a database that was already correct.
     sys.databases.is_read_committed_snapshot_on is a non-nullable bit present
     for every database, so it cannot produce that false alarm.

     A read that returns NOTHING is reported as its own case. "I could not tell"
     must never print the ALTER, because acting on it would be destructive.
--------------------------------------------------------------------------*/
PRINT '';
PRINT '--- 2. Isolation level ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO
DECLARE @rcsi bit = (SELECT d.is_read_committed_snapshot_on
                     FROM sys.databases d WHERE d.database_id = DB_ID());
IF @rcsi = 1
    PRINT ' [PASS]    READ_COMMITTED_SNAPSHOT is ON.';
ELSE IF @rcsi = 0
BEGIN
    PRINT ' [FAIL]    READ_COMMITTED_SNAPSHOT is OFF. The application needs it ON.';
    PRINT '          Fix (run when nobody else is connected):';
    PRINT '          ALTER DATABASE [' + DB_NAME() +
          '] SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE;';
END
ELSE
BEGIN
    PRINT ' [FAIL]    Could not read this database''s isolation setting - no visible';
    PRINT '          sys.databases row. Check the setting before deploying, and do';
    PRINT '          NOT run the ALTER blind: it disconnects every active session.';
END;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*--------------------------------------------------------------------------
  3. Platform tables.
     TSG READS these and must never create or alter them. If they are missing,
     the schema still deploys, but the application cannot resolve an asset, so
     POST /v1/sessions fails at run time. Ask the platform team.
--------------------------------------------------------------------------*/
PRINT '';
PRINT '--- 3. Platform tables (owned by another team - TSG only reads them) ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO
DECLARE @platform TABLE (name sysname);
INSERT INTO @platform (name) VALUES
    ('ctm_scan_category'), ('ctm_scan_entity'), ('ctm_scan_entity_bu'),
    ('ctm_scan_entity_supporting_system'), ('onboarding_sectors'), ('onboarding_services'),
    ('onboarding_supporting_systems'), ('option'), ('option_value'),
    ('user'), ('user_scope_assignment');

SELECT CASE WHEN OBJECT_ID('dbo.' + QUOTENAME(p.name), 'U') IS NULL
            THEN '[WARNING] missing: ' ELSE '[PASS]    present: ' END + p.name AS PlatformTable
FROM   @platform p
ORDER  BY p.name;

DECLARE @missing_platform int =
    (SELECT COUNT(*) FROM @platform p WHERE OBJECT_ID('dbo.' + QUOTENAME(p.name), 'U') IS NULL);

IF @missing_platform > 0
BEGIN
    PRINT ' [WARNING] ' + CAST(@missing_platform AS varchar(10)) + ' platform table(s) missing.';
    PRINT '          This package will NOT create them - they belong to another team.';
    PRINT '          The schema still deploys, but the application cannot resolve an asset.';
END
ELSE
    PRINT ' [PASS]    All 11 platform tables are present.';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*--------------------------------------------------------------------------
  4. TSG tables - is this a fresh install or an upgrade?
--------------------------------------------------------------------------*/
PRINT '';
PRINT '--- 4. TSG tables ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO
DECLARE @owned TABLE (name sysname);
INSERT INTO @owned (name) VALUES
    ('Threat_Category'), ('Threat_Type'), ('Threat_Catalogue'), ('Threat_Actor'),
    ('Threat_Catalogue_Category_Map'), ('ThreatType_ThreatActor_Map'),
    ('Control_Standard'), ('Control_Library'), ('Control_Library_Standard_Map'),
    ('API_Client'), ('Config_Tuning'), ('Grounding_Calibration_Run'),
    ('Scenario_Session'), ('Subsystem_Stage_State'), ('Identified_Threat'),
    ('Identified_Duplicate_Threat'), ('Scoped_Threat'), ('Threat_Scenario'),
    ('Threat_Scenario_Control_Map'), ('Risk_Treatment_Plan'),
    ('Scenario_Audit'), ('Prompt_Log'), ('Diagnostic_Event','Application_Log'), ('Application_Log');

DECLARE @total   int = (SELECT COUNT(*) FROM @owned);
DECLARE @present int = (SELECT COUNT(*) FROM @owned o
                        WHERE OBJECT_ID('dbo.' + QUOTENAME(o.name), 'U') IS NOT NULL);

PRINT ' [INFO]    ' + CAST(@present AS varchar(10)) + ' of ' + CAST(@total AS varchar(10)) +
      ' TSG tables already exist.';
IF @present = 0
    PRINT ' [INFO]    EMPTY DATABASE. The deployment will create everything.';
ELSE IF @present = @total
    PRINT ' [INFO]    UPGRADE. Every table exists; the deployment will reconcile columns only.';
ELSE
    PRINT ' [INFO]    PARTIAL INSTALL. Missing tables are created, existing ones reconciled.';

SELECT CASE WHEN OBJECT_ID('dbo.' + QUOTENAME(o.name), 'U') IS NULL
            THEN '[WILL CREATE] ' ELSE '[EXISTS]      ' END + o.name AS TsgTable
FROM   @owned o
ORDER  BY o.name;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*--------------------------------------------------------------------------
  5. Row counts - how much data is at risk.
     An empty table can be changed freely. A table with rows is where a
     narrowing change or a new NOT NULL column gets blocked or softened.
--------------------------------------------------------------------------*/
PRINT '';
PRINT '--- 5. Existing data ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO
SELECT   t.name          AS TableName,
         SUM(p.rows)     AS ApproxRows
FROM     sys.tables t
JOIN     sys.partitions p ON p.object_id = t.object_id AND p.index_id IN (0, 1)
WHERE    t.name IN ('Threat_Category','Threat_Type','Threat_Catalogue','Threat_Actor',
                    'Threat_Catalogue_Category_Map','ThreatType_ThreatActor_Map',
                    'Control_Standard','Control_Library','Control_Library_Standard_Map',
                    'API_Client','Config_Tuning','Grounding_Calibration_Run',
                    'Scenario_Session','Subsystem_Stage_State','Identified_Threat',
                    'Identified_Duplicate_Threat','Scoped_Threat','Threat_Scenario',
                    'Threat_Scenario_Control_Map','Risk_Treatment_Plan',
                    'Scenario_Audit','Prompt_Log','Diagnostic_Event')
GROUP BY t.name
HAVING   SUM(p.rows) > 0
ORDER BY SUM(p.rows) DESC;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO
PRINT ' [INFO]    Any table listed above holds data. Narrowing a column there, or adding a';
PRINT '          NOT NULL column, will be BLOCKED or added as NULL. That is deliberate.';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*--------------------------------------------------------------------------
  6. The 15 indexes the application refuses to boot without.
     Sources: app/db/invariants.py::REQUIRED_INDEXES (14) AND
              app/db/invariants.py::FILTERED_INDEX_LITERALS, whose second entry
              IX_Session_Active is NOT in REQUIRED_INDEXES. verify_startup runs
              BOTH lists, so a script checking only the first reported a clean
              [PASS] for a database the API would refuse to start against.
     If one is missing after deployment, the API and the workers will not start.
--------------------------------------------------------------------------*/
PRINT '';
PRINT '--- 6. Boot-critical indexes ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO
DECLARE @req TABLE (ix sysname, tbl sysname);
INSERT INTO @req (ix, tbl) VALUES
    ('UX_Session_ActiveAsset','Scenario_Session'),
    ('IX_Session_Active','Scenario_Session'),
    ('UX_Session_IdempotencyKey','Scenario_Session'),
    ('UX_Scenario_ActiveIdentity','Threat_Scenario'),
    ('UX_Scenario_ActiveScoped','Threat_Scenario'),
    ('UX_Scenario_ActiveAccepted','Threat_Scenario'),
    ('UX_ThreatType_NaturalKey','Threat_Type'),
    ('UX_ThreatCatalogue_NaturalKey','Threat_Catalogue'),
    ('UX_ThreatActor_NaturalKey','Threat_Actor'),
    ('UX_ThreatCategory_NaturalKey','Threat_Category'),
    ('UX_SubsystemStageState_SessionSubLevel','Subsystem_Stage_State'),
    ('UX_TreatmentPlan_ActiveScenario','Risk_Treatment_Plan'),
    ('UX_GroundingCalibration_Running','Grounding_Calibration_Run'),
    ('UX_Control_Standard_Name','Control_Standard'),
    ('UX_Control_Library_Code','Control_Library');

SELECT CASE WHEN EXISTS (SELECT 1 FROM sys.indexes i
                         WHERE i.name = r.ix
                           AND i.object_id = OBJECT_ID('dbo.' + QUOTENAME(r.tbl)))
            THEN '[PASS]        ' ELSE '[WILL CREATE] ' END + r.ix + '  on ' + r.tbl
       AS RequiredIndex
FROM   @req r
ORDER  BY r.ix;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '==============================================================';
PRINT ' PRE-DEPLOYMENT VALIDATION COMPLETE - nothing was changed.';
PRINT ' Read any [FAIL] or [WARNING] above before continuing.';
PRINT ' Next: 01_tables, then 02_constraints, then 03_indexes.';
PRINT '==============================================================';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 3 of 51   00_validation/002_enable_isolation_level.sql
============================================================================*/
PRINT '';
PRINT '>>> [3/51] 00_validation/002_enable_isolation_level.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  ENABLE READ-COMMITTED SNAPSHOT ISOLATION

  Script:      002_enable_isolation_level.sql
  Order:       00_validation / 002   (run after 001, before 01_tables)
  Purpose:     Turn READ_COMMITTED_SNAPSHOT ON - the one database-level setting
               the application refuses to start without.
  Depends on:  Nothing.
  Re-runnable: YES. A database that already has it on reports [EXISTS] and is
               not touched.
  Modifies:    This database's READ_COMMITTED_SNAPSHOT setting, and nothing
               else. No table, no row, no other session.

  WHY THIS FILE EXISTS
  ---------------------------------------------------------------------------
  It is the only thing the application needs that is a SETTING rather than an
  object, and until now the package only ever CHECKED it. 001 reported it OFF,
  99_validation/001 failed the sign-off over it, and nothing in 01_tables,
  02_constraints or 03_indexes turned it on. So a deployment could run all 46
  scripts correctly and end by reporting its own omission - which is exactly
  what happened on DevTest5: 22 tables, every index and every constraint built,
  then "Isolation: FAILED".

  The package this one replaced DID set it (scripts, eyshield_handoff,
  "1. TSG_Core.sql"), so a check that outlived its fix is a regression, not a
  deliberate division of labour.

  WHAT THE SETTING DOES, AND WHY THE APPLICATION INSISTS
  ---------------------------------------------------------------------------
  With it OFF, a reader WAITS for whoever is mid-write on the row. TSG runs
  several pipeline stages concurrently over the same session rows, so two of
  them end up waiting on each other and the pipeline deadlocks. With it ON, the
  reader is handed the last committed version at once and never blocks.

  app/db/invariants.py::_assert_rcsi_enabled raises StartupInvariantError when
  it is off, so the API and the workers do not boot. This is not advisory.

  THE ONE SWITCH IN THIS FILE: @disconnect_others
  ---------------------------------------------------------------------------
  Changing this setting needs exclusive access to the database, so the ALTER has
  to do SOMETHING about the other connections. The three choices are not equal:

    no clause           waits forever for every other session to leave. Inside a
                        47-script run that is a silent hang with no output.
                        Not offered here at all.
    NO_WAIT             fails immediately rather than waiting. Nobody is
                        disconnected, nothing hangs.   <-- @disconnect_others = 0
    ROLLBACK IMMEDIATE  disconnects every other session and rolls back its work
                        mid-transaction. Always fast, always destructive - and
                        this database also holds the platform tables
                        (ctm_scan_entity, user, the onboarding_ tables) that
                        other applications read.       <-- @disconnect_others = 1

  BOTH are in this script, because nobody should have to hand-type a destructive
  ALTER with their own database name in it - that is how the wrong database gets
  hit. The switch chooses which one runs, and it starts at 0.

  WHY IT STARTS AT 0. "Force everyone off" is not a property of the DATABASE, it
  is a property of the MOMENT. At 2pm a colleague is mid-report and loses their
  work with no warning; at 9pm in an agreed window nobody notices. Same command,
  same database - only the timing differs, and this script cannot tell those two
  apart. So at 0 it fixes an idle database silently, and on a busy one it changes
  NOTHING, names who is holding it, and STOPS the deployment here rather than
  letting 44 more scripts run and fail at the last.

  Set it to 1 once you have decided this is that moment.

  READ sys.databases, NEVER DATABASEPROPERTYEX. That property returned NULL on a
  SQL Server 2022 Express instance whose setting was demonstrably ON, and every
  comparison against NULL is UNKNOWN, so the check silently decided nothing.
  is_read_committed_snapshot_on is a non-nullable bit present for every
  database. A row this script cannot READ is reported as its own case and is
  never ALTERed blind, because the command it would otherwise suggest
  disconnects people.

  RUN THIS PACKAGE WITH "sqlcmd -b" so the RAISERROR below really does stop the
  sequence. Without -b, sqlcmd prints the error and carries on to 01_tables.
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- isolation level: READ_COMMITTED_SNAPSHOT ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*  vvv  THE ONLY LINE IN THIS PACKAGE YOU ARE MEANT TO EDIT  vvv
    1 = turn the setting on whatever it takes. On an idle database nobody is
        affected; on a busy one every other session is disconnected and its
        in-flight work rolled back. This is the default because the setting is
        REQUIRED - the API does not start without it, so a run that leaves it
        off has not deployed anything.
    0 = never interrupt anyone. A busy database is reported and the deployment
        stops instead. Use this if you would rather choose the moment.         */
DECLARE @disconnect_others bit = 1;

DECLARE @rcsi bit = (SELECT d.is_read_committed_snapshot_on
                     FROM sys.databases d WHERE d.database_id = DB_ID());

IF @rcsi = 1
    PRINT ' [EXISTS]  READ_COMMITTED_SNAPSHOT is already ON. Nothing was changed.';

ELSE IF @rcsi IS NULL
BEGIN
    PRINT ' [ERROR]   Could not read this database''s isolation setting - no visible';
    PRINT '          sys.databases row for DB_ID(). NOTHING was changed.';
    PRINT '          Check the setting by hand before deploying, and do NOT run the';
    PRINT '          ALTER blind: the form that always succeeds disconnects every';
    PRINT '          open session on this database.';
    RAISERROR('READ_COMMITTED_SNAPSHOT could not be read - deployment stopped.', 16, 1);
END

ELSE
BEGIN
    IF @disconnect_others = 1
    BEGIN
        PRINT ' [WARNING] READ_COMMITTED_SNAPSHOT is OFF, and @disconnect_others is 1.';
        PRINT '          EVERY other session on this database is about to be';
        PRINT '          disconnected and its in-flight work rolled back.';
    END
    ELSE
    BEGIN
        PRINT ' [INFO]    READ_COMMITTED_SNAPSHOT is OFF. Turning it on without waiting';
        PRINT '          for anybody, and without disconnecting anybody.';
    END

    /*  Two literal statements rather than one built by sp_executesql. Dynamic SQL
        would spare the IF, but it would also hide the destructive form inside a
        string - and a deployment script has to let a reviewer SEE, by reading it,
        exactly what it is able to do to their database. */
    BEGIN TRY
        IF @disconnect_others = 1
            ALTER DATABASE CURRENT SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE;
        ELSE
            ALTER DATABASE CURRENT SET READ_COMMITTED_SNAPSHOT ON WITH NO_WAIT;

        PRINT ' [FIXED]   READ_COMMITTED_SNAPSHOT is now ON.'
              + CASE WHEN @disconnect_others = 1
                     THEN ' Other sessions were disconnected.' ELSE '' END;
    END TRY
    BEGIN CATCH
        PRINT ' [FAIL]    READ_COMMITTED_SNAPSHOT could not be turned on. NOTHING was';
        PRINT '          changed, and no session was disconnected.';
        PRINT '          SQL Server said (' + CAST(ERROR_NUMBER() AS varchar(10)) + '): '
              + ERROR_MESSAGE();

        /* Branch on what is OBSERVABLE, never on the error number. The first draft of
           this script gated the remedy on `ERROR_NUMBER() IN (5061, 5030, 1205, 1222)`
           - every "database is in use" code that looked plausible. A live run with one
           other session connected raised 5069 ("ALTER DATABASE statement failed."), so
           the one branch that mattered was skipped: the operator was told it was a
           permissions problem, was shown nobody, and never got the command that works.

           "Is anybody else connected?" is the real question, and sys.dm_exec_sessions
           answers it directly - with no catalogue of numbers to go stale the next time
           SQL Server picks a different one. */
        IF EXISTS (SELECT 1 FROM sys.dm_exec_sessions s
                   WHERE s.database_id = DB_ID() AND s.session_id <> @@SPID)
        BEGIN
            /*  PRINTed, NOT returned as a result set. SSMS sends a SELECT to the Results
                grid and PRINT to the Messages pane, so the first version of this told an
                operator reading the Messages pane "Somebody else is connected to this
                database:" and then, with no names in between, "Two ways forward" - the one
                fact they needed was in a tab they had no reason to open. sqlcmd interleaves
                the two, SSMS separates them, and the script has to be legible in both.

                Also padded by hand: at their natural sysname width (nvarchar 128) these
                columns wrap into noise. This listing is only ever read during a failure. */
            DECLARE @others int = 0, @who nvarchar(max) = N'';

            SELECT @others = COUNT(*)
            FROM   sys.dm_exec_sessions s
            WHERE  s.database_id = DB_ID() AND s.session_id <> @@SPID;

            SELECT @who = @who + CHAR(13) + CHAR(10) + N'            ' +
                          RIGHT(N'      ' + CAST(s.session_id AS nvarchar(10)), 6) + N'  ' +
                          LEFT(ISNULL(s.login_name,   N'?') + SPACE(30), 30) + N'  ' +
                          LEFT(ISNULL(s.host_name,    N'?') + SPACE(18), 18) + N'  ' +
                          LEFT(ISNULL(s.program_name, N'?') + SPACE(30), 30)
            FROM   sys.dm_exec_sessions s
            WHERE  s.database_id = DB_ID() AND s.session_id <> @@SPID;

            PRINT '          Somebody else is connected to this database - ' +
                  CAST(@others AS varchar(10)) + ' other session(s):';
            PRINT '              SPID  LOGIN                           HOST' +
                  '                PROGRAM';
            PRINT @who;

            /* PRINT stops at 4000 characters, so a very busy database shows a partial
               list. The COUNT above is read separately and is always exact. */
            IF @others > 40
                PRINT '          (the list above is cut off by PRINT; the count is exact)';

            PRINT '          Two ways forward:';
            PRINT '            1. Ask them to disconnect, then run this script again.';
            PRINT '            2. In an agreed maintenance window, set @disconnect_others';
            PRINT '               to 1 at the top of THIS script and run it again. It will';
            PRINT '               then disconnect the sessions listed above and roll back';
            PRINT '               their work. Put it back to 0 afterwards.';
        END
        ELSE
        BEGIN
            PRINT '          No other session is visible from this login, so this is most';
            PRINT '          likely a permissions problem: either no ALTER permission on the';
            PRINT '          database, or no VIEW SERVER STATE - and without that second one';
            PRINT '          the sessions holding it are hidden from the listing above rather';
            PRINT '          than absent. Ask a DBA to run:';
            PRINT '          ALTER DATABASE [' + DB_NAME() +
                  '] SET READ_COMMITTED_SNAPSHOT ON;';
            PRINT '          ...adding WITH ROLLBACK IMMEDIATE only if that reports the';
            PRINT '          database is in use. It disconnects everyone on it.';
        END

        /* The flag, because END CATCH resets @@ERROR: without it the stop-check that
           TSG_Deploy_All.sql runs after this batch never sees the RAISERROR below. */
        EXEC sp_set_session_context N'tsg_deploy_failed', 1;
        RAISERROR('READ_COMMITTED_SNAPSHOT is OFF and could not be turned on - deployment stopped.',
                  16, 1);
    END CATCH
END;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 4 of 51   01_tables/001_Threat_Category.sql
============================================================================*/
PRINT '';
PRINT '>>> [4/51] 01_tables/001_Threat_Category.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  TABLE: Threat_Category

  Script:      001_Threat_Category.sql
  Order:       01_tables / 001
  Purpose:     Create Threat_Category, or bring an existing copy up to 8 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Threat_Category

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- Threat_Category ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF OBJECT_ID('dbo.Threat_Category', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Threat_Category] (
        [ThreatCategoryID] INT NOT NULL,
        [ThreatCategoryName] NVARCHAR(200) NOT NULL,
        [IsActive] BIT NOT NULL,
        [IsDeleted] BIT NOT NULL,
        [CreatedAt] DATETIME2(7) NULL,
        [CreatedBy] NVARCHAR(200) NULL,
        [UpdatedAt] DATETIME2(7) NULL,
        [UpdatedBy] NVARCHAR(200) NULL,
        CONSTRAINT [PK_Threat_Category] PRIMARY KEY CLUSTERED ([ThreatCategoryID])
    );
    PRINT ' [CREATED] Table: Threat_Category (8 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Threat_Category';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Threat_Category', @column = N'ThreatCategoryID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Category', @column = N'ThreatCategoryName',
     @expected = N'NVARCHAR(200)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Category', @column = N'IsActive',
     @expected = N'BIT', @nullable = 0, @fill = N'1';
EXEC dbo.tsg_reconcile_column @table = N'Threat_Category', @column = N'IsDeleted',
     @expected = N'BIT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Threat_Category', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Category', @column = N'CreatedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Category', @column = N'UpdatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Category', @column = N'UpdatedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Threat_Category', @columns = N'ThreatCategoryID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Threat_Category', @known = N'ThreatCategoryID,ThreatCategoryName,IsActive,IsDeleted,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 5 of 51   01_tables/002_Threat_Type.sql
============================================================================*/
PRINT '';
PRINT '>>> [5/51] 01_tables/002_Threat_Type.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  TABLE: Threat_Type

  Script:      002_Threat_Type.sql
  Order:       01_tables / 002
  Purpose:     Create Threat_Type, or bring an existing copy up to 10 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Threat_Type

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- Threat_Type ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF OBJECT_ID('dbo.Threat_Type', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Threat_Type] (
        [ThreatTypeID] INT IDENTITY(1,1) NOT NULL,
        [ThreatTypeName] NVARCHAR(300) NOT NULL,
        [ThreatCategoryID] INT NULL,
        [IsActive] BIT NOT NULL,
        [IsDeleted] BIT NOT NULL,
        [Source] NVARCHAR(50) NULL,
        [CreatedAt] DATETIME2(7) NULL,
        [CreatedBy] NVARCHAR(200) NULL,
        [UpdatedAt] DATETIME2(7) NULL,
        [UpdatedBy] NVARCHAR(200) NULL,
        CONSTRAINT [PK_Threat_Type] PRIMARY KEY CLUSTERED ([ThreatTypeID])
    );
    PRINT ' [CREATED] Table: Threat_Type (10 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Threat_Type';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Threat_Type', @column = N'ThreatTypeID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Type', @column = N'ThreatTypeName',
     @expected = N'NVARCHAR(300)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Type', @column = N'ThreatCategoryID',
     @expected = N'INT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Type', @column = N'IsActive',
     @expected = N'BIT', @nullable = 0, @fill = N'1';
EXEC dbo.tsg_reconcile_column @table = N'Threat_Type', @column = N'IsDeleted',
     @expected = N'BIT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Threat_Type', @column = N'Source',
     @expected = N'NVARCHAR(50)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Type', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Type', @column = N'CreatedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Type', @column = N'UpdatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Type', @column = N'UpdatedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Threat_Type', @columns = N'ThreatTypeID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Threat_Type', @known = N'ThreatTypeID,ThreatTypeName,ThreatCategoryID,IsActive,IsDeleted,Source,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 6 of 51   01_tables/003_Threat_Catalogue.sql
============================================================================*/
PRINT '';
PRINT '>>> [6/51] 01_tables/003_Threat_Catalogue.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  TABLE: Threat_Catalogue

  Script:      003_Threat_Catalogue.sql
  Order:       01_tables / 003
  Purpose:     Create Threat_Catalogue, or bring an existing copy up to 10 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Threat_Catalogue

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- Threat_Catalogue ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF OBJECT_ID('dbo.Threat_Catalogue', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Threat_Catalogue] (
        [ThreatCatalogueID] INT IDENTITY(1,1) NOT NULL,
        [ThreatTypeID] INT NOT NULL,
        [ThreatName] NVARCHAR(500) NOT NULL,
        [IsActive] BIT NOT NULL,
        [IsDeleted] BIT NOT NULL,
        [Source] NVARCHAR(100) NULL,
        [CreatedAt] DATETIME2(7) NULL,
        [CreatedBy] NVARCHAR(200) NULL,
        [UpdatedAt] DATETIME2(7) NULL,
        [UpdatedBy] NVARCHAR(200) NULL,
        CONSTRAINT [PK_Threat_Catalogue] PRIMARY KEY CLUSTERED ([ThreatCatalogueID])
    );
    PRINT ' [CREATED] Table: Threat_Catalogue (10 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Threat_Catalogue';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Threat_Catalogue', @column = N'ThreatCatalogueID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Catalogue', @column = N'ThreatTypeID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Catalogue', @column = N'ThreatName',
     @expected = N'NVARCHAR(500)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Catalogue', @column = N'IsActive',
     @expected = N'BIT', @nullable = 0, @fill = N'1';
EXEC dbo.tsg_reconcile_column @table = N'Threat_Catalogue', @column = N'IsDeleted',
     @expected = N'BIT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Threat_Catalogue', @column = N'Source',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Catalogue', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Catalogue', @column = N'CreatedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Catalogue', @column = N'UpdatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Catalogue', @column = N'UpdatedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Threat_Catalogue', @columns = N'ThreatCatalogueID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Threat_Catalogue', @known = N'ThreatCatalogueID,ThreatTypeID,ThreatName,IsActive,IsDeleted,Source,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 7 of 51   01_tables/004_Threat_Actor.sql
============================================================================*/
PRINT '';
PRINT '>>> [7/51] 01_tables/004_Threat_Actor.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  TABLE: Threat_Actor

  Script:      004_Threat_Actor.sql
  Order:       01_tables / 004
  Purpose:     Create Threat_Actor, or bring an existing copy up to 10 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Threat_Actor

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- Threat_Actor ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF OBJECT_ID('dbo.Threat_Actor', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Threat_Actor] (
        [ThreatActorID] INT IDENTITY(1,1) NOT NULL,
        [ThreatActorName] NVARCHAR(200) NOT NULL,
        [IsCapable] INT NOT NULL,
        [IsActive] BIT NOT NULL,
        [IsDeleted] BIT NOT NULL,
        [Source] NVARCHAR(100) NULL,
        [CreatedAt] DATETIME2(7) NULL,
        [CreatedBy] NVARCHAR(200) NULL,
        [UpdatedAt] DATETIME2(7) NULL,
        [UpdatedBy] NVARCHAR(200) NULL,
        CONSTRAINT [PK_Threat_Actor] PRIMARY KEY CLUSTERED ([ThreatActorID])
    );
    PRINT ' [CREATED] Table: Threat_Actor (10 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Threat_Actor';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Threat_Actor', @column = N'ThreatActorID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Actor', @column = N'ThreatActorName',
     @expected = N'NVARCHAR(200)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Actor', @column = N'IsCapable',
     @expected = N'INT', @nullable = 0, @fill = N'1';
EXEC dbo.tsg_reconcile_column @table = N'Threat_Actor', @column = N'IsActive',
     @expected = N'BIT', @nullable = 0, @fill = N'1';
EXEC dbo.tsg_reconcile_column @table = N'Threat_Actor', @column = N'IsDeleted',
     @expected = N'BIT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Threat_Actor', @column = N'Source',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Actor', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Actor', @column = N'CreatedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Actor', @column = N'UpdatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Actor', @column = N'UpdatedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Threat_Actor', @columns = N'ThreatActorID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Threat_Actor', @known = N'ThreatActorID,ThreatActorName,IsCapable,IsActive,IsDeleted,Source,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 8 of 51   01_tables/005_Threat_Catalogue_Category_Map.sql
============================================================================*/
PRINT '';
PRINT '>>> [8/51] 01_tables/005_Threat_Catalogue_Category_Map.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  TABLE: Threat_Catalogue_Category_Map

  Script:      005_Threat_Catalogue_Category_Map.sql
  Order:       01_tables / 005
  Purpose:     Create Threat_Catalogue_Category_Map, or bring an existing copy up to 3 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Threat_Catalogue_Category_Map

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- Threat_Catalogue_Category_Map ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF OBJECT_ID('dbo.Threat_Catalogue_Category_Map', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Threat_Catalogue_Category_Map] (
        [ThreatCategoryID] INT NOT NULL,
        [ThreatCatalogueID] INT NOT NULL,
        [CreatedAt] DATETIME2(7) NULL,
        CONSTRAINT [PK_Threat_Catalogue_Category_Map] PRIMARY KEY CLUSTERED ([ThreatCategoryID], [ThreatCatalogueID])
    );
    PRINT ' [CREATED] Table: Threat_Catalogue_Category_Map (3 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Threat_Catalogue_Category_Map';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Threat_Catalogue_Category_Map', @column = N'ThreatCategoryID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Catalogue_Category_Map', @column = N'ThreatCatalogueID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Catalogue_Category_Map', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Threat_Catalogue_Category_Map', @columns = N'ThreatCategoryID,ThreatCatalogueID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Threat_Catalogue_Category_Map', @known = N'ThreatCategoryID,ThreatCatalogueID,CreatedAt';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 9 of 51   01_tables/006_ThreatType_ThreatActor_Map.sql
============================================================================*/
PRINT '';
PRINT '>>> [9/51] 01_tables/006_ThreatType_ThreatActor_Map.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  TABLE: ThreatType_ThreatActor_Map

  Script:      006_ThreatType_ThreatActor_Map.sql
  Order:       01_tables / 006
  Purpose:     Create ThreatType_ThreatActor_Map, or bring an existing copy up to 3 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.ThreatType_ThreatActor_Map

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- ThreatType_ThreatActor_Map ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF OBJECT_ID('dbo.ThreatType_ThreatActor_Map', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[ThreatType_ThreatActor_Map] (
        [ThreatTypeID] INT NOT NULL,
        [ThreatActorID] INT NOT NULL,
        [CreatedAt] DATETIME2(7) NULL,
        CONSTRAINT [PK_ThreatType_ThreatActor_Map] PRIMARY KEY CLUSTERED ([ThreatTypeID], [ThreatActorID])
    );
    PRINT ' [CREATED] Table: ThreatType_ThreatActor_Map (3 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: ThreatType_ThreatActor_Map';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'ThreatType_ThreatActor_Map', @column = N'ThreatTypeID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'ThreatType_ThreatActor_Map', @column = N'ThreatActorID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'ThreatType_ThreatActor_Map', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'ThreatType_ThreatActor_Map', @columns = N'ThreatTypeID,ThreatActorID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'ThreatType_ThreatActor_Map', @known = N'ThreatTypeID,ThreatActorID,CreatedAt';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 10 of 51   01_tables/007_Control_Standard.sql
============================================================================*/
PRINT '';
PRINT '>>> [10/51] 01_tables/007_Control_Standard.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  TABLE: Control_Standard

  Script:      007_Control_Standard.sql
  Order:       01_tables / 007
  Purpose:     Create Control_Standard, or bring an existing copy up to 9 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Control_Standard

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- Control_Standard ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF OBJECT_ID('dbo.Control_Standard', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Control_Standard] (
        [StandardID] INT IDENTITY(1,1) NOT NULL,
        [StandardName] NVARCHAR(200) NOT NULL,
        [Source] NVARCHAR(100) NULL,
        [CreatedAt] DATETIME NULL,
        [CreatedBy] NVARCHAR(200) NULL,
        [UpdatedAt] DATETIME NULL,
        [UpdatedBy] NVARCHAR(200) NULL,
        [IsActive] BIT NOT NULL,
        [IsDeleted] BIT NOT NULL,
        CONSTRAINT [PK_Control_Standard] PRIMARY KEY CLUSTERED ([StandardID])
    );
    PRINT ' [CREATED] Table: Control_Standard (9 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Control_Standard';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Control_Standard', @column = N'StandardID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Control_Standard', @column = N'StandardName',
     @expected = N'NVARCHAR(200)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Control_Standard', @column = N'Source',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Control_Standard', @column = N'CreatedAt',
     @expected = N'DATETIME', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Control_Standard', @column = N'CreatedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Control_Standard', @column = N'UpdatedAt',
     @expected = N'DATETIME', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Control_Standard', @column = N'UpdatedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Control_Standard', @column = N'IsActive',
     @expected = N'BIT', @nullable = 0, @fill = N'1';
EXEC dbo.tsg_reconcile_column @table = N'Control_Standard', @column = N'IsDeleted',
     @expected = N'BIT', @nullable = 0, @fill = N'0';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Control_Standard', @columns = N'StandardID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Control_Standard', @known = N'StandardID,StandardName,Source,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy,IsActive,IsDeleted';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 11 of 51   01_tables/008_Control_Library.sql
============================================================================*/
PRINT '';
PRINT '>>> [11/51] 01_tables/008_Control_Library.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  TABLE: Control_Library

  Script:      008_Control_Library.sql
  Order:       01_tables / 008
  Purpose:     Create Control_Library, or bring an existing copy up to 14 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Control_Library

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- Control_Library ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF OBJECT_ID('dbo.Control_Library', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Control_Library] (
        [ControlLibraryID] INT IDENTITY(1,1) NOT NULL,
        [ControlCode] NVARCHAR(100) NOT NULL,
        [ITOT] NVARCHAR(100) NOT NULL,
        [Domain] NVARCHAR(200) NOT NULL,
        [ControlName] NVARCHAR(500) NOT NULL,
        [ControlDescription] NVARCHAR(max) NOT NULL,
        [SampleEvidence] NVARCHAR(max) NULL,
        [Source] NVARCHAR(100) NULL,
        [CreatedAt] DATETIME NULL,
        [CreatedBy] NVARCHAR(200) NULL,
        [UpdatedAt] DATETIME NULL,
        [UpdatedBy] NVARCHAR(200) NULL,
        [IsActive] BIT NOT NULL,
        [IsDeleted] BIT NOT NULL,
        CONSTRAINT [PK_Control_Library] PRIMARY KEY CLUSTERED ([ControlLibraryID])
    );
    PRINT ' [CREATED] Table: Control_Library (14 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Control_Library';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'ControlLibraryID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'ControlCode',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'ITOT',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'Domain',
     @expected = N'NVARCHAR(200)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'ControlName',
     @expected = N'NVARCHAR(500)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'ControlDescription',
     @expected = N'NVARCHAR(max)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'SampleEvidence',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'Source',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'CreatedAt',
     @expected = N'DATETIME', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'CreatedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'UpdatedAt',
     @expected = N'DATETIME', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'UpdatedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'IsActive',
     @expected = N'BIT', @nullable = 0, @fill = N'1';
EXEC dbo.tsg_reconcile_column @table = N'Control_Library', @column = N'IsDeleted',
     @expected = N'BIT', @nullable = 0, @fill = N'0';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Control_Library', @columns = N'ControlLibraryID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Control_Library', @known = N'ControlLibraryID,ControlCode,ITOT,Domain,ControlName,ControlDescription,SampleEvidence,Source,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy,IsActive,IsDeleted';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 12 of 51   01_tables/009_Control_Library_Standard_Map.sql
============================================================================*/
PRINT '';
PRINT '>>> [12/51] 01_tables/009_Control_Library_Standard_Map.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  TABLE: Control_Library_Standard_Map

  Script:      009_Control_Library_Standard_Map.sql
  Order:       01_tables / 009
  Purpose:     Create Control_Library_Standard_Map, or bring an existing copy up to 3 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Control_Library_Standard_Map

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- Control_Library_Standard_Map ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF OBJECT_ID('dbo.Control_Library_Standard_Map', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Control_Library_Standard_Map] (
        [ControlLibraryID] INT NOT NULL,
        [StandardID] INT NOT NULL,
        [CreatedAt] DATETIME2(7) NULL,
        CONSTRAINT [PK_Control_Library_Standard_Map] PRIMARY KEY CLUSTERED ([ControlLibraryID], [StandardID])
    );
    PRINT ' [CREATED] Table: Control_Library_Standard_Map (3 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Control_Library_Standard_Map';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Control_Library_Standard_Map', @column = N'ControlLibraryID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Control_Library_Standard_Map', @column = N'StandardID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Control_Library_Standard_Map', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Control_Library_Standard_Map', @columns = N'ControlLibraryID,StandardID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Control_Library_Standard_Map', @known = N'ControlLibraryID,StandardID,CreatedAt';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 13 of 51   01_tables/010_API_Client.sql
============================================================================*/
PRINT '';
PRINT '>>> [13/51] 01_tables/010_API_Client.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  TABLE: API_Client

  Script:      010_API_Client.sql
  Order:       01_tables / 010
  Purpose:     Create API_Client, or bring an existing copy up to 9 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.API_Client

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- API_Client ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF OBJECT_ID('dbo.API_Client', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[API_Client] (
        [ClientID] NVARCHAR(100) NOT NULL,
        [KeyHash] NVARCHAR(100) NOT NULL,
        [Name] NVARCHAR(200) NOT NULL,
        [Module] NVARCHAR(100) NOT NULL,
        [Active] BIT NOT NULL,
        [CreatedAt] DATETIME2(3) NOT NULL,
        [CreatedBy] NVARCHAR(200) NULL,
        [RevokedAt] DATETIME2(3) NULL,
        [RevokedBy] NVARCHAR(200) NULL,
        CONSTRAINT [PK_API_Client] PRIMARY KEY CLUSTERED ([ClientID])
    );
    PRINT ' [CREATED] Table: API_Client (9 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: API_Client';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'API_Client', @column = N'ClientID',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'API_Client', @column = N'KeyHash',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'API_Client', @column = N'Name',
     @expected = N'NVARCHAR(200)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'API_Client', @column = N'Module',
     @expected = N'NVARCHAR(100)', @nullable = 0, @fill = N'N''tsg''';
EXEC dbo.tsg_reconcile_column @table = N'API_Client', @column = N'Active',
     @expected = N'BIT', @nullable = 0, @fill = N'1';
EXEC dbo.tsg_reconcile_column @table = N'API_Client', @column = N'CreatedAt',
     @expected = N'DATETIME2(3)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'API_Client', @column = N'CreatedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'API_Client', @column = N'RevokedAt',
     @expected = N'DATETIME2(3)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'API_Client', @column = N'RevokedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'API_Client', @columns = N'ClientID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'API_Client', @known = N'ClientID,KeyHash,Name,Module,Active,CreatedAt,CreatedBy,RevokedAt,RevokedBy';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 14 of 51   01_tables/011_Config_Tuning.sql
============================================================================*/
PRINT '';
PRINT '>>> [14/51] 01_tables/011_Config_Tuning.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  TABLE: Config_Tuning

  Script:      011_Config_Tuning.sql
  Order:       01_tables / 011
  Purpose:     Create Config_Tuning, or bring an existing copy up to 11 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Config_Tuning

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- Config_Tuning ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF OBJECT_ID('dbo.Config_Tuning', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Config_Tuning] (
        [TuningID] INT IDENTITY(1,1) NOT NULL,
        [TuningKey] NVARCHAR(100) NOT NULL,
        [TuningValue] NVARCHAR(100) NOT NULL,
        [ValueType] NVARCHAR(100) NOT NULL,
        [EmbeddingModel] NVARCHAR(200) NULL,
        [CreateDate] DATETIME2(7) NULL,
        [CreatedBy] NVARCHAR(200) NULL,
        [UpdateDate] DATETIME2(7) NULL,
        [UpdatedBy] NVARCHAR(200) NULL,
        [IsActive] BIT NOT NULL,
        [IsDeleted] BIT NOT NULL,
        CONSTRAINT [PK_Config_Tuning] PRIMARY KEY CLUSTERED ([TuningID])
    );
    PRINT ' [CREATED] Table: Config_Tuning (11 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Config_Tuning';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Config_Tuning', @column = N'TuningID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Config_Tuning', @column = N'TuningKey',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Config_Tuning', @column = N'TuningValue',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Config_Tuning', @column = N'ValueType',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Config_Tuning', @column = N'EmbeddingModel',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Config_Tuning', @column = N'CreateDate',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Config_Tuning', @column = N'CreatedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Config_Tuning', @column = N'UpdateDate',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Config_Tuning', @column = N'UpdatedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Config_Tuning', @column = N'IsActive',
     @expected = N'BIT', @nullable = 0, @fill = N'1';
EXEC dbo.tsg_reconcile_column @table = N'Config_Tuning', @column = N'IsDeleted',
     @expected = N'BIT', @nullable = 0, @fill = N'0';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Config_Tuning', @columns = N'TuningID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Config_Tuning', @known = N'TuningID,TuningKey,TuningValue,ValueType,EmbeddingModel,CreateDate,CreatedBy,UpdateDate,UpdatedBy,IsActive,IsDeleted';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 15 of 51   01_tables/012_Grounding_Calibration_Run.sql
============================================================================*/
PRINT '';
PRINT '>>> [15/51] 01_tables/012_Grounding_Calibration_Run.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  TABLE: Grounding_Calibration_Run

  Script:      012_Grounding_Calibration_Run.sql
  Order:       01_tables / 012
  Purpose:     Create Grounding_Calibration_Run, or bring an existing copy up to 19 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Grounding_Calibration_Run

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- Grounding_Calibration_Run ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF OBJECT_ID('dbo.Grounding_Calibration_Run', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Grounding_Calibration_Run] (
        [RunID] UNIQUEIDENTIFIER NOT NULL,
        [JobID] NVARCHAR(100) NULL,
        [Status] NVARCHAR(100) NOT NULL,
        [StartedBy] NVARCHAR(200) NULL,
        [StartedByClient] NVARCHAR(200) NULL,
        [StartedAt] DATETIME2(7) NULL,
        [FinishedAt] DATETIME2(7) NULL,
        [EmbeddingModel] NVARCHAR(500) NULL,
        [RerankerModel] NVARCHAR(500) NULL,
        [Forced] BIT NOT NULL,
        [MatchTh] FLOAT NULL,
        [ControlMapTh] FLOAT NULL,
        [Quality] FLOAT NULL,
        [NegativesCount] INT NULL,
        [PositivesCount] INT NULL,
        [HighestNegative] FLOAT NULL,
        [LowestPositive] FLOAT NULL,
        [NearDuplicatesJSON] NVARCHAR(max) NULL,
        [ErrorMessage] NVARCHAR(max) NULL,
        CONSTRAINT [PK_Grounding_Calibration_Run] PRIMARY KEY CLUSTERED ([RunID])
    );
    PRINT ' [CREATED] Table: Grounding_Calibration_Run (19 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Grounding_Calibration_Run';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'RunID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'JobID',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'Status',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'StartedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'StartedByClient',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'StartedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'FinishedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'EmbeddingModel',
     @expected = N'NVARCHAR(500)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'RerankerModel',
     @expected = N'NVARCHAR(500)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'Forced',
     @expected = N'BIT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'MatchTh',
     @expected = N'FLOAT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'ControlMapTh',
     @expected = N'FLOAT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'Quality',
     @expected = N'FLOAT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'NegativesCount',
     @expected = N'INT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'PositivesCount',
     @expected = N'INT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'HighestNegative',
     @expected = N'FLOAT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'LowestPositive',
     @expected = N'FLOAT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'NearDuplicatesJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Grounding_Calibration_Run', @column = N'ErrorMessage',
     @expected = N'NVARCHAR(max)', @nullable = 1;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Grounding_Calibration_Run', @columns = N'RunID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Grounding_Calibration_Run', @known = N'RunID,JobID,Status,StartedBy,StartedByClient,StartedAt,FinishedAt,EmbeddingModel,RerankerModel,Forced,MatchTh,ControlMapTh,Quality,NegativesCount,PositivesCount,HighestNegative,LowestPositive,NearDuplicatesJSON,ErrorMessage';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 16 of 51   01_tables/013_Scenario_Session.sql
============================================================================*/
PRINT '';
PRINT '>>> [16/51] 01_tables/013_Scenario_Session.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  TABLE: Scenario_Session

  Script:      013_Scenario_Session.sql
  Order:       01_tables / 013
  Purpose:     Create Scenario_Session, or bring an existing copy up to 22 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Scenario_Session

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- Scenario_Session ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF OBJECT_ID('dbo.Scenario_Session', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Scenario_Session] (
        [SessionID] UNIQUEIDENTIFIER NOT NULL,
        [TenantID] NVARCHAR(200) NOT NULL,
        [EntityID] NVARCHAR(200) NOT NULL,
        [UserID] NVARCHAR(200) NULL,
        [AssetName] NVARCHAR(300) NOT NULL,
        [AssetID] NVARCHAR(200) NOT NULL,
        [SessionStatus] NVARCHAR(100) NOT NULL,
        [CurrentStage] NVARCHAR(100) NOT NULL,
        [StageStatus] NVARCHAR(100) NOT NULL,
        [Mode] NVARCHAR(100) NOT NULL,
        [CurrentSubsystemIndex] INT NULL,
        [SubsystemsJSON] NVARCHAR(max) NOT NULL,
        [IdempotencyKey] NVARCHAR(200) NULL,
        [SectorIDsJSON] NVARCHAR(max) NULL,
        [AssetContextJSON] NVARCHAR(max) NULL,
        [ScoringRulesSnapshotJSON] NVARCHAR(max) NULL,
        [CreatedAt] DATETIME2(7) NULL,
        [UpdatedAt] DATETIME2(7) NULL,
        [CompletedAt] DATETIME2(7) NULL,
        [CancelledAt] DATETIME2(7) NULL,
        [CancelledBy] NVARCHAR(200) NULL,
        [ControlMapSeconds] FLOAT NULL,
        CONSTRAINT [PK_Scenario_Session] PRIMARY KEY CLUSTERED ([SessionID])
    );
    PRINT ' [CREATED] Table: Scenario_Session (22 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Scenario_Session';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Legacy column names: renamed in place so their data is kept. */
EXEC dbo.tsg_rename_column @table = N'Scenario_Session', @old = N'TuningJSON', @new = N'ScoringRulesSnapshotJSON';
EXEC dbo.tsg_rename_column @table = N'Scenario_Session', @old = N'TuningSnapshotJSON', @new = N'ScoringRulesSnapshotJSON';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'SessionID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'TenantID',
     @expected = N'NVARCHAR(200)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'EntityID',
     @expected = N'NVARCHAR(200)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'UserID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'AssetName',
     @expected = N'NVARCHAR(300)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'AssetID',
     @expected = N'NVARCHAR(200)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'SessionStatus',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'CurrentStage',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'StageStatus',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'Mode',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'CurrentSubsystemIndex',
     @expected = N'INT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'SubsystemsJSON',
     @expected = N'NVARCHAR(max)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'IdempotencyKey',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'SectorIDsJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'AssetContextJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'ScoringRulesSnapshotJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'UpdatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'CompletedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'CancelledAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'CancelledBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Session', @column = N'ControlMapSeconds',
     @expected = N'FLOAT', @nullable = 1;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Scenario_Session', @columns = N'SessionID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Legacy column TuningJSON, replaced by ScoringRulesSnapshotJSON. Normally already RENAMED away above; it is still here
   only if ScoringRulesSnapshotJSON existed too, in which case its values were copied across. Dropped only when
   EVERY value it holds is already in ScoringRulesSnapshotJSON - nothing is lost. */
IF COL_LENGTH('dbo.Scenario_Session', 'TuningJSON') IS NOT NULL
BEGIN
    DECLARE @n bigint;
    BEGIN TRY
        EXEC sp_executesql N'SELECT @n = COUNT_BIG(*) FROM dbo.[Scenario_Session]
                             WHERE [TuningJSON] IS NOT NULL
                               AND ([ScoringRulesSnapshotJSON] IS NULL OR [ScoringRulesSnapshotJSON] <> [TuningJSON]);',
             N'@n bigint OUTPUT', @n = @n OUTPUT;
        IF @n > 0
        BEGIN
            PRINT ' [BLOCKED] Scenario_Session.TuningJSON holds ' + CAST(@n AS varchar(20)) +
                  ' value(s) that differ from ScoringRulesSnapshotJSON - NOT dropped.';
            PRINT '          Decide which value is right, update ScoringRulesSnapshotJSON, then re-run.';
        END
        ELSE
        BEGIN
            /* Old indexes built on the column go with it, in the same transaction. */
            DECLARE @ix sysname, @ixs nvarchar(max) = N'', @drop nvarchar(max);
            BEGIN TRANSACTION;
            DECLARE legacy_ix CURSOR LOCAL STATIC READ_ONLY FOR
                SELECT i.name
                FROM   sys.indexes i
                WHERE  i.object_id = OBJECT_ID(N'dbo.Scenario_Session') AND i.type IN (1, 2)
                  AND  i.is_primary_key = 0 AND i.is_unique_constraint = 0
                  AND  (EXISTS (SELECT 1 FROM sys.index_columns ic
                                WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id
                                  AND ic.column_id = COLUMNPROPERTY(i.object_id, N'TuningJSON', 'ColumnId'))
                        OR CHARINDEX(N'[TuningJSON]', ISNULL(i.filter_definition, N'')) > 0);
            OPEN legacy_ix; FETCH NEXT FROM legacy_ix INTO @ix;
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @drop = N'DROP INDEX ' + QUOTENAME(@ix) + N' ON dbo.[Scenario_Session];';
                EXEC sp_executesql @drop;
                SET @ixs = @ixs + CASE WHEN @ixs = N'' THEN N'' ELSE N', ' END + @ix;
                FETCH NEXT FROM legacy_ix INTO @ix;
            END;
            CLOSE legacy_ix; DEALLOCATE legacy_ix;
            EXEC sp_executesql N'ALTER TABLE dbo.[Scenario_Session] DROP COLUMN [TuningJSON];';
            COMMIT;
            PRINT ' [DROPPED] Scenario_Session.TuningJSON - legacy column; all of its data is in ScoringRulesSnapshotJSON.';
            IF @ixs <> N''
                PRINT '          Old index(es) on it dropped too: ' + @ixs +
                      ' (the current ones are created by 03_indexes).';
        END
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK;
        PRINT ' [ERROR]   Could not drop Scenario_Session.TuningJSON.';
        PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
        EXEC sp_set_session_context N'tsg_deploy_failed', 1;
        RAISERROR('Legacy column Scenario_Session.TuningJSON could not be dropped - deployment stopped.', 16, 1);
    END CATCH
END
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Legacy column TuningSnapshotJSON, replaced by ScoringRulesSnapshotJSON. Normally already RENAMED away above; it is still here
   only if ScoringRulesSnapshotJSON existed too, in which case its values were copied across. Dropped only when
   EVERY value it holds is already in ScoringRulesSnapshotJSON - nothing is lost. */
IF COL_LENGTH('dbo.Scenario_Session', 'TuningSnapshotJSON') IS NOT NULL
BEGIN
    DECLARE @n bigint;
    BEGIN TRY
        EXEC sp_executesql N'SELECT @n = COUNT_BIG(*) FROM dbo.[Scenario_Session]
                             WHERE [TuningSnapshotJSON] IS NOT NULL
                               AND ([ScoringRulesSnapshotJSON] IS NULL OR [ScoringRulesSnapshotJSON] <> [TuningSnapshotJSON]);',
             N'@n bigint OUTPUT', @n = @n OUTPUT;
        IF @n > 0
        BEGIN
            PRINT ' [BLOCKED] Scenario_Session.TuningSnapshotJSON holds ' + CAST(@n AS varchar(20)) +
                  ' value(s) that differ from ScoringRulesSnapshotJSON - NOT dropped.';
            PRINT '          Decide which value is right, update ScoringRulesSnapshotJSON, then re-run.';
        END
        ELSE
        BEGIN
            /* Old indexes built on the column go with it, in the same transaction. */
            DECLARE @ix sysname, @ixs nvarchar(max) = N'', @drop nvarchar(max);
            BEGIN TRANSACTION;
            DECLARE legacy_ix CURSOR LOCAL STATIC READ_ONLY FOR
                SELECT i.name
                FROM   sys.indexes i
                WHERE  i.object_id = OBJECT_ID(N'dbo.Scenario_Session') AND i.type IN (1, 2)
                  AND  i.is_primary_key = 0 AND i.is_unique_constraint = 0
                  AND  (EXISTS (SELECT 1 FROM sys.index_columns ic
                                WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id
                                  AND ic.column_id = COLUMNPROPERTY(i.object_id, N'TuningSnapshotJSON', 'ColumnId'))
                        OR CHARINDEX(N'[TuningSnapshotJSON]', ISNULL(i.filter_definition, N'')) > 0);
            OPEN legacy_ix; FETCH NEXT FROM legacy_ix INTO @ix;
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @drop = N'DROP INDEX ' + QUOTENAME(@ix) + N' ON dbo.[Scenario_Session];';
                EXEC sp_executesql @drop;
                SET @ixs = @ixs + CASE WHEN @ixs = N'' THEN N'' ELSE N', ' END + @ix;
                FETCH NEXT FROM legacy_ix INTO @ix;
            END;
            CLOSE legacy_ix; DEALLOCATE legacy_ix;
            EXEC sp_executesql N'ALTER TABLE dbo.[Scenario_Session] DROP COLUMN [TuningSnapshotJSON];';
            COMMIT;
            PRINT ' [DROPPED] Scenario_Session.TuningSnapshotJSON - legacy column; all of its data is in ScoringRulesSnapshotJSON.';
            IF @ixs <> N''
                PRINT '          Old index(es) on it dropped too: ' + @ixs +
                      ' (the current ones are created by 03_indexes).';
        END
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK;
        PRINT ' [ERROR]   Could not drop Scenario_Session.TuningSnapshotJSON.';
        PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
        EXEC sp_set_session_context N'tsg_deploy_failed', 1;
        RAISERROR('Legacy column Scenario_Session.TuningSnapshotJSON could not be dropped - deployment stopped.', 16, 1);
    END CATCH
END
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Scenario_Session', @known = N'SessionID,TenantID,EntityID,UserID,AssetName,AssetID,SessionStatus,CurrentStage,StageStatus,Mode,CurrentSubsystemIndex,SubsystemsJSON,IdempotencyKey,SectorIDsJSON,AssetContextJSON,ScoringRulesSnapshotJSON,CreatedAt,UpdatedAt,CompletedAt,CancelledAt,CancelledBy,ControlMapSeconds';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 17 of 51   01_tables/014_Subsystem_Stage_State.sql
============================================================================*/
PRINT '';
PRINT '>>> [17/51] 01_tables/014_Subsystem_Stage_State.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  TABLE: Subsystem_Stage_State

  Script:      014_Subsystem_Stage_State.sql
  Order:       01_tables / 014
  Purpose:     Create Subsystem_Stage_State, or bring an existing copy up to 17 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Subsystem_Stage_State

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- Subsystem_Stage_State ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF OBJECT_ID('dbo.Subsystem_Stage_State', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Subsystem_Stage_State] (
        [StateID] UNIQUEIDENTIFIER NOT NULL,
        [SessionID] UNIQUEIDENTIFIER NOT NULL,
        [TenantID] NVARCHAR(200) NULL,
        [EntityID] NVARCHAR(200) NULL,
        [SubsystemID] INT NOT NULL,
        [Level] NVARCHAR(100) NOT NULL,
        [Status] NVARCHAR(100) NOT NULL,
        [GenerationEpoch] INT NOT NULL,
        [ActiveTaskID] UNIQUEIDENTIFIER NULL,
        [LeaseExpiresAt] DATETIME2(7) NULL,
        [HeartbeatAt] DATETIME2(7) NULL,
        [AttemptCount] INT NOT NULL,
        [ErrorMessage] NVARCHAR(max) NULL,
        [UpdatedAt] DATETIME2(7) NOT NULL,
        [CreatedAt] DATETIME2(7) NULL,
        [StartedAt] DATETIME2(7) NULL,
        [FinishedAt] DATETIME2(7) NULL,
        CONSTRAINT [PK_Subsystem_Stage_State] PRIMARY KEY CLUSTERED ([StateID])
    );
    PRINT ' [CREATED] Table: Subsystem_Stage_State (17 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Subsystem_Stage_State';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'StateID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'SessionID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'TenantID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'EntityID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'SubsystemID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'Level',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'Status',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'GenerationEpoch',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'ActiveTaskID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'LeaseExpiresAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'HeartbeatAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'AttemptCount',
     @expected = N'INT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'ErrorMessage',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'UpdatedAt',
     @expected = N'DATETIME2(7)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'StartedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Subsystem_Stage_State', @column = N'FinishedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Subsystem_Stage_State', @columns = N'StateID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Subsystem_Stage_State', @known = N'StateID,SessionID,TenantID,EntityID,SubsystemID,Level,Status,GenerationEpoch,ActiveTaskID,LeaseExpiresAt,HeartbeatAt,AttemptCount,ErrorMessage,UpdatedAt,CreatedAt,StartedAt,FinishedAt';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 18 of 51   01_tables/015_Identified_Threat.sql
============================================================================*/
PRINT '';
PRINT '>>> [18/51] 01_tables/015_Identified_Threat.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  TABLE: Identified_Threat

  Script:      015_Identified_Threat.sql
  Order:       01_tables / 015
  Purpose:     Create Identified_Threat, or bring an existing copy up to 23 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Identified_Threat

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- Identified_Threat ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF OBJECT_ID('dbo.Identified_Threat', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Identified_Threat] (
        [ThreatID] UNIQUEIDENTIFIER NOT NULL,
        [SessionID] UNIQUEIDENTIFIER NOT NULL,
        [TenantID] NVARCHAR(200) NULL,
        [EntityID] NVARCHAR(200) NULL,
        [UserID] NVARCHAR(200) NULL,
        [SubsystemID] INT NOT NULL,
        [ThreatCategory] NVARCHAR(200) NOT NULL,
        [ThreatType] NVARCHAR(300) NOT NULL,
        [ThreatName] NVARCHAR(500) NULL,
        [GenericName] NVARCHAR(500) NULL,
        [ThreatCategoryID] INT NULL,
        [ThreatActorsJSON] NVARCHAR(max) NULL,
        [LibraryThreatType] NVARCHAR(300) NULL,
        [LibraryThreatName] NVARCHAR(500) NULL,
        [ThreatTypeID] INT NULL,
        [ThreatCatalogueID] INT NULL,
        [IsThreatAIGenerated] BIT NOT NULL,
        [IsThreatTypeAIGenerated] BIT NOT NULL,
        [GroundingStatus] NVARCHAR(100) NOT NULL,
        [GroundingScore] FLOAT NULL,
        [GroundingThresholdOrigin] NVARCHAR(100) NULL,
        [Superseded] INT NOT NULL,
        [CreatedAt] DATETIME2(7) NULL,
        CONSTRAINT [PK_Identified_Threat] PRIMARY KEY CLUSTERED ([ThreatID])
    );
    PRINT ' [CREATED] Table: Identified_Threat (23 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Identified_Threat';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Legacy column names: renamed in place so their data is kept. */
EXEC dbo.tsg_rename_column @table = N'Identified_Threat', @old = N'IsAIGenerated', @new = N'IsThreatAIGenerated';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'ThreatID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'SessionID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'TenantID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'EntityID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'UserID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'SubsystemID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'ThreatCategory',
     @expected = N'NVARCHAR(200)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'ThreatType',
     @expected = N'NVARCHAR(300)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'ThreatName',
     @expected = N'NVARCHAR(500)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'GenericName',
     @expected = N'NVARCHAR(500)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'ThreatCategoryID',
     @expected = N'INT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'ThreatActorsJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'LibraryThreatType',
     @expected = N'NVARCHAR(300)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'LibraryThreatName',
     @expected = N'NVARCHAR(500)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'ThreatTypeID',
     @expected = N'INT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'ThreatCatalogueID',
     @expected = N'INT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'IsThreatAIGenerated',
     @expected = N'BIT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'IsThreatTypeAIGenerated',
     @expected = N'BIT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'GroundingStatus',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'GroundingScore',
     @expected = N'FLOAT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'GroundingThresholdOrigin',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'Superseded',
     @expected = N'INT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Identified_Threat', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Identified_Threat', @columns = N'ThreatID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Legacy column IsAIGenerated, replaced by IsThreatAIGenerated. Normally already RENAMED away above; it is still here
   only if IsThreatAIGenerated existed too, in which case its values were copied across. Dropped only when
   EVERY value it holds is already in IsThreatAIGenerated - nothing is lost. */
IF COL_LENGTH('dbo.Identified_Threat', 'IsAIGenerated') IS NOT NULL
BEGIN
    DECLARE @n bigint;
    BEGIN TRY
        EXEC sp_executesql N'SELECT @n = COUNT_BIG(*) FROM dbo.[Identified_Threat]
                             WHERE [IsAIGenerated] IS NOT NULL
                               AND ([IsThreatAIGenerated] IS NULL OR [IsThreatAIGenerated] <> [IsAIGenerated]);',
             N'@n bigint OUTPUT', @n = @n OUTPUT;
        IF @n > 0
        BEGIN
            PRINT ' [BLOCKED] Identified_Threat.IsAIGenerated holds ' + CAST(@n AS varchar(20)) +
                  ' value(s) that differ from IsThreatAIGenerated - NOT dropped.';
            PRINT '          Decide which value is right, update IsThreatAIGenerated, then re-run.';
        END
        ELSE
        BEGIN
            /* Old indexes built on the column go with it, in the same transaction. */
            DECLARE @ix sysname, @ixs nvarchar(max) = N'', @drop nvarchar(max);
            BEGIN TRANSACTION;
            DECLARE legacy_ix CURSOR LOCAL STATIC READ_ONLY FOR
                SELECT i.name
                FROM   sys.indexes i
                WHERE  i.object_id = OBJECT_ID(N'dbo.Identified_Threat') AND i.type IN (1, 2)
                  AND  i.is_primary_key = 0 AND i.is_unique_constraint = 0
                  AND  (EXISTS (SELECT 1 FROM sys.index_columns ic
                                WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id
                                  AND ic.column_id = COLUMNPROPERTY(i.object_id, N'IsAIGenerated', 'ColumnId'))
                        OR CHARINDEX(N'[IsAIGenerated]', ISNULL(i.filter_definition, N'')) > 0);
            OPEN legacy_ix; FETCH NEXT FROM legacy_ix INTO @ix;
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @drop = N'DROP INDEX ' + QUOTENAME(@ix) + N' ON dbo.[Identified_Threat];';
                EXEC sp_executesql @drop;
                SET @ixs = @ixs + CASE WHEN @ixs = N'' THEN N'' ELSE N', ' END + @ix;
                FETCH NEXT FROM legacy_ix INTO @ix;
            END;
            CLOSE legacy_ix; DEALLOCATE legacy_ix;
            EXEC sp_executesql N'ALTER TABLE dbo.[Identified_Threat] DROP COLUMN [IsAIGenerated];';
            COMMIT;
            PRINT ' [DROPPED] Identified_Threat.IsAIGenerated - legacy column; all of its data is in IsThreatAIGenerated.';
            IF @ixs <> N''
                PRINT '          Old index(es) on it dropped too: ' + @ixs +
                      ' (the current ones are created by 03_indexes).';
        END
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK;
        PRINT ' [ERROR]   Could not drop Identified_Threat.IsAIGenerated.';
        PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
        EXEC sp_set_session_context N'tsg_deploy_failed', 1;
        RAISERROR('Legacy column Identified_Threat.IsAIGenerated could not be dropped - deployment stopped.', 16, 1);
    END CATCH
END
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Identified_Threat', @known = N'ThreatID,SessionID,TenantID,EntityID,UserID,SubsystemID,ThreatCategory,ThreatType,ThreatName,GenericName,ThreatCategoryID,ThreatActorsJSON,LibraryThreatType,LibraryThreatName,ThreatTypeID,ThreatCatalogueID,IsThreatAIGenerated,IsThreatTypeAIGenerated,GroundingStatus,GroundingScore,GroundingThresholdOrigin,Superseded,CreatedAt';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 19 of 51   01_tables/016_Identified_Duplicate_Threat.sql
============================================================================*/
PRINT '';
PRINT '>>> [19/51] 01_tables/016_Identified_Duplicate_Threat.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  TABLE: Identified_Duplicate_Threat

  Script:      016_Identified_Duplicate_Threat.sql
  Order:       01_tables / 016
  Purpose:     Create Identified_Duplicate_Threat, or bring an existing copy up to 15 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Identified_Duplicate_Threat

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- Identified_Duplicate_Threat ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF OBJECT_ID('dbo.Identified_Duplicate_Threat', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Identified_Duplicate_Threat] (
        [DuplicateThreatID] UNIQUEIDENTIFIER NOT NULL,
        [SessionID] UNIQUEIDENTIFIER NOT NULL,
        [TenantID] NVARCHAR(200) NULL,
        [EntityID] NVARCHAR(200) NULL,
        [UserID] NVARCHAR(200) NULL,
        [SubsystemID] INT NOT NULL,
        [ThreatCategory] NVARCHAR(200) NOT NULL,
        [ThreatType] NVARCHAR(300) NOT NULL,
        [ThreatName] NVARCHAR(500) NULL,
        [GenericName] NVARCHAR(500) NULL,
        [ThreatActorsJSON] NVARCHAR(max) NULL,
        [DuplicateOfThreatID] UNIQUEIDENTIFIER NULL,
        [DuplicateReason] NVARCHAR(100) NOT NULL,
        [SimilarityScore] FLOAT NULL,
        [CreatedAt] DATETIME2(7) NULL,
        CONSTRAINT [PK_Identified_Duplicate_Threat] PRIMARY KEY CLUSTERED ([DuplicateThreatID])
    );
    PRINT ' [CREATED] Table: Identified_Duplicate_Threat (15 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Identified_Duplicate_Threat';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'DuplicateThreatID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'SessionID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'TenantID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'EntityID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'UserID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'SubsystemID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'ThreatCategory',
     @expected = N'NVARCHAR(200)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'ThreatType',
     @expected = N'NVARCHAR(300)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'ThreatName',
     @expected = N'NVARCHAR(500)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'GenericName',
     @expected = N'NVARCHAR(500)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'ThreatActorsJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'DuplicateOfThreatID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'DuplicateReason',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'SimilarityScore',
     @expected = N'FLOAT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Identified_Duplicate_Threat', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Identified_Duplicate_Threat', @columns = N'DuplicateThreatID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Identified_Duplicate_Threat', @known = N'DuplicateThreatID,SessionID,TenantID,EntityID,UserID,SubsystemID,ThreatCategory,ThreatType,ThreatName,GenericName,ThreatActorsJSON,DuplicateOfThreatID,DuplicateReason,SimilarityScore,CreatedAt';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 20 of 51   01_tables/017_Scoped_Threat.sql
============================================================================*/
PRINT '';
PRINT '>>> [20/51] 01_tables/017_Scoped_Threat.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  TABLE: Scoped_Threat

  Script:      017_Scoped_Threat.sql
  Order:       01_tables / 017
  Purpose:     Create Scoped_Threat, or bring an existing copy up to 16 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Scoped_Threat

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- Scoped_Threat ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF OBJECT_ID('dbo.Scoped_Threat', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Scoped_Threat] (
        [ScopedThreatID] UNIQUEIDENTIFIER NOT NULL,
        [SessionID] UNIQUEIDENTIFIER NOT NULL,
        [TenantID] NVARCHAR(200) NULL,
        [EntityID] NVARCHAR(200) NULL,
        [UserID] NVARCHAR(200) NULL,
        [SubsystemID] INT NOT NULL,
        [ThreatID] UNIQUEIDENTIFIER NOT NULL,
        [Score] FLOAT NOT NULL,
        [ScopeRank] INT NOT NULL,
        [Selected] INT NOT NULL,
        [Reason] NVARCHAR(500) NULL,
        [RejectionKind] NVARCHAR(100) NULL,
        [SelectionKind] NVARCHAR(100) NULL,
        [FactorsJSON] NVARCHAR(max) NULL,
        [Superseded] INT NOT NULL,
        [CreatedAt] DATETIME2(7) NULL,
        CONSTRAINT [PK_Scoped_Threat] PRIMARY KEY CLUSTERED ([ScopedThreatID])
    );
    PRINT ' [CREATED] Table: Scoped_Threat (16 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Scoped_Threat';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'ScopedThreatID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'SessionID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'TenantID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'EntityID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'UserID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'SubsystemID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'ThreatID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'Score',
     @expected = N'FLOAT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'ScopeRank',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'Selected',
     @expected = N'INT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'Reason',
     @expected = N'NVARCHAR(500)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'RejectionKind',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'SelectionKind',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'FactorsJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'Superseded',
     @expected = N'INT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Scoped_Threat', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Scoped_Threat', @columns = N'ScopedThreatID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Scoped_Threat', @known = N'ScopedThreatID,SessionID,TenantID,EntityID,UserID,SubsystemID,ThreatID,Score,ScopeRank,Selected,Reason,RejectionKind,SelectionKind,FactorsJSON,Superseded,CreatedAt';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 21 of 51   01_tables/018_Threat_Scenario.sql
============================================================================*/
PRINT '';
PRINT '>>> [21/51] 01_tables/018_Threat_Scenario.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  TABLE: Threat_Scenario

  Script:      018_Threat_Scenario.sql
  Order:       01_tables / 018
  Purpose:     Create Threat_Scenario, or bring an existing copy up to 28 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Threat_Scenario

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- Threat_Scenario ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Legacy table name Threat_Scenario_Output. Renamed in place - data kept - BEFORE the CREATE below, which
   would otherwise build an empty Threat_Scenario beside it. An empty Threat_Scenario left by an earlier partial run is
   dropped first (it holds nothing); both holding rows is refused rather than guessed at. */
IF OBJECT_ID('dbo.Threat_Scenario_Output', 'U') IS NOT NULL
BEGIN
    DECLARE @old_rows bigint, @new_rows bigint = 0;
    BEGIN TRY
        EXEC sp_executesql N'SELECT @r = COUNT_BIG(*) FROM dbo.[Threat_Scenario_Output];', N'@r bigint OUTPUT', @r = @old_rows OUTPUT;
        IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL
            EXEC sp_executesql N'SELECT @r = COUNT_BIG(*) FROM dbo.[Threat_Scenario];', N'@r bigint OUTPUT', @r = @new_rows OUTPUT;
        IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL AND @new_rows > 0 AND @old_rows > 0
        BEGIN
            PRINT ' [ERROR]   Both Threat_Scenario_Output (' + CAST(@old_rows AS varchar(20)) + ' rows) and Threat_Scenario (' +
                  CAST(@new_rows AS varchar(20)) + ' rows) hold data. Merge them by hand, then re-run.';
            EXEC sp_set_session_context N'tsg_deploy_failed', 1;
            RAISERROR('Legacy table Threat_Scenario_Output and Threat_Scenario both hold data - deployment stopped.', 16, 1);
        END
        ELSE IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL AND @new_rows > 0
            PRINT ' [INFO]    Threat_Scenario_Output is empty and Threat_Scenario holds the data. Threat_Scenario_Output was left alone.';
        ELSE
        BEGIN
            BEGIN TRANSACTION;
            IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NOT NULL
                EXEC sp_executesql N'DROP TABLE dbo.[Threat_Scenario];';   -- empty: nothing is lost
            EXEC sp_rename 'dbo.Threat_Scenario_Output', 'Threat_Scenario', 'OBJECT';
            COMMIT;
            PRINT ' [RENAMED] Table Threat_Scenario_Output -> Threat_Scenario  (' + CAST(@old_rows AS varchar(20)) + ' row(s), data kept)';
        END
    END TRY
    BEGIN CATCH
        DECLARE @e nvarchar(4000) = ERROR_MESSAGE();
        IF @@TRANCOUNT > 0 ROLLBACK;
        PRINT ' [ERROR]   Could not rename table Threat_Scenario_Output to Threat_Scenario: ' + @e;
        EXEC sp_set_session_context N'tsg_deploy_failed', 1;
        RAISERROR('Legacy table Threat_Scenario_Output could not be renamed - deployment stopped.', 16, 1);
    END CATCH
END
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF OBJECT_ID('dbo.Threat_Scenario', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Threat_Scenario] (
        [ScenarioID] UNIQUEIDENTIFIER NOT NULL,
        [SessionID] UNIQUEIDENTIFIER NOT NULL,
        [TenantID] NVARCHAR(200) NULL,
        [EntityID] NVARCHAR(200) NULL,
        [UserID] NVARCHAR(200) NULL,
        [SubsystemID] INT NOT NULL,
        [ScopedThreatID] UNIQUEIDENTIFIER NOT NULL,
        [Status] NVARCHAR(100) NOT NULL,
        [ScenarioJSON] NVARCHAR(max) NULL,
        [ValidationJSON] NVARCHAR(max) NULL,
        [AcceptedSubsetJSON] NVARCHAR(max) NULL,
        [Accepted] INT NOT NULL,
        [Superseded] INT NOT NULL,
        [IdentityHash] NVARCHAR(100) NULL,
        [ScenarioNumber] INT NOT NULL,
        [ReplacesScenarioID] UNIQUEIDENTIFIER NULL,
        [GenerationEpoch] INT NOT NULL,
        [ErrorMessage] NVARCHAR(max) NULL,
        [CreatedAt] DATETIME2(7) NULL,
        [ControlsMappedAt] DATETIME2(7) NULL,
        [ControlMapAttempts] INT NOT NULL,
        [GenStartedAt] DATETIME2(7) NULL,
        [GenFinishedAt] DATETIME2(7) NULL,
        [ScenarioSource] NVARCHAR(100) NULL,
        [RejectedAt] DATETIME2(7) NULL,
        [RejectedBy] NVARCHAR(200) NULL,
        [AcceptedAt] DATETIME2(7) NULL,
        [AcceptedBy] NVARCHAR(200) NULL,
        CONSTRAINT [PK_Threat_Scenario] PRIMARY KEY CLUSTERED ([ScenarioID])
    );
    PRINT ' [CREATED] Table: Threat_Scenario (28 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Threat_Scenario';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Legacy column names: renamed in place so their data is kept. */
EXEC dbo.tsg_rename_column @table = N'Threat_Scenario', @old = N'OutputID', @new = N'ScenarioID';
EXEC dbo.tsg_rename_column @table = N'Threat_Scenario', @old = N'ReplacesOutputID', @new = N'ReplacesScenarioID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Constraint and index names from before the rename, brought to the current names so the
   constraint and index scripts find them instead of creating a second copy. */
IF OBJECT_ID('dbo.PK_Threat_Scenario_Output') IS NOT NULL AND NOT OBJECT_ID('dbo.PK_Threat_Scenario') IS NOT NULL
BEGIN
    EXEC sp_rename 'dbo.PK_Threat_Scenario_Output', 'PK_Threat_Scenario', 'OBJECT';
    PRINT ' [RENAMED] PK_Threat_Scenario_Output -> PK_Threat_Scenario';
END;
IF OBJECT_ID('dbo.CK_ScenarioOutput_DecisionExclusive') IS NOT NULL AND NOT OBJECT_ID('dbo.CK_Scenario_DecisionExclusive') IS NOT NULL
BEGIN
    EXEC sp_rename 'dbo.CK_ScenarioOutput_DecisionExclusive', 'CK_Scenario_DecisionExclusive', 'OBJECT';
    PRINT ' [RENAMED] CK_ScenarioOutput_DecisionExclusive -> CK_Scenario_DecisionExclusive';
END;
IF OBJECT_ID('dbo.DF_ScenarioOutput_ScenarioNumber') IS NOT NULL AND NOT OBJECT_ID('dbo.DF_Scenario_ScenarioNumber') IS NOT NULL
BEGIN
    EXEC sp_rename 'dbo.DF_ScenarioOutput_ScenarioNumber', 'DF_Scenario_ScenarioNumber', 'OBJECT';
    PRINT ' [RENAMED] DF_ScenarioOutput_ScenarioNumber -> DF_Scenario_ScenarioNumber';
END;
IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioOutput_SessionSubActive' AND object_id = OBJECT_ID('dbo.Threat_Scenario')) AND NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Scenario_SessionSubActive' AND object_id = OBJECT_ID('dbo.Threat_Scenario'))
BEGIN
    EXEC sp_rename 'dbo.Threat_Scenario.IX_ScenarioOutput_SessionSubActive', 'IX_Scenario_SessionSubActive', 'INDEX';
    PRINT ' [RENAMED] IX_ScenarioOutput_SessionSubActive -> IX_Scenario_SessionSubActive';
END;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'ScenarioID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'SessionID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'TenantID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'EntityID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'UserID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'SubsystemID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'ScopedThreatID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'Status',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'ScenarioJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'ValidationJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'AcceptedSubsetJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'Accepted',
     @expected = N'INT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'Superseded',
     @expected = N'INT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'IdentityHash',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'ScenarioNumber',
     @expected = N'INT', @nullable = 0, @fill = N'1';
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'ReplacesScenarioID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'GenerationEpoch',
     @expected = N'INT', @nullable = 0, @fill = N'1';
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'ErrorMessage',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'ControlsMappedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'ControlMapAttempts',
     @expected = N'INT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'GenStartedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'GenFinishedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'ScenarioSource',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'RejectedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'RejectedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'AcceptedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario', @column = N'AcceptedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Threat_Scenario', @columns = N'ScenarioID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Legacy column OutputID, replaced by ScenarioID. Normally already RENAMED away above; it is still here
   only if ScenarioID existed too, in which case its values were copied across. Dropped only when
   EVERY value it holds is already in ScenarioID - nothing is lost. */
IF COL_LENGTH('dbo.Threat_Scenario', 'OutputID') IS NOT NULL
BEGIN
    DECLARE @n bigint;
    BEGIN TRY
        EXEC sp_executesql N'SELECT @n = COUNT_BIG(*) FROM dbo.[Threat_Scenario]
                             WHERE [OutputID] IS NOT NULL
                               AND ([ScenarioID] IS NULL OR [ScenarioID] <> [OutputID]);',
             N'@n bigint OUTPUT', @n = @n OUTPUT;
        IF @n > 0
        BEGIN
            PRINT ' [BLOCKED] Threat_Scenario.OutputID holds ' + CAST(@n AS varchar(20)) +
                  ' value(s) that differ from ScenarioID - NOT dropped.';
            PRINT '          Decide which value is right, update ScenarioID, then re-run.';
        END
        ELSE
        BEGIN
            /* Old indexes built on the column go with it, in the same transaction. */
            DECLARE @ix sysname, @ixs nvarchar(max) = N'', @drop nvarchar(max);
            BEGIN TRANSACTION;
            DECLARE legacy_ix CURSOR LOCAL STATIC READ_ONLY FOR
                SELECT i.name
                FROM   sys.indexes i
                WHERE  i.object_id = OBJECT_ID(N'dbo.Threat_Scenario') AND i.type IN (1, 2)
                  AND  i.is_primary_key = 0 AND i.is_unique_constraint = 0
                  AND  (EXISTS (SELECT 1 FROM sys.index_columns ic
                                WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id
                                  AND ic.column_id = COLUMNPROPERTY(i.object_id, N'OutputID', 'ColumnId'))
                        OR CHARINDEX(N'[OutputID]', ISNULL(i.filter_definition, N'')) > 0);
            OPEN legacy_ix; FETCH NEXT FROM legacy_ix INTO @ix;
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @drop = N'DROP INDEX ' + QUOTENAME(@ix) + N' ON dbo.[Threat_Scenario];';
                EXEC sp_executesql @drop;
                SET @ixs = @ixs + CASE WHEN @ixs = N'' THEN N'' ELSE N', ' END + @ix;
                FETCH NEXT FROM legacy_ix INTO @ix;
            END;
            CLOSE legacy_ix; DEALLOCATE legacy_ix;
            EXEC sp_executesql N'ALTER TABLE dbo.[Threat_Scenario] DROP COLUMN [OutputID];';
            COMMIT;
            PRINT ' [DROPPED] Threat_Scenario.OutputID - legacy column; all of its data is in ScenarioID.';
            IF @ixs <> N''
                PRINT '          Old index(es) on it dropped too: ' + @ixs +
                      ' (the current ones are created by 03_indexes).';
        END
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK;
        PRINT ' [ERROR]   Could not drop Threat_Scenario.OutputID.';
        PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
        EXEC sp_set_session_context N'tsg_deploy_failed', 1;
        RAISERROR('Legacy column Threat_Scenario.OutputID could not be dropped - deployment stopped.', 16, 1);
    END CATCH
END
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Legacy column ReplacesOutputID, replaced by ReplacesScenarioID. Normally already RENAMED away above; it is still here
   only if ReplacesScenarioID existed too, in which case its values were copied across. Dropped only when
   EVERY value it holds is already in ReplacesScenarioID - nothing is lost. */
IF COL_LENGTH('dbo.Threat_Scenario', 'ReplacesOutputID') IS NOT NULL
BEGIN
    DECLARE @n bigint;
    BEGIN TRY
        EXEC sp_executesql N'SELECT @n = COUNT_BIG(*) FROM dbo.[Threat_Scenario]
                             WHERE [ReplacesOutputID] IS NOT NULL
                               AND ([ReplacesScenarioID] IS NULL OR [ReplacesScenarioID] <> [ReplacesOutputID]);',
             N'@n bigint OUTPUT', @n = @n OUTPUT;
        IF @n > 0
        BEGIN
            PRINT ' [BLOCKED] Threat_Scenario.ReplacesOutputID holds ' + CAST(@n AS varchar(20)) +
                  ' value(s) that differ from ReplacesScenarioID - NOT dropped.';
            PRINT '          Decide which value is right, update ReplacesScenarioID, then re-run.';
        END
        ELSE
        BEGIN
            /* Old indexes built on the column go with it, in the same transaction. */
            DECLARE @ix sysname, @ixs nvarchar(max) = N'', @drop nvarchar(max);
            BEGIN TRANSACTION;
            DECLARE legacy_ix CURSOR LOCAL STATIC READ_ONLY FOR
                SELECT i.name
                FROM   sys.indexes i
                WHERE  i.object_id = OBJECT_ID(N'dbo.Threat_Scenario') AND i.type IN (1, 2)
                  AND  i.is_primary_key = 0 AND i.is_unique_constraint = 0
                  AND  (EXISTS (SELECT 1 FROM sys.index_columns ic
                                WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id
                                  AND ic.column_id = COLUMNPROPERTY(i.object_id, N'ReplacesOutputID', 'ColumnId'))
                        OR CHARINDEX(N'[ReplacesOutputID]', ISNULL(i.filter_definition, N'')) > 0);
            OPEN legacy_ix; FETCH NEXT FROM legacy_ix INTO @ix;
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @drop = N'DROP INDEX ' + QUOTENAME(@ix) + N' ON dbo.[Threat_Scenario];';
                EXEC sp_executesql @drop;
                SET @ixs = @ixs + CASE WHEN @ixs = N'' THEN N'' ELSE N', ' END + @ix;
                FETCH NEXT FROM legacy_ix INTO @ix;
            END;
            CLOSE legacy_ix; DEALLOCATE legacy_ix;
            EXEC sp_executesql N'ALTER TABLE dbo.[Threat_Scenario] DROP COLUMN [ReplacesOutputID];';
            COMMIT;
            PRINT ' [DROPPED] Threat_Scenario.ReplacesOutputID - legacy column; all of its data is in ReplacesScenarioID.';
            IF @ixs <> N''
                PRINT '          Old index(es) on it dropped too: ' + @ixs +
                      ' (the current ones are created by 03_indexes).';
        END
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK;
        PRINT ' [ERROR]   Could not drop Threat_Scenario.ReplacesOutputID.';
        PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
        EXEC sp_set_session_context N'tsg_deploy_failed', 1;
        RAISERROR('Legacy column Threat_Scenario.ReplacesOutputID could not be dropped - deployment stopped.', 16, 1);
    END CATCH
END
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Threat_Scenario', @known = N'ScenarioID,SessionID,TenantID,EntityID,UserID,SubsystemID,ScopedThreatID,Status,ScenarioJSON,ValidationJSON,AcceptedSubsetJSON,Accepted,Superseded,IdentityHash,ScenarioNumber,ReplacesScenarioID,GenerationEpoch,ErrorMessage,CreatedAt,ControlsMappedAt,ControlMapAttempts,GenStartedAt,GenFinishedAt,ScenarioSource,RejectedAt,RejectedBy,AcceptedAt,AcceptedBy';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 22 of 51   01_tables/019_Threat_Scenario_Control_Map.sql
============================================================================*/
PRINT '';
PRINT '>>> [22/51] 01_tables/019_Threat_Scenario_Control_Map.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  TABLE: Threat_Scenario_Control_Map

  Script:      019_Threat_Scenario_Control_Map.sql
  Order:       01_tables / 019
  Purpose:     Create Threat_Scenario_Control_Map, or bring an existing copy up to 7 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Threat_Scenario_Control_Map

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- Threat_Scenario_Control_Map ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF OBJECT_ID('dbo.Threat_Scenario_Control_Map', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Threat_Scenario_Control_Map] (
        [ScenarioID] UNIQUEIDENTIFIER NOT NULL,
        [ControlLibraryID] INT NOT NULL,
        [SessionID] UNIQUEIDENTIFIER NOT NULL,
        [MapRank] INT NOT NULL,
        [Score] FLOAT NULL,
        [SuggestedControl] NVARCHAR(500) NULL,
        [CreatedAt] DATETIME2(7) NULL,
        CONSTRAINT [PK_Threat_Scenario_Control_Map] PRIMARY KEY CLUSTERED ([ScenarioID], [ControlLibraryID])
    );
    PRINT ' [CREATED] Table: Threat_Scenario_Control_Map (7 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Threat_Scenario_Control_Map';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Legacy column names: renamed in place so their data is kept. */
EXEC dbo.tsg_rename_column @table = N'Threat_Scenario_Control_Map', @old = N'OutputID', @new = N'ScenarioID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario_Control_Map', @column = N'ScenarioID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario_Control_Map', @column = N'ControlLibraryID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario_Control_Map', @column = N'SessionID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario_Control_Map', @column = N'MapRank',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario_Control_Map', @column = N'Score',
     @expected = N'FLOAT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario_Control_Map', @column = N'SuggestedControl',
     @expected = N'NVARCHAR(500)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Threat_Scenario_Control_Map', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Threat_Scenario_Control_Map', @columns = N'ScenarioID,ControlLibraryID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Legacy column OutputID, replaced by ScenarioID. Normally already RENAMED away above; it is still here
   only if ScenarioID existed too, in which case its values were copied across. Dropped only when
   EVERY value it holds is already in ScenarioID - nothing is lost. */
IF COL_LENGTH('dbo.Threat_Scenario_Control_Map', 'OutputID') IS NOT NULL
BEGIN
    DECLARE @n bigint;
    BEGIN TRY
        EXEC sp_executesql N'SELECT @n = COUNT_BIG(*) FROM dbo.[Threat_Scenario_Control_Map]
                             WHERE [OutputID] IS NOT NULL
                               AND ([ScenarioID] IS NULL OR [ScenarioID] <> [OutputID]);',
             N'@n bigint OUTPUT', @n = @n OUTPUT;
        IF @n > 0
        BEGIN
            PRINT ' [BLOCKED] Threat_Scenario_Control_Map.OutputID holds ' + CAST(@n AS varchar(20)) +
                  ' value(s) that differ from ScenarioID - NOT dropped.';
            PRINT '          Decide which value is right, update ScenarioID, then re-run.';
        END
        ELSE
        BEGIN
            /* Old indexes built on the column go with it, in the same transaction. */
            DECLARE @ix sysname, @ixs nvarchar(max) = N'', @drop nvarchar(max);
            BEGIN TRANSACTION;
            DECLARE legacy_ix CURSOR LOCAL STATIC READ_ONLY FOR
                SELECT i.name
                FROM   sys.indexes i
                WHERE  i.object_id = OBJECT_ID(N'dbo.Threat_Scenario_Control_Map') AND i.type IN (1, 2)
                  AND  i.is_primary_key = 0 AND i.is_unique_constraint = 0
                  AND  (EXISTS (SELECT 1 FROM sys.index_columns ic
                                WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id
                                  AND ic.column_id = COLUMNPROPERTY(i.object_id, N'OutputID', 'ColumnId'))
                        OR CHARINDEX(N'[OutputID]', ISNULL(i.filter_definition, N'')) > 0);
            OPEN legacy_ix; FETCH NEXT FROM legacy_ix INTO @ix;
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @drop = N'DROP INDEX ' + QUOTENAME(@ix) + N' ON dbo.[Threat_Scenario_Control_Map];';
                EXEC sp_executesql @drop;
                SET @ixs = @ixs + CASE WHEN @ixs = N'' THEN N'' ELSE N', ' END + @ix;
                FETCH NEXT FROM legacy_ix INTO @ix;
            END;
            CLOSE legacy_ix; DEALLOCATE legacy_ix;
            EXEC sp_executesql N'ALTER TABLE dbo.[Threat_Scenario_Control_Map] DROP COLUMN [OutputID];';
            COMMIT;
            PRINT ' [DROPPED] Threat_Scenario_Control_Map.OutputID - legacy column; all of its data is in ScenarioID.';
            IF @ixs <> N''
                PRINT '          Old index(es) on it dropped too: ' + @ixs +
                      ' (the current ones are created by 03_indexes).';
        END
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK;
        PRINT ' [ERROR]   Could not drop Threat_Scenario_Control_Map.OutputID.';
        PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
        EXEC sp_set_session_context N'tsg_deploy_failed', 1;
        RAISERROR('Legacy column Threat_Scenario_Control_Map.OutputID could not be dropped - deployment stopped.', 16, 1);
    END CATCH
END
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Threat_Scenario_Control_Map', @known = N'ScenarioID,ControlLibraryID,SessionID,MapRank,Score,SuggestedControl,CreatedAt';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 23 of 51   01_tables/020_Risk_Treatment_Plan.sql
============================================================================*/
PRINT '';
PRINT '>>> [23/51] 01_tables/020_Risk_Treatment_Plan.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  TABLE: Risk_Treatment_Plan

  Script:      020_Risk_Treatment_Plan.sql
  Order:       01_tables / 020
  Purpose:     Create Risk_Treatment_Plan, or bring an existing copy up to 27 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Risk_Treatment_Plan

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- Risk_Treatment_Plan ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF OBJECT_ID('dbo.Risk_Treatment_Plan', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Risk_Treatment_Plan] (
        [PlanID] UNIQUEIDENTIFIER NOT NULL,
        [SessionID] UNIQUEIDENTIFIER NOT NULL,
        [ScenarioID] UNIQUEIDENTIFIER NOT NULL,
        [TenantID] NVARCHAR(200) NULL,
        [EntityID] NVARCHAR(200) NULL,
        [UserID] NVARCHAR(200) NULL,
        [CrmRiskIdentificationID] INT NULL,
        [TreatmentStrategy] NVARCHAR(100) NOT NULL,
        [Status] NVARCHAR(100) NOT NULL,
        [ActiveTaskID] NVARCHAR(100) NULL,
        [RiskIdentificationDate] DATETIME2(7) NULL,
        [InputSnapshotJSON] NVARCHAR(max) NULL,
        [PlanJSON] NVARCHAR(max) NULL,
        [ValidationJSON] NVARCHAR(max) NULL,
        [ErrorMessage] NVARCHAR(max) NULL,
        [Superseded] INT NOT NULL,
        [CreatedAt] DATETIME2(7) NULL,
        [UpdatedAt] DATETIME2(7) NULL,
        [CompletedAt] DATETIME2(7) NULL,
        [RiskLevel] NVARCHAR(100) NULL,
        [ReviewStatus] NVARCHAR(100) NULL,
        [ReviewComment] NVARCHAR(max) NULL,
        [ReviewedBy] NVARCHAR(200) NULL,
        [ReviewedAt] DATETIME2(7) NULL,
        [CancelledAt] DATETIME2(7) NULL,
        [CancelledBy] NVARCHAR(200) NULL,
        [ErrorReason] NVARCHAR(max) NULL,
        CONSTRAINT [PK_Risk_Treatment_Plan] PRIMARY KEY CLUSTERED ([PlanID])
    );
    PRINT ' [CREATED] Table: Risk_Treatment_Plan (27 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Risk_Treatment_Plan';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Legacy column names: renamed in place so their data is kept. */
EXEC dbo.tsg_rename_column @table = N'Risk_Treatment_Plan', @old = N'OutputID', @new = N'ScenarioID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Constraint and index names from before the rename, brought to the current names so the
   constraint and index scripts find them instead of creating a second copy. */
IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_TreatmentPlan_ActiveOutput' AND object_id = OBJECT_ID('dbo.Risk_Treatment_Plan')) AND NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_TreatmentPlan_ActiveScenario' AND object_id = OBJECT_ID('dbo.Risk_Treatment_Plan'))
BEGIN
    EXEC sp_rename 'dbo.Risk_Treatment_Plan.UX_TreatmentPlan_ActiveOutput', 'UX_TreatmentPlan_ActiveScenario', 'INDEX';
    PRINT ' [RENAMED] UX_TreatmentPlan_ActiveOutput -> UX_TreatmentPlan_ActiveScenario';
END;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'PlanID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'SessionID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'ScenarioID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'TenantID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'EntityID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'UserID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'CrmRiskIdentificationID',
     @expected = N'INT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'TreatmentStrategy',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'Status',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'ActiveTaskID',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'RiskIdentificationDate',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'InputSnapshotJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'PlanJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'ValidationJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'ErrorMessage',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'Superseded',
     @expected = N'INT', @nullable = 0, @fill = N'0';
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'UpdatedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'CompletedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'RiskLevel',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'ReviewStatus',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'ReviewComment',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'ReviewedBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'ReviewedAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'CancelledAt',
     @expected = N'DATETIME2(7)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'CancelledBy',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Risk_Treatment_Plan', @column = N'ErrorReason',
     @expected = N'NVARCHAR(max)', @nullable = 1;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Risk_Treatment_Plan', @columns = N'PlanID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Legacy column OutputID, replaced by ScenarioID. Normally already RENAMED away above; it is still here
   only if ScenarioID existed too, in which case its values were copied across. Dropped only when
   EVERY value it holds is already in ScenarioID - nothing is lost. */
IF COL_LENGTH('dbo.Risk_Treatment_Plan', 'OutputID') IS NOT NULL
BEGIN
    DECLARE @n bigint;
    BEGIN TRY
        EXEC sp_executesql N'SELECT @n = COUNT_BIG(*) FROM dbo.[Risk_Treatment_Plan]
                             WHERE [OutputID] IS NOT NULL
                               AND ([ScenarioID] IS NULL OR [ScenarioID] <> [OutputID]);',
             N'@n bigint OUTPUT', @n = @n OUTPUT;
        IF @n > 0
        BEGIN
            PRINT ' [BLOCKED] Risk_Treatment_Plan.OutputID holds ' + CAST(@n AS varchar(20)) +
                  ' value(s) that differ from ScenarioID - NOT dropped.';
            PRINT '          Decide which value is right, update ScenarioID, then re-run.';
        END
        ELSE
        BEGIN
            /* Old indexes built on the column go with it, in the same transaction. */
            DECLARE @ix sysname, @ixs nvarchar(max) = N'', @drop nvarchar(max);
            BEGIN TRANSACTION;
            DECLARE legacy_ix CURSOR LOCAL STATIC READ_ONLY FOR
                SELECT i.name
                FROM   sys.indexes i
                WHERE  i.object_id = OBJECT_ID(N'dbo.Risk_Treatment_Plan') AND i.type IN (1, 2)
                  AND  i.is_primary_key = 0 AND i.is_unique_constraint = 0
                  AND  (EXISTS (SELECT 1 FROM sys.index_columns ic
                                WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id
                                  AND ic.column_id = COLUMNPROPERTY(i.object_id, N'OutputID', 'ColumnId'))
                        OR CHARINDEX(N'[OutputID]', ISNULL(i.filter_definition, N'')) > 0);
            OPEN legacy_ix; FETCH NEXT FROM legacy_ix INTO @ix;
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @drop = N'DROP INDEX ' + QUOTENAME(@ix) + N' ON dbo.[Risk_Treatment_Plan];';
                EXEC sp_executesql @drop;
                SET @ixs = @ixs + CASE WHEN @ixs = N'' THEN N'' ELSE N', ' END + @ix;
                FETCH NEXT FROM legacy_ix INTO @ix;
            END;
            CLOSE legacy_ix; DEALLOCATE legacy_ix;
            EXEC sp_executesql N'ALTER TABLE dbo.[Risk_Treatment_Plan] DROP COLUMN [OutputID];';
            COMMIT;
            PRINT ' [DROPPED] Risk_Treatment_Plan.OutputID - legacy column; all of its data is in ScenarioID.';
            IF @ixs <> N''
                PRINT '          Old index(es) on it dropped too: ' + @ixs +
                      ' (the current ones are created by 03_indexes).';
        END
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK;
        PRINT ' [ERROR]   Could not drop Risk_Treatment_Plan.OutputID.';
        PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
        EXEC sp_set_session_context N'tsg_deploy_failed', 1;
        RAISERROR('Legacy column Risk_Treatment_Plan.OutputID could not be dropped - deployment stopped.', 16, 1);
    END CATCH
END
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Risk_Treatment_Plan', @known = N'PlanID,SessionID,ScenarioID,TenantID,EntityID,UserID,CrmRiskIdentificationID,TreatmentStrategy,Status,ActiveTaskID,RiskIdentificationDate,InputSnapshotJSON,PlanJSON,ValidationJSON,ErrorMessage,Superseded,CreatedAt,UpdatedAt,CompletedAt,RiskLevel,ReviewStatus,ReviewComment,ReviewedBy,ReviewedAt,CancelledAt,CancelledBy,ErrorReason';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 24 of 51   01_tables/021_Scenario_Audit.sql
============================================================================*/
PRINT '';
PRINT '>>> [24/51] 01_tables/021_Scenario_Audit.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  TABLE: Scenario_Audit

  Script:      021_Scenario_Audit.sql
  Order:       01_tables / 021
  Purpose:     Create Scenario_Audit, or bring an existing copy up to 16 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Scenario_Audit

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- Scenario_Audit ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF OBJECT_ID('dbo.Scenario_Audit', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Scenario_Audit] (
        [AuditID] UNIQUEIDENTIFIER NOT NULL,
        [SessionID] UNIQUEIDENTIFIER NOT NULL,
        [TenantID] NVARCHAR(200) NULL,
        [EntityID] NVARCHAR(200) NULL,
        [Stage] NVARCHAR(100) NULL,
        [SubsystemID] INT NULL,
        [EventType] NVARCHAR(100) NOT NULL,
        [ScenarioID] UNIQUEIDENTIFIER NULL,
        [PlanID] UNIQUEIDENTIFIER NULL,
        [Decision] NVARCHAR(100) NULL,
        [Granularity] NVARCHAR(100) NULL,
        [ThreatTypeRefID] INT NULL,
        [ActorUserID] NVARCHAR(200) NULL,
        [ActorType] NVARCHAR(100) NULL,
        [DetailJSON] NVARCHAR(max) NULL,
        [CreatedAt] DATETIME2(7) NOT NULL,
        CONSTRAINT [PK_Scenario_Audit] PRIMARY KEY CLUSTERED ([AuditID])
    );
    PRINT ' [CREATED] Table: Scenario_Audit (16 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Scenario_Audit';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Legacy column names: renamed in place so their data is kept. */
EXEC dbo.tsg_rename_column @table = N'Scenario_Audit', @old = N'OutputID', @new = N'ScenarioID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Constraint and index names from before the rename, brought to the current names so the
   constraint and index scripts find them instead of creating a second copy. */
IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioAudit_Output' AND object_id = OBJECT_ID('dbo.Scenario_Audit')) AND NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioAudit_Scenario' AND object_id = OBJECT_ID('dbo.Scenario_Audit'))
BEGIN
    EXEC sp_rename 'dbo.Scenario_Audit.IX_ScenarioAudit_Output', 'IX_ScenarioAudit_Scenario', 'INDEX';
    PRINT ' [RENAMED] IX_ScenarioAudit_Output -> IX_ScenarioAudit_Scenario';
END;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'AuditID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'SessionID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'TenantID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'EntityID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'Stage',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'SubsystemID',
     @expected = N'INT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'EventType',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'ScenarioID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'PlanID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'Decision',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'Granularity',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'ThreatTypeRefID',
     @expected = N'INT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'ActorUserID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'ActorType',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'DetailJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Scenario_Audit', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 0;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Scenario_Audit', @columns = N'AuditID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Legacy column OutputID, replaced by ScenarioID. Normally already RENAMED away above; it is still here
   only if ScenarioID existed too, in which case its values were copied across. Dropped only when
   EVERY value it holds is already in ScenarioID - nothing is lost. */
IF COL_LENGTH('dbo.Scenario_Audit', 'OutputID') IS NOT NULL
BEGIN
    DECLARE @n bigint;
    BEGIN TRY
        EXEC sp_executesql N'SELECT @n = COUNT_BIG(*) FROM dbo.[Scenario_Audit]
                             WHERE [OutputID] IS NOT NULL
                               AND ([ScenarioID] IS NULL OR [ScenarioID] <> [OutputID]);',
             N'@n bigint OUTPUT', @n = @n OUTPUT;
        IF @n > 0
        BEGIN
            PRINT ' [BLOCKED] Scenario_Audit.OutputID holds ' + CAST(@n AS varchar(20)) +
                  ' value(s) that differ from ScenarioID - NOT dropped.';
            PRINT '          Decide which value is right, update ScenarioID, then re-run.';
        END
        ELSE
        BEGIN
            /* Old indexes built on the column go with it, in the same transaction. */
            DECLARE @ix sysname, @ixs nvarchar(max) = N'', @drop nvarchar(max);
            BEGIN TRANSACTION;
            DECLARE legacy_ix CURSOR LOCAL STATIC READ_ONLY FOR
                SELECT i.name
                FROM   sys.indexes i
                WHERE  i.object_id = OBJECT_ID(N'dbo.Scenario_Audit') AND i.type IN (1, 2)
                  AND  i.is_primary_key = 0 AND i.is_unique_constraint = 0
                  AND  (EXISTS (SELECT 1 FROM sys.index_columns ic
                                WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id
                                  AND ic.column_id = COLUMNPROPERTY(i.object_id, N'OutputID', 'ColumnId'))
                        OR CHARINDEX(N'[OutputID]', ISNULL(i.filter_definition, N'')) > 0);
            OPEN legacy_ix; FETCH NEXT FROM legacy_ix INTO @ix;
            WHILE @@FETCH_STATUS = 0
            BEGIN
                SET @drop = N'DROP INDEX ' + QUOTENAME(@ix) + N' ON dbo.[Scenario_Audit];';
                EXEC sp_executesql @drop;
                SET @ixs = @ixs + CASE WHEN @ixs = N'' THEN N'' ELSE N', ' END + @ix;
                FETCH NEXT FROM legacy_ix INTO @ix;
            END;
            CLOSE legacy_ix; DEALLOCATE legacy_ix;
            EXEC sp_executesql N'ALTER TABLE dbo.[Scenario_Audit] DROP COLUMN [OutputID];';
            COMMIT;
            PRINT ' [DROPPED] Scenario_Audit.OutputID - legacy column; all of its data is in ScenarioID.';
            IF @ixs <> N''
                PRINT '          Old index(es) on it dropped too: ' + @ixs +
                      ' (the current ones are created by 03_indexes).';
        END
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK;
        PRINT ' [ERROR]   Could not drop Scenario_Audit.OutputID.';
        PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
        EXEC sp_set_session_context N'tsg_deploy_failed', 1;
        RAISERROR('Legacy column Scenario_Audit.OutputID could not be dropped - deployment stopped.', 16, 1);
    END CATCH
END
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Scenario_Audit', @known = N'AuditID,SessionID,TenantID,EntityID,Stage,SubsystemID,EventType,ScenarioID,PlanID,Decision,Granularity,ThreatTypeRefID,ActorUserID,ActorType,DetailJSON,CreatedAt';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 25 of 51   01_tables/022_Prompt_Log.sql
============================================================================*/
PRINT '';
PRINT '>>> [25/51] 01_tables/022_Prompt_Log.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  TABLE: Prompt_Log

  Script:      022_Prompt_Log.sql
  Order:       01_tables / 022
  Purpose:     Create Prompt_Log, or bring an existing copy up to 15 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Prompt_Log

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- Prompt_Log ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF OBJECT_ID('dbo.Prompt_Log', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Prompt_Log] (
        [LogID] UNIQUEIDENTIFIER NOT NULL,
        [SessionID] UNIQUEIDENTIFIER NOT NULL,
        [TenantID] NVARCHAR(200) NULL,
        [EntityID] NVARCHAR(200) NULL,
        [UserID] NVARCHAR(200) NULL,
        [SubsystemID] INT NOT NULL,
        [Stage] NVARCHAR(100) NOT NULL,
        [PromptVersion] NVARCHAR(100) NOT NULL,
        [Prompt] NVARCHAR(max) NULL,
        [ResponseText] NVARCHAR(max) NULL,
        [Model] NVARCHAR(200) NULL,
        [ModelVersion] NVARCHAR(100) NULL,
        [ParseSucceeded] BIT NOT NULL,
        [CreatedAt] DATETIME2(7) NOT NULL,
        [CorrelationID] UNIQUEIDENTIFIER NULL,
        CONSTRAINT [PK_Prompt_Log] PRIMARY KEY CLUSTERED ([LogID])
    );
    PRINT ' [CREATED] Table: Prompt_Log (15 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Prompt_Log';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'LogID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'SessionID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'TenantID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'EntityID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'UserID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'SubsystemID',
     @expected = N'INT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'Stage',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'PromptVersion',
     @expected = N'NVARCHAR(100)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'Prompt',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'ResponseText',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'Model',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'ModelVersion',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'ParseSucceeded',
     @expected = N'BIT', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Prompt_Log', @column = N'CorrelationID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 1;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Prompt_Log', @columns = N'LogID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Prompt_Log', @known = N'LogID,SessionID,TenantID,EntityID,UserID,SubsystemID,Stage,PromptVersion,Prompt,ResponseText,Model,ModelVersion,ParseSucceeded,CreatedAt,CorrelationID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 26 of 51   01_tables/023_Diagnostic_Event.sql
============================================================================*/
PRINT '';
PRINT '>>> [26/51] 01_tables/023_Diagnostic_Event.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  TABLE: Diagnostic_Event

  Script:      023_Diagnostic_Event.sql
  Order:       01_tables / 023
  Purpose:     Create Diagnostic_Event, or bring an existing copy up to 14 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Diagnostic_Event

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- Diagnostic_Event ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF OBJECT_ID('dbo.Diagnostic_Event', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Diagnostic_Event] (
        [DiagnosticID] UNIQUEIDENTIFIER NOT NULL,
        [CreatedAt] DATETIME2(7) NOT NULL,
        [SessionID] UNIQUEIDENTIFIER NULL,
        [TenantID] NVARCHAR(200) NULL,
        [EntityID] NVARCHAR(200) NULL,
        [SubsystemID] INT NULL,
        [TaskID] NVARCHAR(100) NULL,
        [RequestID] NVARCHAR(100) NULL,
        [Kind] NVARCHAR(50) NOT NULL,
        [ExceptionClass] NVARCHAR(200) NOT NULL,
        [ExceptionMessage] NVARCHAR(4000) NULL,
        [Traceback] NVARCHAR(max) NULL,
        [ClientMessage] NVARCHAR(1000) NULL,
        [ContextJSON] NVARCHAR(max) NULL,
        CONSTRAINT [PK_Diagnostic_Event] PRIMARY KEY CLUSTERED ([DiagnosticID])
    );
    PRINT ' [CREATED] Table: Diagnostic_Event (14 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Diagnostic_Event';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'DiagnosticID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'SessionID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'TenantID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'EntityID',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'SubsystemID',
     @expected = N'INT', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'TaskID',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'RequestID',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'Kind',
     @expected = N'NVARCHAR(50)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'ExceptionClass',
     @expected = N'NVARCHAR(200)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'ExceptionMessage',
     @expected = N'NVARCHAR(4000)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'Traceback',
     @expected = N'NVARCHAR(max)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'ClientMessage',
     @expected = N'NVARCHAR(1000)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Diagnostic_Event', @column = N'ContextJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Diagnostic_Event', @columns = N'DiagnosticID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Diagnostic_Event', @known = N'DiagnosticID,CreatedAt,SessionID,TenantID,EntityID,SubsystemID,TaskID,RequestID,Kind,ExceptionClass,ExceptionMessage,Traceback,ClientMessage,ContextJSON';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 27 of 51   01_tables/024_Application_Log.sql
============================================================================*/
PRINT '';
PRINT '>>> [27/51] 01_tables/024_Application_Log.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  TABLE: Application_Log

  Script:      024_Application_Log.sql
  Order:       01_tables / 024
  Purpose:     Create Application_Log, or bring an existing copy up to 9 columns.
  Depends on:  00_validation/001_pre_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    dbo.Application_Log

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- Application_Log ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF OBJECT_ID('dbo.Application_Log', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[Application_Log] (
        [LogID] UNIQUEIDENTIFIER NOT NULL,
        [CreatedAt] DATETIME2(7) NOT NULL,
        [Level] NVARCHAR(20) NOT NULL,
        [Logger] NVARCHAR(200) NULL,
        [Event] NVARCHAR(500) NULL,
        [SessionID] NVARCHAR(100) NULL,
        [RequestID] NVARCHAR(100) NULL,
        [TaskID] NVARCHAR(100) NULL,
        [FieldsJSON] NVARCHAR(max) NULL,
        CONSTRAINT [PK_Application_Log] PRIMARY KEY CLUSTERED ([LogID])
    );
    PRINT ' [CREATED] Table: Application_Log (9 columns)';
END
ELSE
    PRINT ' [EXISTS]  Table: Application_Log';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Reconcile every column the application reads or writes. Adds what is missing; reports a type
   difference instead of applying it blind. */
EXEC dbo.tsg_reconcile_column @table = N'Application_Log', @column = N'LogID',
     @expected = N'UNIQUEIDENTIFIER', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Application_Log', @column = N'CreatedAt',
     @expected = N'DATETIME2(7)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Application_Log', @column = N'Level',
     @expected = N'NVARCHAR(20)', @nullable = 0;
EXEC dbo.tsg_reconcile_column @table = N'Application_Log', @column = N'Logger',
     @expected = N'NVARCHAR(200)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Application_Log', @column = N'Event',
     @expected = N'NVARCHAR(500)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Application_Log', @column = N'SessionID',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Application_Log', @column = N'RequestID',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Application_Log', @column = N'TaskID',
     @expected = N'NVARCHAR(100)', @nullable = 1;
EXEC dbo.tsg_reconcile_column @table = N'Application_Log', @column = N'FieldsJSON',
     @expected = N'NVARCHAR(max)', @nullable = 1;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* The primary key the application expects - an older table may carry another. */
EXEC dbo.tsg_reconcile_primary_key @table = N'Application_Log', @columns = N'LogID';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Columns in the database that this application does not know about. Never dropped - they may
   belong to another release or another team. One NOT NULL with no default is made NULL-able,
   because the application never writes it and every insert would fail. */
EXEC dbo.tsg_report_extra_columns @table = N'Application_Log', @known = N'LogID,CreatedAt,Level,Logger,Event,SessionID,RequestID,TaskID,FieldsJSON';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 28 of 51   02_constraints/001_default_constraints.sql
============================================================================*/
PRINT '';
PRINT '>>> [28/51] 02_constraints/001_default_constraints.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  DEFAULT CONSTRAINTS

  Script:      001_default_constraints.sql
  Order:       02_constraints / 001
  Purpose:     22 default constraints.
  Depends on:  01_tables/ *
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    default constraints

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- default constraints ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  SECTION 4 — Default constraints

  Named so a later script can reference or replace them. Every one is guarded,
  so this section is a no-op on a database that already has them.
==============================================================================*/
IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.API_Client')
                 AND c.name = 'Module')
    ALTER TABLE [dbo].[API_Client] ADD CONSTRAINT [DF_API_Client_Module] DEFAULT ('tsg') FOR [Module];
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.API_Client')
                 AND c.name = 'Active')
    ALTER TABLE [dbo].[API_Client] ADD CONSTRAINT [DF_API_Client_Active] DEFAULT ((1)) FOR [Active];
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.API_Client')
                 AND c.name = 'CreatedAt')
    ALTER TABLE [dbo].[API_Client] ADD CONSTRAINT [DF_API_Client_CreatedAt] DEFAULT (sysutcdatetime()) FOR [CreatedAt];
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Config_Tuning')
                 AND c.name = 'IsActive')
    ALTER TABLE [dbo].[Config_Tuning] ADD CONSTRAINT [DF_Config_Tuning_IsActive] DEFAULT ((1)) FOR [IsActive];
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Config_Tuning')
                 AND c.name = 'IsDeleted')
    ALTER TABLE [dbo].[Config_Tuning] ADD CONSTRAINT [DF_Config_Tuning_IsDeleted] DEFAULT ((0)) FOR [IsDeleted];
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Control_Library')
                 AND c.name = 'CreatedAt')
    ALTER TABLE [dbo].[Control_Library] ADD CONSTRAINT [DF_Control_Library_CreatedAt] DEFAULT (sysutcdatetime()) FOR [CreatedAt];
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Control_Library')
                 AND c.name = 'IsActive')
    ALTER TABLE [dbo].[Control_Library] ADD CONSTRAINT [DF_Control_Library_IsActive] DEFAULT ((1)) FOR [IsActive];
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Control_Library')
                 AND c.name = 'IsDeleted')
    ALTER TABLE [dbo].[Control_Library] ADD CONSTRAINT [DF_Control_Library_IsDeleted] DEFAULT ((0)) FOR [IsDeleted];
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Control_Library_Standard_Map')
                 AND c.name = 'CreatedAt')
    ALTER TABLE [dbo].[Control_Library_Standard_Map] ADD CONSTRAINT [DF_ControlStdMap_CreatedAt] DEFAULT (sysutcdatetime()) FOR [CreatedAt];
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Control_Standard')
                 AND c.name = 'CreatedAt')
    ALTER TABLE [dbo].[Control_Standard] ADD CONSTRAINT [DF_Control_Standard_CreatedAt] DEFAULT (sysutcdatetime()) FOR [CreatedAt];
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Control_Standard')
                 AND c.name = 'IsActive')
    ALTER TABLE [dbo].[Control_Standard] ADD CONSTRAINT [DF_Control_Standard_IsActive] DEFAULT ((1)) FOR [IsActive];
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Control_Standard')
                 AND c.name = 'IsDeleted')
    ALTER TABLE [dbo].[Control_Standard] ADD CONSTRAINT [DF_Control_Standard_IsDeleted] DEFAULT ((0)) FOR [IsDeleted];
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Grounding_Calibration_Run')
                 AND c.name = 'Forced')
    ALTER TABLE [dbo].[Grounding_Calibration_Run] ADD CONSTRAINT [DF_GroundingCalibration_Forced] DEFAULT ((0)) FOR [Forced];
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* Named, unlike the SSMS default. A system-generated name differs per database
   and cannot be scripted against later. */
IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Identified_Threat')
                 AND c.name = 'IsThreatAIGenerated')
    ALTER TABLE [dbo].[Identified_Threat] ADD CONSTRAINT [DF_IdentifiedThreat_IsThreatAIGenerated] DEFAULT ((0)) FOR [IsThreatAIGenerated];
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Identified_Threat')
                 AND c.name = 'IsThreatTypeAIGenerated')
    ALTER TABLE [dbo].[Identified_Threat] ADD CONSTRAINT [DF_IdentifiedThreat_IsThreatTypeAIGenerated] DEFAULT ((0)) FOR [IsThreatTypeAIGenerated];
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Risk_Treatment_Plan')
                 AND c.name = 'Superseded')
    ALTER TABLE [dbo].[Risk_Treatment_Plan] ADD CONSTRAINT [DF_TreatmentPlan_Superseded] DEFAULT ((0)) FOR [Superseded];
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Subsystem_Stage_State')
                 AND c.name = 'AttemptCount')
    ALTER TABLE [dbo].[Subsystem_Stage_State] ADD CONSTRAINT [DF_SSS_AttemptCount] DEFAULT ((0)) FOR [AttemptCount];
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Subsystem_Stage_State')
                 AND c.name = 'CreatedAt')
    ALTER TABLE [dbo].[Subsystem_Stage_State] ADD CONSTRAINT [DF_StageState_CreatedAt] DEFAULT (sysutcdatetime()) FOR [CreatedAt];
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Threat_Catalogue_Category_Map')
                 AND c.name = 'CreatedAt')
    ALTER TABLE [dbo].[Threat_Catalogue_Category_Map] ADD CONSTRAINT [DF_CatCategoryMap_CreatedAt] DEFAULT (sysutcdatetime()) FOR [CreatedAt];
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Threat_Scenario')
                 AND c.name = 'ScenarioNumber')
    ALTER TABLE [dbo].[Threat_Scenario] ADD CONSTRAINT [DF_Scenario_ScenarioNumber] DEFAULT ((1)) FOR [ScenarioNumber];
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Threat_Scenario')
                 AND c.name = 'ControlMapAttempts')
    ALTER TABLE [dbo].[Threat_Scenario] ADD CONSTRAINT [DF_ThreatScenario_ControlMapAttempts] DEFAULT ((0)) FOR [ControlMapAttempts];
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.ThreatType_ThreatActor_Map')
                 AND c.name = 'CreatedAt')
    ALTER TABLE [dbo].[ThreatType_ThreatActor_Map] ADD CONSTRAINT [DF_TypeActorMap_CreatedAt] DEFAULT (sysutcdatetime()) FOR [CreatedAt];
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 29 of 51   02_constraints/002_check_constraints.sql
============================================================================*/
PRINT '';
PRINT '>>> [29/51] 02_constraints/002_check_constraints.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  CHECK CONSTRAINTS

  Script:      002_check_constraints.sql
  Order:       02_constraints / 002
  Purpose:     3 check constraints.
  Depends on:  01_tables/ *
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    check constraints

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- check constraints ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  SECTION 5 — Check constraints
==============================================================================*/
IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_Config_Tuning_ValueType')
    ALTER TABLE [dbo].[Config_Tuning] WITH CHECK ADD CONSTRAINT [CK_Config_Tuning_ValueType]
        CHECK (([ValueType] = 'int' OR [ValueType] = 'float'));
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_Session_Status')
    ALTER TABLE [dbo].[Scenario_Session] WITH CHECK ADD CONSTRAINT [CK_Session_Status]
        CHECK (([SessionStatus] = 'cancelled' OR [SessionStatus] = 'completed' OR [SessionStatus] = 'active'));
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* A scenario cannot be accepted and rejected at once. Accept and reject are
   separate routes reachable in either order, so the row is the only place both
   orderings meet. */
IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_Scenario_DecisionExclusive')
    ALTER TABLE [dbo].[Threat_Scenario] WITH CHECK ADD CONSTRAINT [CK_Scenario_DecisionExclusive]
        CHECK (([RejectedAt] IS NULL OR [Accepted] = (0)));
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 30 of 51   02_constraints/003_unique_constraints.sql
============================================================================*/
PRINT '';
PRINT '>>> [30/51] 02_constraints/003_unique_constraints.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  UNIQUE CONSTRAINTS

  Script:      003_unique_constraints.sql
  Order:       02_constraints / 003
  Purpose:     1 unique constraint(s) the CREATE TABLE step omits.
  Depends on:  01_tables/ *
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    unique constraints

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- unique constraints ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/* UQ_Config_Tuning_Key - Config_Tuning (TuningKey).
   Declared unique=True in app/db/models.py and as a table constraint in the reviewed DDL, but
   emitted by NEITHER table_script() (columns + PK only) nor index_blocks() (CREATE INDEX only),
   so the package used to skip it entirely. ALTER, not CREATE TABLE, so an existing database
   gains it too.
   Duplicates are reported instead of letting ALTER fail with a bare constraint error: the rows
   have to be reconciled by a human, and the message needs to say which ones. */
IF NOT EXISTS (SELECT 1 FROM sys.key_constraints
               WHERE name = 'UQ_Config_Tuning_Key'
                 AND parent_object_id = OBJECT_ID('dbo.Config_Tuning'))
BEGIN
    IF EXISTS (SELECT 1 FROM dbo.[Config_Tuning] GROUP BY [TuningKey] HAVING COUNT(*) > 1)
    BEGIN
        PRINT ' [BLOCKED] Config_Tuning.TuningKey has duplicate values, so';
        PRINT '          UQ_Config_Tuning_Key cannot be created. The rows below must be';
        PRINT '          reconciled first - keep one, retire the rest.';
        SELECT [TuningKey], COUNT(*) AS Copies
        FROM   dbo.[Config_Tuning] GROUP BY [TuningKey] HAVING COUNT(*) > 1;
    END
    ELSE
    BEGIN
        ALTER TABLE dbo.[Config_Tuning] ADD CONSTRAINT [UQ_Config_Tuning_Key] UNIQUE ([TuningKey]);
        PRINT ' [ADDED]   UQ_Config_Tuning_Key on Config_Tuning (TuningKey)';
    END
END
ELSE
    PRINT ' [EXISTS]  UQ_Config_Tuning_Key';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 31 of 51   03_indexes/001_Threat_Category_indexes.sql
============================================================================*/
PRINT '';
PRINT '>>> [31/51] 03_indexes/001_Threat_Category_indexes.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  INDEXES: Threat_Category

  Script:      001_Threat_Category_indexes.sql
  Order:       03_indexes / 001
  Purpose:     1 index(es) on Threat_Category.
  Depends on:  01_tables/ *_Threat_Category.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Threat_Category

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- indexes: Threat_Category ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_ThreatCategory_NaturalKey' AND i.object_id = OBJECT_ID(N'dbo.Threat_Category')
          AND (i.is_unique <> 1 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 1
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'ThreatCategoryName')))
BEGIN
    PRINT ' [REBUILD] Threat_Category.UX_ThreatCategory_NaturalKey exists with the wrong shape - recreating it on (ThreatCategoryName).';
    DROP INDEX [UX_ThreatCategory_NaturalKey] ON [dbo].[Threat_Category];
END;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatCategory_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Category'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_ThreatCategory_NaturalKey] ON [dbo].[Threat_Category] ([ThreatCategoryName])
        WHERE [IsActive] = 1 AND [IsDeleted] = 0;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Threat_Category.UX_ThreatCategory_NaturalKey on (ThreatCategoryName).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_ThreatCategory_NaturalKey could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 32 of 51   03_indexes/002_Threat_Type_indexes.sql
============================================================================*/
PRINT '';
PRINT '>>> [32/51] 03_indexes/002_Threat_Type_indexes.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  INDEXES: Threat_Type

  Script:      002_Threat_Type_indexes.sql
  Order:       03_indexes / 002
  Purpose:     2 index(es) on Threat_Type.
  Depends on:  01_tables/ *_Threat_Type.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Threat_Type

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- indexes: Threat_Type ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_ThreatType_NaturalKey' AND i.object_id = OBJECT_ID(N'dbo.Threat_Type')
          AND (i.is_unique <> 1 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 1
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'ThreatTypeName')))
BEGIN
    PRINT ' [REBUILD] Threat_Type.UX_ThreatType_NaturalKey exists with the wrong shape - recreating it on (ThreatTypeName).';
    DROP INDEX [UX_ThreatType_NaturalKey] ON [dbo].[Threat_Type];
END;
/* Library natural keys. Two sessions promoting the same new name at once must
   not both create it. Filtered so a soft-deleted row releases its name.

   THE PREDICATE IS `WHERE [IsDeleted] = 0`, NOT the older
   `WHERE [IsActive] = 1 AND [IsDeleted] = 0`. Widened 2026-09-04: promote-to-library
   inserts AI-authored rows as IsActive = 0 (pending curator review -
   dal.upsert_threat_type / upsert_threat_catalogue), and a FILTERED index only
   constrains rows that satisfy its own predicate, so under the old filter an
   IsActive = 0 insert was NEVER covered. That is not a narrow race: it was ZERO
   duplicate-name protection for every promoted row, and the library quietly
   accumulated same-name twins that normalize_name() in Python already treats as one.

   The widening reached "2. Threat_library.sql" for BOTH keys and
   scripts/tsg_remediation_tables.sql for Threat_Catalogue ONLY - Threat_Type was
   left at the old predicate there, and the generated scripts/tsg_script/ package
   inherited it from that file. So a database built by the numbered scripts enforced
   one rule and a database built by the consolidated script or the package enforced
   another, on a boot-asserted UNIQUE index, with nothing comparing the two.
   tests/test_schema_sync.py::test_every_deploy_path_creates_the_same_indexes now
   compares each index's filter predicate across all three paths - it is the check
   that found this. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatType_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Type'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_ThreatType_NaturalKey] ON [dbo].[Threat_Type] ([ThreatTypeName])
        WHERE [IsDeleted] = 0;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Threat_Type.UX_ThreatType_NaturalKey on (ThreatTypeName).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_ThreatType_NaturalKey could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_ThreatType_Category_Active' AND i.object_id = OBJECT_ID(N'dbo.Threat_Type')
          AND (i.is_unique <> 0 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 1
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'ThreatCategoryID')))
BEGIN
    PRINT ' [REBUILD] Threat_Type.IX_ThreatType_Category_Active exists with the wrong shape - recreating it on (ThreatCategoryID).';
    DROP INDEX [IX_ThreatType_Category_Active] ON [dbo].[Threat_Type];
END;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ThreatType_Category_Active' AND object_id = OBJECT_ID('dbo.Threat_Type'))
    CREATE NONCLUSTERED INDEX [IX_ThreatType_Category_Active] ON [dbo].[Threat_Type] ([ThreatCategoryID])
        WHERE [IsActive] = 1 AND [IsDeleted] = 0;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Threat_Type.IX_ThreatType_Category_Active on (ThreatCategoryID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_ThreatType_Category_Active could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 33 of 51   03_indexes/003_Threat_Catalogue_indexes.sql
============================================================================*/
PRINT '';
PRINT '>>> [33/51] 03_indexes/003_Threat_Catalogue_indexes.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  INDEXES: Threat_Catalogue

  Script:      003_Threat_Catalogue_indexes.sql
  Order:       03_indexes / 003
  Purpose:     1 index(es) on Threat_Catalogue.
  Depends on:  01_tables/ *_Threat_Catalogue.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Threat_Catalogue

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- indexes: Threat_Catalogue ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_ThreatCatalogue_NaturalKey' AND i.object_id = OBJECT_ID(N'dbo.Threat_Catalogue')
          AND (i.is_unique <> 1 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 1
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'ThreatName')))
BEGIN
    PRINT ' [REBUILD] Threat_Catalogue.UX_ThreatCatalogue_NaturalKey exists with the wrong shape - recreating it on (ThreatName).';
    DROP INDEX [UX_ThreatCatalogue_NaturalKey] ON [dbo].[Threat_Catalogue];
END;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatCatalogue_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Catalogue'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_ThreatCatalogue_NaturalKey] ON [dbo].[Threat_Catalogue] ([ThreatName])
        WHERE [IsDeleted] = 0;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Threat_Catalogue.UX_ThreatCatalogue_NaturalKey on (ThreatName).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_ThreatCatalogue_NaturalKey could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 34 of 51   03_indexes/004_Threat_Actor_indexes.sql
============================================================================*/
PRINT '';
PRINT '>>> [34/51] 03_indexes/004_Threat_Actor_indexes.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  INDEXES: Threat_Actor

  Script:      004_Threat_Actor_indexes.sql
  Order:       03_indexes / 004
  Purpose:     1 index(es) on Threat_Actor.
  Depends on:  01_tables/ *_Threat_Actor.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Threat_Actor

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- indexes: Threat_Actor ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_ThreatActor_NaturalKey' AND i.object_id = OBJECT_ID(N'dbo.Threat_Actor')
          AND (i.is_unique <> 1 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 1
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'ThreatActorName')))
BEGIN
    PRINT ' [REBUILD] Threat_Actor.UX_ThreatActor_NaturalKey exists with the wrong shape - recreating it on (ThreatActorName).';
    DROP INDEX [UX_ThreatActor_NaturalKey] ON [dbo].[Threat_Actor];
END;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ThreatActor_NaturalKey' AND object_id = OBJECT_ID('dbo.Threat_Actor'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_ThreatActor_NaturalKey] ON [dbo].[Threat_Actor] ([ThreatActorName])
        WHERE [IsActive] = 1 AND [IsDeleted] = 0;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Threat_Actor.UX_ThreatActor_NaturalKey on (ThreatActorName).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_ThreatActor_NaturalKey could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 35 of 51   03_indexes/005_Control_Standard_indexes.sql
============================================================================*/
PRINT '';
PRINT '>>> [35/51] 03_indexes/005_Control_Standard_indexes.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  INDEXES: Control_Standard

  Script:      005_Control_Standard_indexes.sql
  Order:       03_indexes / 005
  Purpose:     1 index(es) on Control_Standard.
  Depends on:  01_tables/ *_Control_Standard.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Control_Standard

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- indexes: Control_Standard ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_Control_Standard_Name' AND i.object_id = OBJECT_ID(N'dbo.Control_Standard')
          AND (i.is_unique <> 1 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 1
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'StandardName')))
BEGIN
    PRINT ' [REBUILD] Control_Standard.UX_Control_Standard_Name exists with the wrong shape - recreating it on (StandardName).';
    DROP INDEX [UX_Control_Standard_Name] ON [dbo].[Control_Standard];
END;
/* Control library natural keys. A duplicate control code would give the
   matching step a phantom control to choose. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Control_Standard_Name' AND object_id = OBJECT_ID('dbo.Control_Standard'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_Control_Standard_Name] ON [dbo].[Control_Standard] ([StandardName])
        WHERE [IsActive] = 1 AND [IsDeleted] = 0;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Control_Standard.UX_Control_Standard_Name on (StandardName).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_Control_Standard_Name could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 36 of 51   03_indexes/006_Control_Library_indexes.sql
============================================================================*/
PRINT '';
PRINT '>>> [36/51] 03_indexes/006_Control_Library_indexes.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  INDEXES: Control_Library

  Script:      006_Control_Library_indexes.sql
  Order:       03_indexes / 006
  Purpose:     1 index(es) on Control_Library.
  Depends on:  01_tables/ *_Control_Library.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Control_Library

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- indexes: Control_Library ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_Control_Library_Code' AND i.object_id = OBJECT_ID(N'dbo.Control_Library')
          AND (i.is_unique <> 1 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 1
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'ControlCode')))
BEGIN
    PRINT ' [REBUILD] Control_Library.UX_Control_Library_Code exists with the wrong shape - recreating it on (ControlCode).';
    DROP INDEX [UX_Control_Library_Code] ON [dbo].[Control_Library];
END;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Control_Library_Code' AND object_id = OBJECT_ID('dbo.Control_Library'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_Control_Library_Code] ON [dbo].[Control_Library] ([ControlCode])
        WHERE [IsActive] = 1 AND [IsDeleted] = 0;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Control_Library.UX_Control_Library_Code on (ControlCode).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_Control_Library_Code could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 37 of 51   03_indexes/007_API_Client_indexes.sql
============================================================================*/
PRINT '';
PRINT '>>> [37/51] 03_indexes/007_API_Client_indexes.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  INDEXES: API_Client

  Script:      007_API_Client_indexes.sql
  Order:       03_indexes / 007
  Purpose:     1 index(es) on API_Client.
  Depends on:  01_tables/ *_API_Client.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.API_Client

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- indexes: API_Client ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_API_Client_KeyHash' AND i.object_id = OBJECT_ID(N'dbo.API_Client')
          AND (i.is_unique <> 1 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 1
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'KeyHash')))
BEGIN
    PRINT ' [REBUILD] API_Client.UX_API_Client_KeyHash exists with the wrong shape - recreating it on (KeyHash).';
    DROP INDEX [UX_API_Client_KeyHash] ON [dbo].[API_Client];
END;
/* Stops two active clients sharing one key hash, and turns every
   authentication from a table scan into a seek. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_API_Client_KeyHash' AND object_id = OBJECT_ID('dbo.API_Client'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_API_Client_KeyHash] ON [dbo].[API_Client] ([KeyHash])
        WHERE [Active] = 1;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild API_Client.UX_API_Client_KeyHash on (KeyHash).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_API_Client_KeyHash could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 38 of 51   03_indexes/008_Grounding_Calibration_Run_indexes.sql
============================================================================*/
PRINT '';
PRINT '>>> [38/51] 03_indexes/008_Grounding_Calibration_Run_indexes.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  INDEXES: Grounding_Calibration_Run

  Script:      008_Grounding_Calibration_Run_indexes.sql
  Order:       03_indexes / 008
  Purpose:     1 index(es) on Grounding_Calibration_Run.
  Depends on:  01_tables/ *_Grounding_Calibration_Run.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Grounding_Calibration_Run

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- indexes: Grounding_Calibration_Run ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_GroundingCalibration_Running' AND i.object_id = OBJECT_ID(N'dbo.Grounding_Calibration_Run')
          AND (i.is_unique <> 1 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'EmbeddingModel')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'RerankerModel')))
BEGIN
    PRINT ' [REBUILD] Grounding_Calibration_Run.UX_GroundingCalibration_Running exists with the wrong shape - recreating it on (EmbeddingModel, RerankerModel).';
    DROP INDEX [UX_GroundingCalibration_Running] ON [dbo].[Grounding_Calibration_Run];
END;
/* One calibration sweep at a time per model pair. The route cannot prevent a
   double start on its own: two requests arriving together both read "nothing
   running" before either writes. Only this index closes that window, and a
   sweep costs 10 to 15 minutes of billed model calls. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_GroundingCalibration_Running' AND object_id = OBJECT_ID('dbo.Grounding_Calibration_Run'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_GroundingCalibration_Running] ON [dbo].[Grounding_Calibration_Run] ([EmbeddingModel], [RerankerModel])
        WHERE [Status] = 'running';
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Grounding_Calibration_Run.UX_GroundingCalibration_Running on (EmbeddingModel, RerankerModel).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_GroundingCalibration_Running could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 39 of 51   03_indexes/009_Scenario_Session_indexes.sql
============================================================================*/
PRINT '';
PRINT '>>> [39/51] 03_indexes/009_Scenario_Session_indexes.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  INDEXES: Scenario_Session

  Script:      009_Scenario_Session_indexes.sql
  Order:       03_indexes / 009
  Purpose:     4 index(es) on Scenario_Session.
  Depends on:  01_tables/ *_Scenario_Session.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Scenario_Session

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- indexes: Scenario_Session ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_Session_ActiveAsset' AND i.object_id = OBJECT_ID(N'dbo.Scenario_Session')
          AND (i.is_unique <> 1 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'EntityID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'AssetID')))
BEGIN
    PRINT ' [REBUILD] Scenario_Session.UX_Session_ActiveAsset exists with the wrong shape - recreating it on (EntityID, AssetID).';
    DROP INDEX [UX_Session_ActiveAsset] ON [dbo].[Scenario_Session];
END;
/* One active session per asset. Without it a retried request creates a second
   session for the same asset instead of returning the first. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Session_ActiveAsset' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_Session_ActiveAsset] ON [dbo].[Scenario_Session] ([EntityID], [AssetID])
        WHERE [SessionStatus] = 'active';
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Scenario_Session.UX_Session_ActiveAsset on (EntityID, AssetID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_Session_ActiveAsset could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_Session_IdempotencyKey' AND i.object_id = OBJECT_ID(N'dbo.Scenario_Session')
          AND (i.is_unique <> 1 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'EntityID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'IdempotencyKey')))
BEGIN
    PRINT ' [REBUILD] Scenario_Session.UX_Session_IdempotencyKey exists with the wrong shape - recreating it on (EntityID, IdempotencyKey).';
    DROP INDEX [UX_Session_IdempotencyKey] ON [dbo].[Scenario_Session];
END;
/* Idempotency: a repeated request carrying the same key returns the original
   session rather than creating another. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Session_IdempotencyKey' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_Session_IdempotencyKey] ON [dbo].[Scenario_Session] ([EntityID], [IdempotencyKey])
        WHERE [IdempotencyKey] IS NOT NULL;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Scenario_Session.UX_Session_IdempotencyKey on (EntityID, IdempotencyKey).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_Session_IdempotencyKey could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_Session_Active' AND i.object_id = OBJECT_ID(N'dbo.Scenario_Session')
          AND (i.is_unique <> 0 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 1
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionStatus')))
BEGIN
    PRINT ' [REBUILD] Scenario_Session.IX_Session_Active exists with the wrong shape - recreating it on (SessionStatus).';
    DROP INDEX [IX_Session_Active] ON [dbo].[Scenario_Session];
END;
/* Not unique, but also verified at start-up: the application reads this index's
   WHERE clause to confirm the stored status wording still matches its own. It
   also makes the capacity count and the recovery sweep proportional to the
   number of ACTIVE sessions rather than to the whole table. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Session_Active' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
    CREATE NONCLUSTERED INDEX [IX_Session_Active] ON [dbo].[Scenario_Session] ([SessionStatus])
        WHERE [SessionStatus] = 'active';
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Scenario_Session.IX_Session_Active on (SessionStatus).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_Session_Active could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_Session_EntityUser' AND i.object_id = OBJECT_ID(N'dbo.Scenario_Session')
          AND (i.is_unique <> 0 OR i.has_filter <> 0
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'EntityID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'UserID')))
BEGIN
    PRINT ' [REBUILD] Scenario_Session.IX_Session_EntityUser exists with the wrong shape - recreating it on (EntityID, UserID).';
    DROP INDEX [IX_Session_EntityUser] ON [dbo].[Scenario_Session];
END;
/* Backs the cross-session scenario browse feed, which filters entity, then
   optionally user and session status. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Session_EntityUser' AND object_id = OBJECT_ID('dbo.Scenario_Session'))
    CREATE NONCLUSTERED INDEX [IX_Session_EntityUser] ON [dbo].[Scenario_Session] ([EntityID], [UserID])
        INCLUDE ([SessionStatus]);
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Scenario_Session.IX_Session_EntityUser on (EntityID, UserID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_Session_EntityUser could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 40 of 51   03_indexes/010_Subsystem_Stage_State_indexes.sql
============================================================================*/
PRINT '';
PRINT '>>> [40/51] 03_indexes/010_Subsystem_Stage_State_indexes.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  INDEXES: Subsystem_Stage_State

  Script:      010_Subsystem_Stage_State_indexes.sql
  Order:       03_indexes / 010
  Purpose:     1 index(es) on Subsystem_Stage_State.
  Depends on:  01_tables/ *_Subsystem_Stage_State.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Subsystem_Stage_State

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- indexes: Subsystem_Stage_State ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_SubsystemStageState_SessionSubLevel' AND i.object_id = OBJECT_ID(N'dbo.Subsystem_Stage_State')
          AND (i.is_unique <> 1 OR i.has_filter <> 0
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 3
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'SubsystemID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 3 AND c.name = N'Level')))
BEGIN
    PRINT ' [REBUILD] Subsystem_Stage_State.UX_SubsystemStageState_SessionSubLevel exists with the wrong shape - recreating it on (SessionID, SubsystemID, Level).';
    DROP INDEX [UX_SubsystemStageState_SessionSubLevel] ON [dbo].[Subsystem_Stage_State];
END;
/* The row identity the whole locking design depends on. A duplicate would let
   one claim match two rows and put two workers on the same unit of work. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_SubsystemStageState_SessionSubLevel' AND object_id = OBJECT_ID('dbo.Subsystem_Stage_State'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_SubsystemStageState_SessionSubLevel] ON [dbo].[Subsystem_Stage_State] ([SessionID], [SubsystemID], [Level]);
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Subsystem_Stage_State.UX_SubsystemStageState_SessionSubLevel on (SessionID, SubsystemID, Level).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_SubsystemStageState_SessionSubLevel could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 41 of 51   03_indexes/011_Identified_Threat_indexes.sql
============================================================================*/
PRINT '';
PRINT '>>> [41/51] 03_indexes/011_Identified_Threat_indexes.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  INDEXES: Identified_Threat

  Script:      011_Identified_Threat_indexes.sql
  Order:       03_indexes / 011
  Purpose:     1 index(es) on Identified_Threat.
  Depends on:  01_tables/ *_Identified_Threat.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Identified_Threat

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- indexes: Identified_Threat ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_IdentifiedThreat_SessionSubActive' AND i.object_id = OBJECT_ID(N'dbo.Identified_Threat')
          AND (i.is_unique <> 0 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'SubsystemID')))
BEGIN
    PRINT ' [REBUILD] Identified_Threat.IX_IdentifiedThreat_SessionSubActive exists with the wrong shape - recreating it on (SessionID, SubsystemID).';
    DROP INDEX [IX_IdentifiedThreat_SessionSubActive] ON [dbo].[Identified_Threat];
END;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_IdentifiedThreat_SessionSubActive' AND object_id = OBJECT_ID('dbo.Identified_Threat'))
    CREATE NONCLUSTERED INDEX [IX_IdentifiedThreat_SessionSubActive] ON [dbo].[Identified_Threat] ([SessionID], [SubsystemID])
        WHERE [Superseded] = 0;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Identified_Threat.IX_IdentifiedThreat_SessionSubActive on (SessionID, SubsystemID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_IdentifiedThreat_SessionSubActive could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 42 of 51   03_indexes/012_Identified_Duplicate_Threat_indexes.sql
============================================================================*/
PRINT '';
PRINT '>>> [42/51] 03_indexes/012_Identified_Duplicate_Threat_indexes.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  INDEXES: Identified_Duplicate_Threat

  Script:      012_Identified_Duplicate_Threat_indexes.sql
  Order:       03_indexes / 012
  Purpose:     1 index(es) on Identified_Duplicate_Threat.
  Depends on:  01_tables/ *_Identified_Duplicate_Threat.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Identified_Duplicate_Threat

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- indexes: Identified_Duplicate_Threat ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_IdentifiedDuplicateThreat_Session' AND i.object_id = OBJECT_ID(N'dbo.Identified_Duplicate_Threat')
          AND (i.is_unique <> 0 OR i.has_filter <> 0
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 1
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')))
BEGIN
    PRINT ' [REBUILD] Identified_Duplicate_Threat.IX_IdentifiedDuplicateThreat_Session exists with the wrong shape - recreating it on (SessionID).';
    DROP INDEX [IX_IdentifiedDuplicateThreat_Session] ON [dbo].[Identified_Duplicate_Threat];
END;
/* No reader: nothing selects from Identified_Duplicate_Threat at all. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_IdentifiedDuplicateThreat_Session' AND object_id = OBJECT_ID('dbo.Identified_Duplicate_Threat'))
    CREATE NONCLUSTERED INDEX [IX_IdentifiedDuplicateThreat_Session] ON [dbo].[Identified_Duplicate_Threat] ([SessionID]);
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Identified_Duplicate_Threat.IX_IdentifiedDuplicateThreat_Session on (SessionID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_IdentifiedDuplicateThreat_Session could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 43 of 51   03_indexes/013_Scoped_Threat_indexes.sql
============================================================================*/
PRINT '';
PRINT '>>> [43/51] 03_indexes/013_Scoped_Threat_indexes.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  INDEXES: Scoped_Threat

  Script:      013_Scoped_Threat_indexes.sql
  Order:       03_indexes / 013
  Purpose:     2 index(es) on Scoped_Threat.
  Depends on:  01_tables/ *_Scoped_Threat.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Scoped_Threat

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- indexes: Scoped_Threat ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_ScopedThreat_SessionSubActive' AND i.object_id = OBJECT_ID(N'dbo.Scoped_Threat')
          AND (i.is_unique <> 0 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'SubsystemID')))
BEGIN
    PRINT ' [REBUILD] Scoped_Threat.IX_ScopedThreat_SessionSubActive exists with the wrong shape - recreating it on (SessionID, SubsystemID).';
    DROP INDEX [IX_ScopedThreat_SessionSubActive] ON [dbo].[Scoped_Threat];
END;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScopedThreat_SessionSubActive' AND object_id = OBJECT_ID('dbo.Scoped_Threat'))
    CREATE NONCLUSTERED INDEX [IX_ScopedThreat_SessionSubActive] ON [dbo].[Scoped_Threat] ([SessionID], [SubsystemID])
        WHERE [Superseded] = 0;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Scoped_Threat.IX_ScopedThreat_SessionSubActive on (SessionID, SubsystemID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_ScopedThreat_SessionSubActive could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_ScopedThreat_SessionActiveScores' AND i.object_id = OBJECT_ID(N'dbo.Scoped_Threat')
          AND (i.is_unique <> 0 OR i.has_filter <> 0
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'Superseded')))
BEGIN
    PRINT ' [REBUILD] Scoped_Threat.IX_ScopedThreat_SessionActiveScores exists with the wrong shape - recreating it on (SessionID, Superseded).';
    DROP INDEX [IX_ScopedThreat_SessionActiveScores] ON [dbo].[Scoped_Threat];
END;
/* Deliberately NOT filtered, even though Superseded appears in it. SQL Server
   cannot match a filtered index against a parameterised predicate, so the
   column sits in the key instead of a WHERE clause. Backs the scoring read. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScopedThreat_SessionActiveScores' AND object_id = OBJECT_ID('dbo.Scoped_Threat'))
    CREATE NONCLUSTERED INDEX [IX_ScopedThreat_SessionActiveScores] ON [dbo].[Scoped_Threat] ([SessionID], [Superseded])
        INCLUDE ([ThreatID], [Score], [ScopeRank]);
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Scoped_Threat.IX_ScopedThreat_SessionActiveScores on (SessionID, Superseded).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_ScopedThreat_SessionActiveScores could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 44 of 51   03_indexes/014_Threat_Scenario_indexes.sql
============================================================================*/
PRINT '';
PRINT '>>> [44/51] 03_indexes/014_Threat_Scenario_indexes.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  INDEXES: Threat_Scenario

  Script:      014_Threat_Scenario_indexes.sql
  Order:       03_indexes / 014
  Purpose:     5 index(es) on Threat_Scenario.
  Depends on:  01_tables/ *_Threat_Scenario.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Threat_Scenario

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- indexes: Threat_Scenario ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_Scenario_ActiveIdentity' AND i.object_id = OBJECT_ID(N'dbo.Threat_Scenario')
          AND (i.is_unique <> 1 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 3
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'IdentityHash')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 3 AND c.name = N'ScenarioNumber')))
BEGIN
    PRINT ' [REBUILD] Threat_Scenario.UX_Scenario_ActiveIdentity exists with the wrong shape - recreating it on (SessionID, IdentityHash, ScenarioNumber).';
    DROP INDEX [UX_Scenario_ActiveIdentity] ON [dbo].[Threat_Scenario];
END;
/* One current version per scenario identity. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Scenario_ActiveIdentity' AND object_id = OBJECT_ID('dbo.Threat_Scenario'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_Scenario_ActiveIdentity] ON [dbo].[Threat_Scenario] ([SessionID], [IdentityHash], [ScenarioNumber])
        WHERE [Superseded] = 0;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Threat_Scenario.UX_Scenario_ActiveIdentity on (SessionID, IdentityHash, ScenarioNumber).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_Scenario_ActiveIdentity could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_Scenario_ActiveScoped' AND i.object_id = OBJECT_ID(N'dbo.Threat_Scenario')
          AND (i.is_unique <> 1 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'ScopedThreatID')))
BEGIN
    PRINT ' [REBUILD] Threat_Scenario.UX_Scenario_ActiveScoped exists with the wrong shape - recreating it on (SessionID, ScopedThreatID).';
    DROP INDEX [UX_Scenario_ActiveScoped] ON [dbo].[Threat_Scenario];
END;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Scenario_ActiveScoped' AND object_id = OBJECT_ID('dbo.Threat_Scenario'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_Scenario_ActiveScoped] ON [dbo].[Threat_Scenario] ([SessionID], [ScopedThreatID])
        WHERE [Superseded] = 0;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Threat_Scenario.UX_Scenario_ActiveScoped on (SessionID, ScopedThreatID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_Scenario_ActiveScoped could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_Scenario_ActiveAccepted' AND i.object_id = OBJECT_ID(N'dbo.Threat_Scenario')
          AND (i.is_unique <> 1 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 3
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'IdentityHash')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 3 AND c.name = N'ScenarioNumber')))
BEGIN
    PRINT ' [REBUILD] Threat_Scenario.UX_Scenario_ActiveAccepted exists with the wrong shape - recreating it on (SessionID, IdentityHash, ScenarioNumber).';
    DROP INDEX [UX_Scenario_ActiveAccepted] ON [dbo].[Threat_Scenario];
END;
/* One ACCEPTED version per identity. Separate from the index above: a reviewer
   may accept an older version, so "current" and "accepted" are not the same row. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_Scenario_ActiveAccepted' AND object_id = OBJECT_ID('dbo.Threat_Scenario'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_Scenario_ActiveAccepted] ON [dbo].[Threat_Scenario] ([SessionID], [IdentityHash], [ScenarioNumber])
        WHERE [Accepted] = 1 AND [IdentityHash] IS NOT NULL;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Threat_Scenario.UX_Scenario_ActiveAccepted on (SessionID, IdentityHash, ScenarioNumber).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_Scenario_ActiveAccepted could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_Scenario_SessionSubActive' AND i.object_id = OBJECT_ID(N'dbo.Threat_Scenario')
          AND (i.is_unique <> 0 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'SubsystemID')))
BEGIN
    PRINT ' [REBUILD] Threat_Scenario.IX_Scenario_SessionSubActive exists with the wrong shape - recreating it on (SessionID, SubsystemID).';
    DROP INDEX [IX_Scenario_SessionSubActive] ON [dbo].[Threat_Scenario];
END;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Scenario_SessionSubActive' AND object_id = OBJECT_ID('dbo.Threat_Scenario'))
    CREATE NONCLUSTERED INDEX [IX_Scenario_SessionSubActive] ON [dbo].[Threat_Scenario] ([SessionID], [SubsystemID])
        WHERE [Superseded] = 0;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Threat_Scenario.IX_Scenario_SessionSubActive on (SessionID, SubsystemID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_Scenario_SessionSubActive could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_Scenario_RejectedDecision' AND i.object_id = OBJECT_ID(N'dbo.Threat_Scenario')
          AND (i.is_unique <> 0 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 1
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')))
BEGIN
    PRINT ' [REBUILD] Threat_Scenario.IX_Scenario_RejectedDecision exists with the wrong shape - recreating it on (SessionID).';
    DROP INDEX [IX_Scenario_RejectedDecision] ON [dbo].[Threat_Scenario];
END;
/* The reject side of GET /v1/sessions/{id}/results, which re-adds a DECIDED scenario
   even after a regeneration superseded it. Threat_Scenario has NO unfiltered SessionID
   index - its key is the GUID id, and every SessionID-leading index above is filtered
   on Superseded or Accepted - so /results issues one seek per filtered index rather
   than a single OR. Without this index the reject-side seek degrades into a full table
   scan on an endpoint clients POLL: correct, and merely slow, which is how a table scan
   reaches production unnoticed. Filtered over the rejected rows only, so it costs almost
   nothing. The same statement is in "1. TSG_Core.sql" (canonical) and in
   scripts/TSG_Migration_RejectedDecisionIndex.sql (for a database already up); it was
   missing HERE, and from the generated package this file is the source for, because no
   guard compared the three deploy paths' index inventories. One now does:
   tests/test_schema_sync.py::test_every_deploy_path_creates_the_same_indexes. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Scenario_RejectedDecision' AND object_id = OBJECT_ID('dbo.Threat_Scenario'))
    CREATE NONCLUSTERED INDEX [IX_Scenario_RejectedDecision] ON [dbo].[Threat_Scenario] ([SessionID])
        WHERE [RejectedAt] IS NOT NULL;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Threat_Scenario.IX_Scenario_RejectedDecision on (SessionID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_Scenario_RejectedDecision could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 45 of 51   03_indexes/015_Risk_Treatment_Plan_indexes.sql
============================================================================*/
PRINT '';
PRINT '>>> [45/51] 03_indexes/015_Risk_Treatment_Plan_indexes.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  INDEXES: Risk_Treatment_Plan

  Script:      015_Risk_Treatment_Plan_indexes.sql
  Order:       03_indexes / 015
  Purpose:     3 index(es) on Risk_Treatment_Plan.
  Depends on:  01_tables/ *_Risk_Treatment_Plan.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Risk_Treatment_Plan

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- indexes: Risk_Treatment_Plan ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'UX_TreatmentPlan_ActiveScenario' AND i.object_id = OBJECT_ID(N'dbo.Risk_Treatment_Plan')
          AND (i.is_unique <> 1 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 1
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'ScenarioID')))
BEGIN
    PRINT ' [REBUILD] Risk_Treatment_Plan.UX_TreatmentPlan_ActiveScenario exists with the wrong shape - recreating it on (ScenarioID).';
    DROP INDEX [UX_TreatmentPlan_ActiveScenario] ON [dbo].[Risk_Treatment_Plan];
END;
/* One active remediation plan per scenario. This index is what arbitrates two
   simultaneous plan requests. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_TreatmentPlan_ActiveScenario' AND object_id = OBJECT_ID('dbo.Risk_Treatment_Plan'))
    CREATE UNIQUE NONCLUSTERED INDEX [UX_TreatmentPlan_ActiveScenario] ON [dbo].[Risk_Treatment_Plan] ([ScenarioID])
        WHERE [Superseded] = 0;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Risk_Treatment_Plan.UX_TreatmentPlan_ActiveScenario on (ScenarioID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index UX_TreatmentPlan_ActiveScenario could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_TreatmentPlan_SessionActive' AND i.object_id = OBJECT_ID(N'dbo.Risk_Treatment_Plan')
          AND (i.is_unique <> 0 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 1
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')))
BEGIN
    PRINT ' [REBUILD] Risk_Treatment_Plan.IX_TreatmentPlan_SessionActive exists with the wrong shape - recreating it on (SessionID).';
    DROP INDEX [IX_TreatmentPlan_SessionActive] ON [dbo].[Risk_Treatment_Plan];
END;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_TreatmentPlan_SessionActive' AND object_id = OBJECT_ID('dbo.Risk_Treatment_Plan'))
    CREATE NONCLUSTERED INDEX [IX_TreatmentPlan_SessionActive] ON [dbo].[Risk_Treatment_Plan] ([SessionID])
        WHERE [Superseded] = 0;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Risk_Treatment_Plan.IX_TreatmentPlan_SessionActive on (SessionID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_TreatmentPlan_SessionActive could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_TreatmentPlan_SessionHistory' AND i.object_id = OBJECT_ID(N'dbo.Risk_Treatment_Plan')
          AND (i.is_unique <> 0 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 3
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'ScenarioID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 3 AND c.name = N'CreatedAt')))
BEGIN
    PRINT ' [REBUILD] Risk_Treatment_Plan.IX_TreatmentPlan_SessionHistory exists with the wrong shape - recreating it on (SessionID, ScenarioID, CreatedAt).';
    DROP INDEX [IX_TreatmentPlan_SessionHistory] ON [dbo].[Risk_Treatment_Plan];
END;
/* Backs the plan version history, which reads only retired rows. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_TreatmentPlan_SessionHistory' AND object_id = OBJECT_ID('dbo.Risk_Treatment_Plan'))
    CREATE NONCLUSTERED INDEX [IX_TreatmentPlan_SessionHistory] ON [dbo].[Risk_Treatment_Plan] ([SessionID], [ScenarioID], [CreatedAt])
        WHERE [Superseded] = 1;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Risk_Treatment_Plan.IX_TreatmentPlan_SessionHistory on (SessionID, ScenarioID, CreatedAt).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_TreatmentPlan_SessionHistory could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 46 of 51   03_indexes/016_Scenario_Audit_indexes.sql
============================================================================*/
PRINT '';
PRINT '>>> [46/51] 03_indexes/016_Scenario_Audit_indexes.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  INDEXES: Scenario_Audit

  Script:      016_Scenario_Audit_indexes.sql
  Order:       03_indexes / 016
  Purpose:     3 index(es) on Scenario_Audit.
  Depends on:  01_tables/ *_Scenario_Audit.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Scenario_Audit

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- indexes: Scenario_Audit ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_ScenarioAudit_SessionSubEvent' AND i.object_id = OBJECT_ID(N'dbo.Scenario_Audit')
          AND (i.is_unique <> 0 OR i.has_filter <> 0
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 4
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'SubsystemID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 3 AND c.name = N'EventType')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 4 AND c.name = N'CreatedAt')))
BEGIN
    PRINT ' [REBUILD] Scenario_Audit.IX_ScenarioAudit_SessionSubEvent exists with the wrong shape - recreating it on (SessionID, SubsystemID, EventType, CreatedAt).';
    DROP INDEX [IX_ScenarioAudit_SessionSubEvent] ON [dbo].[Scenario_Audit];
END;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioAudit_SessionSubEvent' AND object_id = OBJECT_ID('dbo.Scenario_Audit'))
    CREATE NONCLUSTERED INDEX [IX_ScenarioAudit_SessionSubEvent] ON [dbo].[Scenario_Audit] ([SessionID], [SubsystemID], [EventType], [CreatedAt] DESC);
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Scenario_Audit.IX_ScenarioAudit_SessionSubEvent on (SessionID, SubsystemID, EventType, CreatedAt).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_ScenarioAudit_SessionSubEvent could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_ScenarioAudit_Scenario' AND i.object_id = OBJECT_ID(N'dbo.Scenario_Audit')
          AND (i.is_unique <> 0 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'ScenarioID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'CreatedAt')))
BEGIN
    PRINT ' [REBUILD] Scenario_Audit.IX_ScenarioAudit_Scenario exists with the wrong shape - recreating it on (ScenarioID, CreatedAt).';
    DROP INDEX [IX_ScenarioAudit_Scenario] ON [dbo].[Scenario_Audit];
END;
/* "The decision history of this scenario" is the query a reviewer actually
   runs; this makes it a seek. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioAudit_Scenario' AND object_id = OBJECT_ID('dbo.Scenario_Audit'))
    CREATE NONCLUSTERED INDEX [IX_ScenarioAudit_Scenario] ON [dbo].[Scenario_Audit] ([ScenarioID], [CreatedAt] DESC)
        WHERE [ScenarioID] IS NOT NULL;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Scenario_Audit.IX_ScenarioAudit_Scenario on (ScenarioID, CreatedAt).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_ScenarioAudit_Scenario could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_ScenarioAudit_Plan' AND i.object_id = OBJECT_ID(N'dbo.Scenario_Audit')
          AND (i.is_unique <> 0 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'PlanID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'CreatedAt')))
BEGIN
    PRINT ' [REBUILD] Scenario_Audit.IX_ScenarioAudit_Plan exists with the wrong shape - recreating it on (PlanID, CreatedAt).';
    DROP INDEX [IX_ScenarioAudit_Plan] ON [dbo].[Scenario_Audit];
END;
/* No reader: the treatment audit feed filters session, event type and scenario.
   No query filters the audit table by PlanID; the column is output only. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScenarioAudit_Plan' AND object_id = OBJECT_ID('dbo.Scenario_Audit'))
    CREATE NONCLUSTERED INDEX [IX_ScenarioAudit_Plan] ON [dbo].[Scenario_Audit] ([PlanID], [CreatedAt] DESC)
        WHERE [PlanID] IS NOT NULL;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Scenario_Audit.IX_ScenarioAudit_Plan on (PlanID, CreatedAt).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_ScenarioAudit_Plan could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 47 of 51   03_indexes/017_Prompt_Log_indexes.sql
============================================================================*/
PRINT '';
PRINT '>>> [47/51] 03_indexes/017_Prompt_Log_indexes.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  INDEXES: Prompt_Log

  Script:      017_Prompt_Log_indexes.sql
  Order:       03_indexes / 017
  Purpose:     3 index(es) on Prompt_Log.
  Depends on:  01_tables/ *_Prompt_Log.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Prompt_Log

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- indexes: Prompt_Log ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_PromptLog_Correlation' AND i.object_id = OBJECT_ID(N'dbo.Prompt_Log')
          AND (i.is_unique <> 0 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'CorrelationID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'CreatedAt')))
BEGIN
    PRINT ' [REBUILD] Prompt_Log.IX_PromptLog_Correlation exists with the wrong shape - recreating it on (CorrelationID, CreatedAt).';
    DROP INDEX [IX_PromptLog_Correlation] ON [dbo].[Prompt_Log];
END;
/* The evidence endpoint reads the prompt log by correlation id and nothing
   else. Without this index that read scans the whole table, which grows by one
   row per model call. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_PromptLog_Correlation' AND object_id = OBJECT_ID('dbo.Prompt_Log'))
    CREATE NONCLUSTERED INDEX [IX_PromptLog_Correlation] ON [dbo].[Prompt_Log] ([CorrelationID], [CreatedAt])
        WHERE [CorrelationID] IS NOT NULL;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Prompt_Log.IX_PromptLog_Correlation on (CorrelationID, CreatedAt).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_PromptLog_Correlation could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_PromptLog_Session' AND i.object_id = OBJECT_ID(N'dbo.Prompt_Log')
          AND (i.is_unique <> 0 OR i.has_filter <> 0
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'SubsystemID')))
BEGIN
    PRINT ' [REBUILD] Prompt_Log.IX_PromptLog_Session exists with the wrong shape - recreating it on (SessionID, SubsystemID).';
    DROP INDEX [IX_PromptLog_Session] ON [dbo].[Prompt_Log];
END;
/* No reader: the prompt log is only ever read by CorrelationID, which
   IX_PromptLog_Correlation above now serves. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_PromptLog_Session' AND object_id = OBJECT_ID('dbo.Prompt_Log'))
    CREATE NONCLUSTERED INDEX [IX_PromptLog_Session] ON [dbo].[Prompt_Log] ([SessionID], [SubsystemID]);
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Prompt_Log.IX_PromptLog_Session on (SessionID, SubsystemID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_PromptLog_Session could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'CIX_PromptLog_Created' AND i.object_id = OBJECT_ID(N'dbo.Prompt_Log')
          AND (i.is_unique <> 0 OR i.has_filter <> 0
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'CreatedAt')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'LogID')))
BEGIN
    PRINT ' [REBUILD] Prompt_Log.CIX_PromptLog_Created exists with the wrong shape - recreating it on (CreatedAt, LogID).';
    DROP INDEX [CIX_PromptLog_Created] ON [dbo].[Prompt_Log];
END;
/*------------------------------------------------------------------------------
  Then the clustered indexes themselves.

  The second guard - no clustered index of ANY name on the table - is what keeps
  this statement from ABORTING the run on a database whose primary key could not
  be moved above. Without it the statement fails with Msg 1902 (a table may have
  only one clustered index), the batch stops, and every section after this one is
  skipped over a table that was already reported as a finding. With it the index
  is simply not created, and Section 7 reports it as MISSING INDEX.
------------------------------------------------------------------------------*/
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'CIX_PromptLog_Created' AND object_id = OBJECT_ID('dbo.Prompt_Log'))
   AND NOT EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = OBJECT_ID('dbo.Prompt_Log') AND type_desc = 'CLUSTERED')
    CREATE CLUSTERED INDEX [CIX_PromptLog_Created] ON [dbo].[Prompt_Log] ([CreatedAt], [LogID])
        WITH (DATA_COMPRESSION = PAGE);
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Prompt_Log.CIX_PromptLog_Created on (CreatedAt, LogID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index CIX_PromptLog_Created could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 48 of 51   03_indexes/018_Diagnostic_Event_indexes.sql
============================================================================*/
PRINT '';
PRINT '>>> [48/51] 03_indexes/018_Diagnostic_Event_indexes.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  INDEXES: Diagnostic_Event

  Script:      018_Diagnostic_Event_indexes.sql
  Order:       03_indexes / 018
  Purpose:     3 index(es) on Diagnostic_Event.
  Depends on:  01_tables/ *_Diagnostic_Event.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Diagnostic_Event

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- indexes: Diagnostic_Event ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_DiagnosticEvent_Session' AND i.object_id = OBJECT_ID(N'dbo.Diagnostic_Event')
          AND (i.is_unique <> 0 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'CreatedAt')))
BEGIN
    PRINT ' [REBUILD] Diagnostic_Event.IX_DiagnosticEvent_Session exists with the wrong shape - recreating it on (SessionID, CreatedAt).';
    DROP INDEX [IX_DiagnosticEvent_Session] ON [dbo].[Diagnostic_Event];
END;
/* "Why did session X fail" is THE query the diagnostics table exists to answer,
   and it is asked by a support engineer while someone waits. Without this index
   it scans every row ever recorded. CreatedAt is the second key because the
   answer is always read newest-first, so the ordering comes from the index
   rather than from a sort over the matched rows. Filtered, because a failure
   that happened before any session was resolved has none. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_DiagnosticEvent_Session' AND object_id = OBJECT_ID('dbo.Diagnostic_Event'))
    CREATE NONCLUSTERED INDEX [IX_DiagnosticEvent_Session] ON [dbo].[Diagnostic_Event] ([SessionID], [CreatedAt] DESC)
        WHERE [SessionID] IS NOT NULL;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Diagnostic_Event.IX_DiagnosticEvent_Session on (SessionID, CreatedAt).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_DiagnosticEvent_Session could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_DiagnosticEvent_Created' AND i.object_id = OBJECT_ID(N'dbo.Diagnostic_Event')
          AND (i.is_unique <> 0 OR i.has_filter <> 0
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 1
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'CreatedAt')))
BEGIN
    PRINT ' [REBUILD] Diagnostic_Event.IX_DiagnosticEvent_Created exists with the wrong shape - recreating it on (CreatedAt).';
    DROP INDEX [IX_DiagnosticEvent_Created] ON [dbo].[Diagnostic_Event];
END;
/* Two readers, not one: "what has been failing lately" with no session filter,
   AND the retention purge, which deletes by age. The purge is why this is not
   optional - without it the scheduled DELETE scans the whole table to find the
   old rows, on a table whose entire purpose is to keep growing. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_DiagnosticEvent_Created' AND object_id = OBJECT_ID('dbo.Diagnostic_Event'))
    CREATE NONCLUSTERED INDEX [IX_DiagnosticEvent_Created] ON [dbo].[Diagnostic_Event] ([CreatedAt] DESC);
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Diagnostic_Event.IX_DiagnosticEvent_Created on (CreatedAt).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_DiagnosticEvent_Created could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'CIX_DiagnosticEvent_Created' AND i.object_id = OBJECT_ID(N'dbo.Diagnostic_Event')
          AND (i.is_unique <> 0 OR i.has_filter <> 0
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'CreatedAt')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'DiagnosticID')))
BEGIN
    PRINT ' [REBUILD] Diagnostic_Event.CIX_DiagnosticEvent_Created exists with the wrong shape - recreating it on (CreatedAt, DiagnosticID).';
    DROP INDEX [CIX_DiagnosticEvent_Created] ON [dbo].[Diagnostic_Event];
END;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'CIX_DiagnosticEvent_Created' AND object_id = OBJECT_ID('dbo.Diagnostic_Event'))
   AND NOT EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = OBJECT_ID('dbo.Diagnostic_Event') AND type_desc = 'CLUSTERED')
    CREATE CLUSTERED INDEX [CIX_DiagnosticEvent_Created] ON [dbo].[Diagnostic_Event] ([CreatedAt], [DiagnosticID])
        WITH (DATA_COMPRESSION = PAGE);
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Diagnostic_Event.CIX_DiagnosticEvent_Created on (CreatedAt, DiagnosticID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index CIX_DiagnosticEvent_Created could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 49 of 51   03_indexes/019_Application_Log_indexes.sql
============================================================================*/
PRINT '';
PRINT '>>> [49/51] 03_indexes/019_Application_Log_indexes.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  INDEXES: Application_Log

  Script:      019_Application_Log_indexes.sql
  Order:       03_indexes / 019
  Purpose:     3 index(es) on Application_Log.
  Depends on:  01_tables/ *_Application_Log.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    indexes on dbo.Application_Log

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '--- indexes: Application_Log ---';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_ApplicationLog_Created' AND i.object_id = OBJECT_ID(N'dbo.Application_Log')
          AND (i.is_unique <> 0 OR i.has_filter <> 0
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 1
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'CreatedAt')))
BEGIN
    PRINT ' [REBUILD] Application_Log.IX_ApplicationLog_Created exists with the wrong shape - recreating it on (CreatedAt).';
    DROP INDEX [IX_ApplicationLog_Created] ON [dbo].[Application_Log];
END;
/* The same pair on the log stream, where they matter MORE rather than less:
   this table takes every line at INFO and above - hundreds per run, six figures
   on a busy day - so an unindexed read or purge here is not a slow query, it is
   an outage. CreatedAt leads because every read is time-bounded first. */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ApplicationLog_Created' AND object_id = OBJECT_ID('dbo.Application_Log'))
    CREATE NONCLUSTERED INDEX [IX_ApplicationLog_Created] ON [dbo].[Application_Log] ([CreatedAt] DESC);
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Application_Log.IX_ApplicationLog_Created on (CreatedAt).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_ApplicationLog_Created could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'IX_ApplicationLog_Session' AND i.object_id = OBJECT_ID(N'dbo.Application_Log')
          AND (i.is_unique <> 0 OR i.has_filter <> 1
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'SessionID')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'CreatedAt')))
BEGIN
    PRINT ' [REBUILD] Application_Log.IX_ApplicationLog_Session exists with the wrong shape - recreating it on (SessionID, CreatedAt).';
    DROP INDEX [IX_ApplicationLog_Session] ON [dbo].[Application_Log];
END;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ApplicationLog_Session' AND object_id = OBJECT_ID('dbo.Application_Log'))
    CREATE NONCLUSTERED INDEX [IX_ApplicationLog_Session] ON [dbo].[Application_Log] ([SessionID], [CreatedAt] DESC)
        WHERE [SessionID] IS NOT NULL;
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Application_Log.IX_ApplicationLog_Session on (SessionID, CreatedAt).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index IX_ApplicationLog_Session could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

BEGIN TRY
BEGIN TRANSACTION;
IF EXISTS (SELECT 1 FROM sys.indexes i
        WHERE i.name = N'CIX_ApplicationLog_Created' AND i.object_id = OBJECT_ID(N'dbo.Application_Log')
          AND (i.is_unique <> 0 OR i.has_filter <> 0
          OR (SELECT COUNT(*) FROM sys.index_columns ic WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND ic.key_ordinal > 0) <> 2
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 1 AND c.name = N'CreatedAt')
          OR NOT EXISTS (SELECT 1 FROM sys.index_columns ic, sys.columns c WHERE i.object_id = ic.object_id AND i.index_id = ic.index_id AND c.object_id = ic.object_id AND c.column_id = ic.column_id AND ic.key_ordinal = 2 AND c.name = N'LogID')))
BEGIN
    PRINT ' [REBUILD] Application_Log.CIX_ApplicationLog_Created exists with the wrong shape - recreating it on (CreatedAt, LogID).';
    DROP INDEX [CIX_ApplicationLog_Created] ON [dbo].[Application_Log];
END;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'CIX_ApplicationLog_Created' AND object_id = OBJECT_ID('dbo.Application_Log'))
   AND NOT EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = OBJECT_ID('dbo.Application_Log') AND type_desc = 'CLUSTERED')
    CREATE CLUSTERED INDEX [CIX_ApplicationLog_Created] ON [dbo].[Application_Log] ([CreatedAt], [LogID])
        WITH (DATA_COMPRESSION = PAGE);
COMMIT;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    PRINT ' [ERROR]   Could not create or rebuild Application_Log.CIX_ApplicationLog_Created on (CreatedAt, LogID).';
    PRINT '          Database error ' + CAST(ERROR_NUMBER() AS varchar(20)) + ': ' + ERROR_MESSAGE();
    PRINT '          Nothing was changed - an existing index was kept. For a UNIQUE index this';
    PRINT '          usually means duplicate values in those columns: remove them, then re-run.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('Index CIX_ApplicationLog_Created could not be created - deployment stopped.', 16, 1);
END CATCH;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 50 of 51   99_validation/001_post_deployment_validation.sql
============================================================================*/
PRINT '';
PRINT '>>> [50/51] 99_validation/001_post_deployment_validation.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  POST-DEPLOYMENT VALIDATION  (READ ONLY)

  Script:      001_post_deployment_validation.sql
  Order:       99_validation / 001   (run LAST)
  Purpose:     Prove the database now matches what the application needs.
  Depends on:  Every script in 01_tables, 02_constraints and 03_indexes.
  Re-runnable: YES - it reads catalog views only.
  Modifies:    NOTHING.

  This is the sign-off. If the last line says PASS, the application can start.
  If it says FAILED, the rows above name exactly what is missing.

  WHAT IT CANNOT TELL YOU: whether the threat and control LIBRARIES hold data.
  An empty library is a working schema that returns empty results forever, so
  check the seed scripts separately (see the README, step 8).
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '==============================================================';
PRINT ' TSG POST-DEPLOYMENT VALIDATION';
PRINT ' Database: ' + DB_NAME();
PRINT ' Run at:   ' + CONVERT(varchar(19), SYSUTCDATETIME(), 120) + ' UTC';
PRINT '==============================================================';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

DECLARE @fail_tables      int = 0,
        @fail_pk          int = 0,
        @fail_indexes     int = 0,
        @fail_constraints int = 0,
        @fail_rcsi        int = 0;

DECLARE @owned TABLE (name sysname);
INSERT INTO @owned (name) VALUES
    ('Threat_Category'), ('Threat_Type'), ('Threat_Catalogue'), ('Threat_Actor'),
    ('Threat_Catalogue_Category_Map'), ('ThreatType_ThreatActor_Map'),
    ('Control_Standard'), ('Control_Library'), ('Control_Library_Standard_Map'),
    ('API_Client'), ('Config_Tuning'), ('Grounding_Calibration_Run'),
    ('Scenario_Session'), ('Subsystem_Stage_State'), ('Identified_Threat'),
    ('Identified_Duplicate_Threat'), ('Scoped_Threat'), ('Threat_Scenario'),
    ('Threat_Scenario_Control_Map'), ('Risk_Treatment_Plan'),
    ('Scenario_Audit'), ('Prompt_Log');

/* 15, not 14. app/db/invariants.py::verify_startup runs REQUIRED_INDEXES (14 names) AND
   FILTERED_INDEX_LITERALS, whose second entry IX_Session_Active appears in neither the
   REQUIRED_INDEXES list nor, previously, this one. Checking only REQUIRED_INDEXES signed off
   "Overall: PASS" on a database the API would then refuse to boot against - the precise failure
   this script exists to prevent. */
DECLARE @req TABLE (ix sysname, tbl sysname);
INSERT INTO @req (ix, tbl) VALUES
    ('UX_Session_ActiveAsset','Scenario_Session'),
    ('IX_Session_Active','Scenario_Session'),
    ('UX_Session_IdempotencyKey','Scenario_Session'),
    ('UX_Scenario_ActiveIdentity','Threat_Scenario'),
    ('UX_Scenario_ActiveScoped','Threat_Scenario'),
    ('UX_Scenario_ActiveAccepted','Threat_Scenario'),
    ('UX_ThreatType_NaturalKey','Threat_Type'),
    ('UX_ThreatCatalogue_NaturalKey','Threat_Catalogue'),
    ('UX_ThreatActor_NaturalKey','Threat_Actor'),
    ('UX_ThreatCategory_NaturalKey','Threat_Category'),
    ('UX_SubsystemStageState_SessionSubLevel','Subsystem_Stage_State'),
    ('UX_TreatmentPlan_ActiveScenario','Risk_Treatment_Plan'),
    ('UX_GroundingCalibration_Running','Grounding_Calibration_Run'),
    ('UX_Control_Standard_Name','Control_Standard'),
    ('UX_Control_Library_Code','Control_Library');

DECLARE @checks TABLE (name sysname);
INSERT INTO @checks (name) VALUES
    ('CK_Config_Tuning_ValueType'), ('CK_Session_Status'), ('CK_Scenario_DecisionExclusive');

/*-------------------------- tables --------------------------*/
SELECT @fail_tables = COUNT(*)
FROM   @owned o WHERE OBJECT_ID('dbo.' + QUOTENAME(o.name), 'U') IS NULL;

IF @fail_tables > 0
    SELECT '[FAIL] missing table: ' + o.name AS Problem
    FROM   @owned o WHERE OBJECT_ID('dbo.' + QUOTENAME(o.name), 'U') IS NULL;

/*-------------------------- primary keys --------------------------*/
SELECT @fail_pk = COUNT(*)
FROM   @owned o
WHERE  OBJECT_ID('dbo.' + QUOTENAME(o.name), 'U') IS NOT NULL
  AND  NOT EXISTS (SELECT 1 FROM sys.key_constraints k
                   WHERE k.parent_object_id = OBJECT_ID('dbo.' + QUOTENAME(o.name))
                     AND k.type = 'PK');

IF @fail_pk > 0
    SELECT '[FAIL] no primary key on: ' + o.name AS Problem
    FROM   @owned o
    WHERE  OBJECT_ID('dbo.' + QUOTENAME(o.name), 'U') IS NOT NULL
      AND  NOT EXISTS (SELECT 1 FROM sys.key_constraints k
                       WHERE k.parent_object_id = OBJECT_ID('dbo.' + QUOTENAME(o.name))
                         AND k.type = 'PK');

/*-------------------------- boot-critical indexes --------------------------
  `is_disabled = 0` is part of the match, not an afterthought. A DISABLED index still has its
  row in sys.indexes, so matching on name + table alone reported [PASS] for an index SQL Server
  will not use and that enforces nothing - and every one of these is a UNIQUE constraint the
  application leans on for a race it cannot otherwise win (one active session per asset, one
  accepted version per scenario, one running calibration). Signing off on a disabled uniqueness
  guard is worse than reporting it missing, because nothing else will ever mention it again.

  WHAT THIS STILL DOES NOT CHECK, stated rather than implied: the index's COLUMN LIST and its
  filter predicate. An index carrying the right name over the wrong columns passes here. Column
  and filter verification would need the expected definitions generated from the DDL; until that
  exists, do not read a PASS on this line as "the indexes are correct", only as "they are present
  and enabled".
--------------------------------------------------------------------*/
SELECT @fail_indexes = COUNT(*)
FROM   @req r
WHERE  NOT EXISTS (SELECT 1 FROM sys.indexes i
                   WHERE i.name = r.ix
                     AND i.object_id = OBJECT_ID('dbo.' + QUOTENAME(r.tbl))
                     AND i.is_disabled = 0);

IF @fail_indexes > 0
    SELECT '[FAIL] ' +
           CASE WHEN EXISTS (SELECT 1 FROM sys.indexes i
                             WHERE i.name = r.ix
                               AND i.object_id = OBJECT_ID('dbo.' + QUOTENAME(r.tbl)))
                THEN 'DISABLED index: ' ELSE 'missing index: ' END
           + r.ix + ' on ' + r.tbl +
           '  -> the API and workers will NOT start' AS Problem
    FROM   @req r
    WHERE  NOT EXISTS (SELECT 1 FROM sys.indexes i
                       WHERE i.name = r.ix
                         AND i.object_id = OBJECT_ID('dbo.' + QUOTENAME(r.tbl))
                         AND i.is_disabled = 0);

/*-------------------------- check constraints --------------------------*/
SELECT @fail_constraints = COUNT(*)
FROM   @checks c
WHERE  NOT EXISTS (SELECT 1 FROM sys.check_constraints k WHERE k.name = c.name);

IF @fail_constraints > 0
    SELECT '[FAIL] missing check constraint: ' + c.name AS Problem
    FROM   @checks c
    WHERE  NOT EXISTS (SELECT 1 FROM sys.check_constraints k WHERE k.name = c.name);

/*-------------------------- isolation level --------------------------
  FAIL-OPEN BUG THIS REPLACES, because it is the exact failure a sign-off script
  must not have: DATABASEPROPERTYEX returned NULL on a SQL Server 2022 Express
  instance, and `NULL <> 1` is UNKNOWN - so the SET never ran, @fail_rcsi stayed
  0, and this script printed "Isolation: PASS" and "Overall: PASS" having checked
  nothing at all. A verdict that cannot tell ON from unreadable is not a verdict.

  sys.databases.is_read_committed_snapshot_on is a non-nullable bit for every
  database. NULL here means the row was not visible, which is a FAILURE, not a
  pass - this script's whole job is to say whether the application may start.
--------------------------------------------------------------------*/
DECLARE @rcsi bit = (SELECT d.is_read_committed_snapshot_on
                     FROM sys.databases d WHERE d.database_id = DB_ID());
IF @rcsi IS NULL OR @rcsi = 0
    SET @fail_rcsi = 1;

/*-------------------------- counts, for the record --------------------------*/
PRINT '';
PRINT '--- counted in this database ---';
DECLARE @t int = (SELECT COUNT(*) FROM @owned o
                  WHERE OBJECT_ID('dbo.' + QUOTENAME(o.name), 'U') IS NOT NULL);
DECLARE @i int = (SELECT COUNT(*) FROM sys.indexes i
                  JOIN sys.tables tb ON tb.object_id = i.object_id
                  WHERE tb.name IN (SELECT name FROM @owned)
                    AND i.name IS NOT NULL AND i.is_primary_key = 0);
DECLARE @d int = (SELECT COUNT(*) FROM sys.default_constraints dc
                  JOIN sys.tables tb ON tb.object_id = dc.parent_object_id
                  WHERE tb.name IN (SELECT name FROM @owned));
PRINT ' [INFO]    Tables:              ' + CAST(@t AS varchar(10)) + ' of 22';
PRINT ' [INFO]    Non-PK indexes:      ' + CAST(@i AS varchar(10)) +
      '  (39 expected: 38 from 03_indexes + UQ_Config_Tuning_Key)';
PRINT ' [INFO]    Default constraints: ' + CAST(@d AS varchar(10)) + '  (22 expected)';

/*-------------------------- the verdict --------------------------*/
PRINT '';
PRINT 'DATABASE VALIDATION RESULT';
PRINT '--------------------------';
PRINT 'Tables:        ' + CASE WHEN @fail_tables      = 0 THEN 'PASS' ELSE 'FAILED' END;
PRINT '  (columns are NOT checked here - see 002_schema_verdict.sql)';
PRINT 'Primary keys:  ' + CASE WHEN @fail_pk          = 0 THEN 'PASS' ELSE 'FAILED' END;
PRINT 'Indexes:       ' + CASE WHEN @fail_indexes     = 0 THEN 'PASS' ELSE 'FAILED' END;
PRINT 'Constraints:   ' + CASE WHEN @fail_constraints = 0 THEN 'PASS' ELSE 'FAILED' END;
PRINT 'Isolation:     ' + CASE WHEN @fail_rcsi        = 0 THEN 'PASS' ELSE 'FAILED' END;
PRINT '';

IF (@fail_tables + @fail_pk + @fail_indexes + @fail_constraints + @fail_rcsi) = 0
BEGIN
    PRINT 'Objects: PASS';
    PRINT '';
    PRINT 'NOT YET A SIGN-OFF. The five verdicts above cover OBJECTS only - tables, primary';
    PRINT 'keys, indexes, check constraints, isolation. Not one of them reads a COLUMN, so a';
    PRINT 'deployment that printed [BLOCKED] on a narrowing change, or added a NOT NULL column';
    PRINT 'as NULL because the table had rows, reaches this line looking clean.';
    PRINT '';
    PRINT 'Run 99_validation/002_schema_verdict.sql now. It checks all 318 columns, all 32';
    PRINT 'index shapes, 21 defaults, 6 identity columns and the collation, then prints the';
    PRINT 'FINAL SIGN-OFF. Then confirm the threat and control libraries hold data';
    PRINT '(README step 11) before starting the application.';
END
ELSE
BEGIN
    PRINT 'Objects: FAILED';
    PRINT '';
    PRINT 'Fix the rows listed above and re-run the matching script. Every script in';
    PRINT 'this package is safe to run again.';
    IF @fail_rcsi = 1
    BEGIN
        PRINT '';
        PRINT 'ISOLATION prints no row to fix, so here is its one: run';
        PRINT '00_validation/002_enable_isolation_level.sql. It turns the setting on without';
        PRINT 'waiting for, or disconnecting, anybody, and reports who is holding it if it';
        PRINT 'cannot. The application does not start until this says PASS.';
    END;
END;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*============================================================================
  >>> 51 of 51   99_validation/002_schema_verdict.sql
============================================================================*/
PRINT '';
PRINT '>>> [51/51] 99_validation/002_schema_verdict.sql';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

/*==============================================================================
  SCHEMA VERDICT  (READ ONLY)

  Script:      002_schema_verdict.sql
  Order:       99_validation / 002   (run LAST, after 001)
  Purpose:     Verify all 318 columns and all 39 indexes, down to index key columns and filters.
  Depends on:  99_validation/001_post_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    NOTHING. Catalog views only.

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

PRINT '';
PRINT '==============================================================';
PRINT ' TSG COLUMN VERDICT   (318 columns across 24 tables)';
PRINT ' Database: ' + DB_NAME();
PRINT '==============================================================';
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

DECLARE @expected TABLE (
    tbl sysname, col sysname, base_type sysname, full_type nvarchar(100), is_nullable bit);
INSERT INTO @expected (tbl, col, base_type, full_type, is_nullable) VALUES
    (N'Threat_Category', N'ThreatCategoryID', N'int', N'INT', 0),
    (N'Threat_Category', N'ThreatCategoryName', N'nvarchar', N'NVARCHAR(200)', 0),
    (N'Threat_Category', N'IsActive', N'bit', N'BIT', 0),
    (N'Threat_Category', N'IsDeleted', N'bit', N'BIT', 0),
    (N'Threat_Category', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Category', N'CreatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Threat_Category', N'UpdatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Category', N'UpdatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Threat_Type', N'ThreatTypeID', N'int', N'INT', 0),
    (N'Threat_Type', N'ThreatTypeName', N'nvarchar', N'NVARCHAR(300)', 0),
    (N'Threat_Type', N'ThreatCategoryID', N'int', N'INT', 1),
    (N'Threat_Type', N'IsActive', N'bit', N'BIT', 0),
    (N'Threat_Type', N'IsDeleted', N'bit', N'BIT', 0),
    (N'Threat_Type', N'Source', N'nvarchar', N'NVARCHAR(50)', 1),
    (N'Threat_Type', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Type', N'CreatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Threat_Type', N'UpdatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Type', N'UpdatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Threat_Catalogue', N'ThreatCatalogueID', N'int', N'INT', 0),
    (N'Threat_Catalogue', N'ThreatTypeID', N'int', N'INT', 0),
    (N'Threat_Catalogue', N'ThreatName', N'nvarchar', N'NVARCHAR(500)', 0),
    (N'Threat_Catalogue', N'IsActive', N'bit', N'BIT', 0),
    (N'Threat_Catalogue', N'IsDeleted', N'bit', N'BIT', 0),
    (N'Threat_Catalogue', N'Source', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Threat_Catalogue', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Catalogue', N'CreatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Threat_Catalogue', N'UpdatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Catalogue', N'UpdatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Threat_Actor', N'ThreatActorID', N'int', N'INT', 0),
    (N'Threat_Actor', N'ThreatActorName', N'nvarchar', N'NVARCHAR(200)', 0),
    (N'Threat_Actor', N'IsCapable', N'int', N'INT', 0),
    (N'Threat_Actor', N'IsActive', N'bit', N'BIT', 0),
    (N'Threat_Actor', N'IsDeleted', N'bit', N'BIT', 0),
    (N'Threat_Actor', N'Source', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Threat_Actor', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Actor', N'CreatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Threat_Actor', N'UpdatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Actor', N'UpdatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Threat_Catalogue_Category_Map', N'ThreatCategoryID', N'int', N'INT', 0),
    (N'Threat_Catalogue_Category_Map', N'ThreatCatalogueID', N'int', N'INT', 0),
    (N'Threat_Catalogue_Category_Map', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'ThreatType_ThreatActor_Map', N'ThreatTypeID', N'int', N'INT', 0),
    (N'ThreatType_ThreatActor_Map', N'ThreatActorID', N'int', N'INT', 0),
    (N'ThreatType_ThreatActor_Map', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Control_Standard', N'StandardID', N'int', N'INT', 0),
    (N'Control_Standard', N'StandardName', N'nvarchar', N'NVARCHAR(200)', 0),
    (N'Control_Standard', N'Source', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Control_Standard', N'CreatedAt', N'datetime', N'DATETIME', 1),
    (N'Control_Standard', N'CreatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Control_Standard', N'UpdatedAt', N'datetime', N'DATETIME', 1),
    (N'Control_Standard', N'UpdatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Control_Standard', N'IsActive', N'bit', N'BIT', 0),
    (N'Control_Standard', N'IsDeleted', N'bit', N'BIT', 0),
    (N'Control_Library', N'ControlLibraryID', N'int', N'INT', 0),
    (N'Control_Library', N'ControlCode', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Control_Library', N'ITOT', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Control_Library', N'Domain', N'nvarchar', N'NVARCHAR(200)', 0),
    (N'Control_Library', N'ControlName', N'nvarchar', N'NVARCHAR(500)', 0),
    (N'Control_Library', N'ControlDescription', N'nvarchar', N'NVARCHAR(max)', 0),
    (N'Control_Library', N'SampleEvidence', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Control_Library', N'Source', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Control_Library', N'CreatedAt', N'datetime', N'DATETIME', 1),
    (N'Control_Library', N'CreatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Control_Library', N'UpdatedAt', N'datetime', N'DATETIME', 1),
    (N'Control_Library', N'UpdatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Control_Library', N'IsActive', N'bit', N'BIT', 0),
    (N'Control_Library', N'IsDeleted', N'bit', N'BIT', 0),
    (N'Control_Library_Standard_Map', N'ControlLibraryID', N'int', N'INT', 0),
    (N'Control_Library_Standard_Map', N'StandardID', N'int', N'INT', 0),
    (N'Control_Library_Standard_Map', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'API_Client', N'ClientID', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'API_Client', N'KeyHash', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'API_Client', N'Name', N'nvarchar', N'NVARCHAR(200)', 0),
    (N'API_Client', N'Module', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'API_Client', N'Active', N'bit', N'BIT', 0),
    (N'API_Client', N'CreatedAt', N'datetime2', N'DATETIME2(3)', 0),
    (N'API_Client', N'CreatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'API_Client', N'RevokedAt', N'datetime2', N'DATETIME2(3)', 1),
    (N'API_Client', N'RevokedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Config_Tuning', N'TuningID', N'int', N'INT', 0),
    (N'Config_Tuning', N'TuningKey', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Config_Tuning', N'TuningValue', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Config_Tuning', N'ValueType', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Config_Tuning', N'EmbeddingModel', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Config_Tuning', N'CreateDate', N'datetime2', N'DATETIME2(7)', 1),
    (N'Config_Tuning', N'CreatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Config_Tuning', N'UpdateDate', N'datetime2', N'DATETIME2(7)', 1),
    (N'Config_Tuning', N'UpdatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Config_Tuning', N'IsActive', N'bit', N'BIT', 0),
    (N'Config_Tuning', N'IsDeleted', N'bit', N'BIT', 0),
    (N'Grounding_Calibration_Run', N'RunID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Grounding_Calibration_Run', N'JobID', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Grounding_Calibration_Run', N'Status', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Grounding_Calibration_Run', N'StartedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Grounding_Calibration_Run', N'StartedByClient', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Grounding_Calibration_Run', N'StartedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Grounding_Calibration_Run', N'FinishedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Grounding_Calibration_Run', N'EmbeddingModel', N'nvarchar', N'NVARCHAR(500)', 1),
    (N'Grounding_Calibration_Run', N'RerankerModel', N'nvarchar', N'NVARCHAR(500)', 1),
    (N'Grounding_Calibration_Run', N'Forced', N'bit', N'BIT', 0),
    (N'Grounding_Calibration_Run', N'MatchTh', N'float', N'FLOAT', 1),
    (N'Grounding_Calibration_Run', N'ControlMapTh', N'float', N'FLOAT', 1),
    (N'Grounding_Calibration_Run', N'Quality', N'float', N'FLOAT', 1),
    (N'Grounding_Calibration_Run', N'NegativesCount', N'int', N'INT', 1),
    (N'Grounding_Calibration_Run', N'PositivesCount', N'int', N'INT', 1),
    (N'Grounding_Calibration_Run', N'HighestNegative', N'float', N'FLOAT', 1),
    (N'Grounding_Calibration_Run', N'LowestPositive', N'float', N'FLOAT', 1),
    (N'Grounding_Calibration_Run', N'NearDuplicatesJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Grounding_Calibration_Run', N'ErrorMessage', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Scenario_Session', N'SessionID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Scenario_Session', N'TenantID', N'nvarchar', N'NVARCHAR(200)', 0),
    (N'Scenario_Session', N'EntityID', N'nvarchar', N'NVARCHAR(200)', 0),
    (N'Scenario_Session', N'UserID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Scenario_Session', N'AssetName', N'nvarchar', N'NVARCHAR(300)', 0),
    (N'Scenario_Session', N'AssetID', N'nvarchar', N'NVARCHAR(200)', 0),
    (N'Scenario_Session', N'SessionStatus', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Scenario_Session', N'CurrentStage', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Scenario_Session', N'StageStatus', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Scenario_Session', N'Mode', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Scenario_Session', N'CurrentSubsystemIndex', N'int', N'INT', 1),
    (N'Scenario_Session', N'SubsystemsJSON', N'nvarchar', N'NVARCHAR(max)', 0),
    (N'Scenario_Session', N'IdempotencyKey', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Scenario_Session', N'SectorIDsJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Scenario_Session', N'AssetContextJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Scenario_Session', N'ScoringRulesSnapshotJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Scenario_Session', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Scenario_Session', N'UpdatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Scenario_Session', N'CompletedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Scenario_Session', N'CancelledAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Scenario_Session', N'CancelledBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Scenario_Session', N'ControlMapSeconds', N'float', N'FLOAT', 1),
    (N'Subsystem_Stage_State', N'StateID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Subsystem_Stage_State', N'SessionID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Subsystem_Stage_State', N'TenantID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Subsystem_Stage_State', N'EntityID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Subsystem_Stage_State', N'SubsystemID', N'int', N'INT', 0),
    (N'Subsystem_Stage_State', N'Level', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Subsystem_Stage_State', N'Status', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Subsystem_Stage_State', N'GenerationEpoch', N'int', N'INT', 0),
    (N'Subsystem_Stage_State', N'ActiveTaskID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 1),
    (N'Subsystem_Stage_State', N'LeaseExpiresAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Subsystem_Stage_State', N'HeartbeatAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Subsystem_Stage_State', N'AttemptCount', N'int', N'INT', 0),
    (N'Subsystem_Stage_State', N'ErrorMessage', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Subsystem_Stage_State', N'UpdatedAt', N'datetime2', N'DATETIME2(7)', 0),
    (N'Subsystem_Stage_State', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Subsystem_Stage_State', N'StartedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Subsystem_Stage_State', N'FinishedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Identified_Threat', N'ThreatID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Identified_Threat', N'SessionID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Identified_Threat', N'TenantID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Identified_Threat', N'EntityID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Identified_Threat', N'UserID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Identified_Threat', N'SubsystemID', N'int', N'INT', 0),
    (N'Identified_Threat', N'ThreatCategory', N'nvarchar', N'NVARCHAR(200)', 0),
    (N'Identified_Threat', N'ThreatType', N'nvarchar', N'NVARCHAR(300)', 0),
    (N'Identified_Threat', N'ThreatName', N'nvarchar', N'NVARCHAR(500)', 1),
    (N'Identified_Threat', N'GenericName', N'nvarchar', N'NVARCHAR(500)', 1),
    (N'Identified_Threat', N'ThreatCategoryID', N'int', N'INT', 1),
    (N'Identified_Threat', N'ThreatActorsJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Identified_Threat', N'LibraryThreatType', N'nvarchar', N'NVARCHAR(300)', 1),
    (N'Identified_Threat', N'LibraryThreatName', N'nvarchar', N'NVARCHAR(500)', 1),
    (N'Identified_Threat', N'ThreatTypeID', N'int', N'INT', 1),
    (N'Identified_Threat', N'ThreatCatalogueID', N'int', N'INT', 1),
    (N'Identified_Threat', N'IsThreatAIGenerated', N'bit', N'BIT', 0),
    (N'Identified_Threat', N'IsThreatTypeAIGenerated', N'bit', N'BIT', 0),
    (N'Identified_Threat', N'GroundingStatus', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Identified_Threat', N'GroundingScore', N'float', N'FLOAT', 1),
    (N'Identified_Threat', N'GroundingThresholdOrigin', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Identified_Threat', N'Superseded', N'int', N'INT', 0),
    (N'Identified_Threat', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Identified_Duplicate_Threat', N'DuplicateThreatID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Identified_Duplicate_Threat', N'SessionID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Identified_Duplicate_Threat', N'TenantID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Identified_Duplicate_Threat', N'EntityID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Identified_Duplicate_Threat', N'UserID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Identified_Duplicate_Threat', N'SubsystemID', N'int', N'INT', 0),
    (N'Identified_Duplicate_Threat', N'ThreatCategory', N'nvarchar', N'NVARCHAR(200)', 0),
    (N'Identified_Duplicate_Threat', N'ThreatType', N'nvarchar', N'NVARCHAR(300)', 0),
    (N'Identified_Duplicate_Threat', N'ThreatName', N'nvarchar', N'NVARCHAR(500)', 1),
    (N'Identified_Duplicate_Threat', N'GenericName', N'nvarchar', N'NVARCHAR(500)', 1),
    (N'Identified_Duplicate_Threat', N'ThreatActorsJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Identified_Duplicate_Threat', N'DuplicateOfThreatID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 1),
    (N'Identified_Duplicate_Threat', N'DuplicateReason', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Identified_Duplicate_Threat', N'SimilarityScore', N'float', N'FLOAT', 1),
    (N'Identified_Duplicate_Threat', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Scoped_Threat', N'ScopedThreatID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Scoped_Threat', N'SessionID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Scoped_Threat', N'TenantID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Scoped_Threat', N'EntityID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Scoped_Threat', N'UserID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Scoped_Threat', N'SubsystemID', N'int', N'INT', 0),
    (N'Scoped_Threat', N'ThreatID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Scoped_Threat', N'Score', N'float', N'FLOAT', 0),
    (N'Scoped_Threat', N'ScopeRank', N'int', N'INT', 0),
    (N'Scoped_Threat', N'Selected', N'int', N'INT', 0),
    (N'Scoped_Threat', N'Reason', N'nvarchar', N'NVARCHAR(500)', 1),
    (N'Scoped_Threat', N'RejectionKind', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Scoped_Threat', N'SelectionKind', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Scoped_Threat', N'FactorsJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Scoped_Threat', N'Superseded', N'int', N'INT', 0),
    (N'Scoped_Threat', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Scenario', N'ScenarioID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Threat_Scenario', N'SessionID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Threat_Scenario', N'TenantID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Threat_Scenario', N'EntityID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Threat_Scenario', N'UserID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Threat_Scenario', N'SubsystemID', N'int', N'INT', 0),
    (N'Threat_Scenario', N'ScopedThreatID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Threat_Scenario', N'Status', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Threat_Scenario', N'ScenarioJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Threat_Scenario', N'ValidationJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Threat_Scenario', N'AcceptedSubsetJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Threat_Scenario', N'Accepted', N'int', N'INT', 0),
    (N'Threat_Scenario', N'Superseded', N'int', N'INT', 0),
    (N'Threat_Scenario', N'IdentityHash', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Threat_Scenario', N'ScenarioNumber', N'int', N'INT', 0),
    (N'Threat_Scenario', N'ReplacesScenarioID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 1),
    (N'Threat_Scenario', N'GenerationEpoch', N'int', N'INT', 0),
    (N'Threat_Scenario', N'ErrorMessage', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Threat_Scenario', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Scenario', N'ControlsMappedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Scenario', N'ControlMapAttempts', N'int', N'INT', 0),
    (N'Threat_Scenario', N'GenStartedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Scenario', N'GenFinishedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Scenario', N'ScenarioSource', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Threat_Scenario', N'RejectedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Scenario', N'RejectedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Threat_Scenario', N'AcceptedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Scenario', N'AcceptedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Threat_Scenario_Control_Map', N'ScenarioID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Threat_Scenario_Control_Map', N'ControlLibraryID', N'int', N'INT', 0),
    (N'Threat_Scenario_Control_Map', N'SessionID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Threat_Scenario_Control_Map', N'MapRank', N'int', N'INT', 0),
    (N'Threat_Scenario_Control_Map', N'Score', N'float', N'FLOAT', 1),
    (N'Threat_Scenario_Control_Map', N'SuggestedControl', N'nvarchar', N'NVARCHAR(500)', 1),
    (N'Threat_Scenario_Control_Map', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Risk_Treatment_Plan', N'PlanID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Risk_Treatment_Plan', N'SessionID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Risk_Treatment_Plan', N'ScenarioID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Risk_Treatment_Plan', N'TenantID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Risk_Treatment_Plan', N'EntityID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Risk_Treatment_Plan', N'UserID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Risk_Treatment_Plan', N'CrmRiskIdentificationID', N'int', N'INT', 1),
    (N'Risk_Treatment_Plan', N'TreatmentStrategy', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Risk_Treatment_Plan', N'Status', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Risk_Treatment_Plan', N'ActiveTaskID', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Risk_Treatment_Plan', N'RiskIdentificationDate', N'datetime2', N'DATETIME2(7)', 1),
    (N'Risk_Treatment_Plan', N'InputSnapshotJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Risk_Treatment_Plan', N'PlanJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Risk_Treatment_Plan', N'ValidationJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Risk_Treatment_Plan', N'ErrorMessage', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Risk_Treatment_Plan', N'Superseded', N'int', N'INT', 0),
    (N'Risk_Treatment_Plan', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Risk_Treatment_Plan', N'UpdatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Risk_Treatment_Plan', N'CompletedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Risk_Treatment_Plan', N'RiskLevel', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Risk_Treatment_Plan', N'ReviewStatus', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Risk_Treatment_Plan', N'ReviewComment', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Risk_Treatment_Plan', N'ReviewedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Risk_Treatment_Plan', N'ReviewedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Risk_Treatment_Plan', N'CancelledAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Risk_Treatment_Plan', N'CancelledBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Risk_Treatment_Plan', N'ErrorReason', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Scenario_Audit', N'AuditID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Scenario_Audit', N'SessionID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Scenario_Audit', N'TenantID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Scenario_Audit', N'EntityID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Scenario_Audit', N'Stage', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Scenario_Audit', N'SubsystemID', N'int', N'INT', 1),
    (N'Scenario_Audit', N'EventType', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Scenario_Audit', N'ScenarioID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 1),
    (N'Scenario_Audit', N'PlanID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 1),
    (N'Scenario_Audit', N'Decision', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Scenario_Audit', N'Granularity', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Scenario_Audit', N'ThreatTypeRefID', N'int', N'INT', 1),
    (N'Scenario_Audit', N'ActorUserID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Scenario_Audit', N'ActorType', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Scenario_Audit', N'DetailJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Scenario_Audit', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 0),
    (N'Prompt_Log', N'LogID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Prompt_Log', N'SessionID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Prompt_Log', N'TenantID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Prompt_Log', N'EntityID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Prompt_Log', N'UserID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Prompt_Log', N'SubsystemID', N'int', N'INT', 0),
    (N'Prompt_Log', N'Stage', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Prompt_Log', N'PromptVersion', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Prompt_Log', N'Prompt', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Prompt_Log', N'ResponseText', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Prompt_Log', N'Model', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Prompt_Log', N'ModelVersion', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Prompt_Log', N'ParseSucceeded', N'bit', N'BIT', 0),
    (N'Prompt_Log', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 0),
    (N'Prompt_Log', N'CorrelationID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 1),
    (N'Diagnostic_Event', N'DiagnosticID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Diagnostic_Event', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 0),
    (N'Diagnostic_Event', N'SessionID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 1),
    (N'Diagnostic_Event', N'TenantID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Diagnostic_Event', N'EntityID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Diagnostic_Event', N'SubsystemID', N'int', N'INT', 1),
    (N'Diagnostic_Event', N'TaskID', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Diagnostic_Event', N'RequestID', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Diagnostic_Event', N'Kind', N'nvarchar', N'NVARCHAR(50)', 0),
    (N'Diagnostic_Event', N'ExceptionClass', N'nvarchar', N'NVARCHAR(200)', 0),
    (N'Diagnostic_Event', N'ExceptionMessage', N'nvarchar', N'NVARCHAR(4000)', 1),
    (N'Diagnostic_Event', N'Traceback', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Diagnostic_Event', N'ClientMessage', N'nvarchar', N'NVARCHAR(1000)', 1),
    (N'Diagnostic_Event', N'ContextJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Application_Log', N'LogID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Application_Log', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 0),
    (N'Application_Log', N'Level', N'nvarchar', N'NVARCHAR(20)', 0),
    (N'Application_Log', N'Logger', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Application_Log', N'Event', N'nvarchar', N'NVARCHAR(500)', 1),
    (N'Application_Log', N'SessionID', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Application_Log', N'RequestID', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Application_Log', N'TaskID', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Application_Log', N'FieldsJSON', N'nvarchar', N'NVARCHAR(max)', 1);

DECLARE @missing int = 0, @wrong_type int = 0, @wrong_null int = 0;

/* A column the application reads that the database does not have. The app breaks on first use. */
SELECT @missing = COUNT(*)
FROM   @expected e
WHERE  OBJECT_ID('dbo.' + QUOTENAME(e.tbl), 'U') IS NOT NULL
  AND  NOT EXISTS (SELECT 1 FROM sys.columns c
                   WHERE c.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                     AND c.name = e.col);

IF @missing > 0
    SELECT '[FAIL] missing column: ' + e.tbl + '.' + e.col +
           '  (expected ' + e.full_type + ')' AS Problem
    FROM   @expected e
    WHERE  OBJECT_ID('dbo.' + QUOTENAME(e.tbl), 'U') IS NOT NULL
      AND  NOT EXISTS (SELECT 1 FROM sys.columns c
                       WHERE c.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                         AND c.name = e.col);

/* A different type FAMILY. Not a widening, not recoverable by re-running the deployment. */
SELECT @wrong_type = COUNT(*)
FROM   @expected e
JOIN   sys.columns c ON c.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl)) AND c.name = e.col
WHERE  TYPE_NAME(c.user_type_id) <> e.base_type;

IF @wrong_type > 0
    SELECT '[FAIL] wrong type: ' + e.tbl + '.' + e.col +
           '  is ' + TYPE_NAME(c.user_type_id) + ', expected ' + e.base_type AS Problem
    FROM   @expected e
    JOIN   sys.columns c ON c.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl)) AND c.name = e.col
    WHERE  TYPE_NAME(c.user_type_id) <> e.base_type;

/* NULLABILITY, and only the DANGEROUS direction fails.

   A column the application requires that the database lets be NULL is a real failure: it is
   exactly what the deployment DELIBERATELY creates when it adds a NOT NULL column to a table
   that already has rows, printing a [WARNING] and the ALTER to run after backfilling. That
   warning scrolls past; this does not.

   The OPPOSITE - database NOT NULL where the ORM says nullable - is reported but not failed.
   It is the safe direction (the database is stricter), it is what the reviewed script already
   declares for the library tables' CreatedAt columns, and those carry a DEFAULT so an insert
   that omits the value still succeeds. Failing it would refuse sign-off on the schema this
   package itself deploys. */
SELECT @wrong_null = COUNT(*)
FROM   @expected e
JOIN   sys.columns c ON c.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl)) AND c.name = e.col
WHERE  c.is_nullable = 1 AND e.is_nullable = 0;

IF @wrong_null > 0
    SELECT '[FAIL] nullability: ' + e.tbl + '.' + e.col +
           '  allows NULL but the application requires NOT NULL'
           + '  -> backfill, then: ALTER TABLE dbo.' + QUOTENAME(e.tbl)
           + ' ALTER COLUMN ' + QUOTENAME(e.col) + ' ' + e.full_type + ' NOT NULL;' AS Problem
    FROM   @expected e
    JOIN   sys.columns c ON c.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl)) AND c.name = e.col
    WHERE  c.is_nullable = 1 AND e.is_nullable = 0;

IF EXISTS (SELECT 1 FROM @expected e
           JOIN sys.columns c ON c.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                             AND c.name = e.col
           WHERE c.is_nullable = 0 AND e.is_nullable = 1)
    SELECT '[INFO] stricter than the application: ' + e.tbl + '.' + e.col +
           ' is NOT NULL where the model allows NULL (safe; inserts rely on its DEFAULT)'
           AS Note
    FROM   @expected e
    JOIN   sys.columns c ON c.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl)) AND c.name = e.col
    WHERE  c.is_nullable = 0 AND e.is_nullable = 1;

/*============================ INDEXES ============================
  001 matches indexes by NAME and TABLE only, so an index carrying the right name over the WRONG
  COLUMNS, or with its WHERE filter dropped, signs off clean. Every one of these is a uniqueness
  guard the application leans on for a race it cannot otherwise win - one active session per
  asset, one accepted version per scenario, one running calibration. A filtered unique index
  whose predicate went missing enforces something quite different from what the code assumes.

  Key columns are compared BY NAME AND ORDER (key_ordinal), which is what decides whether the
  index can serve the query and what the uniqueness actually spans. Included columns are not
  compared: they change only cost, never correctness.
==================================================================*/
DECLARE @ix TABLE (name sysname, tbl sysname, is_unique bit, is_filtered bit, cols nvarchar(900));
INSERT INTO @ix (name, tbl, is_unique, is_filtered, cols) VALUES
    (N'UX_Session_ActiveAsset', N'Scenario_Session', 1, 1, N'EntityID,AssetID'),
    (N'UX_Session_IdempotencyKey', N'Scenario_Session', 1, 1, N'EntityID,IdempotencyKey'),
    (N'UX_Scenario_ActiveIdentity', N'Threat_Scenario', 1, 1, N'SessionID,IdentityHash,ScenarioNumber'),
    (N'UX_Scenario_ActiveScoped', N'Threat_Scenario', 1, 1, N'SessionID,ScopedThreatID'),
    (N'UX_Scenario_ActiveAccepted', N'Threat_Scenario', 1, 1, N'SessionID,IdentityHash,ScenarioNumber'),
    (N'UX_SubsystemStageState_SessionSubLevel', N'Subsystem_Stage_State', 1, 0, N'SessionID,SubsystemID,Level'),
    (N'UX_TreatmentPlan_ActiveScenario', N'Risk_Treatment_Plan', 1, 1, N'ScenarioID'),
    (N'UX_GroundingCalibration_Running', N'Grounding_Calibration_Run', 1, 1, N'EmbeddingModel,RerankerModel'),
    (N'UX_ThreatType_NaturalKey', N'Threat_Type', 1, 1, N'ThreatTypeName'),
    (N'UX_ThreatCatalogue_NaturalKey', N'Threat_Catalogue', 1, 1, N'ThreatName'),
    (N'UX_ThreatActor_NaturalKey', N'Threat_Actor', 1, 1, N'ThreatActorName'),
    (N'UX_ThreatCategory_NaturalKey', N'Threat_Category', 1, 1, N'ThreatCategoryName'),
    (N'UX_Control_Standard_Name', N'Control_Standard', 1, 1, N'StandardName'),
    (N'UX_Control_Library_Code', N'Control_Library', 1, 1, N'ControlCode'),
    (N'IX_Session_Active', N'Scenario_Session', 0, 1, N'SessionStatus'),
    (N'UX_API_Client_KeyHash', N'API_Client', 1, 1, N'KeyHash'),
    (N'IX_IdentifiedThreat_SessionSubActive', N'Identified_Threat', 0, 1, N'SessionID,SubsystemID'),
    (N'IX_ScopedThreat_SessionSubActive', N'Scoped_Threat', 0, 1, N'SessionID,SubsystemID'),
    (N'IX_ScopedThreat_SessionActiveScores', N'Scoped_Threat', 0, 0, N'SessionID,Superseded'),
    (N'IX_Scenario_SessionSubActive', N'Threat_Scenario', 0, 1, N'SessionID,SubsystemID'),
    (N'IX_Scenario_RejectedDecision', N'Threat_Scenario', 0, 1, N'SessionID'),
    (N'IX_Session_EntityUser', N'Scenario_Session', 0, 0, N'EntityID,UserID'),
    (N'IX_TreatmentPlan_SessionActive', N'Risk_Treatment_Plan', 0, 1, N'SessionID'),
    (N'IX_TreatmentPlan_SessionHistory', N'Risk_Treatment_Plan', 0, 1, N'SessionID,ScenarioID,CreatedAt'),
    (N'IX_ScenarioAudit_SessionSubEvent', N'Scenario_Audit', 0, 0, N'SessionID,SubsystemID,EventType,CreatedAt'),
    (N'IX_ScenarioAudit_Scenario', N'Scenario_Audit', 0, 1, N'ScenarioID,CreatedAt'),
    (N'IX_ThreatType_Category_Active', N'Threat_Type', 0, 1, N'ThreatCategoryID'),
    (N'IX_PromptLog_Correlation', N'Prompt_Log', 0, 1, N'CorrelationID,CreatedAt'),
    (N'IX_DiagnosticEvent_Session', N'Diagnostic_Event', 0, 1, N'SessionID,CreatedAt'),
    (N'IX_DiagnosticEvent_Created', N'Diagnostic_Event', 0, 0, N'CreatedAt'),
    (N'IX_ApplicationLog_Created', N'Application_Log', 0, 0, N'CreatedAt'),
    (N'IX_ApplicationLog_Session', N'Application_Log', 0, 1, N'SessionID,CreatedAt'),
    (N'IX_IdentifiedDuplicateThreat_Session', N'Identified_Duplicate_Threat', 0, 0, N'SessionID'),
    (N'IX_PromptLog_Session', N'Prompt_Log', 0, 0, N'SessionID,SubsystemID'),
    (N'IX_ScenarioAudit_Plan', N'Scenario_Audit', 0, 1, N'PlanID,CreatedAt'),
    (N'CIX_PromptLog_Created', N'Prompt_Log', 0, 0, N'CreatedAt,LogID'),
    (N'CIX_ApplicationLog_Created', N'Application_Log', 0, 0, N'CreatedAt,LogID'),
    (N'CIX_DiagnosticEvent_Created', N'Diagnostic_Event', 0, 0, N'CreatedAt,DiagnosticID'),
    (N'UQ_Config_Tuning_Key', N'Config_Tuning', 1, 0, N'TuningKey');

DECLARE @ix_missing int = 0, @ix_shape int = 0;

SELECT @ix_missing = COUNT(*)
FROM   @ix e
WHERE  NOT EXISTS (SELECT 1 FROM sys.indexes i
                   WHERE i.name = e.name
                     AND i.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                     AND i.is_disabled = 0);

IF @ix_missing > 0
    SELECT '[FAIL] index missing or disabled: ' + e.name + ' on ' + e.tbl AS Problem
    FROM   @ix e
    WHERE  NOT EXISTS (SELECT 1 FROM sys.indexes i
                       WHERE i.name = e.name
                         AND i.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                         AND i.is_disabled = 0);

/* Shape: uniqueness, filtered-ness, and the key column list in order. */
DECLARE @actual TABLE (name sysname, tbl sysname, is_unique bit, is_filtered bit,
                       cols nvarchar(900));
INSERT INTO @actual (name, tbl, is_unique, is_filtered, cols)
SELECT i.name, t.name, i.is_unique, i.has_filter,
       STUFF((SELECT ',' + c.name
              FROM   sys.index_columns ic
              JOIN   sys.columns c ON c.object_id = ic.object_id
                                  AND c.column_id = ic.column_id
              WHERE  ic.object_id = i.object_id AND ic.index_id = i.index_id
                AND  ic.is_included_column = 0
              ORDER BY ic.key_ordinal
              FOR XML PATH('')), 1, 1, '')
FROM   sys.indexes i
JOIN   sys.tables  t ON t.object_id = i.object_id
WHERE  i.name IN (SELECT name FROM @ix);

SELECT @ix_shape = COUNT(*)
FROM   @ix e JOIN @actual a ON a.name = e.name AND a.tbl = e.tbl
WHERE  a.is_unique <> e.is_unique OR a.is_filtered <> e.is_filtered
   OR  ISNULL(a.cols, '') <> e.cols;

IF @ix_shape > 0
    SELECT '[FAIL] index shape: ' + e.name + ' on ' + e.tbl +
           CASE WHEN a.is_unique   <> e.is_unique   THEN '  UNIQUE differs;' ELSE '' END +
           CASE WHEN a.is_filtered <> e.is_filtered THEN '  filter differs;' ELSE '' END +
           CASE WHEN ISNULL(a.cols, '') <> e.cols
                THEN '  keys are (' + ISNULL(a.cols, '<none>') + '), expected (' + e.cols + ')'
                ELSE '' END AS Problem
    FROM   @ix e JOIN @actual a ON a.name = e.name AND a.tbl = e.tbl
    WHERE  a.is_unique <> e.is_unique OR a.is_filtered <> e.is_filtered
       OR  ISNULL(a.cols, '') <> e.cols;

/*========================== PRIMARY KEYS ==========================
  The key COLUMNS, in order. 001 only asks whether a table HAS a primary key, so an older
  Threat_Scenario_Control_Map keyed on (OutputID, ControlLibraryID) passed it - and every insert
  failed, because the application writes ScenarioID and never supplies OutputID.
==================================================================*/
DECLARE @pk TABLE (tbl sysname, cols nvarchar(900));
INSERT INTO @pk (tbl, cols) VALUES
    (N'Threat_Category', N'ThreatCategoryID'),
    (N'Threat_Type', N'ThreatTypeID'),
    (N'Threat_Catalogue', N'ThreatCatalogueID'),
    (N'Threat_Actor', N'ThreatActorID'),
    (N'Threat_Catalogue_Category_Map', N'ThreatCategoryID,ThreatCatalogueID'),
    (N'ThreatType_ThreatActor_Map', N'ThreatTypeID,ThreatActorID'),
    (N'Control_Standard', N'StandardID'),
    (N'Control_Library', N'ControlLibraryID'),
    (N'Control_Library_Standard_Map', N'ControlLibraryID,StandardID'),
    (N'API_Client', N'ClientID'),
    (N'Config_Tuning', N'TuningID'),
    (N'Grounding_Calibration_Run', N'RunID'),
    (N'Scenario_Session', N'SessionID'),
    (N'Subsystem_Stage_State', N'StateID'),
    (N'Identified_Threat', N'ThreatID'),
    (N'Identified_Duplicate_Threat', N'DuplicateThreatID'),
    (N'Scoped_Threat', N'ScopedThreatID'),
    (N'Threat_Scenario', N'ScenarioID'),
    (N'Threat_Scenario_Control_Map', N'ScenarioID,ControlLibraryID'),
    (N'Risk_Treatment_Plan', N'PlanID'),
    (N'Scenario_Audit', N'AuditID'),
    (N'Prompt_Log', N'LogID'),
    (N'Diagnostic_Event', N'DiagnosticID'),
    (N'Application_Log', N'LogID');

DECLARE @pk_wrong int = 0;
DECLARE @pk_actual TABLE (tbl sysname, cols nvarchar(900));
INSERT INTO @pk_actual (tbl, cols)
SELECT e.tbl,
       STUFF((SELECT ',' + c.name
              FROM   sys.indexes i
              JOIN   sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
              JOIN   sys.columns c        ON c.object_id = ic.object_id AND c.column_id = ic.column_id
              WHERE  i.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                AND  i.is_primary_key = 1 AND ic.key_ordinal > 0
              ORDER BY ic.key_ordinal
              FOR XML PATH('')), 1, 1, '')
FROM   @pk e
WHERE  OBJECT_ID('dbo.' + QUOTENAME(e.tbl), 'U') IS NOT NULL;

SELECT @pk_wrong = COUNT(*)
FROM   @pk e JOIN @pk_actual a ON a.tbl = e.tbl
WHERE  ISNULL(a.cols, '') <> e.cols;

IF @pk_wrong > 0
    SELECT '[FAIL] primary key: ' + e.tbl + '  keys are (' + ISNULL(a.cols, '<none>') +
           '), expected (' + e.cols + ')' AS Problem
    FROM   @pk e JOIN @pk_actual a ON a.tbl = e.tbl
    WHERE  ISNULL(a.cols, '') <> e.cols;

/*============================ DEFAULTS ============================
  Checked BY COLUMN, not by constraint name. SQL Server permits one default per column, and a
  database may legitimately carry it under an auto-generated name
  (DF__Identifie__IsAIG__7954A4F6) — the column still has its default, which is what the
  application depends on. Demanding our name would fail a correct database and tempt someone to
  drop and recreate a constraint for cosmetics.

  Nothing verified these before: 001 prints a count as [INFO] and never fails on it. A column
  that loses its default does not error — it silently stores whatever the insert left out.
==================================================================*/
DECLARE @df TABLE (name sysname, tbl sysname, col sysname);
INSERT INTO @df (name, tbl, col) VALUES
    (N'DF_API_Client_Module', N'API_Client', N'Module'),
    (N'DF_API_Client_Active', N'API_Client', N'Active'),
    (N'DF_API_Client_CreatedAt', N'API_Client', N'CreatedAt'),
    (N'DF_Config_Tuning_IsActive', N'Config_Tuning', N'IsActive'),
    (N'DF_Config_Tuning_IsDeleted', N'Config_Tuning', N'IsDeleted'),
    (N'DF_Control_Library_CreatedAt', N'Control_Library', N'CreatedAt'),
    (N'DF_Control_Library_IsActive', N'Control_Library', N'IsActive'),
    (N'DF_Control_Library_IsDeleted', N'Control_Library', N'IsDeleted'),
    (N'DF_ControlStdMap_CreatedAt', N'Control_Library_Standard_Map', N'CreatedAt'),
    (N'DF_Control_Standard_CreatedAt', N'Control_Standard', N'CreatedAt'),
    (N'DF_Control_Standard_IsActive', N'Control_Standard', N'IsActive'),
    (N'DF_Control_Standard_IsDeleted', N'Control_Standard', N'IsDeleted'),
    (N'DF_GroundingCalibration_Forced', N'Grounding_Calibration_Run', N'Forced'),
    (N'DF_IdentifiedThreat_IsThreatAIGenerated', N'Identified_Threat', N'IsThreatAIGenerated'),
    (N'DF_IdentifiedThreat_IsThreatTypeAIGenerated', N'Identified_Threat', N'IsThreatTypeAIGenerated'),
    (N'DF_TreatmentPlan_Superseded', N'Risk_Treatment_Plan', N'Superseded'),
    (N'DF_SSS_AttemptCount', N'Subsystem_Stage_State', N'AttemptCount'),
    (N'DF_StageState_CreatedAt', N'Subsystem_Stage_State', N'CreatedAt'),
    (N'DF_CatCategoryMap_CreatedAt', N'Threat_Catalogue_Category_Map', N'CreatedAt'),
    (N'DF_Scenario_ScenarioNumber', N'Threat_Scenario', N'ScenarioNumber'),
    (N'DF_ThreatScenario_ControlMapAttempts', N'Threat_Scenario', N'ControlMapAttempts'),
    (N'DF_TypeActorMap_CreatedAt', N'ThreatType_ThreatActor_Map', N'CreatedAt');

DECLARE @df_missing int = 0;
SELECT @df_missing = COUNT(*)
FROM   @df e
WHERE  OBJECT_ID('dbo.' + QUOTENAME(e.tbl), 'U') IS NOT NULL
  AND  NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
                   JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                     AND c.column_id = dc.parent_column_id
                   WHERE dc.parent_object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                     AND c.name = e.col);

IF @df_missing > 0
    SELECT '[FAIL] no DEFAULT on ' + e.tbl + '.' + e.col +
           '  (expected ' + e.name + ') -> inserts omitting it store no value' AS Problem
    FROM   @df e
    WHERE  OBJECT_ID('dbo.' + QUOTENAME(e.tbl), 'U') IS NOT NULL
      AND  NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
                       JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                         AND c.column_id = dc.parent_column_id
                       WHERE dc.parent_object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                         AND c.name = e.col);

/*=================== IDENTITY and COLLATION ===================
  IDENTITY: the application NEVER supplies these ids — dal.upsert_threat_type and its siblings
  insert without the key and read the generated value back. A table created without identity
  therefore passes every other check here and then fails on the first library insert with
  "Cannot insert the value NULL". It cannot be repaired by ALTER (SQL Server needs a table
  rebuild), so this reports it rather than pretending a re-run fixes it.

  COLLATION: the natural-key unique indexes are the database half of the library's dedup
  guarantee. Under a case-SENSITIVE collation 'Ransomware' and 'ransomware' are different keys,
  so both insert and the library quietly accumulates duplicates that normalize_name() in Python
  already treats as one row. Checked as a FAMILY (_CI_), not an exact string, because the
  accent and locale parts are a deployment choice and only case-insensitivity is relied upon.
==============================================================*/
DECLARE @ident TABLE (tbl sysname, col sysname);
INSERT INTO @ident (tbl, col) VALUES
    (N'Config_Tuning', N'TuningID'),
    (N'Control_Library', N'ControlLibraryID'),
    (N'Control_Standard', N'StandardID'),
    (N'Threat_Actor', N'ThreatActorID'),
    (N'Threat_Catalogue', N'ThreatCatalogueID'),
    (N'Threat_Type', N'ThreatTypeID');

DECLARE @id_missing int = 0, @fail_collation int = 0;

SELECT @id_missing = COUNT(*)
FROM   @ident e
WHERE  OBJECT_ID('dbo.' + QUOTENAME(e.tbl), 'U') IS NOT NULL
  AND  NOT EXISTS (SELECT 1 FROM sys.identity_columns ic
                   JOIN sys.columns c ON c.object_id = ic.object_id
                                     AND c.column_id = ic.column_id
                   WHERE ic.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                     AND c.name = e.col);

IF @id_missing > 0
    SELECT '[FAIL] ' + e.tbl + '.' + e.col + ' is not an IDENTITY column. The application '
           + 'inserts without this id, so the first write to ' + e.tbl + ' will fail. '
           + 'IDENTITY cannot be added by ALTER - the table must be rebuilt.' AS Problem
    FROM   @ident e
    WHERE  OBJECT_ID('dbo.' + QUOTENAME(e.tbl), 'U') IS NOT NULL
      AND  NOT EXISTS (SELECT 1 FROM sys.identity_columns ic
                       JOIN sys.columns c ON c.object_id = ic.object_id
                                         AND c.column_id = ic.column_id
                       WHERE ic.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                         AND c.name = e.col);

DECLARE @collation nvarchar(128) = CAST(DATABASEPROPERTYEX(DB_NAME(), 'Collation') AS nvarchar(128));
IF @collation IS NULL OR @collation NOT LIKE '%_CI_%'
BEGIN
    SET @fail_collation = 1;
    PRINT ' [FAIL] Database collation is ' + ISNULL(@collation, '<unreadable>') + '.';
    PRINT '       A case-INSENSITIVE collation is required: the natural-key unique indexes';
    PRINT '       are what stop the threat library holding ''Ransomware'' and ''ransomware''';
    PRINT '       as two rows, and normalize_name() in the application already treats them';
    PRINT '       as one. Case-sensitive here means silent duplicate library entries.';
END;

PRINT '';
PRINT 'SCHEMA VERDICT';
PRINT '--------------';
PRINT ' [INFO]    Columns expected:   318';
PRINT ' [INFO]    Missing:            ' + CAST(@missing    AS varchar(10));
PRINT ' [INFO]    Wrong type:         ' + CAST(@wrong_type AS varchar(10));
PRINT ' [INFO]    Wrong nullability:  ' + CAST(@wrong_null AS varchar(10));
PRINT ' [INFO]    Indexes expected:   39';
PRINT ' [INFO]    Missing/disabled:   ' + CAST(@ix_missing AS varchar(10));
PRINT ' [INFO]    Wrong shape:        ' + CAST(@ix_shape   AS varchar(10));
PRINT ' [INFO]    Primary keys wrong: ' + CAST(@pk_wrong   AS varchar(10));
PRINT ' [INFO]    Defaults expected:  22';
PRINT ' [INFO]    Missing defaults:   ' + CAST(@df_missing AS varchar(10));
PRINT ' [INFO]    Identity expected:  6';
PRINT ' [INFO]    Missing identity:   ' + CAST(@id_missing AS varchar(10));
PRINT ' [INFO]    Collation:          ' + ISNULL(@collation, '<unreadable>');
PRINT '';
PRINT 'Columns:   ' + CASE WHEN (@missing + @wrong_type + @wrong_null) = 0
                           THEN 'PASS' ELSE 'FAILED' END;
PRINT 'Indexes:   ' + CASE WHEN (@ix_missing + @ix_shape) = 0 THEN 'PASS' ELSE 'FAILED' END;
PRINT 'Keys:      ' + CASE WHEN @pk_wrong = 0 THEN 'PASS' ELSE 'FAILED' END;
PRINT 'Defaults:  ' + CASE WHEN @df_missing = 0 THEN 'PASS' ELSE 'FAILED' END;
PRINT 'Identity:  ' + CASE WHEN @id_missing = 0 THEN 'PASS' ELSE 'FAILED' END;
PRINT 'Collation: ' + CASE WHEN @fail_collation = 0 THEN 'PASS' ELSE 'FAILED' END;
PRINT '';

IF (@missing + @wrong_type + @wrong_null + @ix_missing + @ix_shape + @pk_wrong + @df_missing
    + @id_missing + @fail_collation) = 0
BEGIN
    PRINT 'FINAL SIGN-OFF: this script and 001 have both passed. The application may start.';
END
ELSE
BEGIN
    PRINT 'FINAL SIGN-OFF: REFUSED. The failing rows are in the RESULTS tab in SSMS (listed';
    PRINT 'above in sqlcmd). A column [FAIL] usually means the deployment left work for a human -';
    PRINT 'a NOT NULL column added as NULL because the table already had rows - and re-running';
    PRINT 'will NOT clear it. An index [FAIL] should not survive a run: 03_indexes rebuilds a';
    PRINT 'wrong-shaped index, so check the output for an [ERROR] on that index.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('FINAL SIGN-OFF REFUSED - see the rows in the Results tab.', 16, 1);
END;
GO
IF @@ERROR <> 0 OR SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED. The error just above is the cause; the last ">>> [n/total]"';
    PRINT '!!! line above it names the script. NOTHING after this point ran.';
    PRINT '!!! Fix the cause, then run this WHOLE file again - it is re-runnable.';
    PRINT '!!! Any "Invalid column name" errors after this are NOT new problems: the skipped';
    PRINT '!!! steps are still compiled (not run) against columns that were never added.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    SET NOEXEC ON;
END
GO

SET NOEXEC OFF;
GO
SET XACT_ABORT OFF;
IF SESSION_CONTEXT(N'tsg_deploy_failed') = 1
BEGIN
    PRINT '';
    PRINT '!!! DEPLOYMENT STOPPED - it is NOT complete. The error is just above the';
    PRINT '!!! first "!!! DEPLOYMENT STOPPED" lines. Fix it, then run this whole file again.';
END
ELSE
BEGIN
    PRINT '';
    PRINT '>>> all 51 scripts have run. Read the two verdicts above:';
    PRINT '>>>   Objects: PASS   then   FINAL SIGN-OFF';
    PRINT '>>> Anything else means the deployment is NOT complete.';
END
GO
