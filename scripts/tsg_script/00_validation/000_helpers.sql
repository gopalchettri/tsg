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

PRINT ' [CREATED] Helper procedures ready: tsg_reconcile_column, tsg_reconcile_primary_key,';
PRINT '          tsg_report_extra_columns';
GO
