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

PRINT '';
PRINT '--- isolation level: READ_COMMITTED_SNAPSHOT ---';
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
