<#
.SYNOPSIS
    Stop the local TSG stack started by .\start.ps1.

.DESCRIPTION
    Finds the tsg-api / tsg-celery / tsg-celery-admin / tsg-beat launcher windows and kills each
    one's full process tree (taskkill /T), so the celery/uvicorn child process
    goes down with its wrapper window, not just the window itself. Matches by
    command line (via WMI), not window title -- MainWindowTitle is only
    populated for real interactive console windows and is empty in headless/
    remote sessions, which would silently make title-based matching find
    nothing to stop.

    Also matches the celery worker/beat command line directly, not just the
    launcher window -- if that window was closed by hand (or crashed) the
    celery.exe/python.exe process underneath can survive as an orphan with
    'tsg-celery'/'tsg-beat' nowhere in ITS OWN command line, invisible to a
    window-only match forever after. start.ps1's own "already running" guard
    greps ALL processes for 'celery_worker.celery_app worker' for exactly this
    reason; this mirrors that so stop.ps1 can clear anything start.ps1 would
    refuse to start next to.

    Does NOT stop the docker compose services (redis/mongo/litellm) by
    default -- those are slow to reinitialize and usually meant to stay up
    across restarts. Pass -StopDocker to also run 'docker compose down' on
    them.

.PARAMETER ProjectRoot
    Path to the tsg/ folder. Defaults to the directory this script lives in.

.PARAMETER StopDocker
    Also stop the docker compose services (docker/compose.yml down).

.EXAMPLE
    .\stop.ps1

.EXAMPLE
    .\stop.ps1 -StopDocker
#>

[CmdletBinding()]
param(
    [string]$ProjectRoot = $PSScriptRoot,
    [switch]$StopDocker
)

# label -> command-line substrings that identify it. First substring is the launcher
# window (Start-InNewWindow's -Command argument carries the WindowTitle literal);
# celery/beat also match their own underlying invocation, so an orphan that outlived
# its window still gets found. Restricted to the actual executables this stack ever
# runs as (the launcher is powershell.exe; celery.exe re-execs through python.exe/
# pythonw.exe -- observed live as celery.exe -> python.exe -> python.exe) -- querying
# ALL processes matched unrelated short-lived processes whose command line happened
# to transiently contain the same text (e.g. this very script being discussed/edited
# spawns helper processes that quote it), killing things that were never part of the
# stack.
$relevantProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -in @('powershell.exe', 'celery.exe', 'python.exe', 'pythonw.exe') }

$targets = [ordered]@{
    'tsg-api'    = @("'tsg-api'")
    'tsg-celery' = @("'tsg-celery'", 'celery_worker.celery_app worker')
    # The admin-queue worker (start.ps1 3b). It escapes BOTH patterns above: its window is
    # 'tsg-celery-admin' (the tsg-celery match needs the trailing quote, 'tsg-celery'), and it
    # runs celery_app.celery_app (not celery_worker), so before this entry it survived every
    # stop -- the exact Flower bug noted below. '-Q admin' is unique: the main worker is -Q
    # celery, beat has no -Q, so it cannot collide.
    'tsg-celery-admin' = @("'tsg-celery-admin'", '-Q admin')
    'tsg-beat'   = @("'tsg-beat'", 'celery_app.celery_app beat')
    # Flower had NO entry here, so it survived every stop.ps1 and kept running indefinitely --
    # found still up (with a stale-venv python child) after a stop reported "Done." Only the
    # port pre-flight in start.ps1 ever touched it, which frees the PORT, not the process.
    # Matched on 'flower', which cannot collide with the beat pattern above.
    'tsg-flower' = @("'tsg-flower'", 'celery_app.celery_app flower')
}

foreach ($label in $targets.Keys) {
    $matches = $targets[$label]
    $procs = $relevantProcs | Where-Object {
        $cmd = $_.CommandLine
        $cmd -and ($matches | Where-Object { $cmd -like "*$_*" })
    }
    if (-not $procs) {
        Write-Host "  $label : not running." -ForegroundColor DarkGray
        continue
    }
    foreach ($p in $procs) {
        Write-Host "  $label : stopping PID $($p.ProcessId) (and its child processes)..." -ForegroundColor Yellow
        # Race-tolerant: /T can already have reaped a child (e.g. a prior iteration's
        # kill of its parent) by the time we get here -- "not found" is success, not a
        # failure, so don't let a redirected-stderr NativeCommandError (PS 5.1 turns
        # even 2>$null output into a terminating error under an inherited
        # $ErrorActionPreference='Stop', as stop_run.ps1 sets) abort the whole loop.
        try { & taskkill /PID $p.ProcessId /T /F 2>$null | Out-Null } catch {}
    }
}

if ($StopDocker.IsPresent) {
    $composeFile = Join-Path $ProjectRoot 'docker\compose.yml'
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if ($docker) {
        Write-Host "Stopping docker compose services..." -ForegroundColor Yellow
        & docker compose -f $composeFile down
    } else {
        Write-Warning "docker not found on PATH -- skipping compose teardown."
    }
} else {
    Write-Host "Docker compose services left running (pass -StopDocker to stop them too)." -ForegroundColor DarkGray
}

Write-Host "Done." -ForegroundColor Green
