<#
.SYNOPSIS
    Start the full local TSG stack (Docker deps + Celery worker + Celery beat + FastAPI).

.DESCRIPTION
    Brings up docker/compose.yml's redis/mongo/litellm (mssql is skipped by default --
    this environment's .env points TSG_DB_DSN at a native SQL Server Express instance,
    not the dockerized one; pass -DockerServices to include it if your setup differs).
    The Celery worker, Celery beat, and Uvicorn each open in a new PowerShell window so
    their logs stay separate.

    The schema is NOT touched at startup. This project is database-first: the tables
    come from scripts/TSG_Core.sql, run by hand against the DB (see scripts/readme.txt).

    Flower is intentionally not started -- it is not a TSG dependency yet (see
    pyproject.toml / ROADMAP.md "Metrics/OpenTelemetry/Flower" = Pending).

.PARAMETER ProjectRoot
    Path to the tsg/ folder. Defaults to the directory this script lives in.

.PARAMETER Port
    HTTP port for the FastAPI server. Default 8000.

.PARAMETER Concurrency
    Celery gevent-pool concurrency. Default 50, matching docker/compose.prod.yml.

.PARAMETER Reload
    Pass -Reload to start uvicorn with --reload.

.PARAMETER DockerServices
    Which docker/compose.yml services to bring up. Default: redis, mongo, litellm.
    Pass -DockerServices mssql,redis,mongo,litellm to include the dockerized MSSQL too.

.PARAMETER SkipDocker
    Skip the docker compose step entirely (e.g. if you manage those services yourself).

.EXAMPLE
    .\start.ps1

.EXAMPLE
    .\start.ps1 -Reload -Concurrency 10
#>

[CmdletBinding()]
param(
    [string]$ProjectRoot = $PSScriptRoot,
    [int]$Port = 8000,
    [int]$Concurrency = 50,
    [switch]$Reload,
    [switch]$SkipDocker,
    [string[]]$DockerServices = @('redis', 'mongo', 'litellm')
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

$venvActivate = Join-Path $ProjectRoot '.venv\Scripts\Activate.ps1'
if (-not (Test-Path $venvActivate)) {
    throw "venv not found at $venvActivate. From $ProjectRoot run:`n  python -m venv .venv`n  ./.venv/Scripts/pip install -e `".[dev]`""
}

# Always address the venv's own celery.exe by full path. A bare `celery` resolves
# via PATH, and THIS window never activates the venv (only the spawned ones do) --
# so it silently hits whatever global Python is installed. That global has celery
# but no gevent/fastapi, so the readiness probe below errored out and reported
# "worker NOT READY" on every single run, even against a perfectly healthy worker.
$celeryExe = Join-Path $ProjectRoot '.venv\Scripts\celery.exe'

$envFile = Join-Path $ProjectRoot '.env'
if (-not (Test-Path $envFile)) {
    Write-Warning "$envFile not found. Copy .env.example to .env and fill in real values first."
}

Write-Host "Project root : $ProjectRoot" -ForegroundColor Cyan
Write-Host "FastAPI port : $Port"        -ForegroundColor Cyan
Write-Host "Concurrency  : $Concurrency" -ForegroundColor Cyan
Write-Host "Auto-reload  : $($Reload.IsPresent)" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# 1. Docker deps -- redis / mongo / litellm (mssql skipped by default, see PARAMETER above)
# ---------------------------------------------------------------------------

function Test-PortUp {
    param([Parameter(Mandatory)] [string]$HostName, [Parameter(Mandatory)] [int]$Port)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $async = $tcp.ConnectAsync($HostName, $Port)
        if ($async.Wait(500) -and $tcp.Connected) {
            $tcp.Close()
            return $true
        }
        return $false
    } catch {
        return $false
    }
}

# port each docker/compose.yml service listens on, for the readiness poll below
$servicePorts = @{ redis = 6379; mongo = 27017; litellm = 4000; mssql = 1433 }

if ($SkipDocker.IsPresent) {
    Write-Host "Skipping docker compose (-SkipDocker passed)." -ForegroundColor DarkGray
} else {
    $composeFile = Join-Path $ProjectRoot 'docker\compose.yml'
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $docker) {
        Write-Warning "docker not found on PATH -- skipping compose step. Start redis/mongo/litellm yourself, or install Docker."
    } else {
        Write-Host "Starting docker compose services: $($DockerServices -join ', ')..." -ForegroundColor Yellow
        & docker compose -f $composeFile up -d @DockerServices
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "docker compose up -d exited with code $LASTEXITCODE -- check the output above."
        }

        foreach ($svc in $DockerServices) {
            $svcPort = $servicePorts[$svc]
            if (-not $svcPort) { continue }
            $up = $false
            for ($i = 0; $i -lt 20; $i++) {
                if (Test-PortUp -HostName '127.0.0.1' -Port $svcPort) { $up = $true; break }
                Start-Sleep -Milliseconds 300
            }
            if ($up) {
                Write-Host "  $svc : up on port $svcPort" -ForegroundColor Green
            } else {
                Write-Warning "  $svc : did not respond on port $svcPort within 6s -- check 'docker compose logs $svc'."
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 2. (removed) Migration check.
#
# This project is database-first: scripts/TSG_Core.sql is the ONLY thing that
# creates the baseline schema (app/db/engine.py never calls metadata.create_all,
# and tests/test_schema_sync.py guards TSG_Core.sql against models.py). Alembic
# was a second, parallel owner of the same schema and has been removed -- it only
# ever produced a false "DB revision is not at expected head" warning here,
# because the .sql scripts build the tables but not alembic's own version-tracking
# table, which alembic then read as "nothing has ever been applied".
#
# Nothing replaces this step: there is no migration state left to check.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Port pre-flight: free the uvicorn port if a previous run left it bound.
# (Docker-managed ports are not touched here -- compose handles that lifecycle.)
# ---------------------------------------------------------------------------

function Stop-ProcessOnPort {
    param([Parameter(Mandatory)] [int]$Port, [Parameter(Mandatory)] [string]$Label)

    $ownerPids = @()
    try {
        $ownerPids = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue `
                     | Select-Object -ExpandProperty OwningProcess -Unique
    } catch {}

    if (-not $ownerPids) {
        Write-Host "  $Label : port $Port is free." -ForegroundColor DarkGray
        return
    }

    foreach ($ownerPid in $ownerPids) {
        $proc = Get-Process -Id $ownerPid -ErrorAction SilentlyContinue
        if (-not $proc) { continue }
        Write-Host "  $Label : port $Port held by PID $ownerPid ($($proc.ProcessName)) - stopping..." -ForegroundColor Yellow
        try {
            $null = $proc.CloseMainWindow()
            if (-not $proc.WaitForExit(2000)) {
                Stop-Process -Id $ownerPid -Force -ErrorAction SilentlyContinue
            }
        } catch {
            Stop-Process -Id $ownerPid -Force -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Milliseconds 500
}

# ---------------------------------------------------------------------------
# Helper that launches a command in a new PowerShell window with the venv
# already activated. Built piece-by-piece (not interpolated) to avoid quoting
# issues across PowerShell 5.1 and 7.x.
# ---------------------------------------------------------------------------

function Start-InNewWindow {
    param(
        [Parameter(Mandatory)] [string]$WorkDir,
        [Parameter(Mandatory)] [string]$VenvActivate,
        [Parameter(Mandatory)] [string]$InnerCommand,
        [string]$WindowTitle = ''
    )

    $parts = @(
        ("Set-Location -LiteralPath '" + $WorkDir + "'"),
        ("& '" + $VenvActivate + "'")
    )
    if ($WindowTitle) {
        $parts += ('$Host.UI.RawUI.WindowTitle = ''' + $WindowTitle + '''')
    }
    $parts += $InnerCommand

    $command = $parts -join '; '

    Start-Process -FilePath 'powershell.exe' -ArgumentList @(
        '-NoExit', '-NoLogo', '-Command', $command
    )
}

# ---------------------------------------------------------------------------
# 3. Celery worker (new window) -- gevent pool, matches compose.prod.yml's -c 50
# ---------------------------------------------------------------------------

# Full path, not a bare `celery` -- same reason $celeryExe exists above: if
# Activate.ps1 doesn't finish prepending .venv\Scripts to PATH before this line
# runs in the spawned window (profile-script timing, execution-policy quirks,
# etc.), a bare `celery` silently falls through to whatever global Python is on
# PATH, which has celery but not gevent -- reproduced live, worker crashes with
# "ModuleNotFoundError: No module named 'gevent'" instead of starting.
$celeryCmd = "& '$celeryExe' -A app.pipeline.celery_worker.celery_app worker -P gevent -c $Concurrency -l info"
Start-InNewWindow -WorkDir $ProjectRoot -VenvActivate $venvActivate `
                  -InnerCommand $celeryCmd -WindowTitle 'tsg-celery'
Write-Host "Celery worker starting in a new window (title: tsg-celery)..." -ForegroundColor Green

# ---------------------------------------------------------------------------
# 4. Celery beat (new window) -- default scheduler; fires the reaper every 60s
#    (celery_app.py's beat_schedule already defines "reap-stuck-sessions").
# ---------------------------------------------------------------------------

# beat's on-disk schedule cache (celerybeat-schedule.*, gitignored) only remembers
# "when did each periodic task last run" -- a pure cache (clean_up_abandoned_sessions() is safe to re-run
# any time, never a correctness requirement). stop.ps1 uses taskkill /T /F to kill
# the whole process tree reliably (Windows has no graceful-shutdown signal a
# console app can trap), and killing beat mid-write can truncate the underlying
# dbm file to 0 bytes -- which makes beat CRASH AND ABORT on its next startup
# (`EOFError: Ran out of input` unpickling an empty file) instead of just
# rebuilding the cache. Clear a truncated file before beat ever sees it, so a
# prior forceful stop can never take down this startup again.
$beatScheduleDat = Join-Path $ProjectRoot 'celerybeat-schedule.dat'
if ((Test-Path $beatScheduleDat) -and (Get-Item $beatScheduleDat).Length -eq 0) {
    Write-Warning "celerybeat-schedule.dat is 0 bytes (truncated by a prior forceful stop) -- clearing celerybeat-schedule.* so beat rebuilds it fresh."
    Remove-Item -Path (Join-Path $ProjectRoot 'celerybeat-schedule.*') -Force -ErrorAction SilentlyContinue
}

# Full path -- same reason as $celeryCmd above.
$beatCmd = "& '$celeryExe' -A app.pipeline.celery_app.celery_app beat -l info"
Start-InNewWindow -WorkDir $ProjectRoot -VenvActivate $venvActivate `
                  -InnerCommand $beatCmd -WindowTitle 'tsg-beat'
Write-Host "Celery beat starting in a new window (title: tsg-beat)..." -ForegroundColor Green

# skipped: flower isn't a TSG dependency yet (ROADMAP.md marks it Pending) --
# add a -Flower switch once it lands (pyproject.toml would need celery[flower] too).

# ---------------------------------------------------------------------------
# Wait for the worker to register on the broker.
# ---------------------------------------------------------------------------

function Test-CeleryWorkerReady {
    param([int]$TimeoutSec = 3)
    try {
        $output = & $celeryExe -A app.pipeline.celery_app.celery_app inspect ping -t $TimeoutSec 2>&1
        return ($output -match 'pong')
    } catch {
        return $false
    }
}

# 60s was too short and reported a false "NOT READY" against a perfectly healthy
# worker, reproduced live: a cold boot here loads the gevent monkey-patch, pyodbc,
# and the two LOCAL model paths in .env (multilingual-e5-large + bge-reranker-v2-m3),
# which routinely runs past a minute. The probe is also expensive in its own right --
# each call spawns a fresh celery.exe that re-imports the whole app tree (measured:
# ~7s per attempt), so a 60s budget only ever bought ~7 attempts.
$workerWaitSeconds = 180
Write-Host "Waiting up to ${workerWaitSeconds}s for celery worker to register on the broker..." -ForegroundColor Cyan
$workerReady = $false
$started = Get-Date
$deadline = $started.AddSeconds($workerWaitSeconds)
while ((Get-Date) -lt $deadline) {
    if (Test-CeleryWorkerReady -TimeoutSec 2) {
        $workerReady = $true
        $elapsed = [int]((Get-Date) - $started).TotalSeconds
        Write-Host "Celery worker is ready (registered on broker after ${elapsed}s)." -ForegroundColor Green
        break
    }
    # ponytail: no Start-Sleep -- the ~7s cold import inside Test-CeleryWorkerReady
    # already paces this loop; an extra second per iteration only bought fewer attempts.
}
if (-not $workerReady) {
    Write-Warning "Celery worker not ready after ${workerWaitSeconds}s -- it may still be loading local models, or it may have failed."
    Write-Warning "Confirm by hand before assuming failure:"
    Write-Warning "  .\.venv\Scripts\celery -A app.pipeline.celery_app.celery_app inspect ping -t 5"
    Write-Warning "If that still doesn't pong, check the 'tsg-celery' window - common causes:"
    Write-Warning "  - Database unreachable (TSG_DB_DSN in .env)"
    Write-Warning "  - Redis broker URL wrong - confirm TSG_REDIS_URL in .env"
    Write-Warning "  - Module import error in app/pipeline/celery_worker.py or celery_app.py"
    Write-Warning "Continuing to launch Uvicorn so you can inspect the failure."
}

# ---------------------------------------------------------------------------
# 5. FastAPI / Uvicorn (new window)
# ---------------------------------------------------------------------------

Stop-ProcessOnPort -Port $Port -Label 'uvicorn (pre-existing)'

# Full path -- same reason as $celeryCmd/$beatCmd above.
$uvicornExe = Join-Path $ProjectRoot '.venv\Scripts\uvicorn.exe'
$uvicornCmd = "& '$uvicornExe' app.main:app --host 0.0.0.0 --port $Port"
if ($Reload.IsPresent) { $uvicornCmd += ' --reload' }

Start-InNewWindow -WorkDir $ProjectRoot -VenvActivate $venvActivate `
                  -InnerCommand $uvicornCmd -WindowTitle 'tsg-api'
Write-Host "FastAPI server starting in a new window (title: tsg-api)..." -ForegroundColor Green

Write-Host ""
Write-Host "All services launched. Verify with:" -ForegroundColor Cyan
Write-Host "  Celery worker:  $(if ($workerReady) { 'ready (registered)' } else { 'NOT READY - see tsg-celery window' })" -ForegroundColor $(if ($workerReady) { 'Green' } else { 'Yellow' })
Write-Host "  curl http://127.0.0.1:$Port/healthz" -ForegroundColor Cyan
Write-Host "  curl http://127.0.0.1:$Port/readyz"  -ForegroundColor Cyan
Write-Host ""
Write-Host "Stop everything with: .\stop.ps1" -ForegroundColor Cyan
