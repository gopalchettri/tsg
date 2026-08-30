<#
.SYNOPSIS
    Start the full local TSG stack (Docker deps + Celery worker + Celery beat + FastAPI + Flower).

.DESCRIPTION
    Brings up docker/compose.yml's redis/mongo/litellm (mssql is skipped by default --
    this environment's .env points TSG_DB_DSN at a native SQL Server Express instance,
    not the dockerized one; pass -DockerServices to include it if your setup differs).
    The Celery worker, Celery beat, Uvicorn, and Flower each open in a new PowerShell window
    so their logs stay separate.

    The schema is NOT touched at startup. This project is database-first: the tables
    come from scripts/TSG_Core.sql, run by hand against the DB (see scripts/readme.txt).

    Flower (the Celery task dashboard, http://127.0.0.1:5555) starts by default; pass
    -NoFlower to skip it. It binds to 127.0.0.1 only, so a password is optional locally --
    set TSG_FLOWER_BASIC_AUTH in .env (or as a session env var) to require one. Tasks appear
    there only because app/pipeline/celery_app.py enables task events; without that config
    Flower runs but its task list stays empty.

.PARAMETER ProjectRoot
    Path to the tsg/ folder. Defaults to the directory this script lives in.

.PARAMETER Port
    HTTP port for the FastAPI server. Default 8000.

.PARAMETER Concurrency
    Celery gevent-pool concurrency (the worker's -c flag). Default 50, matching
    docker/compose.prod.yml. This is how many tasks ONE worker runs in parallel — gevent
    greenlets (cooperative threads in one process, right for IO-bound LLM/DB calls), not OS
    processes. Since worker_prefetch_multiplier=1 (app/pipeline/celery_app.py), it is also
    the most messages the worker may reserve from the queue — reservation can never exceed
    what is actually running. Lower it (e.g. -Concurrency 10) on a laptop or when the LLM
    endpoint rate-limits.

.PARAMETER Reload
    Pass -Reload to start uvicorn with --reload.

.PARAMETER DockerServices
    Which docker/compose.yml services to bring up. Default: redis, mongo, litellm.
    Pass -DockerServices mssql,redis,mongo,litellm to include the dockerized MSSQL too.

.PARAMETER SkipDocker
    Skip the docker compose step entirely (e.g. if you manage those services yourself).

.PARAMETER NoFlower
    Skip the Flower dashboard window. Flower starts by default.

.PARAMETER FlowerPort
    Port for the Flower dashboard. Default 5555.

.EXAMPLE
    .\start.ps1

.EXAMPLE
    .\start.ps1 -Reload -Concurrency 10

.EXAMPLE
    .\start.ps1 -NoFlower
#>

[CmdletBinding()]
param(
    [string]$ProjectRoot = $PSScriptRoot,
    [int]$Port = 8000,
    [int]$Concurrency = 50,
    [switch]$Reload,
    [switch]$SkipDocker,
    [switch]$NoFlower,
    [int]$FlowerPort = 5555,
    [string[]]$DockerServices = @('redis', 'mongo', 'litellm')
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

$venvActivate = Join-Path $ProjectRoot '.venv\Scripts\Activate.ps1'
if (-not (Test-Path $venvActivate)) {
    throw "venv not found at $venvActivate. From $ProjectRoot run:`n  python -m venv .venv`n  ./.venv/Scripts/pip install -e `".[dev]`"`n  ./.venv/Scripts/pip install -e `".[local]`"  # sentence-transformers, needed by the default EMBEDDING/RERANKER_PROVIDER=local"
}

# Always address the venv's own celery.exe by full path. A bare `celery` resolves
# via PATH, and THIS window never activates the venv (only the spawned ones do) --
# so it silently hits whatever global Python is installed. That global has celery
# but no gevent/fastapi, so the readiness probe below errored out and reported
# "worker NOT READY" on every single run, even against a perfectly healthy worker.
# NOT celery.exe. This checkout's .venv was created for a DIFFERENT directory and copied
# here -- pyvenv.cfg still reads `-m venv ...\DESC\TSG\tsg\.venv` -- so the console-script
# shim resolved a FOREIGN interpreter: the worker ran as a child of the stale venv's
# python.exe, loading that venv's site-packages while this checkout's code sat on sys.path.
# Confirmed live from the process tree (celery.exe -> ...\DESC\TSG\tsg\.venv\python.exe).
# Naming the interpreter explicitly ends it for good: `python -m celery` cannot resolve
# anywhere but this venv, whatever the shims, PATH or Activate.ps1 timing do.
$venvPython = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path $venvPython)) {
    throw "venv interpreter not found at $venvPython -- recreate the venv IN THIS DIRECTORY (do not copy one)."
}

$envFile = Join-Path $ProjectRoot '.env'
if (-not (Test-Path $envFile)) {
    Write-Warning "$envFile not found. Copy .env.example to .env and fill in real values first."
}

# Which env file the APP will actually read. config.py::_env_file() honours TSG_ENV_FILE and
# falls back to '.env'; this script neither sets nor validates it. That is silent-failure
# territory because '.env' (dev) ALSO carries APP_ENV=staging -- so a UAT launch from a shell
# that forgot the variable looks identical to a correct one right up until Mongo
# (localhost:27017) and the LLM provider (azure_openai) turn out to be the dev ones, at which
# point the symptom reads as "calibration keeps failing", not "wrong config file". Print it.
$effectiveEnvFile = if ($env:TSG_ENV_FILE) { $env:TSG_ENV_FILE } else { '.env  (TSG_ENV_FILE not set)' }

# Refuse to double-launch. Two workers on one box race the same queue (and, before -n below,
# under identical broker hostnames). NOTE: ONE healthy stack normally shows a celery.exe +
# TWO python.exe chain per service (launcher parent + real process) -- matched python.exe
# pairs are NOT evidence of a double launch; this guard checks before spawning, so it only
# ever fires on a genuine second start.ps1 run (or a half-dead leftover window). The port
# pre-flight below only protects uvicorn/flower; nothing guarded the worker until this.
$existingWorkers = Get-CimInstance Win32_Process |
    Where-Object { $_.CommandLine -like '*celery_worker.celery_app worker*' }
if ($existingWorkers) {
    $workerPids = ($existingWorkers | Select-Object -ExpandProperty ProcessId) -join ', '
    throw "A TSG celery worker is already running (PID $workerPids) -- the stack is already up. Run .\stop.ps1 first."
}

# Worker/beat output is tee'd to files below so a dead worker's last words survive the window
# closing (the 2026-08-14 "reaped: worker gone" incident was undiagnosable without this).
$logsDir = Join-Path $ProjectRoot 'logs'
New-Item -ItemType Directory -Force -Path $logsDir | Out-Null

Write-Host "Project root : $ProjectRoot" -ForegroundColor Cyan
Write-Host "Env file     : $effectiveEnvFile" -ForegroundColor Cyan
Write-Host "FastAPI port : $Port"        -ForegroundColor Cyan
Write-Host "Concurrency  : $Concurrency" -ForegroundColor Cyan
Write-Host "Auto-reload  : $($Reload.IsPresent)" -ForegroundColor Cyan
if (-not $env:TSG_ENV_FILE) {
    Write-Warning "TSG_ENV_FILE is not set -- the app will load .env (DEV config: azure_openai, mongodb://localhost:27017). For UAT/staging, stop and relaunch with:  `$env:TSG_ENV_FILE='.env.uat'"
}
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
        ("& '" + $VenvActivate + "'"),
        # Unbuffered stdout: the worker/beat windows pipe through Tee-Object, and Python
        # block-buffers stdout into a pipe -- a hard-killed worker's final (most important)
        # lines would die in the buffer instead of reaching the log file.
        '$env:PYTHONUNBUFFERED = ''1'''
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

# Explicit interpreter, not a bare `celery` -- same reason $venvPython exists above: if
# Activate.ps1 doesn't finish prepending .venv\Scripts to PATH before this line
# runs in the spawned window (profile-script timing, execution-policy quirks,
# etc.), a bare `celery` silently falls through to whatever global Python is on
# PATH, which has celery but not gevent -- reproduced live, worker crashes with
# "ModuleNotFoundError: No module named 'gevent'" instead of starting.
# -n gives this worker a unique broker identity. Celery's default is celery@<hostname>, so two
# bare workers on one Windows box register under the IDENTICAL node name and the broker can't
# tell them apart (heartbeat/ack ambiguity). ${PID} = this launcher shell's PID -- unique per
# start.ps1 invocation; %h = celery's own hostname substitution.
#
# 2>&1 merges celery's stderr (its own logging) with stdout (the app's structlog JSON, which
# bypasses celery logging -- see app/core/logging.py); ForEach ToString() flattens PS 5.1's
# ErrorRecord-wrapped stderr lines back to plain text; Tee-Object -Append keeps the live window
# AND a durable file, and never clobbers a previous run's evidence.
# ponytail: no rotation -- logs/ grows unbounded; add size-capped rotation if it ever matters.
$workerLog = Join-Path $logsDir 'celery.log'
$celeryCmd = "& '$venvPython' -m celery -A app.pipeline.celery_worker.celery_app worker -P gevent -c $Concurrency -l info -n tsg-worker-${PID}@%h 2>&1 | ForEach-Object { `$_.ToString() } | Tee-Object -FilePath '$workerLog' -Append"
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

# Full path -- same reason as $celeryCmd above. Same tee-to-file too: beat drives the reaper,
# so its output is the other half of any worker-death post-mortem.
$beatLog = Join-Path $logsDir 'beat.log'
$beatCmd = "& '$venvPython' -m celery -A app.pipeline.celery_app.celery_app beat -l info 2>&1 | ForEach-Object { `$_.ToString() } | Tee-Object -FilePath '$beatLog' -Append"
Start-InNewWindow -WorkDir $ProjectRoot -VenvActivate $venvActivate `
                  -InnerCommand $beatCmd -WindowTitle 'tsg-beat'
Write-Host "Celery beat starting in a new window (title: tsg-beat)..." -ForegroundColor Green

# ---------------------------------------------------------------------------
# Wait for the worker to register on the broker.
# ---------------------------------------------------------------------------

function Test-CeleryWorkerReady {
    param([int]$TimeoutSec = 3)
    try {
        $output = & $venvPython -m celery -A app.pipeline.celery_app.celery_app inspect ping -t $TimeoutSec 2>&1
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
$uvicornCmd = "& '$venvPython' -m uvicorn app.main:app --host 0.0.0.0 --port $Port"
if ($Reload.IsPresent) { $uvicornCmd += ' --reload' }

# Same tee as the worker/beat windows above, and for the same reason: this window is where a
# boot failure prints (unreachable DB, refused setting, wrong env file), and without a file it
# dies with the window -- leaving "the API never came up" with no evidence at all. Appended
# AFTER --reload so the pipe stays last.
# ponytail: no rotation -- logs/ grows unbounded, same as celery.log/beat.log.
$apiLog = Join-Path $logsDir 'api.log'
$uvicornCmd += " 2>&1 | ForEach-Object { `$_.ToString() } | Tee-Object -FilePath '$apiLog' -Append"

Start-InNewWindow -WorkDir $ProjectRoot -VenvActivate $venvActivate `
                  -InnerCommand $uvicornCmd -WindowTitle 'tsg-api'
Write-Host "FastAPI server starting in a new window (title: tsg-api)..." -ForegroundColor Green

# ---------------------------------------------------------------------------
# Wait for the API to answer /ready, mirroring the worker wait above.
# ---------------------------------------------------------------------------

function Test-ApiReady {
    param([int]$TimeoutSec = 2)
    try {
        $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/ready" -TimeoutSec $TimeoutSec -UseBasicParsing
        return $resp.StatusCode -eq 200
    } catch {
        return $false
    }
}

# validate_local_models(warm=False) in main.py only checks the model PATH exists (the API never
# holds the model in RAM), so this is import + DB-connectivity time, not a model load -- 60s is
# generous, not measured against a real cold-start P99.
$apiWaitSeconds = 60
Write-Host "Waiting up to ${apiWaitSeconds}s for the API to answer /ready..." -ForegroundColor Cyan
$apiReady = $false
$apiStarted = Get-Date
$apiDeadline = $apiStarted.AddSeconds($apiWaitSeconds)
while ((Get-Date) -lt $apiDeadline) {
    if (Test-ApiReady) {
        $apiReady = $true
        $elapsed = [int]((Get-Date) - $apiStarted).TotalSeconds
        Write-Host "API is ready (/ready OK after ${elapsed}s)." -ForegroundColor Green
        break
    }
    Start-Sleep -Milliseconds 500
}
if (-not $apiReady) {
    Write-Warning "API not ready after ${apiWaitSeconds}s -- check the 'tsg-api' window. Continuing to launch Flower anyway."
}

# ---------------------------------------------------------------------------
# 6. Flower -- the Celery task dashboard (new window, unless -NoFlower)
# ---------------------------------------------------------------------------
# Placement is deliberate: LAST, after both the worker-ready wait and the API-ready wait above.
# Flower begins broadcasting inspect calls (stats/active/registered/...) about a second after it
# starts, with a 1s timeout. Launched before the worker finishes _init_worker -- which loads local
# models, verifies DB invariants and warms grounding thresholds, easily tens of seconds -- every
# one of those calls times out and logs "Inspect method <x> failed". Harmless (the next poll
# succeeds) but it reads exactly like a broken dashboard. Starting last, once the rest of the
# stack has confirmed itself ready, means Flower's first inspect round -- and the dashboard the
# operator opens right after start.ps1 finishes -- has a fully-up stack to talk to.
#
# beat has no readiness signal to wait on here: unlike the worker it does no local-model warm-load
# or LLM verification, so it's alive within a couple seconds of its window opening with nothing
# meaningful to poll for (compose.prod.yml's beat healthcheck only checks its schedule file's
# mtime, which needs real elapsed run time to be informative -- not useful as a one-shot gate).
#
# Two more things that matter here:
#   1. -A targets app.pipeline.celery_app.celery_app, NOT celery_worker: celery_worker
#      monkey-patches gevent at import, which would corrupt Flower's tornado event loop.
#      Same target beat and `inspect ping` already use.
#   2. --address=127.0.0.1 keeps it off the network. Flower has NO auth by default and can
#      revoke/terminate running tasks, so it must not be reachable beyond this machine unless
#      TSG_FLOWER_BASIC_AUTH is set (docker/compose.prod.yml enforces that for real deployments).
if (-not $NoFlower) {
    # --logging=error: Flower logs a WARNING burst ("Inspect method X failed") every time its
    # periodic inspect poll finds no worker to answer -- not just at boot (already guarded by the
    # wait above) but any time the worker window is restarted by hand mid-session, which is
    # routine during local dev. That's Flower self-healing, not a bug; -error keeps real failures
    # visible while dropping the routine noise.
    $flowerArgs = "-A app.pipeline.celery_app.celery_app flower --address=127.0.0.1 --port=$FlowerPort --logging=error"

    # Session env var WINS, so an operator can override per-shell without editing .env; only
    # fall back to the file when nothing is set. PowerShell does not auto-load .env, so without
    # this fallback the committed TSG_FLOWER_BASIC_AUTH line would be silently inert locally.
    $flowerAuth = $env:TSG_FLOWER_BASIC_AUTH
    if (-not $flowerAuth) { $flowerAuth = $env:FLOWER_BASIC_AUTH }
    if (-not $flowerAuth) {
        # Deliberately parses ONE key, not a general dotenv loader: a broad loader here could
        # shadow the app's own pydantic-settings resolution and make the two disagree.
        # Honours TSG_ENV_FILE the same way app/core/config.py::_env_file() does.
        $envName = $env:TSG_ENV_FILE
        if (-not $envName) { $envName = '.env' }
        $envPath = if ([System.IO.Path]::IsPathRooted($envName)) { $envName }
                   else { Join-Path $ProjectRoot $envName }
        if (Test-Path -LiteralPath $envPath) {
            foreach ($line in (Get-Content -LiteralPath $envPath -ErrorAction SilentlyContinue)) {
                $trimmed = $line.Trim()
                if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { continue }
                $eq = $trimmed.IndexOf('=')          # FIRST '=' only: a password may contain '='
                if ($eq -lt 1) { continue }
                $key = $trimmed.Substring(0, $eq).Trim()
                if ($key -ne 'TSG_FLOWER_BASIC_AUTH' -and $key -ne 'FLOWER_BASIC_AUTH') { continue }
                $flowerAuth = $trimmed.Substring($eq + 1).Trim().Trim('"', "'")
                if ($flowerAuth) { break }           # keep scanning if the line was blank/empty
            }
        }
    }

    if ($flowerAuth) {
        $flowerArgs += " --basic-auth=$flowerAuth"
        Write-Host "Flower: basic auth enabled." -ForegroundColor Green
    } else {
        Write-Host "Flower: no TSG_FLOWER_BASIC_AUTH set (checked session env and .env) -- starting WITHOUT auth, bound to 127.0.0.1 only." -ForegroundColor DarkYellow
    }

    # Free the port first, exactly as the uvicorn launch above does. Flower now starts on EVERY
    # run, so without this a second start.ps1 (or a leftover window from a previous one) makes
    # tornado die on bind with "WinError 10048: Only one usage of each socket address ... is
    # normally permitted" -- the dashboard silently never comes up.
    # Deliberately INSIDE the -NoFlower guard: with -NoFlower we must not kill a Flower the
    # operator started by hand on this port.
    Stop-ProcessOnPort -Port $FlowerPort -Label 'flower (pre-existing)'

    # Tee'd like the other three windows. Flower is the one that most needs it: it can refuse to
    # start (bad --basic-auth), die on bind, or fail its first broker connect, and every one of
    # those messages used to vanish with the window -- which is exactly what makes a dead
    # http://127.0.0.1:5555 undiagnosable after the fact.
    # ponytail: no rotation -- logs/ grows unbounded, same as celery.log/beat.log.
    $flowerLog = Join-Path $logsDir 'flower.log'
    $flowerCmd = "& '$venvPython' -m celery $flowerArgs 2>&1 | ForEach-Object { `$_.ToString() } | Tee-Object -FilePath '$flowerLog' -Append"
    Start-InNewWindow -WorkDir $ProjectRoot -VenvActivate $venvActivate `
                      -InnerCommand $flowerCmd -WindowTitle 'tsg-flower'
    Write-Host "Flower starting in a new window (title: tsg-flower) -- http://127.0.0.1:$FlowerPort" -ForegroundColor Green
}

Write-Host ""
Write-Host "All services launched. Verify with:" -ForegroundColor Cyan
Write-Host "  Celery worker:  $(if ($workerReady) { 'ready (registered)' } else { 'NOT READY - see tsg-celery window' })" -ForegroundColor $(if ($workerReady) { 'Green' } else { 'Yellow' })
Write-Host "  curl http://127.0.0.1:$Port/health" -ForegroundColor Cyan
Write-Host "  curl http://127.0.0.1:$Port/ready"  -ForegroundColor Cyan
Write-Host ""
Write-Host "Stop everything with: .\stop.ps1" -ForegroundColor Cyan
