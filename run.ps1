<#
.SYNOPSIS
    Run TSG against this machine's NATIVE services (no Docker).

.DESCRIPTION
    This box runs MSSQL, MongoDB and Redis (Memurai) as Windows services, so
    docker/compose.yml is not used at all -- this is start.ps1 -SkipDocker with a
    dependency pre-flight in front of it.

    litellm is deliberately not required: .env pins LLM_PROVIDER=azure_openai with
    EMBEDDING_PROVIDER/RERANKER_PROVIDER=local, so nothing ever dials
    TSG_LITELLM_BASE_URL. Moderation would, but LLM_MODERATION_ENABLED defaults off.

    The pre-flight exists because -SkipDocker skips start.ps1's readiness poll along
    with the compose step -- without it a stopped Redis doesn't fail here, it fails
    60s later as "celery worker did not respond to inspect ping", which says nothing
    about the actual cause.

    Do NOT switch this to start.ps1's docker path on this machine: native mongod
    already owns 27017, and Windows lets docker's proxy bind it a SECOND time rather
    than erroring, leaving which one answers a connection undefined.

.PARAMETER Check
    Only run the dependency pre-flight and report; launch nothing.

.PARAMETER Port
    HTTP port for FastAPI. Passed through to start.ps1. Default 8000.

.PARAMETER Concurrency
    Celery gevent-pool concurrency (the worker's -c flag: parallel task slots for one
    worker, gevent greenlets not processes). Passed through to start.ps1. Default 50 —
    see start.ps1's .PARAMETER Concurrency help for the full explanation and when to
    lower it.

.PARAMETER Reload
    Start uvicorn with --reload. Passed through to start.ps1.

.PARAMETER NoFlower
    Skip the Flower dashboard window. Passed through to start.ps1, where Flower starts by default.

.PARAMETER FlowerPort
    Port for the Flower dashboard. Passed through to start.ps1. Default 5555.

.EXAMPLE
    .\run.ps1

.EXAMPLE
    .\run.ps1 -Check

.EXAMPLE
    .\run.ps1 -Reload -Concurrency 10
#>

[CmdletBinding()]
param(
    [switch]$Check,
    [int]$Port = 8000,
    [int]$Concurrency = 50,
    [switch]$Reload,
    [switch]$NoFlower,
    [int]$FlowerPort = 5555
)

$ErrorActionPreference = 'Stop'

# ponytail: Get-Service is the whole check -- all three deps are Windows services
# here, and Running is a stronger signal than a port probe. A port probe would also
# be actively WRONG for SQLEXPRESS: it is a named instance on a dynamic port brokered
# by SQL Browser (Stopped/Disabled on this box), so it never listens on 1433 and
# probing 1433 reports a false "down". Add a real handshake probe only if a service
# ever reports Running while refusing connections.
$required = [ordered]@{
    'Memurai'          = 'Redis -- celery broker/backend + SSE bus'
    'MongoDB'          = 'embedding cache'
    'MSSQL$SQLEXPRESS' = 'application database'
}

Write-Host "Checking native dependencies..." -ForegroundColor Cyan

$problems = @()
foreach ($name in $required.Keys) {
    $why = $required[$name]
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $svc) {
        $problems += "$name is NOT INSTALLED ($why)."
    } elseif ($svc.Status -ne 'Running') {
        $problems += "$name is $($svc.Status) ($why). Start it with:  Start-Service '$name'   (needs an elevated shell)"
    } else {
        Write-Host "  $name : Running -- $why" -ForegroundColor Green
    }
}

if ($problems) {
    Write-Host ""
    foreach ($p in $problems) { Write-Warning $p }
    Write-Host ""
    # Fail closed: launching anyway would open three windows that each die on their own
    # unrelated-looking error, which is exactly how a missing dep stays invisible.
    throw "Native dependencies not ready (see above). Nothing was started."
}

if ($Check.IsPresent) {
    Write-Host ""
    Write-Host "All native dependencies ready. (-Check passed; nothing launched.)" -ForegroundColor Green
    return
}

Write-Host ""
& (Join-Path $PSScriptRoot 'start.ps1') -SkipDocker -Port $Port -Concurrency $Concurrency -Reload:$Reload `
    -NoFlower:$NoFlower -FlowerPort $FlowerPort
