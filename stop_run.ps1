<#
.SYNOPSIS
    Stop the TSG stack started by .\run.ps1 (native services, no Docker).

.DESCRIPTION
    Delegates the actual killing to stop.ps1 -- which takes down the tsg-api /
    tsg-celery / tsg-beat process trees -- then VERIFIES they are gone. stop.ps1
    fires taskkill and prints "Done." without checking anything, so a survivor
    (a child that outlived its wrapper, a uvicorn still holding the port) would
    be reported as a clean stop and only surface as a confusing "port in use" on
    the next run.

    Deliberately does NOT pass -StopDocker: run.ps1 never starts compose, so there
    is nothing of ours to tear down, and stop.ps1's docker branch would only print
    a misleading "docker not found on PATH" here anyway.

    Native services (Memurai / MongoDB / MSSQL$SQLEXPRESS) are left RUNNING on
    purpose. They are machine-wide Windows services shared with everything else on
    this box, not children of this app -- stopping them is an ops decision. By hand,
    elevated, if ever needed:
        Stop-Service Memurai

.PARAMETER Port
    FastAPI port to confirm is released. Must match what run.ps1 used. Default 8000.

.EXAMPLE
    .\stop_run.ps1

.EXAMPLE
    .\stop_run.ps1 -Port 8080
#>

[CmdletBinding()]
param(
    [int]$Port = 8000
)

$ErrorActionPreference = 'Stop'

& (Join-Path $PSScriptRoot 'stop.ps1')

Write-Host ""
Write-Host "Verifying shutdown..." -ForegroundColor Cyan

$stragglers = @()

# ponytail: reuse stop.ps1's own matching rule (command line, not window title --
# MainWindowTitle is empty in headless sessions). If stop.ps1 ever renames its
# labels this check goes blind with it, which is the right coupling: one place to
# change, not two that can silently disagree.
foreach ($label in @('tsg-api', 'tsg-celery', 'tsg-beat')) {
    $procs = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and $_.CommandLine -like "*'$label'*" })
    if ($procs.Count -gt 0) {
        $stragglers += "$label still running (PID $($procs.ProcessId -join ', '))"
    }
}

$owner = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($owner) {
    $proc = Get-Process -Id $owner.OwningProcess -ErrorAction SilentlyContinue
    $stragglers += "port $Port still held by PID $($owner.OwningProcess) ($(if ($proc) { $proc.ProcessName } else { 'unknown' }))"
}

if ($stragglers) {
    Write-Host ""
    foreach ($s in $stragglers) { Write-Warning "  $s" }
    Write-Host ""
    throw "Stop incomplete (see above). Kill the listed PIDs by hand, then re-run."
}

Write-Host "  no tsg-api / tsg-celery / tsg-beat processes left; port $Port free." -ForegroundColor Green
Write-Host "  native services (Memurai / MongoDB / MSSQL`$SQLEXPRESS) left running by design." -ForegroundColor DarkGray
