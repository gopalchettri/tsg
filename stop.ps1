<#
.SYNOPSIS
    Stop the local TSG stack started by .\start.ps1.

.DESCRIPTION
    Finds the tsg-api / tsg-celery / tsg-beat launcher windows and kills each
    one's full process tree (taskkill /T), so the celery/uvicorn child process
    goes down with its wrapper window, not just the window itself. Matches by
    command line (via WMI), not window title -- MainWindowTitle is only
    populated for real interactive console windows and is empty in headless/
    remote sessions, which would silently make title-based matching find
    nothing to stop. Does NOT stop the docker compose services (redis/mongo/
    litellm) by default -- those are slow to reinitialize and usually meant to
    stay up across restarts. Pass -StopDocker to also run 'docker compose down'
    on them.

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

# label -> substring that appears in the launcher window's own command line
# (Start-InNewWindow's -Command argument includes both the WindowTitle-setting
# fragment and the actual celery/uvicorn command, so either substring works).
$targets = [ordered]@{
    'tsg-api'    = "'tsg-api'"
    'tsg-celery' = "'tsg-celery'"
    'tsg-beat'   = "'tsg-beat'"
}

foreach ($label in $targets.Keys) {
    $match = $targets[$label]
    $procs = Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and $_.CommandLine -like "*$match*" }
    if (-not $procs) {
        Write-Host "  $label : not running." -ForegroundColor DarkGray
        continue
    }
    foreach ($p in $procs) {
        Write-Host "  $label : stopping PID $($p.ProcessId) (and its child processes)..." -ForegroundColor Yellow
        & taskkill /PID $p.ProcessId /T /F 2>$null | Out-Null
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
