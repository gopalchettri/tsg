# Applies pending Alembic migrations up to head against the TSG_DB_DSN
# configured in tsg\.env. Safe to run from any working directory.

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot   # tsg\ - where alembic.ini and .venv live

$alembic = Join-Path $PSScriptRoot ".venv\Scripts\alembic.exe"
if (-not (Test-Path $alembic)) {
    Write-Host "Could not find $alembic - has the venv been created? (python -m venv .venv)" -ForegroundColor Red
    exit 1
}

Write-Host "--- Current DB revision ---" -ForegroundColor Cyan
& $alembic current

Write-Host "--- Applying migrations to head ---" -ForegroundColor Cyan
& $alembic upgrade head

if ($LASTEXITCODE -eq 0) {
    Write-Host "--- Done. New revision: ---" -ForegroundColor Green
    & $alembic current
} else {
    Write-Host "Migration FAILED - do not deploy the new code until this succeeds." -ForegroundColor Red
    exit 1
}
