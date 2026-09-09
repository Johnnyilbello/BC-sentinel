param()
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
Write-Host "BC Sentinel v0.10.0-beta.1 - NORMAL TEST" -ForegroundColor Cyan

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    py -3.12 -m venv .venv
}
$Py = ".\.venv\Scripts\python.exe"
& $Py -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "Installazione requirements fallita" }

$PytestTemp = Join-Path $env:TEMP "bc-sentinel-v010-beta1-full-pytest"
Remove-Item $PytestTemp -Recurse -Force -ErrorAction SilentlyContinue
& $Py -m pytest -q --basetemp "$PytestTemp"
if ($LASTEXITCODE -ne 0) { throw "Pytest fallito" }

& $Py -m tools.v010_web_deception_acceptance --output acceptance-v010-beta1-local.json
if ($LASTEXITCODE -ne 0) { throw "Acceptance v0.10 locale fallita" }

& $Py -m compileall -q app sentinel tools tests
if ($LASTEXITCODE -ne 0) { throw "Compileall fallito" }

Write-Host "NORMAL TEST PASS" -ForegroundColor Green
