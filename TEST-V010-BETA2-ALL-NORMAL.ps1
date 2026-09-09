param()
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
Write-Host "BC Sentinel v0.10.0-beta.2 - ALL NORMAL TESTS" -ForegroundColor Cyan
if (-not (Test-Path ".\.venv\Scripts\python.exe")) { py -3.12 -m venv .venv }
$Py = ".\.venv\Scripts\python.exe"
& $Py -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "Installazione requirements fallita" }
$Temp = Join-Path $env:TEMP "bc-sentinel-v010-beta2-all-normal"
Remove-Item $Temp -Recurse -Force -ErrorAction SilentlyContinue
& $Py -m pytest -q --basetemp "$Temp"
if ($LASTEXITCODE -ne 0) { throw "Full pytest fallito" }
& $Py -m tools.v010_web_deception_acceptance --output acceptance-v010-beta2-deception-local.json
if ($LASTEXITCODE -ne 0) { throw "Acceptance deception/reputation fallita" }
& $Py -m tools.v010_web_response_acceptance --output acceptance-v010-beta2-response-local.json
if ($LASTEXITCODE -ne 0) { throw "Acceptance reversible web response fallita" }
& $Py -m tools.web_threat_response_acceptance --output acceptance-v010-beta2-legacy-response-regression.json
if ($LASTEXITCODE -ne 0) { throw "Regressione Web Response v0.7 fallita" }
& $Py -m compileall -q app sentinel tools tests
if ($LASTEXITCODE -ne 0) { throw "Compileall fallito" }
Write-Host "ALL NORMAL TESTS PASS" -ForegroundColor Green
