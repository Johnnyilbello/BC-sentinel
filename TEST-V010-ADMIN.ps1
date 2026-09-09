param()
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Apri PowerShell come amministratore e rilancia questo script."
}
if (-not (Test-Path ".\.venv\Scripts\python.exe")) { throw "Esegui prima TEST-V010-NORMAL.ps1" }
$Py = ".\.venv\Scripts\python.exe"

Write-Host "BC Sentinel v0.10.0-beta.1 - ADMIN/NATIVE TEST" -ForegroundColor Cyan

& $Py -m pytest -q tests\test_checkpoint4_authenticode_hardening_reconstructed.py tests\test_v010_beta1_web_reputation_primitives.py tests\test_v010_beta1_web_deception_anti_scam.py
if ($LASTEXITCODE -ne 0) { throw "Test nativi/target v0.10 falliti" }

& powershell.exe -NoProfile -File .\BUILD-SERVIZIO-PROTEZIONE.ps1
if ($LASTEXITCODE -ne 0) { throw "Build Protection Service fallita" }

& powershell.exe -NoProfile -File .\INSTALLA-SERVIZIO-PROTEZIONE.ps1
if ($LASTEXITCODE -ne 0) { throw "Installazione Protection Service fallita" }

& $Py -m tools.v010_web_deception_acceptance --service-live --output acceptance-v010-beta1-live.json
if ($LASTEXITCODE -ne 0) { throw "Acceptance live v0.10 fallita" }

& $Py -m tools.windows_acceptance --benchmark-files 5000 --realtime-seconds 3 --service-live --output acceptance-v010-beta1-windows-live.json
if ($LASTEXITCODE -ne 0) { throw "Windows acceptance live fallita" }

& $Py -m tools.service_hardening_benchmark --idle-seconds 5 --ipc-requests 200 --storm-files 500 --output benchmark-v010-beta1-service.json
if ($LASTEXITCODE -ne 0) { throw "Benchmark service hardening fallito" }

Write-Host "ADMIN/NATIVE TEST PASS" -ForegroundColor Green
Write-Host "Nota: upgrade/repair/reboot/UAC standard-user restano gate separati finche non vengono eseguiti esplicitamente." -ForegroundColor Yellow
