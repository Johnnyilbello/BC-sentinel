param()
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$identity=[Security.Principal.WindowsIdentity]::GetCurrent(); $principal=New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Apri PowerShell come amministratore e rilancia." }
if (-not (Test-Path ".\.venv\Scripts\python.exe")) { throw "Esegui prima TEST-V010-BETA2-ALL-NORMAL.bat" }
$Py=".\.venv\Scripts\python.exe"
Write-Host "BC Sentinel v0.10.0-beta.2 - ALL ADMIN/NATIVE TESTS" -ForegroundColor Cyan
& $Py -m pytest -q tests\test_checkpoint4_authenticode_hardening_reconstructed.py tests\test_v010_beta1_web_reputation_primitives.py tests\test_v010_beta1_web_deception_anti_scam.py tests\test_v010_beta2_reversible_web_response.py tests\test_v072_beta2_active_web_response.py tests\test_v072_beta3_domain_trust_provenance_browser.py tests\test_v072_beta4_browser_download_incident_chain.py
if ($LASTEXITCODE -ne 0) { throw "Targeted native/Web tests falliti" }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\BUILD-SERVIZIO-PROTEZIONE.ps1
if ($LASTEXITCODE -ne 0) { throw "Build Protection Service/UAC Broker fallita" }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\INSTALLA-SERVIZIO-PROTEZIONE.ps1
if ($LASTEXITCODE -ne 0) { throw "Installazione Protection Service fallita" }
& $Py -m tools.v010_web_deception_acceptance --service-live --output acceptance-v010-beta2-deception-live.json
if ($LASTEXITCODE -ne 0) { throw "Acceptance deception live fallita" }
& $Py -m tools.v010_web_response_acceptance --service-live --output acceptance-v010-beta2-response-live.json
if ($LASTEXITCODE -ne 0) { throw "Acceptance Web Response live fallita" }
& $Py -m tools.web_threat_response_acceptance --service-live --output acceptance-v010-beta2-legacy-response-live.json
if ($LASTEXITCODE -ne 0) { throw "Regressione response live fallita" }
& $Py -m tools.windows_acceptance --benchmark-files 5000 --realtime-seconds 3 --service-live --output acceptance-v010-beta2-windows-live.json
if ($LASTEXITCODE -ne 0) { throw "Windows acceptance live fallita" }
& $Py -m tools.service_hardening_benchmark --idle-seconds 5 --ipc-requests 200 --storm-files 500 --output benchmark-v010-beta2-service.json
if ($LASTEXITCODE -ne 0) { throw "Benchmark service hardening fallito" }
Write-Host "ALL ADMIN/NATIVE TESTS PASS" -ForegroundColor Green
Write-Host "Upgrade/repair/reboot/UAC standard-user restano gate separati e non vengono marcati PASS da questo script." -ForegroundColor Yellow
