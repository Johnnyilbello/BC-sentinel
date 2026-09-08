param()
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$id=[Security.Principal.WindowsIdentity]::GetCurrent(); $principal=New-Object Security.Principal.WindowsPrincipal($id)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Fase admin richiede elevazione." }
if (-not (Test-Path ".\.venv\Scripts\python.exe")) { throw "Esegui prima il launcher NORMAL oppure crea la .venv." }
$Py=".\.venv\Scripts\python.exe"
Write-Host "BC Sentinel v0.10.0-beta.3 - ADMIN PHASE (no reboot)" -ForegroundColor Cyan

& $Py -m pytest -q `
  tests\test_checkpoint4_authenticode_hardening_reconstructed.py `
  tests\test_v062_privileged_broker_update.py `
  tests\test_v010_beta1_web_reputation_primitives.py `
  tests\test_v010_beta1_web_deception_anti_scam.py `
  tests\test_v010_beta2_reversible_web_response.py `
  tests\test_v010_beta3_clone_scam_fraud.py `
  tests\test_v072_beta2_active_web_response.py `
  tests\test_v072_beta3_domain_trust_provenance_browser.py `
  tests\test_v072_beta4_browser_download_incident_chain.py
if ($LASTEXITCODE -ne 0) { throw "Targeted native/Web/update tests falliti" }

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\BUILD-SERVIZIO-PROTEZIONE.ps1
if ($LASTEXITCODE -ne 0) { throw "Build Protection Service/UAC Broker fallita" }

$Target = Join-Path $env:ProgramFiles "BC Sentinel\Protection"
$ServiceExe = Join-Path $Target "BC-Sentinel-Protection.exe"
if (-not (Test-Path $ServiceExe)) {
    throw "Upgrade live richiede una precedente installazione BC Sentinel. Il reboot resta escluso, ma upgrade/repair non viene saltato."
}

$upgradePlanPath = Join-Path $PSScriptRoot "acceptance-v010-beta3-upgrade-plan.json"
& $Py -m tools.update_acceptance --mode upgrade --output $upgradePlanPath
$upgradeExit = $LASTEXITCODE
$upgradePlan = $null
try { $upgradePlan = Get-Content -Raw -LiteralPath $upgradePlanPath | ConvertFrom-Json } catch {}
if ($upgradeExit -eq 0) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1 -Mode Upgrade
    if ($LASTEXITCODE -ne 0) { throw "Upgrade reale fallito" }
    Write-Host "UPGRADE LIVE PASS" -ForegroundColor Green
}
elseif ($upgradePlan -and $upgradePlan.classification -eq "same_version_upgrade_rejected") {
    Write-Host "Upgrade live gia applicato a questa build; anti-downgrade PASS. Procedo al repair reale." -ForegroundColor Yellow
}
else {
    throw "Upgrade acceptance fallita"
}

$repairPlanPath = Join-Path $PSScriptRoot "acceptance-v010-beta3-repair-plan.json"
& $Py -m tools.update_acceptance --mode repair --output $repairPlanPath
if ($LASTEXITCODE -ne 0) { throw "Repair plan acceptance fallita" }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1 -Mode Repair
if ($LASTEXITCODE -ne 0) { throw "Repair reale fallito" }
Write-Host "REPAIR LIVE PASS" -ForegroundColor Green

& $Py -m tools.v010_web_deception_acceptance --service-live --output acceptance-v010-beta3-deception-live.json
if ($LASTEXITCODE -ne 0) { throw "Beta1 deception live fallita" }
& $Py -m tools.v010_web_response_acceptance --service-live --output acceptance-v010-beta3-response-live.json
if ($LASTEXITCODE -ne 0) { throw "Beta2 reversible response live fallita" }
& $Py -m tools.v010_clone_scam_acceptance --service-live --output acceptance-v010-beta3-clone-scam-live.json
if ($LASTEXITCODE -ne 0) { throw "Beta3 clone/scam live fallita" }
& $Py -m tools.web_threat_response_acceptance --service-live --output acceptance-v010-beta3-legacy-response-live.json
if ($LASTEXITCODE -ne 0) { throw "Legacy web response live fallita" }
& $Py -m tools.windows_acceptance --benchmark-files 5000 --realtime-seconds 3 --service-live --output acceptance-v010-beta3-windows-live.json
if ($LASTEXITCODE -ne 0) { throw "Windows acceptance live fallita" }
& $Py -m tools.service_hardening_benchmark --idle-seconds 5 --ipc-requests 200 --storm-files 500 --output benchmark-v010-beta3-service.json
if ($LASTEXITCODE -ne 0) { throw "Benchmark service hardening fallito" }

Write-Host "ADMIN PHASE PASS (upgrade + repair inclusi; reboot escluso)" -ForegroundColor Green
