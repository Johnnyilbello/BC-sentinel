param()
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Fail([string]$Message) {
    Write-Host "V0.11 BETA1 ADMIN PHASE FAIL: $Message" -ForegroundColor Red
    exit 1
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Fase admin richiede elevazione UAC. Avvia solo TEST-V011-BETA1-ALL.bat dalla PowerShell normale."
    }
    if (-not (Test-Path ".\.venv\Scripts\python.exe")) { throw ".venv non disponibile" }
    $Py = ".\.venv\Scripts\python.exe"

    Write-Host "BC Sentinel v0.11.0-beta.1 - AUTOMATED ADMIN PHASE (no reboot)" -ForegroundColor Cyan

    $targeted = @(
        "tests\test_checkpoint4_authenticode_hardening_reconstructed.py",
        "tests\test_v062_privileged_broker_update.py",
        "tests\test_v010_beta1_web_reputation_primitives.py",
        "tests\test_v010_beta1_web_deception_anti_scam.py",
        "tests\test_v010_beta2_reversible_web_response.py",
        "tests\test_v010_beta3_clone_scam_fraud.py",
        "tests\test_v010_rc1_consolidation.py",
        "tests\test_v072_beta2_active_web_response.py",
        "tests\test_v072_beta3_domain_trust_provenance_browser.py",
        "tests\test_v072_beta4_browser_download_incident_chain.py",
        "tests\test_v011_beta1_edr_foundation.py"
    )
    $missingTargeted = @($targeted | Where-Object { -not (Test-Path -LiteralPath $_) })
    if ($missingTargeted.Count -gt 0) {
        throw ("Baseline FULL incompleta; targeted test mancanti: " + ($missingTargeted -join ", "))
    }
    & $Py -m pytest -q $targeted
    if ($LASTEXITCODE -ne 0) { throw "Targeted native/Web/EDR/update tests falliti" }

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\BUILD-SERVIZIO-PROTEZIONE.ps1
    if ($LASTEXITCODE -ne 0) { throw "Build Protection Service/UAC Broker fallita" }

    $Target = Join-Path $env:ProgramFiles "BC Sentinel\Protection"
    $ServiceExe = Join-Path $Target "BC-Sentinel-Protection.exe"
    if (-not (Test-Path $ServiceExe)) {
        if (Test-Path ".\INSTALLA-SERVIZIO-PROTEZIONE.ps1") {
            Write-Host "Installazione precedente assente: installo automaticamente Protection Service." -ForegroundColor Yellow
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\INSTALLA-SERVIZIO-PROTEZIONE.ps1
            if ($LASTEXITCODE -ne 0) { throw "Installazione iniziale Protection Service fallita" }
        } else {
            throw "Protection Service non installato e INSTALLA-SERVIZIO-PROTEZIONE.ps1 non disponibile"
        }
    }

    $upgradePlanPath = Join-Path $PSScriptRoot "acceptance-v011-beta1-upgrade-plan.json"
    & $Py -m tools.update_acceptance --mode upgrade --output $upgradePlanPath
    $upgradeExit = $LASTEXITCODE
    $upgradePlan = $null
    try { $upgradePlan = Get-Content -Raw -LiteralPath $upgradePlanPath | ConvertFrom-Json } catch {}

    if ($upgradeExit -eq 0) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1 -Mode Upgrade
        if ($LASTEXITCODE -ne 0) { throw "Upgrade reale fallito" }
        Write-Host "UPGRADE LIVE PASS" -ForegroundColor Green
    } elseif ($upgradePlan -and $upgradePlan.classification -eq "same_version_upgrade_rejected") {
        Write-Host "Build v0.11.0-beta.1 gia installata; anti-downgrade PASS. Procedo al repair reale." -ForegroundColor Yellow
    } else {
        throw "Upgrade acceptance fallita"
    }

    $repairPlanPath = Join-Path $PSScriptRoot "acceptance-v011-beta1-repair-plan.json"
    & $Py -m tools.update_acceptance --mode repair --output $repairPlanPath
    if ($LASTEXITCODE -ne 0) { throw "Repair plan acceptance fallita" }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1 -Mode Repair
    if ($LASTEXITCODE -ne 0) { throw "Repair reale fallito" }
    Write-Host "REPAIR LIVE PASS" -ForegroundColor Green

    & $Py -m tools.v010_web_deception_acceptance --service-live --output acceptance-v011-regression-deception-live.json
    if ($LASTEXITCODE -ne 0) { throw "v0.10 Beta1 deception live fallita" }
    & $Py -m tools.v010_web_response_acceptance --service-live --output acceptance-v011-regression-response-live.json
    if ($LASTEXITCODE -ne 0) { throw "v0.10 Beta2 reversible response live fallita" }
    & $Py -m tools.v010_clone_scam_acceptance --service-live --output acceptance-v011-regression-clone-scam-live.json
    if ($LASTEXITCODE -ne 0) { throw "v0.10 Beta3 clone/scam live fallita" }
    & $Py -m tools.web_threat_response_acceptance --service-live --output acceptance-v011-regression-legacy-response-live.json
    if ($LASTEXITCODE -ne 0) { throw "Legacy web response live fallita" }
    & $Py -m tools.v010_rc1_acceptance --service-live --output acceptance-v011-regression-rc1-live.json
    if ($LASTEXITCODE -ne 0) { throw "v0.10 RC1 consolidation live fallita" }

    & $Py -m tools.v011_edr_acceptance --output acceptance-v011-beta1-edr-admin.json
    if ($LASTEXITCODE -ne 0) { throw "EDR Beta1 acceptance admin fallita" }

    & $Py -m tools.windows_acceptance --benchmark-files 5000 --realtime-seconds 3 --service-live --output acceptance-v011-beta1-windows-live.json
    if ($LASTEXITCODE -ne 0) { throw "Windows acceptance live fallita" }
    & $Py -m tools.service_hardening_benchmark --idle-seconds 5 --ipc-requests 200 --storm-files 500 --output benchmark-v011-beta1-service.json
    if ($LASTEXITCODE -ne 0) { throw "Benchmark service hardening fallito" }

    Write-Host "ADMIN PHASE PASS (native + upgrade + repair + regressions; reboot escluso)" -ForegroundColor Green
    exit 0
} catch {
    Fail $_.Exception.Message
}
