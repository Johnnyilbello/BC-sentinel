param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$AdminResultPath = Join-Path $PSScriptRoot 'acceptance-v011-beta1-admin-phase-result.json'
$script:CurrentStage = 'initialization'
Remove-Item -LiteralPath $AdminResultPath -Force -ErrorAction SilentlyContinue

function Write-AdminResult([string]$Status, [string]$Stage, [string]$Message) {
    $payload = [ordered]@{
        product = 'BC Sentinel'
        version = '0.11.0-beta.1'
        status = $Status
        stage = $Stage
        message = $Message
        timestamp = (Get-Date).ToString('o')
    }
    $payload | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $AdminResultPath -Encoding UTF8
}

function Fail([string]$Message) {
    try { Write-AdminResult 'FAIL' $script:CurrentStage $Message } catch { }
    Write-Host ('V0.11 BETA1 ADMIN PHASE FAIL [' + $script:CurrentStage + ']: ' + $Message) -ForegroundColor Red
    exit 1
}

function Invoke-Maintenance([ValidateSet('Upgrade','Repair')][string]$Mode) {
    $maintenanceScript = Join-Path $PSScriptRoot 'AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1'
    if (-not (Test-Path -LiteralPath $maintenanceScript)) {
        throw ('Maintenance script missing: ' + $maintenanceScript)
    }

    $logPath = Join-Path $PSScriptRoot ('maintenance-' + $Mode.ToLowerInvariant() + '.log')
    Remove-Item -LiteralPath $logPath -Force -ErrorAction SilentlyContinue

    try {
        & $maintenanceScript -Mode $Mode *>&1 | Tee-Object -FilePath $logPath | ForEach-Object { Write-Host $_ }
    }
    catch {
        $detail = $_.Exception.Message
        $tail = ''
        try {
            if (Test-Path -LiteralPath $logPath) {
                $tail = ((Get-Content -LiteralPath $logPath -Tail 30) -join ' | ')
            }
        }
        catch { $tail = '' }
        if ($tail) {
            throw ('Live ' + $Mode + ' failed: ' + $detail + ' | log tail: ' + $tail)
        }
        throw ('Live ' + $Mode + ' failed: ' + $detail)
    }
}

function Read-JsonSafe([string]$Path) {
    try {
        if (Test-Path -LiteralPath $Path) {
            return (Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json)
        }
    }
    catch { }
    return $null
}

function Compact-Json($Value) {
    try { return ($Value | ConvertTo-Json -Compress -Depth 8) } catch { return '' }
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator phase requires UAC elevation. Start only TEST-V011-BETA1-ALL.bat from normal PowerShell.'
    }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.1 - AUTOMATED ADMIN PHASE (no reboot)' -ForegroundColor Cyan

    $script:CurrentStage = 'targeted_tests'
    $targeted = @('tests\test_checkpoint4_authenticode_hardening_reconstructed.py','tests\test_v062_privileged_broker_update.py','tests\test_v010_beta1_web_reputation_primitives.py','tests\test_v010_beta1_web_deception_anti_scam.py','tests\test_v010_beta2_reversible_web_response.py','tests\test_v010_beta3_clone_scam_fraud.py','tests\test_v010_rc1_consolidation.py','tests\test_v072_beta2_active_web_response.py','tests\test_v072_beta3_domain_trust_provenance_browser.py','tests\test_v072_beta4_browser_download_incident_chain.py','tests\test_v011_beta1_edr_foundation.py','tests\test_v011_beta1_service_performance.py','tests\test_v011_beta1_threat_package_atomic_replace.py','tests\test_v011_beta1_service_update_directory_retry.py')
    foreach ($item in $targeted) {
        if (-not (Test-Path -LiteralPath $item)) {
            throw ('Incomplete FULL baseline. Missing targeted test: ' + $item)
        }
    }

    & $Py -m pytest -q $targeted
    if ($LASTEXITCODE -ne 0) { throw 'Targeted native/Web/EDR/update/performance/threat-package/service-update tests failed' }

    $script:CurrentStage = 'build_preflight'
    $distService = Join-Path $PSScriptRoot 'dist\BC-Sentinel-Protection\BC-Sentinel-Protection.exe'
    if (-not (Test-Path -LiteralPath $distService)) {
        throw 'Standard-user build output missing. The main launcher must build before UAC elevation.'
    }

    $script:CurrentStage = 'service_install_preflight'
    $Target = Join-Path $env:ProgramFiles 'BC Sentinel\Protection'
    $ServiceExe = Join-Path $Target 'BC-Sentinel-Protection.exe'
    if (-not (Test-Path -LiteralPath $ServiceExe)) {
        if (Test-Path -LiteralPath '.\INSTALLA-SERVIZIO-PROTEZIONE.ps1') {
            Write-Host 'Protection Service not installed. Installing automatically...' -ForegroundColor Yellow
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\INSTALLA-SERVIZIO-PROTEZIONE.ps1'
            if ($LASTEXITCODE -ne 0) { throw 'Initial Protection Service installation failed' }
        }
        else {
            throw 'Protection Service is not installed and INSTALLA-SERVIZIO-PROTEZIONE.ps1 is unavailable'
        }
    }

    $script:CurrentStage = 'upgrade'
    $upgradePlanPath = Join-Path $PSScriptRoot 'acceptance-v011-beta1-upgrade-plan.json'
    & $Py -m tools.update_acceptance --mode upgrade --output $upgradePlanPath
    $upgradeExit = $LASTEXITCODE
    $upgradePlan = Read-JsonSafe $upgradePlanPath

    if ($upgradeExit -eq 0) {
        Invoke-Maintenance -Mode Upgrade
        Write-Host 'UPGRADE LIVE PASS' -ForegroundColor Green
    }
    elseif (($null -ne $upgradePlan) -and ($upgradePlan.classification -eq 'same_version_upgrade_rejected')) {
        Write-Host 'v0.11.0-beta.1 is already installed; anti-downgrade PASS. Continuing with real repair.' -ForegroundColor Yellow
    }
    else {
        throw 'Upgrade acceptance failed'
    }

    $script:CurrentStage = 'repair'
    $repairPlanPath = Join-Path $PSScriptRoot 'acceptance-v011-beta1-repair-plan.json'
    & $Py -m tools.update_acceptance --mode repair --output $repairPlanPath
    if ($LASTEXITCODE -ne 0) { throw 'Repair plan acceptance failed' }

    Invoke-Maintenance -Mode Repair
    Write-Host 'REPAIR LIVE PASS' -ForegroundColor Green

    $script:CurrentStage = 'service_readiness'
    $readinessPath = Join-Path $PSScriptRoot 'acceptance-v011-beta1-service-readiness.json'
    & $Py -m tools.v011_service_readiness --timeout-seconds 12 --poll-seconds 0.5 --output $readinessPath
    if ($LASTEXITCODE -ne 0) {
        $ready = Read-JsonSafe $readinessPath
        $detail = if ($null -ne $ready) { Compact-Json $ready } else { 'readiness JSON unavailable' }
        throw ('Protection Service Web/DNS ETW readiness failed: ' + $detail)
    }
    Write-Host 'SERVICE WEB/DNS ETW READINESS PASS' -ForegroundColor Green

    $script:CurrentStage = 'live_regression_deception'
    & $Py -m tools.v010_web_deception_acceptance --service-live --output acceptance-v011-regression-deception-live.json
    if ($LASTEXITCODE -ne 0) { throw 'v0.10 Beta1 deception live regression failed' }

    $script:CurrentStage = 'live_regression_response'
    & $Py -m tools.v010_web_response_acceptance --service-live --output acceptance-v011-regression-response-live.json
    if ($LASTEXITCODE -ne 0) { throw 'v0.10 Beta2 response live regression failed' }

    $script:CurrentStage = 'live_regression_clone_scam'
    & $Py -m tools.v010_clone_scam_acceptance --service-live --output acceptance-v011-regression-clone-scam-live.json
    if ($LASTEXITCODE -ne 0) { throw 'v0.10 Beta3 clone/scam live regression failed' }

    $script:CurrentStage = 'live_regression_legacy_web'
    $legacyPath = Join-Path $PSScriptRoot 'acceptance-v011-regression-legacy-response-live.json'
    & $Py -m tools.web_threat_response_acceptance --service-live --output $legacyPath
    if ($LASTEXITCODE -ne 0) {
        $legacy = Read-JsonSafe $legacyPath
        $detail = if ($null -ne $legacy) { Compact-Json $legacy } else { 'legacy acceptance JSON unavailable' }
        throw ('Legacy web response live regression failed: ' + $detail)
    }

    $script:CurrentStage = 'live_regression_rc1'
    & $Py -m tools.v010_rc1_acceptance --service-live --output acceptance-v011-regression-rc1-live.json
    if ($LASTEXITCODE -ne 0) { throw 'v0.10 RC1 consolidation live regression failed' }

    $script:CurrentStage = 'edr_admin_acceptance'
    & $Py -m tools.v011_edr_acceptance --output acceptance-v011-beta1-edr-admin.json
    if ($LASTEXITCODE -ne 0) { throw 'EDR Beta1 administrator acceptance failed' }

    $script:CurrentStage = 'windows_acceptance'
    & $Py -m tools.windows_acceptance --benchmark-files 5000 --realtime-seconds 3 --service-live --output acceptance-v011-beta1-windows-live.json
    if ($LASTEXITCODE -ne 0) { throw 'Windows live acceptance failed' }

    $script:CurrentStage = 'service_performance'
    Write-Host 'Service performance gates: idle <= 25% one core, IPC >= 10 req/s, benign storm <= 250% one core.' -ForegroundColor Cyan
    & $Py -m tools.service_hardening_benchmark --idle-seconds 5 --ipc-requests 200 --storm-files 500 --max-idle-cpu-percent 25 --min-ipc-rps 10 --max-storm-cpu-percent 250 --output benchmark-v011-beta1-service.json
    if ($LASTEXITCODE -ne 0) { throw 'Service hardening/performance benchmark failed' }

    $script:CurrentStage = 'completed'
    Write-AdminResult 'PASS' $script:CurrentStage 'Administrator phase completed successfully'
    Write-Host 'ADMIN PHASE PASS (native + upgrade + repair + regressions + performance; reboot excluded)' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
