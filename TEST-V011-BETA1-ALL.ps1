param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.1 - ALL GATES FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run TEST-V011-BETA1-ALL.bat from a normal PowerShell. The launcher must validate standard-user to UAC.'
    }

    Write-Host 'BC Sentinel v0.11.0-beta.1 - ONE COMMAND FULL ORCHESTRATION (no reboot)' -ForegroundColor Cyan

    $requiredFullBaseline = @('.\BUILD-SERVIZIO-PROTEZIONE.ps1','.\AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1','.\tools\windows_acceptance.py','.\tools\service_hardening_benchmark.py','.\tools\broker_acceptance.py','.\tests\test_checkpoint4_authenticode_hardening_reconstructed.py','.\tests\test_v062_privileged_broker_update.py')
    foreach ($item in $requiredFullBaseline) {
        if (-not (Test-Path -LiteralPath $item)) {
            throw ('Incomplete FULL baseline. Missing RC1 file: ' + $item)
        }
    }

    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) {
        & py -3.12 -m venv .venv
        if ($LASTEXITCODE -ne 0) { throw 'Failed to create .venv' }
    }
    $Py = '.\.venv\Scripts\python.exe'

    & $Py -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw 'requirements installation failed' }

    & $Py -m tools.v011_legacy_test_compat
    if ($LASTEXITCODE -ne 0) { throw 'Legacy regression compatibility migration failed' }

    & $Py -m tools.v011_threat_package_windows_compat
    if ($LASTEXITCODE -ne 0) { throw 'Threat-package Windows compatibility migration failed' }

    $Temp = Join-Path $env:TEMP 'bc-sentinel-v011-beta1-all'
    Remove-Item -LiteralPath $Temp -Recurse -Force -ErrorAction SilentlyContinue
    & $Py -m pytest -q --basetemp $Temp
    if ($LASTEXITCODE -ne 0) { throw 'Full pytest failed' }

    & $Py -m tools.v011_edr_acceptance --output acceptance-v011-beta1-edr-local.json
    if ($LASTEXITCODE -ne 0) { throw 'EDR Beta1 local acceptance failed' }

    & $Py -m tools.v010_web_deception_acceptance --output acceptance-v011-regression-deception-local.json
    if ($LASTEXITCODE -ne 0) { throw 'v0.10 Beta1 deception regression failed' }
    & $Py -m tools.v010_web_response_acceptance --output acceptance-v011-regression-response-local.json
    if ($LASTEXITCODE -ne 0) { throw 'v0.10 Beta2 response regression failed' }
    & $Py -m tools.v010_clone_scam_acceptance --output acceptance-v011-regression-clone-scam-local.json
    if ($LASTEXITCODE -ne 0) { throw 'v0.10 Beta3 clone/scam regression failed' }
    & $Py -m tools.v010_rc1_acceptance --output acceptance-v011-regression-rc1-local.json
    if ($LASTEXITCODE -ne 0) { throw 'v0.10 RC1 consolidation regression failed' }

    & $Py -m compileall -q app sentinel tools tests
    if ($LASTEXITCODE -ne 0) { throw 'compileall failed' }

    Write-Host 'Building Protection Service and UAC Broker from standard-user PowerShell...' -ForegroundColor Cyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\BUILD-SERVIZIO-PROTEZIONE.ps1'
    if ($LASTEXITCODE -ne 0) { throw 'Protection Service/UAC Broker build failed' }

    $adminScript = Join-Path $PSScriptRoot 'TEST-V011-BETA1-ADMIN-PHASE.ps1'
    if (-not (Test-Path -LiteralPath $adminScript)) { throw 'v0.11 Beta1 admin script missing' }
    $benchmarkPath = Join-Path $PSScriptRoot 'benchmark-v011-beta1-service.json'
    Remove-Item -LiteralPath $benchmarkPath -Force -ErrorAction SilentlyContinue

    Write-Host 'Opening the UAC administrator phase automatically...' -ForegroundColor Yellow
    try {
        $adminArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $adminScript + '"'))
        $proc = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList $adminArgs
    }
    catch {
        throw ('UAC elevation cancelled or failed: ' + $_.Exception.Message)
    }
    if ($null -eq $proc) { throw 'Administrator process was not created' }

    $benchmark = $null
    if (Test-Path -LiteralPath $benchmarkPath) {
        try { $benchmark = Get-Content -Raw -LiteralPath $benchmarkPath | ConvertFrom-Json } catch { $benchmark = $null }
        if ($null -ne $benchmark) {
            $idleValue = [double]$benchmark.idle.cpu_percent_of_one_core
            $ipcValue = [double]$benchmark.ipc.requests_per_second
            $stormValue = [double]$benchmark.benign_event_storm.cpu_percent_of_one_core
            Write-Host (('SERVICE PERFORMANCE: idle={0:N2}% one-core | IPC={1:N2}/s | storm={2:N2}% one-core | passed={3}') -f $idleValue,$ipcValue,$stormValue,[bool]$benchmark.passed) -ForegroundColor Cyan
            if ($benchmark.failure_reasons) {
                foreach ($reason in $benchmark.failure_reasons) { Write-Host ('  - ' + $reason) -ForegroundColor Red }
            }
        }
    }

    if ($proc.ExitCode -ne 0) { throw ('Automated administrator phase failed with exit code ' + $proc.ExitCode) }
    if ($null -eq $benchmark) { throw 'Service performance benchmark result missing or unreadable' }
    if (-not [bool]$benchmark.passed) { throw 'Service performance benchmark did not satisfy the enforced thresholds' }

    & $Py -m tools.broker_acceptance --output acceptance-v011-beta1-standard-user-uac.json
    if ($LASTEXITCODE -ne 0) { throw 'Standard-user to UAC broker acceptance failed' }

    & $Py -m tools.v011_edr_acceptance --output acceptance-v011-beta1-edr-post-admin.json
    if ($LASTEXITCODE -ne 0) { throw 'EDR Beta1 post-admin regression failed' }

    Write-Host 'REBOOT PERSISTENCE GATE: DEFERRED TO FINAL ROADMAP VALIDATION' -ForegroundColor Yellow
    Write-Host 'BC SENTINEL v0.11.0-beta.1 - ALL GATES PASS' -ForegroundColor Green
    Write-Host 'Included: full suite, EDR Beta1, v0.10 RC1 regressions, native/admin, upgrade, repair, enforced service performance and standard-user to UAC. Reboot excluded.' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
