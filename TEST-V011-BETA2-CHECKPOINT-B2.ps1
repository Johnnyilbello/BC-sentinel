param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.2 CHECKPOINT B2 - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

function Read-JsonSafe([string]$Path) {
    try {
        if (Test-Path -LiteralPath $Path) { return (Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json) }
    } catch { }
    return $null
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run B2 from a normal PowerShell. The checkpoint must prove standard-user to UAC separation.'
    }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'

    $required = @(
        '.\BUILD-SERVIZIO-PROTEZIONE.ps1',
        '.\AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1',
        '.\TEST-V011-BETA1-ADMIN-PHASE.ps1',
        '.\sentinel\protection_service_core.py',
        '.\sentinel\protection_protocol.py',
        '.\sentinel\protection_client.py',
        '.\tools\v011_beta2_b1b_patch.py',
        '.\tools\v011_beta2_b2_live_acceptance.py',
        '.\tests\test_v011_beta2_b2_contract.py',
        '.\tools\broker_acceptance.py',
        '.\tools\service_hardening_benchmark.py',
        '.\tools\windows_acceptance.py',
        '.\tools\v011_legacy_test_compat.py',
        '.\tools\v011_threat_package_windows_compat.py',
        '.\tools\v011_threat_index_windows_compat.py',
        '.\tools\v011_threat_trust_windows_compat.py',
        '.\tools\v011_service_update_windows_compat.py',
        '.\tools\v011_low_cpu_runtime_compat.py'
    )
    foreach ($item in $required) {
        if (-not (Test-Path -LiteralPath $item)) { throw ('Incomplete FULL/B2 baseline. Missing: ' + $item) }
    }

    Write-Host 'BC Sentinel v0.11.0-beta.2 - CHECKPOINT B2: SERVICE-NATIVE LIVE / RESTART / PERFORMANCE' -ForegroundColor Cyan

    # The branch is an integration delta over the authoritative FULL Windows
    # tree. Re-apply the same canonical compatibility migrations as the frozen
    # Beta1 one-command gate after every overlay, before pytest/build. This is
    # required because delta copies can contain older FULL-source snapshots.
    $compatibilityMigrations = @(
        'tools.v011_legacy_test_compat',
        'tools.v011_threat_package_windows_compat',
        'tools.v011_threat_index_windows_compat',
        'tools.v011_threat_trust_windows_compat',
        'tools.v011_service_update_windows_compat',
        'tools.v011_low_cpu_runtime_compat'
    )
    foreach ($migration in $compatibilityMigrations) {
        Write-Host ('Applying canonical compatibility migration: ' + $migration) -ForegroundColor DarkCyan
        & $Py -m $migration
        if ($LASTEXITCODE -ne 0) { throw ('Compatibility migration failed before B2 pytest: ' + $migration) }
    }

    # Freeze B1b source shape after canonical FULL compatibility repair and
    # before any build or UAC activity. The compatibility migrations do not
    # relax the accepted B1b protocol/service/client SHA anchors.
    & $Py -m tools.v011_beta2_b1b_patch --verify-only --output integration-v011-beta2-b1b-before-b2.json
    if ($LASTEXITCODE -ne 0) { throw 'Accepted B1b protocol/service integration is not intact before B2' }

    $PytestTemp = Join-Path $env:TEMP ('bc-sentinel-v011-beta2-b2-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $PytestTemp -Force | Out-Null
    try {
        & $Py -m pytest -q --basetemp $PytestTemp
        if ($LASTEXITCODE -ne 0) { throw 'Full pytest regression suite failed before B2 live build' }
    }
    finally {
        Remove-Item -LiteralPath $PytestTemp -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Match the frozen Beta1 local acceptance families before going live.
    & $Py -m tools.v011_edr_acceptance --output acceptance-v011-beta2-b2-edr-local.json
    if ($LASTEXITCODE -ne 0) { throw 'Beta1 EDR local regression failed under B2' }
    & $Py -m tools.v010_web_deception_acceptance --output acceptance-v011-beta2-b2-deception-local.json
    if ($LASTEXITCODE -ne 0) { throw 'v0.10 deception local regression failed under B2' }
    & $Py -m tools.v010_web_response_acceptance --output acceptance-v011-beta2-b2-response-local.json
    if ($LASTEXITCODE -ne 0) { throw 'v0.10 response local regression failed under B2' }
    & $Py -m tools.v010_clone_scam_acceptance --output acceptance-v011-beta2-b2-clone-scam-local.json
    if ($LASTEXITCODE -ne 0) { throw 'v0.10 clone/scam local regression failed under B2' }
    & $Py -m tools.v010_rc1_acceptance --output acceptance-v011-beta2-b2-rc1-local.json
    if ($LASTEXITCODE -ne 0) { throw 'v0.10 RC1 local regression failed under B2' }
    & $Py -m tools.v011_beta2_b1b_acceptance
    if ($LASTEXITCODE -ne 0) { throw 'B1b authenticated IPC/Security Center structural acceptance regressed before B2' }

    & $Py -m compileall -q app sentinel tools tests
    if ($LASTEXITCODE -ne 0) { throw 'B2 compileall failed' }

    Write-Host 'Building fresh Protection Service and UAC Broker from standard-user PowerShell...' -ForegroundColor Cyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\BUILD-SERVIZIO-PROTEZIONE.ps1'
    if ($LASTEXITCODE -ne 0) { throw 'Fresh Protection Service/UAC Broker build failed for B2' }

    $distService = Join-Path $PSScriptRoot 'dist\BC-Sentinel-Protection\BC-Sentinel-Protection.exe'
    $distBroker = Join-Path $PSScriptRoot 'dist\BC-Sentinel-Protection\BC-Sentinel-Broker\BC-Sentinel-Broker.exe'
    if (-not (Test-Path -LiteralPath $distService)) { throw 'Fresh Protection Service executable missing after build' }
    if (-not (Test-Path -LiteralPath $distBroker)) { throw 'Fresh UAC Broker executable missing after build' }

    $adminScript = Join-Path $PSScriptRoot 'TEST-V011-BETA2-CHECKPOINT-B2-ADMIN.ps1'
    $adminResultPath = Join-Path $PSScriptRoot 'acceptance-v011-beta2-b2-admin-result.json'
    Remove-Item -LiteralPath $adminResultPath -Force -ErrorAction SilentlyContinue
    Write-Host 'Opening B2 UAC administrator live phase...' -ForegroundColor Yellow
    try {
        $adminArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $adminScript + '"'))
        $proc = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList $adminArgs
    }
    catch {
        throw ('B2 UAC elevation cancelled or failed: ' + $_.Exception.Message)
    }
    if ($null -eq $proc) { throw 'B2 administrator process was not created' }

    $adminResult = Read-JsonSafe $adminResultPath
    if ($null -ne $adminResult) {
        Write-Host (('B2 ADMIN RESULT: status={0} | stage={1} | message={2}') -f $adminResult.status,$adminResult.stage,$adminResult.message) -ForegroundColor Cyan
    }
    if ($proc.ExitCode -ne 0) {
        if ($null -ne $adminResult) { throw ('B2 administrator phase failed at ' + $adminResult.stage + ': ' + $adminResult.message) }
        throw ('B2 administrator phase failed with exit code ' + $proc.ExitCode)
    }
    if ($null -eq $adminResult -or [string]$adminResult.status -ne 'PASS') { throw 'B2 administrator PASS result missing' }

    # Confirm the existing standard-user -> UAC broker security path remains green.
    & $Py -m tools.broker_acceptance --output acceptance-v011-beta2-b2-standard-user-uac.json
    if ($LASTEXITCODE -ne 0) { throw 'Standard-user to UAC broker regression failed under B2' }

    # Production EDR reads must work for the authenticated local standard user,
    # but direct privileged retention must still be rejected.
    & $Py -m tools.v011_beta2_b2_live_acceptance --mode standard-user --output acceptance-v011-beta2-b2-standard-user-edr.json
    if ($LASTEXITCODE -ne 0) { throw 'B2 standard-user EDR least-privilege acceptance failed' }

    & $Py -m tools.v011_edr_acceptance --output acceptance-v011-beta2-b2-edr-post-admin.json
    if ($LASTEXITCODE -ne 0) { throw 'Beta1 EDR post-admin regression failed under B2' }

    $benchmark = Read-JsonSafe (Join-Path $PSScriptRoot 'benchmark-v011-beta1-service.json')
    if ($null -eq $benchmark -or -not [bool]$benchmark.passed) { throw 'Enforced 25/10/250 service-performance result missing or failed in B2' }
    Write-Host (('B2 PERFORMANCE CONFIRMED: idle={0:N2}% | IPC={1:N2}/s | storm={2:N2}%') -f [double]$benchmark.idle.cpu_percent_of_one_core,[double]$benchmark.ipc.requests_per_second,[double]$benchmark.benign_event_storm.cpu_percent_of_one_core) -ForegroundColor Green

    Write-Host 'REBOOT PERSISTENCE: still deferred to final roadmap validation; B2 validates real service restart persistence.' -ForegroundColor Yellow
    Write-Host 'BC SENTINEL v0.11.0-beta.2 CHECKPOINT B2 - PASS' -ForegroundColor Green
    Write-Host 'Validated: full regression, fresh build, production Named Pipe EDR, native ingestion, Security Center, SCM restart persistence, least privilege and unchanged 25/10/250 performance gates.' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
