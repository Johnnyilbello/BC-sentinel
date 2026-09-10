param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.2 REQUEST.OP RECOVERY - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

function Read-JsonSafe([string]$Path) {
    try {
        if (Test-Path -LiteralPath $Path) { return (Get-Content -Raw -LiteralPath $Path -Encoding UTF8 | ConvertFrom-Json) }
    } catch { }
    return $null
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this recovery from normal PowerShell; UAC separation is part of B2 acceptance.'
    }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }
    if (-not (Test-Path -LiteralPath '.\BUILD-SERVIZIO-PROTEZIONE.ps1')) { throw 'BUILD-SERVIZIO-PROTEZIONE.ps1 missing' }
    if (-not (Test-Path -LiteralPath '.\AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1')) { throw 'AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1 missing' }
    $Py = '.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.2 - REQUEST.OP RECOVERY + LIVE RETEST' -ForegroundColor Cyan
    Write-Host 'Reuses the verified 656-test/Beta1 evidence, corrects the proven B1b request-field mismatch, rebuilds, redeploys and reruns only affected live/security/performance gates.' -ForegroundColor Yellow

    $beta1 = Read-JsonSafe '.\acceptance-v011-beta1-admin-phase-result.json'
    if ($null -eq $beta1 -or [string]$beta1.status -ne 'PASS') { throw 'Previous Beta1 administrator PASS evidence is missing.' }

    $downloads = @(
        @('tools\v011_beta2_b2_request_op_compat.py','tools/v011_beta2_b2_request_op_compat.py'),
        @('tools\v011_beta2_b2_live_acceptance.py','tools/v011_beta2_b2_live_acceptance.py'),
        @('tools\v011_beta2_b2_live_acceptance_compat.py','tools/v011_beta2_b2_live_acceptance_compat.py'),
        @('tools\v011_beta2_b2_frozen_runtime_probe.py','tools/v011_beta2_b2_frozen_runtime_probe.py'),
        @('tests\test_v011_beta2_b2_request_op_compat.py','tests/test_v011_beta2_b2_request_op_compat.py'),
        @('tests\test_v011_beta2_b2_contract.py','tests/test_v011_beta2_b2_contract.py'),
        @('TEST-V011-BETA2-B2-REQUEST-OP-ADMIN.ps1','TEST-V011-BETA2-B2-REQUEST-OP-ADMIN.ps1'),
        @('TEST-V011-BETA2-CHECKPOINT-B2.ps1','TEST-V011-BETA2-CHECKPOINT-B2.ps1'),
        @('TEST-V011-BETA2-CHECKPOINT-B2-ADMIN.ps1','TEST-V011-BETA2-CHECKPOINT-B2-ADMIN.ps1'),
        @('RETEST-V011-BETA2-B2-LIVE-ONLY.ps1','RETEST-V011-BETA2-B2-LIVE-ONLY.ps1')
    )
    foreach ($item in $downloads) {
        $local = Join-Path $PSScriptRoot $item[0]
        $uri = 'https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/v0.11.0-beta.2-checkpoint-b/' + $item[1]
        Invoke-WebRequest -Uri $uri -OutFile $local
    }

    Write-Host 'Applying fail-closed request.operation -> request.op compatibility correction...' -ForegroundColor Cyan
    & $Py -m tools.v011_beta2_b2_request_op_compat --output acceptance-v011-beta2-b2-request-op-lineage.json
    if ($LASTEXITCODE -ne 0) { throw 'B2 request.op compatibility correction or lineage verification failed' }

    $PytestTemp = Join-Path $env:TEMP ('bc-sentinel-v011-beta2-request-op-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $PytestTemp -Force | Out-Null
    try {
        & $Py -m pytest -q --basetemp $PytestTemp tests\test_v011_beta2_b2_request_op_compat.py tests\test_v011_beta2_b2_contract.py tests\test_v011_beta2_b1b_bridge_security.py tests\test_v011_beta2_ipc_preflight.py
        if ($LASTEXITCODE -ne 0) { throw 'Targeted B2 request.op/IPC/security contract tests failed' }
    }
    finally {
        Remove-Item -LiteralPath $PytestTemp -Recurse -Force -ErrorAction SilentlyContinue
    }

    & $Py -m compileall -q sentinel tools tests
    if ($LASTEXITCODE -ne 0) { throw 'Compileall failed after request.op correction' }

    Write-Host 'Building fresh corrected Protection Service and Broker...' -ForegroundColor Cyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\BUILD-SERVIZIO-PROTEZIONE.ps1'
    if ($LASTEXITCODE -ne 0) { throw 'Fresh corrected Protection Service build failed' }

    $distService = Join-Path $PSScriptRoot 'dist\BC-Sentinel-Protection\BC-Sentinel-Protection.exe'
    if (-not (Test-Path -LiteralPath $distService)) { throw 'Corrected Protection Service dist executable missing' }

    $probePath = Join-Path $PSScriptRoot 'probe-v011-beta2-b2-request-op-frozen.json'
    & $Py -m tools.v011_beta2_b2_frozen_runtime_probe --exe $distService --output $probePath
    $probeExit = $LASTEXITCODE
    $probe = Read-JsonSafe $probePath
    if ($probeExit -ne 0 -or $null -eq $probe -or -not [bool]$probe.passed) {
        $classification = if ($null -ne $probe -and $probe.classification) { [string]$probe.classification } else { 'probe_unreadable' }
        throw ('Corrected frozen service routing probe failed: ' + $classification)
    }
    if ([string]$probe.classification -ne 'frozen_b1b_protocol_and_service_present') {
        throw ('Unexpected corrected frozen-service classification: ' + [string]$probe.classification)
    }
    Write-Host 'FROZEN REQUEST.OP ROUTING PROBE PASS' -ForegroundColor Green

    $adminScript = Join-Path $PSScriptRoot 'TEST-V011-BETA2-B2-REQUEST-OP-ADMIN.ps1'
    $adminResultPath = Join-Path $PSScriptRoot 'acceptance-v011-beta2-b2-request-op-admin-result.json'
    Remove-Item -LiteralPath $adminResultPath -Force -ErrorAction SilentlyContinue
    Write-Host 'Opening request.op recovery UAC phase...' -ForegroundColor Yellow
    $adminArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $adminScript + '"'))
    $proc = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList $adminArgs
    if ($null -eq $proc) { throw 'Request.op administrator process was not created' }
    $admin = Read-JsonSafe $adminResultPath
    if ($null -ne $admin) {
        $color = if ([string]$admin.status -eq 'PASS') { 'Green' } else { 'Red' }
        Write-Host (('REQUEST.OP ADMIN RESULT: status={0} | stage={1} | message={2}') -f $admin.status,$admin.stage,$admin.message) -ForegroundColor $color
    }
    if ($proc.ExitCode -ne 0) {
        if ($null -ne $admin) { throw ('Request.op admin failed at ' + [string]$admin.stage + ': ' + [string]$admin.message) }
        throw ('Request.op admin process failed with exit code ' + $proc.ExitCode)
    }
    if ($null -eq $admin -or [string]$admin.status -ne 'PASS') { throw 'Request.op administrator PASS result missing' }

    & $Py -m tools.broker_acceptance --output acceptance-v011-beta2-b2-request-op-standard-user-uac.json
    if ($LASTEXITCODE -ne 0) { throw 'Standard-user to UAC broker regression failed after request.op correction' }

    & $Py -m tools.v011_beta2_b2_live_acceptance_compat --mode standard-user --output acceptance-v011-beta2-b2-request-op-standard-user-edr.json
    if ($LASTEXITCODE -ne 0) {
        $detail = Read-JsonSafe '.\acceptance-v011-beta2-b2-request-op-standard-user-edr.json'
        throw ('Standard-user EDR least-privilege acceptance failed: ' + $(if ($null -ne $detail -and $detail.error) { [string]$detail.error } else { 'no detail' }))
    }

    & $Py -m tools.v011_edr_acceptance --output acceptance-v011-beta2-b2-request-op-edr-post-admin.json
    if ($LASTEXITCODE -ne 0) { throw 'Beta1 EDR regression failed after request.op correction' }

    $benchmark = Read-JsonSafe '.\benchmark-v011-beta2-b2-request-op-fix.json'
    if ($null -eq $benchmark -or -not [bool]$benchmark.passed) { throw 'Corrected-service 25/10/250 benchmark evidence missing or failed' }
    Write-Host (('B2 CORRECTED PERFORMANCE: idle={0:N2}% | IPC={1:N2}/s | storm={2:N2}%') -f [double]$benchmark.idle.cpu_percent_of_one_core,[double]$benchmark.ipc.requests_per_second,[double]$benchmark.benign_event_storm.cpu_percent_of_one_core) -ForegroundColor Green

    Write-Host 'BC SENTINEL v0.11.0-beta.2 REQUEST.OP RECOVERY - PASS' -ForegroundColor Green
    Write-Host 'Combine this PASS with the preceding 656-test/build/Beta1-admin evidence to complete the corrected B2 acceptance chain.' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
