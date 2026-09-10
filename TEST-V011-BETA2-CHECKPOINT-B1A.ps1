param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.2 CHECKPOINT B1a - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

$PytestTemp = Join-Path $env:TEMP ('bc-sentinel-v011-beta2-b1a-' + [guid]::NewGuid().ToString('N'))

try {
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) {
        throw '.venv not available'
    }
    $Py = '.\.venv\Scripts\python.exe'

    $required = @(
        '.\sentinel\protection_service_core.py',
        '.\sentinel\edr.py',
        '.\sentinel\edr_adapter.py',
        '.\sentinel\edr_hunting.py',
        '.\sentinel\edr_service_bridge.py',
        '.\tools\v011_beta2_service_preflight.py',
        '.\tools\v011_beta2_service_runtime_patch.py',
        '.\tests\test_v011_beta1_edr_foundation.py',
        '.\tests\test_v011_beta1_edr_adapter.py',
        '.\tests\test_v011_beta2_hunting.py',
        '.\tests\test_v011_beta2_service_bridge.py',
        '.\tests\test_v011_beta2_service_preflight.py',
        '.\tests\test_v011_beta2_service_runtime_patch.py'
    )
    foreach ($item in $required) {
        if (-not (Test-Path -LiteralPath $item)) {
            throw ('Missing B1a checkpoint file: ' + $item)
        }
    }

    New-Item -ItemType Directory -Path $PytestTemp -Force | Out-Null

    Write-Host 'BC Sentinel v0.11.0-beta.2 - CHECKPOINT B1a: ProtectionRuntime EDR Ownership' -ForegroundColor Cyan

    & $Py -m pytest -q --basetemp $PytestTemp `
        tests\test_v011_beta1_edr_foundation.py `
        tests\test_v011_beta1_edr_adapter.py `
        tests\test_v011_beta2_hunting.py `
        tests\test_v011_beta2_service_bridge.py `
        tests\test_v011_beta2_service_preflight.py `
        tests\test_v011_beta2_service_runtime_patch.py
    if ($LASTEXITCODE -ne 0) {
        throw 'Beta1/Beta2 EDR regressions or B1a patcher tests failed'
    }

    # Re-run the non-mutating source preflight immediately before mutation.
    & $Py -m tools.v011_beta2_service_preflight --output preflight-v011-beta2-service-b1a.json
    if ($LASTEXITCODE -ne 0) {
        throw 'Protection Service preflight failed immediately before B1a mutation'
    }

    & $Py -m tools.v011_beta2_service_runtime_patch --output integration-v011-beta2-b1a-runtime.json
    if ($LASTEXITCODE -ne 0) {
        throw 'ProtectionRuntime B1a integration patch failed'
    }

    & $Py -m tools.v011_beta2_service_runtime_patch --verify-only --output integration-v011-beta2-b1a-runtime-verify.json
    if ($LASTEXITCODE -ne 0) {
        throw 'ProtectionRuntime B1a post-patch verification failed'
    }

    & $Py -m compileall -q sentinel\protection_service_core.py sentinel\edr.py sentinel\edr_adapter.py sentinel\edr_hunting.py sentinel\edr_service_bridge.py
    if ($LASTEXITCODE -ne 0) {
        throw 'B1a compileall failed'
    }

    & $Py -c "from sentinel.protection_service_core import ProtectionRuntime; from sentinel.edr_service_bridge import EdrServiceBridge; print('B1a imports PASS')"
    if ($LASTEXITCODE -ne 0) {
        throw 'B1a runtime import verification failed'
    }

    Write-Host 'BC SENTINEL v0.11.0-beta.2 CHECKPOINT B1a - PASS' -ForegroundColor Green
    Write-Host 'Validated: service-owned EDR store construction, SecurityEvent ingestion hook, EDR status exposure, AST/source verification and legacy EDR regressions.' -ForegroundColor Green
    Write-Host 'Not yet claimed: authenticated EDR IPC operations, Security Center Inbox merge, service-native live ingestion, restart persistence or performance acceptance.' -ForegroundColor Yellow
    exit 0
}
catch {
    Fail $_.Exception.Message
}
finally {
    Remove-Item -LiteralPath $PytestTemp -Recurse -Force -ErrorAction SilentlyContinue
}
