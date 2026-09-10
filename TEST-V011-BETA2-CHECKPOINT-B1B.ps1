param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.2 CHECKPOINT B1b - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

$PytestTemp = Join-Path $env:TEMP ('bc-sentinel-v011-beta2-b1b-' + [guid]::NewGuid().ToString('N'))

try {
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) {
        throw '.venv not available'
    }
    $Py = '.\.venv\Scripts\python.exe'
    $required = @(
        '.\sentinel\protection_service_core.py',
        '.\sentinel\protection_protocol.py',
        '.\sentinel\protection_client.py',
        '.\sentinel\edr_service_bridge.py',
        '.\tools\v011_beta2_ipc_preflight.py',
        '.\tools\v011_beta2_b1b_patch.py',
        '.\tools\v011_beta2_b1b_acceptance.py',
        '.\tests\test_v011_beta2_b1b_bridge_security.py',
        '.\tests\test_v011_beta2_b1b_patch.py'
    )
    foreach ($item in $required) {
        if (-not (Test-Path -LiteralPath $item)) {
            throw ('Missing B1b checkpoint file: ' + $item)
        }
    }

    New-Item -ItemType Directory -Path $PytestTemp -Force | Out-Null
    Write-Host 'BC Sentinel v0.11.0-beta.2 - CHECKPOINT B1b: Authenticated EDR IPC + Security Center' -ForegroundColor Cyan

    & $Py -m pytest -q --basetemp $PytestTemp `
        tests\test_v011_beta1_edr_foundation.py `
        tests\test_v011_beta1_edr_adapter.py `
        tests\test_v011_beta2_hunting.py `
        tests\test_v011_beta2_service_bridge.py `
        tests\test_v011_beta2_service_runtime_patch.py `
        tests\test_v011_beta2_service_preflight.py `
        tests\test_v011_beta2_b1b_bridge_security.py `
        tests\test_v011_beta2_b1b_patch.py
    if ($LASTEXITCODE -ne 0) {
        throw 'Beta1/Beta2 EDR regressions or B1b security/patcher tests failed'
    }

    # Exact non-mutating preflight immediately before protocol/service mutation.
    & $Py -m tools.v011_beta2_ipc_preflight --output preflight-v011-beta2-b1b-before-mutation.json
    if ($LASTEXITCODE -ne 0) {
        throw 'B1b IPC preflight failed immediately before mutation'
    }

    & $Py -m tools.v011_beta2_b1b_patch --output integration-v011-beta2-b1b.json
    if ($LASTEXITCODE -ne 0) {
        throw 'B1b authenticated IPC/service patch failed'
    }

    & $Py -m tools.v011_beta2_b1b_patch --verify-only --output integration-v011-beta2-b1b-verify.json
    if ($LASTEXITCODE -ne 0) {
        throw 'B1b post-patch verification failed'
    }

    # B1a ownership/ingestion/status hooks must remain intact after B1b wrapping.
    & $Py -m tools.v011_beta2_service_runtime_patch --verify-only --output integration-v011-beta2-b1a-after-b1b.json
    if ($LASTEXITCODE -ne 0) {
        throw 'B1a runtime integration regressed after B1b'
    }

    & $Py -m compileall -q `
        sentinel\protection_protocol.py `
        sentinel\protection_service_core.py `
        sentinel\protection_client.py `
        sentinel\edr_service_bridge.py `
        tools\v011_beta2_b1b_patch.py `
        tools\v011_beta2_b1b_acceptance.py
    if ($LASTEXITCODE -ne 0) {
        throw 'B1b compileall failed'
    }

    & $Py -m tools.v011_beta2_b1b_acceptance
    if ($LASTEXITCODE -ne 0) {
        throw 'B1b authenticated IPC/Security Center acceptance failed'
    }

    & $Py -c "from sentinel.protection_protocol import READ_OPERATIONS, PRIVILEGED_OPERATIONS; from sentinel.protection_service_core import ProtectionRuntime, ProtectionServiceCore; assert 'edr_timeline' in READ_OPERATIONS; assert 'edr_update_retention' in PRIVILEGED_OPERATIONS; print('B1b imports/allowlists PASS')"
    if ($LASTEXITCODE -ne 0) {
        throw 'B1b runtime import/allowlist verification failed'
    }

    Write-Host 'BC SENTINEL v0.11.0-beta.2 CHECKPOINT B1b - PASS' -ForegroundColor Green
    Write-Host 'Validated: authenticated EDR read routing, privileged retention authorization classification, strict payload schemas, bounded queries and review-only Security Center merge.' -ForegroundColor Green
    Write-Host 'Not yet claimed: live production Named Pipe round-trip, service restart persistence, fresh service/broker build or enforced performance acceptance. Those remain B2.' -ForegroundColor Yellow
    exit 0
}
catch {
    Fail $_.Exception.Message
}
finally {
    Remove-Item -LiteralPath $PytestTemp -Recurse -Force -ErrorAction SilentlyContinue
}
