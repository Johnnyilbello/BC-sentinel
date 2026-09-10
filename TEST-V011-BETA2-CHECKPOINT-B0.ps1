param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.2 CHECKPOINT B0 - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

$PytestTemp = Join-Path $env:TEMP ('bc-sentinel-v011-beta2-checkpoint-b0-' + [guid]::NewGuid().ToString('N'))

try {
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) {
        throw '.venv not available'
    }
    $Py = '.\.venv\Scripts\python.exe'

    $required = @(
        '.\sentinel\edr.py',
        '.\sentinel\edr_adapter.py',
        '.\sentinel\edr_hunting.py',
        '.\sentinel\edr_service_bridge.py',
        '.\sentinel\protection_service_core.py',
        '.\tests\test_v011_beta2_hunting.py',
        '.\tests\test_v011_beta2_service_bridge.py',
        '.\tests\test_v011_beta2_service_preflight.py',
        '.\tools\v011_beta2_service_preflight.py'
    )
    foreach ($item in $required) {
        if (-not (Test-Path -LiteralPath $item)) {
            throw ('Missing Checkpoint B0 file: ' + $item)
        }
    }

    New-Item -ItemType Directory -Path $PytestTemp -Force | Out-Null
    Write-Host 'BC Sentinel v0.11.0-beta.2 - CHECKPOINT B0: Service Integration Preflight' -ForegroundColor Cyan

    & $Py -m pytest -q --basetemp $PytestTemp tests\test_v011_beta2_hunting.py tests\test_v011_beta2_service_bridge.py tests\test_v011_beta2_service_preflight.py
    if ($LASTEXITCODE -ne 0) {
        throw 'Beta2 hunting/service bridge/preflight tests failed'
    }

    & $Py -m compileall -q sentinel\edr_service_bridge.py tools\v011_beta2_service_preflight.py
    if ($LASTEXITCODE -ne 0) {
        throw 'Beta2 Checkpoint B0 compileall failed'
    }

    & $Py -m tools.v011_beta2_service_preflight --output preflight-v011-beta2-service.json
    if ($LASTEXITCODE -ne 0) {
        throw 'Protection Service FULL source preflight failed closed'
    }

    Write-Host 'BC SENTINEL v0.11.0-beta.2 CHECKPOINT B0 - PASS' -ForegroundColor Green
    Write-Host 'Validated: service-owned EDR bridge contract, read/privileged separation, non-destructive Inbox notification contract and FULL ProtectionRuntime structure discovery.' -ForegroundColor Green
    Write-Host 'No FULL Protection Service source was modified by this checkpoint.' -ForegroundColor Yellow
    exit 0
}
catch {
    Fail $_.Exception.Message
}
finally {
    Remove-Item -LiteralPath $PytestTemp -Recurse -Force -ErrorAction SilentlyContinue
}
