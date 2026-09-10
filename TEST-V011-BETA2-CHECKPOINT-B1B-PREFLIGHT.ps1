param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.2 CHECKPOINT B1b PREFLIGHT - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

$PytestTemp = Join-Path $env:TEMP ('bc-sentinel-v011-beta2-b1b-preflight-' + [guid]::NewGuid().ToString('N'))

try {
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'
    $required = @(
        '.\sentinel\protection_service_core.py',
        '.\sentinel\protection_protocol.py',
        '.\sentinel\edr_service_bridge.py',
        '.\tools\v011_beta2_ipc_preflight.py',
        '.\tests\test_v011_beta2_ipc_preflight.py',
        '.\tests\test_v011_beta2_service_bridge.py',
        '.\tests\test_v011_beta2_service_runtime_patch.py'
    )
    foreach ($item in $required) {
        if (-not (Test-Path -LiteralPath $item)) { throw ('Missing B1b preflight file: ' + $item) }
    }

    New-Item -ItemType Directory -Path $PytestTemp -Force | Out-Null
    Write-Host 'BC Sentinel v0.11.0-beta.2 - CHECKPOINT B1b PREFLIGHT: Authenticated IPC Structure' -ForegroundColor Cyan

    & $Py -m pytest -q --basetemp $PytestTemp tests\test_v011_beta2_ipc_preflight.py tests\test_v011_beta2_service_bridge.py tests\test_v011_beta2_service_runtime_patch.py
    if ($LASTEXITCODE -ne 0) { throw 'B1b preflight/regression tests failed' }

    & $Py -m compileall -q tools\v011_beta2_ipc_preflight.py
    if ($LASTEXITCODE -ne 0) { throw 'B1b preflight compileall failed' }

    & $Py -m tools.v011_beta2_ipc_preflight --output preflight-v011-beta2-b1b-ipc.json
    if ($LASTEXITCODE -ne 0) { throw 'FULL IPC/protocol preflight failed closed' }

    Write-Host 'BC SENTINEL v0.11.0-beta.2 CHECKPOINT B1b PREFLIGHT - PASS' -ForegroundColor Green
    Write-Host 'Validated: exact FULL protocol/dispatcher/client structure captured without mutation.' -ForegroundColor Green
    Write-Host 'No protocol, dispatcher, authorization or client source was modified.' -ForegroundColor Yellow
    exit 0
}
catch { Fail $_.Exception.Message }
finally { Remove-Item -LiteralPath $PytestTemp -Recurse -Force -ErrorAction SilentlyContinue }
