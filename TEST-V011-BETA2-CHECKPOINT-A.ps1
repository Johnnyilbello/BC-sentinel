param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.2 CHECKPOINT A - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

try {
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) {
        throw '.venv not available'
    }
    $Py = '.\.venv\Scripts\python.exe'

    $required = @(
        '.\sentinel\edr.py',
        '.\sentinel\edr_adapter.py',
        '.\sentinel\edr_hunting.py',
        '.\tests\test_v011_beta1_edr_foundation.py',
        '.\tests\test_v011_beta1_edr_adapter.py',
        '.\tests\test_v011_beta2_hunting.py',
        '.\tools\v011_edr_acceptance.py',
        '.\tools\v011_beta2_hunting_acceptance.py'
    )
    foreach ($item in $required) {
        if (-not (Test-Path -LiteralPath $item)) {
            throw ('Missing checkpoint file: ' + $item)
        }
    }

    Write-Host 'BC Sentinel v0.11.0-beta.2 - CHECKPOINT A: Indexed Retrospective Hunting' -ForegroundColor Cyan

    & $Py -m pytest -q tests\test_v011_beta1_edr_foundation.py tests\test_v011_beta1_edr_adapter.py tests\test_v011_beta2_hunting.py
    if ($LASTEXITCODE -ne 0) {
        throw 'Beta1 EDR regressions or Beta2 hunting tests failed'
    }

    & $Py -m tools.v011_edr_acceptance --output acceptance-v011-beta2-beta1-edr-regression.json
    if ($LASTEXITCODE -ne 0) {
        throw 'Beta1 EDR acceptance regression failed'
    }

    & $Py -m tools.v011_beta2_hunting_acceptance --output acceptance-v011-beta2-hunting.json
    if ($LASTEXITCODE -ne 0) {
        throw 'Beta2 retrospective hunting acceptance failed'
    }

    & $Py -m compileall -q sentinel\edr.py sentinel\edr_adapter.py sentinel\edr_hunting.py tools\v011_beta2_hunting_acceptance.py
    if ($LASTEXITCODE -ne 0) {
        throw 'Beta2 checkpoint compileall failed'
    }

    Write-Host 'BC SENTINEL v0.11.0-beta.2 CHECKPOINT A - PASS' -ForegroundColor Green
    Write-Host 'Validated: indexed IOC hunting, bounded pagination, incident evidence navigation, root-cause view and retention bounds.' -ForegroundColor Green
    Write-Host 'Not yet claimed: Protection Service ownership, authenticated EDR IPC endpoints, continuous service-native ingestion or Security Center Inbox integration.' -ForegroundColor Yellow
    exit 0
}
catch {
    Fail $_.Exception.Message
}
