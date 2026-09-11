param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.3 RR-0 - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

try {
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.3 - RR-0 ARCHITECTURE & SAFETY' -ForegroundColor Cyan
    Write-Host 'Architecture-only gate: no repair, delete, registry/boot write, quarantine execution or recovery certification.' -ForegroundColor Yellow

    Write-Host 'Compiling RR-0 contract and acceptance tool...' -ForegroundColor DarkCyan
    & $Py -m compileall -q sentinel\rescue_contract.py tools\v011_beta3_rr0_acceptance.py tests\test_v011_beta3_rr0_rescue_contract.py
    if ($LASTEXITCODE -ne 0) { throw 'RR-0 compileall failed' }

    Write-Host 'Running RR-0 safety tests...' -ForegroundColor DarkCyan
    $Base = Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    if (-not (Test-Path -LiteralPath $Base)) { New-Item -ItemType Directory -Path $Base -Force | Out-Null }
    $Temp = Join-Path $Base ('rr0-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $Temp -Force | Out-Null
    try {
        & $Py -m pytest -q --basetemp $Temp tests/test_v011_beta3_rr0_rescue_contract.py
        if ($LASTEXITCODE -ne 0) { throw 'RR-0 safety test suite failed' }
    }
    finally {
        Remove-Item -LiteralPath $Temp -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host 'Running deterministic RR-0 acceptance...' -ForegroundColor DarkCyan
    & $Py -m tools.v011_beta3_rr0_acceptance --output acceptance-v011-beta3-rr0.json
    if ($LASTEXITCODE -ne 0) { throw 'RR-0 deterministic acceptance failed' }

    $result = Get-Content -Raw -LiteralPath '.\acceptance-v011-beta3-rr0.json' -Encoding UTF8 | ConvertFrom-Json
    if (-not [bool]$result.passed) { throw 'RR-0 acceptance JSON is not PASS' }
    if ([bool]$result.destructive_runtime_actions_added) { throw 'RR-0 unexpectedly enabled destructive runtime actions' }
    if ([bool]$result.repair_engine_enabled) { throw 'RR-0 unexpectedly enabled repair engine' }
    if ([bool]$result.quarantine_execution_enabled) { throw 'RR-0 unexpectedly enabled quarantine execution' }
    if ([bool]$result.recovery_certification_enabled) { throw 'RR-0 unexpectedly enabled recovery certification' }

    Write-Host 'BC SENTINEL v0.11.0-beta.3 RR-0 ARCHITECTURE & SAFETY - PASS' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
