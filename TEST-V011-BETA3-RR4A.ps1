param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Stage,[string]$Message) {
    Write-Host ('RR4A FAIL STAGE=' + $Stage + ' | ' + $Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.3 RR-4A REVERSIBLE TRANSACTION CORE - FAIL' -ForegroundColor Red
    exit 1
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Fail 'preflight' 'Run RR4A acceptance from normal non-elevated PowerShell.'
    }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { Fail 'preflight' '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.3 - RR-4A REVERSIBLE TRANSACTION CORE' -ForegroundColor Cyan
    Write-Host 'Offline harmless-fixture mutation only. Exact plan confirmation + rollback required. No live repair/registry/boot write/certification.' -ForegroundColor Yellow

    $Protected = @(
        '.\sentinel\protection_service_core.py',
        '.\sentinel\realtime.py',
        '.\sentinel\edr.py',
        '.\sentinel\edr_service_bridge.py'
    )
    $BeforeProtected = @{}
    foreach ($path in $Protected) {
        if (-not (Test-Path -LiteralPath $path)) { Fail 'preflight' ('protected source missing: ' + $path) }
        $BeforeProtected[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    & $Py -m compileall -q sentinel\rescue_contract.py sentinel\rescue_portable.py sentinel\rescue_usb.py sentinel\rescue_offline_scanner.py sentinel\rescue_repair_engine.py tools\v011_beta3_rr0_acceptance.py tools\v011_beta3_rr1_acceptance.py tools\v011_beta3_rr2_acceptance.py tools\v011_beta3_rr3_acceptance.py tools\v011_beta3_rr4a_acceptance.py tests\test_v011_beta3_rr4a_repair_engine.py
    if ($LASTEXITCODE -ne 0) { Fail 'compileall' 'RR4A compileall failed' }

    $Base = Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    if (-not (Test-Path -LiteralPath $Base)) { New-Item -ItemType Directory -Path $Base -Force | Out-Null }
    $PytestRoot = Join-Path $Base ('rr4a-pytest-' + [guid]::NewGuid().ToString('N'))
    Write-Host ('RR4A PYTEST BASETEMP=' + $PytestRoot) -ForegroundColor DarkGray
    try {
        & $Py -m pytest -q --basetemp $PytestRoot tests/test_v011_beta3_rr0_rescue_contract.py tests/test_v011_beta3_rr1_portable.py tests/test_v011_beta3_rr2_rescue_usb.py tests/test_v011_beta3_rr3_offline_scanner.py tests/test_v011_beta3_rr4a_repair_engine.py
        if ($LASTEXITCODE -ne 0) { Fail 'pytest' 'RR0/RR1/RR2/RR3/RR4A regression failed' }
    }
    finally {
        Remove-Item -LiteralPath $PytestRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    foreach ($spec in @(
        @('rr0','tools.v011_beta3_rr0_acceptance','acceptance-v011-beta3-rr0-regression.json'),
        @('rr1','tools.v011_beta3_rr1_acceptance','acceptance-v011-beta3-rr1-regression.json'),
        @('rr2','tools.v011_beta3_rr2_acceptance','acceptance-v011-beta3-rr2-regression.json'),
        @('rr3','tools.v011_beta3_rr3_acceptance','acceptance-v011-beta3-rr3-regression.json')
    )) {
        & $Py -m $spec[1] --output $spec[2]
        if ($LASTEXITCODE -ne 0) { Fail ('acceptance-' + $spec[0]) ($spec[0] + ' regression acceptance failed') }
    }

    $AcceptanceTemp = Join-Path $Base ('rr4a-acceptance-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $AcceptanceTemp -Force | Out-Null
    $OldTemp = $env:TEMP
    $OldTmp = $env:TMP
    try {
        $env:TEMP = $AcceptanceTemp
        $env:TMP = $AcceptanceTemp
        Write-Host ('RR4A ACCEPTANCE TEMP=' + $AcceptanceTemp) -ForegroundColor DarkGray
        & $Py -m tools.v011_beta3_rr4a_acceptance --output acceptance-v011-beta3-rr4a.json
        if ($LASTEXITCODE -ne 0) { Fail 'acceptance-rr4a' 'RR4A deterministic reversible transaction acceptance failed' }
    }
    finally {
        $env:TEMP = $OldTemp
        $env:TMP = $OldTmp
        Remove-Item -LiteralPath $AcceptanceTemp -Recurse -Force -ErrorAction SilentlyContinue
    }

    $Acceptance = Get-Content -Raw -LiteralPath '.\acceptance-v011-beta3-rr4a.json' -Encoding UTF8 | ConvertFrom-Json
    if (-not [bool]$Acceptance.passed) { Fail 'acceptance-json' 'RR4A acceptance JSON reports passed=false' }
    $RequiredChecks = @(
        'wrong_confirmation_refused',
        'unchanged_after_wrong_confirmation',
        'repair_applied',
        'verified_backup_before_write',
        'manual_rollback_passed',
        'manual_rollback_restored',
        'stale_precondition_refused',
        'stale_target_preserved',
        'partial_failure_rollback_triggered',
        'partial_failure_restored_all',
        'no_automatic_action',
        'no_recovery_certification'
    )
    foreach ($name in $RequiredChecks) {
        if (-not [bool]$Acceptance.checks.$name) { Fail 'acceptance-json' ('required RR4A check false: ' + $name) }
    }

    foreach ($path in $Protected) {
        $after = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($after -ne $BeforeProtected[$path]) { Fail 'protected-source' ('RR4A modified protected B2 source: ' + $path) }
    }

    Write-Host ('RR4A PLAN SHA256=' + [string]$Acceptance.detail.plan_sha256) -ForegroundColor Green
    Write-Host ('RR4A SESSION=' + [string]$Acceptance.detail.session_id) -ForegroundColor Green
    Write-Host 'RR4A LIVE FIXTURE: exact confirmation PASS | verified backup PASS | repair PASS | manual rollback PASS | stale-state refusal PASS | partial-failure rollback PASS | B2 sources unchanged' -ForegroundColor Green
    Write-Host 'BC SENTINEL v0.11.0-beta.3 RR-4A REVERSIBLE TRANSACTION CORE - PASS' -ForegroundColor Green
    exit 0
}
catch {
    Fail 'unhandled' $_.Exception.Message
}
