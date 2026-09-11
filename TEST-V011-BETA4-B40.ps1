param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Stage,[string]$Message) {
    Write-Host ('B40 FAIL STAGE=' + $Stage + ' | ' + $Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.4 B4-0 RESCUE CONSOLE FOUNDATION - FAIL' -ForegroundColor Red
    exit 1
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Fail 'preflight' 'Run B4-0 from normal non-elevated PowerShell.' }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { Fail 'preflight' '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.4 - B4-0 RESCUE CONSOLE ORCHESTRATOR FOUNDATION' -ForegroundColor Cyan
    Write-Host 'Read-only orchestration only. Operational stages remain planned-only and operator-gated.' -ForegroundColor Yellow

    $Protected = @('.\sentinel\protection_service_core.py','.\sentinel\realtime.py','.\sentinel\edr.py','.\sentinel\edr_service_bridge.py')
    $BeforeProtected = @{}
    foreach ($path in $Protected) {
        if (-not (Test-Path -LiteralPath $path)) { Fail 'preflight' ('protected source missing: ' + $path) }
        $BeforeProtected[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    $Base = Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    New-Item -ItemType Directory -Path $Base -Force | Out-Null
    $ProcessTemp = Join-Path $Base ('b40-process-' + [guid]::NewGuid().ToString('N'))
    $PytestTemp = Join-Path $Base ('b40-pytest-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $ProcessTemp -Force | Out-Null
    $OldTemp = $env:TEMP; $OldTmp = $env:TMP
    $env:TEMP = $ProcessTemp; $env:TMP = $ProcessTemp
    Write-Host ('B40 PYTEST BASETEMP=' + $PytestTemp) -ForegroundColor DarkGray

    try {
        & $Py -m compileall -q sentinel\rescue_console.py tools\v011_beta4_b40_acceptance.py tests\test_v011_beta4_b40_rescue_console.py
        if ($LASTEXITCODE -ne 0) { Fail 'compileall' 'B4-0 compileall failed' }

        $Tests = @(
            'tests/test_v011_beta3_rr0_rescue_contract.py',
            'tests/test_v011_beta3_rr1_portable.py',
            'tests/test_v011_beta3_rr2_rescue_usb.py',
            'tests/test_v011_beta3_rr3_offline_scanner.py',
            'tests/test_v011_beta3_rr4a_repair_engine.py',
            'tests/test_v011_beta3_rr4b_portable_repair.py',
            'tests/test_v011_beta3_rr5_safe_data_rescue.py',
            'tests/test_v011_beta3_rr6_integrity_certification.py',
            'tests/test_v011_beta4_b40_rescue_console.py'
        )
        & $Py -m pytest -q --basetemp $PytestTemp @Tests
        if ($LASTEXITCODE -ne 0) { Fail 'pytest' 'Beta3 + B4-0 regression failed' }

        foreach ($spec in @(
            @('rr0','tools.v011_beta3_rr0_acceptance','acceptance-v011-beta3-rr0-b40-regression.json'),
            @('rr1','tools.v011_beta3_rr1_acceptance','acceptance-v011-beta3-rr1-b40-regression.json'),
            @('rr2','tools.v011_beta3_rr2_acceptance','acceptance-v011-beta3-rr2-b40-regression.json'),
            @('rr3','tools.v011_beta3_rr3_acceptance','acceptance-v011-beta3-rr3-b40-regression.json'),
            @('rr4a','tools.v011_beta3_rr4a_acceptance','acceptance-v011-beta3-rr4a-b40-regression.json'),
            @('rr4b','tools.v011_beta3_rr4b_acceptance','acceptance-v011-beta3-rr4b-b40-regression.json'),
            @('rr5','tools.v011_beta3_rr5_acceptance','acceptance-v011-beta3-rr5-b40-regression.json'),
            @('rr6','tools.v011_beta3_rr6_acceptance','acceptance-v011-beta3-rr6-b40-regression.json'),
            @('b40','tools.v011_beta4_b40_acceptance','acceptance-v011-beta4-b40.json')
        )) {
            & $Py -m $spec[1] --output $spec[2]
            if ($LASTEXITCODE -ne 0) { Fail ('acceptance-' + $spec[0]) ($spec[0] + ' deterministic acceptance failed') }
        }

        $RunRoot = Join-Path $Base ('b40-live-' + [guid]::NewGuid().ToString('N'))
        $Offline = Join-Path $RunRoot 'offline-target'
        $Workspace = Join-Path $RunRoot 'workspace'
        New-Item -ItemType Directory -Path (Join-Path $Offline 'Windows\System32\config') -Force | Out-Null
        [IO.File]::WriteAllBytes((Join-Path $Offline 'Windows\System32\config\SYSTEM'), [Text.Encoding]::UTF8.GetBytes('B40 LIVE SYSTEM'))
        [IO.File]::WriteAllBytes((Join-Path $Offline 'Windows\System32\config\SOFTWARE'), [Text.Encoding]::UTF8.GetBytes('B40 LIVE SOFTWARE'))
        [IO.File]::WriteAllBytes((Join-Path $Offline 'Windows\System32\ntoskrnl.exe'), [Text.Encoding]::UTF8.GetBytes('MZ B40 LIVE KERNEL'))

        $BeforeTarget = @{}
        Get-ChildItem -LiteralPath $Offline -File -Recurse | ForEach-Object { $BeforeTarget[$_.FullName] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }

        $PlanPath = Join-Path $Workspace 'session-plan.json'
        & $Py -m sentinel.rescue_console --target-root $Offline --workspace $Workspace --output-plan $PlanPath
        if ($LASTEXITCODE -ne 0) { Fail 'live-plan' 'B4-0 live session planning failed' }
        if (-not (Test-Path -LiteralPath $PlanPath)) { Fail 'live-plan' 'B4-0 session plan was not created' }

        $Plan = Get-Content -Raw -LiteralPath $PlanPath -Encoding UTF8 | ConvertFrom-Json
        if ([string]$Plan.profile -ne 'v0.11.0-beta.4-b40') { Fail 'live-plan' 'unexpected B4-0 profile' }
        if ([string]$Plan.schema -ne 'bc-sentinel-beta4-rescue-console-plan-v1') { Fail 'live-plan' 'unexpected B4-0 plan schema' }
        if ([string]$Plan.plan_sha256 -notmatch '^[0-9a-f]{64}$') { Fail 'live-plan' 'plan SHA256 missing/invalid' }
        if ([bool]$Plan.safety.automatic_execution) { Fail 'live-safety' 'automatic execution unexpectedly enabled' }
        if ([bool]$Plan.safety.automatic_repair) { Fail 'live-safety' 'automatic repair unexpectedly enabled' }
        if ([bool]$Plan.safety.automatic_quarantine) { Fail 'live-safety' 'automatic quarantine unexpectedly enabled' }

        $ExpectedStages = @('target_validation','evidence_inventory','offline_scan','repair_review','safe_data_rescue','integrity_certification')
        $ActualStages = @($Plan.stages | ForEach-Object { [string]$_.stage })
        if (($ActualStages -join '|') -ne ($ExpectedStages -join '|')) { Fail 'live-plan' ('stage order mismatch: ' + ($ActualStages -join ',')) }
        $PlannedStages = @($Plan.stages | Where-Object { [string]$_.mode -eq 'planned_only' })
        if ($PlannedStages.Count -lt 4) { Fail 'live-plan' 'expected planned-only operational stages missing' }
        foreach ($stage in $PlannedStages) {
            if (-not [bool]$stage.operator_gate) { Fail 'live-safety' ('planned stage lacks operator gate: ' + [string]$stage.stage) }
            if ([bool]$stage.automatic_execution) { Fail 'live-safety' ('automatic execution enabled for stage: ' + [string]$stage.stage) }
        }

        foreach ($p in $BeforeTarget.Keys) {
            $after = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
            if ($after -ne $BeforeTarget[$p]) { Fail 'target-integrity' ('B4-0 modified target: ' + $p) }
        }

        $Services = @(Get-CimInstance Win32_Service | Where-Object { ([string]$_.PathName).ToLowerInvariant().Contains('bc-sentinel-rescue-console') })
        if ($Services.Count -ne 0) { Fail 'live-safety' 'B4-0 unexpectedly registered a Windows service' }

        foreach ($path in $Protected) {
            $after = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($after -ne $BeforeProtected[$path]) { Fail 'protected-source' ('B4-0 modified protected B2 source: ' + $path) }
        }

        Write-Host ('B40 LIVE TARGET FINGERPRINT=' + [string]$Plan.target_fingerprint) -ForegroundColor Green
        Write-Host ('B40 LIVE SESSION=' + [string]$Plan.session_id + ' CORRELATION=' + [string]$Plan.correlation_id) -ForegroundColor Green
        Write-Host ('B40 LIVE PLAN SHA256=' + [string]$Plan.plan_sha256) -ForegroundColor Green
        Write-Host 'B40 LIVE: exact stage order PASS | module inventory PASS | operator gates PASS | no automatic execution | target unchanged | no service | B2 sources unchanged' -ForegroundColor Green
        Write-Host 'BC SENTINEL v0.11.0-beta.4 B4-0 RESCUE CONSOLE FOUNDATION - PASS' -ForegroundColor Green
        exit 0
    }
    finally {
        $env:TEMP = $OldTemp; $env:TMP = $OldTmp
        Remove-Item -LiteralPath $PytestTemp -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $ProcessTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
catch {
    Fail 'unhandled' $_.Exception.Message
}
