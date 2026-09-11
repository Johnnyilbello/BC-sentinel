param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Stage,[string]$Message) {
    Write-Host ('B42 FAIL STAGE=' + $Stage + ' | ' + $Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.4 B4-2 GUIDED REPAIR HANDOFF - FAIL' -ForegroundColor Red
    exit 1
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Fail 'preflight' 'Run B4-2 from normal non-elevated PowerShell.' }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { Fail 'preflight' '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.4 - B4-2 GUIDED REPAIR HANDOFF' -ForegroundColor Cyan
    Write-Host 'Console prepares a trusted RR4B handoff only. Execution and rollback remain delegated to frozen RR4B semantics.' -ForegroundColor Yellow

    $Protected = @('.\sentinel\protection_service_core.py','.\sentinel\realtime.py','.\sentinel\edr.py','.\sentinel\edr_service_bridge.py')
    $BeforeProtected = @{}
    foreach ($path in $Protected) {
        if (-not (Test-Path -LiteralPath $path)) { Fail 'preflight' ('protected source missing: ' + $path) }
        $BeforeProtected[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    $Base = Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    New-Item -ItemType Directory -Path $Base -Force | Out-Null
    $ProcessTemp = Join-Path $Base ('b42-process-' + [guid]::NewGuid().ToString('N'))
    $PytestTemp = Join-Path $Base ('b42-pytest-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $ProcessTemp -Force | Out-Null
    $OldTemp = $env:TEMP; $OldTmp = $env:TMP
    $env:TEMP = $ProcessTemp; $env:TMP = $ProcessTemp
    Write-Host ('B42 PYTEST BASETEMP=' + $PytestTemp) -ForegroundColor DarkGray

    try {
        & $Py -m compileall -q sentinel\rescue_console_guided_repair.py tools\v011_beta4_b42_acceptance.py tests\test_v011_beta4_b42_guided_repair_handoff.py
        if ($LASTEXITCODE -ne 0) { Fail 'compileall' 'B4-2 compileall failed' }

        $Tests = @(
            'tests/test_v011_beta3_rr0_rescue_contract.py',
            'tests/test_v011_beta3_rr1_portable.py',
            'tests/test_v011_beta3_rr2_rescue_usb.py',
            'tests/test_v011_beta3_rr3_offline_scanner.py',
            'tests/test_v011_beta3_rr4a_repair_engine.py',
            'tests/test_v011_beta3_rr4b_portable_repair.py',
            'tests/test_v011_beta3_rr5_safe_data_rescue.py',
            'tests/test_v011_beta3_rr6_integrity_certification.py',
            'tests/test_v011_beta4_b40_rescue_console.py',
            'tests/test_v011_beta4_b41_evidence_inventory_guided_scan.py',
            'tests/test_v011_beta4_b42_guided_repair_handoff.py'
        )
        & $Py -m pytest -q --basetemp $PytestTemp @Tests
        if ($LASTEXITCODE -ne 0) { Fail 'pytest' 'Beta3 + B4-0..B4-2 regression failed' }

        foreach ($spec in @(
            @('rr0','tools.v011_beta3_rr0_acceptance','acceptance-v011-beta3-rr0-b42-regression.json'),
            @('rr1','tools.v011_beta3_rr1_acceptance','acceptance-v011-beta3-rr1-b42-regression.json'),
            @('rr2','tools.v011_beta3_rr2_acceptance','acceptance-v011-beta3-rr2-b42-regression.json'),
            @('rr3','tools.v011_beta3_rr3_acceptance','acceptance-v011-beta3-rr3-b42-regression.json'),
            @('rr4a','tools.v011_beta3_rr4a_acceptance','acceptance-v011-beta3-rr4a-b42-regression.json'),
            @('rr4b','tools.v011_beta3_rr4b_acceptance','acceptance-v011-beta3-rr4b-b42-regression.json'),
            @('rr5','tools.v011_beta3_rr5_acceptance','acceptance-v011-beta3-rr5-b42-regression.json'),
            @('rr6','tools.v011_beta3_rr6_acceptance','acceptance-v011-beta3-rr6-b42-regression.json'),
            @('b40','tools.v011_beta4_b40_acceptance','acceptance-v011-beta4-b40-b42-regression.json'),
            @('b41','tools.v011_beta4_b41_acceptance','acceptance-v011-beta4-b41-b42-regression.json'),
            @('b42','tools.v011_beta4_b42_acceptance','acceptance-v011-beta4-b42.json')
        )) {
            & $Py -m $spec[1] --output $spec[2]
            if ($LASTEXITCODE -ne 0) { Fail ('acceptance-' + $spec[0]) ($spec[0] + ' deterministic acceptance failed') }
        }

        $RunRoot = Join-Path $Base ('b42-live-' + [guid]::NewGuid().ToString('N'))
        $Offline = Join-Path $RunRoot 'offline-target'
        $Workspace = Join-Path $RunRoot 'workspace'
        $Config = Join-Path $Offline 'Windows\System32\config'
        $Drivers = Join-Path $Offline 'Windows\System32\drivers'
        New-Item -ItemType Directory -Path $Config,$Drivers -Force | Out-Null
        [IO.File]::WriteAllBytes((Join-Path $Config 'SYSTEM'), [Text.Encoding]::UTF8.GetBytes('B42 LIVE SYSTEM'))
        [IO.File]::WriteAllBytes((Join-Path $Config 'SOFTWARE'), [Text.Encoding]::UTF8.GetBytes('B42 LIVE SOFTWARE'))
        [IO.File]::WriteAllBytes((Join-Path $Offline 'Windows\System32\ntoskrnl.exe'), [Text.Encoding]::UTF8.GetBytes('MZ B42 LIVE KERNEL'))
        $RepairTarget = Join-Path $Drivers 'repairable.sys'
        [IO.File]::WriteAllBytes($RepairTarget, [Text.Encoding]::UTF8.GetBytes('B42 LIVE ORIGINAL DRIVER'))
        $BeforeRepairTarget = (Get-FileHash -LiteralPath $RepairTarget -Algorithm SHA256).Hash.ToLowerInvariant()

        New-Item -ItemType Directory -Path $Workspace -Force | Out-Null
        $PlanPath = Join-Path $Workspace 'session-plan.json'
        & $Py -m sentinel.rescue_console --target-root $Offline --workspace $Workspace --output-plan $PlanPath | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail 'live-b40' 'B4-0 session plan failed' }
        $Plan = Get-Content -Raw -LiteralPath $PlanPath -Encoding UTF8 | ConvertFrom-Json

        & $Py -m sentinel.rescue_console_guided_scan --target-root $Offline --workspace $Workspace --run-scan | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail 'live-b41' 'B4-1 fresh guided scan failed' }
        $ScanPath = Join-Path $Workspace 'rr3\rr3-offline-scan.json'
        if (-not (Test-Path -LiteralPath $ScanPath)) { Fail 'live-b41' 'RR3 scan evidence missing' }
        $ScanHash = (Get-FileHash -LiteralPath $ScanPath -Algorithm SHA256).Hash.ToLowerInvariant()

        $Replacement = Join-Path $RunRoot 'trusted-replacement.sys'
        [IO.File]::WriteAllBytes($Replacement, [Text.Encoding]::UTF8.GetBytes('B42 LIVE REPLACEMENT DRIVER'))
        $ReplacementHash = (Get-FileHash -LiteralPath $Replacement -Algorithm SHA256).Hash.ToLowerInvariant()
        $OperationsPath = Join-Path $Workspace 'approved-operations.json'
        $Operations = [ordered]@{
            schema = 'bc-sentinel-rr4b-operations-v1'
            approved = $true
            target_fingerprint = [string]$Plan.target_fingerprint
            source_scan_sha256 = $ScanHash
            operations = @(
                [ordered]@{
                    relative_path = 'Windows/System32/drivers/repairable.sys'
                    expected_sha256 = $BeforeRepairTarget
                    replacement_source = $Replacement
                    replacement_sha256 = $ReplacementHash
                    evidence_reference = ('rr3:' + $ScanHash)
                }
            )
        }
        [IO.File]::WriteAllText($OperationsPath, ($Operations | ConvertTo-Json -Depth 8) + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))

        & $Py -m sentinel.rescue_console_guided_repair --target-root $Offline --workspace $Workspace --trusted-scan $ScanPath --operations-file $OperationsPath | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail 'live-b42' 'B4-2 guided repair handoff preparation failed' }
        $HandoffPath = Join-Path $Workspace 'b42-repair-handoff.json'
        if (-not (Test-Path -LiteralPath $HandoffPath)) { Fail 'live-b42' 'B4-2 handoff manifest missing' }
        $Handoff = Get-Content -Raw -LiteralPath $HandoffPath -Encoding UTF8 | ConvertFrom-Json

        if ([string]$Handoff.profile -ne 'v0.11.0-beta.4-b42') { Fail 'live-b42' 'unexpected B4-2 profile' }
        if (-not [bool]$Handoff.operator_confirmation_required) { Fail 'live-b42' 'operator confirmation requirement missing' }
        if ([bool]$Handoff.execution_performed) { Fail 'live-safety' 'B4-2 unexpectedly executed repair' }
        if ([bool]$Handoff.automatic_execution) { Fail 'live-safety' 'B4-2 automatic execution unexpectedly enabled' }
        if ([bool]$Handoff.automatic_repair) { Fail 'live-safety' 'B4-2 automatic repair unexpectedly enabled' }
        if ([string]$Handoff.confirmation_token -notmatch '^CONFIRM-RR4A-[0-9A-F]{16}$') { Fail 'live-b42' 'invalid plan-bound confirmation token' }
        if ([string]$Handoff.plan_sha256 -notmatch '^[0-9a-f]{64}$') { Fail 'live-b42' 'invalid RR4B plan SHA256' }
        if ([string]$Handoff.trusted_scan_sha256 -ne $ScanHash) { Fail 'live-b42' 'handoff scan binding mismatch' }
        if ([string]$Handoff.target_fingerprint -ne [string]$Plan.target_fingerprint) { Fail 'live-b42' 'handoff target fingerprint mismatch' }

        $AfterRepairTarget = (Get-FileHash -LiteralPath $RepairTarget -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($AfterRepairTarget -ne $BeforeRepairTarget) { Fail 'target-integrity' 'B4-2 handoff preparation modified repair target' }

        $Services = @(Get-CimInstance Win32_Service | Where-Object { ([string]$_.PathName).ToLowerInvariant().Contains('bc-sentinel-rescue-console') })
        if ($Services.Count -ne 0) { Fail 'live-safety' 'B4-2 unexpectedly registered a Windows service' }

        foreach ($path in $Protected) {
            $after = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($after -ne $BeforeProtected[$path]) { Fail 'protected-source' ('B4-2 modified protected B2 source: ' + $path) }
        }

        Write-Host ('B42 LIVE TARGET FINGERPRINT=' + [string]$Handoff.target_fingerprint) -ForegroundColor Green
        Write-Host ('B42 LIVE SESSION=' + [string]$Handoff.session_id + ' CORRELATION=' + [string]$Handoff.correlation_id) -ForegroundColor Green
        Write-Host ('B42 LIVE RR3 SCAN SHA256=' + [string]$Handoff.trusted_scan_sha256) -ForegroundColor Green
        Write-Host ('B42 LIVE RR4B PLAN SHA256=' + [string]$Handoff.plan_sha256) -ForegroundColor Green
        Write-Host 'B42 LIVE: trusted scan binding PASS | approved operations binding PASS | plan-bound confirmation PASS | RR4B regression execute/rollback PASS | no console auto-repair | target unchanged | no service | B2 sources unchanged' -ForegroundColor Green
        Write-Host 'BC SENTINEL v0.11.0-beta.4 B4-2 GUIDED REPAIR HANDOFF - PASS' -ForegroundColor Green
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
