param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Stage,[string]$Message) {
    Write-Host ('RR4B FAIL STAGE=' + $Stage + ' | ' + $Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.3 RR-4B PORTABLE REPAIR ENGINE - FAIL' -ForegroundColor Red
    exit 1
}

function Read-JsonText([string]$Text) {
    try { return ($Text | ConvertFrom-Json) } catch { return $null }
}

function Read-JsonFile([string]$Path) {
    try {
        if (Test-Path -LiteralPath $Path) { return (Get-Content -Raw -LiteralPath $Path -Encoding UTF8 | ConvertFrom-Json) }
    } catch { }
    return $null
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Fail 'preflight' 'Run RR4B acceptance from normal non-elevated PowerShell.'
    }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { Fail 'preflight' '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.3 - RR-4B PORTABLE REPAIR ENGINE' -ForegroundColor Cyan
    Write-Host 'Offline harmless-fixture repair only. Exact plan confirmation and verified rollback required; no live-host/registry/boot repair.' -ForegroundColor Yellow

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

    $Base = Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    if (-not (Test-Path -LiteralPath $Base)) { New-Item -ItemType Directory -Path $Base -Force | Out-Null }
    $ProcessTemp = Join-Path $Base ('rr4b-process-temp-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $ProcessTemp -Force | Out-Null
    $OldTemp = $env:TEMP
    $OldTmp = $env:TMP
    $env:TEMP = $ProcessTemp
    $env:TMP = $ProcessTemp

    try {
        & $Py -m compileall -q sentinel\rescue_contract.py sentinel\rescue_portable.py sentinel\rescue_usb.py sentinel\rescue_offline_scanner.py sentinel\rescue_repair_engine.py sentinel\rescue_repair_portable.py tools\v011_beta3_rr4a_acceptance.py tools\v011_beta3_rr4b_acceptance.py tests\test_v011_beta3_rr4a_repair_engine.py tests\test_v011_beta3_rr4b_portable_repair.py
        if ($LASTEXITCODE -ne 0) { Fail 'compileall' 'RR4B compileall failed' }

        $PytestRoot = Join-Path $Base ('rr4b-pytest-' + [guid]::NewGuid().ToString('N'))
        Write-Host ('RR4B PYTEST BASETEMP=' + $PytestRoot) -ForegroundColor DarkGray
        try {
            & $Py -m pytest -q --basetemp $PytestRoot tests/test_v011_beta3_rr0_rescue_contract.py tests/test_v011_beta3_rr1_portable.py tests/test_v011_beta3_rr2_rescue_usb.py tests/test_v011_beta3_rr3_offline_scanner.py tests/test_v011_beta3_rr4a_repair_engine.py tests/test_v011_beta3_rr4b_portable_repair.py
            if ($LASTEXITCODE -ne 0) { Fail 'pytest' 'RR0/RR1/RR2/RR3/RR4A/RR4B regression failed' }
        }
        finally {
            Remove-Item -LiteralPath $PytestRoot -Recurse -Force -ErrorAction SilentlyContinue
        }

        foreach ($spec in @(
            @('rr0','tools.v011_beta3_rr0_acceptance','acceptance-v011-beta3-rr0-regression.json'),
            @('rr1','tools.v011_beta3_rr1_acceptance','acceptance-v011-beta3-rr1-regression.json'),
            @('rr2','tools.v011_beta3_rr2_acceptance','acceptance-v011-beta3-rr2-regression.json'),
            @('rr3','tools.v011_beta3_rr3_acceptance','acceptance-v011-beta3-rr3-regression.json'),
            @('rr4a','tools.v011_beta3_rr4a_acceptance','acceptance-v011-beta3-rr4a-regression.json'),
            @('rr4b','tools.v011_beta3_rr4b_acceptance','acceptance-v011-beta3-rr4b.json')
        )) {
            & $Py -m $spec[1] --output $spec[2]
            if ($LASTEXITCODE -ne 0) { Fail ('acceptance-' + $spec[0]) ($spec[0] + ' deterministic acceptance failed') }
        }

        Write-Host 'Building portable RR4B repair engine...' -ForegroundColor DarkCyan
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\BUILD-RESCUE-REPAIR-PORTABLE.ps1'
        if ($LASTEXITCODE -ne 0) { Fail 'build' 'RR4B portable repair build failed' }

        $Folder = Join-Path $PSScriptRoot 'dist\Rescue\BC-Sentinel-Rescue-Repair-Portable'
        $Exe = Join-Path $Folder 'BC-Sentinel-Rescue-Repair-Portable.exe'
        $IntegrityPath = Join-Path $Folder 'repair-portable-integrity.json'
        $Integrity = Read-JsonFile $IntegrityPath
        if ($null -eq $Integrity) { Fail 'provenance' 'RR4B integrity manifest missing/unreadable' }
        if ([string]$Integrity.profile -ne 'v0.11.0-beta.3-rr4b') { Fail 'provenance' 'RR4B integrity profile mismatch' }
        $ActualHash = (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($ActualHash -ne ([string]$Integrity.sha256).ToLowerInvariant()) { Fail 'provenance' 'RR4B binary SHA256 mismatch' }
        if (-not [bool]$Integrity.offline_target_only -or [bool]$Integrity.live_host_repair -or [bool]$Integrity.registry_write -or [bool]$Integrity.boot_write -or [bool]$Integrity.automatic_repair -or [bool]$Integrity.recovery_certification) {
            Fail 'provenance' 'RR4B build manifest exposes unsafe capability flags'
        }

        $RunRoot = Join-Path $Base ('rr4b-live-' + [guid]::NewGuid().ToString('N'))
        $Offline = Join-Path $RunRoot 'offline-target'
        $Config = Join-Path $Offline 'Windows\System32\config'
        $TargetDir = Join-Path $Offline 'Program Files\Demo'
        $Trusted = Join-Path $RunRoot 'trusted-media'
        $Rollback1 = Join-Path $RunRoot 'rollback-1'
        $Rollback2 = Join-Path $RunRoot 'rollback-2'
        New-Item -ItemType Directory -Path $Config -Force | Out-Null
        New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
        New-Item -ItemType Directory -Path $Trusted -Force | Out-Null
        [IO.File]::WriteAllBytes((Join-Path $Config 'SYSTEM'), [Text.Encoding]::UTF8.GetBytes('RR4B LIVE SYSTEM HIVE'))
        [IO.File]::WriteAllBytes((Join-Path $Offline 'Windows\System32\ntoskrnl.exe'), [Text.Encoding]::UTF8.GetBytes('MZ RR4B harmless live kernel fixture'))
        $Target = Join-Path $TargetDir 'component.dll'
        $Replacement = Join-Path $Trusted 'component-clean.dll'
        [IO.File]::WriteAllBytes($Target, [Text.Encoding]::UTF8.GetBytes('RR4B harmless original component'))
        [IO.File]::WriteAllBytes($Replacement, [Text.Encoding]::UTF8.GetBytes('RR4B harmless trusted replacement'))
        $BeforeHash = (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash.ToLowerInvariant()
        $ReplacementHash = (Get-FileHash -LiteralPath $Replacement -Algorithm SHA256).Hash.ToLowerInvariant()

        $OperationsPath = Join-Path $RunRoot 'approved-operations.json'
        $Operations = [ordered]@{
            schema = 'bc-sentinel-rr4b-operations-v1'
            approved = $true
            operations = @([ordered]@{
                relative_path = 'Program Files/Demo/component.dll'
                expected_sha256 = $BeforeHash
                replacement_source = $Replacement
                replacement_sha256 = $ReplacementHash
                evidence_reference = 'RR3:windows-live-harmless-fixture'
            })
        }
        $OpsJson = $Operations | ConvertTo-Json -Depth 8
        [IO.File]::WriteAllText($OperationsPath, $OpsJson + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
        $PlanPath = Join-Path $RunRoot 'repair-plan.json'

        Write-Host ('RR4B LIVE ROOT=' + $Offline) -ForegroundColor DarkGray
        Write-Host ('RR4B LIVE PLAN=' + $PlanPath) -ForegroundColor DarkGray
        $PlanText = (& $Exe plan --target-root $Offline --operations-file $OperationsPath --output-plan $PlanPath | Out-String)
        if ($LASTEXITCODE -ne 0) { Fail 'live-plan' 'built RR4B plan command failed' }
        $PlanResult = Read-JsonText $PlanText
        if ($null -eq $PlanResult -or -not [bool]$PlanResult.passed) { Fail 'live-plan' 'RR4B plan result missing/unreadable' }
        $PlanSha = [string]$PlanResult.plan_sha256
        if ($PlanSha.Length -ne 64) { Fail 'live-plan' 'RR4B plan SHA256 invalid' }

        $TokenText = (& $Exe confirmation --plan $PlanPath | Out-String)
        if ($LASTEXITCODE -ne 0) { Fail 'live-confirmation' 'RR4B confirmation command failed' }
        $TokenResult = Read-JsonText $TokenText
        $Confirmation = [string]$TokenResult.confirmation_token
        if (-not $Confirmation.StartsWith('CONFIRM-RR4A-')) { Fail 'live-confirmation' 'RR4B confirmation token invalid' }

        $WrongText = (& $Exe execute --plan $PlanPath --rollback-root $Rollback1 --confirmation 'WRONG' | Out-String)
        if ($LASTEXITCODE -eq 0) { Fail 'live-wrong-confirmation' 'RR4B accepted wrong confirmation' }
        $AfterWrong = (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($AfterWrong -ne $BeforeHash) { Fail 'live-wrong-confirmation' 'target changed after wrong confirmation' }

        $ExecuteText = (& $Exe execute --plan $PlanPath --rollback-root $Rollback1 --confirmation $Confirmation | Out-String)
        if ($LASTEXITCODE -ne 0) { Fail 'live-execute' 'RR4B execute failed' }
        $ExecuteResult = Read-JsonText $ExecuteText
        if ($null -eq $ExecuteResult -or -not [bool]$ExecuteResult.passed) { Fail 'live-execute' 'RR4B execute result missing/unreadable' }
        $AfterRepair = (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($AfterRepair -ne $ReplacementHash) { Fail 'live-execute' 'RR4B post-repair hash mismatch' }
        $Transaction = [string]$ExecuteResult.transaction_path
        if (-not (Test-Path -LiteralPath $Transaction)) { Fail 'live-execute' 'RR4B transaction journal missing' }

        $RollbackText = (& $Exe rollback --transaction $Transaction --confirmation $Confirmation | Out-String)
        if ($LASTEXITCODE -ne 0) { Fail 'live-rollback' 'RR4B manual rollback failed' }
        $RollbackResult = Read-JsonText $RollbackText
        if ($null -eq $RollbackResult -or -not [bool]$RollbackResult.passed -or [int]$RollbackResult.preflight_checked -ne 1) { Fail 'live-rollback' 'RR4B rollback result invalid' }
        $AfterRollback = (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($AfterRollback -ne $BeforeHash) { Fail 'live-rollback' 'RR4B rollback did not restore original hash' }

        $Execute2Text = (& $Exe execute --plan $PlanPath --rollback-root $Rollback2 --confirmation $Confirmation | Out-String)
        if ($LASTEXITCODE -ne 0) { Fail 'live-tamper-guard' 'RR4B second execute failed' }
        $Execute2 = Read-JsonText $Execute2Text
        $Transaction2 = [string]$Execute2.transaction_path
        [IO.File]::WriteAllBytes($Target, [Text.Encoding]::UTF8.GetBytes('RR4B third-party change after repair'))
        $TamperedHash = (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash.ToLowerInvariant()
        $TamperRollbackText = (& $Exe rollback --transaction $Transaction2 --confirmation $Confirmation | Out-String)
        if ($LASTEXITCODE -eq 0) { Fail 'live-tamper-guard' 'RR4B rollback ignored changed post-repair state' }
        $AfterRefusal = (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($AfterRefusal -ne $TamperedHash) { Fail 'live-tamper-guard' 'RR4B rollback refusal modified the changed target' }

        $Services = @(Get-CimInstance Win32_Service | Where-Object { ([string]$_.PathName).ToLowerInvariant().Contains('bc-sentinel-rescue-repair-portable.exe') })
        if ($Services.Count -ne 0) { Fail 'live-safety' 'RR4B unexpectedly registered a Windows service' }

        foreach ($path in $Protected) {
            $after = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($after -ne $BeforeProtected[$path]) { Fail 'protected-source' ('RR4B modified protected B2 source: ' + $path) }
        }

        Write-Host ('RR4B PORTABLE REPAIR BINARY SHA256=' + $ActualHash) -ForegroundColor Green
        Write-Host ('RR4B PLAN SHA256=' + $PlanSha) -ForegroundColor Green
        Write-Host 'RR4B LIVE: plan PASS | wrong confirmation zero-mutation PASS | repair PASS | verified manual rollback PASS | changed-post-state rollback refusal PASS | no service | B2 sources unchanged' -ForegroundColor Green
        Write-Host 'BC SENTINEL v0.11.0-beta.3 RR-4B PORTABLE REPAIR ENGINE - PASS' -ForegroundColor Green
        exit 0
    }
    finally {
        $env:TEMP = $OldTemp
        $env:TMP = $OldTmp
        Remove-Item -LiteralPath $ProcessTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
catch {
    Fail 'unhandled' $_.Exception.Message
}
