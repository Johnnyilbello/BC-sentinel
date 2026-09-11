param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.2 B2 FILE-OBSERVATION REPAIR - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

function Read-JsonSafe([string]$Path) {
    try {
        if (Test-Path -LiteralPath $Path) { return (Get-Content -Raw -LiteralPath $Path -Encoding UTF8 | ConvertFrom-Json) }
    } catch { }
    return $null
}

function Download-RequiredFile([string]$Destination,[string]$Uri) {
    $parent = Split-Path -Parent $Destination
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Write-Host ('Downloading: ' + $Uri) -ForegroundColor DarkGray
    Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $Destination -ErrorAction Stop
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this repair from normal PowerShell; UAC separation is part of B2 acceptance.'
    }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }
    if (-not (Test-Path -LiteralPath '.\sentinel\realtime.py')) { throw 'sentinel\realtime.py missing from FULL tree' }
    if (-not (Test-Path -LiteralPath '.\sentinel\protection_service_core.py')) { throw 'sentinel\protection_service_core.py missing from FULL tree' }
    if (-not (Test-Path -LiteralPath '.\BUILD-SERVIZIO-PROTEZIONE.ps1')) { throw 'BUILD-SERVIZIO-PROTEZIONE.ps1 missing' }
    if (-not (Test-Path -LiteralPath '.\AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1')) { throw 'AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1 missing' }

    $Py = '.\.venv\Scripts\python.exe'
    $PatchRef = 'b7bd22d40a67a2c6b82b7786dd07158a94968653'
    $PatchBranch = 'fix/v011-beta2-b2-interactive-temp-watchdog'
    $PinnedRef = '6d833d08912b64bd0d14d4f21d7838a3718c40f7'
    $RepoRaw = 'https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/'

    Write-Host 'BC Sentinel v0.11.0-beta.2 - B2 STABILIZED WATCHDOG FILE OBSERVATION' -ForegroundColor Cyan
    Write-Host 'Adds non-destructive filesystem observation after watchdog stabilization with bounded per-directory EDR admission.' -ForegroundColor Yellow
    Write-Host 'No File ETW re-enable, no timeout relaxation, no 25/10/250 threshold relaxation.' -ForegroundColor Yellow

    $patchFiles = @(
        @('tools\v011_beta2_b2_file_observation_compat.py','tools/v011_beta2_b2_file_observation_compat.py'),
        @('tests\test_v011_beta2_b2_file_observation_compat.py','tests/test_v011_beta2_b2_file_observation_compat.py'),
        @('tools\v011_beta2_b2_watchdog_admission_compat.py','tools/v011_beta2_b2_watchdog_admission_compat.py'),
        @('tests\test_v011_beta2_b2_watchdog_admission_compat.py','tests/test_v011_beta2_b2_watchdog_admission_compat.py'),
        @('tools\v011_beta2_b2_final_lineage.py','tools/v011_beta2_b2_final_lineage_v2.py'),
        @('sentinel\config.py','sentinel/config.py'),
        @('sentinel\edr_adapter.py','sentinel/edr_adapter.py'),
        @('tests\test_v011_beta2_b2_service_profile_roots.py','tests/test_v011_beta2_b2_service_profile_roots.py'),
        @('tests\test_v011_beta2_b2_service_settings_compat.py','tests/test_v011_beta2_b2_service_settings_compat.py'),
        @('tests\test_v011_beta2_b2_temp_root_compat.py','tests/test_v011_beta2_b2_temp_root_compat.py'),
        @('tests\test_v011_beta1_edr_adapter.py','tests/test_v011_beta1_edr_adapter.py')
    )
    foreach ($item in $patchFiles) {
        Download-RequiredFile $item[0] ($RepoRaw + $PatchRef + '/' + $item[1])
    }

    Write-Host 'Applying stabilized watchdog file-observation bridge...' -ForegroundColor DarkCyan
    & $Py -m tools.v011_beta2_b2_file_observation_compat
    if ($LASTEXITCODE -ne 0) { throw 'Watchdog file-observation compatibility patch failed' }

    Write-Host 'Applying bounded per-directory watchdog EDR admission...' -ForegroundColor DarkCyan
    & $Py -m tools.v011_beta2_b2_watchdog_admission_compat
    if ($LASTEXITCODE -ne 0) { throw 'Watchdog EDR admission patch failed' }

    Write-Host 'Running focused final B2 regression suite...' -ForegroundColor DarkCyan
    $FocusedBase = Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    if (-not (Test-Path -LiteralPath $FocusedBase)) { New-Item -ItemType Directory -Path $FocusedBase -Force | Out-Null }
    $FocusedTemp = Join-Path $FocusedBase ('b2-final-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $FocusedTemp -Force | Out-Null
    try {
        & $Py -m pytest -q --basetemp $FocusedTemp `
            tests/test_v011_beta2_b2_file_observation_compat.py `
            tests/test_v011_beta2_b2_watchdog_admission_compat.py `
            tests/test_v011_beta2_b2_service_profile_roots.py `
            tests/test_v011_beta2_b2_service_settings_compat.py `
            tests/test_v011_beta2_b2_temp_root_compat.py `
            tests/test_v011_beta1_edr_adapter.py `
            tests/test_v011_beta1_low_cpu_runtime_compat.py `
            tests/test_v011_beta1_watchdog_coalescing.py `
            tests/test_v011_beta1_service_performance.py
        if ($LASTEXITCODE -ne 0) { throw 'Focused final B2 watchdog admission regression failed' }
    }
    finally {
        Remove-Item -LiteralPath $FocusedTemp -Recurse -Force -ErrorAction SilentlyContinue
    }

    & $Py -m compileall -q sentinel tools tests
    if ($LASTEXITCODE -ne 0) { throw 'compileall failed after watchdog admission patch' }

    & $Py -m tools.v011_beta2_b2_final_lineage --verify-only --output acceptance-v011-beta2-b2-final-lineage-prebuild.json
    if ($LASTEXITCODE -ne 0) { throw 'Strict final source-lineage v2 verification failed before build' }

    Write-Host 'Building final Protection Service with stabilized bounded watchdog observation...' -ForegroundColor Cyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\BUILD-SERVIZIO-PROTEZIONE.ps1'
    if ($LASTEXITCODE -ne 0) { throw 'Fresh Protection Service build failed after watchdog admission patch' }

    $distService = Join-Path $PSScriptRoot 'dist\BC-Sentinel-Protection\BC-Sentinel-Protection.exe'
    if (-not (Test-Path -LiteralPath $distService)) { throw 'Final Protection Service executable missing after build' }
    $distHash = (Get-FileHash -LiteralPath $distService -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host ('FINAL WATCHDOG-ADMISSION BUILD: SHA256=' + $distHash) -ForegroundColor Green

    Write-Host 'Deploying final Protection Service through UAC Repair...' -ForegroundColor Yellow
    $maintenance = Join-Path $PSScriptRoot 'AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1'
    $repairArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $maintenance + '"'),'-Mode','Repair')
    $repairProc = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList $repairArgs
    if ($null -eq $repairProc -or $repairProc.ExitCode -ne 0) { throw 'Repair deployment of final Protection Service failed' }

    $installedService = Join-Path $env:ProgramFiles 'BC Sentinel\Protection\BC-Sentinel-Protection.exe'
    if (-not (Test-Path -LiteralPath $installedService)) { throw 'Installed Protection Service missing after Repair' }
    $installedHash = (Get-FileHash -LiteralPath $installedService -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($installedHash -ne $distHash) { throw 'Installed final Protection Service does not match freshly rebuilt dist' }
    Write-Host ('FINAL BINARY PROVENANCE PASS: SHA256=' + $installedHash) -ForegroundColor Green

    $pinnedFiles = @(
        @('TEST-V011-BETA2-B2-REQUEST-OP-ADMIN.ps1','TEST-V011-BETA2-B2-REQUEST-OP-ADMIN.ps1'),
        @('tools\v011_beta2_b2_live_acceptance.py','tools/v011_beta2_b2_live_acceptance.py'),
        @('tools\v011_beta2_b2_live_acceptance_compat.py','tools/v011_beta2_b2_live_acceptance_compat.py'),
        @('tools\v011_service_readiness.py','tools/v011_service_readiness.py'),
        @('tools\service_hardening_benchmark.py','tools/service_hardening_benchmark.py'),
        @('tools\v011_edr_acceptance.py','tools/v011_edr_acceptance.py')
    )
    foreach ($item in $pinnedFiles) {
        Download-RequiredFile $item[0] ($RepoRaw + $PinnedRef + '/' + $item[1])
    }

    # Frozen admin/live compatibility imports this historical module name.
    # Supply the strict deterministic final v2 verifier under that name.
    Download-RequiredFile `
        '.\tools\v011_beta2_b2_request_op_compat.py' `
        ($RepoRaw + $PatchRef + '/tools/v011_beta2_b2_final_lineage_v2.py')

    $adminText = Get-Content -Raw -LiteralPath '.\TEST-V011-BETA2-B2-REQUEST-OP-ADMIN.ps1' -Encoding UTF8
    if (-not $adminText.Contains('Start-Sleep -Seconds 15')) { throw 'Frozen admin gate is missing 15-second stabilization window' }
    if (-not $adminText.Contains('--max-idle-cpu-percent 25') -or -not $adminText.Contains('--min-ipc-rps 10') -or -not $adminText.Contains('--max-storm-cpu-percent 250')) {
        throw 'Frozen 25/10/250 benchmark thresholds are missing from admin gate'
    }
    Write-Host ('PINNED FINAL LIVE GATE PASS: ' + $PinnedRef) -ForegroundColor Green

    & $Py -m tools.v011_beta2_b2_request_op_compat --verify-only --output acceptance-v011-beta2-b2-final-lineage-live.json
    if ($LASTEXITCODE -ne 0) { throw 'Strict final source-lineage v2 verification failed before live gate' }

    $adminResultPath = Join-Path $PSScriptRoot 'acceptance-v011-beta2-b2-request-op-admin-result.json'
    Remove-Item -LiteralPath $adminResultPath -Force -ErrorAction SilentlyContinue
    Write-Host 'Opening frozen B2 UAC final live phase...' -ForegroundColor Yellow
    $adminArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + (Join-Path $PSScriptRoot 'TEST-V011-BETA2-B2-REQUEST-OP-ADMIN.ps1') + '"'))
    $proc = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList $adminArgs
    if ($null -eq $proc) { throw 'B2 administrator process was not created' }
    $admin = Read-JsonSafe $adminResultPath
    if ($null -ne $admin) {
        $color = if ([string]$admin.status -eq 'PASS') { 'Green' } else { 'Red' }
        Write-Host (('FINAL ADMIN RESULT: status={0} | stage={1} | message={2}') -f $admin.status,$admin.stage,$admin.message) -ForegroundColor $color
    }
    if ($proc.ExitCode -ne 0) {
        if ($null -ne $admin) { throw ('B2 admin failed at ' + [string]$admin.stage + ': ' + [string]$admin.message) }
        throw ('B2 administrator process failed with exit code ' + $proc.ExitCode)
    }
    if ($null -eq $admin -or [string]$admin.status -ne 'PASS') { throw 'B2 administrator PASS result missing' }

    & $Py -m tools.broker_acceptance --output acceptance-v011-beta2-b2-final-standard-user-uac.json
    if ($LASTEXITCODE -ne 0) { throw 'Standard-user to UAC broker regression failed after final admin PASS' }

    & $Py -m tools.v011_beta2_b2_live_acceptance_compat --mode standard-user --output acceptance-v011-beta2-b2-final-standard-user-edr.json
    if ($LASTEXITCODE -ne 0) {
        $detail = Read-JsonSafe '.\acceptance-v011-beta2-b2-final-standard-user-edr.json'
        throw ('Standard-user EDR least-privilege acceptance failed: ' + $(if ($null -ne $detail -and $detail.error) { [string]$detail.error } else { 'no detail' }))
    }

    & $Py -m tools.v011_edr_acceptance --output acceptance-v011-beta2-b2-final-edr-post-admin.json
    if ($LASTEXITCODE -ne 0) { throw 'Beta1 EDR regression failed after final admin PASS' }

    $benchmark = Read-JsonSafe '.\benchmark-v011-beta2-b2-request-op-fix.json'
    if ($null -eq $benchmark -or -not [bool]$benchmark.passed) { throw 'Final frozen 25/10/250 benchmark evidence missing or failed' }
    Write-Host (('B2 FINAL PERFORMANCE: idle={0:N2}% | IPC={1:N2}/s | storm={2:N2}%') -f [double]$benchmark.idle.cpu_percent_of_one_core,[double]$benchmark.ipc.requests_per_second,[double]$benchmark.benign_event_storm.cpu_percent_of_one_core) -ForegroundColor Green

    Write-Host 'BC SENTINEL v0.11.0-beta.2 B2 WATCHDOG ADMISSION REPAIR - PASS' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
