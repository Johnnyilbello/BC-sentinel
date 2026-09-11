param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.2 B2 NONEXEC OBSERVATION V6 - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

function Download-RequiredFile([string]$Destination,[string]$Uri) {
    $parent = Split-Path -Parent $Destination
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Write-Host ('Downloading: ' + $Uri) -ForegroundColor DarkGray
    Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $Destination -ErrorAction Stop
}

function Read-JsonSafe([string]$Path) {
    try {
        if (Test-Path -LiteralPath $Path) {
            return (Get-Content -Raw -LiteralPath $Path -Encoding UTF8 | ConvertFrom-Json)
        }
    } catch { }
    return $null
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this repair from normal PowerShell; the frozen B2 live phase must cross UAC explicitly.'
    }

    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }
    if (-not (Test-Path -LiteralPath '.\sentinel\realtime.py')) { throw 'sentinel\realtime.py missing from FULL tree' }
    if (-not (Test-Path -LiteralPath '.\sentinel\protection_service_core.py')) { throw 'sentinel\protection_service_core.py missing from FULL tree' }
    if (-not (Test-Path -LiteralPath '.\BUILD-SERVIZIO-PROTEZIONE.ps1')) { throw 'BUILD-SERVIZIO-PROTEZIONE.ps1 missing' }
    if (-not (Test-Path -LiteralPath '.\AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1')) { throw 'AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1 missing' }

    $Py = '.\.venv\Scripts\python.exe'
    $PatchRef = 'f86f989e6f02e782684f105f15e4f84fb78b8c57'
    $PinnedRef = '6d833d08912b64bd0d14d4f21d7838a3718c40f7'
    $RepoRaw = 'https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/'

    Write-Host 'BC Sentinel v0.11.0-beta.2 - B2 NON-EXECUTABLE FILE OBSERVATION V6' -ForegroundColor Cyan
    Write-Host 'Root cause fixed: .tmp/.txt filesystem observation is separated from static-scan eligibility.' -ForegroundColor Yellow
    Write-Host 'No .tmp expansion of POTENTIALLY_EXECUTABLE, no File ETW re-enable, no timeout or 25/10/250 relaxation.' -ForegroundColor Yellow

    $patchFiles = @(
        @('tools\v011_beta2_b2_diagnostic_cleanup_v6.py','tools/v011_beta2_b2_diagnostic_cleanup_v6.py'),
        @('tools\v011_beta2_b2_nonexec_observation_fix_v6.py','tools/v011_beta2_b2_nonexec_observation_fix_v6.py'),
        @('tools\v011_beta2_b2_final_lineage_v3.py','tools/v011_beta2_b2_final_lineage_v3.py'),
        @('tools\v011_beta2_b2_file_observation_compat.py','tools/v011_beta2_b2_file_observation_compat.py'),
        @('tools\v011_beta2_b2_watchdog_admission_compat.py','tools/v011_beta2_b2_watchdog_admission_compat.py'),
        @('tests\test_v011_beta2_b2_diagnostic_cleanup_v6.py','tests/test_v011_beta2_b2_diagnostic_cleanup_v6.py'),
        @('tests\test_v011_beta2_b2_nonexec_observation_fix_v6.py','tests/test_v011_beta2_b2_nonexec_observation_fix_v6.py'),
        @('tests\test_v011_beta2_b2_file_observation_compat.py','tests/test_v011_beta2_b2_file_observation_compat.py'),
        @('tests\test_v011_beta2_b2_watchdog_admission_compat.py','tests/test_v011_beta2_b2_watchdog_admission_compat.py'),
        @('tests\test_v011_beta2_b2_service_profile_roots.py','tests/test_v011_beta2_b2_service_profile_roots.py'),
        @('tests\test_v011_beta2_b2_service_settings_compat.py','tests/test_v011_beta2_b2_service_settings_compat.py'),
        @('tests\test_v011_beta2_b2_temp_root_compat.py','tests/test_v011_beta2_b2_temp_root_compat.py'),
        @('tests\test_v011_beta1_low_cpu_runtime_compat.py','tests/test_v011_beta1_low_cpu_runtime_compat.py'),
        @('tests\test_v011_beta1_watchdog_coalescing.py','tests/test_v011_beta1_watchdog_coalescing.py'),
        @('tests\test_v011_beta1_service_performance.py','tests/test_v011_beta1_service_performance.py'),
        @('tests\test_v011_beta1_edr_adapter.py','tests/test_v011_beta1_edr_adapter.py')
    )
    foreach ($item in $patchFiles) {
        Download-RequiredFile $item[0] ($RepoRaw + $PatchRef + '/' + $item[1])
    }

    Write-Host 'Preflight: testing cleanup and V6 transform BEFORE touching production source...' -ForegroundColor DarkCyan
    $PreflightBase = Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    if (-not (Test-Path -LiteralPath $PreflightBase)) { New-Item -ItemType Directory -Path $PreflightBase -Force | Out-Null }
    $PreflightTemp = Join-Path $PreflightBase ('b2-v6-preflight-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $PreflightTemp -Force | Out-Null
    try {
        & $Py -m pytest -q --basetemp $PreflightTemp `
            tests/test_v011_beta2_b2_diagnostic_cleanup_v6.py `
            tests/test_v011_beta2_b2_nonexec_observation_fix_v6.py
        if ($LASTEXITCODE -ne 0) { throw 'V6 patcher preflight failed; production source was not intentionally modified by this launcher' }
    }
    finally {
        Remove-Item -LiteralPath $PreflightTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host 'V6 PATCHER PREFLIGHT PASS' -ForegroundColor Green

    Write-Host 'Removing temporary V1/V4 marker diagnostics using exact pre-instrumentation backups...' -ForegroundColor DarkCyan
    & $Py -m tools.v011_beta2_b2_diagnostic_cleanup_v6
    if ($LASTEXITCODE -ne 0) { throw 'Safe diagnostic cleanup failed' }

    Write-Host 'Applying final non-executable filesystem-observation separation...' -ForegroundColor DarkCyan
    & $Py -m tools.v011_beta2_b2_nonexec_observation_fix_v6
    if ($LASTEXITCODE -ne 0) { throw 'V6 non-executable observation fix failed' }

    Write-Host 'Running focused final V6 regression suite...' -ForegroundColor DarkCyan
    $FocusedTemp = Join-Path $PreflightBase ('b2-v6-final-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $FocusedTemp -Force | Out-Null
    try {
        & $Py -m pytest -q --basetemp $FocusedTemp `
            tests/test_v011_beta2_b2_nonexec_observation_fix_v6.py `
            tests/test_v011_beta2_b2_file_observation_compat.py `
            tests/test_v011_beta2_b2_watchdog_admission_compat.py `
            tests/test_v011_beta2_b2_service_profile_roots.py `
            tests/test_v011_beta2_b2_service_settings_compat.py `
            tests/test_v011_beta2_b2_temp_root_compat.py `
            tests/test_v011_beta1_low_cpu_runtime_compat.py `
            tests/test_v011_beta1_watchdog_coalescing.py `
            tests/test_v011_beta1_service_performance.py `
            tests/test_v011_beta1_edr_adapter.py
        if ($LASTEXITCODE -ne 0) { throw 'Focused final V6 regression suite failed' }
    }
    finally {
        Remove-Item -LiteralPath $FocusedTemp -Recurse -Force -ErrorAction SilentlyContinue
    }

    & $Py -m compileall -q sentinel tools tests
    if ($LASTEXITCODE -ne 0) { throw 'compileall failed after V6 source repair' }

    & $Py -m tools.v011_beta2_b2_final_lineage_v3 --verify-only --output acceptance-v011-beta2-b2-final-lineage-v3-prebuild.json
    if ($LASTEXITCODE -ne 0) { throw 'Strict final B2 source-lineage v3 failed before build' }

    Write-Host 'Building final V6 Protection Service...' -ForegroundColor Cyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\BUILD-SERVIZIO-PROTEZIONE.ps1'
    if ($LASTEXITCODE -ne 0) { throw 'Fresh V6 Protection Service build failed' }

    $distService = Join-Path $PSScriptRoot 'dist\BC-Sentinel-Protection\BC-Sentinel-Protection.exe'
    if (-not (Test-Path -LiteralPath $distService)) { throw 'Final V6 Protection Service executable missing' }
    $distHash = (Get-FileHash -LiteralPath $distService -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host ('FINAL V6 BUILD SHA256=' + $distHash) -ForegroundColor Green

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

    # The frozen compatibility layer imports this historical module name.
    Download-RequiredFile '.\tools\v011_beta2_b2_request_op_compat.py' ($RepoRaw + $PatchRef + '/tools/v011_beta2_b2_final_lineage_v3.py')

    $adminText = Get-Content -Raw -LiteralPath '.\TEST-V011-BETA2-B2-REQUEST-OP-ADMIN.ps1' -Encoding UTF8
    if (-not $adminText.Contains('Start-Sleep -Seconds 15')) { throw 'Frozen admin gate is missing its 15-second stabilization window' }
    if (-not $adminText.Contains('--max-idle-cpu-percent 25') -or -not $adminText.Contains('--min-ipc-rps 10') -or -not $adminText.Contains('--max-storm-cpu-percent 250')) {
        throw 'Frozen 25/10/250 performance thresholds are missing from admin gate'
    }
    if (-not $adminText.Contains('--storm-files 500')) { throw 'Frozen 500-file benign storm workload is missing from admin gate' }
    Write-Host ('PINNED FROZEN B2 LIVE/PERFORMANCE GATE PASS: ' + $PinnedRef) -ForegroundColor Green

    & $Py -m tools.v011_beta2_b2_request_op_compat --verify-only --output acceptance-v011-beta2-b2-final-lineage-v3-live.json
    if ($LASTEXITCODE -ne 0) { throw 'Strict final source-lineage v3 failed immediately before frozen live gate' }

    $adminResultPath = Join-Path $PSScriptRoot 'acceptance-v011-beta2-b2-request-op-admin-result.json'
    Remove-Item -LiteralPath $adminResultPath -Force -ErrorAction SilentlyContinue
    Write-Host 'Opening frozen B2 administrator live/performance phase...' -ForegroundColor Yellow
    $adminArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + (Join-Path $PSScriptRoot 'TEST-V011-BETA2-B2-REQUEST-OP-ADMIN.ps1') + '"'))
    $proc = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList $adminArgs
    if ($null -eq $proc) { throw 'B2 administrator process was not created' }

    $admin = Read-JsonSafe $adminResultPath
    if ($null -ne $admin) {
        $color = if ([string]$admin.status -eq 'PASS') { 'Green' } else { 'Red' }
        Write-Host (('FINAL ADMIN RESULT: status={0} | stage={1} | message={2}') -f $admin.status,$admin.stage,$admin.message) -ForegroundColor $color
    }
    if ($proc.ExitCode -ne 0) {
        if ($null -ne $admin) { throw ('Frozen B2 admin gate failed at ' + [string]$admin.stage + ': ' + [string]$admin.message) }
        throw ('Frozen B2 administrator process failed with exit code ' + $proc.ExitCode)
    }
    if ($null -eq $admin -or [string]$admin.status -ne 'PASS') { throw 'Frozen B2 administrator PASS result missing' }

    $installedService = Join-Path $env:ProgramFiles 'BC Sentinel\Protection\BC-Sentinel-Protection.exe'
    if (-not (Test-Path -LiteralPath $installedService)) { throw 'Installed final V6 Protection Service missing after frozen admin phase' }
    $installedHash = (Get-FileHash -LiteralPath $installedService -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($installedHash -ne $distHash) { throw 'Installed final V6 service does not match freshly built dist' }
    Write-Host ('FINAL V6 BINARY PROVENANCE PASS: SHA256=' + $installedHash) -ForegroundColor Green

    $benchmark = Read-JsonSafe '.\benchmark-v011-beta2-b2-request-op-fix.json'
    if ($null -eq $benchmark -or -not [bool]$benchmark.passed) { throw 'Frozen 25/10/250 benchmark evidence missing or failed' }
    Write-Host (('B2 V6 PERFORMANCE PASS: idle={0:N2}% | IPC={1:N2}/s | storm={2:N2}%') -f [double]$benchmark.idle.cpu_percent_of_one_core,[double]$benchmark.ipc.requests_per_second,[double]$benchmark.benign_event_storm.cpu_percent_of_one_core) -ForegroundColor Green

    $pre = Read-JsonSafe '.\acceptance-v011-beta2-b2-request-op-pre-restart.json'
    $post = Read-JsonSafe '.\acceptance-v011-beta2-b2-request-op-post-restart.json'
    if ($null -eq $pre -or -not [bool]$pre.passed) { throw 'Pre-restart native marker acceptance evidence missing or failed' }
    if ($null -eq $post -or -not [bool]$post.passed) { throw 'Post-restart marker/incident persistence evidence missing or failed' }
    Write-Host ('B2 NATIVE MARKER PASS: ' + [string]$pre.marker_path) -ForegroundColor Green

    & $Py -m tools.v011_edr_acceptance --output acceptance-v011-beta2-b2-v6-edr-regression.json
    if ($LASTEXITCODE -ne 0) { throw 'EDR regression failed after frozen B2 admin PASS' }

    & $Py -m tools.v011_beta2_b2_final_lineage_v3 --verify-only --output acceptance-v011-beta2-b2-final-lineage-v3-final.json
    if ($LASTEXITCODE -ne 0) { throw 'Strict final B2 source-lineage v3 failed after live gate' }

    Write-Host 'BC SENTINEL v0.11.0-beta.2 B2 NONEXEC OBSERVATION V6 - PASS' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
