param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.2 B2 WATCHDOG-EDR DIAGNOSTIC V2 - FAIL' -ForegroundColor Red
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

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this diagnostic from normal PowerShell; UAC is requested only for service deployment.'
    }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }
    if (-not (Test-Path -LiteralPath '.\sentinel\realtime.py')) { throw 'sentinel\realtime.py missing from FULL tree' }
    if (-not (Test-Path -LiteralPath '.\sentinel\protection_service_core.py')) { throw 'sentinel\protection_service_core.py missing from FULL tree' }
    if (-not (Test-Path -LiteralPath '.\sentinel\watchdog_coalescing.py')) { throw 'sentinel\watchdog_coalescing.py missing from FULL tree' }
    if (-not (Test-Path -LiteralPath '.\sentinel\edr_service_bridge.py')) { throw 'sentinel\edr_service_bridge.py missing from FULL tree' }
    if (-not (Test-Path -LiteralPath '.\BUILD-SERVIZIO-PROTEZIONE.ps1')) { throw 'BUILD-SERVIZIO-PROTEZIONE.ps1 missing' }
    if (-not (Test-Path -LiteralPath '.\AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1')) { throw 'AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1 missing' }

    $Py = '.\.venv\Scripts\python.exe'
    $PatchRef = 'ea5bc44f2bfc272d62718c79f8ac4613b96613b0'
    $PinnedRef = '6d833d08912b64bd0d14d4f21d7838a3718c40f7'
    $RepoRaw = 'https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/'

    Write-Host 'BC Sentinel v0.11.0-beta.2 - WATCHDOG -> EDR MARKER TRACE V2' -ForegroundColor Cyan
    Write-Host 'AST-resilient realtime instrumentation plus marker-only structured tracing.' -ForegroundColor Yellow
    Write-Host 'Also checks Windows 8.3 short-path vs long-path EDR hunt aliases.' -ForegroundColor Yellow
    Write-Host 'No File ETW re-enable, timeout relaxation, benchmark threshold change or destructive action.' -ForegroundColor Yellow

    $patchFiles = @(
        @('tools\v011_beta2_b2_file_observation_compat.py','tools/v011_beta2_b2_file_observation_compat.py'),
        @('tools\v011_beta2_b2_watchdog_admission_compat.py','tools/v011_beta2_b2_watchdog_admission_compat.py'),
        @('sentinel\b2_diagnostic_trace.py','sentinel/b2_diagnostic_trace.py'),
        @('tools\v011_beta2_b2_diagnostic_trace_compat.py','tools/v011_beta2_b2_diagnostic_trace_compat.py'),
        @('tools\v011_beta2_b2_diagnostic_trace_compat_v2.py','tools/v011_beta2_b2_diagnostic_trace_compat_v2.py'),
        @('tools\v011_beta2_b2_trace_probe.py','tools/v011_beta2_b2_trace_probe.py'),
        @('tools\v011_beta2_b2_path_alias_probe.py','tools/v011_beta2_b2_path_alias_probe.py'),
        @('tests\test_v011_beta2_b2_diagnostic_trace.py','tests/test_v011_beta2_b2_diagnostic_trace.py'),
        @('tests\test_v011_beta2_b2_diagnostic_trace_compat_v2.py','tests/test_v011_beta2_b2_diagnostic_trace_compat_v2.py'),
        @('tests\test_v011_beta2_b2_file_observation_compat.py','tests/test_v011_beta2_b2_file_observation_compat.py'),
        @('tests\test_v011_beta2_b2_watchdog_admission_compat.py','tests/test_v011_beta2_b2_watchdog_admission_compat.py'),
        @('tests\test_v011_beta1_watchdog_coalescing.py','tests/test_v011_beta1_watchdog_coalescing.py'),
        @('tests\test_v011_beta1_edr_adapter.py','tests/test_v011_beta1_edr_adapter.py')
    )
    foreach ($item in $patchFiles) {
        Download-RequiredFile $item[0] ($RepoRaw + $PatchRef + '/' + $item[1])
    }

    Download-RequiredFile `
        '.\tools\v011_beta2_b2_live_acceptance.py' `
        ($RepoRaw + $PinnedRef + '/tools/v011_beta2_b2_live_acceptance.py')

    Write-Host 'Ensuring stabilized watchdog observation bridge...' -ForegroundColor DarkCyan
    & $Py -m tools.v011_beta2_b2_file_observation_compat
    if ($LASTEXITCODE -ne 0) { throw 'Watchdog file-observation compatibility patch failed' }

    Write-Host 'Ensuring bounded per-directory EDR admission...' -ForegroundColor DarkCyan
    & $Py -m tools.v011_beta2_b2_watchdog_admission_compat
    if ($LASTEXITCODE -ne 0) { throw 'Watchdog EDR admission patch failed' }

    Write-Host 'Adding AST-resilient marker-only end-to-end diagnostic tracing...' -ForegroundColor DarkCyan
    & $Py -m tools.v011_beta2_b2_diagnostic_trace_compat_v2
    if ($LASTEXITCODE -ne 0) { throw 'Marker trace instrumentation v2 failed' }

    Write-Host 'Running focused diagnostic regression tests...' -ForegroundColor DarkCyan
    $FocusedBase = Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    if (-not (Test-Path -LiteralPath $FocusedBase)) { New-Item -ItemType Directory -Path $FocusedBase -Force | Out-Null }
    $FocusedTemp = Join-Path $FocusedBase ('b2-trace-v2-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $FocusedTemp -Force | Out-Null
    try {
        & $Py -m pytest -q --basetemp $FocusedTemp `
            tests/test_v011_beta2_b2_diagnostic_trace.py `
            tests/test_v011_beta2_b2_diagnostic_trace_compat_v2.py `
            tests/test_v011_beta2_b2_file_observation_compat.py `
            tests/test_v011_beta2_b2_watchdog_admission_compat.py `
            tests/test_v011_beta1_watchdog_coalescing.py `
            tests/test_v011_beta1_edr_adapter.py
        if ($LASTEXITCODE -ne 0) { throw 'Focused marker-trace v2 regression suite failed' }
    }
    finally {
        Remove-Item -LiteralPath $FocusedTemp -Recurse -Force -ErrorAction SilentlyContinue
    }

    & $Py -m compileall -q sentinel tools tests
    if ($LASTEXITCODE -ne 0) { throw 'compileall failed after marker trace v2 instrumentation' }

    Write-Host 'Building diagnostic Protection Service...' -ForegroundColor Cyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\BUILD-SERVIZIO-PROTEZIONE.ps1'
    if ($LASTEXITCODE -ne 0) { throw 'Diagnostic Protection Service build failed' }

    $distService = Join-Path $PSScriptRoot 'dist\BC-Sentinel-Protection\BC-Sentinel-Protection.exe'
    if (-not (Test-Path -LiteralPath $distService)) { throw 'Diagnostic Protection Service executable missing' }
    $distHash = (Get-FileHash -LiteralPath $distService -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host ('DIAGNOSTIC BUILD SHA256=' + $distHash) -ForegroundColor Green

    Write-Host 'Deploying diagnostic service through UAC Repair...' -ForegroundColor Yellow
    $maintenance = Join-Path $PSScriptRoot 'AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1'
    $repairArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $maintenance + '"'),'-Mode','Repair')
    $repairProc = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList $repairArgs
    if ($null -eq $repairProc -or $repairProc.ExitCode -ne 0) { throw 'Diagnostic service deployment failed' }

    $installedService = Join-Path $env:ProgramFiles 'BC Sentinel\Protection\BC-Sentinel-Protection.exe'
    if (-not (Test-Path -LiteralPath $installedService)) { throw 'Installed diagnostic Protection Service missing' }
    $installedHash = (Get-FileHash -LiteralPath $installedService -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($installedHash -ne $distHash) { throw 'Installed diagnostic service does not match freshly built dist' }
    Write-Host ('DIAGNOSTIC BINARY PROVENANCE PASS: SHA256=' + $installedHash) -ForegroundColor Green

    Write-Host 'Running harmless multi-root marker trace probe...' -ForegroundColor Cyan
    & $Py -m tools.v011_beta2_b2_trace_probe --poll-seconds 12 --output acceptance-v011-beta2-b2-marker-trace-probe.json
    if ($LASTEXITCODE -ne 0) { throw 'Marker trace probe execution failed' }

    Write-Host 'Running Windows short-path/long-path alias probe...' -ForegroundColor Cyan
    & $Py -m tools.v011_beta2_b2_path_alias_probe --poll-seconds 12 --output acceptance-v011-beta2-b2-path-alias-probe.json
    if ($LASTEXITCODE -ne 0) { throw 'Path alias probe execution failed' }

    $probePath = Join-Path $PSScriptRoot 'acceptance-v011-beta2-b2-marker-trace-probe.json'
    $aliasPath = Join-Path $PSScriptRoot 'acceptance-v011-beta2-b2-path-alias-probe.json'
    if (-not (Test-Path -LiteralPath $probePath)) { throw 'Marker trace probe output missing' }
    if (-not (Test-Path -LiteralPath $aliasPath)) { throw 'Path alias probe output missing' }
    $probe = Get-Content -Raw -LiteralPath $probePath -Encoding UTF8 | ConvertFrom-Json
    $alias = Get-Content -Raw -LiteralPath $aliasPath -Encoding UTF8 | ConvertFrom-Json

    Write-Host '--- AUTOMATIC ROOT-CAUSE SUMMARY ---' -ForegroundColor Cyan
    foreach ($property in $probe.records.PSObject.Properties) {
        $label = $property.Name
        $record = $property.Value
        Write-Host (('- {0}: diagnosis={1} | last={2} | trace={3} | hunt={4} | timeline={5}') -f `
            $label, [string]$record.diagnosis, [string]$record.last_stage, [int]$record.trace_count, `
            [int]$record.hunt.count, [int]$record.timeline.match_count) -ForegroundColor Green
    }
    Write-Host (('PATH ALIAS DIAGNOSIS: {0} | raw={1} | long={2} | short={3}') -f `
        [string]$alias.diagnosis, [string]$alias.paths.raw, [string]$alias.paths.long, [string]$alias.paths.short) -ForegroundColor Magenta
    Write-Host (('EDR INGEST DELTA DURING ALIAS PROBE: {0}') -f [int]$alias.status.service_ingested_delta) -ForegroundColor DarkGray

    if ($null -ne $probe.trace_meta -and $probe.trace_meta.jsonl_path) {
        Write-Host ('Persistent marker trace: ' + [string]$probe.trace_meta.jsonl_path) -ForegroundColor DarkGray
    }
    Write-Host ('Marker trace JSON: ' + $probePath) -ForegroundColor DarkGray
    Write-Host ('Path alias JSON: ' + $aliasPath) -ForegroundColor DarkGray
    Write-Host 'BC SENTINEL v0.11.0-beta.2 B2 WATCHDOG-EDR DIAGNOSTIC V2 - COMPLETE' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
