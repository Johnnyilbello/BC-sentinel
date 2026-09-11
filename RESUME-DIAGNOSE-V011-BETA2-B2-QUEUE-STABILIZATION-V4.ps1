param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.2 B2 QUEUE/STABILIZATION DIAGNOSTIC V4 - FAIL' -ForegroundColor Red
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

function Get-TraceStages($Record) {
    if ($null -eq $Record -or $null -eq $Record.trace) { return @() }
    return @($Record.trace | ForEach-Object { [string]$_.stage })
}

function Write-QueueDiagnosis([string]$Label, $Record) {
    $stages = @(Get-TraceStages $Record)
    $queueEnter = $stages -contains 'QUEUE_SCAN_ENTER'
    $queueReturn = $stages -contains 'QUEUE_SCAN_RETURN'
    $threadRequest = $stages -contains 'QUEUE_SCAN_THREAD_START_REQUEST'
    $threadStarted = $stages -contains 'QUEUE_SCAN_THREAD_STARTED'
    $stableEnter = $stages -contains 'STABLE_ENTER'
    $stableReturn = $stages -contains 'STABLE_RETURN'
    $callback = $stages -contains 'FILE_STABLE_CALLBACK_ENTER'

    $diagnosis = 'undetermined_queue_to_stabilization_gap'
    if (-not $queueEnter) {
        $diagnosis = 'handler_forwarded_event_but_never_called_queue_scan'
    } elseif ($queueReturn -and -not $threadRequest) {
        $diagnosis = 'queue_scan_early_return_before_thread_start'
    } elseif ($threadRequest -and -not $threadStarted) {
        $diagnosis = 'queue_scan_thread_start_did_not_complete'
    } elseif ($threadStarted -and -not $stableEnter) {
        $diagnosis = 'realtime_scan_thread_started_but_target_never_entered'
    } elseif ($stableEnter -and $stableReturn -and -not $callback) {
        $diagnosis = 'stabilization_returned_before_observation_callback'
    } elseif ($callback) {
        $diagnosis = 'stabilized_callback_reached'
    }

    Write-Host (('- {0}: {1}') -f $Label,$diagnosis) -ForegroundColor Green

    $interesting = @($Record.trace | Where-Object {
        [string]$_.stage -like 'QUEUE_SCAN_*' -or
        [string]$_.stage -like 'STABLE_*' -or
        [string]$_.stage -like 'FILE_STABLE_*'
    })
    foreach ($event in $interesting) {
        $line = ''
        $context = ''
        if ($null -ne $event.fields) {
            if ($null -ne $event.fields.source_line) { $line = [string]$event.fields.source_line }
            if ($null -ne $event.fields.source_context) { $context = [string]$event.fields.source_context }
        }
        $suffix = ''
        if ($line) { $suffix += (' | source_line=' + $line) }
        if ($context) { $suffix += (' | context=' + $context) }
        Write-Host (('    {0}{1}') -f [string]$event.stage,$suffix) -ForegroundColor DarkCyan
    }
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this diagnostic from normal PowerShell; UAC separation remains part of the service deployment path.'
    }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }
    if (-not (Test-Path -LiteralPath '.\sentinel\realtime.py')) { throw 'sentinel\realtime.py missing from FULL tree' }
    if (-not (Test-Path -LiteralPath '.\BUILD-SERVIZIO-PROTEZIONE.ps1')) { throw 'BUILD-SERVIZIO-PROTEZIONE.ps1 missing' }
    if (-not (Test-Path -LiteralPath '.\AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1')) { throw 'AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1 missing' }

    $Py = '.\.venv\Scripts\python.exe'
    $PatchRef = '8fe97f5bdc95b79fa723e6a2ea6af461832048ac'
    $PinnedRef = '6d833d08912b64bd0d14d4f21d7838a3718c40f7'
    $RepoRaw = 'https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/'

    Write-Host 'BC Sentinel v0.11.0-beta.2 - QUEUE -> STABILIZATION TRACE V4' -ForegroundColor Cyan
    Write-Host 'Scope: Handler/_queue_scan -> BCS-RealtimeScan -> _scan_when_stable.' -ForegroundColor Yellow
    Write-Host 'Marker-only logging with exact return source context. No EDR/hunt policy change and no threshold relaxation.' -ForegroundColor Yellow

    $patchFiles = @(
        @('sentinel\b2_diagnostic_trace.py','sentinel/b2_diagnostic_trace.py'),
        @('tools\v011_beta2_b2_queue_scan_trace_compat_v4.py','tools/v011_beta2_b2_queue_scan_trace_compat_v4.py'),
        @('tests\test_v011_beta2_b2_queue_scan_trace_compat_v4.py','tests/test_v011_beta2_b2_queue_scan_trace_compat_v4.py'),
        @('tests\test_v011_beta2_b2_diagnostic_trace.py','tests/test_v011_beta2_b2_diagnostic_trace.py'),
        @('tests\test_v011_beta1_watchdog_coalescing.py','tests/test_v011_beta1_watchdog_coalescing.py'),
        @('tests\test_v011_beta1_edr_adapter.py','tests/test_v011_beta1_edr_adapter.py'),
        @('tools\v011_beta2_b2_trace_probe.py','tools/v011_beta2_b2_trace_probe.py'),
        @('tools\v011_beta2_b2_service_startup_probe.py','tools/v011_beta2_b2_service_startup_probe.py')
    )
    foreach ($item in $patchFiles) {
        Download-RequiredFile $item[0] ($RepoRaw + $PatchRef + '/' + $item[1])
    }
    Download-RequiredFile '.\tools\v011_beta2_b2_live_acceptance.py' ($RepoRaw + $PinnedRef + '/tools/v011_beta2_b2_live_acceptance.py')

    Write-Host 'Instrumenting queue -> stabilization boundary...' -ForegroundColor DarkCyan
    & $Py -m tools.v011_beta2_b2_queue_scan_trace_compat_v4
    if ($LASTEXITCODE -ne 0) { throw 'Queue/stabilization trace instrumentation failed' }

    Write-Host 'Running focused V4 regression tests...' -ForegroundColor DarkCyan
    $FocusedBase = Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    if (-not (Test-Path -LiteralPath $FocusedBase)) { New-Item -ItemType Directory -Path $FocusedBase -Force | Out-Null }
    $FocusedTemp = Join-Path $FocusedBase ('b2-queue-v4-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $FocusedTemp -Force | Out-Null
    try {
        & $Py -m pytest -q --basetemp $FocusedTemp `
            tests/test_v011_beta2_b2_queue_scan_trace_compat_v4.py `
            tests/test_v011_beta2_b2_diagnostic_trace.py `
            tests/test_v011_beta1_watchdog_coalescing.py `
            tests/test_v011_beta1_edr_adapter.py
        if ($LASTEXITCODE -ne 0) { throw 'Focused V4 queue/stabilization regression suite failed' }
    }
    finally {
        Remove-Item -LiteralPath $FocusedTemp -Recurse -Force -ErrorAction SilentlyContinue
    }

    & $Py -m compileall -q sentinel tools tests
    if ($LASTEXITCODE -ne 0) { throw 'compileall failed after V4 instrumentation' }

    Write-Host 'Building V4 diagnostic Protection Service...' -ForegroundColor Cyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\BUILD-SERVIZIO-PROTEZIONE.ps1'
    if ($LASTEXITCODE -ne 0) { throw 'V4 diagnostic Protection Service build failed' }

    $distService = Join-Path $PSScriptRoot 'dist\BC-Sentinel-Protection\BC-Sentinel-Protection.exe'
    if (-not (Test-Path -LiteralPath $distService)) { throw 'V4 Protection Service executable missing' }
    $distHash = (Get-FileHash -LiteralPath $distService -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host ('V4 DIAGNOSTIC BUILD SHA256=' + $distHash) -ForegroundColor Green

    Write-Host 'Deploying V4 diagnostic service through UAC Repair...' -ForegroundColor Yellow
    $maintenance = Join-Path $PSScriptRoot 'AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1'
    $repairArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $maintenance + '"'),'-Mode','Repair')
    $repairProc = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList $repairArgs
    if ($null -eq $repairProc -or $repairProc.ExitCode -ne 0) { throw 'V4 diagnostic service deployment failed' }

    $installedService = Join-Path $env:ProgramFiles 'BC Sentinel\Protection\BC-Sentinel-Protection.exe'
    if (-not (Test-Path -LiteralPath $installedService)) { throw 'Installed V4 Protection Service missing' }
    $installedHash = (Get-FileHash -LiteralPath $installedService -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($installedHash -ne $distHash) { throw 'Installed V4 service does not match freshly built dist' }
    Write-Host ('V4 BINARY PROVENANCE PASS: SHA256=' + $installedHash) -ForegroundColor Green

    Write-Host 'Polling named pipe before marker generation...' -ForegroundColor Cyan
    & $Py -m tools.v011_beta2_b2_service_startup_probe `
        --timeout-seconds 20 `
        --interval-seconds 0.5 `
        --output acceptance-v011-beta2-b2-v4-service-startup.json
    if ($LASTEXITCODE -ne 0) { throw 'V4 service named pipe was not ready within 20 seconds' }

    Write-Host 'Running V4 multi-root marker trace...' -ForegroundColor Cyan
    & $Py -m tools.v011_beta2_b2_trace_probe `
        --poll-seconds 12 `
        --output acceptance-v011-beta2-b2-queue-stabilization-v4.json
    if ($LASTEXITCODE -ne 0) { throw 'V4 marker trace probe execution failed' }

    $probePath = Join-Path $PSScriptRoot 'acceptance-v011-beta2-b2-queue-stabilization-v4.json'
    if (-not (Test-Path -LiteralPath $probePath)) { throw 'V4 marker trace output missing' }
    $probe = Get-Content -Raw -LiteralPath $probePath -Encoding UTF8 | ConvertFrom-Json

    Write-Host '--- V4 QUEUE/STABILIZATION ROOT-CAUSE SUMMARY ---' -ForegroundColor Cyan
    foreach ($property in $probe.records.PSObject.Properties) {
        Write-QueueDiagnosis $property.Name $property.Value
    }

    Write-Host ('Persistent trace: C:\ProgramData\BC Sentinel\Logs\b2-marker-trace.jsonl') -ForegroundColor DarkGray
    Write-Host ('Diagnostic JSON: ' + $probePath) -ForegroundColor DarkGray
    Write-Host 'BC SENTINEL v0.11.0-beta.2 B2 QUEUE/STABILIZATION DIAGNOSTIC V4 - COMPLETE' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
