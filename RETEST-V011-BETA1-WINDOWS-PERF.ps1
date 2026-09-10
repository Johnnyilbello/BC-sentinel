param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$ResultPath = Join-Path $PSScriptRoot 'retest-v011-beta1-windows-perf-result.json'
$BenchmarkPath = Join-Path $PSScriptRoot 'benchmark-v011-beta1-service.json'
$WindowsPath = Join-Path $PSScriptRoot 'acceptance-v011-beta1-windows-live.json'
$ReadinessPath = Join-Path $PSScriptRoot 'acceptance-v011-beta1-service-readiness.json'

function Read-JsonSafe([string]$Path) {
    try {
        if (Test-Path -LiteralPath $Path) {
            return (Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json)
        }
    }
    catch { }
    return $null
}

function Compact-Json($Value) {
    try { return ($Value | ConvertTo-Json -Compress -Depth 8) } catch { return '' }
}

function Write-RetestResult([string]$Status, [string]$Stage, [string]$Message) {
    try {
        $payload = [ordered]@{
            product = 'BC Sentinel'
            version = '0.11.0-beta.1'
            status = $Status
            stage = $Stage
            message = $Message
            timestamp_utc = (Get-Date).ToUniversalTime().ToString('o')
        }
        $payload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
    }
    catch { }
}

function Print-BenchmarkSummary($benchmark) {
    if ($null -eq $benchmark) { return }
    Write-Host (('SERVICE PERFORMANCE: idle={0:N2}% one-core | IPC={1:N2}/s | storm={2:N2}% one-core | passed={3}') -f [double]$benchmark.idle.cpu_percent_of_one_core,[double]$benchmark.ipc.requests_per_second,[double]$benchmark.benign_event_storm.cpu_percent_of_one_core,[bool]$benchmark.passed) -ForegroundColor Cyan
    if ($benchmark.failure_reasons) {
        foreach ($reason in $benchmark.failure_reasons) { Write-Host ('  - ' + $reason) -ForegroundColor Red }
    }
    if ($benchmark.idle.hottest_threads) {
        Write-Host 'IDLE HOTTEST THREADS:' -ForegroundColor Yellow
        foreach ($thread in $benchmark.idle.hottest_threads) {
            $role = [string]$thread.role
            if ([string]::IsNullOrWhiteSpace($role)) { $role = 'unattributed' }
            Write-Host (('  TID {0} [{1}]: {2:N2}% one-core ({3:N4}s CPU)') -f [int]$thread.tid,$role,[double]$thread.cpu_percent_of_one_core,[double]$thread.cpu_seconds) -ForegroundColor Yellow
        }
    }
}

function Print-ParentSummary([int]$ExitCode) {
    $result = Read-JsonSafe $ResultPath
    if ($null -ne $result) {
        $color = if ([string]$result.status -eq 'PASS') { 'Green' } else { 'Red' }
        Write-Host (('ADMIN RETEST RESULT: status={0} | stage={1} | message={2}') -f $result.status,$result.stage,$result.message) -ForegroundColor $color
    }
    else {
        Write-Host ('ADMIN RETEST RESULT: result JSON unavailable | exit=' + $ExitCode) -ForegroundColor Yellow
    }

    $windows = Read-JsonSafe $WindowsPath
    if ($null -ne $windows) {
        $windowsPassed = $false
        try { $windowsPassed = [bool]$windows.passed } catch { $windowsPassed = $false }
        Write-Host (('WINDOWS LIVE ACCEPTANCE RESULT: passed={0}') -f $windowsPassed) -ForegroundColor $(if ($windowsPassed) { 'Green' } else { 'Yellow' })
    }

    Print-BenchmarkSummary (Read-JsonSafe $BenchmarkPath)
}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Remove-Item -LiteralPath $ResultPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $BenchmarkPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $WindowsPath -Force -ErrorAction SilentlyContinue
    try {
        $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $PSCommandPath + '"'))
        $proc = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList $args
    }
    catch {
        Write-Host 'BC SENTINEL v0.11.0-beta.1 - WINDOWS/PERF RETEST FAIL' -ForegroundColor Red
        Write-Host ('UAC elevation cancelled or failed: ' + $_.Exception.Message) -ForegroundColor Red
        exit 1
    }
    Print-ParentSummary -ExitCode $proc.ExitCode
    exit $proc.ExitCode
}

$Stage = 'initialization'
try {
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.1 - TARGETED WINDOWS LIVE + PERFORMANCE RETEST' -ForegroundColor Cyan

    $Stage = 'service_repair'
    $distService = Join-Path $PSScriptRoot 'dist\BC-Sentinel-Protection\BC-Sentinel-Protection.exe'
    if (-not (Test-Path -LiteralPath $distService)) {
        throw ('Rebuilt Protection Service missing before repair: ' + $distService)
    }
    $maintenanceScript = Join-Path $PSScriptRoot 'AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1'
    if (-not (Test-Path -LiteralPath $maintenanceScript)) {
        throw ('Maintenance script missing: ' + $maintenanceScript)
    }

    Write-Host 'Installing the freshly rebuilt Protection Service via real Repair...' -ForegroundColor Cyan
    & $maintenanceScript -Mode Repair
    if ($LASTEXITCODE -ne 0) { throw 'Live Repair of rebuilt Protection Service failed' }
    Write-Host 'REBUILT SERVICE REPAIR PASS' -ForegroundColor Green

    $Stage = 'service_readiness'
    & $Py -m tools.v011_service_readiness --timeout-seconds 12 --poll-seconds 0.5 --output $ReadinessPath
    if ($LASTEXITCODE -ne 0) {
        $ready = Read-JsonSafe $ReadinessPath
        $detail = if ($null -ne $ready) { Compact-Json $ready } else { 'readiness JSON unavailable' }
        throw ('Protection Service readiness failed: ' + $detail)
    }
    Write-Host 'SERVICE WEB/DNS ETW READINESS PASS' -ForegroundColor Green

    # Measure true service idle before Windows Acceptance generates its synthetic
    # 5,000-file workload. The benchmark still includes its own bounded benign
    # storm after the idle window, so performance coverage is not weakened.
    $Stage = 'service_performance'
    Remove-Item -LiteralPath $BenchmarkPath -Force -ErrorAction SilentlyContinue
    Write-Host 'Service performance gates: idle <= 25% one core, IPC >= 10 req/s, benign storm <= 250% one core.' -ForegroundColor Cyan
    & $Py -m tools.service_hardening_benchmark --idle-seconds 5 --ipc-requests 200 --storm-files 500 --max-idle-cpu-percent 25 --min-ipc-rps 10 --max-storm-cpu-percent 250 --output $BenchmarkPath
    $benchmarkExit = $LASTEXITCODE
    $benchmark = Read-JsonSafe $BenchmarkPath
    Print-BenchmarkSummary $benchmark

    # Always run Windows Acceptance even if the performance gate failed so one
    # targeted retest reports both independent gate families.
    $Stage = 'windows_acceptance'
    Remove-Item -LiteralPath $WindowsPath -Force -ErrorAction SilentlyContinue
    & $Py -m tools.windows_acceptance --benchmark-files 5000 --realtime-seconds 3 --service-live --output $WindowsPath
    $windowsExit = $LASTEXITCODE
    if ($windowsExit -ne 0) {
        $windows = Read-JsonSafe $WindowsPath
        $detail = if ($null -ne $windows) { Compact-Json $windows } else { 'windows acceptance JSON unavailable' }
        Write-Host ('WINDOWS LIVE ACCEPTANCE DETAIL: ' + $detail) -ForegroundColor Yellow
        throw ('Windows live acceptance failed: ' + $detail)
    }
    Write-Host 'WINDOWS LIVE ACCEPTANCE PASS' -ForegroundColor Green

    if ($benchmarkExit -ne 0) {
        $Stage = 'service_performance'
        throw 'Service hardening/performance benchmark failed'
    }

    $Stage = 'complete'
    Write-RetestResult -Status 'PASS' -Stage $Stage -Message 'Enforced service performance and Windows live acceptance gates passed'
    Write-Host 'BC SENTINEL v0.11.0-beta.1 - WINDOWS/PERF RETEST PASS' -ForegroundColor Green
    exit 0
}
catch {
    $message = $_.Exception.Message
    Write-RetestResult -Status 'FAIL' -Stage $Stage -Message $message
    Write-Host 'BC SENTINEL v0.11.0-beta.1 - WINDOWS/PERF RETEST FAIL' -ForegroundColor Red
    Write-Host $message -ForegroundColor Red
    exit 1
}
