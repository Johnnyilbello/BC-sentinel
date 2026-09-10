param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.1 - WINDOWS/PERF RETEST FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

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

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $PSCommandPath + '"'))
        $proc = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList $args
        exit $proc.ExitCode
    }

    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.1 - TARGETED WINDOWS LIVE + PERFORMANCE RETEST' -ForegroundColor Cyan

    $readinessPath = Join-Path $PSScriptRoot 'acceptance-v011-beta1-service-readiness.json'
    & $Py -m tools.v011_service_readiness --timeout-seconds 12 --poll-seconds 0.5 --output $readinessPath
    if ($LASTEXITCODE -ne 0) {
        $ready = Read-JsonSafe $readinessPath
        $detail = if ($null -ne $ready) { Compact-Json $ready } else { 'readiness JSON unavailable' }
        throw ('Protection Service readiness failed: ' + $detail)
    }
    Write-Host 'SERVICE WEB/DNS ETW READINESS PASS' -ForegroundColor Green

    $windowsPath = Join-Path $PSScriptRoot 'acceptance-v011-beta1-windows-live.json'
    Remove-Item -LiteralPath $windowsPath -Force -ErrorAction SilentlyContinue
    & $Py -m tools.windows_acceptance --benchmark-files 5000 --realtime-seconds 3 --service-live --output $windowsPath
    if ($LASTEXITCODE -ne 0) {
        $windows = Read-JsonSafe $windowsPath
        $detail = if ($null -ne $windows) { Compact-Json $windows } else { 'windows acceptance JSON unavailable' }
        Write-Host ('WINDOWS LIVE ACCEPTANCE DETAIL: ' + $detail) -ForegroundColor Yellow
        throw ('Windows live acceptance failed: ' + $detail)
    }
    Write-Host 'WINDOWS LIVE ACCEPTANCE PASS' -ForegroundColor Green

    $benchmarkPath = Join-Path $PSScriptRoot 'benchmark-v011-beta1-service.json'
    Remove-Item -LiteralPath $benchmarkPath -Force -ErrorAction SilentlyContinue
    Write-Host 'Service performance gates: idle <= 25% one core, IPC >= 10 req/s, benign storm <= 250% one core.' -ForegroundColor Cyan
    & $Py -m tools.service_hardening_benchmark --idle-seconds 5 --ipc-requests 200 --storm-files 500 --max-idle-cpu-percent 25 --min-ipc-rps 10 --max-storm-cpu-percent 250 --output $benchmarkPath
    $benchmarkExit = $LASTEXITCODE
    $benchmark = Read-JsonSafe $benchmarkPath
    if ($null -ne $benchmark) {
        Write-Host (('SERVICE PERFORMANCE: idle={0:N2}% one-core | IPC={1:N2}/s | storm={2:N2}% one-core | passed={3}') -f [double]$benchmark.idle.cpu_percent_of_one_core,[double]$benchmark.ipc.requests_per_second,[double]$benchmark.benign_event_storm.cpu_percent_of_one_core,[bool]$benchmark.passed) -ForegroundColor Cyan
        if ($benchmark.idle.hottest_threads) {
            Write-Host 'IDLE HOTTEST THREADS:' -ForegroundColor Yellow
            foreach ($thread in $benchmark.idle.hottest_threads) {
                $role = [string]$thread.role
                if ([string]::IsNullOrWhiteSpace($role)) { $role = 'unattributed' }
                Write-Host (('  TID {0} [{1}]: {2:N2}% one-core ({3:N4}s CPU)') -f [int]$thread.tid,$role,[double]$thread.cpu_percent_of_one_core,[double]$thread.cpu_seconds) -ForegroundColor Yellow
            }
        }
        if ($benchmark.failure_reasons) {
            foreach ($reason in $benchmark.failure_reasons) { Write-Host ('  - ' + $reason) -ForegroundColor Red }
        }
    }
    if ($benchmarkExit -ne 0) { throw 'Service hardening/performance benchmark failed' }

    Write-Host 'BC SENTINEL v0.11.0-beta.1 - WINDOWS/PERF RETEST PASS' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
