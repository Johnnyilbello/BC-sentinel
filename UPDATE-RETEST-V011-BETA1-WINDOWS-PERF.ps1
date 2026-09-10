param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.1 - TARGETED UPDATE/RETEST FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

$Zip = Join-Path $env:TEMP 'bc-sentinel-v011-beta1-latest.zip'
$Stage = Join-Path $env:TEMP 'bc-sentinel-v011-beta1-latest'
$Url = 'https://github.com/Johnnyilbello/BC-sentinel/archive/refs/heads/v0.11.0-beta.1.zip'

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run UPDATE-RETEST-V011-BETA1-WINDOWS-PERF.bat from a normal PowerShell so the service build occurs before UAC elevation.'
    }

    $requiredFullBaseline = @(
        '.\sentinel\protection_client.py',
        '.\sentinel\realtime.py',
        '.\tools\windows_acceptance.py',
        '.\tools\service_hardening_benchmark.py',
        '.\BUILD-SERVIZIO-PROTEZIONE.ps1',
        '.\AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1'
    )
    foreach ($item in $requiredFullBaseline) {
        if (-not (Test-Path -LiteralPath $item)) {
            throw ('Incomplete FULL baseline. Missing required local file: ' + $item)
        }
    }

    Write-Host 'BC Sentinel v0.11.0-beta.1 - downloading latest Git delta for targeted retest...' -ForegroundColor Cyan
    Remove-Item -LiteralPath $Zip -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue
    Invoke-WebRequest -Uri $Url -OutFile $Zip
    Expand-Archive -LiteralPath $Zip -DestinationPath $Stage -Force

    $Source = Join-Path $Stage 'BC-sentinel-0.11.0-beta.1'
    if (-not (Test-Path -LiteralPath $Source)) { throw ('Downloaded branch layout is invalid: ' + $Source) }
    $requiredDelta = @(
        'RETEST-V011-BETA1-WINDOWS-PERF.ps1',
        'sentinel\watchdog_coalescing.py',
        'tools\v011_low_cpu_runtime_compat.py',
        'tests\test_v011_beta1_watchdog_coalescing.py',
        'tests\test_v011_beta1_low_cpu_runtime_compat.py',
        'tests\test_v011_beta1_service_performance.py'
    )
    foreach ($relative in $requiredDelta) {
        if (-not (Test-Path -LiteralPath (Join-Path $Source $relative))) {
            throw ('Downloaded Git delta is incomplete. Missing: ' + $relative)
        }
    }

    Copy-Item -Path (Join-Path $Source '*') -Destination $PSScriptRoot -Recurse -Force
    Write-Host 'Latest Git delta applied.' -ForegroundColor Green

    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'

    Write-Host 'Applying low-CPU runtime compatibility before rebuild...' -ForegroundColor Cyan
    & $Py -m tools.v011_low_cpu_runtime_compat
    if ($LASTEXITCODE -ne 0) { throw 'Low-CPU runtime compatibility migration failed' }

    $targeted = @(
        'tests\test_v011_beta1_watchdog_coalescing.py',
        'tests\test_v011_beta1_low_cpu_runtime_compat.py',
        'tests\test_v011_beta1_service_performance.py'
    )
    $targetedTemp = Join-Path $env:TEMP 'bc-sentinel-v011-beta1-targeted'
    Remove-Item -LiteralPath $targetedTemp -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host 'Running targeted scheduler/runtime/performance regression tests...' -ForegroundColor Cyan
    & $Py -m pytest -q --basetemp $targetedTemp $targeted
    if ($LASTEXITCODE -ne 0) { throw 'Targeted scheduler/runtime/performance tests failed' }

    & $Py -m compileall -q sentinel tools tests
    if ($LASTEXITCODE -ne 0) { throw 'compileall failed' }

    Write-Host 'Rebuilding Protection Service and UAC Broker from standard-user PowerShell...' -ForegroundColor Cyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\BUILD-SERVIZIO-PROTEZIONE.ps1'
    if ($LASTEXITCODE -ne 0) { throw 'Protection Service/UAC Broker build failed' }

    $distService = Join-Path $PSScriptRoot 'dist\BC-Sentinel-Protection\BC-Sentinel-Protection.exe'
    if (-not (Test-Path -LiteralPath $distService)) {
        throw ('Rebuilt Protection Service missing: ' + $distService)
    }

    Write-Host 'Targeted source tests and rebuild PASS. Opening UAC for live repair + Windows/performance retest...' -ForegroundColor Green
}
catch {
    Fail $_.Exception.Message
}
finally {
    Remove-Item -LiteralPath $Zip -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue
}

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\RETEST-V011-BETA1-WINDOWS-PERF.ps1'
exit $LASTEXITCODE
