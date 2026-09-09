param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.1 - GIT UPDATE/TEST FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

$Zip = Join-Path $env:TEMP 'bc-sentinel-v011-beta1-latest.zip'
$Stage = Join-Path $env:TEMP 'bc-sentinel-v011-beta1-latest'
$Url = 'https://github.com/Johnnyilbello/BC-sentinel/archive/refs/heads/v0.11.0-beta.1.zip'

try {
    $requiredFullBaseline = @(
        '.\BUILD-SERVIZIO-PROTEZIONE.ps1',
        '.\AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1',
        '.\sentinel\protection_client.py',
        '.\sentinel\realtime.py',
        '.\tools\windows_acceptance.py',
        '.\tools\service_hardening_benchmark.py'
    )
    foreach ($item in $requiredFullBaseline) {
        if (-not (Test-Path -LiteralPath $item)) {
            throw ('Incomplete FULL baseline. Missing required local file: ' + $item)
        }
    }

    Write-Host 'BC Sentinel v0.11.0-beta.1 - downloading latest Git delta...' -ForegroundColor Cyan
    Remove-Item -LiteralPath $Zip -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue

    Invoke-WebRequest -Uri $Url -OutFile $Zip
    Expand-Archive -LiteralPath $Zip -DestinationPath $Stage -Force

    $Source = Join-Path $Stage 'BC-sentinel-0.11.0-beta.1'
    if (-not (Test-Path -LiteralPath $Source)) {
        throw ('Downloaded branch layout is invalid: ' + $Source)
    }

    $requiredDelta = @(
        'TEST-V011-BETA1-ALL.bat',
        'TEST-V011-BETA1-ALL.ps1',
        'TEST-V011-BETA1-ADMIN-PHASE.ps1',
        'sentinel\pywintrace_idle.py',
        'sentinel\etw_monitor.py',
        'tools\v011_low_cpu_runtime_compat.py'
    )
    foreach ($relative in $requiredDelta) {
        if (-not (Test-Path -LiteralPath (Join-Path $Source $relative))) {
            throw ('Downloaded Git delta is incomplete. Missing: ' + $relative)
        }
    }

    # v0.11 Git is intentionally a delta over the authoritative v0.10 RC1 FULL
    # Windows baseline. Overlay the branch without deleting FULL-only files.
    Copy-Item -Path (Join-Path $Source '*') -Destination $PSScriptRoot -Recurse -Force

    Write-Host 'Latest Git delta applied. Starting the complete one-command gate...' -ForegroundColor Green
}
catch {
    Fail $_.Exception.Message
}
finally {
    Remove-Item -LiteralPath $Zip -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue
}

& cmd.exe /d /c 'TEST-V011-BETA1-ALL.bat'
exit $LASTEXITCODE
