param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.2 CHECKPOINT B1b PREFLIGHT UPDATE - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

$Zip = Join-Path $env:TEMP 'bc-sentinel-v011-beta2-b1b-preflight-latest.zip'
$Stage = Join-Path $env:TEMP 'bc-sentinel-v011-beta2-b1b-preflight-latest'
$Url = 'https://github.com/Johnnyilbello/BC-sentinel/archive/refs/heads/v0.11.0-beta.2-checkpoint-b.zip'

try {
    $requiredFullBaseline = @(
        '.\sentinel\protection_service_core.py',
        '.\sentinel\protection_protocol.py',
        '.\packaging\protection_service_entry.py',
        '.\BUILD-SERVIZIO-PROTEZIONE.ps1',
        '.\AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1'
    )
    foreach ($item in $requiredFullBaseline) {
        if (-not (Test-Path -LiteralPath $item)) { throw ('Incomplete FULL baseline. Missing: ' + $item) }
    }

    Write-Host 'BC Sentinel v0.11.0-beta.2 Checkpoint B1b preflight - downloading latest integration delta...' -ForegroundColor Cyan
    Remove-Item -LiteralPath $Zip -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue
    Invoke-WebRequest -Uri $Url -OutFile $Zip
    Expand-Archive -LiteralPath $Zip -DestinationPath $Stage -Force

    $Source = Join-Path $Stage 'BC-sentinel-0.11.0-beta.2-checkpoint-b'
    if (-not (Test-Path -LiteralPath $Source)) { throw ('Downloaded branch layout is invalid: ' + $Source) }

    $requiredDelta = @(
        'tools\v011_beta2_ipc_preflight.py',
        'tests\test_v011_beta2_ipc_preflight.py',
        'TEST-V011-BETA2-CHECKPOINT-B1B-PREFLIGHT.ps1',
        'TEST-V011-BETA2-CHECKPOINT-B1B-PREFLIGHT.bat'
    )
    foreach ($relative in $requiredDelta) {
        if (-not (Test-Path -LiteralPath (Join-Path $Source $relative))) { throw ('Downloaded B1b preflight delta incomplete: ' + $relative) }
    }

    # Overlay delta only. FULL-only protocol/service files are intentionally not present in Git and remain untouched.
    Copy-Item -Path (Join-Path $Source '*') -Destination $PSScriptRoot -Recurse -Force
    Write-Host 'B1b preflight delta applied. Starting non-mutating IPC discovery...' -ForegroundColor Green
}
catch { Fail $_.Exception.Message }
finally {
    Remove-Item -LiteralPath $Zip -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue
}

& cmd.exe /d /c 'TEST-V011-BETA2-CHECKPOINT-B1B-PREFLIGHT.bat'
exit $LASTEXITCODE
