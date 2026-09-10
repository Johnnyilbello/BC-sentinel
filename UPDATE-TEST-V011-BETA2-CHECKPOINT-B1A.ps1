param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.2 CHECKPOINT B1a UPDATE - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

$Zip = Join-Path $env:TEMP 'bc-sentinel-v011-beta2-b1a-latest.zip'
$Stage = Join-Path $env:TEMP 'bc-sentinel-v011-beta2-b1a-latest'
$Url = 'https://github.com/Johnnyilbello/BC-sentinel/archive/refs/heads/v0.11.0-beta.2-checkpoint-b.zip'

try {
    $requiredFullBaseline = @(
        '.\sentinel\protection_service_core.py',
        '.\packaging\protection_service_entry.py',
        '.\BUILD-SERVIZIO-PROTEZIONE.ps1',
        '.\AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1'
    )
    foreach ($item in $requiredFullBaseline) {
        if (-not (Test-Path -LiteralPath $item)) {
            throw ('Incomplete FULL baseline. Missing required local file: ' + $item)
        }
    }

    Write-Host 'BC Sentinel v0.11.0-beta.2 Checkpoint B1a - downloading latest integration delta...' -ForegroundColor Cyan
    Remove-Item -LiteralPath $Zip -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue
    Invoke-WebRequest -Uri $Url -OutFile $Zip
    Expand-Archive -LiteralPath $Zip -DestinationPath $Stage -Force

    $Source = Join-Path $Stage 'BC-sentinel-0.11.0-beta.2-checkpoint-b'
    if (-not (Test-Path -LiteralPath $Source)) {
        throw ('Downloaded branch layout is invalid: ' + $Source)
    }

    $requiredDelta = @(
        'sentinel\edr_service_bridge.py',
        'tools\v011_beta2_service_preflight.py',
        'tools\v011_beta2_service_runtime_patch.py',
        'tests\test_v011_beta2_service_runtime_patch.py',
        'TEST-V011-BETA2-CHECKPOINT-B1A.ps1',
        'TEST-V011-BETA2-CHECKPOINT-B1A.bat'
    )
    foreach ($relative in $requiredDelta) {
        if (-not (Test-Path -LiteralPath (Join-Path $Source $relative))) {
            throw ('Downloaded Checkpoint B1a delta is incomplete. Missing: ' + $relative)
        }
    }

    # Overlay only. FULL-only Protection Service source is preserved until the
    # fail-closed B1a patcher validates the exact B0 source SHA and AST shape.
    Copy-Item -Path (Join-Path $Source '*') -Destination $PSScriptRoot -Recurse -Force
    Write-Host 'Checkpoint B1a delta applied. Starting guarded ProtectionRuntime integration...' -ForegroundColor Green
}
catch {
    Fail $_.Exception.Message
}
finally {
    Remove-Item -LiteralPath $Zip -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue
}

& cmd.exe /d /c 'TEST-V011-BETA2-CHECKPOINT-B1A.bat'
exit $LASTEXITCODE
