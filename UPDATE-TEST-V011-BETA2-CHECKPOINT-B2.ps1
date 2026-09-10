param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.2 CHECKPOINT B2 UPDATE - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

$Zip = Join-Path $env:TEMP 'bc-sentinel-v011-beta2-b2-latest.zip'
$Stage = Join-Path $env:TEMP 'bc-sentinel-v011-beta2-b2-latest'
$Url = 'https://github.com/Johnnyilbello/BC-sentinel/archive/refs/heads/v0.11.0-beta.2-checkpoint-b.zip'

try {
    $requiredFullBaseline = @(
        '.\sentinel\protection_service_core.py',
        '.\sentinel\protection_protocol.py',
        '.\sentinel\protection_client.py',
        '.\packaging\protection_service_entry.py',
        '.\BUILD-SERVIZIO-PROTEZIONE.ps1',
        '.\AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1',
        '.\TEST-V011-BETA1-ADMIN-PHASE.ps1'
    )
    foreach ($item in $requiredFullBaseline) {
        if (-not (Test-Path -LiteralPath $item)) {
            throw ('Incomplete FULL baseline. Missing required local file: ' + $item)
        }
    }

    Write-Host 'BC Sentinel v0.11.0-beta.2 Checkpoint B2 - downloading latest live acceptance delta...' -ForegroundColor Cyan
    Remove-Item -LiteralPath $Zip -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue
    Invoke-WebRequest -Uri $Url -OutFile $Zip
    Expand-Archive -LiteralPath $Zip -DestinationPath $Stage -Force

    $Source = Join-Path $Stage 'BC-sentinel-0.11.0-beta.2-checkpoint-b'
    if (-not (Test-Path -LiteralPath $Source)) {
        throw ('Downloaded branch layout is invalid: ' + $Source)
    }

    $requiredDelta = @(
        'sentinel\edr.py',
        'sentinel\edr_adapter.py',
        'sentinel\edr_hunting.py',
        'sentinel\edr_service_bridge.py',
        'tools\v011_beta2_b1b_patch.py',
        'tools\v011_beta2_b1b_acceptance.py',
        'tools\v011_beta2_b2_live_acceptance.py',
        'tools\v011_threat_trust_windows_compat.py',
        'tests\test_v011_beta2_b2_contract.py',
        'tests\test_v011_beta2_threat_trust_windows_compat.py',
        'TEST-V011-BETA2-CHECKPOINT-B2.ps1',
        'TEST-V011-BETA2-CHECKPOINT-B2-ADMIN.ps1',
        'TEST-V011-BETA2-CHECKPOINT-B2.bat'
    )
    foreach ($relative in $requiredDelta) {
        if (-not (Test-Path -LiteralPath (Join-Path $Source $relative))) {
            throw ('Downloaded Checkpoint B2 delta is incomplete. Missing: ' + $relative)
        }
    }

    # Overlay Git delta only. FULL-only protocol/service/client remain exactly as
    # accepted by B1b and are verified by SHA before any B2 live action.
    Copy-Item -Path (Join-Path $Source '*') -Destination $PSScriptRoot -Recurse -Force
    Write-Host 'Checkpoint B2 delta applied. Starting full service-native live gate...' -ForegroundColor Green
}
catch {
    Fail $_.Exception.Message
}
finally {
    Remove-Item -LiteralPath $Zip -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue
}

& cmd.exe /d /c 'TEST-V011-BETA2-CHECKPOINT-B2.bat'
exit $LASTEXITCODE
