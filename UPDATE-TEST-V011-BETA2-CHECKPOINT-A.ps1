param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.2 CHECKPOINT A - GIT UPDATE/TEST FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

$Zip = Join-Path $env:TEMP 'bc-sentinel-v011-beta2-checkpoint-a-latest.zip'
$Stage = Join-Path $env:TEMP 'bc-sentinel-v011-beta2-checkpoint-a-latest'
$Url = 'https://github.com/Johnnyilbello/BC-sentinel/archive/refs/heads/v0.11.0-beta.2.zip'

try {
    $requiredFullBaseline = @(
        '.\TEST-V011-BETA1-ALL.bat',
        '.\sentinel\edr.py',
        '.\sentinel\edr_adapter.py',
        '.\sentinel\config.py',
        '.\tools\v011_edr_acceptance.py'
    )
    foreach ($item in $requiredFullBaseline) {
        if (-not (Test-Path -LiteralPath $item)) {
            throw ('Incomplete v0.11 Beta1 FULL baseline. Missing required local file: ' + $item)
        }
    }

    Write-Host 'BC Sentinel v0.11.0-beta.2 checkpoint A - downloading latest Git delta...' -ForegroundColor Cyan
    Remove-Item -LiteralPath $Zip -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue

    Invoke-WebRequest -Uri $Url -OutFile $Zip
    Expand-Archive -LiteralPath $Zip -DestinationPath $Stage -Force

    $Source = Join-Path $Stage 'BC-sentinel-0.11.0-beta.2'
    if (-not (Test-Path -LiteralPath $Source)) {
        throw ('Downloaded branch layout is invalid: ' + $Source)
    }

    $requiredDelta = @(
        'sentinel\edr_hunting.py',
        'tests\test_v011_beta2_hunting.py',
        'tools\v011_beta2_hunting_acceptance.py',
        'TEST-V011-BETA2-CHECKPOINT-A.ps1',
        'TEST-V011-BETA2-CHECKPOINT-A.bat'
    )
    foreach ($relative in $requiredDelta) {
        if (-not (Test-Path -LiteralPath (Join-Path $Source $relative))) {
            throw ('Downloaded Beta2 delta is incomplete. Missing: ' + $relative)
        }
    }

    # Beta2 remains a delta over the already-certified Beta1 FULL Windows tree.
    # Overlay only; never delete files that exist only in the authoritative FULL baseline.
    Copy-Item -Path (Join-Path $Source '*') -Destination $PSScriptRoot -Recurse -Force

    Write-Host 'Latest Beta2 checkpoint A delta applied. Starting targeted gate...' -ForegroundColor Green
}
catch {
    Fail $_.Exception.Message
}
finally {
    Remove-Item -LiteralPath $Zip -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue
}

& cmd.exe /d /c 'TEST-V011-BETA2-CHECKPOINT-A.bat'
exit $LASTEXITCODE
