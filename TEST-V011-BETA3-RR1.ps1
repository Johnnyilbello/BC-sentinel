param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.3 RR-1 PORTABLE - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

function Read-JsonSafe([string]$Path) {
    try {
        if (Test-Path -LiteralPath $Path) { return (Get-Content -Raw -LiteralPath $Path -Encoding UTF8 | ConvertFrom-Json) }
    } catch { }
    return $null
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'RR1 must pass from normal non-elevated PowerShell.'
    }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.3 - RR-1 PORTABLE' -ForegroundColor Cyan
    Write-Host 'No installer, service, driver, registry/boot write, delete, kill or repair execution.' -ForegroundColor Yellow

    & $Py -m compileall -q sentinel\rescue_contract.py sentinel\rescue_portable.py tools\v011_beta3_rr0_acceptance.py tools\v011_beta3_rr1_acceptance.py tests\test_v011_beta3_rr0_rescue_contract.py tests\test_v011_beta3_rr1_portable.py
    if ($LASTEXITCODE -ne 0) { throw 'RR0/RR1 compileall failed' }

    Write-Host 'Running RR0 + RR1 safety regression...' -ForegroundColor DarkCyan
    & $Py -m pytest -q tests/test_v011_beta3_rr0_rescue_contract.py tests/test_v011_beta3_rr1_portable.py
    if ($LASTEXITCODE -ne 0) { throw 'RR0/RR1 pytest regression failed' }

    & $Py -m tools.v011_beta3_rr0_acceptance --output acceptance-v011-beta3-rr0-regression.json
    if ($LASTEXITCODE -ne 0) { throw 'RR0 safety regression acceptance failed' }

    & $Py -m tools.v011_beta3_rr1_acceptance --output acceptance-v011-beta3-rr1.json
    if ($LASTEXITCODE -ne 0) { throw 'RR1 deterministic Python acceptance failed' }

    Write-Host 'Building portable Windows runtime...' -ForegroundColor DarkCyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\BUILD-RESCUE-PORTABLE.ps1'
    if ($LASTEXITCODE -ne 0) { throw 'RR1 portable build failed' }

    $Exe = Join-Path $PSScriptRoot 'dist\Rescue\BC-Sentinel-Rescue-Portable\BC-Sentinel-Rescue-Portable.exe'
    $IntegrityPath = Join-Path $PSScriptRoot 'dist\Rescue\BC-Sentinel-Rescue-Portable\portable-integrity.json'
    if (-not (Test-Path -LiteralPath $Exe) -or -not (Test-Path -LiteralPath $IntegrityPath)) { throw 'RR1 portable build artifacts missing' }
    $Integrity = Read-JsonSafe $IntegrityPath
    if ($null -eq $Integrity -or [string]$Integrity.profile -ne 'v0.11.0-beta.3-rr1') { throw 'RR1 integrity manifest invalid' }
    $ActualHash = (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ActualHash -ne ([string]$Integrity.sha256).ToLowerInvariant()) { throw 'RR1 portable binary provenance mismatch' }

    $Base = Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    if (-not (Test-Path -LiteralPath $Base)) { New-Item -ItemType Directory -Path $Base -Force | Out-Null }
    $RunRoot = Join-Path $Base ('rr1-live-' + [guid]::NewGuid().ToString('N'))
    $Target = Join-Path $RunRoot 'target'
    $Evidence = Join-Path $RunRoot 'evidence'
    New-Item -ItemType Directory -Path $Target -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $Target 'nested') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $Target 'alpha.txt') -Value 'RR1 harmless alpha fixture' -Encoding UTF8
    [IO.File]::WriteAllBytes((Join-Path $Target 'nested\beta.bin'), [byte[]](1,2,3,4,5,6))
    $BeforeA = (Get-FileHash -LiteralPath (Join-Path $Target 'alpha.txt') -Algorithm SHA256).Hash
    $BeforeB = (Get-FileHash -LiteralPath (Join-Path $Target 'nested\beta.bin') -Algorithm SHA256).Hash

    try {
        Write-Host 'Running built portable executable as standard user...' -ForegroundColor DarkCyan
        & $Exe --target $Target --output $Evidence --max-items 32 --max-file-bytes 1048576
        if ($LASTEXITCODE -ne 0) { throw 'built RR1 portable executable returned failure' }

        $EvidenceJson = Join-Path $Evidence 'rr1-evidence.json'
        $Result = Read-JsonSafe $EvidenceJson
        if ($null -eq $Result) { throw 'built RR1 portable evidence JSON missing/unreadable' }
        if ([string]$Result.profile -ne 'v0.11.0-beta.3-rr1') { throw 'built RR1 portable profile mismatch' }
        if ([int]$Result.summary.hashed -ne 2) { throw ('expected 2 hashed files, got ' + [string]$Result.summary.hashed) }
        if ([bool]$Result.manifest.write_authorized) { throw 'portable session unexpectedly authorized writes' }
        if ([bool]$Result.safety.installation_required -or [bool]$Result.safety.service_install -or [bool]$Result.safety.driver_install) { throw 'portable runtime unexpectedly requires install/service/driver' }
        if ([bool]$Result.safety.registry_write -or [bool]$Result.safety.boot_write -or [bool]$Result.safety.target_filesystem_write) { throw 'portable runtime unexpectedly enabled write capabilities' }
        if ([bool]$Result.safety.file_delete -or [bool]$Result.safety.process_kill -or [bool]$Result.safety.repair_engine_enabled) { throw 'portable runtime unexpectedly enabled destructive/repair capability' }

        $AfterA = (Get-FileHash -LiteralPath (Join-Path $Target 'alpha.txt') -Algorithm SHA256).Hash
        $AfterB = (Get-FileHash -LiteralPath (Join-Path $Target 'nested\beta.bin') -Algorithm SHA256).Hash
        if ($BeforeA -ne $AfterA -or $BeforeB -ne $AfterB) { throw 'target content changed during portable acquisition' }

        $Installed = @(Get-CimInstance Win32_Service | Where-Object { ([string]$_.PathName).ToLowerInvariant().Contains('bc-sentinel-rescue-portable.exe') })
        if ($Installed.Count -ne 0) { throw 'portable runtime unexpectedly registered a Windows service' }
    }
    finally {
        Remove-Item -LiteralPath $RunRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host ('RR1 PORTABLE BINARY SHA256=' + $ActualHash) -ForegroundColor Green
    Write-Host 'RR1 LIVE: standard-user launch PASS | target unchanged | 2/2 SHA256 evidence | no service installed' -ForegroundColor Green
    Write-Host 'BC SENTINEL v0.11.0-beta.3 RR-1 PORTABLE - PASS' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
