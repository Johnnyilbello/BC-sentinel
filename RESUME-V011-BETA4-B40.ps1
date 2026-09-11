param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.4 B4-0 BOOTSTRAP - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

function Download-RequiredFile([string]$Destination,[string]$Uri) {
    $parent = Split-Path -Parent $Destination
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    Write-Host ('Downloading: ' + $Uri) -ForegroundColor DarkGray
    Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $Destination -ErrorAction Stop
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run B4-0 from normal non-elevated PowerShell.' }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }

    $PatchRef = '677ae60013b9e5c116bee12cee076617cfa04790'
    $RepoRaw = 'https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/'

    Write-Host 'BC Sentinel v0.11.0-beta.4 - B4-0 RESCUE CONSOLE FOUNDATION BOOTSTRAP' -ForegroundColor Cyan
    Write-Host 'Read-only orchestration only. No new mutation authority is enabled.' -ForegroundColor Yellow

    $Protected = @('.\sentinel\protection_service_core.py','.\sentinel\realtime.py','.\sentinel\edr.py','.\sentinel\edr_service_bridge.py')
    $Before = @{}
    foreach ($path in $Protected) {
        if (-not (Test-Path -LiteralPath $path)) { throw ('protected source missing: ' + $path) }
        $Before[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    $Files = @(
        @('sentinel\rescue_contract.py','sentinel/rescue_contract.py'),
        @('sentinel\rescue_portable.py','sentinel/rescue_portable.py'),
        @('sentinel\rescue_usb.py','sentinel/rescue_usb.py'),
        @('sentinel\rescue_offline_scanner.py','sentinel/rescue_offline_scanner.py'),
        @('sentinel\rescue_repair_engine.py','sentinel/rescue_repair_engine.py'),
        @('sentinel\rescue_repair_portable.py','sentinel/rescue_repair_portable.py'),
        @('sentinel\rescue_data_rescue.py','sentinel/rescue_data_rescue.py'),
        @('sentinel\rescue_integrity_certification.py','sentinel/rescue_integrity_certification.py'),
        @('sentinel\rescue_console.py','sentinel/rescue_console.py'),
        @('tests\test_v011_beta3_rr0_rescue_contract.py','tests/test_v011_beta3_rr0_rescue_contract.py'),
        @('tests\test_v011_beta3_rr1_portable.py','tests/test_v011_beta3_rr1_portable.py'),
        @('tests\test_v011_beta3_rr2_rescue_usb.py','tests/test_v011_beta3_rr2_rescue_usb.py'),
        @('tests\test_v011_beta3_rr3_offline_scanner.py','tests/test_v011_beta3_rr3_offline_scanner.py'),
        @('tests\test_v011_beta3_rr4a_repair_engine.py','tests/test_v011_beta3_rr4a_repair_engine.py'),
        @('tests\test_v011_beta3_rr4b_portable_repair.py','tests/test_v011_beta3_rr4b_portable_repair.py'),
        @('tests\test_v011_beta3_rr5_safe_data_rescue.py','tests/test_v011_beta3_rr5_safe_data_rescue.py'),
        @('tests\test_v011_beta3_rr6_integrity_certification.py','tests/test_v011_beta3_rr6_integrity_certification.py'),
        @('tests\test_v011_beta4_b40_rescue_console.py','tests/test_v011_beta4_b40_rescue_console.py'),
        @('tools\v011_beta3_rr0_acceptance.py','tools/v011_beta3_rr0_acceptance.py'),
        @('tools\v011_beta3_rr1_acceptance.py','tools/v011_beta3_rr1_acceptance.py'),
        @('tools\v011_beta3_rr2_acceptance.py','tools/v011_beta3_rr2_acceptance.py'),
        @('tools\v011_beta3_rr3_acceptance.py','tools/v011_beta3_rr3_acceptance.py'),
        @('tools\v011_beta3_rr4a_acceptance.py','tools/v011_beta3_rr4a_acceptance.py'),
        @('tools\v011_beta3_rr4b_acceptance.py','tools/v011_beta3_rr4b_acceptance.py'),
        @('tools\v011_beta3_rr5_acceptance.py','tools/v011_beta3_rr5_acceptance.py'),
        @('tools\v011_beta3_rr6_acceptance.py','tools/v011_beta3_rr6_acceptance.py'),
        @('tools\v011_beta4_b40_acceptance.py','tools/v011_beta4_b40_acceptance.py'),
        @('TEST-V011-BETA4-B40.ps1','TEST-V011-BETA4-B40.ps1'),
        @('BC_SENTINEL_V011_BETA4_B40_RESCUE_CONSOLE_FOUNDATION.md','BC_SENTINEL_V011_BETA4_B40_RESCUE_CONSOLE_FOUNDATION.md'),
        @('BC_Sentinel_Roadmap_v0_11_0_Beta4.md','BC_Sentinel_Roadmap_v0_11_0_Beta4.md')
    )

    foreach ($item in $Files) { Download-RequiredFile $item[0] ($RepoRaw + $PatchRef + '/' + $item[1]) }

    foreach ($path in $Protected) {
        $after = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($after -ne $Before[$path]) { throw ('B4-0 bootstrap modified protected source: ' + $path) }
    }
    Write-Host 'Protected B2 service/realtime/EDR sources unchanged after B4-0 bootstrap download.' -ForegroundColor Green

    $RepoRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
    $OldPythonPath = $env:PYTHONPATH
    if ([string]::IsNullOrWhiteSpace($OldPythonPath)) { $env:PYTHONPATH = $RepoRoot }
    else { $env:PYTHONPATH = $RepoRoot + [IO.Path]::PathSeparator + $OldPythonPath }
    Write-Host ('B40 BOOTSTRAP PYTHONPATH_ROOT=' + $RepoRoot) -ForegroundColor DarkGray

    try {
        Write-Host 'Launching Beta3 regression + B4-0 deterministic + live Windows planning acceptance...' -ForegroundColor DarkCyan
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\TEST-V011-BETA4-B40.ps1'
        if ($LASTEXITCODE -ne 0) { throw 'B4-0 acceptance failed' }
    }
    finally {
        $env:PYTHONPATH = $OldPythonPath
    }

    foreach ($path in $Protected) {
        $after = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($after -ne $Before[$path]) { throw ('B4-0 acceptance modified protected source: ' + $path) }
    }

    Write-Host 'BC SENTINEL v0.11.0-beta.4 B4-0 BOOTSTRAP - PASS' -ForegroundColor Green
    exit 0
}
catch { Fail $_.Exception.Message }
