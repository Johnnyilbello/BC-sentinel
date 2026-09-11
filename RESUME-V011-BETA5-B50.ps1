param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.5 B5-0 BOOTSTRAP - FAIL' -ForegroundColor Red
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
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run B5-0 from normal non-elevated PowerShell.' }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }

    $PatchRef = 'e53837da29fd734c01e68d6f17c401b9e541c2af'
    $RepoRaw = 'https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/'

    Write-Host 'BC Sentinel v0.11.0-beta.5 - B5-0 REAL-WORLD TARGET DISCOVERY BOOTSTRAP' -ForegroundColor Cyan
    Write-Host 'Read-only discovery + live SystemDrive refusal + observational BitLocker status. No unlock/mount/write.' -ForegroundColor Yellow

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
        @('sentinel\rescue_console_guided_scan.py','sentinel/rescue_console_guided_scan.py'),
        @('sentinel\rescue_console_guided_repair.py','sentinel/rescue_console_guided_repair.py'),
        @('sentinel\rescue_console_guided_data_rescue.py','sentinel/rescue_console_guided_data_rescue.py'),
        @('sentinel\rescue_console_integrated_certification.py','sentinel/rescue_console_integrated_certification.py'),
        @('sentinel\rescue_console_portable.py','sentinel/rescue_console_portable.py'),
        @('sentinel\rescue_target_discovery.py','sentinel/rescue_target_discovery.py'),
        @('tests\test_v011_beta3_rr0_rescue_contract.py','tests/test_v011_beta3_rr0_rescue_contract.py'),
        @('tests\test_v011_beta3_rr1_portable.py','tests/test_v011_beta3_rr1_portable.py'),
        @('tests\test_v011_beta3_rr2_rescue_usb.py','tests/test_v011_beta3_rr2_rescue_usb.py'),
        @('tests\test_v011_beta3_rr3_offline_scanner.py','tests/test_v011_beta3_rr3_offline_scanner.py'),
        @('tests\test_v011_beta3_rr4a_repair_engine.py','tests/test_v011_beta3_rr4a_repair_engine.py'),
        @('tests\test_v011_beta3_rr4b_portable_repair.py','tests/test_v011_beta3_rr4b_portable_repair.py'),
        @('tests\test_v011_beta3_rr5_safe_data_rescue.py','tests/test_v011_beta3_rr5_safe_data_rescue.py'),
        @('tests\test_v011_beta3_rr6_integrity_certification.py','tests/test_v011_beta3_rr6_integrity_certification.py'),
        @('tests\test_v011_beta4_b40_rescue_console.py','tests/test_v011_beta4_b40_rescue_console.py'),
        @('tests\test_v011_beta4_b41_evidence_inventory_guided_scan.py','tests/test_v011_beta4_b41_evidence_inventory_guided_scan.py'),
        @('tests\test_v011_beta4_b42_guided_repair_handoff.py','tests/test_v011_beta4_b42_guided_repair_handoff.py'),
        @('tests\test_v011_beta4_b43_guided_safe_data_rescue.py','tests/test_v011_beta4_b43_guided_safe_data_rescue.py'),
        @('tests\test_v011_beta4_b44_integrated_certification_summary.py','tests/test_v011_beta4_b44_integrated_certification_summary.py'),
        @('tests\test_v011_beta4_b45_portable_rescue_console.py','tests/test_v011_beta4_b45_portable_rescue_console.py'),
        @('tests\test_v011_beta5_b50_real_world_target_discovery.py','tests/test_v011_beta5_b50_real_world_target_discovery.py'),
        @('tools\v011_beta3_rr0_acceptance.py','tools/v011_beta3_rr0_acceptance.py'),
        @('tools\v011_beta3_rr1_acceptance.py','tools/v011_beta3_rr1_acceptance.py'),
        @('tools\v011_beta3_rr2_acceptance.py','tools/v011_beta3_rr2_acceptance.py'),
        @('tools\v011_beta3_rr3_acceptance.py','tools/v011_beta3_rr3_acceptance.py'),
        @('tools\v011_beta3_rr4a_acceptance.py','tools/v011_beta3_rr4a_acceptance.py'),
        @('tools\v011_beta3_rr4b_acceptance.py','tools/v011_beta3_rr4b_acceptance.py'),
        @('tools\v011_beta3_rr5_acceptance.py','tools/v011_beta3_rr5_acceptance.py'),
        @('tools\v011_beta3_rr6_acceptance.py','tools/v011_beta3_rr6_acceptance.py'),
        @('tools\v011_beta4_b40_acceptance.py','tools/v011_beta4_b40_acceptance.py'),
        @('tools\v011_beta4_b41_acceptance.py','tools/v011_beta4_b41_acceptance.py'),
        @('tools\v011_beta4_b42_acceptance.py','tools/v011_beta4_b42_acceptance.py'),
        @('tools\v011_beta4_b43_acceptance.py','tools/v011_beta4_b43_acceptance.py'),
        @('tools\v011_beta4_b44_acceptance.py','tools/v011_beta4_b44_acceptance.py'),
        @('tools\v011_beta4_b45_acceptance.py','tools/v011_beta4_b45_acceptance.py'),
        @('tools\v011_beta5_b50_acceptance.py','tools/v011_beta5_b50_acceptance.py'),
        @('TEST-V011-BETA5-B50.ps1','TEST-V011-BETA5-B50.ps1'),
        @('BC_SENTINEL_V011_BETA5_B50_REAL_WORLD_TARGET_DISCOVERY.md','BC_SENTINEL_V011_BETA5_B50_REAL_WORLD_TARGET_DISCOVERY.md'),
        @('BC_Sentinel_Roadmap_v0_11_0_Beta5.md','BC_Sentinel_Roadmap_v0_11_0_Beta5.md')
    )

    foreach ($item in $Files) { Download-RequiredFile $item[0] ($RepoRaw + $PatchRef + '/' + $item[1]) }

    foreach ($path in $Protected) {
        $after = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($after -ne $Before[$path]) { throw ('B5-0 bootstrap modified protected source: ' + $path) }
    }
    Write-Host 'Protected B2 service/realtime/EDR sources unchanged after B5-0 bootstrap download.' -ForegroundColor Green

    $RepoRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
    $OldPythonPath = $env:PYTHONPATH
    if ([string]::IsNullOrWhiteSpace($OldPythonPath)) { $env:PYTHONPATH = $RepoRoot }
    else { $env:PYTHONPATH = $RepoRoot + [IO.Path]::PathSeparator + $OldPythonPath }
    Write-Host ('B50 BOOTSTRAP PYTHONPATH_ROOT=' + $RepoRoot) -ForegroundColor DarkGray

    try {
        Write-Host 'Launching Beta3 + complete Beta4 + B5-0 regression, deterministic gates and live Windows discovery acceptance...' -ForegroundColor DarkCyan
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\TEST-V011-BETA5-B50.ps1'
        if ($LASTEXITCODE -ne 0) { throw 'B5-0 acceptance failed' }
    }
    finally { $env:PYTHONPATH = $OldPythonPath }

    foreach ($path in $Protected) {
        $after = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($after -ne $Before[$path]) { throw ('B5-0 acceptance modified protected source: ' + $path) }
    }

    Write-Host 'BC SENTINEL v0.11.0-beta.5 B5-0 BOOTSTRAP - PASS' -ForegroundColor Green
    exit 0
}
catch { Fail $_.Exception.Message }
