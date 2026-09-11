param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.3 RR-3 BOOTSTRAP - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

function Download-RequiredFile([string]$Destination,[string]$Uri) {
    $parent = Split-Path -Parent $Destination
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Write-Host ('Downloading: ' + $Uri) -ForegroundColor DarkGray
    Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $Destination -ErrorAction Stop
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run RR3 from normal non-elevated PowerShell.'
    }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }

    $PatchRef = '9fe7d64f4865233ca8a88a586a7e174c2a800fdf'
    $RepoRaw = 'https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/'

    Write-Host 'BC Sentinel v0.11.0-beta.3 - RR-3 OFFLINE THREAT SCANNER BOOTSTRAP' -ForegroundColor Cyan
    Write-Host 'Read-only offline analysis. No Protection Service/realtime/EDR replacement and no repair/delete/quarantine execution.' -ForegroundColor Yellow

    $Protected = @(
        '.\sentinel\protection_service_core.py',
        '.\sentinel\realtime.py',
        '.\sentinel\edr.py',
        '.\sentinel\edr_service_bridge.py'
    )
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
        @('tests\test_v011_beta3_rr0_rescue_contract.py','tests/test_v011_beta3_rr0_rescue_contract.py'),
        @('tests\test_v011_beta3_rr1_portable.py','tests/test_v011_beta3_rr1_portable.py'),
        @('tests\test_v011_beta3_rr2_rescue_usb.py','tests/test_v011_beta3_rr2_rescue_usb.py'),
        @('tests\test_v011_beta3_rr3_offline_scanner.py','tests/test_v011_beta3_rr3_offline_scanner.py'),
        @('tools\v011_beta3_rr0_acceptance.py','tools/v011_beta3_rr0_acceptance.py'),
        @('tools\v011_beta3_rr1_acceptance.py','tools/v011_beta3_rr1_acceptance.py'),
        @('tools\v011_beta3_rr2_acceptance.py','tools/v011_beta3_rr2_acceptance.py'),
        @('tools\v011_beta3_rr3_acceptance.py','tools/v011_beta3_rr3_acceptance.py'),
        @('packaging\rescue_offline_scanner_entry.py','packaging/rescue_offline_scanner_entry.py'),
        @('BUILD-RESCUE-OFFLINE-SCANNER.ps1','BUILD-RESCUE-OFFLINE-SCANNER.ps1'),
        @('TEST-V011-BETA3-RR3.ps1','TEST-V011-BETA3-RR3.ps1'),
        @('BC_SENTINEL_V011_BETA3_RR3_OFFLINE_THREAT_SCANNER.md','BC_SENTINEL_V011_BETA3_RR3_OFFLINE_THREAT_SCANNER.md'),
        @('BC_Sentinel_Roadmap_v0_11_0_Beta3_Updated.md','BC_Sentinel_Roadmap_v0_11_0_Beta3_Updated.md')
    )
    foreach ($item in $Files) {
        Download-RequiredFile $item[0] ($RepoRaw + $PatchRef + '/' + $item[1])
    }

    foreach ($path in $Protected) {
        $after = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($after -ne $Before[$path]) { throw ('RR3 bootstrap modified protected source: ' + $path) }
    }
    Write-Host 'Protected B2 service/realtime/EDR sources unchanged after RR3 bootstrap download.' -ForegroundColor Green

    Write-Host 'Launching RR3 deterministic + real portable Windows acceptance...' -ForegroundColor DarkCyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\TEST-V011-BETA3-RR3.ps1'
    if ($LASTEXITCODE -ne 0) { throw 'RR3 acceptance failed' }

    foreach ($path in $Protected) {
        $after = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($after -ne $Before[$path]) { throw ('RR3 acceptance modified protected source: ' + $path) }
    }

    Write-Host 'BC SENTINEL v0.11.0-beta.3 RR-3 BOOTSTRAP - PASS' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
