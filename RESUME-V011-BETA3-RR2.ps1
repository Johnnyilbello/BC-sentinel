param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Stage,[string]$Message) {
    Write-Host ('RR2 BOOTSTRAP FAIL STAGE=' + $Stage + ' | ' + $Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.3 RR-2 BOOTSTRAP - FAIL' -ForegroundColor Red
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
        throw 'Run RR2 from normal non-elevated PowerShell.'
    }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }

    $PatchRef = '76a41b8b90d5b2b94af21c91116fad66e01393b4'
    $RepoRaw = 'https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/'

    Write-Host 'BC Sentinel v0.11.0-beta.3 - RR-2 RESCUE USB BOOTSTRAP' -ForegroundColor Cyan
    Write-Host 'Safe-media scope: no format, partition/boot-sector/bootloader/BCD/firmware writes and no repair execution.' -ForegroundColor Yellow

    $Protected = @(
        '.\sentinel\protection_service_core.py',
        '.\sentinel\realtime.py',
        '.\sentinel\edr.py',
        '.\sentinel\edr_service_bridge.py'
    )
    $Before = @{}
    foreach ($path in $Protected) {
        if (-not (Test-Path -LiteralPath $path)) { Fail 'protected_source_preflight' ('missing ' + $path) }
        $Before[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    $Files = @(
        @('sentinel\rescue_contract.py','sentinel/rescue_contract.py'),
        @('sentinel\rescue_portable.py','sentinel/rescue_portable.py'),
        @('sentinel\rescue_usb.py','sentinel/rescue_usb.py'),
        @('tests\test_v011_beta3_rr0_rescue_contract.py','tests/test_v011_beta3_rr0_rescue_contract.py'),
        @('tests\test_v011_beta3_rr1_portable.py','tests/test_v011_beta3_rr1_portable.py'),
        @('tests\test_v011_beta3_rr2_rescue_usb.py','tests/test_v011_beta3_rr2_rescue_usb.py'),
        @('tools\v011_beta3_rr0_acceptance.py','tools/v011_beta3_rr0_acceptance.py'),
        @('tools\v011_beta3_rr1_acceptance.py','tools/v011_beta3_rr1_acceptance.py'),
        @('tools\v011_beta3_rr2_acceptance.py','tools/v011_beta3_rr2_acceptance.py'),
        @('packaging\rescue_portable_entry.py','packaging/rescue_portable_entry.py'),
        @('BUILD-RESCUE-PORTABLE.ps1','BUILD-RESCUE-PORTABLE.ps1'),
        @('TEST-V011-BETA3-RR2.ps1','TEST-V011-BETA3-RR2.ps1'),
        @('BC_SENTINEL_V011_BETA3_RR2_RESCUE_USB.md','BC_SENTINEL_V011_BETA3_RR2_RESCUE_USB.md'),
        @('BC_Sentinel_Roadmap_v0_11_0_Beta3_Updated.md','BC_Sentinel_Roadmap_v0_11_0_Beta3_Updated.md')
    )
    foreach ($item in $Files) {
        Download-RequiredFile $item[0] ($RepoRaw + $PatchRef + '/' + $item[1])
    }

    foreach ($path in $Protected) {
        $after = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($after -ne $Before[$path]) { Fail 'bootstrap_source_guard' ('RR2 bootstrap modified protected B2 source: ' + $path) }
    }
    Write-Host 'Protected B2 service/realtime/EDR sources unchanged after bootstrap download.' -ForegroundColor Green

    Write-Host 'Launching RR2 deterministic + live safe-media Windows acceptance...' -ForegroundColor DarkCyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\TEST-V011-BETA3-RR2.ps1'
    if ($LASTEXITCODE -ne 0) { Fail 'rr2_acceptance' ('TEST-V011-BETA3-RR2.ps1 exit=' + $LASTEXITCODE) }

    foreach ($path in $Protected) {
        $after = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($after -ne $Before[$path]) { Fail 'final_source_guard' ('RR2 acceptance modified protected B2 source: ' + $path) }
    }

    Write-Host 'BC SENTINEL v0.11.0-beta.3 RR-2 BOOTSTRAP - PASS' -ForegroundColor Green
    exit 0
}
catch {
    Fail 'unhandled' $_.Exception.Message
}
