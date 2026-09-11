param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.3 RR-0 BOOTSTRAP - FAIL' -ForegroundColor Red
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
        throw 'Run RR-0 from normal PowerShell; this architecture gate does not require elevation.'
    }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }

    $Ref = 'eed9ec79c7e347bffb589d4b14852b88064167b3'
    $RepoRaw = 'https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/'

    Write-Host 'BC Sentinel v0.11.0-beta.3 - RR-0 BOOTSTRAP' -ForegroundColor Cyan
    Write-Host 'Downloads architecture-only RR-0 contract/tests. No Protection Service, realtime, EDR or remediation source is replaced.' -ForegroundColor Yellow

    $files = @(
        @('sentinel\rescue_contract.py','sentinel/rescue_contract.py'),
        @('tests\test_v011_beta3_rr0_rescue_contract.py','tests/test_v011_beta3_rr0_rescue_contract.py'),
        @('tools\v011_beta3_rr0_acceptance.py','tools/v011_beta3_rr0_acceptance.py'),
        @('BC_SENTINEL_V011_BETA3_RR0_ARCHITECTURE_SAFETY.md','BC_SENTINEL_V011_BETA3_RR0_ARCHITECTURE_SAFETY.md'),
        @('TEST-V011-BETA3-RR0.ps1','TEST-V011-BETA3-RR0.ps1')
    )
    foreach ($item in $files) {
        Download-RequiredFile $item[0] ($RepoRaw + $Ref + '/' + $item[1])
    }

    Write-Host 'Launching deterministic RR-0 acceptance...' -ForegroundColor Cyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\TEST-V011-BETA3-RR0.ps1'
    if ($LASTEXITCODE -ne 0) { throw 'RR-0 acceptance launcher failed' }

    Write-Host 'BC SENTINEL v0.11.0-beta.3 RR-0 BOOTSTRAP - PASS' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
