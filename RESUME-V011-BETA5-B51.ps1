param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.5 B5-1 BOOTSTRAP - FAIL' -ForegroundColor Red
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
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run B5-1 from normal non-elevated PowerShell.' }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }

    $PatchRef = '44e9166df298cbc47e61fab8c8773ec362908c59'
    $RepoRaw = 'https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/'

    Write-Host 'BC Sentinel v0.11.0-beta.5 - B5-1 HOSTILE / DAMAGED SYSTEM SCENARIOS BOOTSTRAP' -ForegroundColor Cyan
    Write-Host 'Read-only hostile/damaged assessment. No repair, quarantine, delete, registry/boot write or target execution.' -ForegroundColor Yellow

    $Protected = @('.\sentinel\protection_service_core.py','.\sentinel\realtime.py','.\sentinel\edr.py','.\sentinel\edr_service_bridge.py')
    $Before = @{}
    foreach ($path in $Protected) {
        if (-not (Test-Path -LiteralPath $path)) { throw ('protected source missing: ' + $path) }
        $Before[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    $PredecessorRequired = @(
        '.\sentinel\rescue_contract.py','.\sentinel\rescue_portable.py','.\sentinel\rescue_usb.py','.\sentinel\rescue_offline_scanner.py',
        '.\sentinel\rescue_repair_engine.py','.\sentinel\rescue_repair_portable.py','.\sentinel\rescue_data_rescue.py','.\sentinel\rescue_integrity_certification.py',
        '.\sentinel\rescue_console.py','.\sentinel\rescue_console_guided_scan.py','.\sentinel\rescue_console_guided_repair.py','.\sentinel\rescue_console_guided_data_rescue.py',
        '.\sentinel\rescue_console_integrated_certification.py','.\sentinel\rescue_console_portable.py','.\sentinel\rescue_target_discovery.py',
        '.\tests\test_v011_beta5_b50_real_world_target_discovery.py','.\tools\v011_beta5_b50_acceptance.py'
    )
    foreach($p in $PredecessorRequired){ if(-not (Test-Path -LiteralPath $p)){ throw ('predecessor file missing; run accepted B5-0 bootstrap first: ' + $p) } }

    $Files = @(
        @('sentinel\rescue_hostile_scenarios.py','sentinel/rescue_hostile_scenarios.py'),
        @('tests\test_v011_beta5_b51_hostile_damaged_system_scenarios.py','tests/test_v011_beta5_b51_hostile_damaged_system_scenarios.py'),
        @('tools\v011_beta5_b51_acceptance.py','tools/v011_beta5_b51_acceptance.py'),
        @('TEST-V011-BETA5-B51.ps1','TEST-V011-BETA5-B51.ps1'),
        @('BC_SENTINEL_V011_BETA5_B51_HOSTILE_DAMAGED_SCENARIOS.md','BC_SENTINEL_V011_BETA5_B51_HOSTILE_DAMAGED_SCENARIOS.md'),
        @('BC_Sentinel_Roadmap_v0_11_0_Beta5.md','BC_Sentinel_Roadmap_v0_11_0_Beta5.md')
    )
    foreach($item in $Files){ Download-RequiredFile $item[0] ($RepoRaw + $PatchRef + '/' + $item[1]) }

    foreach($path in $Protected){$after=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant(); if($after -ne $Before[$path]){throw ('B5-1 bootstrap modified protected source: '+$path)}}
    Write-Host 'Protected B2 service/realtime/EDR sources unchanged after B5-1 bootstrap download.' -ForegroundColor Green

    $RepoRoot=(Resolve-Path -LiteralPath $PSScriptRoot).Path
    $OldPythonPath=$env:PYTHONPATH
    if([string]::IsNullOrWhiteSpace($OldPythonPath)){$env:PYTHONPATH=$RepoRoot}else{$env:PYTHONPATH=$RepoRoot+[IO.Path]::PathSeparator+$OldPythonPath}
    Write-Host ('B51 BOOTSTRAP PYTHONPATH_ROOT=' + $RepoRoot) -ForegroundColor DarkGray
    try {
        Write-Host 'Launching Beta3 + complete Beta4 + B5-0..B5-1 regression and Windows hostile-scenario acceptance...' -ForegroundColor DarkCyan
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\TEST-V011-BETA5-B51.ps1'
        if($LASTEXITCODE -ne 0){throw 'B5-1 acceptance failed'}
    }
    finally{$env:PYTHONPATH=$OldPythonPath}

    foreach($path in $Protected){$after=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant(); if($after -ne $Before[$path]){throw ('B5-1 acceptance modified protected source: '+$path)}}
    Write-Host 'BC SENTINEL v0.11.0-beta.5 B5-1 BOOTSTRAP - PASS' -ForegroundColor Green
    exit 0
}
catch { Fail $_.Exception.Message }
