param()
$ErrorActionPreference='Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message){
    Write-Host 'BC SENTINEL v0.11.0-beta.5 B5-7 BOOTSTRAP - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}
function Download-RequiredFile([string]$Destination,[string]$Uri){
    $parent=Split-Path -Parent $Destination
    if($parent -and -not(Test-Path -LiteralPath $parent)){New-Item -ItemType Directory -Path $parent -Force|Out-Null}
    Write-Host ('Downloading: '+$Uri) -ForegroundColor DarkGray
    Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $Destination -ErrorAction Stop
}

try{
    $id=[Security.Principal.WindowsIdentity]::GetCurrent();$principal=New-Object Security.Principal.WindowsPrincipal($id)
    if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run B5-7 from normal non-elevated PowerShell.'}
    if(-not(Test-Path -LiteralPath '.\.venv\Scripts\python.exe')){throw '.venv not available'}

    $PatchRef='938340da0565193c535c070879c6d4998f0db702'
    $RepoRaw='https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/'

    Write-Host 'BC Sentinel v0.11.0-beta.5 - B5-7 PORTABLE TECHNICIAN RELEASE BOOTSTRAP' -ForegroundColor Cyan
    Write-Host 'Final Beta5 portable packaging. No repair-execute, unlock, format or reimage authority is added.' -ForegroundColor Yellow

    $Protected=@('.\sentinel\protection_service_core.py','.\sentinel\realtime.py','.\sentinel\edr.py','.\sentinel\edr_service_bridge.py')
    $Before=@{}
    foreach($path in $Protected){if(-not(Test-Path -LiteralPath $path)){throw ('protected source missing: '+$path)};$Before[$path]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}

    $PredecessorRequired=@(
        '.\TEST-V011-BETA5-B56.ps1',
        '.\sentinel\rescue_console_portable.py',
        '.\sentinel\rescue_target_discovery.py',
        '.\sentinel\rescue_hostile_scenarios.py',
        '.\sentinel\rescue_stress_hardening.py',
        '.\sentinel\rescue_session_resume.py',
        '.\sentinel\rescue_recovery_decision.py',
        '.\sentinel\rescue_technician_report.py'
    )
    foreach($p in $PredecessorRequired){if(-not(Test-Path -LiteralPath $p)){throw ('predecessor file missing; run accepted B5-6 bootstrap first: '+$p)}}

    $Files=@(
        @('sentinel\rescue_technician_portable.py','sentinel/rescue_technician_portable.py'),
        @('packaging\rescue_technician_portable_entry.py','packaging/rescue_technician_portable_entry.py'),
        @('tests\test_v011_beta5_b57_portable_technician_release.py','tests/test_v011_beta5_b57_portable_technician_release.py'),
        @('tools\v011_beta5_b57_acceptance.py','tools/v011_beta5_b57_acceptance.py'),
        @('BUILD-TECHNICIAN-RELEASE-PORTABLE.ps1','BUILD-TECHNICIAN-RELEASE-PORTABLE.ps1'),
        @('TEST-V011-BETA5-B57.ps1','TEST-V011-BETA5-B57.ps1'),
        @('BC_SENTINEL_V011_BETA5_B57_PORTABLE_TECHNICIAN_RELEASE.md','BC_SENTINEL_V011_BETA5_B57_PORTABLE_TECHNICIAN_RELEASE.md')
    )
    foreach($item in $Files){Download-RequiredFile $item[0] ($RepoRaw+$PatchRef+'/'+$item[1])}

    foreach($path in $Protected){$after=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();if($after -ne $Before[$path]){throw ('B5-7 bootstrap modified protected source: '+$path)}}
    Write-Host 'Protected B2 service/realtime/EDR sources unchanged after B5-7 bootstrap download.' -ForegroundColor Green

    $RepoRoot=(Resolve-Path -LiteralPath $PSScriptRoot).Path;$OldPythonPath=$env:PYTHONPATH
    if([string]::IsNullOrWhiteSpace($OldPythonPath)){$env:PYTHONPATH=$RepoRoot}else{$env:PYTHONPATH=$RepoRoot+[IO.Path]::PathSeparator+$OldPythonPath}
    Write-Host ('B57 BOOTSTRAP PYTHONPATH_ROOT='+$RepoRoot) -ForegroundColor DarkGray
    try{
        Write-Host 'Launching accepted B5-6 predecessor gate + B5-7 portable technician release acceptance...' -ForegroundColor DarkCyan
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\TEST-V011-BETA5-B57.ps1'
        if($LASTEXITCODE -ne 0){throw 'B5-7 acceptance failed'}
    }finally{$env:PYTHONPATH=$OldPythonPath}

    foreach($path in $Protected){$after=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();if($after -ne $Before[$path]){throw ('B5-7 acceptance modified protected source: '+$path)}}
    Write-Host 'BC SENTINEL v0.11.0-beta.5 B5-7 BOOTSTRAP - PASS' -ForegroundColor Green
    exit 0
}catch{Fail $_.Exception.Message}
