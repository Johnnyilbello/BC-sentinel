param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.5 B5-3 BOOTSTRAP - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

function Download-RequiredFile([string]$Destination,[string]$Uri) {
    $parent=Split-Path -Parent $Destination
    if($parent -and -not(Test-Path -LiteralPath $parent)){New-Item -ItemType Directory -Path $parent -Force|Out-Null}
    Write-Host ('Downloading: '+$Uri) -ForegroundColor DarkGray
    Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $Destination -ErrorAction Stop
}

try {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($id)
    if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run B5-3 from normal non-elevated PowerShell.'}
    if(-not(Test-Path -LiteralPath '.\.venv\Scripts\python.exe')){throw '.venv not available'}

    $PatchRef='959352b23f950f3b87374ddb6cad3d61648d4dbe'
    $RepoRaw='https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/'

    Write-Host 'BC Sentinel v0.11.0-beta.5 - B5-3 SESSION RESUME & CRASH RECOVERY BOOTSTRAP' -ForegroundColor Cyan
    Write-Host 'Hash-chained journal + trusted resume. Mutation-capable stages require fresh operator confirmation after interruption.' -ForegroundColor Yellow

    $Protected=@('.\sentinel\protection_service_core.py','.\sentinel\realtime.py','.\sentinel\edr.py','.\sentinel\edr_service_bridge.py')
    $Before=@{}
    foreach($path in $Protected){if(-not(Test-Path -LiteralPath $path)){throw ('protected source missing: '+$path)};$Before[$path]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}

    $PredecessorRequired=@(
        '.\sentinel\rescue_stress_hardening.py',
        '.\tests\test_v011_beta5_b52_large_scale_stress_hardening.py',
        '.\tools\v011_beta5_b52_acceptance.py',
        '.\TEST-V011-BETA5-B52.ps1'
    )
    foreach($p in $PredecessorRequired){if(-not(Test-Path -LiteralPath $p)){throw ('accepted B5-2 predecessor file missing; run B5-2 bootstrap first: '+$p)}}

    $Files=@(
        @('sentinel\rescue_session_resume.py','sentinel/rescue_session_resume.py'),
        @('tests\test_v011_beta5_b53_session_resume_crash_recovery.py','tests/test_v011_beta5_b53_session_resume_crash_recovery.py'),
        @('tools\v011_beta5_b53_acceptance.py','tools/v011_beta5_b53_acceptance.py'),
        @('TEST-V011-BETA5-B53.ps1','TEST-V011-BETA5-B53.ps1'),
        @('BC_SENTINEL_V011_BETA5_B53_SESSION_RESUME_CRASH_RECOVERY.md','BC_SENTINEL_V011_BETA5_B53_SESSION_RESUME_CRASH_RECOVERY.md'),
        @('BC_Sentinel_Roadmap_v0_11_0_Beta5.md','BC_Sentinel_Roadmap_v0_11_0_Beta5.md')
    )
    foreach($item in $Files){Download-RequiredFile $item[0] ($RepoRaw+$PatchRef+'/'+$item[1])}

    foreach($path in $Protected){$after=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();if($after -ne $Before[$path]){throw ('B5-3 bootstrap modified protected source: '+$path)}}
    Write-Host 'Protected B2 service/realtime/EDR sources unchanged after B5-3 bootstrap download.' -ForegroundColor Green

    $RepoRoot=(Resolve-Path -LiteralPath $PSScriptRoot).Path
    $OldPythonPath=$env:PYTHONPATH
    if([string]::IsNullOrWhiteSpace($OldPythonPath)){$env:PYTHONPATH=$RepoRoot}else{$env:PYTHONPATH=$RepoRoot+[IO.Path]::PathSeparator+$OldPythonPath}
    Write-Host ('B53 BOOTSTRAP PYTHONPATH_ROOT='+$RepoRoot) -ForegroundColor DarkGray
    try {
        Write-Host 'Launching accepted B5-2 predecessor gate + B5-3 journal/resume/crash acceptance...' -ForegroundColor DarkCyan
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\TEST-V011-BETA5-B53.ps1'
        if($LASTEXITCODE -ne 0){throw 'B5-3 acceptance failed'}
    }
    finally{$env:PYTHONPATH=$OldPythonPath}

    foreach($path in $Protected){$after=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();if($after -ne $Before[$path]){throw ('B5-3 acceptance modified protected source: '+$path)}}
    Write-Host 'BC SENTINEL v0.11.0-beta.5 B5-3 BOOTSTRAP - PASS' -ForegroundColor Green
    exit 0
}
catch{Fail $_.Exception.Message}
