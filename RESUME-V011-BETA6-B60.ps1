param()
$ErrorActionPreference='Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message){
    Write-Host 'BC SENTINEL v0.11.0-beta.6 B6-0 BOOTSTRAP - FAIL' -ForegroundColor Red
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
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($id)
    if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run B6-0 from normal non-elevated PowerShell.'}
    if(-not(Test-Path -LiteralPath '.\.venv\Scripts\python.exe')){throw '.venv not available'}
    if(-not(Test-Path -LiteralPath '.\TEST-V011-BETA5-B57.ps1')){throw 'accepted B5-7 predecessor gate missing; run B5-7 bootstrap first'}

    $PatchRef='2b8092c4d1087da0f9c01f759b84cac4dd9af978'
    $RepoRaw='https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/'

    Write-Host 'BC Sentinel v0.11.0-beta.6 - B6-0 TECHNICIAN UX FOUNDATION BOOTSTRAP' -ForegroundColor Cyan
    Write-Host 'UI foundation only. Startup dispatch and destructive authority remain disabled.' -ForegroundColor Yellow

    $Protected=@('.\sentinel\protection_service_core.py','.\sentinel\realtime.py','.\sentinel\edr.py','.\sentinel\edr_service_bridge.py')
    $Before=@{}
    foreach($path in $Protected){if(-not(Test-Path -LiteralPath $path)){throw ('protected source missing: '+$path)};$Before[$path]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}

    $Files=@(
        @('sentinel\rescue_technician_ui_model.py','sentinel/rescue_technician_ui_model.py'),
        @('sentinel\rescue_technician_ui.py','sentinel/rescue_technician_ui.py'),
        @('packaging\rescue_technician_ui_entry.py','packaging/rescue_technician_ui_entry.py'),
        @('tests\test_v011_beta6_b60_technician_ux_foundation.py','tests/test_v011_beta6_b60_technician_ux_foundation.py'),
        @('tools\v011_beta6_b60_acceptance.py','tools/v011_beta6_b60_acceptance.py'),
        @('TEST-V011-BETA6-B60.ps1','TEST-V011-BETA6-B60.ps1'),
        @('BC_SENTINEL_V011_BETA6_B60_TECHNICIAN_UX_FOUNDATION.md','BC_SENTINEL_V011_BETA6_B60_TECHNICIAN_UX_FOUNDATION.md'),
        @('BC_Sentinel_Roadmap_v0_11_0_Beta6.md','BC_Sentinel_Roadmap_v0_11_0_Beta6.md')
    )
    foreach($item in $Files){Download-RequiredFile $item[0] ($RepoRaw+$PatchRef+'/'+$item[1])}

    foreach($path in $Protected){$after=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();if($after -ne $Before[$path]){throw ('B6-0 bootstrap modified protected source: '+$path)}}
    Write-Host 'Protected B2 service/realtime/EDR sources unchanged after B6-0 bootstrap download.' -ForegroundColor Green

    $RepoRoot=(Resolve-Path -LiteralPath $PSScriptRoot).Path
    $OldPythonPath=$env:PYTHONPATH
    if([string]::IsNullOrWhiteSpace($OldPythonPath)){$env:PYTHONPATH=$RepoRoot}else{$env:PYTHONPATH=$RepoRoot+[IO.Path]::PathSeparator+$OldPythonPath}
    Write-Host ('B60 BOOTSTRAP PYTHONPATH_ROOT='+$RepoRoot) -ForegroundColor DarkGray
    try{
        Write-Host 'Launching accepted B5-7 predecessor gate + B6-0 technician UX foundation acceptance...' -ForegroundColor DarkCyan
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\TEST-V011-BETA6-B60.ps1'
        if($LASTEXITCODE -ne 0){throw 'B6-0 acceptance failed'}
    }
    finally{$env:PYTHONPATH=$OldPythonPath}

    foreach($path in $Protected){$after=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();if($after -ne $Before[$path]){throw ('B6-0 acceptance modified protected source: '+$path)}}
    Write-Host 'BC SENTINEL v0.11.0-beta.6 B6-0 BOOTSTRAP - PASS' -ForegroundColor Green
    exit 0
}
catch{Fail $_.Exception.Message}
