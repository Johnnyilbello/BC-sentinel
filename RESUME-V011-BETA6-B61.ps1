param()
$ErrorActionPreference='Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message){
    Write-Host 'BC SENTINEL v0.11.0-beta.6 B6-1 BOOTSTRAP - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

function Download-RequiredFile([string]$Destination,[string]$Uri){
    $parent=Split-Path -Parent $Destination
    if($parent -and -not(Test-Path -LiteralPath $parent)){New-Item -ItemType Directory -Path $parent -Force|Out-Null}
    Write-Host ('Downloading: '+$Uri) -ForegroundColor DarkGray
    Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $Destination -ErrorAction Stop
}

function Hash-Set([string[]]$Paths){
    $map=@{}
    foreach($path in $Paths){
        if(-not(Test-Path -LiteralPath $path)){throw ('required protected/frozen source missing: '+$path)}
        $map[$path]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    return $map
}

try{
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($id)
    if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run B6-1 from normal non-elevated PowerShell.'}
    if(-not(Test-Path -LiteralPath '.\.venv\Scripts\python.exe')){throw '.venv not available'}
    if(-not(Test-Path -LiteralPath '.\TEST-V011-BETA6-B60.ps1')){throw 'accepted B6-0 predecessor gate missing; run B6-0 bootstrap first'}

    $PatchRef='6c402e8eb8bdd7e7555c0b057a6d3c2a34eb0402'
    $RepoRaw='https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/'

    Write-Host 'BC Sentinel v0.11.0-beta.6 - B6-1 TARGET DISCOVERY & SELECTION UX BOOTSTRAP' -ForegroundColor Cyan
    Write-Host 'READY-only explicit target selection. No unlock or mount-write authority is added.' -ForegroundColor Yellow

    $Protected=@('.\sentinel\protection_service_core.py','.\sentinel\realtime.py','.\sentinel\edr.py','.\sentinel\edr_service_bridge.py')
    $FrozenB60=@('.\sentinel\rescue_technician_ui_model.py','.\sentinel\rescue_technician_ui.py','.\packaging\rescue_technician_ui_entry.py')
    $BeforeProtected=Hash-Set $Protected
    $BeforeB60=Hash-Set $FrozenB60

    $Files=@(
        @('sentinel\rescue_technician_target_selection.py','sentinel/rescue_technician_target_selection.py'),
        @('sentinel\rescue_technician_ui_b61.py','sentinel/rescue_technician_ui_b61.py'),
        @('packaging\rescue_technician_ui_b61_entry.py','packaging/rescue_technician_ui_b61_entry.py'),
        @('tests\test_v011_beta6_b61_target_discovery_selection_ux.py','tests/test_v011_beta6_b61_target_discovery_selection_ux.py'),
        @('tools\v011_beta6_b61_acceptance.py','tools/v011_beta6_b61_acceptance.py'),
        @('TEST-V011-BETA6-B61.ps1','TEST-V011-BETA6-B61.ps1'),
        @('BC_SENTINEL_V011_BETA6_B61_TARGET_DISCOVERY_SELECTION_UX.md','BC_SENTINEL_V011_BETA6_B61_TARGET_DISCOVERY_SELECTION_UX.md'),
        @('BC_Sentinel_Roadmap_v0_11_0_Beta6.md','BC_Sentinel_Roadmap_v0_11_0_Beta6.md')
    )
    foreach($item in $Files){Download-RequiredFile $item[0] ($RepoRaw+$PatchRef+'/'+$item[1])}

    foreach($path in $Protected){$after=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();if($after -ne $BeforeProtected[$path]){throw ('B6-1 bootstrap modified protected B2 source: '+$path)}}
    foreach($path in $FrozenB60){$after=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();if($after -ne $BeforeB60[$path]){throw ('B6-1 bootstrap modified frozen B6-0 source: '+$path)}}
    Write-Host 'Protected B2 and frozen B6-0 sources unchanged after B6-1 bootstrap download.' -ForegroundColor Green

    $RepoRoot=(Resolve-Path -LiteralPath $PSScriptRoot).Path
    $OldPythonPath=$env:PYTHONPATH
    if([string]::IsNullOrWhiteSpace($OldPythonPath)){$env:PYTHONPATH=$RepoRoot}else{$env:PYTHONPATH=$RepoRoot+[IO.Path]::PathSeparator+$OldPythonPath}
    Write-Host ('B61 BOOTSTRAP PYTHONPATH_ROOT='+$RepoRoot) -ForegroundColor DarkGray
    try{
        Write-Host 'Launching accepted B6-0 predecessor gate + B6-1 target discovery/selection acceptance...' -ForegroundColor DarkCyan
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\TEST-V011-BETA6-B61.ps1'
        if($LASTEXITCODE -ne 0){throw 'B6-1 acceptance failed'}
    }
    finally{$env:PYTHONPATH=$OldPythonPath}

    foreach($path in $Protected){$after=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();if($after -ne $BeforeProtected[$path]){throw ('B6-1 acceptance modified protected source: '+$path)}}
    foreach($path in $FrozenB60){$after=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();if($after -ne $BeforeB60[$path]){throw ('B6-1 acceptance modified frozen B6-0 source: '+$path)}}
    Write-Host 'BC SENTINEL v0.11.0-beta.6 B6-1 BOOTSTRAP - PASS' -ForegroundColor Green
    exit 0
}
catch{Fail $_.Exception.Message}
