param()
$ErrorActionPreference='Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Stage,[string]$Message){
    Write-Host ('B61 FAIL STAGE='+$Stage+' | '+$Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.6 B6-1 TARGET DISCOVERY & SELECTION UX - FAIL' -ForegroundColor Red
    exit 1
}

function Hash-Set([string[]]$Paths){
    $map=@{}
    foreach($path in $Paths){
        if(-not(Test-Path -LiteralPath $path)){Fail 'preflight' ('required protected/frozen source missing: '+$path)}
        $map[$path]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    return $map
}

try{
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($id)
    if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){Fail 'preflight' 'Run B6-1 from normal non-elevated PowerShell.'}
    if(-not(Test-Path -LiteralPath '.\.venv\Scripts\python.exe')){Fail 'preflight' '.venv not available'}
    if(-not(Test-Path -LiteralPath '.\TEST-V011-BETA6-B60.ps1')){Fail 'preflight' 'accepted B6-0 gate missing; run B6-0 bootstrap first'}
    $Py='.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.6 - B6-1 TARGET DISCOVERY & SELECTION UX' -ForegroundColor Cyan
    Write-Host 'Guided B5-0 target picker. READY-only explicit selection; no unlock or mount-write authority.' -ForegroundColor Yellow

    $Protected=@('.\sentinel\protection_service_core.py','.\sentinel\realtime.py','.\sentinel\edr.py','.\sentinel\edr_service_bridge.py')
    $FrozenB60=@('.\sentinel\rescue_technician_ui_model.py','.\sentinel\rescue_technician_ui.py','.\packaging\rescue_technician_ui_entry.py')
    $BeforeProtected=Hash-Set $Protected
    $BeforeB60=Hash-Set $FrozenB60

    Write-Host 'B61 PREDECESSOR GATE: running accepted B6-0 complete technician UX foundation gate...' -ForegroundColor DarkCyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\TEST-V011-BETA6-B60.ps1'
    if($LASTEXITCODE -ne 0){Fail 'predecessor-b60' ('accepted B6-0 gate failed exit='+$LASTEXITCODE)}

    $Base=Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    New-Item -ItemType Directory -Path $Base -Force|Out-Null
    $PytestTemp=Join-Path $Base ('b61-pytest-'+[guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $PytestTemp -Force|Out-Null
    $OldQt=$env:QT_QPA_PLATFORM
    $env:QT_QPA_PLATFORM='offscreen'
    try{
        & $Py -m compileall -q sentinel\rescue_technician_target_selection.py sentinel\rescue_technician_ui_b61.py packaging\rescue_technician_ui_b61_entry.py tools\v011_beta6_b61_acceptance.py tests\test_v011_beta6_b61_target_discovery_selection_ux.py
        if($LASTEXITCODE -ne 0){Fail 'compileall' 'B6-1 compileall failed'}

        Write-Host ('B61 PYTEST BASETEMP='+$PytestTemp) -ForegroundColor DarkGray
        & $Py -m pytest -q --basetemp $PytestTemp tests/test_v011_beta6_b61_target_discovery_selection_ux.py
        if($LASTEXITCODE -ne 0){Fail 'pytest-b61' '20 B6-1 tests failed'}

        & $Py -m tools.v011_beta6_b61_acceptance --output '.\acceptance-v011-beta6-b61.json'
        if($LASTEXITCODE -ne 0){Fail 'acceptance-b61' 'B6-1 deterministic acceptance failed'}
        $A=Get-Content -Raw -LiteralPath '.\acceptance-v011-beta6-b61.json' -Encoding UTF8|ConvertFrom-Json
        if(-not[bool]$A.passed){Fail 'acceptance-b61' 'B6-1 acceptance JSON did not pass'}
        if(-not[bool]$A.checks.four_controlled_states_present){Fail 'state-mapping' 'controlled target state mapping incomplete'}
        if(-not[bool]$A.checks.only_ready_selectable){Fail 'ready-gate' 'non-READY target became selectable'}
        if(-not[bool]$A.checks.locked_selection_disabled){Fail 'ready-gate' 'LOCKED target selection was enabled'}
        if(-not[bool]$A.checks.explicit_selection_ready){Fail 'selection' 'explicit READY target selection did not reach READY UI state'}
        if(-not[bool]$A.checks.live_system_refused){Fail 'live-system' ('SystemDrive not refused: state='+[string]$A.detail.live_system_state+' reason='+[string]$A.detail.live_system_reason)}
        if(-not[bool]$A.checks.target_byte_identical){Fail 'target-integrity' 'controlled target bytes changed'}
        if(-not[bool]$A.checks.no_unlock_action -or -not[bool]$A.checks.no_mount_write_action){Fail 'command-surface' 'unlock or mount-write action appeared in UI'}

        $SelfRaw=@(& $Py -m sentinel.rescue_technician_ui_b61 --self-check)
        if($LASTEXITCODE -ne 0){Fail 'self-check' ('B6-1 UI self-check exit='+$LASTEXITCODE)}
        $Self=($SelfRaw -join [Environment]::NewLine)|ConvertFrom-Json
        if(-not[bool]$Self.passed -or [bool]$Self.startup_discovery){Fail 'self-check' 'B6-1 startup safety contract failed'}
        if([bool]$Self.safety.unlock_offered -or [bool]$Self.safety.mount_write_offered){Fail 'self-check' 'unlock/mount-write exposed by B6-1 safety contract'}

        $SmokeRaw=@(& $Py -m sentinel.rescue_technician_ui_b61 --offscreen-smoke)
        if($LASTEXITCODE -ne 0){Fail 'qt-smoke' ('B6-1 offscreen Qt smoke exit='+$LASTEXITCODE)}
        $Smoke=($SmokeRaw -join [Environment]::NewLine)|ConvertFrom-Json
        if(-not[bool]$Smoke.passed -or -not[bool]$Smoke.window_created){Fail 'qt-smoke' 'B6-1 target picker window did not construct'}
        if(-not[bool]$Smoke.discover_enabled){Fail 'qt-smoke' 'Discover targets action not available for explicit operator use'}
        if([bool]$Smoke.use_target_enabled){Fail 'qt-smoke' 'Use selected target enabled before READY selection'}
        if([string]$Smoke.startup_state -ne 'IDLE'){Fail 'qt-smoke' ('unexpected B6-1 startup state='+[string]$Smoke.startup_state)}

        $Services=@(Get-CimInstance Win32_Service|Where-Object{([string]$_.PathName).ToLowerInvariant().Contains('rescue_technician_ui_b61') -or ([string]$_.PathName).ToLowerInvariant().Contains('b61')})
        if($Services.Count -ne 0){Fail 'service-check' 'B6-1 unexpectedly registered a Windows service'}

        foreach($path in $Protected){$after=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();if($after -ne $BeforeProtected[$path]){Fail 'protected-source' ('B6-1 modified protected B2 source: '+$path)}}
        foreach($path in $FrozenB60){$after=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();if($after -ne $BeforeB60[$path]){Fail 'frozen-b60' ('B6-1 modified frozen B6-0 source: '+$path)}}

        Write-Host ('B61 ACCEPTANCE STATES='+($A.detail.states -join ',')+' READY_FP='+[string]$A.detail.ready_fingerprint+' LIVE_SYSTEM='+[string]$A.detail.live_system_state+'/'+[string]$A.detail.live_system_reason) -ForegroundColor Green
        Write-Host 'B61 LIVE: predecessor B6-0 PASS | 20 B6-1 tests PASS | READY-only explicit selection PASS | locked/incomplete/unsupported states PASS | live SystemDrive refusal PASS | no unlock/mount-write action | target unchanged | no service | B6-0 + B2 sources unchanged' -ForegroundColor Green
        Write-Host 'BC SENTINEL v0.11.0-beta.6 B6-1 TARGET DISCOVERY & SELECTION UX - PASS' -ForegroundColor Green
        exit 0
    }
    finally{
        if($null -eq $OldQt){Remove-Item Env:QT_QPA_PLATFORM -ErrorAction SilentlyContinue}else{$env:QT_QPA_PLATFORM=$OldQt}
        Remove-Item -LiteralPath $PytestTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
catch{Fail 'unhandled' $_.Exception.Message}
