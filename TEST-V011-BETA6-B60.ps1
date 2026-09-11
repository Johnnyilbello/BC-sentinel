param()
$ErrorActionPreference='Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Stage,[string]$Message){
    Write-Host ('B60 FAIL STAGE='+$Stage+' | '+$Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.6 B6-0 TECHNICIAN UX FOUNDATION - FAIL' -ForegroundColor Red
    exit 1
}

try{
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($id)
    if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){Fail 'preflight' 'Run B6-0 from normal non-elevated PowerShell.'}
    if(-not(Test-Path -LiteralPath '.\.venv\Scripts\python.exe')){Fail 'preflight' '.venv not available'}
    if(-not(Test-Path -LiteralPath '.\TEST-V011-BETA5-B57.ps1')){Fail 'preflight' 'accepted B5-7 gate missing; run B5-7 bootstrap first'}
    $Py='.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.6 - B6-0 TECHNICIAN UX FOUNDATION' -ForegroundColor Cyan
    Write-Host 'PySide6 shell + deterministic state model only. Startup dispatch is forbidden.' -ForegroundColor Yellow

    $Protected=@('.\sentinel\protection_service_core.py','.\sentinel\realtime.py','.\sentinel\edr.py','.\sentinel\edr_service_bridge.py')
    $BeforeProtected=@{}
    foreach($path in $Protected){if(-not(Test-Path -LiteralPath $path)){Fail 'preflight' ('protected source missing: '+$path)};$BeforeProtected[$path]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}

    Write-Host 'B60 PREDECESSOR GATE: running accepted B5-7 complete portable technician release gate...' -ForegroundColor DarkCyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\TEST-V011-BETA5-B57.ps1'
    if($LASTEXITCODE -ne 0){Fail 'predecessor-b57' ('accepted B5-7 gate failed exit='+$LASTEXITCODE)}

    $Base=Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    New-Item -ItemType Directory -Path $Base -Force|Out-Null
    $PytestTemp=Join-Path $Base ('b60-pytest-'+[guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $PytestTemp -Force|Out-Null
    $OldQt=$env:QT_QPA_PLATFORM
    $env:QT_QPA_PLATFORM='offscreen'
    try{
        & $Py -m compileall -q sentinel\rescue_technician_ui_model.py sentinel\rescue_technician_ui.py packaging\rescue_technician_ui_entry.py tools\v011_beta6_b60_acceptance.py tests\test_v011_beta6_b60_technician_ux_foundation.py
        if($LASTEXITCODE -ne 0){Fail 'compileall' 'B6-0 compileall failed'}

        Write-Host ('B60 PYTEST BASETEMP='+$PytestTemp) -ForegroundColor DarkGray
        & $Py -m pytest -q --basetemp $PytestTemp tests/test_v011_beta6_b60_technician_ux_foundation.py
        if($LASTEXITCODE -ne 0){Fail 'pytest-b60' '16 B6-0 tests failed'}

        & $Py -m tools.v011_beta6_b60_acceptance --output '.\acceptance-v011-beta6-b60.json'
        if($LASTEXITCODE -ne 0){Fail 'acceptance-b60' 'B6-0 deterministic acceptance failed'}
        $A=Get-Content -Raw -LiteralPath '.\acceptance-v011-beta6-b60.json' -Encoding UTF8|ConvertFrom-Json
        if(-not[bool]$A.passed){Fail 'acceptance-b60' 'B6-0 acceptance JSON did not pass'}
        if(-not[bool]$A.checks.command_surface_exact){Fail 'command-surface' 'B5-7 command inventory drifted'}
        if(-not[bool]$A.checks.forbidden_commands_absent){Fail 'command-surface' 'forbidden command appeared'}
        if(-not[bool]$A.checks.startup_dispatch_disabled){Fail 'startup' 'startup dispatch unexpectedly enabled'}
        if(-not[bool]$A.checks.workflow_actions_disabled){Fail 'startup' 'foundation workflow action unexpectedly enabled'}
        if(-not[bool]$A.checks.no_destructive_authority){Fail 'safety' 'destructive authority appeared'}

        $SelfRaw=@(& $Py -m sentinel.rescue_technician_ui --self-check)
        if($LASTEXITCODE -ne 0){Fail 'self-check' ('UI self-check exit='+$LASTEXITCODE)}
        $Self=($SelfRaw -join [Environment]::NewLine)|ConvertFrom-Json
        if(-not[bool]$Self.passed -or [bool]$Self.startup_dispatch){Fail 'self-check' 'UI self-check contract failed'}
        if([string]$Self.initial_state.state -ne 'IDLE'){Fail 'self-check' ('unexpected initial state='+[string]$Self.initial_state.state)}

        $SmokeRaw=@(& $Py -m sentinel.rescue_technician_ui --offscreen-smoke)
        if($LASTEXITCODE -ne 0){Fail 'qt-smoke' ('offscreen Qt smoke exit='+$LASTEXITCODE)}
        $Smoke=($SmokeRaw -join [Environment]::NewLine)|ConvertFrom-Json
        if(-not[bool]$Smoke.passed -or -not[bool]$Smoke.window_created){Fail 'qt-smoke' 'Qt window did not construct successfully'}
        if([string]$Smoke.window_title -ne 'BC Sentinel — Rescue Technician'){Fail 'qt-smoke' ('unexpected window title='+[string]$Smoke.window_title)}

        $Services=@(Get-CimInstance Win32_Service|Where-Object{([string]$_.PathName).ToLowerInvariant().Contains('rescue_technician_ui') -or ([string]$_.PathName).ToLowerInvariant().Contains('b60')})
        if($Services.Count -ne 0){Fail 'service-check' 'B6-0 unexpectedly registered a Windows service'}
        foreach($path in $Protected){$after=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();if($after -ne $BeforeProtected[$path]){Fail 'protected-source' ('B6-0 modified protected B2 source: '+$path)}}

        Write-Host ('B60 ACCEPTANCE ENGINE='+[string]$A.detail.engine_profile+' STATE='+[string]$A.detail.initial_state.state+' COMMANDS='+[string]$A.detail.engine_commands.Count) -ForegroundColor Green
        Write-Host 'B60 LIVE: predecessor B5-7 PASS | 16 B6-0 tests PASS | Qt offscreen shell PASS | exact engine surface PASS | startup dispatch disabled | workflow actions disabled | no destructive authority | no service | B2 sources unchanged' -ForegroundColor Green
        Write-Host 'BC SENTINEL v0.11.0-beta.6 B6-0 TECHNICIAN UX FOUNDATION - PASS' -ForegroundColor Green
        exit 0
    }
    finally{
        if($null -eq $OldQt){Remove-Item Env:QT_QPA_PLATFORM -ErrorAction SilentlyContinue}else{$env:QT_QPA_PLATFORM=$OldQt}
        Remove-Item -LiteralPath $PytestTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
catch{Fail 'unhandled' $_.Exception.Message}
