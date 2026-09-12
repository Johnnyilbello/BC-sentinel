param()
$ErrorActionPreference='Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Stage,[string]$Message){
    Write-Host ('B61 FAIL STAGE='+$Stage+' | '+$Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.6 B6-1 UNIFIED HOME TARGET DISCOVERY - FAIL' -ForegroundColor Red
    exit 1
}

try{
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($id)
    if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){Fail 'preflight' 'Run B6-1 from normal non-elevated PowerShell.'}
    if(-not(Test-Path -LiteralPath '.\.venv\Scripts\python.exe')){Fail 'preflight' '.venv not available'}
    if(-not(Test-Path -LiteralPath '.\tests\test_v011_beta6_b60_technician_ux_foundation.py')){Fail 'preflight' 'accepted B6-0 regression tests missing'}
    if(-not(Test-Path -LiteralPath '.\tools\v011_beta6_b60_acceptance.py')){Fail 'preflight' 'accepted B6-0 deterministic acceptance missing'}
    $Py='.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.6 - B6-1 UNIFIED HOME TARGET DISCOVERY UX' -ForegroundColor Cyan
    Write-Host 'One Home experience. Discovery is explicit and read-only. Advanced details retain technical evidence.' -ForegroundColor Yellow

    # Protect only predecessor/runtime sources that are actually part of the current repository snapshot.
    # Historical B6-0 harness entries protection_service_core.py and realtime.py are not present in this source tree,
    # so B6-1 validates the accepted B6-0 contract through its deterministic pytest + acceptance tool instead.
    $Protected=@(
        '.\sentinel\edr.py',
        '.\sentinel\edr_service_bridge.py',
        '.\sentinel\rescue_target_discovery.py',
        '.\sentinel\rescue_technician_portable.py',
        '.\sentinel\rescue_technician_ui.py',
        '.\sentinel\rescue_technician_ui_model.py'
    )
    $BeforeProtected=@{}
    foreach($path in $Protected){
        if(-not(Test-Path -LiteralPath $path)){Fail 'preflight' ('protected source missing: '+$path)}
        $BeforeProtected[$path]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    $Base=Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    New-Item -ItemType Directory -Path $Base -Force|Out-Null
    $PytestTemp=Join-Path $Base ('b61-pytest-'+[guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $PytestTemp -Force|Out-Null
    $OldQt=$env:QT_QPA_PLATFORM
    $env:QT_QPA_PLATFORM='offscreen'
    try{
        & $Py -m compileall -q sentinel\rescue_home_ui_model.py sentinel\rescue_home_ui.py packaging\rescue_home_ui_entry.py tools\v011_beta6_b60_acceptance.py tools\v011_beta6_b61_acceptance.py tests\test_v011_beta6_b60_technician_ux_foundation.py tests\test_v011_beta6_b61_unified_home_target_discovery.py tests\test_v011_beta6_b61_home_real_ui_regressions.py
        if($LASTEXITCODE -ne 0){Fail 'compileall' 'B6-0/B6-1 compileall failed'}

        Write-Host 'B61 PREDECESSOR CONTRACT: validating accepted B6-0 deterministic acceptance...' -ForegroundColor DarkCyan
        & $Py -m tools.v011_beta6_b60_acceptance --output '.\acceptance-v011-beta6-b60-b61-regression.json'
        if($LASTEXITCODE -ne 0){Fail 'predecessor-b60' 'accepted B6-0 deterministic acceptance failed'}
        $B60=Get-Content -Raw -LiteralPath '.\acceptance-v011-beta6-b60-b61-regression.json' -Encoding UTF8|ConvertFrom-Json
        if(-not[bool]$B60.passed){Fail 'predecessor-b60' 'accepted B6-0 acceptance JSON did not pass'}
        if(-not[bool]$B60.checks.no_destructive_authority){Fail 'predecessor-b60' 'B6-0 destructive-authority contract changed'}
        if(-not[bool]$B60.checks.startup_dispatch_disabled){Fail 'predecessor-b60' 'B6-0 startup-dispatch contract changed'}

        Write-Host ('B61 PYTEST BASETEMP='+$PytestTemp) -ForegroundColor DarkGray
        & $Py -m pytest -q --basetemp $PytestTemp tests/test_v011_beta6_b60_technician_ux_foundation.py tests/test_v011_beta6_b61_unified_home_target_discovery.py tests/test_v011_beta6_b61_home_real_ui_regressions.py
        if($LASTEXITCODE -ne 0){Fail 'pytest-b61' 'B6-0/B6-1 regression tests failed'}

        & $Py -m tools.v011_beta6_b61_acceptance --output '.\acceptance-v011-beta6-b61.json'
        if($LASTEXITCODE -ne 0){Fail 'acceptance-b61' 'B6-1 deterministic acceptance failed'}
        $A=Get-Content -Raw -LiteralPath '.\acceptance-v011-beta6-b61.json' -Encoding UTF8|ConvertFrom-Json
        if(-not[bool]$A.passed){Fail 'acceptance-b61' 'B6-1 acceptance JSON did not pass'}
        if(-not[bool]$A.checks.parent_b60_contract_green){Fail 'parent-contract' 'B6-0 contract is no longer green'}
        if(-not[bool]$A.checks.multi_target_no_silent_recommendation){Fail 'recommendation' 'multiple valid targets were silently recommended'}
        if(-not[bool]$A.checks.locked_target_fail_closed){Fail 'bitlocker' 'locked target did not fail closed'}
        if(-not[bool]$A.checks.changed_identity_refused){Fail 'identity' 'changed target fingerprint was not refused'}
        if(-not[bool]$A.checks.home_startup_passive){Fail 'startup' 'Home startup dispatched discovery or changed state'}

        $SelfRaw=@(& $Py -m sentinel.rescue_home_ui --self-check)
        if($LASTEXITCODE -ne 0){Fail 'self-check' ('Home self-check exit='+$LASTEXITCODE)}
        $Self=($SelfRaw -join [Environment]::NewLine)|ConvertFrom-Json
        if(-not[bool]$Self.passed -or [bool]$Self.startup_dispatch -or [bool]$Self.automatic_discovery){Fail 'self-check' 'Home passive startup contract failed'}
        if([string]$Self.initial_state.state -ne 'IDLE'){Fail 'self-check' ('unexpected initial state='+[string]$Self.initial_state.state)}

        $SmokeRaw=@(& $Py -m sentinel.rescue_home_ui --offscreen-smoke)
        if($LASTEXITCODE -ne 0){Fail 'qt-smoke' ('offscreen Qt smoke exit='+$LASTEXITCODE)}
        $Smoke=($SmokeRaw -join [Environment]::NewLine)|ConvertFrom-Json
        if(-not[bool]$Smoke.passed -or -not[bool]$Smoke.window_created){Fail 'qt-smoke' 'Home window did not construct successfully'}
        if([string]$Smoke.window_title -cne 'BC Sentinel - Home'){Fail 'qt-smoke' ('unexpected Home window title='+[string]$Smoke.window_title)}

        foreach($path in $Protected){
            $after=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            if($after -ne $BeforeProtected[$path]){Fail 'protected-source' ('B6-1 modified frozen/predecessor source during gate: '+$path)}
        }

        Write-Host 'B61 LOCAL: B6-0 deterministic predecessor PASS | B6-0/B6-1 tests PASS | real Home UX regressions PASS | synthetic acceptance PASS | Home Qt smoke PASS | passive startup PASS | no destructive authority added' -ForegroundColor Green
        Write-Host 'B61 STATUS: LOCAL IMPLEMENTATION GATE PASS. Real Windows target/multi-disk/BitLocker acceptance is still REQUIRED before checkpoint stabilization.' -ForegroundColor Yellow
        Write-Host 'BC SENTINEL v0.11.0-beta.6 B6-1 UNIFIED HOME TARGET DISCOVERY - LOCAL PASS / WINDOWS GATE PENDING' -ForegroundColor Green
        exit 0
    }
    finally{
        if($null -eq $OldQt){Remove-Item Env:QT_QPA_PLATFORM -ErrorAction SilentlyContinue}else{$env:QT_QPA_PLATFORM=$OldQt}
        Remove-Item -LiteralPath $PytestTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
catch{Fail 'unhandled' $_.Exception.Message}
