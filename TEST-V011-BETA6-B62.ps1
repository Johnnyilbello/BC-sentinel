param()
$ErrorActionPreference='Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Stage,[string]$Message){
    Write-Host ('B62 FAIL STAGE='+$Stage+' | '+$Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.6 B6-2 HOME SECURITY OVERVIEW - FAIL' -ForegroundColor Red
    exit 1
}

try{
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($id)
    if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){Fail 'preflight' 'Run B6-2 from normal non-elevated PowerShell.'}
    if(-not(Test-Path -LiteralPath '.\.venv\Scripts\python.exe')){Fail 'preflight' '.venv not available'}
    if(-not(Test-Path -LiteralPath '.\TEST-V011-BETA6-B61.ps1')){Fail 'preflight' 'B6-1 local regression gate missing'}
    if(-not(Test-Path -LiteralPath '.\tools\v011_beta6_b62_acceptance.py')){Fail 'preflight' 'B6-2 acceptance tool missing'}
    $Py='.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.6 - B6-2 HOME / SECURITY OVERVIEW' -ForegroundColor Cyan
    Write-Host 'Consumer Home foundation. Runtime truth is conservative; Smart Scan remains disabled until B6-3.' -ForegroundColor Yellow

    $Protected=@(
        '.\sentinel\advanced_antimalware.py',
        '.\sentinel\edr.py',
        '.\sentinel\edr_service_bridge.py',
        '.\sentinel\web_deception.py',
        '.\sentinel\web_clone_scam.py',
        '.\sentinel\web_response.py',
        '.\sentinel\rescue_target_discovery.py',
        '.\sentinel\rescue_home_ui.py',
        '.\sentinel\rescue_home_ui_model.py',
        '.\sentinel\rescue_technician_ui.py',
        '.\sentinel\rescue_technician_ui_model.py'
    )
    $BeforeProtected=@{}
    foreach($path in $Protected){
        if(-not(Test-Path -LiteralPath $path)){Fail 'preflight' ('protected source missing: '+$path)}
        $BeforeProtected[$path]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    Write-Host 'B62 PREDECESSOR GATE: running B6-1 local regression gate...' -ForegroundColor DarkCyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\TEST-V011-BETA6-B61.ps1'
    if($LASTEXITCODE -ne 0){Fail 'predecessor-b61' ('B6-1 local gate failed exit='+$LASTEXITCODE)}

    $Base=Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    New-Item -ItemType Directory -Path $Base -Force|Out-Null
    $PytestTemp=Join-Path $Base ('b62-pytest-'+[guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $PytestTemp -Force|Out-Null
    $OldQt=$env:QT_QPA_PLATFORM
    $OldMotion=$env:BC_SENTINEL_REDUCED_MOTION
    $env:QT_QPA_PLATFORM='offscreen'
    $env:BC_SENTINEL_REDUCED_MOTION='1'
    try{
        & $Py -m compileall -q `
            sentinel\home_security_model.py `
            sentinel\home_security_ui.py `
            packaging\home_security_ui_entry.py `
            tools\v011_beta6_b62_acceptance.py `
            tests\test_v011_beta6_b62_home_security_overview.py
        if($LASTEXITCODE -ne 0){Fail 'compileall' 'B6-2 compileall failed'}

        Write-Host ('B62 PYTEST BASETEMP='+$PytestTemp) -ForegroundColor DarkGray
        & $Py -m pytest -q --basetemp $PytestTemp `
            tests/test_v011_beta6_b60_technician_ux_foundation.py `
            tests/test_v011_beta6_b61_unified_home_target_discovery.py `
            tests/test_v011_beta6_b61_home_real_ui_regressions.py `
            tests/test_v011_beta6_b62_home_security_overview.py
        if($LASTEXITCODE -ne 0){Fail 'pytest-b62' 'B6-0/B6-1/B6-2 regression tests failed'}

        & $Py -m tools.v011_beta6_b62_acceptance --output '.\acceptance-v011-beta6-b62.json'
        if($LASTEXITCODE -ne 0){Fail 'acceptance-b62' 'B6-2 deterministic acceptance failed'}
        $A=Get-Content -Raw -LiteralPath '.\acceptance-v011-beta6-b62.json' -Encoding UTF8|ConvertFrom-Json
        if(-not[bool]$A.passed){Fail 'acceptance-b62' 'B6-2 acceptance JSON did not pass'}
        if(-not[bool]$A.checks.parent_b61_contract_green){Fail 'parent-contract' 'B6-1 contract is no longer green'}
        if(-not[bool]$A.checks.default_posture_unverified){Fail 'truthfulness' 'default Home posture is not conservative'}
        if(-not[bool]$A.checks.default_never_claims_active){Fail 'truthfulness' 'module/source availability was promoted to active protection'}
        if(-not[bool]$A.checks.missing_runtime_proof_blocks_protected){Fail 'truthfulness' 'missing runtime proof did not block Protected posture'}
        if(-not[bool]$A.checks.smart_scan_disabled_in_ui){Fail 'smart-scan' 'Smart Scan became executable before B6-3'}
        if(-not[bool]$A.checks.dark_surface_contract){Fail 'visual' 'dark page/viewport ownership contract failed'}
        if(-not[bool]$A.checks.motion_tokens_within_contract){Fail 'motion' 'motion token contract failed'}

        $SelfRaw=@(& $Py -m sentinel.home_security_ui --self-check)
        if($LASTEXITCODE -ne 0){Fail 'self-check' ('Home overview self-check exit='+$LASTEXITCODE)}
        $Self=($SelfRaw -join [Environment]::NewLine)|ConvertFrom-Json
        if(-not[bool]$Self.passed){Fail 'self-check' 'Home overview self-check did not pass'}
        if([bool]$Self.startup_scan_dispatch -or [bool]$Self.startup_rescue_dispatch){Fail 'startup' 'Home overview dispatched scan or Rescue during self-check'}
        if([bool]$Self.smart_scan_enabled){Fail 'smart-scan' 'Smart Scan unexpectedly enabled in B6-2 self-check'}

        $SmokeRaw=@(& $Py -m sentinel.home_security_ui --offscreen-smoke)
        if($LASTEXITCODE -ne 0){Fail 'qt-smoke' ('B6-2 Qt smoke exit='+$LASTEXITCODE)}
        $Smoke=($SmokeRaw -join [Environment]::NewLine)|ConvertFrom-Json
        if(-not[bool]$Smoke.passed -or -not[bool]$Smoke.window_created){Fail 'qt-smoke' 'B6-2 Home window did not construct successfully'}
        if([string]$Smoke.window_title -cne 'BC Sentinel'){Fail 'qt-smoke' ('unexpected B6-2 window title='+[string]$Smoke.window_title)}
        if([int]$Smoke.card_count -ne 4){Fail 'qt-smoke' ('unexpected protection card count='+[string]$Smoke.card_count)}
        if([bool]$Smoke.smart_scan_enabled){Fail 'smart-scan' 'Smart Scan unexpectedly enabled in Qt smoke'}
        if([int]$Smoke.minimum_size[0] -lt 980 -or [int]$Smoke.minimum_size[1] -lt 700){Fail 'visual' 'minimum window contract regressed'}

        foreach($path in $Protected){
            $after=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            if($after -ne $BeforeProtected[$path]){Fail 'protected-source' ('B6-2 modified predecessor/security source during gate: '+$path)}
        }

        Write-Host 'B62 LOCAL: B6-1 predecessor PASS | B6-0/B6-1/B6-2 regressions PASS | deterministic acceptance PASS | Home Qt smoke PASS | conservative runtime truth PASS | visual token contract PASS | Smart Scan disabled | no destructive authority added' -ForegroundColor Green
        Write-Host 'B62 STATUS: LOCAL IMPLEMENTATION GATE PASS. Real Windows visual acceptance is REQUIRED before B6-2 checkpoint acceptance.' -ForegroundColor Yellow
        Write-Host 'NOTE: B6-1 offline multi-disk/locked-BitLocker hardware edge cases remain separately pending.' -ForegroundColor Yellow
        Write-Host 'BC SENTINEL v0.11.0-beta.6 B6-2 HOME SECURITY OVERVIEW - LOCAL PASS / WINDOWS VISUAL GATE PENDING' -ForegroundColor Green
        exit 0
    }
    finally{
        if($null -eq $OldQt){Remove-Item Env:QT_QPA_PLATFORM -ErrorAction SilentlyContinue}else{$env:QT_QPA_PLATFORM=$OldQt}
        if($null -eq $OldMotion){Remove-Item Env:BC_SENTINEL_REDUCED_MOTION -ErrorAction SilentlyContinue}else{$env:BC_SENTINEL_REDUCED_MOTION=$OldMotion}
        Remove-Item -LiteralPath $PytestTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
catch{Fail 'unhandled' $_.Exception.Message}
