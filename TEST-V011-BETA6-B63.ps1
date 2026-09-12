param()
$ErrorActionPreference='Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Stage,[string]$Message){
    Write-Host ('B63 FAIL STAGE='+$Stage+' | '+$Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.6 B6-3 SMART SCAN ORCHESTRATION - FAIL' -ForegroundColor Red
    exit 1
}

try{
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($id)
    if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        Fail 'preflight' 'Run B6-3 from normal non-elevated PowerShell.'
    }
    if(-not(Test-Path -LiteralPath '.\.venv\Scripts\python.exe')){Fail 'preflight' '.venv not available'}
    if(-not(Test-Path -LiteralPath '.\TEST-V011-BETA6-B62.ps1')){Fail 'preflight' 'B6-2 predecessor gate missing'}
    if(-not(Test-Path -LiteralPath '.\sentinel\home_smart_scan.py')){Fail 'preflight' 'Smart Scan coordinator missing'}
    if(-not(Test-Path -LiteralPath '.\sentinel\home_smart_scan_ui.py')){Fail 'preflight' 'Smart Scan page missing'}
    if(-not(Test-Path -LiteralPath '.\sentinel\home_smart_scan_window.py')){Fail 'preflight' 'B6-3 Home integration missing'}
    if(-not(Test-Path -LiteralPath '.\tools\v011_beta6_b63_acceptance.py')){Fail 'preflight' 'B6-3 acceptance tool missing'}
    $Py='.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.6 - B6-3 SMART SCAN ORCHESTRATION FOUNDATION' -ForegroundColor Cyan
    Write-Host 'B6-3 adds explicit Smart Scan orchestration only. No remediation authority is added.' -ForegroundColor Yellow

    $Protected=@(
        '.\sentinel\advanced_antimalware.py',
        '.\sentinel\edr.py',
        '.\sentinel\edr_service_bridge.py',
        '.\sentinel\web_deception.py',
        '.\sentinel\web_clone_scam.py',
        '.\sentinel\web_response.py',
        '.\sentinel\rescue_target_discovery.py',
        '.\sentinel\rescue_home_ui_model.py',
        '.\sentinel\rescue_technician_ui.py',
        '.\sentinel\rescue_technician_ui_model.py',
        '.\sentinel\home_security_model.py'
    )
    $BeforeProtected=@{}
    foreach($path in $Protected){
        if(-not(Test-Path -LiteralPath $path)){Fail 'preflight' ('protected source missing: '+$path)}
        $BeforeProtected[$path]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    Write-Host 'B63 PREDECESSOR GATE: running B6-2 regression/visual contract gate...' -ForegroundColor DarkCyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\TEST-V011-BETA6-B62.ps1'
    if($LASTEXITCODE -ne 0){Fail 'predecessor-b62' ('B6-2 gate failed exit='+$LASTEXITCODE)}

    $Base=Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    New-Item -ItemType Directory -Path $Base -Force|Out-Null
    $PytestTemp=Join-Path $Base ('b63-smart-scan-'+[guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $PytestTemp -Force|Out-Null
    $OldQt=$env:QT_QPA_PLATFORM
    $OldMotion=$env:BC_SENTINEL_REDUCED_MOTION
    $env:QT_QPA_PLATFORM='offscreen'
    $env:BC_SENTINEL_REDUCED_MOTION='1'
    try{
        & $Py -m compileall -q `
            sentinel\home_smart_scan.py `
            sentinel\home_smart_scan_ui.py `
            sentinel\home_smart_scan_window.py `
            tools\v011_beta6_b63_acceptance.py `
            tests\test_v011_beta6_b63_smart_scan.py `
            tests\test_v011_beta6_b63_smart_scan_ui.py
        if($LASTEXITCODE -ne 0){Fail 'compileall' 'B6-3 compileall failed'}

        Write-Host ('B63 PYTEST BASETEMP='+$PytestTemp) -ForegroundColor DarkGray
        & $Py -m pytest -q --basetemp $PytestTemp `
            tests/test_v011_beta6_b63_smart_scan.py `
            tests/test_v011_beta6_b63_smart_scan_ui.py
        if($LASTEXITCODE -ne 0){Fail 'pytest-b63' 'B6-3 Smart Scan tests failed'}

        & $Py -m tools.v011_beta6_b63_acceptance --output '.\acceptance-v011-beta6-b63.json'
        if($LASTEXITCODE -ne 0){Fail 'acceptance-b63' 'B6-3 deterministic acceptance failed'}
        $A=Get-Content -Raw -LiteralPath '.\acceptance-v011-beta6-b63.json' -Encoding UTF8|ConvertFrom-Json
        if(-not[bool]$A.passed){Fail 'acceptance-b63' ('B6-3 acceptance failures: '+(($A.failures|ForEach-Object{[string]$_}) -join ', '))}
        $Required=@(
            'parent_b62_green','b63_contract_green','startup_scan_dispatch_false','navigation_scan_dispatch_false',
            'refresh_scan_dispatch_false','no_destructive_authority','default_provider_unavailable_truthful',
            'clean_requires_complete_coverage','findings_preserved','incomplete_never_clean','progress_monotonic',
            'default_ui_does_not_enable_fake_scan','accepted_provider_enables_only_smart_scan','ui_construction_is_passive',
            'six_page_shell_preserved','desktop_no_horizontal_overflow','tablet_no_horizontal_overflow'
        )
        foreach($name in $Required){
            if(-not[bool]$A.checks.$name){Fail 'acceptance-b63' ('required check failed: '+$name)}
        }

        $SelfRaw=@(& $Py -m sentinel.home_smart_scan_window --self-check)
        if($LASTEXITCODE -ne 0){Fail 'self-check' ('B6-3 self-check exit='+$LASTEXITCODE)}
        $Self=($SelfRaw -join [Environment]::NewLine)|ConvertFrom-Json
        if(-not[bool]$Self.passed){Fail 'self-check' 'B6-3 self-check did not pass'}
        if([bool]$Self.startup_scan_dispatch -or [bool]$Self.navigation_scan_dispatch -or [bool]$Self.refresh_scan_dispatch){
            Fail 'passive-contract' 'B6-3 dispatched a scan from startup/navigation/refresh'
        }
        if([bool]$Self.full_scan_enabled){Fail 'full-scan' 'Full Scan became enabled in B6-3'}

        $SmokeRaw=@(& $Py -m sentinel.home_smart_scan_window --offscreen-smoke)
        if($LASTEXITCODE -ne 0){Fail 'qt-smoke' ('B6-3 Qt smoke exit='+$LASTEXITCODE)}
        $Smoke=($SmokeRaw -join [Environment]::NewLine)|ConvertFrom-Json
        if(-not[bool]$Smoke.passed -or -not[bool]$Smoke.window_created){Fail 'qt-smoke' 'B6-3 Home did not construct'}
        if([int]$Smoke.page_count -ne 6){Fail 'qt-smoke' ('unexpected page count='+[string]$Smoke.page_count)}
        if([bool]$Smoke.provider_available){Fail 'provider-truth' 'GitHub delta unexpectedly claims a live provider is available'}
        if([bool]$Smoke.smart_scan_enabled -or [bool]$Smoke.scan_page_quick_enabled){Fail 'provider-truth' 'Default UI enabled Smart Scan without accepted provider'}
        if([bool]$Smoke.full_scan_enabled){Fail 'full-scan' 'Full Scan unexpectedly enabled'}
        if([int]$Smoke.horizontal_scroll_max -ne 0 -or [int]$Smoke.scan_page_horizontal_scroll_max -ne 0){
            Fail 'overflow' 'B6-3 Home introduced horizontal overflow'
        }

        foreach($path in $Protected){
            $after=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            if($after -ne $BeforeProtected[$path]){
                Fail 'protected-source' ('B6-3 gate modified protected predecessor/security source: '+$path)
            }
        }

        Write-Host 'B63 LOCAL: predecessor B6-2 PASS | Smart Scan state machine PASS | explicit-start contract PASS | coverage truth PASS | cancellation PASS | UI integration PASS | no destructive authority | Full Scan disabled' -ForegroundColor Green
        Write-Host 'B63 STATUS: ORCHESTRATION FOUNDATION PASS. Accepted live Windows scan-provider integration remains REQUIRED before B6-3 stabilization.' -ForegroundColor Yellow
        Write-Host 'NOTE: B6-2 manual visual acceptance/polish is intentionally deferred and remains a separate open acceptance item.' -ForegroundColor Yellow
        Write-Host 'BC SENTINEL v0.11.0-beta.6 B6-3 SMART SCAN ORCHESTRATION - LOCAL PASS / LIVE PROVIDER WINDOWS GATE PENDING' -ForegroundColor Green
        exit 0
    }
    finally{
        if($null -eq $OldQt){Remove-Item Env:QT_QPA_PLATFORM -ErrorAction SilentlyContinue}else{$env:QT_QPA_PLATFORM=$OldQt}
        if($null -eq $OldMotion){Remove-Item Env:BC_SENTINEL_REDUCED_MOTION -ErrorAction SilentlyContinue}else{$env:BC_SENTINEL_REDUCED_MOTION=$OldMotion}
        Remove-Item -LiteralPath $PytestTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
catch{Fail 'unhandled' $_.Exception.Message}
