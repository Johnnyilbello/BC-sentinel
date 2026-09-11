param()
$ErrorActionPreference='Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Stage,[string]$Message){
    Write-Host ('B54 FAIL STAGE='+$Stage+' | '+$Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.5 B5-4 ADVANCED RECOVERY DECISION ENGINE - FAIL' -ForegroundColor Red
    exit 1
}

try{
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($id)
    if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){Fail 'preflight' 'Run B5-4 from normal non-elevated PowerShell.'}
    if(-not(Test-Path -LiteralPath '.\.venv\Scripts\python.exe')){Fail 'preflight' '.venv not available'}
    if(-not(Test-Path -LiteralPath '.\TEST-V011-BETA5-B53.ps1')){Fail 'preflight' 'accepted B5-3 gate missing; run B5-3 bootstrap first'}
    $Py='.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.5 - B5-4 ADVANCED RECOVERY DECISION ENGINE' -ForegroundColor Cyan
    Write-Host 'Advisory-only evidence decision. RR-6 outcome is authoritative and can never be overridden.' -ForegroundColor Yellow

    $Protected=@('.\sentinel\protection_service_core.py','.\sentinel\realtime.py','.\sentinel\edr.py','.\sentinel\edr_service_bridge.py')
    $BeforeProtected=@{}
    foreach($path in $Protected){if(-not(Test-Path -LiteralPath $path)){Fail 'preflight' ('protected source missing: '+$path)};$BeforeProtected[$path]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}

    Write-Host 'B54 PREDECESSOR GATE: running accepted B5-3 complete regression/resume gate...' -ForegroundColor DarkCyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\TEST-V011-BETA5-B53.ps1'
    if($LASTEXITCODE -ne 0){Fail 'predecessor-b53' ('accepted B5-3 gate failed exit='+$LASTEXITCODE)}

    $Base=Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    New-Item -ItemType Directory -Path $Base -Force|Out-Null
    $ProcessTemp=Join-Path $Base ('b54-process-'+[guid]::NewGuid().ToString('N'))
    $PytestTemp=Join-Path $Base ('b54-pytest-'+[guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $ProcessTemp,$PytestTemp -Force|Out-Null
    $OldTemp=$env:TEMP;$OldTmp=$env:TMP
    $env:TEMP=$ProcessTemp;$env:TMP=$ProcessTemp
    try{
        & $Py -m compileall -q sentinel\rescue_recovery_decision.py tools\v011_beta5_b54_acceptance.py tests\test_v011_beta5_b54_advanced_recovery_decision_engine.py
        if($LASTEXITCODE -ne 0){Fail 'compileall' 'B5-4 compileall failed'}

        Write-Host ('B54 PYTEST BASETEMP='+$PytestTemp) -ForegroundColor DarkGray
        & $Py -m pytest -q --basetemp $PytestTemp tests/test_v011_beta5_b54_advanced_recovery_decision_engine.py
        if($LASTEXITCODE -ne 0){Fail 'pytest-b54' '15 B5-4 tests failed'}

        $LiveFixture=Join-Path $ProcessTemp 'live-fixture'
        & $Py -m tools.v011_beta5_b54_acceptance --output '.\acceptance-v011-beta5-b54.json' --fixture-dir $LiveFixture
        if($LASTEXITCODE -ne 0){Fail 'acceptance-b54' 'B5-4 deterministic acceptance failed'}
        $A=Get-Content -Raw -LiteralPath '.\acceptance-v011-beta5-b54.json' -Encoding UTF8|ConvertFrom-Json
        if(-not[bool]$A.passed){Fail 'acceptance-b54' 'acceptance JSON did not pass'}
        if([string]$A.detail.refused_state -ne 'INDETERMINATE'){Fail 'acceptance-b54' 'RR6 refused precedence failed'}
        if([string]$A.detail.repairable_state -ne 'REPAIRABLE'){Fail 'acceptance-b54' 'REPAIRABLE state missing'}
        if([string]$A.detail.data_rescue_only_state -ne 'DATA_RESCUE_ONLY'){Fail 'acceptance-b54' 'DATA_RESCUE_ONLY state missing'}
        if([string]$A.detail.reimage_state -ne 'REIMAGE_RECOMMENDED'){Fail 'acceptance-b54' 'REIMAGE_RECOMMENDED state missing'}
        if([string]$A.detail.recovered_state -ne 'MANUAL_REVIEW'){Fail 'acceptance-b54' 'RECOVERED manual signoff precedence failed'}
        if([string]$A.detail.reconfirm_state -ne 'MANUAL_REVIEW'){Fail 'acceptance-b54' 'reconfirm precedence failed'}
        if(-not[bool]$A.checks.no_automatic_destructive_action){Fail 'acceptance-b54' 'automatic destructive action safety failed'}
        if(-not[bool]$A.checks.rr6_never_overridden){Fail 'acceptance-b54' 'RR6 override safety failed'}

        $Cert=[string]$A.detail.live_fixture.cert
        $Health=[string]$A.detail.live_fixture.health
        $Stress=[string]$A.detail.live_fixture.stress
        $LiveOut=[string]$A.detail.live_fixture.output
        foreach($p in @($Cert,$Health,$Stress)){if(-not(Test-Path -LiteralPath $p)){Fail 'live-cli' ('live fixture missing: '+$p)}}
        & $Py -m sentinel.rescue_recovery_decision --certification-summary $Cert --health-assessment $Health --stress-probe $Stress --output $LiveOut | Out-Null
        if($LASTEXITCODE -ne 0){Fail 'live-cli' ('decision CLI exit='+$LASTEXITCODE)}
        if(-not(Test-Path -LiteralPath $LiveOut)){Fail 'live-cli' 'live decision output missing'}
        $Live=Get-Content -Raw -LiteralPath $LiveOut -Encoding UTF8|ConvertFrom-Json
        if([string]$Live.state -ne 'MANUAL_REVIEW'){Fail 'live-cli' ('unexpected live state='+[string]$Live.state)}
        if([string]$Live.rr6_outcome -ne 'RECOVERED'){Fail 'live-cli' ('RR6 outcome not preserved='+[string]$Live.rr6_outcome)}
        if(-not[bool]$Live.safety.advisory_only){Fail 'live-cli' 'live advisory_only false'}
        if([bool]$Live.safety.rr6_outcome_override){Fail 'live-cli' 'live RR6 override enabled'}
        if([bool]$Live.safety.automatic_destructive_action){Fail 'live-cli' 'live automatic destructive action enabled'}
        if([string]$Live.decision_sha256 -notmatch '^[0-9a-f]{64}$'){Fail 'live-cli' 'live decision hash invalid'}

        $Services=@(Get-CimInstance Win32_Service|Where-Object{([string]$_.PathName).ToLowerInvariant().Contains('rescue_recovery_decision') -or ([string]$_.PathName).ToLowerInvariant().Contains('b54')})
        if($Services.Count -ne 0){Fail 'live-safety' 'B5-4 unexpectedly registered a Windows service'}
        foreach($path in $Protected){$after=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();if($after -ne $BeforeProtected[$path]){Fail 'protected-source' ('B5-4 modified protected B2 source: '+$path)}}

        Write-Host ('B54 ACCEPTANCE REPAIRABLE_SHA256='+[string]$A.detail.repairable_decision_sha256) -ForegroundColor Green
        Write-Host ('B54 LIVE RR6_OUTCOME='+[string]$Live.rr6_outcome+' STATE='+[string]$Live.state+' DECISION_SHA256='+[string]$Live.decision_sha256) -ForegroundColor Green
        Write-Host 'B54 LIVE: predecessor B5-3 PASS | 15 B5-4 tests PASS | RR6 refusal precedence PASS | repairable/data-rescue/reimage states PASS | reconfirm precedence PASS | tamper fail-closed PASS | advisory-only PASS | no service | B2 sources unchanged' -ForegroundColor Green
        Write-Host 'BC SENTINEL v0.11.0-beta.5 B5-4 ADVANCED RECOVERY DECISION ENGINE - PASS' -ForegroundColor Green
        exit 0
    }
    finally{
        $env:TEMP=$OldTemp;$env:TMP=$OldTmp
        Remove-Item -LiteralPath $PytestTemp -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $ProcessTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
catch{Fail 'unhandled' $_.Exception.Message}
