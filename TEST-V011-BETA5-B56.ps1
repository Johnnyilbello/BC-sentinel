param()
$ErrorActionPreference='Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Stage,[string]$Message){
    Write-Host ('B56 FAIL STAGE='+$Stage+' | '+$Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.5 B5-6 CONTROLLED REAL-PC ACCEPTANCE - FAIL' -ForegroundColor Red
    exit 1
}

try{
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($id)
    if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){Fail 'preflight' 'Run B5-6 from normal non-elevated PowerShell.'}
    if(-not(Test-Path -LiteralPath '.\.venv\Scripts\python.exe')){Fail 'preflight' '.venv not available'}
    if(-not(Test-Path -LiteralPath '.\TEST-V011-BETA5-B55.ps1')){Fail 'preflight' 'accepted B5-5 gate missing; run B5-5 bootstrap first'}
    $Py='.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.5 - B5-6 CONTROLLED REAL-PC ACCEPTANCE' -ForegroundColor Cyan
    Write-Host 'Real host control + explicitly labeled controlled offline fixtures. No repair, quarantine, unlock, format or reimage execution is added.' -ForegroundColor Yellow

    $Protected=@('.\sentinel\protection_service_core.py','.\sentinel\realtime.py','.\sentinel\edr.py','.\sentinel\edr_service_bridge.py')
    $BeforeProtected=@{}
    foreach($path in $Protected){if(-not(Test-Path -LiteralPath $path)){Fail 'preflight' ('protected source missing: '+$path)};$BeforeProtected[$path]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}

    Write-Host 'B56 PREDECESSOR GATE: running accepted B5-5 complete technician-package gate...' -ForegroundColor DarkCyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\TEST-V011-BETA5-B55.ps1'
    if($LASTEXITCODE -ne 0){Fail 'predecessor-b55' ('accepted B5-5 gate failed exit='+$LASTEXITCODE)}

    $ExpectedPredecessor=@(
        '.\acceptance-v011-beta5-b50-b52-regression.json',
        '.\acceptance-v011-beta5-b51-b52-regression.json',
        '.\acceptance-v011-beta5-b52.json',
        '.\acceptance-v011-beta5-b53.json',
        '.\acceptance-v011-beta5-b54.json',
        '.\acceptance-v011-beta5-b55.json'
    )
    foreach($p in $ExpectedPredecessor){if(-not(Test-Path -LiteralPath $p)){Fail 'predecessor-evidence' ('missing predecessor acceptance evidence: '+$p)}}

    $Base=Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    New-Item -ItemType Directory -Path $Base -Force|Out-Null
    $ProcessTemp=Join-Path $Base ('b56-process-'+[guid]::NewGuid().ToString('N'))
    $PytestTemp=Join-Path $Base ('b56-pytest-'+[guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $ProcessTemp,$PytestTemp -Force|Out-Null
    $EvidenceDir=Join-Path $PSScriptRoot 'acceptance-v011-beta5-b56-evidence'
    if(Test-Path -LiteralPath $EvidenceDir){Remove-Item -LiteralPath $EvidenceDir -Recurse -Force}
    New-Item -ItemType Directory -Path $EvidenceDir -Force|Out-Null

    $OldTemp=$env:TEMP;$OldTmp=$env:TMP
    $env:TEMP=$ProcessTemp;$env:TMP=$ProcessTemp
    try{
        & $Py -m compileall -q sentinel\rescue_real_pc_acceptance.py tools\v011_beta5_b56_acceptance.py tests\test_v011_beta5_b56_controlled_real_pc_acceptance.py
        if($LASTEXITCODE -ne 0){Fail 'compileall' 'B5-6 compileall failed'}

        Write-Host ('B56 PYTEST BASETEMP='+$PytestTemp) -ForegroundColor DarkGray
        & $Py -m pytest -q --basetemp $PytestTemp tests/test_v011_beta5_b56_controlled_real_pc_acceptance.py
        if($LASTEXITCODE -ne 0){Fail 'pytest-b56' '16 B5-6 tests failed'}

        $SummaryPath=Join-Path $EvidenceDir 'controlled-real-pc-summary.json'
        & $Py -m tools.v011_beta5_b56_acceptance --repo-root $PSScriptRoot --work-dir $EvidenceDir --output $SummaryPath
        if($LASTEXITCODE -ne 0){Fail 'acceptance-b56' ('B5-6 deterministic/host acceptance failed exit='+$LASTEXITCODE)}
        $ResultPath=Join-Path $EvidenceDir 'b56-acceptance-result.json'
        if(-not(Test-Path -LiteralPath $ResultPath)){Fail 'acceptance-b56' 'B5-6 acceptance result missing'}
        $A=Get-Content -Raw -LiteralPath $ResultPath -Encoding UTF8|ConvertFrom-Json
        if(-not[bool]$A.passed){Fail 'acceptance-b56' 'B5-6 acceptance result did not pass'}
        if(-not[bool]$A.checks.real_hardware_control_present){Fail 'real-host' 'REAL_HARDWARE control record missing'}
        if(-not[bool]$A.checks.controlled_fixture_coverage){Fail 'fixtures' 'controlled fixture coverage incomplete'}
        if(-not[bool]$A.checks.fixture_not_mislabeled){Fail 'labeling' 'fixture/real-hardware labeling contract failed'}
        if(-not[bool]$A.checks.problematic_pc_optional_not_faked){Fail 'problematic-pc' 'problematic PC was claimed without real evidence'}
        if(-not[bool]$A.checks.no_automatic_destructive_action){Fail 'safety' 'automatic destructive action safety failed'}
        if(-not[bool]$A.checks.no_repair_authority){Fail 'safety' 'repair execution authority appeared'}
        if(-not[bool]$A.checks.no_reimage_execution){Fail 'safety' 'reimage execution appeared'}

        if(-not(Test-Path -LiteralPath $SummaryPath)){Fail 'summary' 'controlled real-PC summary missing'}
        $Summary=Get-Content -Raw -LiteralPath $SummaryPath -Encoding UTF8|ConvertFrom-Json
        if(-not[bool]$Summary.passed){Fail 'summary' ('summary failures='+(($Summary.failures|ForEach-Object{[string]$_}) -join ','))}
        if([int]$Summary.counts.real_hardware -lt 1){Fail 'summary' 'no real-hardware record'}
        if([int]$Summary.counts.controlled_fixture -lt 5){Fail 'summary' 'fewer than five controlled fixture records'}
        if([string]$Summary.problematic_pc_status -ne 'NOT_RUN'){Fail 'summary' ('unexpected problematic_pc_status='+[string]$Summary.problematic_pc_status)}
        if([string]$Summary.summary_sha256 -notmatch '^[0-9a-f]{64}$'){Fail 'summary' 'summary SHA256 invalid'}

        $ScenarioFiles=@(Get-ChildItem -LiteralPath (Join-Path $EvidenceDir 'scenarios') -Filter '*.json' -File)
        if($ScenarioFiles.Count -ne 6){Fail 'scenario-count' ('expected 6 scenario records, got '+$ScenarioFiles.Count)}

        $Services=@(Get-CimInstance Win32_Service|Where-Object{([string]$_.PathName).ToLowerInvariant().Contains('rescue_real_pc_acceptance') -or ([string]$_.PathName).ToLowerInvariant().Contains('b56')})
        if($Services.Count -ne 0){Fail 'live-safety' 'B5-6 unexpectedly registered a Windows service'}
        foreach($path in $Protected){$after=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();if($after -ne $BeforeProtected[$path]){Fail 'protected-source' ('B5-6 modified protected B2 source: '+$path)}}

        Write-Host ('B56 ACCEPTANCE HOST_FINGERPRINT='+[string]$A.detail.host_fingerprint+' SUMMARY_SHA256='+[string]$A.detail.summary_sha256) -ForegroundColor Green
        Write-Host ('B56 COVERAGE REAL_HARDWARE='+[string]$Summary.counts.real_hardware+' CONTROLLED_FIXTURE='+[string]$Summary.counts.controlled_fixture+' PROBLEMATIC_PC='+[string]$Summary.problematic_pc_status) -ForegroundColor Green
        Write-Host 'B56 LIVE: predecessor B5-5 PASS | 16 B5-6 tests PASS | real Windows host control PASS | damaged/persistence/resource/locked/resume controlled scenarios PASS | fixture labeling PASS | problematic PC not faked | no destructive authority | no service | B2 sources unchanged' -ForegroundColor Green
        Write-Host 'BC SENTINEL v0.11.0-beta.5 B5-6 CONTROLLED REAL-PC ACCEPTANCE - PASS' -ForegroundColor Green
        exit 0
    }
    finally{
        $env:TEMP=$OldTemp;$env:TMP=$OldTmp
        Remove-Item -LiteralPath $PytestTemp -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $ProcessTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
catch{Fail 'unhandled' $_.Exception.Message}
