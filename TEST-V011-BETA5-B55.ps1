param()
$ErrorActionPreference='Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Stage,[string]$Message){
    Write-Host ('B55 FAIL STAGE='+$Stage+' | '+$Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.5 B5-5 TECHNICIAN REPORT & EVIDENCE PACKAGE - FAIL' -ForegroundColor Red
    exit 1
}

try{
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($id)
    if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){Fail 'preflight' 'Run B5-5 from normal non-elevated PowerShell.'}
    if(-not(Test-Path -LiteralPath '.\.venv\Scripts\python.exe')){Fail 'preflight' '.venv not available'}
    if(-not(Test-Path -LiteralPath '.\TEST-V011-BETA5-B54.ps1')){Fail 'preflight' 'accepted B5-4 gate missing; run B5-4 bootstrap first'}
    $Py='.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.5 - B5-5 TECHNICIAN REPORT & EVIDENCE PACKAGE' -ForegroundColor Cyan
    Write-Host 'Evidence export only. Trusted evidence is SHA-256 bound; no repair, rescue, quarantine or reimage is executed.' -ForegroundColor Yellow

    $Protected=@('.\sentinel\protection_service_core.py','.\sentinel\realtime.py','.\sentinel\edr.py','.\sentinel\edr_service_bridge.py')
    $BeforeProtected=@{}
    foreach($path in $Protected){if(-not(Test-Path -LiteralPath $path)){Fail 'preflight' ('protected source missing: '+$path)};$BeforeProtected[$path]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}

    Write-Host 'B55 PREDECESSOR GATE: running accepted B5-4 complete decision-engine gate...' -ForegroundColor DarkCyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\TEST-V011-BETA5-B54.ps1'
    if($LASTEXITCODE -ne 0){Fail 'predecessor-b54' ('accepted B5-4 gate failed exit='+$LASTEXITCODE)}

    $Base=Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    New-Item -ItemType Directory -Path $Base -Force|Out-Null
    $ProcessTemp=Join-Path $Base ('b55-process-'+[guid]::NewGuid().ToString('N'))
    $PytestTemp=Join-Path $Base ('b55-pytest-'+[guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $ProcessTemp,$PytestTemp -Force|Out-Null
    $OldTemp=$env:TEMP;$OldTmp=$env:TMP
    $env:TEMP=$ProcessTemp;$env:TMP=$ProcessTemp
    try{
        & $Py -m compileall -q sentinel\rescue_technician_report.py tools\v011_beta5_b55_acceptance.py tests\test_v011_beta5_b55_technician_report_evidence_package.py tests\test_v011_beta5_b55_package_reparse_verification.py
        if($LASTEXITCODE -ne 0){Fail 'compileall' 'B5-5 compileall failed'}

        Write-Host ('B55 PYTEST BASETEMP='+$PytestTemp) -ForegroundColor DarkGray
        & $Py -m pytest -q --basetemp $PytestTemp tests/test_v011_beta5_b55_technician_report_evidence_package.py tests/test_v011_beta5_b55_package_reparse_verification.py
        if($LASTEXITCODE -ne 0){Fail 'pytest-b55' '15 B5-5 tests failed'}

        $LiveFixture=Join-Path $ProcessTemp 'live-fixture'
        & $Py -m tools.v011_beta5_b55_acceptance --output '.\acceptance-v011-beta5-b55.json' --fixture-dir $LiveFixture
        if($LASTEXITCODE -ne 0){Fail 'acceptance-b55' 'B5-5 deterministic acceptance failed'}
        $A=Get-Content -Raw -LiteralPath '.\acceptance-v011-beta5-b55.json' -Encoding UTF8|ConvertFrom-Json
        if(-not[bool]$A.passed){Fail 'acceptance-b55' 'acceptance JSON did not pass'}
        if(-not[bool]$A.checks.tampered_package_detected){Fail 'acceptance-b55' 'package tamper detection failed'}
        if(-not[bool]$A.checks.trusted_source_drift_refused){Fail 'acceptance-b55' 'trusted source drift refusal failed'}
        if(-not[bool]$A.checks.untrusted_risk_preserved){Fail 'acceptance-b55' 'untrusted evidence risk not preserved'}
        if(-not[bool]$A.checks.target_byte_identical){Fail 'acceptance-b55' 'deterministic fixture target changed'}

        $Target=[string]$A.detail.live_fixture.target
        $Decision=[string]$A.detail.live_fixture.decision
        $Package=[string]$A.detail.live_fixture.package
        foreach($p in @($Target,$Decision)){if(-not(Test-Path -LiteralPath $p)){Fail 'live-fixture' ('missing live fixture: '+$p)}}
        if(Test-Path -LiteralPath $Package){Remove-Item -LiteralPath $Package -Recurse -Force}

        $BeforeTarget=@{}
        Get-ChildItem -LiteralPath $Target -File -Recurse|ForEach-Object{$BeforeTarget[$_.FullName]=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}

        $BuildText=(& $Py -m sentinel.rescue_technician_report build --target-root $Target --decision $Decision --package-dir $Package | Out-String)
        if($LASTEXITCODE -ne 0){Fail 'live-build' ('B5-5 build CLI exit='+$LASTEXITCODE+' output='+$BuildText)}
        try{$Build=$BuildText|ConvertFrom-Json}catch{Fail 'live-build' ('build output not JSON: '+$BuildText)}
        if(-not[bool]$Build.verification_passed){Fail 'live-build' 'build self verification false'}
        if([string]$Build.report_sha256 -notmatch '^[0-9a-f]{64}$'){Fail 'live-build' 'report hash invalid'}
        if([string]$Build.evidence_index_sha256 -notmatch '^[0-9a-f]{64}$'){Fail 'live-build' 'evidence index hash invalid'}
        if([string]$Build.manifest_sha256 -notmatch '^[0-9a-f]{64}$'){Fail 'live-build' 'manifest hash invalid'}

        $VerifyText=(& $Py -m sentinel.rescue_technician_report verify --package-dir $Package | Out-String)
        if($LASTEXITCODE -ne 0){Fail 'live-verify' ('B5-5 verify CLI exit='+$LASTEXITCODE+' output='+$VerifyText)}
        try{$Verify=$VerifyText|ConvertFrom-Json}catch{Fail 'live-verify' ('verify output not JSON: '+$VerifyText)}
        if(-not[bool]$Verify.passed){Fail 'live-verify' ('verify failed: '+(($Verify.errors|ForEach-Object{[string]$_}) -join ','))}

        $ReportPath=Join-Path $Package 'technician-report.json'
        $HumanPath=Join-Path $Package 'technician-report.md'
        $IndexPath=Join-Path $Package 'evidence-index.json'
        $ManifestPath=Join-Path $Package 'package-manifest.json'
        foreach($p in @($ReportPath,$HumanPath,$IndexPath,$ManifestPath)){if(-not(Test-Path -LiteralPath $p)){Fail 'live-artifacts' ('missing package artifact: '+$p)}}
        $Report=Get-Content -Raw -LiteralPath $ReportPath -Encoding UTF8|ConvertFrom-Json
        if([string]$Report.rr6_outcome -ne 'RECOVERED'){Fail 'live-report' ('RR6 outcome changed: '+[string]$Report.rr6_outcome)}
        if([string]$Report.advisory_state -ne 'MANUAL_REVIEW'){Fail 'live-report' ('advisory state changed: '+[string]$Report.advisory_state)}
        if(-not[bool]$Report.safety.report_only){Fail 'live-report' 'report_only false'}
        if([bool]$Report.safety.repair_execution -or [bool]$Report.safety.data_rescue_execution -or [bool]$Report.safety.format_or_reimage_execution){Fail 'live-report' 'execution authority appeared in report'}
        if([int]$Report.evidence_summary.untrusted_not_copied -ne 1){Fail 'live-report' 'untrusted evidence count not preserved'}

        foreach($p in $BeforeTarget.Keys){$after=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant();if($after -ne $BeforeTarget[$p]){Fail 'target-integrity' ('B5-5 modified target: '+$p)}}
        $AfterCount=@(Get-ChildItem -LiteralPath $Target -File -Recurse).Count
        if($AfterCount -ne $BeforeTarget.Count){Fail 'target-integrity' ('target file count changed before='+$BeforeTarget.Count+' after='+$AfterCount)}

        $Services=@(Get-CimInstance Win32_Service|Where-Object{([string]$_.PathName).ToLowerInvariant().Contains('rescue_technician_report') -or ([string]$_.PathName).ToLowerInvariant().Contains('b55')})
        if($Services.Count -ne 0){Fail 'live-safety' 'B5-5 unexpectedly registered a Windows service'}
        foreach($path in $Protected){$after=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();if($after -ne $BeforeProtected[$path]){Fail 'protected-source' ('B5-5 modified protected B2 source: '+$path)}}

        Write-Host ('B55 ACCEPTANCE REPORT_SHA256='+[string]$A.detail.report_sha256+' INDEX_SHA256='+[string]$A.detail.evidence_index_sha256+' MANIFEST_SHA256='+[string]$A.detail.manifest_sha256) -ForegroundColor Green
        Write-Host ('B55 LIVE RR6_OUTCOME='+[string]$Report.rr6_outcome+' STATE='+[string]$Report.advisory_state+' MANIFEST_SHA256='+[string]$Build.manifest_sha256+' VERIFIED_FILES='+[string]$Verify.checked) -ForegroundColor Green
        Write-Host 'B55 LIVE: predecessor B5-4 PASS | 15 B5-5 tests PASS | human+JSON report PASS | evidence hash index PASS | manifest verify PASS | tamper/reparse detection PASS | trusted drift refusal PASS | untrusted risk preserved PASS | target unchanged | no service | B2 sources unchanged' -ForegroundColor Green
        Write-Host 'BC SENTINEL v0.11.0-beta.5 B5-5 TECHNICIAN REPORT & EVIDENCE PACKAGE - PASS' -ForegroundColor Green
        exit 0
    }
    finally{
        $env:TEMP=$OldTemp;$env:TMP=$OldTmp
        Remove-Item -LiteralPath $PytestTemp -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $ProcessTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
catch{Fail 'unhandled' $_.Exception.Message}
