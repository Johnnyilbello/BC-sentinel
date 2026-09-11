param()
$ErrorActionPreference='Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Stage,[string]$Message){
    Write-Host ('B57 FAIL STAGE='+$Stage+' | '+$Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.5 B5-7 PORTABLE TECHNICIAN RELEASE - FAIL' -ForegroundColor Red
    exit 1
}

try{
    $id=[Security.Principal.WindowsIdentity]::GetCurrent();$principal=New-Object Security.Principal.WindowsPrincipal($id)
    if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){Fail 'preflight' 'Run B5-7 from normal non-elevated PowerShell.'}
    if(-not(Test-Path -LiteralPath '.\.venv\Scripts\python.exe')){Fail 'preflight' '.venv not available'}
    if(-not(Test-Path -LiteralPath '.\TEST-V011-BETA5-B56.ps1')){Fail 'preflight' 'accepted B5-6 gate missing; run B5-6 bootstrap first'}
    $Py='.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.5 - B5-7 PORTABLE TECHNICIAN RELEASE' -ForegroundColor Cyan
    Write-Host 'Final Beta5 portable packaging. No installer/service/driver and no repair-execute/unlock/format/reimage command.' -ForegroundColor Yellow

    $Protected=@('.\sentinel\protection_service_core.py','.\sentinel\realtime.py','.\sentinel\edr.py','.\sentinel\edr_service_bridge.py')
    $BeforeProtected=@{}
    foreach($path in $Protected){if(-not(Test-Path -LiteralPath $path)){Fail 'preflight' ('protected source missing: '+$path)};$BeforeProtected[$path]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}

    Write-Host 'B57 PREDECESSOR GATE: running accepted B5-6 complete controlled real-PC gate...' -ForegroundColor DarkCyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\TEST-V011-BETA5-B56.ps1'
    if($LASTEXITCODE -ne 0){Fail 'predecessor-b56' ('accepted B5-6 gate failed exit='+$LASTEXITCODE)}

    $Base=Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    New-Item -ItemType Directory -Path $Base -Force|Out-Null
    $ProcessTemp=Join-Path $Base ('b57-process-'+[guid]::NewGuid().ToString('N'))
    $PytestTemp=Join-Path $Base ('b57-pytest-'+[guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $ProcessTemp,$PytestTemp -Force|Out-Null
    $OldTemp=$env:TEMP;$OldTmp=$env:TMP;$env:TEMP=$ProcessTemp;$env:TMP=$ProcessTemp
    try{
        & $Py -m compileall -q sentinel\rescue_technician_portable.py packaging\rescue_technician_portable_entry.py tools\v011_beta5_b57_acceptance.py tests\test_v011_beta5_b57_portable_technician_release.py
        if($LASTEXITCODE -ne 0){Fail 'compileall' 'B5-7 compileall failed'}

        Write-Host ('B57 PYTEST BASETEMP='+$PytestTemp) -ForegroundColor DarkGray
        & $Py -m pytest -q --basetemp $PytestTemp tests/test_v011_beta5_b57_portable_technician_release.py
        if($LASTEXITCODE -ne 0){Fail 'pytest-b57' '20 B5-7 tests failed'}

        $AcceptanceDir=Join-Path $ProcessTemp 'acceptance'
        New-Item -ItemType Directory -Path $AcceptanceDir -Force|Out-Null
        $AcceptanceOut=Join-Path $AcceptanceDir 'acceptance-v011-beta5-b57.json'
        & $Py -m tools.v011_beta5_b57_acceptance --output $AcceptanceOut --fixture-dir (Join-Path $AcceptanceDir 'fixture')
        if($LASTEXITCODE -ne 0){Fail 'acceptance-b57' ('B5-7 deterministic acceptance failed exit='+$LASTEXITCODE)}
        $A=Get-Content -Raw -LiteralPath $AcceptanceOut -Encoding UTF8|ConvertFrom-Json
        if(-not[bool]$A.passed){Fail 'acceptance-b57' ('acceptance failed checks='+(($A.checks.psobject.Properties|Where-Object{-not[bool]$_.Value}|ForEach-Object{$_.Name}) -join ','))}
        if(-not[bool]$A.checks.target_byte_identical){Fail 'acceptance-b57' 'deterministic target integrity failed'}
        if(-not[bool]$A.checks.repair_execute_refused){Fail 'acceptance-b57' 'repair-execute refusal missing'}

        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\BUILD-TECHNICIAN-RELEASE-PORTABLE.ps1'
        if($LASTEXITCODE -ne 0){Fail 'build' 'B5-7 technician release build failed'}

        $Folder=Join-Path $PSScriptRoot 'dist\Rescue\BC-Sentinel-Technician-Portable'
        $Exe=Join-Path $Folder 'BC-Sentinel-Technician-Portable.exe'
        $Integrity=Join-Path $Folder 'technician-release-integrity.json'
        if(-not(Test-Path -LiteralPath $Exe)){Fail 'build-integrity' 'technician EXE missing'}
        if(-not(Test-Path -LiteralPath $Integrity)){Fail 'build-integrity' 'technician integrity manifest missing'}
        $BuildManifest=Get-Content -Raw -LiteralPath $Integrity -Encoding UTF8|ConvertFrom-Json
        $ExeHash=(Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLowerInvariant()
        if([string]$BuildManifest.sha256 -ne $ExeHash){Fail 'build-integrity' 'manifest SHA256 does not match EXE'}
        if([string]$BuildManifest.profile -ne 'v0.11.0-beta.5-b57'){Fail 'build-integrity' 'unexpected build profile'}
        if([bool]$BuildManifest.installer_required -or [bool]$BuildManifest.service_install -or [bool]$BuildManifest.driver_install){Fail 'build-integrity' 'installer/service/driver requirement appeared'}
        if([bool]$BuildManifest.repair_execution_exposed_by_launcher -or [bool]$BuildManifest.unlock_exposed -or [bool]$BuildManifest.format_exposed -or [bool]$BuildManifest.reimage_execution_exposed){Fail 'build-integrity' 'forbidden execution authority appeared'}

        $StatusRaw=@(& $Exe status);if($LASTEXITCODE -ne 0){Fail 'built-status' ('status exit='+$LASTEXITCODE)}
        $Status=($StatusRaw -join [Environment]::NewLine)|ConvertFrom-Json
        if(-not[bool]$Status.passed -or [string]$Status.profile -ne 'v0.11.0-beta.5-b57'){Fail 'built-status' 'built status invalid'}
        $ExpectedCommands='plan|scan|repair-handoff|data-rescue|certify|discover|assess|stress|resume|decide|report'
        if(($Status.commands -join '|') -ne $ExpectedCommands){Fail 'built-status' ('command surface mismatch='+(($Status.commands)-join '|'))}
        if([bool]$Status.safety.repair_execution_exposed_by_launcher){Fail 'built-status' 'repair execution exposed'}

        foreach($Forbidden in @('repair-execute','unlock','format','reimage')){
            $Raw=@(& $Exe $Forbidden);$Code=$LASTEXITCODE
            if($Code -ne 2){Fail 'built-refusal' ($Forbidden+' expected exit=2 actual='+$Code)}
            $Payload=($Raw -join [Environment]::NewLine)|ConvertFrom-Json
            if([string]$Payload.reason -ne ('unknown_command:'+$Forbidden)){Fail 'built-refusal' ($Forbidden+' refusal reason mismatch')}
        }

        foreach($HelpCommand in @('scan','repair-handoff','data-rescue','certify','discover','assess','stress','resume','decide','report')){
            & $Exe $HelpCommand --help|Out-Null
            if($LASTEXITCODE -ne 0){Fail 'built-help' ($HelpCommand+' did not load from built artifact')}
        }

        $RunRoot=Join-Path $Base ('b57-live-'+[guid]::NewGuid().ToString('N'))
        $Offline=Join-Path $RunRoot 'offline-target';$Workspace=Join-Path $RunRoot 'workspace';$Evidence=Join-Path $RunRoot 'evidence';$Config=Join-Path $Offline 'Windows\System32\config';$Bulk=Join-Path $Offline 'Bulk'
        New-Item -ItemType Directory -Path $Config,$Workspace,$Evidence,$Bulk -Force|Out-Null
        [IO.File]::WriteAllBytes((Join-Path $Config 'SYSTEM'),[Text.Encoding]::UTF8.GetBytes('B57 LIVE SYSTEM'))
        [IO.File]::WriteAllBytes((Join-Path $Config 'SOFTWARE'),[Text.Encoding]::UTF8.GetBytes('B57 LIVE SOFTWARE'))
        [IO.File]::WriteAllBytes((Join-Path $Offline 'Windows\System32\ntoskrnl.exe'),[Text.Encoding]::UTF8.GetBytes('MZ B57 LIVE KERNEL'))
        0..199|ForEach-Object{[IO.File]::WriteAllText((Join-Path $Bulk ('f{0:D3}.dat' -f $_)),('payload-'+$_),(New-Object Text.UTF8Encoding($false)))}
        $BeforeTarget=@{};Get-ChildItem -LiteralPath $Offline -File -Recurse|ForEach-Object{$BeforeTarget[$_.FullName]=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}

        $Plan=Join-Path $Workspace 'session-plan.json'
        & $Exe plan --target-root $Offline --workspace $Workspace --output-plan $Plan|Out-Null
        if($LASTEXITCODE -ne 0 -or -not(Test-Path -LiteralPath $Plan)){Fail 'built-plan' 'plan command failed'}
        & $Exe scan --target-root $Offline --workspace $Workspace --run-scan|Out-Null
        if($LASTEXITCODE -ne 0){Fail 'built-scan' 'scan command failed'}

        $Discover=Join-Path $Evidence 'discover.json'
        & $Exe discover $Offline --no-windows-volumes --no-child-probe --output $Discover|Out-Null
        if($LASTEXITCODE -ne 0 -or -not(Test-Path -LiteralPath $Discover)){Fail 'built-discover' 'discover command failed'}
        $D=Get-Content -Raw -LiteralPath $Discover -Encoding UTF8|ConvertFrom-Json
        if([int]$D.counts.READY -ne 1){Fail 'built-discover' ('READY count='+[string]$D.counts.READY)}

        $Assess=Join-Path $Evidence 'assessment.json'
        & $Exe assess --target-root $Offline --output $Assess --max-files 512|Out-Null
        $AssessExit=$LASTEXITCODE
        if($AssessExit -notin @(0,3) -or -not(Test-Path -LiteralPath $Assess)){Fail 'built-assess' ('assess exit='+$AssessExit)}
        $H=Get-Content -Raw -LiteralPath $Assess -Encoding UTF8|ConvertFrom-Json
        if([string]$H.state -notin @('HEALTHY','REVIEW_REQUIRED','IO_DEGRADED','DAMAGED')){Fail 'built-assess' ('unexpected state='+[string]$H.state)}

        $Stress=Join-Path $Evidence 'stress.json'
        & $Exe stress --target-root $Offline --output $Stress --max-files 1000 --max-total-sample-bytes 8388608 --max-elapsed-sec 15 --max-depth 64 --sample-bytes 64 --max-workers 2 --max-inflight 16|Out-Null
        if($LASTEXITCODE -ne 0 -or -not(Test-Path -LiteralPath $Stress)){Fail 'built-stress' 'stress command failed'}
        $S=Get-Content -Raw -LiteralPath $Stress -Encoding UTF8|ConvertFrom-Json
        if([string]$S.state -ne 'COMPLETE'){Fail 'built-stress' ('unexpected state='+[string]$S.state)}

        $ResumeRaw=@(& $Exe resume init --target-root $Offline --workspace $Workspace);if($LASTEXITCODE -ne 0){Fail 'built-resume' ('resume init exit='+$LASTEXITCODE)}
        $R=($ResumeRaw -join [Environment]::NewLine)|ConvertFrom-Json
        if([string]$R.profile -ne 'v0.11.0-beta.5-b53' -or [string]::IsNullOrWhiteSpace([string]$R.session_id)){Fail 'built-resume' 'resume session invalid'}

        foreach($p in $BeforeTarget.Keys){$after=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant();if($after -ne $BeforeTarget[$p]){Fail 'target-integrity' ('B5-7 modified target: '+$p)}}
        $AfterCount=@(Get-ChildItem -LiteralPath $Offline -File -Recurse).Count
        if($AfterCount -ne $BeforeTarget.Count){Fail 'target-integrity' ('target file count changed before='+$BeforeTarget.Count+' after='+$AfterCount)}

        $Services=@(Get-CimInstance Win32_Service|Where-Object{([string]$_.PathName).ToLowerInvariant().Contains('bc-sentinel-technician-portable') -or ([string]$_.PathName).ToLowerInvariant().Contains('rescue_technician_portable')})
        if($Services.Count -ne 0){Fail 'service-check' 'B5-7 unexpectedly registered a Windows service'}
        foreach($path in $Protected){$after=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();if($after -ne $BeforeProtected[$path]){Fail 'protected-source' ('B5-7 modified protected B2 source: '+$path)}}

        Write-Host ('B57 LIVE EXE SHA256='+$ExeHash) -ForegroundColor Green
        Write-Host ('B57 LIVE TARGET FILES='+[string]$BeforeTarget.Count+' DISCOVER_READY='+[string]$D.counts.READY+' ASSESS='+[string]$H.state+' STRESS='+[string]$S.state) -ForegroundColor Green
        Write-Host ('B57 LIVE RESUME SESSION='+[string]$R.session_id) -ForegroundColor Green
        Write-Host 'B57 LIVE: predecessor B5-6 PASS | 20 B5-7 tests PASS | deterministic dispatcher acceptance PASS | PyInstaller onedir PASS | built status/refusals PASS | built plan/scan/discover/assess/stress/resume PASS | decide/report load PASS | target unchanged | no service | B2 sources unchanged' -ForegroundColor Green
        Write-Host 'BC SENTINEL v0.11.0-beta.5 B5-7 PORTABLE TECHNICIAN RELEASE - PASS' -ForegroundColor Green
        exit 0
    }finally{
        $env:TEMP=$OldTemp;$env:TMP=$OldTmp
        Remove-Item -LiteralPath $PytestTemp -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $ProcessTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}catch{Fail 'unhandled' $_.Exception.Message}
