param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Stage,[string]$Message) {
    Write-Host ('B53 FAIL STAGE=' + $Stage + ' | ' + $Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.5 B5-3 SESSION RESUME & CRASH RECOVERY - FAIL' -ForegroundColor Red
    exit 1
}

try {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($id)
    if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){Fail 'preflight' 'Run B5-3 from normal non-elevated PowerShell.'}
    if(-not(Test-Path -LiteralPath '.\.venv\Scripts\python.exe')){Fail 'preflight' '.venv not available'}
    if(-not(Test-Path -LiteralPath '.\TEST-V011-BETA5-B52.ps1')){Fail 'preflight' 'accepted B5-2 gate missing'}
    $Py='.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.5 - B5-3 SESSION RESUME & CRASH RECOVERY' -ForegroundColor Cyan
    Write-Host 'Durable journal + hash chain + safe resume. Interrupted mutation-capable stages never auto-resume.' -ForegroundColor Yellow

    $Protected=@('.\sentinel\protection_service_core.py','.\sentinel\realtime.py','.\sentinel\edr.py','.\sentinel\edr_service_bridge.py')
    $BeforeProtected=@{}
    foreach($path in $Protected){if(-not(Test-Path -LiteralPath $path)){Fail 'preflight' ('protected source missing: '+$path)};$BeforeProtected[$path]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}

    Write-Host 'B53 PREDECESSOR GATE: running accepted B5-2 complete regression/stress gate...' -ForegroundColor DarkCyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\TEST-V011-BETA5-B52.ps1'
    if($LASTEXITCODE -ne 0){Fail 'predecessor-b52' ('accepted B5-2 gate failed exit='+$LASTEXITCODE)}

    $Base=Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    New-Item -ItemType Directory -Path $Base -Force|Out-Null
    $ProcessTemp=Join-Path $Base ('b53-process-'+[guid]::NewGuid().ToString('N'))
    $PytestTemp=Join-Path $Base ('b53-pytest-'+[guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $ProcessTemp -Force|Out-Null
    $OldTemp=$env:TEMP;$OldTmp=$env:TMP
    $env:TEMP=$ProcessTemp;$env:TMP=$ProcessTemp
    Write-Host ('B53 PYTEST BASETEMP='+$PytestTemp) -ForegroundColor DarkGray

    try {
        & $Py -m compileall -q sentinel\rescue_session_resume.py tools\v011_beta5_b53_acceptance.py tests\test_v011_beta5_b53_session_resume_crash_recovery.py
        if($LASTEXITCODE -ne 0){Fail 'compileall' 'B5-3 compileall failed'}

        & $Py -m pytest -q --basetemp $PytestTemp tests/test_v011_beta5_b53_session_resume_crash_recovery.py
        if($LASTEXITCODE -ne 0){Fail 'pytest-b53' 'B5-3 tests failed'}

        & $Py -m tools.v011_beta5_b53_acceptance --output acceptance-v011-beta5-b53.json
        if($LASTEXITCODE -ne 0){Fail 'acceptance-b53' 'B5-3 deterministic acceptance failed'}
        $A=Get-Content -Raw -LiteralPath '.\acceptance-v011-beta5-b53.json' -Encoding UTF8|ConvertFrom-Json
        if(-not[bool]$A.passed){Fail 'acceptance-b53' 'B5-3 acceptance JSON did not pass'}
        if(-not[bool]$A.checks.read_only_resume_allowed){Fail 'acceptance-b53' 'read-only resume was not allowed'}
        if(-not[bool]$A.checks.repair_reconfirmation_required){Fail 'acceptance-b53' 'repair interruption did not require reconfirmation'}
        if(-not[bool]$A.checks.data_rescue_reconfirmation_required){Fail 'acceptance-b53' 'data-rescue interruption did not require reconfirmation'}
        if(-not[bool]$A.checks.replay_refused){Fail 'acceptance-b53' 'idempotent replay was not refused'}
        if(-not[bool]$A.checks.tampered_evidence_refused){Fail 'acceptance-b53' 'tampered evidence was not refused'}
        if(-not[bool]$A.checks.changed_target_refused){Fail 'acceptance-b53' 'changed target was not refused'}
        if(-not[bool]$A.checks.tampered_journal_refused){Fail 'acceptance-b53' 'tampered journal was not refused'}

        $LiveRoot=Join-Path $ProcessTemp 'live-fixture'
        $Target=Join-Path $LiveRoot 'offline'
        $Workspace=Join-Path $LiveRoot 'workspace'
        New-Item -ItemType Directory -Path (Join-Path $Target 'Windows\System32\config') -Force|Out-Null
        [IO.File]::WriteAllBytes((Join-Path $Target 'Windows\System32\config\SYSTEM'),[Text.Encoding]::UTF8.GetBytes('B53 LIVE SYSTEM'))
        [IO.File]::WriteAllBytes((Join-Path $Target 'Windows\System32\config\SOFTWARE'),[Text.Encoding]::UTF8.GetBytes('B53 LIVE SOFTWARE'))
        [IO.File]::WriteAllBytes((Join-Path $Target 'Windows\System32\ntoskrnl.exe'),[Text.Encoding]::UTF8.GetBytes('MZ B53 LIVE KERNEL'))
        $Before=@{}
        Get-ChildItem -LiteralPath $Target -File -Recurse|ForEach-Object{$Before[$_.FullName]=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}

        $InitLines=@(& $Py -m sentinel.rescue_session_resume init --target-root $Target --workspace $Workspace)
        if($LASTEXITCODE -ne 0){Fail 'live-init' ('init exit='+$LASTEXITCODE)}
        $Init=(($InitLines -join "`n")|ConvertFrom-Json)
        $Journal=[string]$Init.journal_path
        if(-not(Test-Path -LiteralPath $Journal)){Fail 'live-init' 'journal missing'}
        if([string]$Init.journal_sha256 -notmatch '^[0-9a-f]{64}$'){Fail 'live-init' 'journal hash invalid'}

        $Evidence=Join-Path $Workspace 'scan-evidence.json'
        [IO.File]::WriteAllText($Evidence,'{"status":"trusted"}',(New-Object Text.UTF8Encoding($false)))

        @(& $Py -m sentinel.rescue_session_resume event --journal $Journal --stage offline_scan --state STARTED --reason live_scan_started --evidence $Evidence)|Out-Null
        if($LASTEXITCODE -ne 0){Fail 'live-event-scan-start' ('exit='+$LASTEXITCODE)}
        @(& $Py -m sentinel.rescue_session_resume event --journal $Journal --stage offline_scan --state INTERRUPTED --reason simulated_console_close --evidence $Evidence)|Out-Null
        if($LASTEXITCODE -ne 0){Fail 'live-event-scan-interrupt' ('exit='+$LASTEXITCODE)}
        @(& $Py -m sentinel.rescue_session_resume event --journal $Journal --stage repair_execute --state INTERRUPTED --reason simulated_repair_crash)|Out-Null
        if($LASTEXITCODE -ne 0){Fail 'live-event-repair' ('exit='+$LASTEXITCODE)}
        @(& $Py -m sentinel.rescue_session_resume event --journal $Journal --stage data_rescue --state STARTED --reason simulated_copy_crash)|Out-Null
        if($LASTEXITCODE -ne 0){Fail 'live-event-data-rescue' ('exit='+$LASTEXITCODE)}

        $ResumeLines=@(& $Py -m sentinel.rescue_session_resume resume --journal $Journal --target-root $Target)
        if($LASTEXITCODE -ne 0){Fail 'live-resume' ('trusted resume exit='+$LASTEXITCODE)}
        $Resume=(($ResumeLines -join "`n")|ConvertFrom-Json)
        if(-not[bool]$Resume.trusted -or [string]$Resume.state -ne 'READY'){Fail 'live-resume' 'trusted resume not READY'}
        $ScanAction=@($Resume.actions|Where-Object{$_.stage -eq 'offline_scan'})
        $RepairAction=@($Resume.actions|Where-Object{$_.stage -eq 'repair_execute'})
        $DataAction=@($Resume.actions|Where-Object{$_.stage -eq 'data_rescue'})
        if($ScanAction.Count -ne 1 -or [string]$ScanAction[0].decision -ne 'RESUME_READ_ONLY_ALLOWED'){Fail 'live-resume' 'offline_scan not safely resumable'}
        if($RepairAction.Count -ne 1 -or [string]$RepairAction[0].decision -ne 'RECONFIRM_REQUIRED'){Fail 'live-resume' 'repair did not require reconfirmation'}
        if($DataAction.Count -ne 1 -or [string]$DataAction[0].decision -ne 'RECONFIRM_REQUIRED'){Fail 'live-resume' 'data rescue did not require reconfirmation'}
        if([bool]$Resume.safety.automatic_mutation_resume){Fail 'live-resume' 'automatic mutation resume unexpectedly enabled'}

        $ReplayLines=@(& $Py -m sentinel.rescue_session_resume event --journal $Journal --stage repair_execute --state INTERRUPTED --reason simulated_repair_crash 2>&1)
        if($LASTEXITCODE -eq 0){Fail 'live-replay' 'duplicate repair event unexpectedly accepted'}
        if(($ReplayLines -join "`n") -notmatch 'idempotent replay refused'){Fail 'live-replay' 'duplicate refusal reason missing'}

        [IO.File]::WriteAllText($Evidence,'{"status":"tampered"}',(New-Object Text.UTF8Encoding($false)))
        $TamperedLines=@(& $Py -m sentinel.rescue_session_resume resume --journal $Journal --target-root $Target)
        $TamperedExit=$LASTEXITCODE
        $Tampered=(($TamperedLines -join "`n")|ConvertFrom-Json)
        if($TamperedExit -ne 4){Fail 'live-tamper' ('tampered evidence exit='+$TamperedExit)}
        if([bool]$Tampered.trusted -or [string]$Tampered.state -ne 'REFUSED'){Fail 'live-tamper' 'tampered evidence did not refuse resume'}
        if([int]$Tampered.evidence_failed -lt 1){Fail 'live-tamper' 'tampered evidence failure counter missing'}

        foreach($p in $Before.Keys){$after=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant();if($after -ne $Before[$p]){Fail 'target-integrity' ('B5-3 modified target: '+$p)}}

        $Services=@(Get-CimInstance Win32_Service|Where-Object{([string]$_.PathName).ToLowerInvariant().Contains('rescue_session_resume') -or ([string]$_.PathName).ToLowerInvariant().Contains('b53')})
        if($Services.Count -ne 0){Fail 'live-safety' 'B5-3 unexpectedly registered a Windows service'}
        foreach($path in $Protected){$after=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();if($after -ne $BeforeProtected[$path]){Fail 'protected-source' ('B5-3 modified protected B2 source: '+$path)}}

        Write-Host ('B53 ACCEPTANCE SESSION='+[string]$A.detail.session_id+' JOURNAL_SHA256='+[string]$A.detail.journal_sha256+' DECISION_SHA256='+[string]$A.detail.decision_sha256) -ForegroundColor Green
        Write-Host ('B53 LIVE SESSION='+[string]$Resume.session_id+' JOURNAL_SHA256='+[string]$Resume.journal_sha256+' DECISION_SHA256='+[string]$Resume.decision_sha256) -ForegroundColor Green
        Write-Host 'B53 LIVE: predecessor B5-2 PASS | 16 B5-3 tests PASS | read-only resume PASS | repair/data-rescue reconfirm PASS | replay refused PASS | tampered evidence refused PASS | target unchanged | no service | B2 sources unchanged' -ForegroundColor Green
        Write-Host 'BC SENTINEL v0.11.0-beta.5 B5-3 SESSION RESUME & CRASH RECOVERY - PASS' -ForegroundColor Green
        exit 0
    }
    finally{
        $env:TEMP=$OldTemp;$env:TMP=$OldTmp
        Remove-Item -LiteralPath $PytestTemp -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $ProcessTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
catch{Fail 'unhandled' $_.Exception.Message}
