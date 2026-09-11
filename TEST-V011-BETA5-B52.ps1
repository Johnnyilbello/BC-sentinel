param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Stage,[string]$Message) {
    Write-Host ('B52 FAIL STAGE=' + $Stage + ' | ' + $Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.5 B5-2 LARGE-SCALE & STRESS HARDENING - FAIL' -ForegroundColor Red
    exit 1
}

try {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($id)
    if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){Fail 'preflight' 'Run B5-2 from normal non-elevated PowerShell.'}
    if(-not(Test-Path -LiteralPath '.\.venv\Scripts\python.exe')){Fail 'preflight' '.venv not available'}
    $Py='.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.5 - B5-2 LARGE-SCALE & STRESS HARDENING' -ForegroundColor Cyan
    Write-Host 'Bounded read-only stress probe. Partial results are explicit; no repair/quarantine/write is authorized.' -ForegroundColor Yellow

    $Protected=@('.\sentinel\protection_service_core.py','.\sentinel\realtime.py','.\sentinel\edr.py','.\sentinel\edr_service_bridge.py')
    $BeforeProtected=@{}
    foreach($path in $Protected){if(-not(Test-Path -LiteralPath $path)){Fail 'preflight' ('protected source missing: '+$path)};$BeforeProtected[$path]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}

    $Base=Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    New-Item -ItemType Directory -Path $Base -Force|Out-Null
    $ProcessTemp=Join-Path $Base ('b52-process-'+[guid]::NewGuid().ToString('N'))
    $PytestTemp=Join-Path $Base ('b52-pytest-'+[guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $ProcessTemp -Force|Out-Null
    $OldTemp=$env:TEMP;$OldTmp=$env:TMP
    $env:TEMP=$ProcessTemp;$env:TMP=$ProcessTemp
    Write-Host ('B52 PYTEST BASETEMP='+$PytestTemp) -ForegroundColor DarkGray

    try {
        & $Py -m compileall -q sentinel\rescue_stress_hardening.py tools\v011_beta5_b52_acceptance.py tests\test_v011_beta5_b52_large_scale_stress_hardening.py
        if($LASTEXITCODE -ne 0){Fail 'compileall' 'B5-2 compileall failed'}

        $Tests=@(
            'tests/test_v011_beta3_rr0_rescue_contract.py',
            'tests/test_v011_beta3_rr1_portable.py',
            'tests/test_v011_beta3_rr2_rescue_usb.py',
            'tests/test_v011_beta3_rr3_offline_scanner.py',
            'tests/test_v011_beta3_rr4a_repair_engine.py',
            'tests/test_v011_beta3_rr4b_portable_repair.py',
            'tests/test_v011_beta3_rr5_safe_data_rescue.py',
            'tests/test_v011_beta3_rr6_integrity_certification.py',
            'tests/test_v011_beta4_b40_rescue_console.py',
            'tests/test_v011_beta4_b41_evidence_inventory_guided_scan.py',
            'tests/test_v011_beta4_b42_guided_repair_handoff.py',
            'tests/test_v011_beta4_b43_guided_safe_data_rescue.py',
            'tests/test_v011_beta4_b44_integrated_certification_summary.py',
            'tests/test_v011_beta4_b45_portable_rescue_console.py',
            'tests/test_v011_beta5_b50_real_world_target_discovery.py',
            'tests/test_v011_beta5_b51_hostile_damaged_system_scenarios.py',
            'tests/test_v011_beta5_b52_large_scale_stress_hardening.py'
        )
        & $Py -m pytest -q --basetemp $PytestTemp @Tests
        if($LASTEXITCODE -ne 0){Fail 'pytest' 'Beta3 + Beta4 + B5-0..B5-2 regression failed'}

        foreach($spec in @(
            @('rr0','tools.v011_beta3_rr0_acceptance','acceptance-v011-beta3-rr0-b52-regression.json'),
            @('rr1','tools.v011_beta3_rr1_acceptance','acceptance-v011-beta3-rr1-b52-regression.json'),
            @('rr2','tools.v011_beta3_rr2_acceptance','acceptance-v011-beta3-rr2-b52-regression.json'),
            @('rr3','tools.v011_beta3_rr3_acceptance','acceptance-v011-beta3-rr3-b52-regression.json'),
            @('rr4a','tools.v011_beta3_rr4a_acceptance','acceptance-v011-beta3-rr4a-b52-regression.json'),
            @('rr4b','tools.v011_beta3_rr4b_acceptance','acceptance-v011-beta3-rr4b-b52-regression.json'),
            @('rr5','tools.v011_beta3_rr5_acceptance','acceptance-v011-beta3-rr5-b52-regression.json'),
            @('rr6','tools.v011_beta3_rr6_acceptance','acceptance-v011-beta3-rr6-b52-regression.json'),
            @('b40','tools.v011_beta4_b40_acceptance','acceptance-v011-beta4-b40-b52-regression.json'),
            @('b41','tools.v011_beta4_b41_acceptance','acceptance-v011-beta4-b41-b52-regression.json'),
            @('b42','tools.v011_beta4_b42_acceptance','acceptance-v011-beta4-b42-b52-regression.json'),
            @('b43','tools.v011_beta4_b43_acceptance','acceptance-v011-beta4-b43-b52-regression.json'),
            @('b44','tools.v011_beta4_b44_acceptance','acceptance-v011-beta4-b44-b52-regression.json'),
            @('b45','tools.v011_beta4_b45_acceptance','acceptance-v011-beta4-b45-b52-regression.json'),
            @('b50','tools.v011_beta5_b50_acceptance','acceptance-v011-beta5-b50-b52-regression.json'),
            @('b51','tools.v011_beta5_b51_acceptance','acceptance-v011-beta5-b51-b52-regression.json'),
            @('b52','tools.v011_beta5_b52_acceptance','acceptance-v011-beta5-b52.json')
        )){
            & $Py -m $spec[1] --output $spec[2]
            if($LASTEXITCODE -ne 0){Fail ('acceptance-'+$spec[0]) ($spec[0]+' deterministic acceptance failed')}
        }

        $A=Get-Content -Raw -LiteralPath '.\acceptance-v011-beta5-b52.json' -Encoding UTF8|ConvertFrom-Json
        if(-not[bool]$A.passed){Fail 'acceptance-b52' 'B5-2 acceptance JSON did not pass'}
        if([int]$A.detail.probed -lt 12000){Fail 'acceptance-b52' ('stress probed too few files: '+[string]$A.detail.probed)}
        if([double]$A.detail.files_per_sec -lt [double]$A.thresholds.throughput_floor_files_per_sec){Fail 'acceptance-b52' ('throughput below floor: '+[string]$A.detail.files_per_sec)}
        if([int64]$A.detail.python_peak_bytes -gt [int64]$A.thresholds.peak_python_memory_ceiling_bytes){Fail 'acceptance-b52' ('memory above ceiling: '+[string]$A.detail.python_peak_bytes)}
        if([int]$A.detail.inflight_peak -gt [int]$A.thresholds.max_inflight){Fail 'acceptance-b52' ('inflight exceeded bound: '+[string]$A.detail.inflight_peak)}
        if([string]$A.detail.limited_state -ne 'PARTIAL_FILE_LIMIT'){Fail 'acceptance-b52' 'file-limit partial state missing'}
        if([string]$A.detail.cancelled_state -ne 'CANCELLED'){Fail 'acceptance-b52' 'cancelled state missing'}
        if([string]$A.detail.timed_state -ne 'PARTIAL_TIME_LIMIT'){Fail 'acceptance-b52' 'time-limit partial state missing'}

        $LiveRoot=Join-Path $ProcessTemp 'live-fixture'
        $Target=Join-Path $LiveRoot 'offline'
        New-Item -ItemType Directory -Path (Join-Path $Target 'Windows\System32\config'),(Join-Path $Target 'Bulk') -Force|Out-Null
        [IO.File]::WriteAllBytes((Join-Path $Target 'Windows\System32\config\SYSTEM'),[Text.Encoding]::UTF8.GetBytes('B52 LIVE SYSTEM'))
        [IO.File]::WriteAllBytes((Join-Path $Target 'Windows\System32\config\SOFTWARE'),[Text.Encoding]::UTF8.GetBytes('B52 LIVE SOFTWARE'))
        [IO.File]::WriteAllBytes((Join-Path $Target 'Windows\System32\ntoskrnl.exe'),[Text.Encoding]::UTF8.GetBytes('MZ B52 LIVE KERNEL'))
        0..1499|ForEach-Object{[IO.File]::WriteAllText((Join-Path $Target ('Bulk\f{0:D4}.dat' -f $_)),('payload-'+$_),(New-Object Text.UTF8Encoding($false)))}
        $Before=@{}
        Get-ChildItem -LiteralPath $Target -File -Recurse|ForEach-Object{$Before[$_.FullName]=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
        $LiveOut=Join-Path $LiveRoot 'evidence\stress.json'
        & $Py -m sentinel.rescue_stress_hardening --target-root $Target --output $LiveOut --max-files 5000 --max-total-sample-bytes 8388608 --max-elapsed-sec 20 --max-depth 64 --sample-bytes 64 --max-workers 4 --max-inflight 32 --slow-read-ms 1000 | Out-Null
        if($LASTEXITCODE -ne 0){Fail 'live-cli' ('B5-2 CLI returned exit='+$LASTEXITCODE)}
        if(-not(Test-Path -LiteralPath $LiveOut)){Fail 'live-cli' 'live stress output missing'}
        $Live=Get-Content -Raw -LiteralPath $LiveOut -Encoding UTF8|ConvertFrom-Json
        if([string]$Live.state -ne 'COMPLETE'){Fail 'live-cli' ('live state='+[string]$Live.state)}
        if([int]$Live.counters.probed -lt 1503){Fail 'live-cli' ('live probed='+[string]$Live.counters.probed)}
        if([int]$Live.performance.inflight_peak -gt 32){Fail 'live-cli' 'live inflight exceeded 32'}
        if([string]$Live.probe_sha256 -notmatch '^[0-9a-f]{64}$'){Fail 'live-cli' 'live probe hash invalid'}
        foreach($p in $Before.Keys){$after=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant();if($after -ne $Before[$p]){Fail 'target-integrity' ('B5-2 modified target: '+$p)}}

        $Services=@(Get-CimInstance Win32_Service|Where-Object{([string]$_.PathName).ToLowerInvariant().Contains('rescue_stress_hardening') -or ([string]$_.PathName).ToLowerInvariant().Contains('b52')})
        if($Services.Count -ne 0){Fail 'live-safety' 'B5-2 unexpectedly registered a Windows service'}
        foreach($path in $Protected){$after=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();if($after -ne $BeforeProtected[$path]){Fail 'protected-source' ('B5-2 modified protected B2 source: '+$path)}}

        Write-Host ('B52 STRESS FILES='+[string]$A.detail.probed+' FILES_PER_SEC='+[string]$A.detail.files_per_sec+' PYTHON_PEAK_BYTES='+[string]$A.detail.python_peak_bytes+' INFLIGHT_PEAK='+[string]$A.detail.inflight_peak) -ForegroundColor Green
        Write-Host ('B52 LIVE STATE='+[string]$Live.state+' PROBED='+[string]$Live.counters.probed+' PROBE_SHA256='+[string]$Live.probe_sha256) -ForegroundColor Green
        Write-Host 'B52 LIVE: 12k+ scale PASS | deep tree PASS | large-file bounded sample PASS | file/time/cancel partial states PASS | worker/inflight bounds PASS | throughput/memory thresholds PASS | target unchanged | no repair/quarantine/write | no service | B2 sources unchanged' -ForegroundColor Green
        Write-Host 'BC SENTINEL v0.11.0-beta.5 B5-2 LARGE-SCALE & STRESS HARDENING - PASS' -ForegroundColor Green
        exit 0
    }
    finally{
        $env:TEMP=$OldTemp;$env:TMP=$OldTmp
        Remove-Item -LiteralPath $PytestTemp -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $ProcessTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
catch{Fail 'unhandled' $_.Exception.Message}
