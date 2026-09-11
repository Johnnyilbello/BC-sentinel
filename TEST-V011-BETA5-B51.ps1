param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Stage,[string]$Message) {
    Write-Host ('B51 FAIL STAGE=' + $Stage + ' | ' + $Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.5 B5-1 HOSTILE / DAMAGED SYSTEM SCENARIOS - FAIL' -ForegroundColor Red
    exit 1
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Fail 'preflight' 'Run B5-1 from normal non-elevated PowerShell.' }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { Fail 'preflight' '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.5 - B5-1 HOSTILE / DAMAGED SYSTEM SCENARIOS' -ForegroundColor Cyan
    Write-Host 'Read-only health probe. Missing/corrupt critical files, persistence, permissions and degraded I/O never trigger automatic repair.' -ForegroundColor Yellow

    $Protected = @('.\sentinel\protection_service_core.py','.\sentinel\realtime.py','.\sentinel\edr.py','.\sentinel\edr_service_bridge.py')
    $BeforeProtected = @{}
    foreach ($path in $Protected) {
        if (-not (Test-Path -LiteralPath $path)) { Fail 'preflight' ('protected source missing: ' + $path) }
        $BeforeProtected[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    $Base = Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    New-Item -ItemType Directory -Path $Base -Force | Out-Null
    $ProcessTemp = Join-Path $Base ('b51-process-' + [guid]::NewGuid().ToString('N'))
    $PytestTemp = Join-Path $Base ('b51-pytest-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $ProcessTemp -Force | Out-Null
    $OldTemp=$env:TEMP; $OldTmp=$env:TMP; $env:TEMP=$ProcessTemp; $env:TMP=$ProcessTemp
    Write-Host ('B51 PYTEST BASETEMP=' + $PytestTemp) -ForegroundColor DarkGray

    try {
        & $Py -m compileall -q sentinel\rescue_hostile_scenarios.py tools\v011_beta5_b51_acceptance.py tests\test_v011_beta5_b51_hostile_damaged_system_scenarios.py
        if ($LASTEXITCODE -ne 0) { Fail 'compileall' 'B5-1 compileall failed' }

        $Tests = @(
            'tests/test_v011_beta3_rr0_rescue_contract.py','tests/test_v011_beta3_rr1_portable.py','tests/test_v011_beta3_rr2_rescue_usb.py','tests/test_v011_beta3_rr3_offline_scanner.py','tests/test_v011_beta3_rr4a_repair_engine.py','tests/test_v011_beta3_rr4b_portable_repair.py','tests/test_v011_beta3_rr5_safe_data_rescue.py','tests/test_v011_beta3_rr6_integrity_certification.py',
            'tests/test_v011_beta4_b40_rescue_console.py','tests/test_v011_beta4_b41_evidence_inventory_guided_scan.py','tests/test_v011_beta4_b42_guided_repair_handoff.py','tests/test_v011_beta4_b43_guided_safe_data_rescue.py','tests/test_v011_beta4_b44_integrated_certification_summary.py','tests/test_v011_beta4_b45_portable_rescue_console.py',
            'tests/test_v011_beta5_b50_real_world_target_discovery.py','tests/test_v011_beta5_b51_hostile_damaged_system_scenarios.py'
        )
        & $Py -m pytest -q --basetemp $PytestTemp @Tests
        if ($LASTEXITCODE -ne 0) { Fail 'pytest' 'Beta3 + Beta4 + B5-0..B5-1 regression failed' }

        foreach ($spec in @(
            @('rr0','tools.v011_beta3_rr0_acceptance'),@('rr1','tools.v011_beta3_rr1_acceptance'),@('rr2','tools.v011_beta3_rr2_acceptance'),@('rr3','tools.v011_beta3_rr3_acceptance'),@('rr4a','tools.v011_beta3_rr4a_acceptance'),@('rr4b','tools.v011_beta3_rr4b_acceptance'),@('rr5','tools.v011_beta3_rr5_acceptance'),@('rr6','tools.v011_beta3_rr6_acceptance'),
            @('b40','tools.v011_beta4_b40_acceptance'),@('b41','tools.v011_beta4_b41_acceptance'),@('b42','tools.v011_beta4_b42_acceptance'),@('b43','tools.v011_beta4_b43_acceptance'),@('b44','tools.v011_beta4_b44_acceptance'),@('b45','tools.v011_beta4_b45_acceptance'),@('b50','tools.v011_beta5_b50_acceptance'),@('b51','tools.v011_beta5_b51_acceptance')
        )) {
            $out = ('acceptance-' + $spec[0] + '-b51.json')
            & $Py -m $spec[1] --output $out
            if ($LASTEXITCODE -ne 0) { Fail ('acceptance-' + $spec[0]) ($spec[0] + ' deterministic acceptance failed') }
        }
        $A = Get-Content -Raw -LiteralPath '.\acceptance-b51-b51.json' -Encoding UTF8 | ConvertFrom-Json
        if (-not [bool]$A.passed) { Fail 'acceptance-b51' 'B5-1 acceptance JSON did not pass' }
        if ([string]$A.detail.clean_state -ne 'HEALTHY') { Fail 'acceptance-b51' 'clean target not HEALTHY' }
        if ([string]$A.detail.damaged_state -ne 'DAMAGED') { Fail 'acceptance-b51' 'damaged target not DAMAGED' }
        if ([string]$A.detail.persistence_state -ne 'REVIEW_REQUIRED') { Fail 'acceptance-b51' 'persistence target not REVIEW_REQUIRED' }
        if ([string]$A.detail.restricted_state -ne 'ACCESS_RESTRICTED') { Fail 'acceptance-b51' 'permission case not ACCESS_RESTRICTED' }
        if ([string]$A.detail.degraded_state -ne 'IO_DEGRADED') { Fail 'acceptance-b51' 'I/O case not IO_DEGRADED' }

        $Live = Join-Path $ProcessTemp 'live'
        $Clean = Join-Path $Live 'clean'; $Damaged = Join-Path $Live 'damaged'; $Review = Join-Path $Live 'review'; $Evidence = Join-Path $Live 'evidence'
        foreach($r in @($Clean,$Damaged,$Review)) {
            New-Item -ItemType Directory -Path (Join-Path $r 'Windows\System32\config') -Force | Out-Null
            [IO.File]::WriteAllBytes((Join-Path $r 'Windows\System32\config\SYSTEM'),[Text.Encoding]::UTF8.GetBytes('B51 SYSTEM'))
            [IO.File]::WriteAllBytes((Join-Path $r 'Windows\System32\config\SOFTWARE'),[Text.Encoding]::UTF8.GetBytes('B51 SOFTWARE'))
            [IO.File]::WriteAllBytes((Join-Path $r 'Windows\System32\ntoskrnl.exe'),[Text.Encoding]::UTF8.GetBytes('MZ B51 KERNEL'))
        }
        Remove-Item -LiteralPath (Join-Path $Damaged 'Windows\System32\config\SOFTWARE') -Force
        $Startup = Join-Path $Review 'ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp'
        New-Item -ItemType Directory -Path $Startup -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $Startup 'persistence.ps1'),'Write-Output harmless',(New-Object Text.UTF8Encoding($false)))

        $BeforeTarget=@{}
        foreach($root in @($Clean,$Damaged,$Review)) { Get-ChildItem -LiteralPath $root -File -Recurse | ForEach-Object { $BeforeTarget[$_.FullName]=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() } }

        New-Item -ItemType Directory -Path $Evidence -Force | Out-Null
        $CleanOut=Join-Path $Evidence 'clean.json'; $DamagedOut=Join-Path $Evidence 'damaged.json'; $ReviewOut=Join-Path $Evidence 'review.json'
        & $Py -m sentinel.rescue_hostile_scenarios --target-root $Clean --output $CleanOut | Out-Null; if($LASTEXITCODE -ne 0){Fail 'live-clean' ('exit='+$LASTEXITCODE)}
        & $Py -m sentinel.rescue_hostile_scenarios --target-root $Damaged --output $DamagedOut | Out-Null; if($LASTEXITCODE -ne 3){Fail 'live-damaged' ('exit='+$LASTEXITCODE)}
        & $Py -m sentinel.rescue_hostile_scenarios --target-root $Review --output $ReviewOut | Out-Null; if($LASTEXITCODE -ne 0){Fail 'live-review' ('exit='+$LASTEXITCODE)}
        $C=Get-Content -Raw $CleanOut | ConvertFrom-Json; $D=Get-Content -Raw $DamagedOut | ConvertFrom-Json; $R=Get-Content -Raw $ReviewOut | ConvertFrom-Json
        if([string]$C.state -ne 'HEALTHY'){Fail 'live-clean' ('state='+$C.state)}
        if([string]$D.state -ne 'DAMAGED'){Fail 'live-damaged' ('state='+$D.state)}
        if([string]$R.state -ne 'REVIEW_REQUIRED'){Fail 'live-review' ('state='+$R.state)}
        if([int]$R.counters.persistence_review_items -lt 1){Fail 'live-review' 'persistence item missing'}
        foreach($p in $BeforeTarget.Keys){$after=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant(); if($after -ne $BeforeTarget[$p]){Fail 'target-integrity' ('modified '+$p)}}

        $Services=@(Get-CimInstance Win32_Service | Where-Object { ([string]$_.PathName).ToLowerInvariant().Contains('rescue_hostile_scenarios') -or ([string]$_.PathName).ToLowerInvariant().Contains('b51') })
        if($Services.Count -ne 0){Fail 'live-safety' 'B5-1 unexpectedly registered a service'}
        foreach($path in $Protected){$after=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant(); if($after -ne $BeforeProtected[$path]){Fail 'protected-source' ('modified '+$path)}}

        Write-Host ('B51 LIVE CLEAN STATE=' + [string]$C.state + ' SHA256=' + [string]$C.assessment_sha256) -ForegroundColor Green
        Write-Host ('B51 LIVE DAMAGED STATE=' + [string]$D.state + ' MISSING=' + (($D.critical_missing -join ','))) -ForegroundColor Green
        Write-Host ('B51 LIVE REVIEW STATE=' + [string]$R.state + ' PERSISTENCE_ITEMS=' + [string]$R.counters.persistence_review_items) -ForegroundColor Green
        Write-Host 'B51 LIVE: clean health PASS | damaged critical-file detection PASS | persistence review PASS | permission/I-O deterministic classification PASS | target unchanged | no repair/quarantine/write | no service | B2 sources unchanged' -ForegroundColor Green
        Write-Host 'BC SENTINEL v0.11.0-beta.5 B5-1 HOSTILE / DAMAGED SYSTEM SCENARIOS - PASS' -ForegroundColor Green
        exit 0
    }
    finally {
        $env:TEMP=$OldTemp; $env:TMP=$OldTmp
        Remove-Item -LiteralPath $PytestTemp -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $ProcessTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
catch { Fail 'unhandled' $_.Exception.Message }
