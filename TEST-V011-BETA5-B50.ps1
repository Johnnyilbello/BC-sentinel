param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Stage,[string]$Message) {
    Write-Host ('B50 FAIL STAGE=' + $Stage + ' | ' + $Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.5 B5-0 REAL-WORLD TARGET DISCOVERY - FAIL' -ForegroundColor Red
    exit 1
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Fail 'preflight' 'Run B5-0 from normal non-elevated PowerShell.' }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { Fail 'preflight' '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.5 - B5-0 REAL-WORLD TARGET DISCOVERY' -ForegroundColor Cyan
    Write-Host 'Read-only multi-volume discovery. Live SystemDrive is refused; BitLocker is observed only, never unlocked.' -ForegroundColor Yellow

    $Protected = @('.\sentinel\protection_service_core.py','.\sentinel\realtime.py','.\sentinel\edr.py','.\sentinel\edr_service_bridge.py')
    $BeforeProtected = @{}
    foreach ($path in $Protected) {
        if (-not (Test-Path -LiteralPath $path)) { Fail 'preflight' ('protected source missing: ' + $path) }
        $BeforeProtected[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    $Base = Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    New-Item -ItemType Directory -Path $Base -Force | Out-Null
    $ProcessTemp = Join-Path $Base ('b50-process-' + [guid]::NewGuid().ToString('N'))
    $PytestTemp = Join-Path $Base ('b50-pytest-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $ProcessTemp -Force | Out-Null
    $OldTemp = $env:TEMP; $OldTmp = $env:TMP
    $env:TEMP = $ProcessTemp; $env:TMP = $ProcessTemp
    Write-Host ('B50 PYTEST BASETEMP=' + $PytestTemp) -ForegroundColor DarkGray

    try {
        & $Py -m compileall -q sentinel\rescue_target_discovery.py tools\v011_beta5_b50_acceptance.py tests\test_v011_beta5_b50_real_world_target_discovery.py
        if ($LASTEXITCODE -ne 0) { Fail 'compileall' 'B5-0 compileall failed' }

        $Tests = @(
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
            'tests/test_v011_beta5_b50_real_world_target_discovery.py'
        )
        & $Py -m pytest -q --basetemp $PytestTemp @Tests
        if ($LASTEXITCODE -ne 0) { Fail 'pytest' 'Beta3 + Beta4 + B5-0 regression failed' }

        foreach ($spec in @(
            @('rr0','tools.v011_beta3_rr0_acceptance','acceptance-v011-beta3-rr0-b50-regression.json'),
            @('rr1','tools.v011_beta3_rr1_acceptance','acceptance-v011-beta3-rr1-b50-regression.json'),
            @('rr2','tools.v011_beta3_rr2_acceptance','acceptance-v011-beta3-rr2-b50-regression.json'),
            @('rr3','tools.v011_beta3_rr3_acceptance','acceptance-v011-beta3-rr3-b50-regression.json'),
            @('rr4a','tools.v011_beta3_rr4a_acceptance','acceptance-v011-beta3-rr4a-b50-regression.json'),
            @('rr4b','tools.v011_beta3_rr4b_acceptance','acceptance-v011-beta3-rr4b-b50-regression.json'),
            @('rr5','tools.v011_beta3_rr5_acceptance','acceptance-v011-beta3-rr5-b50-regression.json'),
            @('rr6','tools.v011_beta3_rr6_acceptance','acceptance-v011-beta3-rr6-b50-regression.json'),
            @('b40','tools.v011_beta4_b40_acceptance','acceptance-v011-beta4-b40-b50-regression.json'),
            @('b41','tools.v011_beta4_b41_acceptance','acceptance-v011-beta4-b41-b50-regression.json'),
            @('b42','tools.v011_beta4_b42_acceptance','acceptance-v011-beta4-b42-b50-regression.json'),
            @('b43','tools.v011_beta4_b43_acceptance','acceptance-v011-beta4-b43-b50-regression.json'),
            @('b44','tools.v011_beta4_b44_acceptance','acceptance-v011-beta4-b44-b50-regression.json'),
            @('b45','tools.v011_beta4_b45_acceptance','acceptance-v011-beta4-b45-b50-regression.json'),
            @('b50','tools.v011_beta5_b50_acceptance','acceptance-v011-beta5-b50.json')
        )) {
            & $Py -m $spec[1] --output $spec[2]
            if ($LASTEXITCODE -ne 0) { Fail ('acceptance-' + $spec[0]) ($spec[0] + ' deterministic acceptance failed') }
        }

        $B50Acceptance = Get-Content -Raw -LiteralPath '.\acceptance-v011-beta5-b50.json' -Encoding UTF8 | ConvertFrom-Json
        if (-not [bool]$B50Acceptance.passed) { Fail 'acceptance-b50' 'B5-0 acceptance JSON did not pass' }
        if ([int]$B50Acceptance.detail.counts.READY -ne 2) { Fail 'acceptance-b50' 'deterministic READY count mismatch' }
        if (-not [bool]$B50Acceptance.checks.locked_refused) { Fail 'acceptance-b50' 'locked candidate was not refused' }
        if (-not [bool]$B50Acceptance.checks.target_byte_identical) { Fail 'acceptance-b50' 'deterministic target changed' }

        $LiveRoot = Join-Path $ProcessTemp 'live-fixture'
        $Volumes = Join-Path $LiveRoot 'volumes'
        $Ready = Join-Path $Volumes 'OfflineWindows'
        $Partial = Join-Path $Volumes 'PartialWindows'
        $DataOnly = Join-Path $Volumes 'DataOnly'
        New-Item -ItemType Directory -Path (Join-Path $Ready 'Windows\System32\config'),(Join-Path $Partial 'Windows\System32\config'),$DataOnly -Force | Out-Null
        [IO.File]::WriteAllBytes((Join-Path $Ready 'Windows\System32\config\SYSTEM'), [Text.Encoding]::UTF8.GetBytes('B50 LIVE SYSTEM'))
        [IO.File]::WriteAllBytes((Join-Path $Ready 'Windows\System32\config\SOFTWARE'), [Text.Encoding]::UTF8.GetBytes('B50 LIVE SOFTWARE'))
        [IO.File]::WriteAllBytes((Join-Path $Ready 'Windows\System32\ntoskrnl.exe'), [Text.Encoding]::UTF8.GetBytes('MZ B50 LIVE KERNEL'))
        [IO.File]::WriteAllBytes((Join-Path $Partial 'Windows\System32\config\SYSTEM'), [Text.Encoding]::UTF8.GetBytes('B50 PARTIAL SYSTEM'))
        [IO.File]::WriteAllText((Join-Path $DataOnly 'notes.txt'),'B50 data only',(New-Object Text.UTF8Encoding($false)))

        $BeforeTarget = @{}
        Get-ChildItem -LiteralPath $Volumes -File -Recurse | ForEach-Object { $BeforeTarget[$_.FullName] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }

        $DiscoveryOut = Join-Path $LiveRoot 'evidence\b50-discovery.json'
        & $Py -m sentinel.rescue_target_discovery $Volumes --no-windows-volumes --max-roots 16 --max-children-per-root 16 --output $DiscoveryOut | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail 'live-fixture-discovery' ('B5-0 CLI returned exit=' + $LASTEXITCODE) }
        if (-not (Test-Path -LiteralPath $DiscoveryOut)) { Fail 'live-fixture-discovery' 'discovery output missing' }
        $Discovery = Get-Content -Raw -LiteralPath $DiscoveryOut -Encoding UTF8 | ConvertFrom-Json
        $ReadyRec = @($Discovery.candidates | Where-Object { [IO.Path]::GetFileName([string]$_.normalized_root) -eq 'OfflineWindows' })
        $PartialRec = @($Discovery.candidates | Where-Object { [IO.Path]::GetFileName([string]$_.normalized_root) -eq 'PartialWindows' })
        $DataRec = @($Discovery.candidates | Where-Object { [IO.Path]::GetFileName([string]$_.normalized_root) -eq 'DataOnly' })
        if ($ReadyRec.Count -ne 1 -or [string]$ReadyRec[0].state -ne 'READY') { Fail 'live-fixture-discovery' 'OfflineWindows not READY' }
        if ($PartialRec.Count -ne 1 -or [string]$PartialRec[0].state -ne 'INCOMPLETE') { Fail 'live-fixture-discovery' 'PartialWindows not INCOMPLETE' }
        if ($DataRec.Count -ne 1 -or [string]$DataRec[0].state -ne 'UNSUPPORTED') { Fail 'live-fixture-discovery' 'DataOnly not UNSUPPORTED' }
        if ([string]$ReadyRec[0].target_fingerprint -notmatch '^[0-9a-f]{64}$') { Fail 'live-fixture-discovery' 'READY target fingerprint invalid' }

        foreach ($p in $BeforeTarget.Keys) {
            $after = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($after -ne $BeforeTarget[$p]) { Fail 'target-integrity' ('B5-0 modified target: ' + $p) }
        }

        $SystemDriveCheck = @(& $Py -c "import json,os; from pathlib import Path; from sentinel import rescue_target_discovery as d; r=d.classify_candidate(Path(os.environ['SystemDrive']+'\\'),discovery_source='live_system_drive'); print(json.dumps(r.to_record()))")
        if ($LASTEXITCODE -ne 0 -or $SystemDriveCheck.Count -lt 1) { Fail 'live-system-drive' 'could not classify live SystemDrive' }
        $SystemDriveRecord = ($SystemDriveCheck[-1] | ConvertFrom-Json)
        if ([string]$SystemDriveRecord.state -ne 'UNSUPPORTED') { Fail 'live-system-drive' ('live SystemDrive state=' + [string]$SystemDriveRecord.state) }
        if ([string]$SystemDriveRecord.reason -ne 'live_system_volume_refused') { Fail 'live-system-drive' ('live SystemDrive reason=' + [string]$SystemDriveRecord.reason) }
        if ([bool]$SystemDriveRecord.write_attempted) { Fail 'live-system-drive' 'write attempted on live SystemDrive' }

        $VolumeProbe = @(& $Py -c "import json; from sentinel import rescue_target_discovery as d; v=d.enumerate_windows_volume_roots(max_roots=32); print(json.dumps({'count':len(v),'roots':[str(x) for x in v]}))")
        if ($LASTEXITCODE -ne 0 -or $VolumeProbe.Count -lt 1) { Fail 'live-volume-enumeration' 'Windows volume enumeration failed' }
        $VolumeInfo = ($VolumeProbe[-1] | ConvertFrom-Json)
        if ([int]$VolumeInfo.count -gt 32) { Fail 'live-volume-enumeration' 'volume enumeration exceeded bound' }

        $Services = @(Get-CimInstance Win32_Service | Where-Object { ([string]$_.PathName).ToLowerInvariant().Contains('rescue_target_discovery') -or ([string]$_.PathName).ToLowerInvariant().Contains('b50') })
        if ($Services.Count -ne 0) { Fail 'live-safety' 'B5-0 unexpectedly registered a Windows service' }

        foreach ($path in $Protected) {
            $after = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($after -ne $BeforeProtected[$path]) { Fail 'protected-source' ('B5-0 modified protected B2 source: ' + $path) }
        }

        Write-Host ('B50 LIVE READY TARGET=' + [string]$ReadyRec[0].normalized_root) -ForegroundColor Green
        Write-Host ('B50 LIVE TARGET FINGERPRINT=' + [string]$ReadyRec[0].target_fingerprint) -ForegroundColor Green
        Write-Host ('B50 LIVE DISCOVERY SESSION=' + [string]$Discovery.session_id + ' CORRELATION=' + [string]$Discovery.correlation_id) -ForegroundColor Green
        Write-Host ('B50 LIVE WINDOWS VOLUMES OBSERVED=' + [string]$VolumeInfo.count) -ForegroundColor Green
        Write-Host ('B50 LIVE SYSTEMDRIVE=' + [string]$SystemDriveRecord.normalized_root + ' STATE=' + [string]$SystemDriveRecord.state + ' REASON=' + [string]$SystemDriveRecord.reason) -ForegroundColor Green
        Write-Host 'B50 LIVE: multi-volume fixture PASS | READY/INCOMPLETE/UNSUPPORTED PASS | live SystemDrive refusal PASS | bounded Windows volume enumeration PASS | target unchanged | no unlock/mount/write | no service | B2 sources unchanged' -ForegroundColor Green
        Write-Host 'BC SENTINEL v0.11.0-beta.5 B5-0 REAL-WORLD TARGET DISCOVERY - PASS' -ForegroundColor Green
        exit 0
    }
    finally {
        $env:TEMP = $OldTemp; $env:TMP = $OldTmp
        Remove-Item -LiteralPath $PytestTemp -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $ProcessTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
catch {
    Fail 'unhandled' $_.Exception.Message
}
