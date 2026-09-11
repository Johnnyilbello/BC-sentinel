param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Stage,[string]$Message) {
    Write-Host ('B43 FAIL STAGE=' + $Stage + ' | ' + $Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.4 B4-3 GUIDED SAFE DATA RESCUE - FAIL' -ForegroundColor Red
    exit 1
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Fail 'preflight' 'Run B4-3 from normal non-elevated PowerShell.' }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { Fail 'preflight' '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.4 - B4-3 GUIDED SAFE DATA RESCUE' -ForegroundColor Cyan
    Write-Host 'Explicit selection only. Active/ambiguous/IOC content stays contained; source remains read-only.' -ForegroundColor Yellow

    $Protected = @('.\sentinel\protection_service_core.py','.\sentinel\realtime.py','.\sentinel\edr.py','.\sentinel\edr_service_bridge.py')
    $BeforeProtected = @{}
    foreach ($path in $Protected) {
        if (-not (Test-Path -LiteralPath $path)) { Fail 'preflight' ('protected source missing: ' + $path) }
        $BeforeProtected[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    $Base = Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    New-Item -ItemType Directory -Path $Base -Force | Out-Null
    $ProcessTemp = Join-Path $Base ('b43-process-' + [guid]::NewGuid().ToString('N'))
    $PytestTemp = Join-Path $Base ('b43-pytest-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $ProcessTemp -Force | Out-Null
    $OldTemp = $env:TEMP; $OldTmp = $env:TMP
    $env:TEMP = $ProcessTemp; $env:TMP = $ProcessTemp
    Write-Host ('B43 PYTEST BASETEMP=' + $PytestTemp) -ForegroundColor DarkGray

    try {
        & $Py -m compileall -q sentinel\rescue_console_guided_data_rescue.py tools\v011_beta4_b43_acceptance.py tests\test_v011_beta4_b43_guided_safe_data_rescue.py
        if ($LASTEXITCODE -ne 0) { Fail 'compileall' 'B4-3 compileall failed' }

        $Tests = @(
            'tests/test_v011_beta3_rr0_rescue_contract.py','tests/test_v011_beta3_rr1_portable.py','tests/test_v011_beta3_rr2_rescue_usb.py','tests/test_v011_beta3_rr3_offline_scanner.py','tests/test_v011_beta3_rr4a_repair_engine.py','tests/test_v011_beta3_rr4b_portable_repair.py','tests/test_v011_beta3_rr5_safe_data_rescue.py','tests/test_v011_beta3_rr6_integrity_certification.py',
            'tests/test_v011_beta4_b40_rescue_console.py','tests/test_v011_beta4_b41_evidence_inventory_guided_scan.py','tests/test_v011_beta4_b42_guided_repair_handoff.py','tests/test_v011_beta4_b43_guided_safe_data_rescue.py'
        )
        & $Py -m pytest -q --basetemp $PytestTemp @Tests
        if ($LASTEXITCODE -ne 0) { Fail 'pytest' 'Beta3 + B4-0..B4-3 regression failed' }

        foreach ($spec in @(
            @('rr0','tools.v011_beta3_rr0_acceptance','acceptance-v011-beta3-rr0-b43-regression.json'),
            @('rr1','tools.v011_beta3_rr1_acceptance','acceptance-v011-beta3-rr1-b43-regression.json'),
            @('rr2','tools.v011_beta3_rr2_acceptance','acceptance-v011-beta3-rr2-b43-regression.json'),
            @('rr3','tools.v011_beta3_rr3_acceptance','acceptance-v011-beta3-rr3-b43-regression.json'),
            @('rr4a','tools.v011_beta3_rr4a_acceptance','acceptance-v011-beta3-rr4a-b43-regression.json'),
            @('rr4b','tools.v011_beta3_rr4b_acceptance','acceptance-v011-beta3-rr4b-b43-regression.json'),
            @('rr5','tools.v011_beta3_rr5_acceptance','acceptance-v011-beta3-rr5-b43-regression.json'),
            @('rr6','tools.v011_beta3_rr6_acceptance','acceptance-v011-beta3-rr6-b43-regression.json'),
            @('b40','tools.v011_beta4_b40_acceptance','acceptance-v011-beta4-b40-b43-regression.json'),
            @('b41','tools.v011_beta4_b41_acceptance','acceptance-v011-beta4-b41-b43-regression.json'),
            @('b42','tools.v011_beta4_b42_acceptance','acceptance-v011-beta4-b42-b43-regression.json'),
            @('b43','tools.v011_beta4_b43_acceptance','acceptance-v011-beta4-b43.json')
        )) {
            & $Py -m $spec[1] --output $spec[2]
            if ($LASTEXITCODE -ne 0) { Fail ('acceptance-' + $spec[0]) ($spec[0] + ' deterministic acceptance failed') }
        }

        $RunRoot = Join-Path $Base ('b43-live-' + [guid]::NewGuid().ToString('N'))
        $Offline = Join-Path $RunRoot 'offline-target'
        $Workspace = Join-Path $RunRoot 'workspace'
        $Destination = Join-Path $RunRoot 'rescued-output'
        New-Item -ItemType Directory -Path (Join-Path $Offline 'Windows\System32\config'),(Join-Path $Offline 'Users\Alice\Documents'),(Join-Path $Offline 'Users\Alice\AppData\Local\Temp'),$Workspace -Force | Out-Null
        [IO.File]::WriteAllBytes((Join-Path $Offline 'Windows\System32\config\SYSTEM'), [Text.Encoding]::UTF8.GetBytes('B43 LIVE SYSTEM'))
        [IO.File]::WriteAllBytes((Join-Path $Offline 'Windows\System32\config\SOFTWARE'), [Text.Encoding]::UTF8.GetBytes('B43 LIVE SOFTWARE'))
        [IO.File]::WriteAllBytes((Join-Path $Offline 'Windows\System32\ntoskrnl.exe'), [Text.Encoding]::UTF8.GetBytes('MZ B43 LIVE KERNEL'))
        [IO.File]::WriteAllText((Join-Path $Offline 'Users\Alice\Documents\notes.txt'),'B43 SAFE NOTES',(New-Object Text.UTF8Encoding($false)))
        $Bad = Join-Path $Offline 'Users\Alice\AppData\Local\Temp\bad.exe'
        [IO.File]::WriteAllBytes($Bad, [Text.Encoding]::UTF8.GetBytes('MZ B43 LIVE IOC'))
        $BadHash = (Get-FileHash -LiteralPath $Bad -Algorithm SHA256).Hash.ToLowerInvariant()
        $Intel = Join-Path $RunRoot 'intel.json'
        $IntelPayload = [ordered]@{schema='bc-sentinel-offline-intel-v1';approved=$true;sha256=@([ordered]@{value=$BadHash;name='B43.Live.IOC'})}
        [IO.File]::WriteAllText($Intel,($IntelPayload | ConvertTo-Json -Depth 5) + [Environment]::NewLine,(New-Object Text.UTF8Encoding($false)))

        $BeforeTarget = @{}
        Get-ChildItem -LiteralPath $Offline -File -Recurse | ForEach-Object { $BeforeTarget[$_.FullName] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }

        & $Py -m sentinel.rescue_console --target-root $Offline --workspace $Workspace --output-plan (Join-Path $Workspace 'session-plan.json') | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail 'live-b40' 'B4-0 session plan failed' }
        & $Py -m sentinel.rescue_console_guided_scan --target-root $Offline --workspace $Workspace --run-scan --intel-catalog $Intel | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail 'live-b41' 'B4-1 trusted scan failed' }
        $Scan = Join-Path $Workspace 'rr3\rr3-offline-scan.json'

        & $Py -m sentinel.rescue_console_guided_data_rescue --target-root $Offline --workspace $Workspace --scan $Scan --destination $Destination --include 'Users/Alice' | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail 'live-preview' 'B4-3 preview failed' }
        if (Test-Path -LiteralPath $Destination) { Fail 'live-preview' 'preview unexpectedly created rescue destination' }

        & $Py -m sentinel.rescue_console_guided_data_rescue --target-root $Offline --workspace $Workspace --scan $Scan --destination $Destination --include 'Users/Alice' --execute-rescue | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail 'live-execute' 'B4-3 explicit rescue failed' }
        $SummaryPath = Join-Path $Workspace 'b43-guided-data-rescue-summary.json'
        $Summary = Get-Content -Raw -LiteralPath $SummaryPath -Encoding UTF8 | ConvertFrom-Json
        if (-not [bool]$Summary.execution_requested) { Fail 'live-execute' 'execution flag not recorded' }
        if (-not (Test-Path -LiteralPath (Join-Path $Destination 'rescued-data\Users\Alice\Documents\notes.txt'))) { Fail 'live-execute' 'passive document missing from clean rescue tree' }
        if (-not (Test-Path -LiteralPath (Join-Path $Destination 'containment\Users\Alice\AppData\Local\Temp\bad.exe'))) { Fail 'live-execute' 'IOC executable missing from containment' }
        if (Test-Path -LiteralPath (Join-Path $Destination 'rescued-data\Users\Alice\AppData\Local\Temp\bad.exe')) { Fail 'live-safety' 'IOC executable entered clean rescue tree' }
        if ([string]$Summary.manifest_sha256 -notmatch '^[0-9a-f]{64}$') { Fail 'live-execute' 'manifest SHA256 missing/invalid' }

        foreach ($p in $BeforeTarget.Keys) {
            $after = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
            if ($after -ne $BeforeTarget[$p]) { Fail 'target-integrity' ('B4-3 modified source target: ' + $p) }
        }
        $Services = @(Get-CimInstance Win32_Service | Where-Object { ([string]$_.PathName).ToLowerInvariant().Contains('bc-sentinel-rescue-console') })
        if ($Services.Count -ne 0) { Fail 'live-safety' 'B4-3 unexpectedly registered a Windows service' }
        foreach ($path in $Protected) {
            $after = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($after -ne $BeforeProtected[$path]) { Fail 'protected-source' ('B4-3 modified protected B2 source: ' + $path) }
        }

        Write-Host ('B43 LIVE TARGET FINGERPRINT=' + [string]$Summary.target_fingerprint) -ForegroundColor Green
        Write-Host ('B43 LIVE SESSION=' + [string]$Summary.session_id + ' CORRELATION=' + [string]$Summary.correlation_id) -ForegroundColor Green
        Write-Host ('B43 LIVE RR3 SCAN SHA256=' + [string]$Summary.trusted_scan_sha256) -ForegroundColor Green
        Write-Host ('B43 LIVE RR5 MANIFEST SHA256=' + [string]$Summary.manifest_sha256) -ForegroundColor Green
        Write-Host 'B43 LIVE: preview no-copy PASS | explicit selection PASS | passive clean rescue PASS | IOC containment PASS | manifest verification PASS | source unchanged | no service | B2 sources unchanged' -ForegroundColor Green
        Write-Host 'BC SENTINEL v0.11.0-beta.4 B4-3 GUIDED SAFE DATA RESCUE - PASS' -ForegroundColor Green
        exit 0
    }
    finally {
        $env:TEMP = $OldTemp; $env:TMP = $OldTmp
        Remove-Item -LiteralPath $PytestTemp -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $ProcessTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
catch { Fail 'unhandled' $_.Exception.Message }
