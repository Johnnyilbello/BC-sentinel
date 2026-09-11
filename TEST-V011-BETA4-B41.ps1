param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Stage,[string]$Message) {
    Write-Host ('B41 FAIL STAGE=' + $Stage + ' | ' + $Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.4 B4-1 EVIDENCE INVENTORY + GUIDED SCAN - FAIL' -ForegroundColor Red
    exit 1
}

function Read-Json([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    return (Get-Content -Raw -LiteralPath $Path -Encoding UTF8 | ConvertFrom-Json)
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Fail 'preflight' 'Run B4-1 from normal non-elevated PowerShell.' }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { Fail 'preflight' '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.4 - B4-1 EVIDENCE INVENTORY + GUIDED SCAN' -ForegroundColor Cyan
    Write-Host 'RR3 scan is read-only and explicit. Scan findings never auto-trigger repair or quarantine.' -ForegroundColor Yellow

    $Protected = @('.\sentinel\protection_service_core.py','.\sentinel\realtime.py','.\sentinel\edr.py','.\sentinel\edr_service_bridge.py')
    $BeforeProtected = @{}
    foreach ($path in $Protected) {
        if (-not (Test-Path -LiteralPath $path)) { Fail 'preflight' ('protected source missing: ' + $path) }
        $BeforeProtected[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    $Base = Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    New-Item -ItemType Directory -Path $Base -Force | Out-Null
    $ProcessTemp = Join-Path $Base ('b41-process-' + [guid]::NewGuid().ToString('N'))
    $PytestTemp = Join-Path $Base ('b41-pytest-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $ProcessTemp -Force | Out-Null
    $OldTemp = $env:TEMP; $OldTmp = $env:TMP
    $env:TEMP = $ProcessTemp; $env:TMP = $ProcessTemp
    Write-Host ('B41 PYTEST BASETEMP=' + $PytestTemp) -ForegroundColor DarkGray

    try {
        & $Py -m compileall -q sentinel\rescue_console.py sentinel\rescue_console_guided_scan.py tools\v011_beta4_b40_acceptance.py tools\v011_beta4_b41_acceptance.py tests\test_v011_beta4_b40_rescue_console.py tests\test_v011_beta4_b41_evidence_inventory_guided_scan.py
        if ($LASTEXITCODE -ne 0) { Fail 'compileall' 'B4-1 compileall failed' }

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
            'tests/test_v011_beta4_b41_evidence_inventory_guided_scan.py'
        )
        & $Py -m pytest -q --basetemp $PytestTemp @Tests
        if ($LASTEXITCODE -ne 0) { Fail 'pytest' 'Beta3 + B4-0 + B4-1 regression failed' }

        foreach ($spec in @(
            @('rr0','tools.v011_beta3_rr0_acceptance','acceptance-v011-beta3-rr0-b41-regression.json'),
            @('rr1','tools.v011_beta3_rr1_acceptance','acceptance-v011-beta3-rr1-b41-regression.json'),
            @('rr2','tools.v011_beta3_rr2_acceptance','acceptance-v011-beta3-rr2-b41-regression.json'),
            @('rr3','tools.v011_beta3_rr3_acceptance','acceptance-v011-beta3-rr3-b41-regression.json'),
            @('rr4a','tools.v011_beta3_rr4a_acceptance','acceptance-v011-beta3-rr4a-b41-regression.json'),
            @('rr4b','tools.v011_beta3_rr4b_acceptance','acceptance-v011-beta3-rr4b-b41-regression.json'),
            @('rr5','tools.v011_beta3_rr5_acceptance','acceptance-v011-beta3-rr5-b41-regression.json'),
            @('rr6','tools.v011_beta3_rr6_acceptance','acceptance-v011-beta3-rr6-b41-regression.json'),
            @('b40','tools.v011_beta4_b40_acceptance','acceptance-v011-beta4-b40-b41-regression.json'),
            @('b41','tools.v011_beta4_b41_acceptance','acceptance-v011-beta4-b41.json')
        )) {
            & $Py -m $spec[1] --output $spec[2]
            if ($LASTEXITCODE -ne 0) { Fail ('acceptance-' + $spec[0]) ($spec[0] + ' deterministic acceptance failed') }
        }

        $RunRoot = Join-Path $Base ('b41-live-' + [guid]::NewGuid().ToString('N'))
        $Offline = Join-Path $RunRoot 'offline-target'
        $Workspace = Join-Path $RunRoot 'workspace'
        New-Item -ItemType Directory -Path (Join-Path $Offline 'Windows\System32\config') -Force | Out-Null
        [IO.File]::WriteAllBytes((Join-Path $Offline 'Windows\System32\config\SYSTEM'), [Text.Encoding]::UTF8.GetBytes('B41 LIVE SYSTEM'))
        [IO.File]::WriteAllBytes((Join-Path $Offline 'Windows\System32\config\SOFTWARE'), [Text.Encoding]::UTF8.GetBytes('B41 LIVE SOFTWARE'))
        [IO.File]::WriteAllBytes((Join-Path $Offline 'Windows\System32\ntoskrnl.exe'), [Text.Encoding]::UTF8.GetBytes('MZ B41 LIVE KERNEL'))
        $IocFile = Join-Path $Offline 'Windows\System32\b41-live-ioc.exe'
        [IO.File]::WriteAllBytes($IocFile, [Text.Encoding]::UTF8.GetBytes('MZ harmless B41 LIVE IOC fixture'))

        $BeforeTarget = @{}
        Get-ChildItem -LiteralPath $Offline -File -Recurse | ForEach-Object { $BeforeTarget[$_.FullName] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }

        $PlanPath = Join-Path $Workspace 'session-plan.json'
        & $Py -m sentinel.rescue_console --target-root $Offline --workspace $Workspace --output-plan $PlanPath
        if ($LASTEXITCODE -ne 0) { Fail 'live-plan' 'B4-0 plan prerequisite failed' }

        $IocHash = (Get-FileHash -LiteralPath $IocFile -Algorithm SHA256).Hash.ToLowerInvariant()
        $Catalog = Join-Path $RunRoot 'approved-ioc.json'
        $CatalogObject = [ordered]@{
            schema = 'bc-sentinel-offline-intel-v1'
            approved = $true
            sha256 = @([ordered]@{ value = $IocHash; name = 'B41.Live.IOC'; source = 'synthetic-windows-gate' })
        }
        [IO.File]::WriteAllText($Catalog, (($CatalogObject | ConvertTo-Json -Depth 8) + [Environment]::NewLine), (New-Object Text.UTF8Encoding($false)))

        & $Py -m sentinel.rescue_console_guided_scan --target-root $Offline --workspace $Workspace --run-scan --intel-catalog $Catalog --max-files 64 --max-file-bytes 1048576
        $FreshExit = $LASTEXITCODE
        if ($FreshExit -ne 0) { Fail 'live-fresh-scan' ('guided fresh scan exit_code=' + $FreshExit) }

        $SummaryPath = Join-Path $Workspace 'b41-guided-scan-summary.json'
        $InventoryPath = Join-Path $Workspace 'b41-evidence-inventory.json'
        $ScanPath = Join-Path $Workspace 'rr3\rr3-offline-scan.json'
        $AuditPath = Join-Path $Workspace 'b41-audit.jsonl'
        $Summary = Read-Json $SummaryPath
        $Inventory = Read-Json $InventoryPath
        if ($null -eq $Summary -or $null -eq $Inventory) { Fail 'live-fresh-scan' 'summary or inventory missing' }
        if ([string]$Summary.profile -ne 'v0.11.0-beta.4-b41') { Fail 'live-fresh-scan' 'unexpected B4-1 profile' }
        if ([string]$Summary.scan.source -ne 'fresh_operator_requested') { Fail 'live-fresh-scan' 'fresh scan source mismatch' }
        if (-not [bool]$Summary.scan.available) { Fail 'live-fresh-scan' 'fresh scan not available' }
        if ([int]$Summary.scan.summary.ioc_hits -ne 1) { Fail 'live-fresh-scan' ('expected one IOC hit, got ' + [string]$Summary.scan.summary.ioc_hits) }
        if ([bool]$Summary.repair_triggered -or [bool]$Summary.quarantine_triggered -or [bool]$Summary.automatic_execution) { Fail 'live-safety' 'scan result triggered forbidden automatic action' }
        if (-not (Test-Path -LiteralPath $ScanPath)) { Fail 'live-fresh-scan' 'RR3 scan evidence missing' }
        if (-not (Test-Path -LiteralPath $AuditPath)) { Fail 'live-audit' 'B4-1 audit missing' }

        $PostInventoryDir = Join-Path $RunRoot 'inventory-post'
        & $Py -c "from pathlib import Path; from sentinel import rescue_console_guided_scan as b; import json; x=b.inventory_evidence(Path(r'$Offline'),Path(r'$Workspace'),Path(r'$ScanPath')); Path(r'$PostInventoryDir').mkdir(parents=True,exist_ok=True); Path(r'$PostInventoryDir\inventory.json').write_text(json.dumps(x,indent=2),encoding='utf-8')"
        if ($LASTEXITCODE -ne 0) { Fail 'live-inventory' 'post-scan inventory failed' }
        $PostInventory = Read-Json (Join-Path $PostInventoryDir 'inventory.json')
        if (-not [bool]$PostInventory.trusted_rr3_scan_available) { Fail 'live-inventory' 'fresh RR3 evidence was not trusted for reuse' }

        $ReuseWorkspace = Join-Path $RunRoot 'reuse-workspace'
        & $Py -m sentinel.rescue_console_guided_scan --target-root $Offline --workspace $ReuseWorkspace --existing-scan $ScanPath --reuse-trusted-scan
        $ReuseExit = $LASTEXITCODE
        if ($ReuseExit -ne 0) { Fail 'live-reuse' ('trusted reuse exit_code=' + $ReuseExit) }
        $ReuseSummary = Read-Json (Join-Path $ReuseWorkspace 'b41-guided-scan-summary.json')
        if ([string]$ReuseSummary.scan.source -ne 'reused_trusted_existing') { Fail 'live-reuse' 'trusted scan was not reused' }
        if ([string]$ReuseSummary.operator_action_required -ne 'none') { Fail 'live-reuse' 'trusted reuse unexpectedly requires fresh scan' }

        $TamperedScan = Join-Path $RunRoot 'tampered-scan.json'
        Copy-Item -LiteralPath $ScanPath -Destination $TamperedScan -Force
        $TamperedObject = Read-Json $TamperedScan
        $TamperedObject.summary.errors = 1
        [IO.File]::WriteAllText($TamperedScan, (($TamperedObject | ConvertTo-Json -Depth 100) + [Environment]::NewLine), (New-Object Text.UTF8Encoding($false)))
        $RefusedWorkspace = Join-Path $RunRoot 'refused-workspace'
        & $Py -m sentinel.rescue_console_guided_scan --target-root $Offline --workspace $RefusedWorkspace --existing-scan $TamperedScan --reuse-trusted-scan
        $RefusedExit = $LASTEXITCODE
        if ($RefusedExit -ne 0) { Fail 'live-untrusted' ('untrusted evidence handling exit_code=' + $RefusedExit) }
        $RefusedSummary = Read-Json (Join-Path $RefusedWorkspace 'b41-guided-scan-summary.json')
        if ([bool]$RefusedSummary.scan.available) { Fail 'live-untrusted' 'tampered scan was incorrectly accepted' }
        if ([string]$RefusedSummary.operator_action_required -ne 'run_fresh_scan') { Fail 'live-untrusted' 'tampered scan did not require fresh scan' }

        foreach ($p in $BeforeTarget.Keys) {
            $after = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
            if ($after -ne $BeforeTarget[$p]) { Fail 'target-integrity' ('B4-1 modified target: ' + $p) }
        }

        $Services = @(Get-CimInstance Win32_Service | Where-Object { ([string]$_.PathName).ToLowerInvariant().Contains('bc-sentinel-rescue-console') })
        if ($Services.Count -ne 0) { Fail 'live-safety' 'B4-1 unexpectedly registered a Windows service' }

        foreach ($path in $Protected) {
            $after = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($after -ne $BeforeProtected[$path]) { Fail 'protected-source' ('B4-1 modified protected B2 source: ' + $path) }
        }

        $ScanHash = (Get-FileHash -LiteralPath $ScanPath -Algorithm SHA256).Hash.ToLowerInvariant()
        Write-Host ('B41 LIVE TARGET FINGERPRINT=' + [string]$Summary.target_fingerprint) -ForegroundColor Green
        Write-Host ('B41 LIVE SESSION=' + [string]$Summary.session_id + ' CORRELATION=' + [string]$Summary.correlation_id) -ForegroundColor Green
        Write-Host ('B41 LIVE RR3 SCAN SHA256=' + $ScanHash) -ForegroundColor Green
        Write-Host 'B41 LIVE: evidence inventory PASS | fresh RR3 scan PASS | IOC observed without action PASS | trusted reuse PASS | tampered evidence refused PASS | target unchanged | no service | B2 sources unchanged' -ForegroundColor Green
        Write-Host 'BC SENTINEL v0.11.0-beta.4 B4-1 EVIDENCE INVENTORY + GUIDED SCAN - PASS' -ForegroundColor Green
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
