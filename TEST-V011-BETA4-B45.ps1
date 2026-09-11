param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Stage,[string]$Message) {
    Write-Host ('B45 FAIL STAGE=' + $Stage + ' | ' + $Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.4 B4-5 PORTABLE RESCUE CONSOLE - FAIL' -ForegroundColor Red
    exit 1
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Fail 'preflight' 'Run B4-5 from normal non-elevated PowerShell.' }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { Fail 'preflight' '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.4 - B4-5 PORTABLE RESCUE CONSOLE' -ForegroundColor Cyan
    Write-Host 'Built artifact must preserve B4-0..B4-4 trust boundaries and expose no automatic repair path.' -ForegroundColor Yellow

    $Protected = @('.\sentinel\protection_service_core.py','.\sentinel\realtime.py','.\sentinel\edr.py','.\sentinel\edr_service_bridge.py')
    $BeforeProtected = @{}
    foreach ($path in $Protected) {
        if (-not (Test-Path -LiteralPath $path)) { Fail 'preflight' ('protected source missing: ' + $path) }
        $BeforeProtected[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    $Base = Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    New-Item -ItemType Directory -Path $Base -Force | Out-Null
    $ProcessTemp = Join-Path $Base ('b45-process-' + [guid]::NewGuid().ToString('N'))
    $PytestTemp = Join-Path $Base ('b45-pytest-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $ProcessTemp -Force | Out-Null
    $OldTemp = $env:TEMP; $OldTmp = $env:TMP
    $env:TEMP = $ProcessTemp; $env:TMP = $ProcessTemp
    Write-Host ('B45 PYTEST BASETEMP=' + $PytestTemp) -ForegroundColor DarkGray

    try {
        & $Py -m compileall -q sentinel\rescue_console_portable.py packaging\rescue_console_portable_entry.py tools\v011_beta4_b45_acceptance.py tests\test_v011_beta4_b45_portable_rescue_console.py
        if ($LASTEXITCODE -ne 0) { Fail 'compileall' 'B4-5 compileall failed' }

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
            'tests/test_v011_beta4_b45_portable_rescue_console.py'
        )
        & $Py -m pytest -q --basetemp $PytestTemp @Tests
        if ($LASTEXITCODE -ne 0) { Fail 'pytest' 'Beta3 + B4-0..B4-5 regression failed' }

        foreach ($spec in @(
            @('rr0','tools.v011_beta3_rr0_acceptance','acceptance-v011-beta3-rr0-b45-regression.json'),
            @('rr1','tools.v011_beta3_rr1_acceptance','acceptance-v011-beta3-rr1-b45-regression.json'),
            @('rr2','tools.v011_beta3_rr2_acceptance','acceptance-v011-beta3-rr2-b45-regression.json'),
            @('rr3','tools.v011_beta3_rr3_acceptance','acceptance-v011-beta3-rr3-b45-regression.json'),
            @('rr4a','tools.v011_beta3_rr4a_acceptance','acceptance-v011-beta3-rr4a-b45-regression.json'),
            @('rr4b','tools.v011_beta3_rr4b_acceptance','acceptance-v011-beta3-rr4b-b45-regression.json'),
            @('rr5','tools.v011_beta3_rr5_acceptance','acceptance-v011-beta3-rr5-b45-regression.json'),
            @('rr6','tools.v011_beta3_rr6_acceptance','acceptance-v011-beta3-rr6-b45-regression.json'),
            @('b40','tools.v011_beta4_b40_acceptance','acceptance-v011-beta4-b40-b45-regression.json'),
            @('b41','tools.v011_beta4_b41_acceptance','acceptance-v011-beta4-b41-b45-regression.json'),
            @('b42','tools.v011_beta4_b42_acceptance','acceptance-v011-beta4-b42-b45-regression.json'),
            @('b43','tools.v011_beta4_b43_acceptance','acceptance-v011-beta4-b43-b45-regression.json'),
            @('b44','tools.v011_beta4_b44_acceptance','acceptance-v011-beta4-b44-b45-regression.json'),
            @('b45','tools.v011_beta4_b45_acceptance','acceptance-v011-beta4-b45.json')
        )) {
            & $Py -m $spec[1] --output $spec[2]
            if ($LASTEXITCODE -ne 0) { Fail ('acceptance-' + $spec[0]) ($spec[0] + ' deterministic acceptance failed') }
        }

        $B45Acceptance = Get-Content -Raw -LiteralPath '.\acceptance-v011-beta4-b45.json' -Encoding UTF8 | ConvertFrom-Json
        if (-not [bool]$B45Acceptance.passed) { Fail 'acceptance-b45' 'B4-5 deterministic acceptance JSON did not pass' }
        if (-not [bool]$B45Acceptance.checks.repair_execute_refused) { Fail 'acceptance-b45' 'repair-execute refusal missing' }
        if ([bool]$B45Acceptance.new_mutation_authority_added) { Fail 'acceptance-b45' 'new mutation authority unexpectedly added' }

        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\BUILD-RESCUE-CONSOLE-PORTABLE.ps1'
        if ($LASTEXITCODE -ne 0) { Fail 'build' 'B4-5 portable console build failed' }

        $Folder = Join-Path $PSScriptRoot 'dist\Rescue\BC-Sentinel-Rescue-Console-Portable'
        $Exe = Join-Path $Folder 'BC-Sentinel-Rescue-Console-Portable.exe'
        $Integrity = Join-Path $Folder 'rescue-console-integrity.json'
        if (-not (Test-Path -LiteralPath $Exe)) { Fail 'build-integrity' 'portable console EXE missing' }
        if (-not (Test-Path -LiteralPath $Integrity)) { Fail 'build-integrity' 'build integrity manifest missing' }
        $BuildManifest = Get-Content -Raw -LiteralPath $Integrity -Encoding UTF8 | ConvertFrom-Json
        $ExeHash = (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLowerInvariant()
        if ([string]$BuildManifest.sha256 -ne $ExeHash) { Fail 'build-integrity' 'manifest SHA256 does not match built EXE' }
        if ([string]$BuildManifest.profile -ne 'v0.11.0-beta.4-b45') { Fail 'build-integrity' 'unexpected build profile' }
        if ([bool]$BuildManifest.installer_required -or [bool]$BuildManifest.service_install -or [bool]$BuildManifest.driver_install) { Fail 'build-integrity' 'portable artifact unexpectedly requires install/service/driver' }
        if ([bool]$BuildManifest.repair_execution_exposed_by_console) { Fail 'build-integrity' 'portable console unexpectedly exposes repair execution' }

        $StatusRaw = @(& $Exe status)
        if ($LASTEXITCODE -ne 0) { Fail 'built-status' ('built status exit=' + $LASTEXITCODE) }
        $Status = ($StatusRaw -join [Environment]::NewLine) | ConvertFrom-Json
        if (-not [bool]$Status.passed -or [string]$Status.profile -ne 'v0.11.0-beta.4-b45') { Fail 'built-status' 'built status contract invalid' }
        if ([bool]$Status.safety.repair_execution_exposed_by_console) { Fail 'built-status' 'built status exposes repair execution' }
        if (($Status.commands -join '|') -ne 'plan|scan|repair-handoff|data-rescue|certify') { Fail 'built-status' 'built command surface mismatch' }

        $RefusedRaw = @(& $Exe repair-execute)
        $RefusedExit = $LASTEXITCODE
        if ($RefusedExit -ne 2) { Fail 'built-refusal' ('repair-execute expected exit=2 actual=' + $RefusedExit) }
        $Refused = ($RefusedRaw -join [Environment]::NewLine) | ConvertFrom-Json
        if ([string]$Refused.reason -ne 'unknown_command:repair-execute') { Fail 'built-refusal' 'repair-execute refusal reason mismatch' }

        foreach ($HelpCommand in @('scan','repair-handoff','data-rescue','certify')) {
            & $Exe $HelpCommand --help | Out-Null
            if ($LASTEXITCODE -ne 0) { Fail 'built-help' ($HelpCommand + ' subcommand did not load from built artifact') }
        }

        $RunRoot = Join-Path $Base ('b45-live-' + [guid]::NewGuid().ToString('N'))
        $Offline = Join-Path $RunRoot 'offline-target'
        $Workspace = Join-Path $RunRoot 'workspace'
        $Evidence = Join-Path $RunRoot 'evidence'
        $Config = Join-Path $Offline 'Windows\System32\config'
        New-Item -ItemType Directory -Path $Config,$Workspace,$Evidence -Force | Out-Null
        [IO.File]::WriteAllBytes((Join-Path $Config 'SYSTEM'), [Text.Encoding]::UTF8.GetBytes('B45 LIVE SYSTEM'))
        [IO.File]::WriteAllBytes((Join-Path $Config 'SOFTWARE'), [Text.Encoding]::UTF8.GetBytes('B45 LIVE SOFTWARE'))
        [IO.File]::WriteAllBytes((Join-Path $Offline 'Windows\System32\ntoskrnl.exe'), [Text.Encoding]::UTF8.GetBytes('MZ B45 LIVE KERNEL'))
        $BeforeTarget = @{}
        Get-ChildItem -LiteralPath $Offline -File -Recurse | ForEach-Object { $BeforeTarget[$_.FullName] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }

        $PlanPath = Join-Path $Workspace 'session-plan.json'
        & $Exe plan --target-root $Offline --workspace $Workspace --output-plan $PlanPath | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $PlanPath)) { Fail 'built-plan' 'built plan command failed' }

        & $Exe scan --target-root $Offline --workspace $Workspace --run-scan | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail 'built-scan' 'built scan command failed' }
        $ScanPath = Join-Path $Workspace 'rr3\rr3-offline-scan.json'
        if (-not (Test-Path -LiteralPath $ScanPath)) { Fail 'built-scan' 'built scan evidence missing' }

        $FixtureScript = Join-Path $ProcessTemp 'make_b45_evidence.py'
        $FixtureCode = @'
import hashlib, json, sys
from pathlib import Path
from sentinel import rescue_integrity_certification as rr6
root=Path(sys.argv[1]).resolve(); scan=Path(sys.argv[2]).resolve(); ev=Path(sys.argv[3]).resolve(); ev.mkdir(parents=True,exist_ok=True)
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def write(p,x): Path(p).write_text(json.dumps(x,indent=2,sort_keys=True)+'\n',encoding='utf-8')
fp=rr6.target_fingerprint(root)
baseline=ev/'critical-baseline.json'
write(baseline,{'schema':rr6.BASELINE_SCHEMA,'target_fingerprint':fp,'entries':[{'relative_path':rel,'sha256':sha(root/rel),'required':True} for rel in rr6.MANDATORY_CRITICAL_PATHS]})
prov=ev/'provenance.json'
write(prov,{'schema':rr6.PROVENANCE_SCHEMA,'approved':True,'target_fingerprint':fp,'repairs_performed':False,'evidence':[{'kind':'rr3_scan','path':str(scan),'sha256':sha(scan)},{'kind':'critical_baseline','path':str(baseline),'sha256':sha(baseline)}]})
print(str(baseline)); print(str(prov))
'@
        [IO.File]::WriteAllText($FixtureScript, $FixtureCode, (New-Object Text.UTF8Encoding($false)))
        $FixtureOutput = @(& $Py $FixtureScript $Offline $ScanPath $Evidence)
        if ($LASTEXITCODE -ne 0 -or $FixtureOutput.Count -lt 2) { Fail 'built-evidence' 'could not create clean certification evidence' }
        $BaselinePath = [string]$FixtureOutput[$FixtureOutput.Count - 2]
        $ProvenancePath = [string]$FixtureOutput[$FixtureOutput.Count - 1]

        & $Exe certify --target-root $Offline --workspace $Workspace --scan $ScanPath --baseline $BaselinePath --provenance $ProvenancePath | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail 'built-certify' ('clean built certification exit=' + $LASTEXITCODE) }
        $SummaryPath = Join-Path $Workspace 'b44-session-summary.json'
        if (-not (Test-Path -LiteralPath $SummaryPath)) { Fail 'built-certify' 'built B4-4 session summary missing' }
        $Summary = Get-Content -Raw -LiteralPath $SummaryPath -Encoding UTF8 | ConvertFrom-Json
        if ([string]$Summary.outcome -ne 'RECOVERED' -or -not [bool]$Summary.certified_recovered) { Fail 'built-certify' ('unexpected clean outcome=' + [string]$Summary.outcome) }
        if (-not [bool]$Summary.rr6_invoked) { Fail 'built-certify' 'RR6 not invoked by built console' }

        foreach ($p in $BeforeTarget.Keys) {
            $after = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($after -ne $BeforeTarget[$p]) { Fail 'target-integrity' ('B4-5 built console modified target: ' + $p) }
        }

        $Services = @(Get-CimInstance Win32_Service | Where-Object { ([string]$_.PathName).ToLowerInvariant().Contains('bc-sentinel-rescue-console-portable') })
        if ($Services.Count -ne 0) { Fail 'service-check' 'B4-5 portable console unexpectedly registered a Windows service' }

        foreach ($path in $Protected) {
            $after = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($after -ne $BeforeProtected[$path]) { Fail 'protected-source' ('B4-5 modified protected B2 source: ' + $path) }
        }

        Write-Host ('B45 LIVE EXE SHA256=' + $ExeHash) -ForegroundColor Green
        Write-Host ('B45 LIVE TARGET FINGERPRINT=' + [string]$Summary.target_fingerprint) -ForegroundColor Green
        Write-Host ('B45 LIVE SESSION=' + [string]$Summary.session_id + ' CORRELATION=' + [string]$Summary.correlation_id) -ForegroundColor Green
        Write-Host ('B45 LIVE RR6 REPORT SHA256=' + [string]$Summary.rr6_report_sha256) -ForegroundColor Green
        Write-Host ('B45 LIVE SESSION SUMMARY SHA256=' + [string]$Summary.summary_sha256) -ForegroundColor Green
        Write-Host 'B45 LIVE: built status PASS | forbidden repair-execute refused PASS | built plan PASS | built scan PASS | built integrated certification RECOVERED PASS | target unchanged | no service | B2 sources unchanged' -ForegroundColor Green
        Write-Host 'BC SENTINEL v0.11.0-beta.4 B4-5 PORTABLE RESCUE CONSOLE - PASS' -ForegroundColor Green
        exit 0
    }
    finally {
        $env:TEMP = $OldTemp; $env:TMP = $OldTmp
        Remove-Item -LiteralPath $PytestTemp -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $ProcessTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
catch { Fail 'unhandled' $_.Exception.Message }
