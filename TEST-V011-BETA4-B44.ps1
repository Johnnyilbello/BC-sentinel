param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Stage,[string]$Message) {
    Write-Host ('B44 FAIL STAGE=' + $Stage + ' | ' + $Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.4 B4-4 INTEGRATED CERTIFICATION + SESSION SUMMARY - FAIL' -ForegroundColor Red
    exit 1
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Fail 'preflight' 'Run B4-4 from normal non-elevated PowerShell.' }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { Fail 'preflight' '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.4 - B4-4 INTEGRATED CERTIFICATION + SESSION SUMMARY' -ForegroundColor Cyan
    Write-Host 'Session trust is validated before RR6. RR6 RECOVERED / NOT_RECOVERED / INDETERMINATE_REFUSED is preserved exactly.' -ForegroundColor Yellow

    $Protected = @('.\sentinel\protection_service_core.py','.\sentinel\realtime.py','.\sentinel\edr.py','.\sentinel\edr_service_bridge.py')
    $BeforeProtected = @{}
    foreach ($path in $Protected) {
        if (-not (Test-Path -LiteralPath $path)) { Fail 'preflight' ('protected source missing: ' + $path) }
        $BeforeProtected[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    $Base = Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    New-Item -ItemType Directory -Path $Base -Force | Out-Null
    $ProcessTemp = Join-Path $Base ('b44-process-' + [guid]::NewGuid().ToString('N'))
    $PytestTemp = Join-Path $Base ('b44-pytest-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $ProcessTemp -Force | Out-Null
    $OldTemp = $env:TEMP; $OldTmp = $env:TMP
    $env:TEMP = $ProcessTemp; $env:TMP = $ProcessTemp
    Write-Host ('B44 PYTEST BASETEMP=' + $PytestTemp) -ForegroundColor DarkGray

    try {
        & $Py -m compileall -q sentinel\rescue_console_integrated_certification.py tools\v011_beta4_b44_acceptance.py tests\test_v011_beta4_b44_integrated_certification_summary.py
        if ($LASTEXITCODE -ne 0) { Fail 'compileall' 'B4-4 compileall failed' }

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
            'tests/test_v011_beta4_b44_integrated_certification_summary.py'
        )
        & $Py -m pytest -q --basetemp $PytestTemp @Tests
        if ($LASTEXITCODE -ne 0) { Fail 'pytest' 'Beta3 + B4-0..B4-4 regression failed' }

        foreach ($spec in @(
            @('rr0','tools.v011_beta3_rr0_acceptance','acceptance-v011-beta3-rr0-b44-regression.json'),
            @('rr1','tools.v011_beta3_rr1_acceptance','acceptance-v011-beta3-rr1-b44-regression.json'),
            @('rr2','tools.v011_beta3_rr2_acceptance','acceptance-v011-beta3-rr2-b44-regression.json'),
            @('rr3','tools.v011_beta3_rr3_acceptance','acceptance-v011-beta3-rr3-b44-regression.json'),
            @('rr4a','tools.v011_beta3_rr4a_acceptance','acceptance-v011-beta3-rr4a-b44-regression.json'),
            @('rr4b','tools.v011_beta3_rr4b_acceptance','acceptance-v011-beta3-rr4b-b44-regression.json'),
            @('rr5','tools.v011_beta3_rr5_acceptance','acceptance-v011-beta3-rr5-b44-regression.json'),
            @('rr6','tools.v011_beta3_rr6_acceptance','acceptance-v011-beta3-rr6-b44-regression.json'),
            @('b40','tools.v011_beta4_b40_acceptance','acceptance-v011-beta4-b40-b44-regression.json'),
            @('b41','tools.v011_beta4_b41_acceptance','acceptance-v011-beta4-b41-b44-regression.json'),
            @('b42','tools.v011_beta4_b42_acceptance','acceptance-v011-beta4-b42-b44-regression.json'),
            @('b43','tools.v011_beta4_b43_acceptance','acceptance-v011-beta4-b43-b44-regression.json'),
            @('b44','tools.v011_beta4_b44_acceptance','acceptance-v011-beta4-b44.json')
        )) {
            & $Py -m $spec[1] --output $spec[2]
            if ($LASTEXITCODE -ne 0) { Fail ('acceptance-' + $spec[0]) ($spec[0] + ' deterministic acceptance failed') }
        }

        $B44Acceptance = Get-Content -Raw -LiteralPath '.\acceptance-v011-beta4-b44.json' -Encoding UTF8 | ConvertFrom-Json
        if (-not [bool]$B44Acceptance.passed) { Fail 'acceptance-b44' 'B4-4 acceptance JSON did not pass' }
        if ([string]$B44Acceptance.detail.clean_outcome -ne 'RECOVERED') { Fail 'acceptance-b44' 'clean outcome not RECOVERED' }
        if ([string]$B44Acceptance.detail.not_recovered_outcome -ne 'NOT_RECOVERED') { Fail 'acceptance-b44' 'threat outcome not NOT_RECOVERED' }
        if ([string]$B44Acceptance.detail.session_refused_outcome -ne 'INDETERMINATE_REFUSED') { Fail 'acceptance-b44' 'session refusal outcome not INDETERMINATE_REFUSED' }
        if ([string]$B44Acceptance.detail.rr6_refused_outcome -ne 'INDETERMINATE_REFUSED') { Fail 'acceptance-b44' 'RR6 refusal outcome not INDETERMINATE_REFUSED' }

        $RunRoot = Join-Path $Base ('b44-live-' + [guid]::NewGuid().ToString('N'))
        $Offline = Join-Path $RunRoot 'offline-target'
        $Workspace = Join-Path $RunRoot 'workspace'
        $Evidence = Join-Path $RunRoot 'evidence'
        $Config = Join-Path $Offline 'Windows\System32\config'
        New-Item -ItemType Directory -Path $Config,$Workspace,$Evidence -Force | Out-Null
        [IO.File]::WriteAllBytes((Join-Path $Config 'SYSTEM'), [Text.Encoding]::UTF8.GetBytes('B44 LIVE SYSTEM'))
        [IO.File]::WriteAllBytes((Join-Path $Config 'SOFTWARE'), [Text.Encoding]::UTF8.GetBytes('B44 LIVE SOFTWARE'))
        [IO.File]::WriteAllBytes((Join-Path $Offline 'Windows\System32\ntoskrnl.exe'), [Text.Encoding]::UTF8.GetBytes('MZ B44 LIVE KERNEL'))

        $BeforeTarget = @{}
        Get-ChildItem -LiteralPath $Offline -File -Recurse | ForEach-Object { $BeforeTarget[$_.FullName] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }

        $PlanPath = Join-Path $Workspace 'session-plan.json'
        & $Py -m sentinel.rescue_console --target-root $Offline --workspace $Workspace --output-plan $PlanPath | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail 'live-b40' 'B4-0 session plan failed' }

        & $Py -m sentinel.rescue_console_guided_scan --target-root $Offline --workspace $Workspace --run-scan | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail 'live-b41' 'B4-1 guided scan failed' }
        $ScanPath = Join-Path $Workspace 'rr3\rr3-offline-scan.json'
        if (-not (Test-Path -LiteralPath $ScanPath)) { Fail 'live-b41' 'RR3 scan missing' }

        $FixtureScript = Join-Path $ProcessTemp 'make_b44_evidence.py'
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
        if ($LASTEXITCODE -ne 0 -or $FixtureOutput.Count -lt 2) { Fail 'live-evidence' 'could not build RR6 evidence fixture' }
        $BaselinePath = [string]$FixtureOutput[$FixtureOutput.Count - 2]
        $ProvenancePath = [string]$FixtureOutput[$FixtureOutput.Count - 1]

        & $Py -m sentinel.rescue_console_integrated_certification --target-root $Offline --workspace $Workspace --scan $ScanPath --baseline $BaselinePath --provenance $ProvenancePath | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail 'live-b44' ('clean integrated certification returned exit=' + $LASTEXITCODE) }
        $SummaryPath = Join-Path $Workspace 'b44-session-summary.json'
        if (-not (Test-Path -LiteralPath $SummaryPath)) { Fail 'live-b44' 'B4-4 session summary missing' }
        $Summary = Get-Content -Raw -LiteralPath $SummaryPath -Encoding UTF8 | ConvertFrom-Json
        if ([string]$Summary.profile -ne 'v0.11.0-beta.4-b44') { Fail 'live-b44' 'unexpected B4-4 profile' }
        if ([string]$Summary.outcome -ne 'RECOVERED') { Fail 'live-b44' ('clean outcome=' + [string]$Summary.outcome) }
        if (-not [bool]$Summary.certified_recovered) { Fail 'live-b44' 'clean session not certified recovered' }
        if (-not [bool]$Summary.rr6_invoked) { Fail 'live-b44' 'RR6 was not invoked for trusted session' }
        if ([string]$Summary.summary_sha256 -notmatch '^[0-9a-f]{64}$') { Fail 'live-b44' 'session summary SHA256 invalid' }
        if ([string]$Summary.rr6_report_sha256 -notmatch '^[0-9a-f]{64}$') { Fail 'live-b44' 'RR6 report SHA256 invalid' }
        if ([bool]$Summary.safety.automatic_destructive_action) { Fail 'live-safety' 'automatic destructive action unexpectedly enabled' }
        if ([bool]$Summary.safety.repair_execution) { Fail 'live-safety' 'repair execution unexpectedly enabled' }
        if ([bool]$Summary.safety.format_or_reimage_suppressed) { Fail 'live-safety' 'format/reimage unexpectedly suppressed' }

        foreach ($p in $BeforeTarget.Keys) {
            $after = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($after -ne $BeforeTarget[$p]) { Fail 'target-integrity' ('B4-4 modified target: ' + $p) }
        }

        $Services = @(Get-CimInstance Win32_Service | Where-Object { ([string]$_.PathName).ToLowerInvariant().Contains('bc-sentinel-rescue-console') })
        if ($Services.Count -ne 0) { Fail 'live-safety' 'B4-4 unexpectedly registered a Windows service' }

        foreach ($path in $Protected) {
            $after = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($after -ne $BeforeProtected[$path]) { Fail 'protected-source' ('B4-4 modified protected B2 source: ' + $path) }
        }

        Write-Host ('B44 LIVE TARGET FINGERPRINT=' + [string]$Summary.target_fingerprint) -ForegroundColor Green
        Write-Host ('B44 LIVE SESSION=' + [string]$Summary.session_id + ' CORRELATION=' + [string]$Summary.correlation_id) -ForegroundColor Green
        Write-Host ('B44 LIVE RR6 REPORT SHA256=' + [string]$Summary.rr6_report_sha256) -ForegroundColor Green
        Write-Host ('B44 LIVE SESSION SUMMARY SHA256=' + [string]$Summary.summary_sha256) -ForegroundColor Green
        Write-Host 'B44 LIVE: RECOVERED PASS | NOT_RECOVERED preserved PASS | INDETERMINATE_REFUSED preserved PASS | session refusal pre-RR6 PASS | target unchanged | no service | B2 sources unchanged' -ForegroundColor Green
        Write-Host 'BC SENTINEL v0.11.0-beta.4 B4-4 INTEGRATED CERTIFICATION + SESSION SUMMARY - PASS' -ForegroundColor Green
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
