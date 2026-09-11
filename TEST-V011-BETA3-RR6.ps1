param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Stage,[string]$Message) {
    Write-Host ('RR6 FAIL STAGE=' + $Stage + ' | ' + $Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.3 RR-6 INTEGRITY CERTIFICATION - FAIL' -ForegroundColor Red
    exit 1
}

function Read-JsonSafe([string]$Path) {
    try {
        if (Test-Path -LiteralPath $Path) { return (Get-Content -Raw -LiteralPath $Path -Encoding UTF8 | ConvertFrom-Json) }
    } catch { }
    return $null
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Fail 'preflight' 'Run RR6 from normal non-elevated PowerShell.' }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { Fail 'preflight' '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.3 - RR-6 INTEGRITY VERIFICATION & RECOVERY CERTIFICATION' -ForegroundColor Cyan
    Write-Host 'Read-only certification: RECOVERED only with complete independent evidence; otherwise NOT_RECOVERED or INDETERMINATE_REFUSED.' -ForegroundColor Yellow

    $Protected = @('.\sentinel\protection_service_core.py','.\sentinel\realtime.py','.\sentinel\edr.py','.\sentinel\edr_service_bridge.py')
    $BeforeProtected = @{}
    foreach ($path in $Protected) {
        if (-not (Test-Path -LiteralPath $path)) { Fail 'preflight' ('protected source missing: ' + $path) }
        $BeforeProtected[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    $Base = Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    New-Item -ItemType Directory -Path $Base -Force | Out-Null
    $ProcessTemp = Join-Path $Base ('rr6-process-temp-' + [guid]::NewGuid().ToString('N'))
    $PytestTemp = Join-Path $Base ('rr6-pytest-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $ProcessTemp -Force | Out-Null
    $OldTemp = $env:TEMP; $OldTmp = $env:TMP
    $env:TEMP = $ProcessTemp; $env:TMP = $ProcessTemp
    Write-Host ('RR6 PYTEST BASETEMP=' + $PytestTemp) -ForegroundColor DarkGray

    try {
        & $Py -m compileall -q sentinel\rescue_contract.py sentinel\rescue_portable.py sentinel\rescue_usb.py sentinel\rescue_offline_scanner.py sentinel\rescue_repair_engine.py sentinel\rescue_repair_portable.py sentinel\rescue_data_rescue.py sentinel\rescue_integrity_certification.py tools\v011_beta3_rr6_acceptance.py tests\test_v011_beta3_rr6_integrity_certification.py
        if ($LASTEXITCODE -ne 0) { Fail 'compileall' 'RR6 compileall failed' }

        $Tests = @(
            'tests/test_v011_beta3_rr0_rescue_contract.py','tests/test_v011_beta3_rr1_portable.py','tests/test_v011_beta3_rr2_rescue_usb.py','tests/test_v011_beta3_rr3_offline_scanner.py','tests/test_v011_beta3_rr4a_repair_engine.py','tests/test_v011_beta3_rr4b_portable_repair.py','tests/test_v011_beta3_rr5_safe_data_rescue.py','tests/test_v011_beta3_rr6_integrity_certification.py'
        )
        & $Py -m pytest -q --basetemp $PytestTemp @Tests
        if ($LASTEXITCODE -ne 0) { Fail 'pytest' 'RR0..RR6 regression failed' }

        foreach ($spec in @(
            @('rr0','tools.v011_beta3_rr0_acceptance','acceptance-v011-beta3-rr0-regression.json'),
            @('rr1','tools.v011_beta3_rr1_acceptance','acceptance-v011-beta3-rr1-regression.json'),
            @('rr2','tools.v011_beta3_rr2_acceptance','acceptance-v011-beta3-rr2-regression.json'),
            @('rr3','tools.v011_beta3_rr3_acceptance','acceptance-v011-beta3-rr3-regression.json'),
            @('rr4a','tools.v011_beta3_rr4a_acceptance','acceptance-v011-beta3-rr4a-regression.json'),
            @('rr4b','tools.v011_beta3_rr4b_acceptance','acceptance-v011-beta3-rr4b-regression.json'),
            @('rr5','tools.v011_beta3_rr5_acceptance','acceptance-v011-beta3-rr5-regression.json'),
            @('rr6','tools.v011_beta3_rr6_acceptance','acceptance-v011-beta3-rr6.json')
        )) {
            & $Py -m $spec[1] --output $spec[2]
            if ($LASTEXITCODE -ne 0) { Fail ('acceptance-' + $spec[0]) ($spec[0] + ' deterministic acceptance failed') }
        }

        Write-Host 'Building portable RR6 certification engine...' -ForegroundColor DarkCyan
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\BUILD-RESCUE-CERTIFICATION-PORTABLE.ps1'
        if ($LASTEXITCODE -ne 0) { Fail 'build' 'RR6 certification build failed' }

        $Folder = Join-Path $PSScriptRoot 'dist\Rescue\BC-Sentinel-Rescue-Certification-Portable'
        $Exe = Join-Path $Folder 'BC-Sentinel-Rescue-Certification-Portable.exe'
        $Integrity = Read-JsonSafe (Join-Path $Folder 'certification-integrity.json')
        if ($null -eq $Integrity) { Fail 'provenance' 'RR6 build integrity manifest missing/unreadable' }
        $BinaryHash = (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($BinaryHash -ne ([string]$Integrity.sha256).ToLowerInvariant()) { Fail 'provenance' 'RR6 binary SHA256 mismatch' }

        $RunRoot = Join-Path $Base ('rr6-live-' + [guid]::NewGuid().ToString('N'))
        $Offline = Join-Path $RunRoot 'offline-target'
        $Evidence = Join-Path $RunRoot 'evidence'
        New-Item -ItemType Directory -Path (Join-Path $Offline 'Windows\System32\config') -Force | Out-Null
        New-Item -ItemType Directory -Path $Evidence -Force | Out-Null
        [IO.File]::WriteAllBytes((Join-Path $Offline 'Windows\System32\config\SYSTEM'), [Text.Encoding]::UTF8.GetBytes('RR6 LIVE SYSTEM'))
        [IO.File]::WriteAllBytes((Join-Path $Offline 'Windows\System32\config\SOFTWARE'), [Text.Encoding]::UTF8.GetBytes('RR6 LIVE SOFTWARE'))
        [IO.File]::WriteAllBytes((Join-Path $Offline 'Windows\System32\ntoskrnl.exe'), [Text.Encoding]::UTF8.GetBytes('MZ RR6 LIVE KERNEL'))

        $BeforeTarget = @{}
        Get-ChildItem -LiteralPath $Offline -File -Recurse | ForEach-Object { $BeforeTarget[$_.FullName] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }

        $FixtureScript = Join-Path $ProcessTemp 'make_rr6_fixture.py'
        $FixtureCode = @'
import hashlib, json, sys
from pathlib import Path
from sentinel import rescue_integrity_certification as rr6
root=Path(sys.argv[1]); evdir=Path(sys.argv[2]); evdir.mkdir(parents=True, exist_ok=True)
def sha(p):
    h=hashlib.sha256(); h.update(Path(p).read_bytes()); return h.hexdigest()
def write(p,x): Path(p).write_text(json.dumps(x,indent=2,sort_keys=True)+"\n",encoding="utf-8")
fp=rr6.target_fingerprint(root)
scan=evdir/'rr3-scan.json'; baseline=evdir/'critical-baseline.json'; prov=evdir/'provenance.json'
write(scan,{"profile":rr6.RR3_PROFILE,"summary":{"enumerated":3,"hashed":3,"skipped":0,"errors":0,"ioc_hits":0,"yara_hits":0,"heuristic_review_items":0,"registry_hives":2,"truncated_by_max_files":False},"findings":[],"registry_hives":[{"label":"system:SYSTEM","sha256":sha(root/'Windows/System32/config/SYSTEM'),"status":"hashed","write_attempted":False},{"label":"system:SOFTWARE","sha256":sha(root/'Windows/System32/config/SOFTWARE'),"status":"hashed","write_attempted":False}]})
write(baseline,{"schema":rr6.BASELINE_SCHEMA,"target_fingerprint":fp,"entries":[{"relative_path":r,"sha256":sha(root/r),"required":True} for r in rr6.MANDATORY_CRITICAL_PATHS]})
write(prov,{"schema":rr6.PROVENANCE_SCHEMA,"approved":True,"target_fingerprint":fp,"repairs_performed":False,"evidence":[{"kind":"rr3_scan","path":scan.name,"sha256":sha(scan)},{"kind":"critical_baseline","path":baseline.name,"sha256":sha(baseline)}],"lineage":{"rr3":rr6.RR3_PROFILE,"rr6":rr6.PROFILE}})
print(fp)
'@
        [IO.File]::WriteAllText($FixtureScript, $FixtureCode, (New-Object Text.UTF8Encoding($false)))
        $Fingerprint = (& $Py $FixtureScript $Offline $Evidence | Select-Object -Last 1).Trim()
        if ($LASTEXITCODE -ne 0 -or $Fingerprint.Length -ne 64) { Fail 'live-fixture' 'RR6 fixture generation failed' }

        Write-Host ('RR6 LIVE ROOT=' + $Offline) -ForegroundColor DarkGray
        Write-Host ('RR6 LIVE TARGET FINGERPRINT=' + $Fingerprint) -ForegroundColor DarkGray

        $CleanOut = Join-Path $RunRoot 'report-clean'
        & $Exe --root $Offline --scan (Join-Path $Evidence 'rr3-scan.json') --baseline (Join-Path $Evidence 'critical-baseline.json') --provenance (Join-Path $Evidence 'provenance.json') --output $CleanOut
        if ($LASTEXITCODE -ne 0) { Fail 'live-clean' 'clean fixture was not certified' }
        $CleanReport = Read-JsonSafe (Join-Path $CleanOut 'rr6-certification-report.json')
        if ($null -eq $CleanReport -or [string]$CleanReport.outcome -ne 'RECOVERED' -or -not [bool]$CleanReport.certified_recovered) { Fail 'live-clean' 'clean fixture report is not RECOVERED' }

        $Mutator = Join-Path $ProcessTemp 'mutate_rr6_evidence.py'
        $MutatorCode = @'
import hashlib,json,sys
from pathlib import Path
mode=sys.argv[1]; scan=Path(sys.argv[2]); prov=Path(sys.argv[3]); root=Path(sys.argv[4])
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
s=json.loads(scan.read_text(encoding='utf-8'))
if mode=='threat':
    s['summary']['ioc_hits']=1
    k=root/'Windows/System32/ntoskrnl.exe'
    s['findings']=[{'relative_path':'Windows/System32/ntoskrnl.exe','sha256':sha(k),'verdict':'deterministic_ioc'}]
elif mode=='truncated':
    s['summary']['truncated_by_max_files']=True
scan.write_text(json.dumps(s,indent=2,sort_keys=True)+'\n',encoding='utf-8')
p=json.loads(prov.read_text(encoding='utf-8'))
for e in p['evidence']:
    if e['kind']=='rr3_scan': e['sha256']=sha(scan)
prov.write_text(json.dumps(p,indent=2,sort_keys=True)+'\n',encoding='utf-8')
'@
        [IO.File]::WriteAllText($Mutator, $MutatorCode, (New-Object Text.UTF8Encoding($false)))

        & $Py $Mutator threat (Join-Path $Evidence 'rr3-scan.json') (Join-Path $Evidence 'provenance.json') $Offline
        if ($LASTEXITCODE -ne 0) { Fail 'live-threat' 'failed to prepare threat evidence' }
        $ThreatOut = Join-Path $RunRoot 'report-threat'
        & $Exe --root $Offline --scan (Join-Path $Evidence 'rr3-scan.json') --baseline (Join-Path $Evidence 'critical-baseline.json') --provenance (Join-Path $Evidence 'provenance.json') --output $ThreatOut
        if ($LASTEXITCODE -ne 3) { Fail 'live-threat' ('expected exit 3 for NOT_RECOVERED, got ' + $LASTEXITCODE) }
        $ThreatReport = Read-JsonSafe (Join-Path $ThreatOut 'rr6-certification-report.json')
        if ($null -eq $ThreatReport -or [string]$ThreatReport.outcome -ne 'NOT_RECOVERED') { Fail 'live-threat' 'IOC fixture did not return NOT_RECOVERED' }

        & $Py $FixtureScript $Offline $Evidence | Out-Null
        & $Py $Mutator truncated (Join-Path $Evidence 'rr3-scan.json') (Join-Path $Evidence 'provenance.json') $Offline
        if ($LASTEXITCODE -ne 0) { Fail 'live-refusal' 'failed to prepare incomplete evidence' }
        $RefusedOut = Join-Path $RunRoot 'report-refused'
        & $Exe --root $Offline --scan (Join-Path $Evidence 'rr3-scan.json') --baseline (Join-Path $Evidence 'critical-baseline.json') --provenance (Join-Path $Evidence 'provenance.json') --output $RefusedOut
        if ($LASTEXITCODE -ne 3) { Fail 'live-refusal' ('expected exit 3 for REFUSED, got ' + $LASTEXITCODE) }
        $RefusedReport = Read-JsonSafe (Join-Path $RefusedOut 'rr6-certification-report.json')
        if ($null -eq $RefusedReport -or [string]$RefusedReport.outcome -ne 'INDETERMINATE_REFUSED') { Fail 'live-refusal' 'truncated evidence did not return INDETERMINATE_REFUSED' }

        foreach ($p in $BeforeTarget.Keys) {
            $after = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
            if ($after -ne $BeforeTarget[$p]) { Fail 'target-integrity' ('RR6 modified target: ' + $p) }
        }

        $Services = @(Get-CimInstance Win32_Service | Where-Object { ([string]$_.PathName).ToLowerInvariant().Contains('bc-sentinel-rescue-certification-portable.exe') })
        if ($Services.Count -ne 0) { Fail 'live-safety' 'RR6 unexpectedly registered a Windows service' }

        foreach ($path in $Protected) {
            $after = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($after -ne $BeforeProtected[$path]) { Fail 'protected-source' ('RR6 modified protected B2 source: ' + $path) }
        }

        Write-Host ('RR6 CERTIFICATION BINARY SHA256=' + $BinaryHash) -ForegroundColor Green
        Write-Host ('RR6 CLEAN REPORT SHA256=' + [string]$CleanReport.report_sha256) -ForegroundColor Green
        Write-Host 'RR6 LIVE: clean RECOVERED PASS | unresolved IOC NOT_RECOVERED PASS | incomplete evidence REFUSED PASS | target unchanged | no service | B2 sources unchanged' -ForegroundColor Green
        Write-Host 'BC SENTINEL v0.11.0-beta.3 RR-6 INTEGRITY CERTIFICATION - PASS' -ForegroundColor Green
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
