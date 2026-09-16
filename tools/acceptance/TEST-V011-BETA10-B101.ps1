param([switch]$ConfirmSentinelProofMode)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

if (-not $ConfirmSentinelProofMode) { throw 'Explicit Beta10 B10-1 Sentinel Proof Mode confirmation required.' }
$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve B10-1 acceptance commit.' }
Write-Host ('B10-1 Windows acceptance commit: ' + $commit)
& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B10-1 acceptance commit.' }

$frozen = '8f9b315eb3137f461dce1f679af32d8a9d680990'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted B10-0 predecessor missing.' }
$frozenPaths = @(& git ls-tree -r --name-only $frozen)
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate frozen B10-0 paths.' }
$changes = @(& git diff --name-only $frozen HEAD)
if ($LASTEXITCODE -ne 0) { throw 'Cannot compare frozen B10-0 sources.' }
foreach ($path in $changes) {
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B10-0 path changed: ' + $path)
    }
}
$rootFiles = @(& git ls-files | Where-Object { $_ -notmatch '/' })
$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($rootFiles.Count -ne 10 -or $roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository hygiene failed.'
}
Write-Host 'Frozen B10-0 paths and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) { $py = (Get-Command python -ErrorAction Stop).Source }
& $py -m compileall -q sentinel/beta10_proof_mode.py tests/test_v011_beta10_b101_proof_mode.py
if ($LASTEXITCODE -ne 0) { throw 'B10-1 compile failed.' }

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b101-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testBase -Force | Out-Null
try {
    $tests = @(Get-ChildItem tests/test_v011_beta5_*.py,tests/test_v011_beta6_*.py,tests/test_v011_beta7_*.py,tests/test_v011_beta8_*.py,tests/test_v011_beta9_*.py,tests/test_v011_beta10_*.py | Sort-Object FullName | ForEach-Object { $_.FullName })
    & $py -m pytest -q --basetemp (Join-Path $testBase 'pytest') @tests
    if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta10 B10-1 regression failed.' }

    & $py -m sentinel.beta10_proof_mode
    if ($LASTEXITCODE -ne 0) { throw 'B10-1 baseline Proof Mode self-check failed.' }

    $evidenceFile = Join-Path $testBase 'b101-live-proof.json'
    $proofStart = [DateTime]::UtcNow.ToString('o')
    & $py (Join-Path $PSScriptRoot 'RUN-V011-BETA9-B93-LIVE-FILES.py') --output $evidenceFile --confirm-live-controls
    if ($LASTEXITCODE -ne 0) { throw 'B10-1 live harmless proof exercise failed.' }

    & $py -m sentinel.beta10_proof_mode --evidence $evidenceFile --proof-started-after-utc $proofStart
    if ($LASTEXITCODE -ne 0) { throw 'B10-1 fresh Proof Mode composition failed.' }

    & $py -c "import json,sys; from sentinel.beta10_proof_mode import baseline_report,attach_fresh_ransomware_proof,proof_summary; e=json.load(open(sys.argv[1],encoding='utf-8-sig')); r=attach_fresh_ransomware_proof(baseline_report(),e,proof_started_after_utc=sys.argv[2]); assert r['passed']; s=proof_summary(r); assert s['passed']; assert s['coverage_summary']=={'PARTIAL':5,'GAP':0,'VERIFIED':1}; assert s['verified_count']==1 and s['scenario_count']==6 and s['fresh_proof_count']==1; assert s['current_machine_proof_performed']; assert not s['broad_protection_claimed']; assert not s['authority_expanded']; assert s['proof_capable_scenarios']==['B7-RANSOMWARE-001']; rows=r['scenarios']; assert [x['scenario_id'] for x in rows if x['status']=='VERIFIED']==['B7-RANSOMWARE-001']; rr=next(x for x in rows if x['scenario_id']=='B7-RANSOMWARE-001'); assert rr['fresh_proof'] and rr['proof_outcome']=='DETECTED'; assert rr['proof_details']['control_outcomes']=={'positive-ransomware-like':'DETECTED','administrative-backup-like':'REVIEW_REQUIRED','benign-save':'NO_MATCH'}; assert rr['proof_details']['detector_to_security_graph_bound'] and rr['proof_details']['security_graph_to_incident_bound']" $evidenceFile $proofStart
    if ($LASTEXITCODE -ne 0) { throw 'B10-1 Proof Mode assertions failed.' }

    Write-Host 'BC SENTINEL v0.11.0-beta.10 B10-1 SENTINEL PROOF MODE - PASS'
}
finally {
    Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
}
