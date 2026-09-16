param([switch]$ConfirmFalsePositiveCoverageAcceptance)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

if (-not $ConfirmFalsePositiveCoverageAcceptance) { throw 'Explicit B9-3 acceptance switch required.' }
$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve acceptance commit.' }
Write-Host ('B9-3 Windows acceptance commit: ' + $commit)
& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from acceptance commit.' }

$frozen = '7359f780f206b36355dcb3f6ba3687ad75240b98'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted B9-2 predecessor missing.' }
$frozenPaths = @(& git ls-tree -r --name-only $frozen)
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate frozen B9-2 paths.' }
$changes = @(& git diff --name-only $frozen HEAD)
if ($LASTEXITCODE -ne 0) { throw 'Cannot compare frozen B9-2 sources.' }
foreach ($path in $changes) {
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B9-2 path changed: ' + $path)
    }
}
$rootFiles = @(& git ls-files | Where-Object { $_ -notmatch '/' })
$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($rootFiles.Count -ne 10 -or $roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository hygiene failed.'
}
Write-Host 'Frozen B9-2 paths and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) { $py = (Get-Command python -ErrorAction Stop).Source }
& $py -m compileall -q sentinel/beta9_ransomware_controls.py tests/test_v011_beta9_b93_ransomware_controls.py tools/acceptance/RUN-V011-BETA9-B93-LIVE-FILES.py
if ($LASTEXITCODE -ne 0) { throw 'Compile failed.' }

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b93-' + [guid]::NewGuid().ToString('N'))
$tests = @(Get-ChildItem tests/test_v011_beta5_*.py,tests/test_v011_beta6_*.py,tests/test_v011_beta7_*.py,tests/test_v011_beta8_*.py,tests/test_v011_beta9_*.py | Sort-Object FullName | ForEach-Object { $_.FullName })
& $py -m pytest -q --basetemp $testBase @tests
if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta9 regression failed.' }

$evidenceFile = Join-Path $testBase 'b93-live-file-controls.json'
& $py (Join-Path $PSScriptRoot 'RUN-V011-BETA9-B93-LIVE-FILES.py') --output $evidenceFile --confirm-live-controls
if ($LASTEXITCODE -ne 0) { throw 'B9-3 harmless live file controls failed.' }

& $py -m sentinel.beta9_ransomware_controls --evidence $evidenceFile
if ($LASTEXITCODE -ne 0) { throw 'B9-3 live detector controls contract failed.' }

& $py -c "import json,sys; from sentinel.beta9_ransomware_controls import summarize; d=json.load(open(sys.argv[1],encoding='utf-8')); r=summarize(d); assert r['passed']; c={x['control_id']:x for x in d['controls']}; assert c['positive-ransomware-like']['write_event_count']>=20; assert c['positive-ransomware-like']['rename_event_count']>=15; assert all(x['cleanup_state']=='CLEAN' for x in d['controls']); assert r['control_outcomes']['positive-ransomware-like']=='DETECTED'; assert r['control_outcomes']['administrative-backup-like']=='REVIEW_REQUIRED'; assert r['control_outcomes']['benign-save']=='NO_MATCH'; assert r['live_thresholds_met']; assert r['detector_to_security_graph_bound']; assert r['security_graph_to_incident_bound']; assert r['controlled_threat_detector_verification_performed']; assert not r['broad_ransomware_protection_claimed']; assert not r['synthetic_fallback_used']; assert r['coverage_summary']=={'PARTIAL':5,'GAP':0,'VERIFIED':1}; decisions={x['scenario_id']:x for x in r['coverage_decisions']}; assert decisions['B7-RANSOMWARE-001']['status']=='VERIFIED'; assert all(decisions[s]['status']=='PARTIAL' for s in decisions if s!='B7-RANSOMWARE-001'); b=r['boundaries']; assert b['acceptance_harness_file_mutation']; assert b['dedicated_temp_directory_only']; assert not b['user_file_access']; assert not b['file_content_collected']; assert not b['absolute_paths_exported']; assert not b['real_malware_executed']; assert not b['product_file_write_authority']; assert not b['product_file_rename_authority']; assert not b['product_file_delete_authority']; assert not b['remediation_authority']; assert not b['privileged_system_mutation']" $evidenceFile
if ($LASTEXITCODE -ne 0) { throw 'B9-3 live false-positive and coverage assertions failed.' }

Write-Host 'BC SENTINEL v0.11.0-beta.9 B9-3 FALSE-POSITIVE CONTROLS & COVERAGE DECISIONS - PASS'
