param([switch]$ConfirmHarmlessEventIncidentAcceptance)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

if (-not $ConfirmHarmlessEventIncidentAcceptance) { throw 'Explicit acceptance switch required.' }
$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve acceptance commit.' }
Write-Host ('B9-2 Windows acceptance commit: ' + $commit)
& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from acceptance commit.' }

$frozen = 'c4cf63fb0c61e9fc65287b624cb0f59c0cf74c69'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted B9-1 predecessor missing.' }
$frozenPaths = @(& git ls-tree -r --name-only $frozen)
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate frozen B9-1 paths.' }
$changes = @(& git diff --name-only $frozen HEAD)
if ($LASTEXITCODE -ne 0) { throw 'Cannot compare frozen B9-1 sources.' }
foreach ($path in $changes) {
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B9-1 path changed: ' + $path)
    }
}
$rootFiles = @(& git ls-files | Where-Object { $_ -notmatch '/' })
$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($rootFiles.Count -ne 10 -or $roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository hygiene failed.'
}
Write-Host 'Frozen B9-1 paths and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) { $py = (Get-Command python -ErrorAction Stop).Source }
& $py -m compileall -q sentinel/beta9_event_to_incident.py tests/test_v011_beta9_b92_event_to_incident.py
if ($LASTEXITCODE -ne 0) { throw 'Compile failed.' }

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b92-' + [guid]::NewGuid().ToString('N'))
$tests = @(Get-ChildItem tests/test_v011_beta5_*.py,tests/test_v011_beta6_*.py,tests/test_v011_beta7_*.py,tests/test_v011_beta8_*.py,tests/test_v011_beta9_*.py | Sort-Object FullName | ForEach-Object { $_.FullName })
& $py -m pytest -q --basetemp $testBase @tests
if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta9 regression failed.' }

$exerciseFile = Join-Path $testBase 'harmless-event-exercise.json'
$raw = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'EXERCISE-V011-BETA9-B92.ps1') -ConfirmHarmlessEventExercise -QueryTimeoutSeconds 8
if ($LASTEXITCODE -ne 0) { throw 'Harmless live event exercise failed.' }
[IO.File]::WriteAllText($exerciseFile, ($raw -join [Environment]::NewLine), [Text.UTF8Encoding]::new($false))

& $py -m sentinel.beta9_event_to_incident --exercise $exerciseFile
if ($LASTEXITCODE -ne 0) { throw 'Live event-to-incident contract failed.' }

& $py -c "import json,sys; from sentinel.beta9_event_to_incident import summarize; d=json.load(open(sys.argv[1],encoding='utf-8')); r=summarize(d); assert r['passed']; assert d['exercise']['live_observation'] is True; assert d['exercise']['cleanup_state']=='EXITED'; assert d['exercise']['exit_code']==0; assert d['event']['process_id']==d['exercise']['child_process_id']; assert d['event']['event_id'] in {400,403}; b=d['exercise']['baseline_record_id']; assert b is None or d['event']['record_id']>b; assert r['live_event_bound']; assert r['event_to_acceptance_detector_bound']; assert r['detector_to_security_graph_bound']; assert r['security_graph_to_incident_bound']; assert r['incident_count']==1; assert r['graph_node_count']==2; assert r['graph_edge_count']==1; assert not r['threat_detector_verification_performed']; assert not r['threat_classification_performed']; assert r['coverage_summary']=={'PARTIAL':6,'GAP':0,'VERIFIED':0}" $exerciseFile
if ($LASTEXITCODE -ne 0) { throw 'Live B9-2 provenance binding assertions failed.' }

Write-Host 'BC SENTINEL v0.11.0-beta.9 B9-2 HARMLESS EVENT-TO-INCIDENT ACCEPTANCE - PASS'
