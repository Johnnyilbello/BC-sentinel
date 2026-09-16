param([switch]$ConfirmBeta10ValueFoundation)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

if (-not $ConfirmBeta10ValueFoundation) { throw 'Explicit Beta10 B10-0 value-foundation confirmation required.' }
$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve B10-0 acceptance commit.' }
Write-Host ('B10-0 Windows acceptance commit: ' + $commit)
& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B10-0 acceptance commit.' }

$frozen = 'cc32c2c31ebb9b863624632a38175ec5825430e4'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted Beta9 B9-4 predecessor missing.' }
$frozenPaths = @(& git ls-tree -r --name-only $frozen)
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate frozen Beta9 paths.' }
$changes = @(& git diff --name-only $frozen HEAD)
if ($LASTEXITCODE -ne 0) { throw 'Cannot compare frozen Beta9 sources.' }
foreach ($path in $changes) {
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen Beta9 path changed: ' + $path)
    }
}
$rootFiles = @(& git ls-files | Where-Object { $_ -notmatch '/' })
$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($rootFiles.Count -ne 10 -or $roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository hygiene failed.'
}
Write-Host 'Frozen Beta9 paths and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) { $py = (Get-Command python -ErrorAction Stop).Source }
& $py -m compileall -q sentinel/beta10_value_foundation.py tests/test_v011_beta10_b100_value_foundation.py
if ($LASTEXITCODE -ne 0) { throw 'B10-0 compile failed.' }

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b100-' + [guid]::NewGuid().ToString('N'))
$tests = @(Get-ChildItem tests/test_v011_beta5_*.py,tests/test_v011_beta6_*.py,tests/test_v011_beta7_*.py,tests/test_v011_beta8_*.py,tests/test_v011_beta9_*.py,tests/test_v011_beta10_*.py | Sort-Object FullName | ForEach-Object { $_.FullName })
& $py -m pytest -q --basetemp $testBase @tests
if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta10 B10-0 regression failed.' }

& $py -m sentinel.beta10_value_foundation
if ($LASTEXITCODE -ne 0) { throw 'B10-0 value contract self-check failed.' }

& $py -c "from sentinel.beta10_value_foundation import contract,self_check; r=contract(); s=self_check(); assert s['passed']; assert s['deterministic_contract']; assert r['baseline_coverage']=={'PARTIAL':5,'GAP':0,'VERIFIED':1}; assert r['verified_scenario_id']=='B7-RANSOMWARE-001'; assert len(r['value_pillars'])==6; assert len(r['milestones'])==10; assert not s['authority_expanded']; assert not s['protection_claim_expanded']; assert all(v is False for v in r['authority_boundary'].values())"
if ($LASTEXITCODE -ne 0) { throw 'B10-0 value-foundation assertions failed.' }

Write-Host 'BC SENTINEL v0.11.0-beta.10 B10-0 VALUE FOUNDATION + COMPETITIVE CONTRACT - PASS'
