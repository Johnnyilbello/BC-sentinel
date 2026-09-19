param([switch]$ConfirmConsumerReadiness)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot
$env:PYTHONPATH = $repoRoot

if (-not $ConfirmConsumerReadiness) {
    throw 'Explicit Beta13 B13-0 consumer readiness confirmation required.'
}

$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve B13-0 acceptance commit.' }
Write-Host ('B13-0 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B13-0 acceptance commit.' }

$frozen = 'c8e51a2a3fc34c593905896d3b055f9fec252c4b'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted Beta12 final checkpoint missing.' }

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
$changes = @(& git diff --name-only $frozen HEAD)
$allowed = @(
    '.github/workflows/b130-consumer-product-readiness.yml',
    'ROADMAP.md',
    'sentinel/beta13_consumer_readiness.py',
    'tests/test_v013_b130_consumer_readiness.py',
    'tools/acceptance/TEST-V013-B130-CONSUMER-READINESS.ps1'
)
if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B13-0 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) { throw ('Unexpected B13-0 changed path: ' + $path) }
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen Beta12 path changed: ' + $path)
    }
}
Write-Host 'Accepted Beta12 source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta13_consumer_readiness.py tests/test_v013_b130_consumer_readiness.py
if ($LASTEXITCODE -ne 0) { throw 'B13-0 compile failed.' }

$patterns = @(
    'tests/test_v011_beta5_*.py',
    'tests/test_v011_beta6_*.py',
    'tests/test_v011_beta7_*.py',
    'tests/test_v011_beta8_*.py',
    'tests/test_v011_beta9_*.py',
    'tests/test_v011_beta10_*.py',
    'tests/test_v011_beta11_*.py',
    'tests/test_v012_beta12_*.py',
    'tests/test_v013_*.py'
)
$tests = @(
    $patterns |
        ForEach-Object { Get-ChildItem $_ } |
        Sort-Object FullName |
        ForEach-Object { $_.FullName }
)

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b130-' + [guid]::NewGuid().ToString('N'))
& $py -m pytest -q --basetemp $testBase @tests
if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta13 B13-0 regression failed.' }

& $py -m sentinel.beta13_consumer_readiness
if ($LASTEXITCODE -ne 0) { throw 'B13-0 consumer readiness self-check failed.' }

& $py -c "import json; from sentinel.beta13_consumer_readiness import self_check; r=self_check(); assert r['passed']; assert r['source_checkpoint_commit']=='c8e51a2a3fc34c593905896d3b055f9fec252c4b'; assert r['pillar_counts']=={'READY':3,'PARTIAL':2,'BLOCKED':5}; assert r['release_blocker_count']==7; assert r['ready_for_public_launch'] is False; assert r['ready_for_paid_launch'] is False; assert r['ready_for_installer_work'] is True; assert r['installer_alone_is_launch_readiness'] is False; assert r['coverage_promoted'] is False; assert r['authority_expanded'] is False; print(json.dumps({'b13_0_passed':True,'pillar_counts':r['pillar_counts'],'release_blockers':r['release_blockers'],'release_blocker_count':r['release_blocker_count'],'ready_for_public_launch':r['ready_for_public_launch'],'ready_for_installer_work':r['ready_for_installer_work'],'contract_digest':r['contract_digest']},indent=2,sort_keys=True))"
if ($LASTEXITCODE -ne 0) { throw 'B13-0 final acceptance assertions failed.' }

Write-Host 'BC SENTINEL v0.13.0 B13-0 CONSUMER PRODUCT READINESS FOUNDATION - PASS'
