param([switch]$ConfirmBeta12ActiveProtectionFoundation)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

if (-not $ConfirmBeta12ActiveProtectionFoundation) {
    throw 'Explicit Beta12 B12-0 active-protection-foundation confirmation required.'
}

$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve B12-0 acceptance commit.' }
Write-Host ('B12-0 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B12-0 acceptance commit.' }

$frozen = '3c5204ca949d41d3a740b8745ab9af06913b8555'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted Beta11 B11-9 predecessor missing.' }

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate frozen Beta11 paths.' }
$changes = @(& git diff --name-only $frozen HEAD)
if ($LASTEXITCODE -ne 0) { throw 'Cannot compare frozen Beta11 sources.' }

$allowed = @(
    '.github/workflows/b120-active-protection-foundation.yml',
    'ROADMAP.md',
    'sentinel/beta12_active_protection_foundation.py',
    'tests/test_v012_beta12_b120_active_protection_foundation.py',
    'tools/acceptance/TEST-V012-BETA12-B120.ps1'
)

if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B12-0 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) {
        throw ('Unexpected B12-0 changed path: ' + $path)
    }
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen Beta11 path changed: ' + $path)
    }
}

$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository roadmap hygiene failed.'
}
Write-Host 'Accepted Beta11 source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta12_active_protection_foundation.py tests/test_v012_beta12_b120_active_protection_foundation.py
if ($LASTEXITCODE -ne 0) { throw 'B12-0 compile failed.' }

$patterns = @(
    'tests/test_v011_beta5_*.py',
    'tests/test_v011_beta6_*.py',
    'tests/test_v011_beta7_*.py',
    'tests/test_v011_beta8_*.py',
    'tests/test_v011_beta9_*.py',
    'tests/test_v011_beta10_*.py',
    'tests/test_v011_beta11_*.py',
    'tests/test_v012_beta12_*.py'
)
$tests = @(
    $patterns |
        ForEach-Object { Get-ChildItem $_ } |
        Sort-Object FullName |
        ForEach-Object { $_.FullName }
)

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b120-' + [guid]::NewGuid().ToString('N'))
& $py -m pytest -q --basetemp $testBase @tests
if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta12 B12-0 regression failed.' }

& $py -m sentinel.beta12_active_protection_foundation
if ($LASTEXITCODE -ne 0) { throw 'B12-0 active-protection contract self-check failed.' }

& $py -c "from sentinel.beta12_active_protection_foundation import contract,self_check; r=contract(); s=self_check(); assert s['passed']; assert s['deterministic_contract']; assert r['source_checkpoint_commit']=='3c5204ca949d41d3a740b8745ab9af06913b8555'; assert r['baseline_coverage']=={'PARTIAL':4,'GAP':0,'VERIFIED':2}; assert len(r['protection_pillars'])==7; assert len(r['milestones'])==10; assert r['final_freeze_targets']['minimum_total_verified_scenarios']==4; assert r['final_freeze_targets']['minimum_new_verified_scenarios']==2; assert not s['coverage_promoted']; assert not s['authority_expanded']; assert s['installer_work_deferred']"
if ($LASTEXITCODE -ne 0) { throw 'B12-0 active-protection-foundation assertions failed.' }

Write-Host 'BC SENTINEL v0.12.0-beta.12 B12-0 ACTIVE PROTECTION FOUNDATION - PASS'
