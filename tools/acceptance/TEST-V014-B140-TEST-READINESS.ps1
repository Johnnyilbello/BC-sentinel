param(
    [switch]$ConfirmTestReadinessFoundation
)

$ErrorActionPreference = 'Stop'

if (-not $ConfirmTestReadinessFoundation) {
    throw 'B14-0 acceptance requires -ConfirmTestReadinessFoundation.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

$commit = (& git rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Unable to resolve exact B14-0 acceptance commit.'
}
Write-Host ('B14-0 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Tracked working files differ from B14-0 acceptance commit.'
}

$frozen = '01df0a9c58b856cfe841909fb5c39f7ef71decb8'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Accepted Beta13 final predecessor missing.'
}

$checkpoint = (& git rev-parse 'refs/remotes/origin/checkpoint/v013-b137-pass' 2>$null)
if ($LASTEXITCODE -ne 0) {
    $checkpoint = (& git rev-parse 'checkpoint/v013-b137-pass' 2>$null)
}
if ($LASTEXITCODE -ne 0 -or ([string]$checkpoint).Trim().ToLowerInvariant() -ne $frozen) {
    throw 'Accepted Beta13 final checkpoint mismatch.'
}
Write-Host 'Accepted Beta13 final checkpoint identity: PASS'

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
$changes = @(& git diff --name-only $frozen HEAD)
$allowed = @(
    '.github/workflows/b140-verified-protection-test-readiness.yml',
    'ROADMAP.md',
    'sentinel/beta14_test_readiness.py',
    'tests/test_v014_b140_test_readiness.py',
    'tools/acceptance/TEST-V014-B140-TEST-READINESS.ps1'
)
if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B14-0 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) {
        throw ('Unexpected B14-0 changed path: ' + $path)
    }
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen Beta13 path changed: ' + $path)
    }
}
Write-Host 'Accepted Beta13 source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta14_test_readiness.py tests/test_v014_b140_test_readiness.py
if ($LASTEXITCODE -ne 0) {
    throw 'B14-0 compile failed.'
}

$patterns = @(
    'tests/test_v011_beta5_*.py',
    'tests/test_v011_beta6_*.py',
    'tests/test_v011_beta7_*.py',
    'tests/test_v011_beta8_*.py',
    'tests/test_v011_beta9_*.py',
    'tests/test_v011_beta10_*.py',
    'tests/test_v011_beta11_*.py',
    'tests/test_v012_beta12_*.py',
    'tests/test_v013_*.py',
    'tests/test_v014_*.py'
)
$tests = @(
    $patterns |
        ForEach-Object { Get-ChildItem $_ } |
        Sort-Object FullName |
        ForEach-Object { $_.FullName }
)
$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b140-pytest-' + [guid]::NewGuid().ToString('N'))
try {
    & $py -m pytest -q --basetemp $testBase @tests
    if ($LASTEXITCODE -ne 0) {
        throw 'Beta5 through Beta14 B14-0 regression failed.'
    }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

& $py -m sentinel.beta14_test_readiness
if ($LASTEXITCODE -ne 0) {
    throw 'B14-0 test-readiness contract self-check failed.'
}

$reportJson = & $py -c "import json; from sentinel.beta14_test_readiness import self_check; print(json.dumps(self_check(),sort_keys=True))"
if ($LASTEXITCODE -ne 0) {
    throw 'B14-0 readiness report generation failed.'
}
$report = $reportJson | ConvertFrom-Json

if (-not [bool]$report.passed) {
    throw 'B14-0 readiness report did not pass.'
}
if ([int]$report.verified_scenario_count -ne 7) {
    throw 'B14-0 verified scenario count changed unexpectedly.'
}
if ([int]$report.source_coverage.VERIFIED -ne 7 -or [int]$report.source_coverage.PARTIAL -ne 4 -or [int]$report.source_coverage.GAP -ne 0) {
    throw 'B14-0 canonical coverage changed unexpectedly.'
}
if ([bool]$report.independent_test_ready -or [bool]$report.independent_certification_claimed) {
    throw 'B14-0 incorrectly claims independent test readiness/certification.'
}
if (@($report.release_blockers).Count -ne 1 -or $report.release_blockers[0] -ne 'CODE_SIGNING') {
    throw 'B14-0 release blocker mismatch.'
}
if ([bool]$report.coverage_promoted -or [bool]$report.authority_expanded) {
    throw 'B14-0 expanded coverage or authority.'
}
if ([bool]$report.network_required -or [bool]$report.cloud_required) {
    throw 'B14-0 introduced mandatory network/cloud dependency.'
}

Write-Host ('B14-0 contract digest: ' + [string]$report.contract_digest)
Write-Host 'B14-0 evidence gates: READY=2 PARTIAL=3 BLOCKED=5'
Write-Host 'B14-0 safety: ordinary_CI_local_real_malware=false harmless_fixtures_only=true synthetic_only_cannot_promote_verified=true'
Write-Host 'B14-0 coverage: PARTIAL=4 GAP=0 VERIFIED=7 / promoted=false'
Write-Host 'B14-0 independent-test status: READY=false CERTIFIED=false'
Write-Host 'B14-0 release status: ENGINEERING_RC=inherited / PUBLIC_RELEASE=BLOCKED / remaining_release_blocker=CODE_SIGNING'
Write-Host 'BC SENTINEL v0.14.0 B14-0 VERIFIED PROTECTION & INDEPENDENT-TEST READINESS FOUNDATION - PASS'

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'B14-0 acceptance modified tracked repository sources.'
}
