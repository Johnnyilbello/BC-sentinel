param(
    [switch]$ConfirmSafeAdversaryMatrix
)

$ErrorActionPreference = 'Stop'

if (-not $ConfirmSafeAdversaryMatrix) {
    throw 'B14-1 acceptance requires -ConfirmSafeAdversaryMatrix.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

$commit = (& git rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Unable to resolve exact B14-1 acceptance commit.'
}
Write-Host ('B14-1 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Tracked working files differ from B14-1 acceptance commit.'
}

$frozen = 'a29de186a95d006b83fcb4e1c17992068b216255'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Accepted B14-0 predecessor missing.'
}

$checkpoint = (& git rev-parse 'refs/remotes/origin/checkpoint/v014-b140-pass' 2>$null)
if ($LASTEXITCODE -ne 0) {
    $checkpoint = (& git rev-parse 'checkpoint/v014-b140-pass' 2>$null)
}
if ($LASTEXITCODE -ne 0 -or ([string]$checkpoint).Trim().ToLowerInvariant() -ne $frozen) {
    throw 'Accepted B14-0 checkpoint mismatch.'
}
Write-Host 'Accepted B14-0 checkpoint identity: PASS'

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
$changes = @(& git diff --name-only $frozen HEAD)
$allowed = @(
    '.github/workflows/b141-safe-adversary-emulation-matrix.yml',
    'ROADMAP.md',
    'sentinel/beta14_safe_adversary_matrix.py',
    'tests/test_v014_b141_safe_adversary_matrix.py',
    'tools/acceptance/TEST-V014-B141-SAFE-ADVERSARY-MATRIX.ps1'
)
if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B14-1 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) {
        throw ('Unexpected B14-1 changed path: ' + $path)
    }
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B14-0 path changed: ' + $path)
    }
}
Write-Host 'Accepted B14-0 source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta14_safe_adversary_matrix.py tests/test_v014_b141_safe_adversary_matrix.py
if ($LASTEXITCODE -ne 0) {
    throw 'B14-1 compile failed.'
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
$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b141-pytest-' + [guid]::NewGuid().ToString('N'))
try {
    & $py -m pytest -q --basetemp $testBase @tests
    if ($LASTEXITCODE -ne 0) {
        throw 'Beta5 through Beta14 B14-1 regression failed.'
    }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

& $py -m sentinel.beta14_safe_adversary_matrix
if ($LASTEXITCODE -ne 0) {
    throw 'B14-1 safe adversary matrix self-check failed.'
}

$reportJson = & $py -c "import json; from sentinel.beta14_safe_adversary_matrix import self_check; print(json.dumps(self_check(),sort_keys=True))"
if ($LASTEXITCODE -ne 0) {
    throw 'B14-1 report generation failed.'
}
$report = $reportJson | ConvertFrom-Json

if (-not [bool]$report.passed) {
    throw 'B14-1 report did not pass.'
}
if ([int]$report.scenario_count -ne 6 -or [int]$report.control_count -ne 18) {
    throw 'B14-1 scenario/control inventory mismatch.'
}
if ([int]$report.positive_alerts -ne 6) {
    throw 'B14-1 positive control count mismatch.'
}
if ([int]$report.administrative_reviews -ne 6) {
    throw 'B14-1 administrative review count mismatch.'
}
if ([int]$report.benign_no_alerts -ne 6) {
    throw 'B14-1 benign control count mismatch.'
}
if ([bool]$report.real_malware_executed -or [bool]$report.network_io -or [bool]$report.credential_access) {
    throw 'B14-1 unsafe execution/network/credential boundary violated.'
}
if ([bool]$report.real_persistence_mutation -or [bool]$report.real_data_encryption) {
    throw 'B14-1 persistence/encryption boundary violated.'
}
if ([bool]$report.coverage_promoted -or [bool]$report.authority_expanded) {
    throw 'B14-1 expanded coverage or authority.'
}
if ([int]$report.source_coverage.VERIFIED -ne 7 -or [int]$report.source_coverage.PARTIAL -ne 4 -or [int]$report.source_coverage.GAP -ne 0) {
    throw 'B14-1 canonical coverage changed unexpectedly.'
}

Write-Host ('B14-1 contract digest: ' + [string]$report.contract_digest)
Write-Host 'B14-1 matrix: scenarios=6 controls=18 positive_alerts=6 admin_reviews=6 benign_no_alerts=6'
Write-Host 'B14-1 safety: metadata_only=true real_malware=false network=false credentials=false persistence=false real_encryption=false'
Write-Host 'B14-1 coverage: PARTIAL=4 GAP=0 VERIFIED=7 / promoted=false'
Write-Host 'B14-1 authority: expanded=false / remediation_expansion=false'
Write-Host 'BC SENTINEL v0.14.0 B14-1 SAFE ADVERSARY EMULATION MATRIX - PASS'

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'B14-1 acceptance modified tracked repository sources.'
}
