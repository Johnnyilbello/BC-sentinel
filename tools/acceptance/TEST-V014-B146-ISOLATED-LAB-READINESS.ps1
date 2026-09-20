param(
    [switch]$ConfirmIsolatedLabReadiness
)

$ErrorActionPreference = 'Stop'

if (-not $ConfirmIsolatedLabReadiness) {
    throw 'B14-6 acceptance requires -ConfirmIsolatedLabReadiness.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

$commit = (& git rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Unable to resolve exact B14-6 acceptance commit.'
}
Write-Host ('B14-6 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Tracked working files differ from B14-6 acceptance commit.'
}

$frozen = 'e8fd49ca12f51e132d497913d01d3edc07f020a3'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Accepted B14-5 predecessor missing.'
}

$checkpoint = (& git rev-parse 'refs/remotes/origin/checkpoint/v014-b145-pass' 2>$null)
if ($LASTEXITCODE -ne 0) {
    $checkpoint = (& git rev-parse 'checkpoint/v014-b145-pass' 2>$null)
}
if ($LASTEXITCODE -ne 0 -or ([string]$checkpoint).Trim().ToLowerInvariant() -ne $frozen) {
    throw 'Accepted B14-5 checkpoint mismatch.'
}
Write-Host 'Accepted B14-5 checkpoint identity: PASS'

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
$changes = @(& git diff --name-only $frozen HEAD)
$allowed = @(
    '.github/workflows/b146-isolated-lab-readiness.yml',
    'ROADMAP.md',
    'sentinel/beta14_isolated_lab_readiness.py',
    'tests/test_v014_b146_isolated_lab_readiness.py',
    'tools/acceptance/TEST-V014-B146-ISOLATED-LAB-READINESS.ps1'
)
if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B14-6 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) {
        throw ('Unexpected B14-6 changed path: ' + $path)
    }
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B14-5 path changed: ' + $path)
    }
}
Write-Host 'Accepted B14-5 source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta14_isolated_lab_readiness.py tests/test_v014_b146_isolated_lab_readiness.py
if ($LASTEXITCODE -ne 0) {
    throw 'B14-6 compile failed.'
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
$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b146-pytest-' + [guid]::NewGuid().ToString('N'))
try {
    & $py -m pytest -q --basetemp $testBase @tests
    if ($LASTEXITCODE -ne 0) {
        throw 'Beta5 through Beta14 B14-6 regression failed.'
    }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

& $py -m sentinel.beta14_isolated_lab_readiness
if ($LASTEXITCODE -ne 0) {
    throw 'B14-6 isolated lab readiness self-check failed.'
}

$reportJson = & $py -c "import json; from sentinel.beta14_isolated_lab_readiness import self_check; print(json.dumps(self_check(),sort_keys=True))"
if ($LASTEXITCODE -ne 0) {
    throw 'B14-6 report generation failed.'
}
$report = $reportJson | ConvertFrom-Json

if (-not [bool]$report.passed) {
    throw 'B14-6 report did not pass.'
}
if (-not [bool]$report.t2_ready -or -not [bool]$report.t3_ready) {
    throw 'B14-6 baseline T2/T3 readiness contract did not pass.'
}
if (-not [bool]$report.direct_internet_rejected) {
    throw 'B14-6 did not reject direct Internet.'
}
if (-not [bool]$report.bridged_network_rejected) {
    throw 'B14-6 did not reject bridged networking.'
}
if (-not [bool]$report.missing_revert_rejected) {
    throw 'B14-6 did not reject missing snapshot/revert verification.'
}
if (-not [bool]$report.shared_host_surface_rejected) {
    throw 'B14-6 did not reject shared host surfaces.'
}
if (-not [bool]$report.raw_sample_export_rejected) {
    throw 'B14-6 did not reject raw sample export.'
}
if (
    [bool]$report.sample_execution_capability_in_module -or
    [bool]$report.sample_download_capability_in_module -or
    [bool]$report.sample_transfer_capability_in_module -or
    [bool]$report.hypervisor_mutation_capability_in_module
) {
    throw 'B14-6 readiness module gained prohibited authority.'
}
if ([bool]$report.coverage_promoted -or [bool]$report.authority_expanded) {
    throw 'B14-6 expanded coverage or authority.'
}
if ([int]$report.source_coverage.VERIFIED -ne 7 -or [int]$report.source_coverage.PARTIAL -ne 4 -or [int]$report.source_coverage.GAP -ne 0) {
    throw 'B14-6 canonical coverage changed unexpectedly.'
}

Write-Host ('B14-6 contract digest: ' + [string]$report.contract_digest)
Write-Host 'B14-6 lab baseline: dedicated_host=PASS snapshot_revert=PASS isolated_network=PASS'
Write-Host 'B14-6 network policy: NONE/DROP/INETSIM only / direct_internet=REJECTED bridged=REJECTED normal_nat=REJECTED'
Write-Host 'B14-6 host isolation: shared_folders=false clipboard=false dragdrop=false usb_passthrough=false host_drive_mount=false'
Write-Host 'B14-6 evidence policy: B14-3_importer=true raw_sample_export=false sensitive_exports=false'
Write-Host 'B14-6 readiness: T2_STATIC=READY T3_ISOLATED_DYNAMIC=READY'
Write-Host 'B14-6 coverage: PARTIAL=4 GAP=0 VERIFIED=7 / promoted=false'
Write-Host 'BC SENTINEL v0.14.0 B14-6 ISOLATED LAB READINESS - PASS'

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'B14-6 acceptance modified tracked repository sources.'
}
