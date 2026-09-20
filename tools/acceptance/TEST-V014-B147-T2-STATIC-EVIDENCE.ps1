param(
    [switch]$ConfirmT2StaticEvidence
)

$ErrorActionPreference = 'Stop'

if (-not $ConfirmT2StaticEvidence) {
    throw 'B14-7 acceptance requires -ConfirmT2StaticEvidence.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

$commit = (& git rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Unable to resolve exact B14-7 acceptance commit.'
}
Write-Host ('B14-7 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Tracked working files differ from B14-7 acceptance commit.'
}

$frozen = '98a702e178e8ef07da2c25751efcf5d1a7c2006f'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Accepted B14-6 predecessor missing.'
}

$checkpoint = (& git rev-parse 'refs/remotes/origin/checkpoint/v014-b146-pass' 2>$null)
if ($LASTEXITCODE -ne 0) {
    $checkpoint = (& git rev-parse 'checkpoint/v014-b146-pass' 2>$null)
}
if ($LASTEXITCODE -ne 0 -or ([string]$checkpoint).Trim().ToLowerInvariant() -ne $frozen) {
    throw 'Accepted B14-6 checkpoint mismatch.'
}
Write-Host 'Accepted B14-6 checkpoint identity: PASS'

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
$changes = @(& git diff --name-only $frozen HEAD)
$allowed = @(
    '.github/workflows/b147-t2-static-real-sample-evidence.yml',
    'ROADMAP.md',
    'sentinel/beta14_t2_static_real_sample_evidence.py',
    'tests/test_v014_b147_t2_static_real_sample_evidence.py',
    'tools/acceptance/TEST-V014-B147-T2-STATIC-EVIDENCE.ps1'
)
if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B14-7 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) {
        throw ('Unexpected B14-7 changed path: ' + $path)
    }
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B14-6 path changed: ' + $path)
    }
}
Write-Host 'Accepted B14-6 source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta14_t2_static_real_sample_evidence.py tests/test_v014_b147_t2_static_real_sample_evidence.py
if ($LASTEXITCODE -ne 0) {
    throw 'B14-7 compile failed.'
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
$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b147-pytest-' + [guid]::NewGuid().ToString('N'))
try {
    & $py -m pytest -q --basetemp $testBase @tests
    if ($LASTEXITCODE -ne 0) {
        throw 'Beta5 through Beta14 B14-7 regression failed.'
    }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

& $py -m sentinel.beta14_t2_static_real_sample_evidence
if ($LASTEXITCODE -ne 0) {
    throw 'B14-7 T2 static evidence self-check failed.'
}

$reportJson = & $py -c "import json; from sentinel.beta14_t2_static_real_sample_evidence import self_check; print(json.dumps(self_check(),sort_keys=True))"
if ($LASTEXITCODE -ne 0) {
    throw 'B14-7 report generation failed.'
}
$report = $reportJson | ConvertFrom-Json

if (-not [bool]$report.passed) {
    throw 'B14-7 report did not pass.'
}
if ([int]$report.fixture_sample_count -ne 4) {
    throw 'B14-7 fixture sample inventory mismatch.'
}
if (-not [bool]$report.sample_execution_rejected) {
    throw 'B14-7 did not reject sample execution.'
}
if (-not [bool]$report.network_rejected) {
    throw 'B14-7 did not reject networked T2 evidence.'
}
if (-not [bool]$report.raw_sample_export_rejected) {
    throw 'B14-7 did not reject raw sample export.'
}
if (
    [bool]$report.sample_download_capability -or
    [bool]$report.sample_storage_capability -or
    [bool]$report.sample_transfer_capability -or
    [bool]$report.sample_unpack_capability
) {
    throw 'B14-7 gained prohibited sample-handling capability.'
}
if ([bool]$report.real_sample_executed -or [bool]$report.network_io -or [bool]$report.raw_sample_bytes_imported) {
    throw 'B14-7 static-only boundary violated.'
}
if ([bool]$report.coverage_promoted -or [bool]$report.authority_expanded -or [bool]$report.independent_certification_claimed) {
    throw 'B14-7 expanded claims or authority.'
}
if ([int]$report.source_coverage.VERIFIED -ne 7 -or [int]$report.source_coverage.PARTIAL -ne 4 -or [int]$report.source_coverage.GAP -ne 0) {
    throw 'B14-7 canonical coverage changed unexpectedly.'
}

Write-Host ('B14-7 contract digest: ' + [string]$report.contract_digest)
Write-Host 'B14-7 T2 policy: authorized_real_samples=true execution=false network=NONE only'
Write-Host 'B14-7 evidence: DETECTED/MISSED/ERROR explicit / B14-3 bridge=PASS'
Write-Host 'B14-7 safety: download=false store=false transfer=false unpack=false raw_sample_export=false'
Write-Host 'B14-7 metrics: static_detection_rate=MEASURED latency=MEASURED category_distribution=MEASURED'
Write-Host 'B14-7 coverage: PARTIAL=4 GAP=0 VERIFIED=7 / promoted=false'
Write-Host 'BC SENTINEL v0.14.0 B14-7 T2 STATIC REAL-SAMPLE EVIDENCE - PASS'

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'B14-7 acceptance modified tracked repository sources.'
}
