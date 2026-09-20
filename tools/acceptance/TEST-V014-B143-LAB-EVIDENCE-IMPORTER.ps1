param(
    [switch]$ConfirmIsolatedLabEvidenceImporter
)

$ErrorActionPreference = 'Stop'

if (-not $ConfirmIsolatedLabEvidenceImporter) {
    throw 'B14-3 acceptance requires -ConfirmIsolatedLabEvidenceImporter.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

$commit = (& git rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Unable to resolve exact B14-3 acceptance commit.'
}
Write-Host ('B14-3 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Tracked working files differ from B14-3 acceptance commit.'
}

$frozen = '346f3d2ffb61db09437d82c3762991b3c25c45b7'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Accepted B14-2 predecessor missing.'
}

$checkpoint = (& git rev-parse 'refs/remotes/origin/checkpoint/v014-b142-pass' 2>$null)
if ($LASTEXITCODE -ne 0) {
    $checkpoint = (& git rev-parse 'checkpoint/v014-b142-pass' 2>$null)
}
if ($LASTEXITCODE -ne 0 -or ([string]$checkpoint).Trim().ToLowerInvariant() -ne $frozen) {
    throw 'Accepted B14-2 checkpoint mismatch.'
}
Write-Host 'Accepted B14-2 checkpoint identity: PASS'

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
$changes = @(& git diff --name-only $frozen HEAD)
$allowed = @(
    '.github/workflows/b143-isolated-lab-evidence-importer.yml',
    'ROADMAP.md',
    'sentinel/beta14_lab_evidence_importer.py',
    'tests/test_v014_b143_lab_evidence_importer.py',
    'tools/acceptance/TEST-V014-B143-LAB-EVIDENCE-IMPORTER.ps1'
)
if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B14-3 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) {
        throw ('Unexpected B14-3 changed path: ' + $path)
    }
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B14-2 path changed: ' + $path)
    }
}
Write-Host 'Accepted B14-2 source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta14_lab_evidence_importer.py tests/test_v014_b143_lab_evidence_importer.py
if ($LASTEXITCODE -ne 0) {
    throw 'B14-3 compile failed.'
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
$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b143-pytest-' + [guid]::NewGuid().ToString('N'))
try {
    & $py -m pytest -q --basetemp $testBase @tests
    if ($LASTEXITCODE -ne 0) {
        throw 'Beta5 through Beta14 B14-3 regression failed.'
    }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

& $py -m sentinel.beta14_lab_evidence_importer
if ($LASTEXITCODE -ne 0) {
    throw 'B14-3 lab evidence importer self-check failed.'
}

$reportJson = & $py -c "import json; from sentinel.beta14_lab_evidence_importer import self_check; print(json.dumps(self_check(),sort_keys=True))"
if ($LASTEXITCODE -ne 0) {
    throw 'B14-3 report generation failed.'
}
$report = $reportJson | ConvertFrom-Json

if (-not [bool]$report.passed) {
    throw 'B14-3 report did not pass.'
}
if ([int]$report.fixture_record_count -ne 3 -or [int]$report.fixture_authoritative_count -ne 3) {
    throw 'B14-3 fixture evidence inventory mismatch.'
}
if (-not [bool]$report.direct_internet_rejected) {
    throw 'B14-3 did not reject direct Internet evidence.'
}
if (-not [bool]$report.missing_revert_rejected) {
    throw 'B14-3 did not reject missing cleanup/revert evidence.'
}
if (-not [bool]$report.raw_sample_bytes_rejected) {
    throw 'B14-3 did not reject raw sample bytes.'
}
if ([bool]$report.sample_execution_capability_in_importer) {
    throw 'B14-3 importer unexpectedly gained sample execution capability.'
}
if ([bool]$report.sample_storage_capability_in_importer) {
    throw 'B14-3 importer unexpectedly gained sample storage capability.'
}
if ([bool]$report.sample_transfer_capability_in_importer) {
    throw 'B14-3 importer unexpectedly gained sample transfer capability.'
}
if ([bool]$report.coverage_promoted -or [bool]$report.authority_expanded) {
    throw 'B14-3 expanded coverage or authority.'
}
if ([int]$report.source_coverage.VERIFIED -ne 7 -or [int]$report.source_coverage.PARTIAL -ne 4 -or [int]$report.source_coverage.GAP -ne 0) {
    throw 'B14-3 canonical coverage changed unexpectedly.'
}

Write-Host ('B14-3 contract digest: ' + [string]$report.contract_digest)
Write-Host 'B14-3 importer: authorized_isolated_dynamic=PASS authorized_static=PASS benign=PASS'
Write-Host 'B14-3 rejection gates: direct_internet=PASS missing_revert=PASS raw_sample_bytes=PASS sensitive_exports=PASS'
Write-Host 'B14-3 capabilities: execute_sample=false store_sample=false transfer_sample=false unpack_sample=false'
Write-Host 'B14-3 evidence policy: sanitized_metadata_only=true authoritative_lab_binding=true'
Write-Host 'B14-3 coverage: PARTIAL=4 GAP=0 VERIFIED=7 / promoted=false'
Write-Host 'BC SENTINEL v0.14.0 B14-3 ISOLATED LAB EVIDENCE IMPORTER - PASS'

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'B14-3 acceptance modified tracked repository sources.'
}
