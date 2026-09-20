param(
    [switch]$ConfirmT3DynamicEvidence
)

$ErrorActionPreference = 'Stop'

if (-not $ConfirmT3DynamicEvidence) {
    throw 'B14-8 acceptance requires -ConfirmT3DynamicEvidence.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

$commit = (& git rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Unable to resolve exact B14-8 acceptance commit.'
}
Write-Host ('B14-8 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Tracked working files differ from B14-8 acceptance commit.'
}

$frozen = '4b4bcb4d11ee1ac6847f1dba3a353f6976c959b2'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Accepted B14-7 predecessor missing.'
}

$checkpoint = (& git rev-parse 'refs/remotes/origin/checkpoint/v014-b147-pass' 2>$null)
if ($LASTEXITCODE -ne 0) {
    $checkpoint = (& git rev-parse 'checkpoint/v014-b147-pass' 2>$null)
}
if ($LASTEXITCODE -ne 0 -or ([string]$checkpoint).Trim().ToLowerInvariant() -ne $frozen) {
    throw 'Accepted B14-7 checkpoint mismatch.'
}
Write-Host 'Accepted B14-7 checkpoint identity: PASS'

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
$changes = @(& git diff --name-only $frozen HEAD)
$allowed = @(
    '.github/workflows/b148-t3-isolated-dynamic-evidence.yml',
    'ROADMAP.md',
    'sentinel/beta14_t3_isolated_dynamic_evidence.py',
    'tests/test_v014_b148_t3_isolated_dynamic_evidence.py',
    'tools/acceptance/TEST-V014-B148-T3-DYNAMIC-EVIDENCE.ps1'
)
if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B14-8 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) {
        throw ('Unexpected B14-8 changed path: ' + $path)
    }
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B14-7 path changed: ' + $path)
    }
}
Write-Host 'Accepted B14-7 source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta14_t3_isolated_dynamic_evidence.py tests/test_v014_b148_t3_isolated_dynamic_evidence.py
if ($LASTEXITCODE -ne 0) {
    throw 'B14-8 compile failed.'
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
$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b148-pytest-' + [guid]::NewGuid().ToString('N'))
try {
    & $py -m pytest -q --basetemp $testBase @tests
    if ($LASTEXITCODE -ne 0) {
        throw 'Beta5 through Beta14 B14-8 regression failed.'
    }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

& $py -m sentinel.beta14_t3_isolated_dynamic_evidence
if ($LASTEXITCODE -ne 0) {
    throw 'B14-8 T3 dynamic evidence self-check failed.'
}

$reportJson = & $py -c "import json; from sentinel.beta14_t3_isolated_dynamic_evidence import self_check; print(json.dumps(self_check(),sort_keys=True))"
if ($LASTEXITCODE -ne 0) {
    throw 'B14-8 report generation failed.'
}
$report = $reportJson | ConvertFrom-Json

if (-not [bool]$report.passed) {
    throw 'B14-8 report did not pass.'
}
if ([int]$report.fixture_sample_count -ne 5) {
    throw 'B14-8 fixture inventory mismatch.'
}
if (-not [bool]$report.direct_internet_rejected) {
    throw 'B14-8 did not reject direct Internet evidence.'
}
if (-not [bool]$report.host_escape_rejected) {
    throw 'B14-8 did not reject host escape evidence.'
}
if (-not [bool]$report.propagation_rejected) {
    throw 'B14-8 did not reject propagation beyond guest.'
}
if (-not [bool]$report.missing_revert_rejected) {
    throw 'B14-8 did not reject missing snapshot/revert evidence.'
}
if (-not [bool]$report.raw_sample_export_rejected) {
    throw 'B14-8 did not reject raw sample export.'
}
if (
    [bool]$report.sample_execution_capability_in_module -or
    [bool]$report.sample_download_capability_in_module -or
    [bool]$report.sample_storage_capability_in_module -or
    [bool]$report.sample_transfer_capability_in_module -or
    [bool]$report.sample_unpack_capability_in_module -or
    [bool]$report.network_route_creation_capability_in_module
) {
    throw 'B14-8 module gained prohibited sample/network authority.'
}
if (
    [bool]$report.direct_internet_observed -or
    [bool]$report.propagation_beyond_guest -or
    [bool]$report.host_escape_observed -or
    [bool]$report.real_user_data_touched -or
    [bool]$report.credential_material_exported -or
    [bool]$report.security_control_impairment_succeeded -or
    [bool]$report.raw_sample_bytes_imported
) {
    throw 'B14-8 dynamic safety boundary violated.'
}
if ([bool]$report.coverage_promoted -or [bool]$report.authority_expanded -or [bool]$report.independent_certification_claimed) {
    throw 'B14-8 expanded claims or authority.'
}
if ([int]$report.source_coverage.VERIFIED -ne 7 -or [int]$report.source_coverage.PARTIAL -ne 4 -or [int]$report.source_coverage.GAP -ne 0) {
    throw 'B14-8 canonical coverage changed unexpectedly.'
}

Write-Host ('B14-8 contract digest: ' + [string]$report.contract_digest)
Write-Host 'B14-8 T3 evidence: authorized_dynamic=true isolated_guest=true one_sample_per_revert=true'
Write-Host 'B14-8 network policy: NONE/FAKE_SERVICES/INETSIM only / direct_internet=REJECTED'
Write-Host 'B14-8 containment: host_escape=REJECTED propagation=REJECTED real_user_data=REJECTED control_impairment=REJECTED'
Write-Host 'B14-8 evidence: BLOCKED/DETECTED/REVIEW_REQUIRED/MISSED/ERROR explicit / B14-3 bridge=PASS'
Write-Host 'B14-8 metrics: dynamic_protection_rate=MEASURED latency=MEASURED behavior_distribution=MEASURED'
Write-Host 'B14-8 module capabilities: execute=false download=false store=false transfer=false unpack=false create_routes=false'
Write-Host 'B14-8 coverage: PARTIAL=4 GAP=0 VERIFIED=7 / promoted=false'
Write-Host 'BC SENTINEL v0.14.0 B14-8 T3 ISOLATED DYNAMIC EVIDENCE - PASS'

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'B14-8 acceptance modified tracked repository sources.'
}
