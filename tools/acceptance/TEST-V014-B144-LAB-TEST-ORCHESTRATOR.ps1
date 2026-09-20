param(
    [switch]$ConfirmLabTestOrchestrator
)

$ErrorActionPreference = 'Stop'

if (-not $ConfirmLabTestOrchestrator) {
    throw 'B14-4 acceptance requires -ConfirmLabTestOrchestrator.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

$commit = (& git rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Unable to resolve exact B14-4 acceptance commit.'
}
Write-Host ('B14-4 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Tracked working files differ from B14-4 acceptance commit.'
}

$frozen = 'b807797b35e40dc34235c569e4f56b099824bca5'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Accepted B14-3 predecessor missing.'
}

$checkpoint = (& git rev-parse 'refs/remotes/origin/checkpoint/v014-b143-pass' 2>$null)
if ($LASTEXITCODE -ne 0) {
    $checkpoint = (& git rev-parse 'checkpoint/v014-b143-pass' 2>$null)
}
if ($LASTEXITCODE -ne 0 -or ([string]$checkpoint).Trim().ToLowerInvariant() -ne $frozen) {
    throw 'Accepted B14-3 checkpoint mismatch.'
}
Write-Host 'Accepted B14-3 checkpoint identity: PASS'

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
$changes = @(& git diff --name-only $frozen HEAD)
$allowed = @(
    '.github/workflows/b144-lab-test-orchestrator.yml',
    'ROADMAP.md',
    'sentinel/beta14_lab_test_orchestrator.py',
    'tests/test_v014_b144_lab_test_orchestrator.py',
    'tools/acceptance/TEST-V014-B144-LAB-TEST-ORCHESTRATOR.ps1'
)
if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B14-4 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) {
        throw ('Unexpected B14-4 changed path: ' + $path)
    }
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B14-3 path changed: ' + $path)
    }
}
Write-Host 'Accepted B14-3 source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta14_lab_test_orchestrator.py tests/test_v014_b144_lab_test_orchestrator.py
if ($LASTEXITCODE -ne 0) {
    throw 'B14-4 compile failed.'
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
$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b144-pytest-' + [guid]::NewGuid().ToString('N'))
try {
    & $py -m pytest -q --basetemp $testBase @tests
    if ($LASTEXITCODE -ne 0) {
        throw 'Beta5 through Beta14 B14-4 regression failed.'
    }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

& $py -m sentinel.beta14_lab_test_orchestrator
if ($LASTEXITCODE -ne 0) {
    throw 'B14-4 lab test orchestrator self-check failed.'
}

$reportJson = & $py -c "import json; from sentinel.beta14_lab_test_orchestrator import self_check; print(json.dumps(self_check(),sort_keys=True))"
if ($LASTEXITCODE -ne 0) {
    throw 'B14-4 report generation failed.'
}
$report = $reportJson | ConvertFrom-Json

if (-not [bool]$report.passed) {
    throw 'B14-4 report did not pass.'
}
if ([int]$report.tier_count -ne 6 -or [int]$report.plan_count -ne 6) {
    throw 'B14-4 T0-T5 inventory mismatch.'
}
if (-not [bool]$report.direct_internet_rejected) {
    throw 'B14-4 did not reject direct Internet dynamic-lab planning.'
}
if (-not [bool]$report.unauthorized_real_sample_rejected) {
    throw 'B14-4 did not reject unauthorized real-sample planning.'
}
if (-not [bool]$report.nonisolated_dynamic_rejected) {
    throw 'B14-4 did not reject non-isolated dynamic real-sample planning.'
}
if (-not [bool]$report.evidence_importer_required_for_all) {
    throw 'B14-4 does not require B14-3 evidence import for every tier.'
}
if (
    [bool]$report.orchestrator_executes_samples -or
    [bool]$report.orchestrator_downloads_samples -or
    [bool]$report.orchestrator_stores_samples -or
    [bool]$report.orchestrator_transfers_samples -or
    [bool]$report.orchestrator_unpacks_samples -or
    [bool]$report.orchestrator_opens_network_connections
) {
    throw 'B14-4 orchestrator gained prohibited sample/network authority.'
}
if ([bool]$report.coverage_promoted -or [bool]$report.authority_expanded) {
    throw 'B14-4 expanded coverage or authority.'
}
if ([int]$report.source_coverage.VERIFIED -ne 7 -or [int]$report.source_coverage.PARTIAL -ne 4 -or [int]$report.source_coverage.GAP -ne 0) {
    throw 'B14-4 canonical coverage changed unexpectedly.'
}

Write-Host ('B14-4 contract digest: ' + [string]$report.contract_digest)
Write-Host 'B14-4 campaign: tiers=6 plans=6 T0-T5=PASS'
Write-Host 'B14-4 real-sample policy: T2=static_only T3=isolated_dynamic only / authorization_required=true'
Write-Host 'B14-4 rejection gates: direct_internet=PASS unauthorized_sample=PASS nonisolated_dynamic=PASS'
Write-Host 'B14-4 orchestrator capabilities: execute=false download=false store=false transfer=false unpack=false network=false'
Write-Host 'B14-4 evidence: B14-3_importer_required_for_all=true'
Write-Host 'B14-4 coverage: PARTIAL=4 GAP=0 VERIFIED=7 / promoted=false'
Write-Host 'BC SENTINEL v0.14.0 B14-4 LAB TEST ORCHESTRATOR T0-T5 - PASS'

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'B14-4 acceptance modified tracked repository sources.'
}
