param(
    [switch]$ConfirmDetectorEmulationIntegration
)

$ErrorActionPreference = 'Stop'

if (-not $ConfirmDetectorEmulationIntegration) {
    throw 'B14-2 acceptance requires -ConfirmDetectorEmulationIntegration.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

$commit = (& git rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Unable to resolve exact B14-2 acceptance commit.'
}
Write-Host ('B14-2 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Tracked working files differ from B14-2 acceptance commit.'
}

$frozen = 'b2a00aac183905ec7f5988ef558dcf5612761ad5'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Accepted B14-1 predecessor missing.'
}

$checkpoint = (& git rev-parse 'refs/remotes/origin/checkpoint/v014-b141-pass' 2>$null)
if ($LASTEXITCODE -ne 0) {
    $checkpoint = (& git rev-parse 'checkpoint/v014-b141-pass' 2>$null)
}
if ($LASTEXITCODE -ne 0 -or ([string]$checkpoint).Trim().ToLowerInvariant() -ne $frozen) {
    throw 'Accepted B14-1 checkpoint mismatch.'
}
Write-Host 'Accepted B14-1 checkpoint identity: PASS'

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
$changes = @(& git diff --name-only $frozen HEAD)
$allowed = @(
    '.github/workflows/b142-detector-emulation-integration.yml',
    'ROADMAP.md',
    'sentinel/beta14_detector_emulation_integration.py',
    'tests/test_v014_b142_detector_emulation_integration.py',
    'tools/acceptance/TEST-V014-B142-DETECTOR-EMULATION-INTEGRATION.ps1'
)
if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B14-2 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) {
        throw ('Unexpected B14-2 changed path: ' + $path)
    }
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B14-1 path changed: ' + $path)
    }
}
Write-Host 'Accepted B14-1 source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta14_detector_emulation_integration.py tests/test_v014_b142_detector_emulation_integration.py
if ($LASTEXITCODE -ne 0) {
    throw 'B14-2 compile failed.'
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
$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b142-pytest-' + [guid]::NewGuid().ToString('N'))
try {
    & $py -m pytest -q --basetemp $testBase @tests
    if ($LASTEXITCODE -ne 0) {
        throw 'Beta5 through Beta14 B14-2 regression failed.'
    }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

& $py -m sentinel.beta14_detector_emulation_integration
if ($LASTEXITCODE -ne 0) {
    throw 'B14-2 detector/emulation integration self-check failed.'
}

$reportJson = & $py -c "import json; from sentinel.beta14_detector_emulation_integration import self_check; print(json.dumps(self_check(),sort_keys=True))"
if ($LASTEXITCODE -ne 0) {
    throw 'B14-2 report generation failed.'
}
$report = $reportJson | ConvertFrom-Json

if (-not [bool]$report.passed) {
    throw 'B14-2 report did not pass.'
}
if ([int]$report.binding_count -ne 6 -or [int]$report.bound_count -ne 5 -or [int]$report.explicit_gap_count -ne 1) {
    throw 'B14-2 detector binding inventory mismatch.'
}
if ([string]$report.explicit_gap_family -ne 'ARCHIVE_METADATA') {
    throw 'B14-2 explicit gap family mismatch.'
}
if ([bool]$report.real_attack_execution -or [bool]$report.real_malware_executed -or [bool]$report.network_io) {
    throw 'B14-2 unsafe execution/network boundary violated.'
}
if ([bool]$report.credential_access -or [bool]$report.real_persistence_mutation -or [bool]$report.real_data_encryption) {
    throw 'B14-2 sensitive/destructive boundary violated.'
}
if ([bool]$report.detector_threshold_mutation -or [bool]$report.coverage_promoted -or [bool]$report.authority_expanded) {
    throw 'B14-2 detector/coverage/authority boundary violated.'
}
if ([int]$report.source_coverage.VERIFIED -ne 7 -or [int]$report.source_coverage.PARTIAL -ne 4 -or [int]$report.source_coverage.GAP -ne 0) {
    throw 'B14-2 canonical coverage changed unexpectedly.'
}

Write-Host ('B14-2 contract digest: ' + [string]$report.contract_digest)
Write-Host 'B14-2 detector bindings: total=6 bound=5 explicit_gap=1 gap_family=ARCHIVE_METADATA'
Write-Host 'B14-2 safety: real_attack=false real_malware=false network=false credentials=false persistence=false real_encryption=false'
Write-Host 'B14-2 detector policy: thresholds_unchanged=true attack_payload_invocation=false'
Write-Host 'B14-2 coverage: PARTIAL=4 GAP=0 VERIFIED=7 / promoted=false'
Write-Host 'BC SENTINEL v0.14.0 B14-2 DETECTOR / EMULATION INTEGRATION - PASS'

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'B14-2 acceptance modified tracked repository sources.'
}
