param(
    [switch]$ConfirmExternalLabProvisioningEvidence
)

$ErrorActionPreference = 'Stop'

if (-not $ConfirmExternalLabProvisioningEvidence) {
    throw 'B14-9 acceptance requires -ConfirmExternalLabProvisioningEvidence.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

$commit = (& git rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Unable to resolve exact B14-9 acceptance commit.'
}
Write-Host ('B14-9 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Tracked working files differ from B14-9 acceptance commit.'
}

$frozen = '8df6218b2db9e7738b2e2f719531fd24912ad0bc'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Accepted B14-8 predecessor missing.'
}

$checkpoint = (& git rev-parse 'refs/remotes/origin/checkpoint/v014-b148-pass' 2>$null)
if ($LASTEXITCODE -ne 0) {
    $checkpoint = (& git rev-parse 'checkpoint/v014-b148-pass' 2>$null)
}
if ($LASTEXITCODE -ne 0 -or ([string]$checkpoint).Trim().ToLowerInvariant() -ne $frozen) {
    throw 'Accepted B14-8 checkpoint mismatch.'
}
Write-Host 'Accepted B14-8 checkpoint identity: PASS'

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
$changes = @(& git diff --name-only $frozen HEAD)
$allowed = @(
    '.github/workflows/b149-external-lab-provisioning-evidence.yml',
    'ROADMAP.md',
    'sentinel/beta14_external_lab_provisioning_evidence.py',
    'tests/test_v014_b149_external_lab_provisioning_evidence.py',
    'tools/acceptance/TEST-V014-B149-EXTERNAL-LAB-PROVISIONING.ps1'
)
if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B14-9 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) {
        throw ('Unexpected B14-9 changed path: ' + $path)
    }
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B14-8 path changed: ' + $path)
    }
}
Write-Host 'Accepted B14-8 source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta14_external_lab_provisioning_evidence.py tests/test_v014_b149_external_lab_provisioning_evidence.py
if ($LASTEXITCODE -ne 0) {
    throw 'B14-9 compile failed.'
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
$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b149-pytest-' + [guid]::NewGuid().ToString('N'))
try {
    & $py -m pytest -q --basetemp $testBase @tests
    if ($LASTEXITCODE -ne 0) {
        throw 'Beta5 through Beta14 B14-9 regression failed.'
    }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

& $py -m sentinel.beta14_external_lab_provisioning_evidence
if ($LASTEXITCODE -ne 0) {
    throw 'B14-9 provisioning evidence self-check failed.'
}

$reportJson = & $py -c "import json; from sentinel.beta14_external_lab_provisioning_evidence import self_check; print(json.dumps(self_check(),sort_keys=True))"
if ($LASTEXITCODE -ne 0) {
    throw 'B14-9 report generation failed.'
}
$report = $reportJson | ConvertFrom-Json

if (-not [bool]$report.passed) {
    throw 'B14-9 report did not pass.'
}
if (-not [bool]$report.ci_fixture_valid) {
    throw 'B14-9 CI fixture did not validate.'
}
if ([bool]$report.ci_fixture_authoritative_physical_lab) {
    throw 'B14-9 CI fixture incorrectly claimed a physical lab.'
}
if ([bool]$report.ci_fixture_t2_real_campaign_ready -or [bool]$report.ci_fixture_t3_real_campaign_ready) {
    throw 'B14-9 CI fixture incorrectly claimed real campaign readiness.'
}
if (-not [bool]$report.real_observation_can_be_authoritative) {
    throw 'B14-9 real-host observation path cannot become authoritative.'
}
if (-not [bool]$report.direct_internet_rejected) {
    throw 'B14-9 did not reject direct Internet.'
}
if (-not [bool]$report.missing_revert_drill_rejected) {
    throw 'B14-9 did not reject missing revert drill.'
}
if (-not [bool]$report.shared_host_surface_rejected) {
    throw 'B14-9 did not reject shared host surfaces.'
}
if (
    [bool]$report.module_creates_vms -or
    [bool]$report.module_modifies_networking -or
    [bool]$report.module_manages_hypervisor -or
    [bool]$report.module_executes_samples -or
    [bool]$report.module_downloads_samples -or
    [bool]$report.module_stores_samples -or
    [bool]$report.module_transfers_samples -or
    [bool]$report.module_unpacks_samples
) {
    throw 'B14-9 module gained prohibited authority.'
}
if ([bool]$report.coverage_promoted -or [bool]$report.authority_expanded) {
    throw 'B14-9 expanded coverage or authority.'
}

Write-Host ('B14-9 contract digest: ' + [string]$report.contract_digest)
Write-Host 'B14-9 evidence classes: CI_FIXTURE=VALID_NON_AUTHORITATIVE REAL_HOST_OBSERVATION=ONLY_AUTHORITATIVE_PATH'
Write-Host 'B14-9 CI boundary: physical_lab=false T2_real_ready=false T3_real_ready=false'
Write-Host 'B14-9 provisioning gates: dedicated_host snapshot_revert revert_drill isolated_network management_separation firewall=REQUIRED'
Write-Host 'B14-9 isolation: direct_internet=REJECTED bridge=REJECTED normal_nat=REJECTED shared_host_surfaces=REJECTED'
Write-Host 'B14-9 module capabilities: create_vm=false modify_network=false manage_hypervisor=false execute=false download=false store=false transfer=false unpack=false'
Write-Host 'B14-9 coverage: PARTIAL=4 GAP=0 VERIFIED=7 / promoted=false'
Write-Host 'BC SENTINEL v0.14.0 B14-9 EXTERNAL LAB PROVISIONING EVIDENCE - PASS'

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'B14-9 acceptance modified tracked repository sources.'
}
