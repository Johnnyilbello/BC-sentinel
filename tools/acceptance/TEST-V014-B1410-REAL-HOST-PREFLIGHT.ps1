param(
    [switch]$ConfirmRealHostPreflight
)

$ErrorActionPreference = 'Stop'

if (-not $ConfirmRealHostPreflight) {
    throw 'B14-10 acceptance requires -ConfirmRealHostPreflight.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

$commit = (& git rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Unable to resolve exact B14-10 acceptance commit.'
}
Write-Host ('B14-10 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Tracked working files differ from B14-10 acceptance commit.'
}

$frozen = 'e743af638f97860aaa0cfebbdfdbf8efc484a973'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Accepted B14-9 predecessor missing.'
}

$checkpoint = (& git rev-parse 'refs/remotes/origin/checkpoint/v014-b149-pass' 2>$null)
if ($LASTEXITCODE -ne 0) {
    $checkpoint = (& git rev-parse 'checkpoint/v014-b149-pass' 2>$null)
}
if ($LASTEXITCODE -ne 0 -or ([string]$checkpoint).Trim().ToLowerInvariant() -ne $frozen) {
    throw 'Accepted B14-9 checkpoint mismatch.'
}
Write-Host 'Accepted B14-9 checkpoint identity: PASS'

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
$changes = @(& git diff --name-only $frozen HEAD)
$allowed = @(
    '.github/workflows/b1410-real-host-preflight.yml',
    'ROADMAP.md',
    'sentinel/beta14_real_host_preflight.py',
    'tests/test_v014_b1410_real_host_preflight.py',
    'tools/acceptance/TEST-V014-B1410-REAL-HOST-PREFLIGHT.ps1',
    'tools/lab/COLLECT-V014-B1410-REAL-HOST-PREFLIGHT.sh'
)
if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B14-10 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) {
        throw ('Unexpected B14-10 changed path: ' + $path)
    }
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B14-9 path changed: ' + $path)
    }
}
Write-Host 'Accepted B14-9 source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta14_real_host_preflight.py tests/test_v014_b1410_real_host_preflight.py
if ($LASTEXITCODE -ne 0) {
    throw 'B14-10 compile failed.'
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
$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b1410-pytest-' + [guid]::NewGuid().ToString('N'))
try {
    & $py -m pytest -q --basetemp $testBase @tests
    if ($LASTEXITCODE -ne 0) {
        throw 'Beta5 through Beta14 B14-10 regression failed.'
    }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

& $py -m sentinel.beta14_real_host_preflight
if ($LASTEXITCODE -ne 0) {
    throw 'B14-10 real host preflight self-check failed.'
}

$reportJson = & $py -c "import json; from sentinel.beta14_real_host_preflight import self_check; print(json.dumps(self_check(),sort_keys=True))"
if ($LASTEXITCODE -ne 0) {
    throw 'B14-10 report generation failed.'
}
$report = $reportJson | ConvertFrom-Json

if (-not [bool]$report.passed) {
    throw 'B14-10 report did not pass.'
}
if (-not [bool]$report.real_host_preflight -or -not [bool]$report.ready_for_revert_drill) {
    throw 'B14-10 baseline preflight contract did not pass.'
}
if ([bool]$report.authoritative_physical_lab -or [bool]$report.t2_real_campaign_ready -or [bool]$report.t3_real_campaign_ready) {
    throw 'B14-10 preflight incorrectly promoted physical-lab authority.'
}
if (
    [bool]$report.sample_execution_performed -or
    [bool]$report.network_configuration_modified -or
    [bool]$report.hypervisor_state_modified
) {
    throw 'B14-10 read-only boundary violated.'
}
if ([bool]$report.coverage_promoted -or [bool]$report.authority_expanded) {
    throw 'B14-10 expanded coverage or authority.'
}

Write-Host ('B14-10 contract digest: ' + [string]$report.contract_digest)
Write-Host 'B14-10 preflight contract: linux_kvm=true vm_snapshot=true split_interfaces=true analysis_default_route=false'
Write-Host 'B14-10 collector: read_only=true sample_execution=false network_changes=false hypervisor_changes=false'
Write-Host 'B14-10 authority: physical_lab=false T2_real_ready=false T3_real_ready=false'
Write-Host 'B14-10 next gate: REAL_HOST_PREFLIGHT must run on dedicated Linux/KVM host, then snapshot/revert drill'
Write-Host 'B14-10 coverage: PARTIAL=4 GAP=0 VERIFIED=7 / promoted=false'
Write-Host 'BC SENTINEL v0.14.0 B14-10 REAL HOST PREFLIGHT - PASS'

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'B14-10 acceptance modified tracked repository sources.'
}
