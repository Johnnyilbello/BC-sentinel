param([switch]$ConfirmProductizationFoundation)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot
$env:PYTHONPATH = $repoRoot

if (-not $ConfirmProductizationFoundation) {
    throw 'Explicit Beta11 B11-0 Productization Foundation confirmation required.'
}

$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve B11-0 acceptance commit.' }
Write-Host ('B11-0 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B11-0 acceptance commit.' }

$b109Accepted = '89d2b0d59c73ad5d07d46af58db03d03c6fbfdc9'
& git merge-base --is-ancestor $b109Accepted HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted B10-9 predecessor is missing.' }

$checkpointSha = (& git rev-parse 'refs/remotes/origin/checkpoint/v011-beta10-b109-pass' 2>$null)
if ($LASTEXITCODE -ne 0) {
    $checkpointSha = (& git rev-parse 'checkpoint/v011-beta10-b109-pass' 2>$null)
}
if ($LASTEXITCODE -ne 0 -or [string]$checkpointSha -ne $b109Accepted) {
    throw 'B10-9 immutable checkpoint is missing or points to the wrong commit.'
}

$predecessorPaths = @(& git ls-tree -r --name-only $b109Accepted)
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate accepted B10-9 predecessor paths.' }
$changes = @(& git diff --name-only $b109Accepted HEAD)
if ($LASTEXITCODE -ne 0) { throw 'Cannot compare accepted B10-9 predecessor sources.' }

$allowedNew = @(
    'sentinel/beta11_productization_foundation.py',
    'tests/test_v011_beta11_b110_productization_foundation.py',
    'tools/acceptance/RUN-V011-BETA11-B110-FOUNDATION.py',
    'tools/acceptance/TEST-V011-BETA11-B110.ps1',
    '.github/workflows/b110-productization-foundation.yml',
    'ROADMAP.md'
)

foreach ($path in $changes) {
    if ($predecessorPaths -contains $path -and $path -ne 'ROADMAP.md') {
        throw ('Accepted B10-9 predecessor path changed: ' + $path)
    }
    if ($allowedNew -notcontains $path) {
        throw ('Unexpected B11-0 path changed: ' + $path)
    }
}

$rootFiles = @(& git ls-files | Where-Object { $_ -notmatch '/' })
$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($rootFiles.Count -ne 10 -or $roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository hygiene failed.'
}
Write-Host 'Accepted B10-9 predecessor immutability, checkpoint identity and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q `
    sentinel/beta11_productization_foundation.py `
    tests/test_v011_beta11_b110_productization_foundation.py `
    tools/acceptance/RUN-V011-BETA11-B110-FOUNDATION.py
if ($LASTEXITCODE -ne 0) { throw 'B11-0 compile failed.' }

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b110-pytest-' + [guid]::NewGuid().ToString('N'))
$tests = @(
    Get-ChildItem `
        tests/test_v011_beta5_*.py, `
        tests/test_v011_beta6_*.py, `
        tests/test_v011_beta7_*.py, `
        tests/test_v011_beta8_*.py, `
        tests/test_v011_beta9_*.py, `
        tests/test_v011_beta10_*.py, `
        tests/test_v011_beta11_*.py |
    Sort-Object FullName |
    ForEach-Object { $_.FullName }
)
try {
    & $py -m pytest -q --basetemp $testBase @tests
    if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta11 B11-0 full regression failed.' }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

& $py '.\tools\acceptance\RUN-V011-BETA11-B110-FOUNDATION.py'
if ($LASTEXITCODE -ne 0) { throw 'B11-0 productization foundation self-check failed.' }

$contractCode = @'
from sentinel.beta11_productization_foundation import validate_contract, contract, self_check

c = contract()
r = self_check()
assert r["passed"]
assert validate_contract(c) == ()
assert c["source_checkpoint"] == "checkpoint/v011-beta10-b109-pass"
assert c["source_checkpoint_commit"] == "89d2b0d59c73ad5d07d46af58db03d03c6fbfdc9"
assert c["source_coverage"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
assert c["verified_scenarios"] == ["B7-POWERSHELL-001", "B7-RANSOMWARE-001"]
assert len(c["productization_pillars"]) == 6
assert len(c["milestones"]) == 10
assert not any(c["current_distribution_state"].values())
assert not any(c["inherited_authority_boundary"].values())
assert c["adds_installer_in_b110"] is False
assert c["adds_service_or_driver_in_b110"] is False
assert c["adds_network_or_cloud_dependency_in_b110"] is False
assert c["adds_protection_claim_in_b110"] is False
assert c["adds_response_authority_in_b110"] is False
assert c["foundation_guardrails"]["release_requires_exact_ci_and_local_acceptance"] is True
assert c["foundation_guardrails"]["clean_pc_acceptance_required_before_rc_freeze"] is True
print("B11-0 contract assertions: PASS")
'@

$contractScript = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b110-contract-' + [guid]::NewGuid().ToString('N') + '.py')
try {
    Set-Content -LiteralPath $contractScript -Value $contractCode -Encoding UTF8
    & $py $contractScript
    if ($LASTEXITCODE -ne 0) { throw 'B11-0 contract assertions failed.' }
}
finally {
    Remove-Item -LiteralPath $contractScript -Force -ErrorAction SilentlyContinue
}

Write-Host 'BC SENTINEL v0.11.0-beta.11 B11-0 WINDOWS PRODUCTIZATION FOUNDATION - PASS'
