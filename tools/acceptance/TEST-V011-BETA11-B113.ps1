param(
    [switch]$ConfirmInstallerUninstallerContract
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location -LiteralPath $repoRoot
$env:PYTHONPATH = $repoRoot

if (-not $ConfirmInstallerUninstallerContract) {
    throw 'Explicit Beta11 B11-3 Installer / Uninstaller Contract confirmation required.'
}

$commit = (& git rev-parse --verify HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Cannot resolve B11-3 acceptance commit.'
}
Write-Host ('B11-3 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Tracked working files differ from B11-3 acceptance commit.'
}

$b112Accepted = '92b6317aa9e642a0062268bce9f92bb0a4ffb1a1'
& git merge-base --is-ancestor $b112Accepted HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Accepted B11-2 predecessor is missing.'
}

$checkpointSha = (& git rev-parse 'refs/remotes/origin/checkpoint/v011-beta11-b112-pass' 2>$null)
if ($LASTEXITCODE -ne 0) {
    $checkpointSha = (& git rev-parse 'checkpoint/v011-beta11-b112-pass' 2>$null)
}
if ($LASTEXITCODE -ne 0 -or ([string]$checkpointSha).Trim().ToLowerInvariant() -ne $b112Accepted) {
    throw 'B11-2 immutable checkpoint is missing or points to the wrong commit.'
}

$predecessorPaths = @(& git ls-tree -r --name-only $b112Accepted)
if ($LASTEXITCODE -ne 0) {
    throw 'Cannot enumerate accepted B11-2 predecessor paths.'
}
$changes = @(& git diff --name-only $b112Accepted HEAD)
if ($LASTEXITCODE -ne 0) {
    throw 'Cannot compare accepted B11-2 predecessor sources.'
}

$allowedNew = @(
    'sentinel/beta11_install_lifecycle_contract.py',
    'tests/test_v011_beta11_b113_installer_uninstaller_contract.py',
    'tools/acceptance/TEST-V011-BETA11-B113.ps1',
    '.github/workflows/b113-installer-uninstaller-contract.yml'
)
$expectedChanges = @($allowedNew + 'ROADMAP.md')
foreach ($path in $changes) {
    if ($path -eq 'ROADMAP.md') { continue }
    if ($predecessorPaths -contains $path) {
        throw ('Accepted B11-2 predecessor path changed: ' + $path)
    }
    if ($allowedNew -notcontains $path) {
        throw ('Unexpected B11-3 path changed: ' + $path)
    }
}
foreach ($path in $expectedChanges) {
    if ($changes -notcontains $path) {
        throw ('Expected B11-3 path missing from diff: ' + $path)
    }
}
if ($changes.Count -ne $expectedChanges.Count) {
    throw ('Unexpected B11-3 diff cardinality: expected ' + $expectedChanges.Count + ', got ' + $changes.Count)
}

$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository roadmap hygiene failed.'
}
Write-Host 'Accepted B11-2 predecessor immutability, checkpoint identity and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q `
    sentinel/beta11_install_lifecycle_contract.py `
    tests/test_v011_beta11_b113_installer_uninstaller_contract.py
if ($LASTEXITCODE -ne 0) {
    throw 'B11-3 compile failed.'
}

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b113-pytest-' + [guid]::NewGuid().ToString('N'))
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
    if ($LASTEXITCODE -ne 0) {
        throw 'Beta5 through Beta11 B11-3 full regression failed.'
    }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$jsonLines = @(& $py -m sentinel.beta11_install_lifecycle_contract)
if ($LASTEXITCODE -ne 0) {
    throw 'B11-3 install lifecycle contract self-check failed.'
}
$jsonText = $jsonLines -join [Environment]::NewLine
Write-Host $jsonText
$report = $jsonText | ConvertFrom-Json

if (-not $report.passed) { throw 'B11-3 report is not PASS.' }
if (@($report.failures).Count -ne 0) { throw 'B11-3 report contains failures.' }
if ($report.source_checkpoint -ne 'checkpoint/v011-beta11-b112-pass') { throw 'B11-3 source checkpoint mismatch.' }
if ($report.source_checkpoint_commit -ne $b112Accepted) { throw 'B11-3 source checkpoint commit mismatch.' }
if (-not $report.contract_only) { throw 'B11-3 must remain contract-only.' }
if ($report.planned_resource_count -ne 4) { throw 'B11-3 planned resource count mismatch.' }
if ($report.lifecycle_operation_count -ne 4) { throw 'B11-3 lifecycle operation count mismatch.' }
if ($report.installer_available -or $report.uninstaller_available -or $report.lifecycle_execution_available) {
    throw 'B11-3 cannot claim installer/uninstaller lifecycle execution.'
}
if ($report.artifact_signed) { throw 'B11-3 cannot claim artifact signing.' }
if ($report.elevation_policy -ne 'ON_DEMAND_MACHINE_SCOPE_ONLY') { throw 'B11-3 elevation policy mismatch.' }
if (-not $report.ownership_manifest_required) { throw 'B11-3 ownership manifest requirement missing.' }
if (-not $report.unknown_children_preserved) { throw 'B11-3 unknown-child preservation missing.' }
if ($report.persistent_app_data_removed_by_default) { throw 'B11-3 cannot remove persistent app data by default.' }
if ($report.service_or_driver_installation_available) { throw 'B11-3 cannot enable service or driver installation.' }
if ($report.autostart_registration_available) { throw 'B11-3 cannot enable autostart registration.' }
if ($report.authority_expanded -or $report.coverage_promoted) { throw 'B11-3 widened authority or coverage.' }
if ($report.source_coverage.PARTIAL -ne 4 -or $report.source_coverage.GAP -ne 0 -or $report.source_coverage.VERIFIED -ne 2) {
    throw 'B11-3 coverage changed.'
}
$verified = @($report.verified_scenarios)
if ($verified.Count -ne 2 -or $verified[0] -ne 'B7-POWERSHELL-001' -or $verified[1] -ne 'B7-RANSOMWARE-001') {
    throw 'B11-3 verified scenario identity changed.'
}
if ([string]$report.contract_digest -notmatch '^[0-9a-f]{64}$' -or -not $report.deterministic_contract) {
    throw 'B11-3 contract digest/determinism invalid.'
}

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'B11-3 acceptance modified tracked repository sources.'
}

Write-Host ('B11-3 contract digest: ' + $report.contract_digest)
Write-Host 'B11-3 contract assertions: PASS'
Write-Host 'BC SENTINEL v0.11.0-beta.11 B11-3 INSTALLER / UNINSTALLER CONTRACT - PASS'
