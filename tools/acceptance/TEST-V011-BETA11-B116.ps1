param(
    [switch]$ConfirmUpgradeRollbackConfigMigration
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

if (-not $ConfirmUpgradeRollbackConfigMigration) {
    throw 'Explicit Beta11 B11-6 Upgrade / Rollback + Config Migration confirmation required.'
}

$commit = (& git rev-parse --verify HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Cannot resolve B11-6 acceptance commit.'
}
Write-Host ('B11-6 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Tracked working files differ from B11-6 acceptance commit.'
}

$b115Accepted = '19e40b9b41f4d87b3f081bb7e8bfb5b155db4660'
& git merge-base --is-ancestor $b115Accepted HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Accepted B11-5 predecessor is missing.'
}

$checkpointSha = (& git rev-parse 'refs/remotes/origin/checkpoint/v011-beta11-b115-pass' 2>$null)
if ($LASTEXITCODE -ne 0) {
    $checkpointSha = (& git rev-parse 'checkpoint/v011-beta11-b115-pass' 2>$null)
}
if ($LASTEXITCODE -ne 0 -or ([string]$checkpointSha).Trim().ToLowerInvariant() -ne $b115Accepted) {
    throw 'B11-5 immutable checkpoint is missing or points to the wrong commit.'
}

$predecessorPaths = @(& git ls-tree -r --name-only $b115Accepted)
if ($LASTEXITCODE -ne 0) {
    throw 'Cannot enumerate accepted B11-5 predecessor paths.'
}
$changes = @(& git diff --name-only $b115Accepted HEAD)
if ($LASTEXITCODE -ne 0) {
    throw 'Cannot compare accepted B11-5 predecessor sources.'
}

$allowedNew = @(
    'sentinel/beta11_upgrade_migration_contract.py',
    'tests/test_v011_beta11_b116_upgrade_rollback_config_migration.py',
    'tools/acceptance/TEST-V011-BETA11-B116.ps1',
    '.github/workflows/b116-upgrade-rollback-config-migration.yml'
)
$expectedChanges = @($allowedNew + 'ROADMAP.md')
foreach ($path in $changes) {
    if ($path -eq 'ROADMAP.md') { continue }
    if ($predecessorPaths -contains $path) {
        throw ('Accepted B11-5 predecessor path changed: ' + $path)
    }
    if ($allowedNew -notcontains $path) {
        throw ('Unexpected B11-6 path changed: ' + $path)
    }
}
foreach ($path in $expectedChanges) {
    if ($changes -notcontains $path) {
        throw ('Expected B11-6 path missing from diff: ' + $path)
    }
}
if ($changes.Count -ne $expectedChanges.Count) {
    throw ('Unexpected B11-6 diff cardinality: expected ' + $expectedChanges.Count + ', got ' + $changes.Count)
}

$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository roadmap hygiene failed.'
}
Write-Host 'Accepted B11-5 predecessor identity, source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q `
    sentinel/beta11_upgrade_migration_contract.py `
    tests/test_v011_beta11_b116_upgrade_rollback_config_migration.py
if ($LASTEXITCODE -ne 0) {
    throw 'B11-6 compile failed.'
}

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b116-pytest-' + [guid]::NewGuid().ToString('N'))
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
        throw 'Beta5 through Beta11 B11-6 full regression failed.'
    }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$jsonLines = @(& $py -m sentinel.beta11_upgrade_migration_contract)
if ($LASTEXITCODE -ne 0) {
    throw 'B11-6 upgrade migration contract self-check failed.'
}
$jsonText = $jsonLines -join [Environment]::NewLine
Write-Host $jsonText
$report = $jsonText | ConvertFrom-Json

if (-not $report.passed) { throw 'B11-6 report is not PASS.' }
if (@($report.failures).Count -ne 0) { throw 'B11-6 report contains failures.' }
if ($report.schema -ne 'bc-sentinel-beta11-upgrade-migration-contract-v1') { throw 'B11-6 schema mismatch.' }
if ($report.profile -ne 'v0.11.0-beta.11-b116-upgrade-rollback-config-migration') { throw 'B11-6 profile mismatch.' }
if ($report.source_checkpoint -ne 'checkpoint/v011-beta11-b115-pass') { throw 'B11-6 source checkpoint mismatch.' }
if ($report.source_checkpoint_commit -ne $b115Accepted) { throw 'B11-6 source checkpoint commit mismatch.' }
if ($report.b115_model_digest -ne '38df2751392cd71bec8662c6d4f80b287c30aeb70841606399057254fe7a2a08') { throw 'B11-6 B11-5 model binding mismatch.' }
if ($report.legacy_mapping_count -ne 4) { throw 'B11-6 legacy mapping count mismatch.' }
if ($report.upgrade_phase_count -ne 7) { throw 'B11-6 upgrade phase count mismatch.' }
if ($report.migration_mode -ne 'COPY_VERIFY_SWITCH_KEEP_SOURCE') { throw 'B11-6 migration mode mismatch.' }
if ($report.rollback_mode -ne 'POINTER_ROLLBACK_KEEP_BOTH_DATASETS') { throw 'B11-6 rollback mode mismatch.' }
if (-not $report.config_migration_idempotent) { throw 'B11-6 config migration must be idempotent.' }
if (-not $report.source_preserved) { throw 'B11-6 source data must remain preserved.' }
if ($report.host_migration_execution_available) { throw 'B11-6 cannot enable host migration execution.' }
if ($report.host_upgrade_execution_available) { throw 'B11-6 cannot enable host upgrade execution.' }
if ($report.host_rollback_execution_available) { throw 'B11-6 cannot enable host rollback execution.' }
if ($report.config_write_execution_available) { throw 'B11-6 cannot enable config writes.' }
if ($report.legacy_source_delete_available) { throw 'B11-6 cannot delete legacy source data.' }
if ($report.quarantine_restore_execution_available) { throw 'B11-6 cannot imply quarantine restore.' }
if ($report.network_required -or $report.cloud_required) { throw 'B11-6 cannot introduce network/cloud requirement.' }
if ($report.authority_expanded -or $report.coverage_promoted) { throw 'B11-6 widened authority or coverage.' }
if ($report.source_coverage.PARTIAL -ne 4 -or $report.source_coverage.GAP -ne 0 -or $report.source_coverage.VERIFIED -ne 2) {
    throw 'B11-6 coverage changed.'
}
$verified = @($report.verified_scenarios)
if ($verified.Count -ne 2 -or $verified[0] -ne 'B7-POWERSHELL-001' -or $verified[1] -ne 'B7-RANSOMWARE-001') {
    throw 'B11-6 verified scenario identity changed.'
}
foreach ($digest in @($report.contract_digest, $report.sample_migration_plan_digest, $report.sample_rollback_plan_digest)) {
    if ([string]$digest -notmatch '^[0-9a-f]{64}$') {
        throw 'B11-6 deterministic digest invalid.'
    }
}
if (-not $report.deterministic_contract) { throw 'B11-6 contract is not deterministic.' }

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'B11-6 acceptance modified tracked repository sources.'
}

Write-Host ('B11-6 upgrade migration contract digest: ' + $report.contract_digest)
Write-Host 'B11-6 upgrade/rollback/config migration assertions: PASS'
Write-Host 'BC SENTINEL v0.11.0-beta.11 B11-6 UPGRADE / ROLLBACK + CONFIG MIGRATION - PASS'
