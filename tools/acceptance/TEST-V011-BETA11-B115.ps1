param(
    [switch]$ConfirmPersistentDataLifecycle
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

if (-not $ConfirmPersistentDataLifecycle) {
    throw 'Explicit Beta11 B11-5 Persistent App Data + Logs + Quarantine Model confirmation required.'
}

$commit = (& git rev-parse --verify HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Cannot resolve B11-5 acceptance commit.'
}
Write-Host ('B11-5 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Tracked working files differ from B11-5 acceptance commit.'
}

$b114Accepted = '5ec361050f4c490652f88c30ad3a3b60e586fecb'
& git merge-base --is-ancestor $b114Accepted HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Accepted B11-4 predecessor is missing.'
}

$checkpointSha = (& git rev-parse 'refs/remotes/origin/checkpoint/v011-beta11-b114-pass' 2>$null)
if ($LASTEXITCODE -ne 0) {
    $checkpointSha = (& git rev-parse 'checkpoint/v011-beta11-b114-pass' 2>$null)
}
if ($LASTEXITCODE -ne 0 -or ([string]$checkpointSha).Trim().ToLowerInvariant() -ne $b114Accepted) {
    throw 'B11-4 immutable checkpoint is missing or points to the wrong commit.'
}

$predecessorPaths = @(& git ls-tree -r --name-only $b114Accepted)
if ($LASTEXITCODE -ne 0) {
    throw 'Cannot enumerate accepted B11-4 predecessor paths.'
}
$changes = @(& git diff --name-only $b114Accepted HEAD)
if ($LASTEXITCODE -ne 0) {
    throw 'Cannot compare accepted B11-4 predecessor sources.'
}

$allowedNew = @(
    'sentinel/beta11_persistent_data_model.py',
    'tests/test_v011_beta11_b115_persistent_data_lifecycle.py',
    'tools/acceptance/TEST-V011-BETA11-B115.ps1',
    '.github/workflows/b115-persistent-app-data-lifecycle.yml'
)
$expectedChanges = @($allowedNew + 'ROADMAP.md')
foreach ($path in $changes) {
    if ($path -eq 'ROADMAP.md') { continue }
    if ($predecessorPaths -contains $path) {
        throw ('Accepted B11-4 predecessor path changed: ' + $path)
    }
    if ($allowedNew -notcontains $path) {
        throw ('Unexpected B11-5 path changed: ' + $path)
    }
}
foreach ($path in $expectedChanges) {
    if ($changes -notcontains $path) {
        throw ('Expected B11-5 path missing from diff: ' + $path)
    }
}
if ($changes.Count -ne $expectedChanges.Count) {
    throw ('Unexpected B11-5 diff cardinality: expected ' + $expectedChanges.Count + ', got ' + $changes.Count)
}

$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository roadmap hygiene failed.'
}
Write-Host 'Accepted B11-4 predecessor identity, source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q `
    sentinel/beta11_persistent_data_model.py `
    tests/test_v011_beta11_b115_persistent_data_lifecycle.py
if ($LASTEXITCODE -ne 0) {
    throw 'B11-5 compile failed.'
}

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b115-pytest-' + [guid]::NewGuid().ToString('N'))
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
        throw 'Beta5 through Beta11 B11-5 full regression failed.'
    }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$jsonLines = @(& $py -m sentinel.beta11_persistent_data_model)
if ($LASTEXITCODE -ne 0) {
    throw 'B11-5 persistent data model self-check failed.'
}
$jsonText = $jsonLines -join [Environment]::NewLine
Write-Host $jsonText
$report = $jsonText | ConvertFrom-Json

if (-not $report.passed) { throw 'B11-5 report is not PASS.' }
if (@($report.failures).Count -ne 0) { throw 'B11-5 report contains failures.' }
if ($report.schema -ne 'bc-sentinel-beta11-persistent-data-model-v1') { throw 'B11-5 schema mismatch.' }
if ($report.profile -ne 'v0.11.0-beta.11-b115-persistent-app-data-lifecycle') { throw 'B11-5 profile mismatch.' }
if ($report.source_checkpoint -ne 'checkpoint/v011-beta11-b114-pass') { throw 'B11-5 source checkpoint mismatch.' }
if ($report.source_checkpoint_commit -ne $b114Accepted) { throw 'B11-5 source checkpoint commit mismatch.' }
if ($report.machine_data_root -ne '{PROGRAM_DATA}\BC Sentinel') { throw 'B11-5 canonical machine-data root mismatch.' }
if ($report.data_class_count -ne 5) { throw 'B11-5 persistent data class count mismatch.' }
if (-not $report.quarantine_metadata_payload_separated) { throw 'B11-5 quarantine metadata/payload separation missing.' }
if ($report.legacy_migration_policy -ne 'DEFERRED_TO_B11_6_NO_AUTOMATIC_MIGRATION') { throw 'B11-5 legacy migration boundary mismatch.' }
if (-not $report.persistent_data_preserved_by_default) { throw 'B11-5 persistent data must be preserved by default.' }
if (-not $report.unknown_children_fail_closed) { throw 'B11-5 unknown children must fail closed.' }
if (-not $report.ownership_manifest_required) { throw 'B11-5 exact ownership manifest requirement missing.' }
if ($report.destructive_execution_available) { throw 'B11-5 cannot enable destructive data execution.' }
if ($report.permission_enforcement_available) { throw 'B11-5 cannot claim permission enforcement.' }
if ($report.migration_execution_available) { throw 'B11-5 cannot enable legacy data migration.' }
if ($report.installer_or_uninstaller_execution_available) { throw 'B11-5 cannot enable installer/uninstaller execution.' }
if ($report.network_required -or $report.cloud_required) { throw 'B11-5 cannot introduce network/cloud requirement.' }
if ($report.authority_expanded -or $report.coverage_promoted) { throw 'B11-5 widened authority or coverage.' }
if ($report.source_coverage.PARTIAL -ne 4 -or $report.source_coverage.GAP -ne 0 -or $report.source_coverage.VERIFIED -ne 2) {
    throw 'B11-5 coverage changed.'
}
$verified = @($report.verified_scenarios)
if ($verified.Count -ne 2 -or $verified[0] -ne 'B7-POWERSHELL-001' -or $verified[1] -ne 'B7-RANSOMWARE-001') {
    throw 'B11-5 verified scenario identity changed.'
}
if ([string]$report.model_digest -notmatch '^[0-9a-f]{64}$' -or -not $report.deterministic_model) {
    throw 'B11-5 model digest/determinism invalid.'
}

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'B11-5 acceptance modified tracked repository sources.'
}

Write-Host ('B11-5 persistent data model digest: ' + $report.model_digest)
Write-Host 'B11-5 persistent data lifecycle assertions: PASS'
Write-Host 'BC SENTINEL v0.11.0-beta.11 B11-5 PERSISTENT APP DATA + LOGS + QUARANTINE MODEL - PASS'
