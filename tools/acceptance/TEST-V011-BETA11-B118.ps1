param(
    [switch]$ConfirmCleanPcLifecycleAcceptance
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

if (-not $ConfirmCleanPcLifecycleAcceptance) {
    throw 'Explicit Beta11 B11-8 clean-PC disposable lifecycle confirmation required.'
}

$commit = (& git rev-parse --verify HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Cannot resolve B11-8 acceptance commit.'
}
Write-Host ('B11-8 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Tracked working files differ from B11-8 acceptance commit.'
}

$b117Accepted = 'c7ca5e86af196863cc980bcd1e8616447d9f3d8a'
& git merge-base --is-ancestor $b117Accepted HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Accepted B11-7 predecessor is missing.'
}

$checkpointSha = (& git rev-parse 'refs/remotes/origin/checkpoint/v011-beta11-b117-pass' 2>$null)
if ($LASTEXITCODE -ne 0) {
    $checkpointSha = (& git rev-parse 'checkpoint/v011-beta11-b117-pass' 2>$null)
}
if ($LASTEXITCODE -ne 0 -or ([string]$checkpointSha).Trim().ToLowerInvariant() -ne $b117Accepted) {
    throw 'B11-7 immutable checkpoint is missing or points to the wrong commit.'
}

$predecessorPaths = @(& git ls-tree -r --name-only $b117Accepted)
if ($LASTEXITCODE -ne 0) {
    throw 'Cannot enumerate accepted B11-7 predecessor paths.'
}
$changes = @(& git diff --name-only $b117Accepted HEAD)
if ($LASTEXITCODE -ne 0) {
    throw 'Cannot compare accepted B11-7 predecessor sources.'
}

$allowedNew = @(
    'sentinel/beta11_clean_pc_lifecycle_acceptance.py',
    'tests/test_v011_beta11_b118_clean_pc_lifecycle_acceptance.py',
    'tools/acceptance/TEST-V011-BETA11-B118.ps1',
    '.github/workflows/b118-clean-pc-lifecycle-acceptance.yml'
)
$expectedChanges = @($allowedNew + 'ROADMAP.md')
foreach ($path in $changes) {
    if ($path -eq 'ROADMAP.md') { continue }
    if ($predecessorPaths -contains $path) {
        throw ('Accepted B11-7 predecessor path changed: ' + $path)
    }
    if ($allowedNew -notcontains $path) {
        throw ('Unexpected B11-8 path changed: ' + $path)
    }
}
foreach ($path in $expectedChanges) {
    if ($changes -notcontains $path) {
        throw ('Expected B11-8 path missing from diff: ' + $path)
    }
}
if ($changes.Count -ne $expectedChanges.Count) {
    throw ('Unexpected B11-8 diff cardinality: expected ' + $expectedChanges.Count + ', got ' + $changes.Count)
}

$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository roadmap hygiene failed.'
}
Write-Host 'Accepted B11-7 predecessor identity, source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q `
    sentinel/beta11_clean_pc_lifecycle_acceptance.py `
    tests/test_v011_beta11_b118_clean_pc_lifecycle_acceptance.py
if ($LASTEXITCODE -ne 0) {
    throw 'B11-8 compile failed.'
}

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b118-pytest-' + [guid]::NewGuid().ToString('N'))
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
        throw 'Beta5 through Beta11 B11-8 full regression failed.'
    }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$jsonLines = @(& $py -m sentinel.beta11_clean_pc_lifecycle_acceptance --run-disposable-acceptance)
if ($LASTEXITCODE -ne 0) {
    throw 'B11-8 disposable lifecycle acceptance self-check failed.'
}
$jsonText = $jsonLines -join [Environment]::NewLine
Write-Host $jsonText
$report = $jsonText | ConvertFrom-Json

if (-not $report.passed) { throw 'B11-8 report is not PASS.' }
if (@($report.failures).Count -ne 0) { throw 'B11-8 report contains failures.' }
if ($report.schema -ne 'bc-sentinel-beta11-clean-pc-lifecycle-acceptance-v1') { throw 'B11-8 schema mismatch.' }
if ($report.profile -ne 'v0.11.0-beta.11-b118-clean-pc-install-upgrade-uninstall-acceptance') { throw 'B11-8 profile mismatch.' }
if ($report.source_checkpoint -ne 'checkpoint/v011-beta11-b117-pass') { throw 'B11-8 source checkpoint mismatch.' }
if ($report.source_checkpoint_commit -ne $b117Accepted) { throw 'B11-8 source checkpoint commit mismatch.' }
if ($report.source_b113_contract_digest -ne 'f084b67d16b87e17722e70890be13ba33fcd10d7c3ece43b499fcb01020e5aa6') { throw 'B11-8 B11-3 contract binding mismatch.' }
if ($report.source_b115_model_digest -ne '38df2751392cd71bec8662c6d4f80b287c30aeb70841606399057254fe7a2a08') { throw 'B11-8 B11-5 model binding mismatch.' }
if ($report.source_b116_contract_digest -ne 'd2aa15228ba6d7e84b8cef074f132718549373d51b35d93da6f12aac54c700d9') { throw 'B11-8 B11-6 contract binding mismatch.' }
if ($report.source_b117_contract_digest -ne 'a19d1ea8ad887b670cbbb9aef1a09db17e806fd59e5e89b603f9574c1912f109') { throw 'B11-8 B11-7 contract binding mismatch.' }
if ($report.execution_scope -ne 'EXPLICIT_DISPOSABLE_TEMP_WORKSPACE_ONLY') { throw 'B11-8 execution scope widened.' }
if (-not $report.deterministic_contract) { throw 'B11-8 contract is not deterministic.' }
if ($report.lifecycle_event_count -ne 4) { throw 'B11-8 lifecycle event count mismatch.' }
if (-not $report.unknown_child_preserved) { throw 'B11-8 unknown product child was not preserved.' }
if (-not $report.persistent_data_preserved) { throw 'B11-8 persistent data was not preserved.' }
if (-not $report.outside_canary_preserved) { throw 'B11-8 outside-workspace canary changed.' }
if (-not $report.unsafe_scope_rejected) { throw 'B11-8 unsafe workspace scope was not rejected.' }
if (-not $report.disposable_workspace_lifecycle_execution_available) { throw 'B11-8 disposable lifecycle execution did not run.' }
if ($report.host_machine_scope_install_execution_available) { throw 'B11-8 cannot install into real machine scope.' }
if ($report.host_machine_scope_upgrade_execution_available) { throw 'B11-8 cannot upgrade real machine scope.' }
if ($report.host_machine_scope_uninstall_execution_available) { throw 'B11-8 cannot uninstall real machine scope.' }
if ($report.host_registry_mutation_available) { throw 'B11-8 cannot mutate real HKLM.' }
if ($report.privilege_elevation_available) { throw 'B11-8 cannot elevate privileges.' }
if ($report.service_or_driver_registration_available) { throw 'B11-8 cannot register services or drivers.' }
if ($report.autostart_registration_available) { throw 'B11-8 cannot register autostart.' }
if ($report.network_required -or $report.cloud_required) { throw 'B11-8 cannot introduce network/cloud requirement.' }
if ($report.authority_expanded -or $report.coverage_promoted) { throw 'B11-8 widened authority or coverage.' }
if ($report.source_coverage.PARTIAL -ne 4 -or $report.source_coverage.GAP -ne 0 -or $report.source_coverage.VERIFIED -ne 2) {
    throw 'B11-8 coverage changed.'
}
$verified = @($report.verified_scenarios)
if ($verified.Count -ne 2 -or $verified[0] -ne 'B7-POWERSHELL-001' -or $verified[1] -ne 'B7-RANSOMWARE-001') {
    throw 'B11-8 verified scenario identity changed.'
}
foreach ($digest in @($report.contract_digest, $report.lifecycle_transcript_digest)) {
    if ([string]$digest -notmatch '^[0-9a-f]{64}$') {
        throw 'B11-8 deterministic digest invalid.'
    }
}

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'B11-8 acceptance modified tracked repository sources.'
}

Write-Host ('B11-8 lifecycle contract digest: ' + $report.contract_digest)
Write-Host ('B11-8 lifecycle transcript digest: ' + $report.lifecycle_transcript_digest)
Write-Host 'B11-8 clean-PC disposable install/upgrade/uninstall assertions: PASS'
Write-Host 'BC SENTINEL v0.11.0-beta.11 B11-8 CLEAN-PC INSTALL / UPGRADE / UNINSTALL ACCEPTANCE - PASS'
