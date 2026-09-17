param(
    [switch]$ConfirmFirstRunHealthRepairGuidance
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

if (-not $ConfirmFirstRunHealthRepairGuidance) {
    throw 'Explicit Beta11 B11-4 First-Run Health + Repair Guidance confirmation required.'
}

$commit = (& git rev-parse --verify HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Cannot resolve B11-4 acceptance commit.'
}
Write-Host ('B11-4 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Tracked working files differ from B11-4 acceptance commit.'
}

$b113Accepted = '4ce33199bb72d87c09b0c204a40c2046efcb615a'
& git merge-base --is-ancestor $b113Accepted HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Accepted B11-3 predecessor is missing.'
}

$checkpointSha = (& git rev-parse 'refs/remotes/origin/checkpoint/v011-beta11-b113-pass' 2>$null)
if ($LASTEXITCODE -ne 0) {
    $checkpointSha = (& git rev-parse 'checkpoint/v011-beta11-b113-pass' 2>$null)
}
if ($LASTEXITCODE -ne 0 -or ([string]$checkpointSha).Trim().ToLowerInvariant() -ne $b113Accepted) {
    throw 'B11-3 immutable checkpoint is missing or points to the wrong commit.'
}

$predecessorPaths = @(& git ls-tree -r --name-only $b113Accepted)
if ($LASTEXITCODE -ne 0) {
    throw 'Cannot enumerate accepted B11-3 predecessor paths.'
}
$changes = @(& git diff --name-only $b113Accepted HEAD)
if ($LASTEXITCODE -ne 0) {
    throw 'Cannot compare accepted B11-3 predecessor sources.'
}

$allowedModified = @(
    'ROADMAP.md',
    'packaging/beta11_desktop_entry.py'
)
$allowedNew = @(
    'sentinel/beta11_first_run_health.py',
    'tests/test_v011_beta11_b114_first_run_health.py',
    'tools/acceptance/TEST-V011-BETA11-B114.ps1',
    '.github/workflows/b114-first-run-health-repair-guidance.yml'
)
$expectedChanges = @($allowedModified + $allowedNew)
foreach ($path in $changes) {
    if ($allowedModified -contains $path) { continue }
    if ($predecessorPaths -contains $path) {
        throw ('Accepted B11-3 predecessor path changed outside B11-4 integration scope: ' + $path)
    }
    if ($allowedNew -notcontains $path) {
        throw ('Unexpected B11-4 path changed: ' + $path)
    }
}
foreach ($path in $expectedChanges) {
    if ($changes -notcontains $path) {
        throw ('Expected B11-4 path missing from diff: ' + $path)
    }
}
if ($changes.Count -ne $expectedChanges.Count) {
    throw ('Unexpected B11-4 diff cardinality: expected ' + $expectedChanges.Count + ', got ' + $changes.Count)
}

$b113Protected = @(
    'sentinel/beta11_install_lifecycle_contract.py',
    'tests/test_v011_beta11_b113_installer_uninstaller_contract.py',
    'tools/acceptance/TEST-V011-BETA11-B113.ps1',
    '.github/workflows/b113-installer-uninstaller-contract.yml'
)
foreach ($path in $b113Protected) {
    $before = (& git rev-parse ($b113Accepted + ':' + $path)).Trim().ToLowerInvariant()
    $after = (& git rev-parse ('HEAD:' + $path)).Trim().ToLowerInvariant()
    if ($LASTEXITCODE -ne 0 -or $before -ne $after) {
        throw ('Accepted B11-3 milestone source changed: ' + $path)
    }
}

$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository roadmap hygiene failed.'
}
Write-Host 'Accepted B11-3 predecessor identity, protected milestone sources and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q `
    sentinel/beta11_first_run_health.py `
    packaging/beta11_desktop_entry.py `
    tests/test_v011_beta11_b114_first_run_health.py
if ($LASTEXITCODE -ne 0) {
    throw 'B11-4 compile failed.'
}

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b114-pytest-' + [guid]::NewGuid().ToString('N'))
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
        throw 'Beta5 through Beta11 B11-4 full regression failed.'
    }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$selfLines = @(& $py -m sentinel.beta11_first_run_health --self-check)
if ($LASTEXITCODE -ne 0) {
    throw 'B11-4 health contract self-check failed.'
}
$selfText = $selfLines -join [Environment]::NewLine
Write-Host $selfText
$self = $selfText | ConvertFrom-Json

if (-not $self.passed) { throw 'B11-4 self-check is not PASS.' }
if (@($self.failures).Count -ne 0) { throw 'B11-4 self-check contains failures.' }
if ($self.source_checkpoint -ne 'checkpoint/v011-beta11-b113-pass') { throw 'B11-4 source checkpoint mismatch.' }
if ($self.source_checkpoint_commit -ne $b113Accepted) { throw 'B11-4 source checkpoint commit mismatch.' }
if (-not $self.deterministic_evaluation) { throw 'B11-4 health evaluation is not deterministic.' }
if ($self.healthy_fixture_status -ne 'READY' -or $self.degraded_fixture_status -ne 'DEGRADED' -or $self.blocked_fixture_status -ne 'BLOCKED') {
    throw 'B11-4 health status semantics mismatch.'
}
if ($self.health_mutates_system -or $self.automatic_repair -or $self.repair_execution_available -or $self.privilege_elevation_available -or $self.network_required) {
    throw 'B11-4 enabled mutation, repair execution, elevation or network dependency.'
}
if ($self.coverage_promoted -or $self.authority_expanded) { throw 'B11-4 widened coverage or authority.' }
if ($self.source_coverage.PARTIAL -ne 4 -or $self.source_coverage.GAP -ne 0 -or $self.source_coverage.VERIFIED -ne 2) {
    throw 'B11-4 coverage changed.'
}
$verified = @($self.verified_scenarios)
if ($verified.Count -ne 2 -or $verified[0] -ne 'B7-POWERSHELL-001' -or $verified[1] -ne 'B7-RANSOMWARE-001') {
    throw 'B11-4 verified scenario identity changed.'
}
if ([string]$self.health_contract_digest -notmatch '^[0-9a-f]{64}$') {
    throw 'B11-4 health contract digest invalid.'
}

$liveLines = @(& $py -m sentinel.beta11_first_run_health --health-json)
if ($LASTEXITCODE -ne 0) {
    throw 'B11-4 live Windows health probe blocked.'
}
$liveText = $liveLines -join [Environment]::NewLine
Write-Host $liveText
$live = $liveText | ConvertFrom-Json
if ($live.overall_status -ne 'READY' -and $live.overall_status -ne 'DEGRADED') { throw 'B11-4 live health is not startable.' }
if (-not $live.ready_to_start -or $live.critical_failure_count -ne 0) { throw 'B11-4 live health has a critical failure.' }
if ($live.facts.platform_system -ne 'Windows' -or $live.facts.pointer_bits -ne 64) { throw 'B11-4 live Windows/x64 facts invalid.' }
if ($live.non_execution_boundary.health_mutates_system -or $live.non_execution_boundary.automatic_repair -or $live.non_execution_boundary.repair_execution_available) {
    throw 'B11-4 live health enabled mutation or repair.'
}
if ($live.non_execution_boundary.privilege_elevation_available -or $live.non_execution_boundary.network_required -or $live.non_execution_boundary.cloud_required) {
    throw 'B11-4 live health enabled elevation/network/cloud.'
}
if ($live.non_execution_boundary.coverage_promoted -or $live.non_execution_boundary.authority_expanded) {
    throw 'B11-4 live health widened coverage or authority.'
}

$entryHealthLines = @(& $py packaging/beta11_desktop_entry.py --health-json)
if ($LASTEXITCODE -ne 0) { throw 'B11-4 desktop health probe failed.' }
$entryHealth = ($entryHealthLines -join [Environment]::NewLine) | ConvertFrom-Json
if (-not $entryHealth.ready_to_start -or $entryHealth.critical_failure_count -ne 0) { throw 'B11-4 desktop entry health is blocked.' }

$entrySelfLines = @(& $py packaging/beta11_desktop_entry.py --self-check)
if ($LASTEXITCODE -ne 0) { throw 'B11-4 desktop self-check failed.' }
$entrySelf = ($entrySelfLines -join [Environment]::NewLine) | ConvertFrom-Json
if (-not $entrySelf.passed -or -not $entrySelf.first_run_health_contract_valid -or -not $entrySelf.first_run_health_ready_to_start) {
    throw 'B11-4 desktop self-check health integration invalid.'
}
if ($entrySelf.first_run_health_mutates_system -or $entrySelf.automatic_repair_available) {
    throw 'B11-4 desktop self-check enabled mutation or repair.'
}

$smokeLines = @(& $py packaging/beta11_desktop_entry.py --smoke)
if ($LASTEXITCODE -ne 0) { throw 'B11-4 desktop smoke failed.' }
$smoke = ($smokeLines -join [Environment]::NewLine) | ConvertFrom-Json
if (-not $smoke.passed -or -not $smoke.first_run_health_ready_to_start) { throw 'B11-4 smoke did not pass health gate.' }
if ($smoke.first_run_health_mutates_system -or $smoke.automatic_repair_available -or $smoke.startup_authority_expanded -or $smoke.coverage_promoted) {
    throw 'B11-4 smoke widened startup authority or enabled repair.'
}

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'B11-4 acceptance modified tracked repository sources.'
}

Write-Host ('B11-4 health contract digest: ' + $self.health_contract_digest)
Write-Host ('B11-4 live health status: ' + $live.overall_status)
Write-Host 'B11-4 first-run health assertions: PASS'
Write-Host 'BC SENTINEL v0.11.0-beta.11 B11-4 FIRST-RUN HEALTH + REPAIR GUIDANCE - PASS'
