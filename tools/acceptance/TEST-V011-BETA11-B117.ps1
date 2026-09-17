param(
    [switch]$ConfirmReleaseProvenanceSigningReadiness
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

if (-not $ConfirmReleaseProvenanceSigningReadiness) {
    throw 'Explicit Beta11 B11-7 Release Provenance + Signing Readiness confirmation required.'
}

$commit = (& git rev-parse --verify HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Cannot resolve B11-7 acceptance commit.'
}
Write-Host ('B11-7 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Tracked working files differ from B11-7 acceptance commit.'
}

$b116Accepted = '25fc9b50b17d9deb65d61a8e8994334259bb5042'
& git merge-base --is-ancestor $b116Accepted HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Accepted B11-6 predecessor is missing.'
}

$checkpointSha = (& git rev-parse 'refs/remotes/origin/checkpoint/v011-beta11-b116-pass' 2>$null)
if ($LASTEXITCODE -ne 0) {
    $checkpointSha = (& git rev-parse 'checkpoint/v011-beta11-b116-pass' 2>$null)
}
if ($LASTEXITCODE -ne 0 -or ([string]$checkpointSha).Trim().ToLowerInvariant() -ne $b116Accepted) {
    throw 'B11-6 immutable checkpoint is missing or points to the wrong commit.'
}

$predecessorPaths = @(& git ls-tree -r --name-only $b116Accepted)
if ($LASTEXITCODE -ne 0) {
    throw 'Cannot enumerate accepted B11-6 predecessor paths.'
}
$changes = @(& git diff --name-only $b116Accepted HEAD)
if ($LASTEXITCODE -ne 0) {
    throw 'Cannot compare accepted B11-6 predecessor sources.'
}

$allowedNew = @(
    'sentinel/beta11_release_provenance.py',
    'tests/test_v011_beta11_b117_release_provenance_signing_readiness.py',
    'tools/acceptance/TEST-V011-BETA11-B117.ps1',
    '.github/workflows/b117-release-provenance-signing-readiness.yml'
)
$expectedChanges = @($allowedNew + 'ROADMAP.md')
foreach ($path in $changes) {
    if ($path -eq 'ROADMAP.md') { continue }
    if ($predecessorPaths -contains $path) {
        throw ('Accepted B11-6 predecessor path changed: ' + $path)
    }
    if ($allowedNew -notcontains $path) {
        throw ('Unexpected B11-7 path changed: ' + $path)
    }
}
foreach ($path in $expectedChanges) {
    if ($changes -notcontains $path) {
        throw ('Expected B11-7 path missing from diff: ' + $path)
    }
}
if ($changes.Count -ne $expectedChanges.Count) {
    throw ('Unexpected B11-7 diff cardinality: expected ' + $expectedChanges.Count + ', got ' + $changes.Count)
}

$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository roadmap hygiene failed.'
}
Write-Host 'Accepted B11-6 predecessor identity, source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q `
    sentinel/beta11_release_provenance.py `
    tests/test_v011_beta11_b117_release_provenance_signing_readiness.py
if ($LASTEXITCODE -ne 0) {
    throw 'B11-7 compile failed.'
}

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b117-pytest-' + [guid]::NewGuid().ToString('N'))
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
        throw 'Beta5 through Beta11 B11-7 full regression failed.'
    }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$jsonLines = @(& $py -m sentinel.beta11_release_provenance)
if ($LASTEXITCODE -ne 0) {
    throw 'B11-7 release provenance contract self-check failed.'
}
$jsonText = $jsonLines -join [Environment]::NewLine
Write-Host $jsonText
$report = $jsonText | ConvertFrom-Json

if (-not $report.passed) { throw 'B11-7 report is not PASS.' }
if (@($report.failures).Count -ne 0) { throw 'B11-7 report contains failures.' }
if ($report.schema -ne 'bc-sentinel-beta11-release-provenance-contract-v1') { throw 'B11-7 schema mismatch.' }
if ($report.profile -ne 'v0.11.0-beta.11-b117-release-provenance-signing-readiness') { throw 'B11-7 profile mismatch.' }
if ($report.source_checkpoint -ne 'checkpoint/v011-beta11-b116-pass') { throw 'B11-7 source checkpoint mismatch.' }
if ($report.source_checkpoint_commit -ne $b116Accepted) { throw 'B11-7 source checkpoint commit mismatch.' }
if ($report.source_b116_contract_digest -ne 'd2aa15228ba6d7e84b8cef074f132718549373d51b35d93da6f12aac54c700d9') {
    throw 'B11-7 B11-6 contract binding mismatch.'
}
if ($report.artifact_name -ne 'BC-Sentinel-Beta11.exe') { throw 'B11-7 artifact identity mismatch.' }
if ($report.artifact_manifest_schema -ne 'bc-sentinel-beta11-onedir-manifest-v1') { throw 'B11-7 artifact manifest schema mismatch.' }
if (-not $report.sample_release_record_only) { throw 'B11-7 self-check must remain explicitly sample-only.' }
if ($report.release_artifact_observed) { throw 'B11-7 cannot claim a real release artifact was observed by the contract self-check.' }
if ($report.sample_signing_state -ne 'UNSIGNED') { throw 'B11-7 sample must remain factually unsigned.' }
if (-not $report.sample_provenance_ready) { throw 'B11-7 sample provenance should be internally complete.' }
if ($report.sample_signed_release_ready) { throw 'B11-7 unsigned sample cannot be signed-release-ready.' }
if (-not $report.verified_signing_state_supported) { throw 'B11-7 must model explicit verified signing evidence.' }
if ($report.artifact_signing_execution_available) { throw 'B11-7 cannot execute artifact signing.' }
if ($report.signature_verification_execution_available) { throw 'B11-7 cannot execute signature verification.' }
if ($report.private_key_access_available) { throw 'B11-7 cannot access signing private keys.' }
if ($report.certificate_enrollment_available) { throw 'B11-7 cannot enroll signing certificates.' }
if ($report.timestamp_service_execution_available) { throw 'B11-7 cannot call timestamp services.' }
if ($report.release_publication_execution_available) { throw 'B11-7 cannot publish releases.' }
if ($report.artifact_mutation_available) { throw 'B11-7 cannot mutate artifacts.' }
if ($report.network_required -or $report.cloud_required) { throw 'B11-7 cannot introduce network/cloud requirement.' }
if ($report.authority_expanded -or $report.coverage_promoted) { throw 'B11-7 widened authority or coverage.' }
if ($report.source_coverage.PARTIAL -ne 4 -or $report.source_coverage.GAP -ne 0 -or $report.source_coverage.VERIFIED -ne 2) {
    throw 'B11-7 coverage changed.'
}
$verified = @($report.verified_scenarios)
if ($verified.Count -ne 2 -or $verified[0] -ne 'B7-POWERSHELL-001' -or $verified[1] -ne 'B7-RANSOMWARE-001') {
    throw 'B11-7 verified scenario identity changed.'
}
$states = @($report.signing_states)
if ($states.Count -ne 3 -or $states[0] -ne 'UNSIGNED' -or $states[1] -ne 'SIGNED_UNVERIFIED' -or $states[2] -ne 'SIGNED_VERIFIED') {
    throw 'B11-7 signing state vocabulary changed.'
}
foreach ($digest in @($report.contract_digest, $report.sample_release_record_digest)) {
    if ([string]$digest -notmatch '^[0-9a-f]{64}$') {
        throw 'B11-7 deterministic digest invalid.'
    }
}
if (-not $report.deterministic_contract) { throw 'B11-7 contract is not deterministic.' }

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'B11-7 acceptance modified tracked repository sources.'
}

Write-Host ('B11-7 release provenance contract digest: ' + $report.contract_digest)
Write-Host 'B11-7 release provenance/signing readiness assertions: PASS'
Write-Host 'BC SENTINEL v0.11.0-beta.11 B11-7 RELEASE PROVENANCE + SIGNING READINESS - PASS'