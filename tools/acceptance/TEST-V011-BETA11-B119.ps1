param(
    [switch]$ConfirmReleaseCandidateFreeze,
    [string]$DistRoot = ".\dist\Beta11-B119-RC"
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

if (-not $ConfirmReleaseCandidateFreeze) { throw 'Explicit Beta11 B11-9 release-candidate freeze confirmation required.' }

$commit = (& git rev-parse --verify HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') { throw 'Cannot resolve B11-9 acceptance commit.' }
Write-Host ('B11-9 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B11-9 acceptance commit.' }

$b118Accepted = '46d18b77aa382573e1e4e2a2eb381bcb71e03a69'
& git merge-base --is-ancestor $b118Accepted HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted B11-8 predecessor is missing.' }

$accepted = [ordered]@{
    'checkpoint/v011-beta11-b110-pass' = '0bee65100c6713d11dedd56c28ee3118f0082624'
    'checkpoint/v011-beta11-b111-pass' = '2d49bc2037d3d1f3fb40280277cf8d53927cc68b'
    'checkpoint/v011-beta11-b112-pass' = '92b6317aa9e642a0062268bce9f92bb0a4ffb1a1'
    'checkpoint/v011-beta11-b113-pass' = '4ce33199bb72d87c09b0c204a40c2046efcb615a'
    'checkpoint/v011-beta11-b114-pass' = '5ec361050f4c490652f88c30ad3a3b60e586fecb'
    'checkpoint/v011-beta11-b115-pass' = '19e40b9b41f4d87b3f081bb7e8bfb5b155db4660'
    'checkpoint/v011-beta11-b116-pass' = '25fc9b50b17d9deb65d61a8e8994334259bb5042'
    'checkpoint/v011-beta11-b117-pass' = 'c7ca5e86af196863cc980bcd1e8616447d9f3d8a'
    'checkpoint/v011-beta11-b118-pass' = $b118Accepted
}
foreach ($name in $accepted.Keys) {
    $resolved = (& git rev-parse ('refs/remotes/origin/' + $name) 2>$null)
    if ($LASTEXITCODE -ne 0) { $resolved = (& git rev-parse $name 2>$null) }
    if ($LASTEXITCODE -ne 0 -or ([string]$resolved).Trim().ToLowerInvariant() -ne $accepted[$name]) { throw ('Accepted checkpoint mismatch: ' + $name) }
}
Write-Host 'All accepted Beta11 predecessor checkpoints: PASS'

$predecessorPaths = @(& git ls-tree -r --name-only $b118Accepted)
$changes = @(& git diff --name-only $b118Accepted HEAD)
$allowedNew = @(
    'sentinel/beta11_release_candidate_freeze.py',
    'tests/test_v011_beta11_b119_release_candidate_freeze.py',
    'tools/acceptance/TEST-V011-BETA11-B119.ps1',
    '.github/workflows/b119-windows-release-candidate-freeze.yml'
)
$expectedChanges = @($allowedNew + 'ROADMAP.md')
foreach ($path in $changes) {
    if ($path -eq 'ROADMAP.md') { continue }
    if ($predecessorPaths -contains $path) { throw ('Accepted B11-8 predecessor path changed: ' + $path) }
    if ($allowedNew -notcontains $path) { throw ('Unexpected B11-9 path changed: ' + $path) }
}
foreach ($path in $expectedChanges) { if ($changes -notcontains $path) { throw ('Expected B11-9 path missing from diff: ' + $path) } }
if ($changes.Count -ne $expectedChanges.Count) { throw ('Unexpected B11-9 diff cardinality: ' + $changes.Count) }
$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') { throw 'Repository roadmap hygiene failed.' }
Write-Host 'Accepted B11-8 source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py -PathType Leaf)) { $py = (Get-Command python -ErrorAction Stop).Source }

& $py -m compileall -q sentinel/beta11_release_candidate_freeze.py tests/test_v011_beta11_b119_release_candidate_freeze.py
if ($LASTEXITCODE -ne 0) { throw 'B11-9 compile failed.' }

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b119-pytest-' + [guid]::NewGuid().ToString('N'))
$tests = @(Get-ChildItem tests/test_v011_beta5_*.py, tests/test_v011_beta6_*.py, tests/test_v011_beta7_*.py, tests/test_v011_beta8_*.py, tests/test_v011_beta9_*.py, tests/test_v011_beta10_*.py, tests/test_v011_beta11_*.py | Sort-Object FullName | ForEach-Object { $_.FullName })
try {
    & $py -m pytest -q --basetemp $testBase @tests
    if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta11 B11-9 full regression failed.' }
}
finally {
    if (Test-Path -LiteralPath $testBase) { Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue }
}

$freezeLines = @(& $py -m sentinel.beta11_release_candidate_freeze)
if ($LASTEXITCODE -ne 0) { throw 'B11-9 freeze-contract self-check failed.' }
$freezeText = $freezeLines -join [Environment]::NewLine
Write-Host $freezeText
$freeze = $freezeText | ConvertFrom-Json
if (-not $freeze.passed -or @($freeze.failures).Count -ne 0) { throw 'B11-9 freeze contract is not PASS.' }
if ($freeze.source_checkpoint -ne 'checkpoint/v011-beta11-b118-pass' -or $freeze.source_checkpoint_commit -ne $b118Accepted) { throw 'B11-9 predecessor binding mismatch.' }
if ($freeze.accepted_checkpoint_count -ne 9 -or $freeze.required_evidence_count -ne 10) { throw 'B11-9 evidence/checkpoint accounting mismatch.' }
if ($freeze.source_b118_contract_digest -ne '8fb9060e3e41146a400a9cebdeec8978b96909c6aa6b2e29327ad9c60fb36269') { throw 'B11-9 B11-8 contract digest mismatch.' }
if ($freeze.source_b118_transcript_digest -ne '1d010b2ff4a4e52f8fed405180ff404331c4ada08684cf1bc1e126600b62bf22') { throw 'B11-9 B11-8 transcript digest mismatch.' }
if ($freeze.release_publication_execution_available -or $freeze.artifact_signing_execution_available -or $freeze.authority_expanded -or $freeze.coverage_promoted) { throw 'B11-9 widened release/security authority.' }

$lifecycleLines = @(& $py -m sentinel.beta11_clean_pc_lifecycle_acceptance --run-disposable-acceptance)
if ($LASTEXITCODE -ne 0) { throw 'B11-9 B11-8 lifecycle replay failed.' }
$lifecycle = ($lifecycleLines -join [Environment]::NewLine) | ConvertFrom-Json
if (-not $lifecycle.passed -or $lifecycle.contract_digest -ne '8fb9060e3e41146a400a9cebdeec8978b96909c6aa6b2e29327ad9c60fb36269' -or $lifecycle.lifecycle_transcript_digest -ne '1d010b2ff4a4e52f8fed405180ff404331c4ada08684cf1bc1e126600b62bf22') { throw 'B11-9 lifecycle replay evidence mismatch.' }
Write-Host 'B11-9 B11-8 lifecycle replay: PASS'

$healthLines = @(& $py -m sentinel.beta11_first_run_health --health-json)
if ($LASTEXITCODE -ne 0) { throw 'B11-9 live first-run health probe failed.' }
$health = ($healthLines -join [Environment]::NewLine) | ConvertFrom-Json
if ($health.overall_status -ne 'READY' -or -not $health.ready_to_start -or $health.critical_failure_count -ne 0 -or $health.warning_count -ne 0) { throw 'B11-9 live first-run health is not READY.' }
Write-Host 'B11-9 live first-run health: READY'

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\BUILD-V011-BETA11-B112-ONEDIR.ps1' -DistRoot $DistRoot
if ($LASTEXITCODE -ne 0) { throw 'B11-9 fresh Windows onedir build failed.' }
if ([IO.Path]::IsPathRooted($DistRoot)) { $resolvedDist = $DistRoot } else { $resolvedDist = Join-Path $repoRoot $DistRoot }
$artifactRoot = Join-Path $resolvedDist 'BC-Sentinel-Beta11'
$exe = Join-Path $artifactRoot 'BC-Sentinel-Beta11.exe'
$manifestPath = Join-Path $artifactRoot 'artifact-integrity.json'
if (-not (Test-Path -LiteralPath $exe -PathType Leaf) -or -not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'B11-9 RC artifact or manifest missing.' }

& $py -m sentinel.beta11_artifact_manifest --validate --root $artifactRoot --build-commit $commit
if ($LASTEXITCODE -ne 0) { throw 'B11-9 artifact manifest validation failed.' }
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.build_commit -ne $commit -or -not $manifest.release_artifact_available) { throw 'B11-9 artifact is not bound to exact RC commit.' }
if ($manifest.startup_authority_expanded -or $manifest.coverage_promoted) { throw 'B11-9 artifact widened authority/coverage.' }

foreach ($arg in @('--identity-json', '--self-check', '--smoke')) {
    $process = Start-Process -FilePath $exe -ArgumentList $arg -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -ne 0) { throw ('B11-9 packaged runtime probe failed: ' + $arg) }
    Write-Host ('B11-9 packaged runtime probe ' + $arg + ': PASS')
}

$signature = Get-AuthenticodeSignature -LiteralPath $exe
$authState = 'SIGNED_UNVERIFIED'
$certSha256 = $null
if ($signature.Status -eq 'NotSigned') {
    $authState = 'UNSIGNED'
} elseif ($signature.Status -eq 'Valid' -and $null -ne $signature.SignerCertificate) {
    $authState = 'SIGNED_VERIFIED'
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $certSha256 = ([BitConverter]::ToString($sha.ComputeHash($signature.SignerCertificate.RawData))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
} else {
    throw ('B11-9 Authenticode signature is present/unresolved but not valid. Status=' + $signature.Status)
}
Write-Host ('B11-9 Authenticode state: ' + $authState)
if ($authState -eq 'SIGNED_VERIFIED') { Write-Host ('B11-9 signer certificate SHA256: ' + $certSha256) }
if ($authState -eq 'UNSIGNED') { Write-Host 'B11-9 candidate is accepted as an UNSIGNED release candidate; signed public-release readiness is not claimed.' }

if ($freeze.source_coverage.PARTIAL -ne 4 -or $freeze.source_coverage.GAP -ne 0 -or $freeze.source_coverage.VERIFIED -ne 2) { throw 'B11-9 coverage changed.' }

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'B11-9 acceptance modified tracked repository sources.' }

Write-Host ('B11-9 freeze contract digest: ' + $freeze.contract_digest)
Write-Host ('B11-9 artifact SHA256: ' + $manifest.artifact_sha256)
Write-Host ('B11-9 artifact tree digest: ' + $manifest.tree_digest)
Write-Host 'B11-9 Windows release-candidate evidence reconciliation: PASS'
Write-Host 'BC SENTINEL v0.11.0-beta.11 B11-9 WINDOWS RELEASE CANDIDATE ACCEPTANCE & FREEZE - PASS'
