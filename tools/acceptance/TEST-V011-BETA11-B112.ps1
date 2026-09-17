param(
    [switch]$ConfirmReproducibleOnedirBuild,
    [string]$DistRoot = ".\dist\Beta11-B112"
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot
$env:PYTHONPATH = $repoRoot

if (-not $ConfirmReproducibleOnedirBuild) {
    throw 'Explicit Beta11 B11-2 Reproducible Onedir Build confirmation required.'
}

$commit = (& git rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve B11-2 acceptance commit.' }
Write-Host ('B11-2 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B11-2 acceptance commit.' }

$b111Accepted = '2d49bc2037d3d1f3fb40280277cf8d53927cc68b'
& git merge-base --is-ancestor $b111Accepted HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted B11-1 predecessor is missing.' }

$checkpointSha = (& git rev-parse 'refs/remotes/origin/checkpoint/v011-beta11-b111-pass' 2>$null)
if ($LASTEXITCODE -ne 0) { $checkpointSha = (& git rev-parse 'checkpoint/v011-beta11-b111-pass' 2>$null) }
if ($LASTEXITCODE -ne 0 -or [string]$checkpointSha -ne $b111Accepted) {
    throw 'B11-1 immutable checkpoint is missing or points to the wrong commit.'
}

$predecessorPaths = @(& git ls-tree -r --name-only $b111Accepted)
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate accepted B11-1 predecessor paths.' }
$changes = @(& git diff --name-only $b111Accepted HEAD)
if ($LASTEXITCODE -ne 0) { throw 'Cannot compare accepted B11-1 predecessor sources.' }

$allowedNew = @(
    'packaging/beta11_windowed_runtime_hook.py',
    'sentinel/beta11_artifact_manifest.py',
    'BUILD-V011-BETA11-B112-ONEDIR.ps1',
    'tests/test_v011_beta11_b112_reproducible_windows_onedir.py',
    'tools/acceptance/TEST-V011-BETA11-B112.ps1',
    '.github/workflows/b112-reproducible-windows-onedir.yml'
)
foreach ($path in $changes) {
    if ($predecessorPaths -contains $path) { throw ('Accepted B11-1 predecessor path changed: ' + $path) }
    if ($allowedNew -notcontains $path) { throw ('Unexpected B11-2 path changed: ' + $path) }
}
foreach ($path in $allowedNew) {
    if ($changes -notcontains $path) { throw ('Expected B11-2 path missing from diff: ' + $path) }
}
$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') { throw 'Repository roadmap hygiene failed.' }
Write-Host 'Accepted B11-1 predecessor immutability, checkpoint identity and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) { $py = (Get-Command python -ErrorAction Stop).Source }

& $py -m compileall -q `
    sentinel/beta11_artifact_manifest.py `
    packaging/beta11_windowed_runtime_hook.py `
    tests/test_v011_beta11_b112_reproducible_windows_onedir.py
if ($LASTEXITCODE -ne 0) { throw 'B11-2 compile failed.' }

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b112-pytest-' + [guid]::NewGuid().ToString('N'))
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
    if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta11 B11-2 full regression failed.' }
}
finally {
    if (Test-Path -LiteralPath $testBase) { Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue }
}

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\BUILD-V011-BETA11-B112-ONEDIR.ps1' -DistRoot $DistRoot
if ($LASTEXITCODE -ne 0) { throw 'B11-2 PyInstaller onedir build failed.' }

if ([IO.Path]::IsPathRooted($DistRoot)) { $resolvedDist = $DistRoot } else { $resolvedDist = Join-Path $repoRoot $DistRoot }
$artifactRoot = Join-Path $resolvedDist 'BC-Sentinel-Beta11'
$exe = Join-Path $artifactRoot 'BC-Sentinel-Beta11.exe'
$manifestPath = Join-Path $artifactRoot 'artifact-integrity.json'
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'B11-2 executable missing.' }
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'B11-2 manifest missing.' }

& $py -m sentinel.beta11_artifact_manifest --validate --root $artifactRoot --build-commit $commit
if ($LASTEXITCODE -ne 0) { throw 'B11-2 post-build integrity validation failed.' }

$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.build_commit -ne $commit) { throw 'B11-2 manifest is not bound to the exact acceptance commit.' }
if ($manifest.source_checkpoint -ne 'checkpoint/v011-beta11-b111-pass') { throw 'B11-2 source checkpoint mismatch.' }
if ($manifest.source_checkpoint_commit -ne $b111Accepted) { throw 'B11-2 source checkpoint commit mismatch.' }
if ($manifest.canonical_entrypoint -ne 'packaging/beta11_desktop_entry.py') { throw 'B11-2 canonical entrypoint mismatch.' }
if ($manifest.build_mode -ne 'onedir' -or -not $manifest.windowed) { throw 'B11-2 build-mode contract mismatch.' }
if (-not $manifest.release_artifact_available) { throw 'B11-2 release artifact was not declared available.' }
if ($manifest.installer_available -or $manifest.artifact_signed) { throw 'B11-2 cannot claim installer/signing acceptance.' }
if ($manifest.startup_authority_expanded -or $manifest.coverage_promoted) { throw 'B11-2 widened authority or coverage.' }
if ($manifest.source_coverage.PARTIAL -ne 4 -or $manifest.source_coverage.GAP -ne 0 -or $manifest.source_coverage.VERIFIED -ne 2) { throw 'B11-2 coverage changed.' }
if ($manifest.file_count -lt 2 -or $manifest.total_bytes -le 0) { throw 'B11-2 artifact inventory is implausible.' }
if ([string]$manifest.artifact_sha256 -notmatch '^[0-9a-f]{64}$' -or [string]$manifest.tree_digest -notmatch '^[0-9a-f]{64}$') { throw 'B11-2 artifact digest invalid.' }

foreach ($arg in @('--identity-json', '--self-check', '--smoke')) {
    $process = Start-Process -FilePath $exe -ArgumentList $arg -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -ne 0) { throw ('B11-2 packaged executable failed runtime probe ' + $arg + ' exit=' + $process.ExitCode) }
    Write-Host ('B11-2 packaged runtime probe ' + $arg + ': PASS')
}

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'B11-2 build modified tracked repository sources.' }

Write-Host ('B11-2 artifact SHA256: ' + $manifest.artifact_sha256)
Write-Host ('B11-2 tree digest: ' + $manifest.tree_digest)
Write-Host ('B11-2 artifact files: ' + $manifest.file_count + '; bytes=' + $manifest.total_bytes)
Write-Host ('B11-2 artifact folder: ' + $artifactRoot)
Write-Host 'B11-2 contract assertions: PASS'
Write-Host 'BC SENTINEL v0.11.0-beta.11 B11-2 REPRODUCIBLE WINDOWS ONEDIR BUILD - PASS'
