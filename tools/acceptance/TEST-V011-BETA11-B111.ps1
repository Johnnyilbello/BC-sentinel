param([switch]$ConfirmCanonicalDesktopEntry)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot
$env:PYTHONPATH = $repoRoot

if (-not $ConfirmCanonicalDesktopEntry) {
    throw 'Explicit Beta11 B11-1 Canonical Desktop Entry confirmation required.'
}

$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve B11-1 acceptance commit.' }
Write-Host ('B11-1 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B11-1 acceptance commit.' }

$b110Accepted = '0bee65100c6713d11dedd56c28ee3118f0082624'
& git merge-base --is-ancestor $b110Accepted HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted B11-0 predecessor is missing.' }

$checkpointSha = (& git rev-parse 'refs/remotes/origin/checkpoint/v011-beta11-b110-pass' 2>$null)
if ($LASTEXITCODE -ne 0) {
    $checkpointSha = (& git rev-parse 'checkpoint/v011-beta11-b110-pass' 2>$null)
}
if ($LASTEXITCODE -ne 0 -or [string]$checkpointSha -ne $b110Accepted) {
    throw 'B11-0 immutable checkpoint is missing or points to the wrong commit.'
}

$predecessorPaths = @(& git ls-tree -r --name-only $b110Accepted)
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate accepted B11-0 predecessor paths.' }
$changes = @(& git diff --name-only $b110Accepted HEAD)
if ($LASTEXITCODE -ne 0) { throw 'Cannot compare accepted B11-0 predecessor sources.' }

$allowedNew = @(
    'sentinel/beta11_runtime_identity.py',
    'packaging/beta11_desktop_entry.py',
    'tests/test_v011_beta11_b111_canonical_desktop_entry.py',
    'tools/acceptance/RUN-V011-BETA11-B111-ENTRY.py',
    'tools/acceptance/TEST-V011-BETA11-B111.ps1',
    '.github/workflows/b111-canonical-desktop-entry.yml'
)

foreach ($path in $changes) {
    if ($predecessorPaths -contains $path) {
        throw ('Accepted B11-0 predecessor path changed: ' + $path)
    }
    if ($allowedNew -notcontains $path) {
        throw ('Unexpected B11-1 path changed: ' + $path)
    }
}

$rootFiles = @(& git ls-files | Where-Object { $_ -notmatch '/' })
$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($rootFiles.Count -ne 10 -or $roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository hygiene failed.'
}
Write-Host 'Accepted B11-0 predecessor immutability, checkpoint identity and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q `
    sentinel/beta11_runtime_identity.py `
    packaging/beta11_desktop_entry.py `
    tests/test_v011_beta11_b111_canonical_desktop_entry.py `
    tools/acceptance/RUN-V011-BETA11-B111-ENTRY.py
if ($LASTEXITCODE -ne 0) { throw 'B11-1 compile failed.' }

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b111-pytest-' + [guid]::NewGuid().ToString('N'))
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
    if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta11 B11-1 full regression failed.' }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

& $py '.\tools\acceptance\RUN-V011-BETA11-B111-ENTRY.py'
if ($LASTEXITCODE -ne 0) { throw 'B11-1 runtime identity self-check failed.' }

& $py '.\packaging\beta11_desktop_entry.py' --self-check
if ($LASTEXITCODE -ne 0) { throw 'B11-1 canonical desktop self-check failed.' }

& $py '.\packaging\beta11_desktop_entry.py' --smoke
if ($LASTEXITCODE -ne 0) { throw 'B11-1 canonical desktop UI smoke failed.' }

$contractCode = @'
from pathlib import Path
from sentinel.beta11_runtime_identity import runtime_identity, validate_runtime_identity, self_check

identity = runtime_identity()
result = self_check()
assert result["passed"]
assert validate_runtime_identity(identity) == ()
assert identity["source_checkpoint"] == "checkpoint/v011-beta11-b110-pass"
assert identity["source_checkpoint_commit"] == "0bee65100c6713d11dedd56c28ee3118f0082624"
assert identity["canonical_entrypoint"] == "packaging/beta11_desktop_entry.py"
assert identity["canonical_ui_module"] == "sentinel.beta10_trust_center_ui"
assert identity["canonical_ui_class"] == "TrustCenterWindow"
assert identity["expected_page_count"] == 7
assert identity["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
assert identity["verified_scenarios"] == ["B7-POWERSHELL-001", "B7-RANSOMWARE-001"]
state = identity["distribution_state"]
assert state["canonical_beta11_desktop_entry_available"] is True
assert state["runtime_identity_available"] is True
assert state["trust_center_included"] is True
assert state["beta11_release_artifact_available"] is False
assert state["installer_available"] is False
assert state["artifact_signed"] is False
assert not any(identity["startup_boundary"].values())
assert identity["release_artifact_claimed"] is False
assert identity["signing_claimed"] is False
assert identity["authority_expanded_in_b111"] is False
assert identity["coverage_promoted_in_b111"] is False
source = Path("packaging/beta11_desktop_entry.py").read_text(encoding="utf-8")
assert "beta10_trust_center_ui as product_ui" in source
assert "product_ui.TrustCenterWindow" in source
assert "from sentinel.home_security_ui import main" not in source
print("B11-1 contract assertions: PASS")
'@

$contractScript = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b111-contract-' + [guid]::NewGuid().ToString('N') + '.py')
try {
    Set-Content -LiteralPath $contractScript -Value $contractCode -Encoding UTF8
    & $py $contractScript
    if ($LASTEXITCODE -ne 0) { throw 'B11-1 contract assertions failed.' }
}
finally {
    Remove-Item -LiteralPath $contractScript -Force -ErrorAction SilentlyContinue
}

Write-Host 'BC SENTINEL v0.11.0-beta.11 B11-1 CANONICAL DESKTOP ENTRY + RUNTIME IDENTITY - PASS'
