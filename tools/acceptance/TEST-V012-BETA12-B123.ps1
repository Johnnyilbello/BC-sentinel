param([switch]$ConfirmLiveAutostartDetection)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot
$env:PYTHONPATH = $repoRoot

if (-not $ConfirmLiveAutostartDetection) {
    throw 'Explicit Beta12 B12-3 live autostart-detection confirmation required.'
}

$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve B12-3 acceptance commit.' }
Write-Host ('B12-3 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B12-3 acceptance commit.' }

$frozen = 'dedf78ae920b87f44636a0b9bd0c9708d2ae760b'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted Beta12 B12-2 predecessor missing.' }

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate frozen B12-2 paths.' }
$changes = @(& git diff --name-only $frozen HEAD)
if ($LASTEXITCODE -ne 0) { throw 'Cannot compare frozen B12-2 sources.' }

$allowed = @(
    '.github/workflows/b123-persistence-autostart-detection.yml',
    'ROADMAP.md',
    'sentinel/beta12_autostart_detection.py',
    'tests/test_v012_beta12_b123_autostart_detection.py',
    'tools/acceptance/RUN-V012-BETA12-B123-AUTOSTART.ps1',
    'tools/acceptance/TEST-V012-BETA12-B123.ps1'
)

if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B12-3 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) {
        throw ('Unexpected B12-3 changed path: ' + $path)
    }
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B12-2 path changed: ' + $path)
    }
}

$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository roadmap hygiene failed.'
}
Write-Host 'Accepted B12-2 source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta12_autostart_detection.py tests/test_v012_beta12_b123_autostart_detection.py
if ($LASTEXITCODE -ne 0) { throw 'B12-3 compile failed.' }

$patterns = @(
    'tests/test_v011_beta5_*.py',
    'tests/test_v011_beta6_*.py',
    'tests/test_v011_beta7_*.py',
    'tests/test_v011_beta8_*.py',
    'tests/test_v011_beta9_*.py',
    'tests/test_v011_beta10_*.py',
    'tests/test_v011_beta11_*.py',
    'tests/test_v012_beta12_*.py'
)
$tests = @(
    $patterns |
        ForEach-Object { Get-ChildItem $_ } |
        Sort-Object FullName |
        ForEach-Object { $_.FullName }
)

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b123-' + [guid]::NewGuid().ToString('N'))
& $py -m pytest -q --basetemp $testBase @tests
if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta12 B12-3 regression failed.' }

& $py -m sentinel.beta12_autostart_detection --self-check
if ($LASTEXITCODE -ne 0) { throw 'B12-3 contract self-check failed.' }

$liveBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b123-live-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $liveBase -Force | Out-Null
$evidence = Join-Path $liveBase 'autostart-live-controls.json'
$assertFile = Join-Path $liveBase 'assert_b123.py'

try {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\tools\acceptance\RUN-V012-BETA12-B123-AUTOSTART.ps1' -ConfirmLiveAutostartShortcutControls -Output $evidence
    if ($LASTEXITCODE -ne 0) { throw 'B12-3 harmless live Windows shortcut exercise failed.' }

    & $py -m sentinel.beta12_autostart_detection --evidence $evidence
    if ($LASTEXITCODE -ne 0) { throw 'B12-3 live autostart detector-path verification failed.' }

    @'
import json, sys
from pathlib import Path
from sentinel.beta12_autostart_detection import summarize

p = Path(sys.argv[1])
data = json.loads(p.read_text(encoding="utf-8-sig"))
r = summarize(data)

assert r["passed"], r
assert r["target_scenario_id"] == "B12-AUTOSTART-LINK-001", r
assert r["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 4}, r
assert r["verified_scenarios"] == [
    "B7-POWERSHELL-001",
    "B7-RANSOMWARE-001",
    "B12-SCRIPT-ABUSE-001",
    "B12-AUTOSTART-LINK-001",
], r
assert r["new_verified_scenario_earned"] is True
assert r["legacy_persistence_scenario_promoted"] is False

outcomes = {k:v["outcome"] for k,v in r["control_results"].items()}
assert outcomes == {
    "positive-autostart-like-shortcut": "DETECTED",
    "administrative-autostart-like-shortcut": "REVIEW_REQUIRED",
    "benign-shortcut": "NO_MATCH",
}, outcomes

assert r["detector_to_security_graph_bound"] is True
assert r["security_graph_to_incident_bound"] is True
assert r["actual_persistence_surface_mutated"] is False
assert r["actual_persistence_execution_verified"] is False
assert r["raw_path_exported"] is False
assert r["shortcut_arguments_exported"] is False
assert r["authority_expanded"] is False
assert r["network_required"] is False
assert r["cloud_required"] is False

for key in (
    "real_startup_folder_mutated",
    "registry_run_key_mutated",
    "scheduled_task_mutated",
    "service_mutated",
    "shell_extension_mutated",
    "raw_path_exported",
    "shortcut_arguments_exported",
    "username_collected",
    "credential_access",
    "network_io",
    "remote_access",
    "automatic_quarantine",
    "automatic_repair",
    "automatic_restore",
    "terminate_process_authority",
    "trust_allowlist_mutation",
    "privileged_system_mutation",
):
    assert r["boundaries"][key] is False, key

print(json.dumps({
    "b12_3_passed": True,
    "coverage_summary": r["coverage_summary"],
    "verified_scenarios": r["verified_scenarios"],
    "control_outcomes": outcomes,
    "graph_digest": r["graph_digest"],
    "correlation_digest": r["correlation_digest"],
    "legacy_persistence_scenario_promoted": r["legacy_persistence_scenario_promoted"],
    "actual_persistence_surface_mutated": r["actual_persistence_surface_mutated"],
}, indent=2, sort_keys=True))
'@ | Set-Content -LiteralPath $assertFile -Encoding UTF8

    & $py $assertFile $evidence
    if ($LASTEXITCODE -ne 0) { throw 'B12-3 final live acceptance assertions failed.' }
}
finally {
    if (Test-Path -LiteralPath $liveBase) {
        Remove-Item -LiteralPath $liveBase -Recurse -Force
    }
}

Write-Host 'BC SENTINEL v0.12.0-beta.12 B12-3 PERSISTENCE & AUTOSTART DETECTION - PASS'
