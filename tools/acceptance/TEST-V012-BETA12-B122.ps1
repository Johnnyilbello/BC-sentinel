param([switch]$ConfirmLiveScriptAbuseExpansion)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot
$env:PYTHONPATH = $repoRoot

if (-not $ConfirmLiveScriptAbuseExpansion) {
    throw 'Explicit Beta12 B12-2 live script-abuse confirmation required.'
}

$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve B12-2 acceptance commit.' }
Write-Host ('B12-2 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B12-2 acceptance commit.' }

$frozen = 'cd8b3e89211afe29bf32a2646f4210c73179bc1f'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted Beta12 B12-1 predecessor missing.' }

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate frozen B12-1 paths.' }
$changes = @(& git diff --name-only $frozen HEAD)
if ($LASTEXITCODE -ne 0) { throw 'Cannot compare frozen B12-1 sources.' }

$allowed = @(
    '.github/workflows/b122-powershell-script-abuse-expansion.yml',
    'ROADMAP.md',
    'sentinel/beta12_script_abuse_controls.py',
    'tests/test_v012_beta12_b122_script_abuse_controls.py',
    'tools/acceptance/RUN-V012-BETA12-B122-SCRIPT-ABUSE.ps1',
    'tools/acceptance/TEST-V012-BETA12-B122.ps1'
)

if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B12-2 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) {
        throw ('Unexpected B12-2 changed path: ' + $path)
    }
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B12-1 path changed: ' + $path)
    }
}

$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository roadmap hygiene failed.'
}
Write-Host 'Accepted B12-1 source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta12_script_abuse_controls.py tests/test_v012_beta12_b122_script_abuse_controls.py
if ($LASTEXITCODE -ne 0) { throw 'B12-2 compile failed.' }

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

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b122-' + [guid]::NewGuid().ToString('N'))
& $py -m pytest -q --basetemp $testBase @tests
if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta12 B12-2 regression failed.' }

& $py -m sentinel.beta12_script_abuse_controls --self-check
if ($LASTEXITCODE -ne 0) { throw 'B12-2 contract self-check failed.' }

$liveBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b122-live-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $liveBase -Force | Out-Null
$evidence = Join-Path $liveBase 'script-abuse-live-controls.json'
$assertFile = Join-Path $liveBase 'assert_b122.py'

try {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\tools\acceptance\RUN-V012-BETA12-B122-SCRIPT-ABUSE.ps1' -ConfirmLiveScriptAbuseControls -Output $evidence
    if ($LASTEXITCODE -ne 0) { throw 'B12-2 harmless live script-abuse exercise failed.' }

    & $py -m sentinel.beta12_script_abuse_controls --evidence $evidence
    if ($LASTEXITCODE -ne 0) { throw 'B12-2 live script-abuse detector-path verification failed.' }

    @'
import json, sys
from pathlib import Path
from sentinel.beta12_script_abuse_controls import summarize

p = Path(sys.argv[1])
data = json.loads(p.read_text(encoding="utf-8-sig"))
r = summarize(data)

assert r["passed"], r
assert r["target_scenario_id"] == "B12-SCRIPT-ABUSE-001", r
assert r["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 3}, r
assert r["verified_scenarios"] == [
    "B7-POWERSHELL-001",
    "B7-RANSOMWARE-001",
    "B12-SCRIPT-ABUSE-001",
], r
assert r["new_verified_scenario_earned"] is True, r

outcomes = {k:v["outcome"] for k,v in r["control_results"].items()}
assert outcomes == {
    "positive-script-mutation-burst": "DETECTED",
    "administrative-script-mutation-burst": "REVIEW_REQUIRED",
    "benign-powershell-script": "NO_MATCH",
}, outcomes

assert r["detector_to_security_graph_bound"] is True
assert r["security_graph_to_incident_bound"] is True
assert r["script_content_exported"] is False
assert r["command_line_exported"] is False
assert r["raw_path_exported"] is False
assert r["synthetic_fallback_used"] is False
assert r["broad_powershell_protection_claimed"] is False
assert r["authority_expanded"] is False
assert r["network_required"] is False
assert r["cloud_required"] is False

for key in (
    "script_content_exported",
    "command_line_exported",
    "raw_path_exported",
    "username_collected",
    "event_payload_collected",
    "credential_access",
    "network_io",
    "remote_access",
    "registry_mutation",
    "logging_configuration_mutation",
    "audit_policy_mutation",
    "real_malware_executed",
    "automatic_quarantine",
    "automatic_repair",
    "automatic_restore",
    "terminate_process_authority",
    "trust_allowlist_mutation",
    "privileged_system_mutation",
):
    assert r["boundaries"][key] is False, key

print(json.dumps({
    "b12_2_passed": True,
    "coverage_summary": r["coverage_summary"],
    "verified_scenarios": r["verified_scenarios"],
    "control_outcomes": outcomes,
    "graph_digest": r["graph_digest"],
    "correlation_digest": r["correlation_digest"],
    "authority_expanded": r["authority_expanded"],
}, indent=2, sort_keys=True))
'@ | Set-Content -LiteralPath $assertFile -Encoding UTF8

    & $py $assertFile $evidence
    if ($LASTEXITCODE -ne 0) { throw 'B12-2 final live acceptance assertions failed.' }
}
finally {
    if (Test-Path -LiteralPath $liveBase) {
        Remove-Item -LiteralPath $liveBase -Recurse -Force
    }
}

Write-Host 'BC SENTINEL v0.12.0-beta.12 B12-2 POWERSHELL & SCRIPT ABUSE EXPANSION - PASS'
