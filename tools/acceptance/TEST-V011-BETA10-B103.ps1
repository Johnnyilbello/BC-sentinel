param([switch]$ConfirmLiveCoverageExpansion)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

if (-not $ConfirmLiveCoverageExpansion) { throw 'Explicit Beta10 B10-3 live coverage confirmation required.' }
$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve B10-3 acceptance commit.' }
Write-Host ('B10-3 Windows acceptance commit: ' + $commit)
& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B10-3 acceptance commit.' }

$frozen = '9882a6f675bcf53e99fee8cd8d6b92286dd3ce66'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted B10-2 predecessor missing.' }
$frozenPaths = @(& git ls-tree -r --name-only $frozen)
$changes = @(& git diff --name-only $frozen HEAD)
foreach ($path in $changes) {
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) { throw ('Frozen B10-2 path changed: ' + $path) }
}
$rootFiles = @(& git ls-files | Where-Object { $_ -notmatch '/' })
$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($rootFiles.Count -ne 10 -or $roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') { throw 'Repository hygiene failed.' }
Write-Host 'Frozen B10-2 paths and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) { $py = (Get-Command python -ErrorAction Stop).Source }
& $py -m compileall -q sentinel/beta10_powershell_controls.py tests/test_v011_beta10_b103_powershell_controls.py
if ($LASTEXITCODE -ne 0) { throw 'B10-3 compile failed.' }

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b103-pytest-' + [guid]::NewGuid().ToString('N'))
$tests = @(Get-ChildItem tests/test_v011_beta5_*.py,tests/test_v011_beta6_*.py,tests/test_v011_beta7_*.py,tests/test_v011_beta8_*.py,tests/test_v011_beta9_*.py,tests/test_v011_beta10_*.py | Sort-Object FullName | ForEach-Object { $_.FullName })
& $py -m pytest -q --basetemp $testBase @tests
if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta10 B10-3 regression failed.' }

$liveBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b103-live-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $liveBase -Force | Out-Null
$evidence = Join-Path $liveBase 'powershell-live-controls.json'
$assertFile = Join-Path $liveBase 'assert_b103.py'
try {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\tools\acceptance\RUN-V011-BETA10-B103-POWERSHELL.ps1' -ConfirmLivePowerShellControls -Output $evidence
    if ($LASTEXITCODE -ne 0) { throw 'B10-3 live PowerShell control exercise failed.' }

    & $py -m sentinel.beta10_powershell_controls --evidence $evidence
    if ($LASTEXITCODE -ne 0) { throw 'B10-3 PowerShell detector-path verification failed.' }

    @'
import json, sys
from pathlib import Path
from sentinel.beta10_powershell_controls import summarize
p = Path(sys.argv[1])
data = json.loads(p.read_text(encoding="utf-8-sig"))
r = summarize(data)
assert r["passed"], r
assert r["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}, r
statuses = {x["scenario_id"]: x["status"] for x in r["coverage_decisions"]}
assert statuses["B7-POWERSHELL-001"] == "VERIFIED"
assert statuses["B7-RANSOMWARE-001"] == "VERIFIED"
assert statuses["B7-PERSISTENCE-001"] == "PARTIAL"
outcomes = {k:v["outcome"] for k,v in r["control_results"].items()}
assert outcomes == {"positive-powershell-burst":"DETECTED","administrative-powershell-burst":"REVIEW_REQUIRED","benign-powershell-session":"NO_MATCH"}, outcomes
assert r["controlled_threat_detector_verification_performed"] is True
assert r["powershell_content_read"] is False
assert r["synthetic_fallback_used"] is False
assert r["broad_powershell_protection_claimed"] is False
assert r["broad_protection_claimed"] is False
assert r["authority_expanded"] is False
assert r["detector_to_security_graph_bound"] is True
assert r["security_graph_to_incident_bound"] is True
for key in ("event_message_read","event_payload_read","event_properties_read","powershell_command_read","powershell_script_read","personal_data_collected","user_file_access","file_content_collected","absolute_paths_exported","remote_access","network_io","logging_configuration_mutation","audit_policy_mutation","registry_mutation","credential_access","real_malware_executed","product_process_launch_authority","product_process_termination_authority","remediation_authority","automatic_quarantine","privileged_system_mutation"):
    assert r["boundaries"][key] is False, key
print(json.dumps({"b10_3_passed": True, "coverage_summary": r["coverage_summary"], "verified_scenarios": [k for k,v in statuses.items() if v == "VERIFIED"], "control_outcomes": outcomes, "powershell_content_read": r["powershell_content_read"], "authority_expanded": r["authority_expanded"]}, indent=2, sort_keys=True))
'@ | Set-Content -LiteralPath $assertFile -Encoding UTF8
    & $py $assertFile $evidence
    if ($LASTEXITCODE -ne 0) { throw 'B10-3 final acceptance assertions failed.' }
}
finally {
    if (Test-Path -LiteralPath $liveBase) { Remove-Item -LiteralPath $liveBase -Recurse -Force }
}

Write-Host 'BC SENTINEL v0.11.0-beta.10 B10-3 LIVE COVERAGE EXPANSION I - PASS'
