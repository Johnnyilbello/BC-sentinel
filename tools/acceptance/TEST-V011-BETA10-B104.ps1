param([switch]$ConfirmSafeResponsePlan)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot
$env:PYTHONPATH = $repoRoot

if (-not $ConfirmSafeResponsePlan) { throw 'Explicit Beta10 B10-4 Safe Response Plan confirmation required.' }
$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve B10-4 acceptance commit.' }
Write-Host ('B10-4 Windows acceptance commit: ' + $commit)
& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B10-4 acceptance commit.' }

$frozen = 'b3de7f34cb7ddc381499f34cf68ebd4dd02c0fb8'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted B10-3 predecessor missing.' }
$frozenPaths = @(& git ls-tree -r --name-only $frozen)
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate frozen B10-3 paths.' }
$changes = @(& git diff --name-only $frozen HEAD)
if ($LASTEXITCODE -ne 0) { throw 'Cannot compare frozen B10-3 sources.' }
foreach ($path in $changes) {
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B10-3 path changed: ' + $path)
    }
}
$rootFiles = @(& git ls-files | Where-Object { $_ -notmatch '/' })
$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($rootFiles.Count -ne 10 -or $roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository hygiene failed.'
}
Write-Host 'Frozen B10-3 paths and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) { $py = (Get-Command python -ErrorAction Stop).Source }
& $py -m compileall -q sentinel/beta10_safe_response_plan.py tests/test_v011_beta10_b104_safe_response_plan.py
if ($LASTEXITCODE -ne 0) { throw 'B10-4 compile failed.' }

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b104-pytest-' + [guid]::NewGuid().ToString('N'))
$tests = @(Get-ChildItem tests/test_v011_beta5_*.py,tests/test_v011_beta6_*.py,tests/test_v011_beta7_*.py,tests/test_v011_beta8_*.py,tests/test_v011_beta9_*.py,tests/test_v011_beta10_*.py | Sort-Object FullName | ForEach-Object { $_.FullName })
& $py -m pytest -q --basetemp $testBase @tests
if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta10 B10-4 regression failed.' }

$liveBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b104-live-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $liveBase -Force | Out-Null
$evidence = Join-Path $liveBase 'b93-live-evidence.json'
try {
    & $py '.\tools\acceptance\RUN-V011-BETA9-B93-LIVE-FILES.py' --output $evidence --confirm-live-controls
    if ($LASTEXITCODE -ne 0) { throw 'B10-4 live file-control exercise failed.' }

    & $py -m sentinel.beta10_safe_response_plan --b93-evidence $evidence
    if ($LASTEXITCODE -ne 0) { throw 'B10-4 live Safe Response Plan generation failed.' }

    $assertCode = @'
import json, sys
from pathlib import Path
from sentinel.beta10_safe_response_plan import plan_from_b93_evidence, validate_b104_contract
p = Path(sys.argv[1])
evidence = json.loads(p.read_text(encoding='utf-8-sig'))
r = plan_from_b93_evidence(evidence)
assert r['passed'], r
assert r['plan_state'] == 'PLANNED_NOT_EXECUTABLE'
assert r['coverage_summary'] == {'PARTIAL': 4, 'GAP': 0, 'VERIFIED': 2}
assert r['coverage_changed'] is False
assert r['broad_protection_claimed'] is False
assert r['authority_expanded'] is False
assert r['execution_api'] is False
assert r['execution_available'] is False
assert r['execution_authorized'] is False
assert r['automatic_action'] is False
assert r['remediation_performed'] is False
assert r['system_mutation_performed'] is False
assert r['response_stage_claimed_observed'] is False
assert r['source_response_stage_status'] == 'UNKNOWN'
assert r['source_live_control'] is True
assert r['source_detector_outcome'] == 'DETECTED'
assert r['source_detector_score'] == 10
assert r['detector_to_security_graph_bound'] is True
assert r['security_graph_to_incident_bound'] is True
assert r['synthetic_fallback_used'] is False
assert r['legacy_guided_resolution_boundary_preserved'] is True
assert not any(r['authority_boundary'].values())
assert r['privacy']['personal_data_collected'] is False
assert r['privacy']['file_content_collected'] is False
assert r['privacy']['absolute_paths_exported'] is False
assert r['privacy']['remote_access'] is False
assert r['observed_stage_ids'] == ['FILE_ACTIVITY', 'DETECTION'], r['observed_stage_ids']
assert r['unknown_stage_ids'] == ['ENTRY_POINT', 'EXECUTION', 'PERSISTENCE', 'NETWORK_ACTIVITY', 'RESPONSE'], r['unknown_stage_ids']
actions = r['actions']
assert [a['action_id'] for a in actions] == [
    'PRESERVE_INCIDENT_EVIDENCE',
    'PREPARE_CONTAINMENT',
    'VERIFY_UNKNOWN_STAGES',
    'PREPARE_RESCUE_HANDOFF',
]
assert all(a['execution_available'] is False for a in actions)
assert all(a['execution_authorized'] is False for a in actions)
assert all(a['automatic'] is False for a in actions)
assert all(a['mutates_system'] is False for a in actions)
containment = actions[1]
assert containment['state'] == 'BLOCKED_AUTHORITY'
assert containment['would_mutate_system_if_executed'] is True
assert containment['rollback_required'] is True
assert containment['user_confirmation_required'] is True
for blocker in (
    'execution_authority_not_granted',
    'quarantine_authority_not_granted',
    'target_identity_binding_required',
    'journal_storage_not_bound',
    'rollback_not_bound',
):
    assert blocker in containment['blockers']
contract = validate_b104_contract()
assert contract['passed']
assert contract['planning_only'] is True
assert contract['execution_api'] is False
assert contract['legacy_guided_resolution_boundary_preserved'] is True
print(json.dumps({
    'safe_response_plan_passed': True,
    'action_count': len(actions),
    'action_ids': [a['action_id'] for a in actions],
    'containment_state': containment['state'],
    'source_response_stage_status': r['source_response_stage_status'],
    'coverage_summary': r['coverage_summary'],
    'authority_expanded': r['authority_expanded'],
    'execution_authorized': r['execution_authorized'],
    'remediation_performed': r['remediation_performed'],
}, indent=2, sort_keys=True))
'@
    & $py -c $assertCode $evidence
    if ($LASTEXITCODE -ne 0) { throw 'B10-4 Safe Response Plan acceptance assertions failed.' }
}
finally {
    if (Test-Path -LiteralPath $liveBase) { Remove-Item -LiteralPath $liveBase -Recurse -Force }
}

Write-Host 'BC SENTINEL v0.11.0-beta.10 B10-4 SAFE RESPONSE PLAN ENGINE - PASS'
