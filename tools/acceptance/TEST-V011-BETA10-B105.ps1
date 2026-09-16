param([switch]$ConfirmRescueContinuity)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot
$env:PYTHONPATH = $repoRoot

if (-not $ConfirmRescueContinuity) { throw 'Explicit Beta10 B10-5 Rescue Continuity confirmation required.' }
$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve B10-5 acceptance commit.' }
Write-Host ('B10-5 Windows acceptance commit: ' + $commit)
& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B10-5 acceptance commit.' }

$frozen = 'a23550a0cf31aecdce54d5eca333b3930ca2edc7'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted B10-4 predecessor missing.' }
$frozenPaths = @(& git ls-tree -r --name-only $frozen)
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate frozen B10-4 paths.' }
$changes = @(& git diff --name-only $frozen HEAD)
if ($LASTEXITCODE -ne 0) { throw 'Cannot compare frozen B10-4 sources.' }
foreach ($path in $changes) {
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B10-4 path changed: ' + $path)
    }
}
$rootFiles = @(& git ls-files | Where-Object { $_ -notmatch '/' })
$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($rootFiles.Count -ne 10 -or $roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository hygiene failed.'
}
Write-Host 'Frozen B10-4 paths and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) { $py = (Get-Command python -ErrorAction Stop).Source }
& $py -m compileall -q sentinel/beta10_rescue_continuity.py tests/test_v011_beta10_b105_rescue_continuity.py
if ($LASTEXITCODE -ne 0) { throw 'B10-5 compile failed.' }

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b105-pytest-' + [guid]::NewGuid().ToString('N'))
$tests = @(Get-ChildItem tests/test_v011_beta5_*.py,tests/test_v011_beta6_*.py,tests/test_v011_beta7_*.py,tests/test_v011_beta8_*.py,tests/test_v011_beta9_*.py,tests/test_v011_beta10_*.py | Sort-Object FullName | ForEach-Object { $_.FullName })
& $py -m pytest -q --basetemp $testBase @tests
if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta10 B10-5 regression failed.' }

$liveBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b105-live-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $liveBase -Force | Out-Null
$evidence = Join-Path $liveBase 'b93-live-evidence.json'
$transport = Join-Path $liveBase 'b105-rescue-continuity.json'
try {
    & $py '.\tools\acceptance\RUN-V011-BETA9-B93-LIVE-FILES.py' --output $evidence --confirm-live-controls
    if ($LASTEXITCODE -ne 0) { throw 'B10-5 live file-control exercise failed.' }

    & $py -m sentinel.beta10_rescue_continuity --b93-evidence $evidence
    if ($LASTEXITCODE -ne 0) { throw 'B10-5 live Rescue Continuity generation failed.' }

    $assertCode = @'
import json, sys
from pathlib import Path
from sentinel.beta10_rescue_continuity import (
    continuity_from_b93_evidence,
    validate_b105_contract,
    validate_continuity_envelope,
    validate_rescue_projection,
)

evidence_path = Path(sys.argv[1])
transport_path = Path(sys.argv[2])
evidence = json.loads(evidence_path.read_text(encoding='utf-8-sig'))
r = continuity_from_b93_evidence(evidence)
assert r['passed'], r
assert r['source_detector_outcome'] == 'DETECTED'
assert r['source_detector_score'] == 10
assert r['detector_to_security_graph_bound'] is True
assert r['security_graph_to_incident_bound'] is True
assert r['synthetic_fallback_used'] is False

envelope = r['envelope']
assert validate_continuity_envelope(envelope)['passed'], envelope
assert envelope['source_checkpoint'] == 'checkpoint/v011-beta10-b104-pass'
assert envelope['source_checkpoint_commit'] == 'a23550a0cf31aecdce54d5eca333b3930ca2edc7'
assert envelope['continuity_state'] == 'PORTABLE_CONTEXT_PREPARED_NOT_EXECUTABLE'
assert envelope['target_binding_state'] == 'REQUIRED'
assert envelope['accepted_rescue_contexts'] == ['trusted_external_media', 'offline_image']
assert envelope['coverage_summary'] == {'PARTIAL': 4, 'GAP': 0, 'VERIFIED': 2}
assert envelope['coverage_changed'] is False
assert envelope['broad_protection_claimed'] is False
assert envelope['authority_expanded'] is False
assert envelope['rescue_start_authorized'] is False
assert envelope['execution_available'] is False
assert envelope['execution_authorized'] is False
assert envelope['automatic_action'] is False
assert envelope['remediation_performed'] is False
assert envelope['system_mutation_performed'] is False
assert envelope['response_stage_claimed_observed'] is False
assert envelope['source_response_stage_status'] == 'UNKNOWN'
assert envelope['source_live_control'] is True
assert envelope['legacy_rescue_resume_boundary_preserved'] is True
assert not any(envelope['authority_boundary'].values())
assert envelope['privacy']['local_only'] is True
assert envelope['privacy']['personal_data_collected'] is False
assert envelope['privacy']['file_content_collected'] is False
assert envelope['privacy']['absolute_paths_exported'] is False
assert envelope['privacy']['remote_access'] is False
assert envelope['privacy']['network_required'] is False
assert envelope['privacy']['cloud_required'] is False
assert envelope['observed_stage_ids'] == ['FILE_ACTIVITY', 'DETECTION']
assert envelope['unknown_stage_ids'] == ['ENTRY_POINT', 'EXECUTION', 'PERSISTENCE', 'NETWORK_ACTIVITY', 'RESPONSE']
assert len(envelope['evidence_provenance']) == 1
assert envelope['evidence_provenance'][0]['reference'].startswith('b93-live-file:')
steps = envelope['recommended_rescue_steps']
assert [step['step_id'] for step in steps] == [
    'VERIFY_CONTINUITY_INTEGRITY',
    'BIND_RESCUE_TARGET',
    'ACQUIRE_READ_ONLY_EVIDENCE',
    'INSPECT_OFFLINE_TARGET',
    'REVIEW_UNKNOWN_ATTACK_STAGES',
    'REVIEW_PLANNED_RECOVERY',
]
assert all(step['execution_available'] is False for step in steps)

serialized = json.dumps(envelope, indent=2, sort_keys=True, ensure_ascii=False) + '\n'
assert 'target_root' not in serialized
assert 'output_dir' not in serialized
assert 'journal_path' not in serialized
transport_path.write_text(serialized, encoding='utf-8')
transported = json.loads(transport_path.read_text(encoding='utf-8'))
assert transported == envelope
assert validate_continuity_envelope(transported)['passed']

projections = r['projections']
assert [p['execution_context'] for p in projections] == ['trusted_external_media', 'offline_image']
for projection in projections:
    assert validate_rescue_projection(projection)['passed'], projection
    assert projection['target_binding_state'] == 'REQUIRED'
    assert projection['target_bound'] is False
    assert projection['write_authorized'] is False
    assert projection['recovery_certification_available'] is False
    assert projection['automatic_resume_allowed'] is False
    assert projection['operator_confirmation_required'] is True
    assert projection['execution_available'] is False
    assert projection['execution_authorized'] is False
    assert projection['system_mutation_performed'] is False
    assert projection['authority_expanded'] is False
    assert projection['planning_only_capabilities'] == ['plan_quarantine', 'plan_repair']

contract = validate_b105_contract()
assert contract['passed']
assert contract['continuity_only'] is True
assert contract['path_free_handoff'] is True
assert contract['target_binding_required'] is True
assert contract['rescue_start_authorized'] is False
assert contract['execution_available'] is False
assert contract['execution_authorized'] is False
assert contract['automatic_mutation_resume'] is False
assert contract['legacy_rescue_read_only_default'] is True
assert contract['legacy_destructive_actions_enabled'] is False
assert contract['legacy_resume_boundary_preserved'] is True

print(json.dumps({
    'rescue_continuity_passed': True,
    'continuity_id': envelope['continuity_id'],
    'evidence_reference_count': len(envelope['evidence_provenance']),
    'recommended_step_count': len(steps),
    'projection_contexts': [p['execution_context'] for p in projections],
    'target_binding_state': envelope['target_binding_state'],
    'coverage_summary': envelope['coverage_summary'],
    'authority_expanded': envelope['authority_expanded'],
    'execution_authorized': envelope['execution_authorized'],
    'remediation_performed': envelope['remediation_performed'],
    'transport_round_trip': True,
}, indent=2, sort_keys=True))
'@
    & $py -c $assertCode $evidence $transport
    if ($LASTEXITCODE -ne 0) { throw 'B10-5 Rescue Continuity acceptance assertions failed.' }
}
finally {
    if (Test-Path -LiteralPath $liveBase) { Remove-Item -LiteralPath $liveBase -Recurse -Force }
    if (Test-Path -LiteralPath $testBase) { Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host 'BC SENTINEL v0.11.0-beta.10 B10-5 RESCUE CONTINUITY - PASS'
