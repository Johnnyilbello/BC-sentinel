param([switch]$ConfirmSecureUpdates)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot
$env:PYTHONPATH = $repoRoot

if (-not $ConfirmSecureUpdates) {
    throw 'Explicit Beta13 B13-2 secure update confirmation required.'
}

$commit = (& git rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Cannot resolve B13-2 acceptance commit.'
}
Write-Host ('B13-2 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B13-2 acceptance commit.' }

$frozen = 'cfb94fb65f90327504296809270bf3c573f083d0'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted Beta13 B13-1 predecessor missing.' }

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
$changes = @(& git diff --name-only $frozen HEAD)
$allowed = @(
    '.github/workflows/b132-secure-update-channel-rule-delivery.yml',
    'ROADMAP.md',
    'sentinel/beta13_secure_updates.py',
    'tests/test_v013_b132_secure_updates.py',
    'tools/acceptance/RUN-V013-B132-SECURE-UPDATE.py',
    'tools/acceptance/TEST-V013-B132-SECURE-UPDATES.ps1'
)
if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B13-2 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) { throw ('Unexpected B13-2 changed path: ' + $path) }
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B13-1 path changed: ' + $path)
    }
}
Write-Host 'Accepted B13-1 source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta13_secure_updates.py tests/test_v013_b132_secure_updates.py tools/acceptance/RUN-V013-B132-SECURE-UPDATE.py
if ($LASTEXITCODE -ne 0) { throw 'B13-2 compile failed.' }

$patterns = @(
    'tests/test_v011_beta5_*.py',
    'tests/test_v011_beta6_*.py',
    'tests/test_v011_beta7_*.py',
    'tests/test_v011_beta8_*.py',
    'tests/test_v011_beta9_*.py',
    'tests/test_v011_beta10_*.py',
    'tests/test_v011_beta11_*.py',
    'tests/test_v012_beta12_*.py',
    'tests/test_v013_*.py'
)
$tests = @(
    $patterns |
        ForEach-Object { Get-ChildItem $_ } |
        Sort-Object FullName |
        ForEach-Object { $_.FullName }
)
$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b132-' + [guid]::NewGuid().ToString('N'))
try {
    & $py -m pytest -q --basetemp $testBase @tests
    if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta13 B13-2 regression failed.' }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

& $py -m sentinel.beta13_secure_updates
if ($LASTEXITCODE -ne 0) { throw 'B13-2 secure-update self-check failed.' }

$runnerOutput = @(& $py '.\tools\acceptance\RUN-V013-B132-SECURE-UPDATE.py')
$runnerExit = $LASTEXITCODE
$runnerText = $runnerOutput -join [Environment]::NewLine
Write-Host $runnerText
if ($runnerExit -ne 0) { throw 'B13-2 secure-update live acceptance runner failed.' }

$runner = $runnerText | ConvertFrom-Json
if (-not [bool]$runner.passed) { throw 'B13-2 live acceptance report failed.' }
if (-not [bool]$runner.application_manifest_verified -or -not [bool]$runner.application_payload_staged) {
    throw 'B13-2 signed application staging failed.'
}
if ([bool]$runner.application_payload_executed) { throw 'B13-2 executed an application payload unexpectedly.' }
if (-not [bool]$runner.replay_rejected -or -not [bool]$runner.tampered_payload_rejected -or -not [bool]$runner.expired_manifest_rejected -or -not [bool]$runner.wrong_root_rejected) {
    throw 'B13-2 fail-closed update controls did not all reject.'
}
if (-not [bool]$runner.rollback_previous_verified_only -or [bool]$runner.rollback_execution_available) {
    throw 'B13-2 rollback boundary changed.'
}
if (-not [bool]$runner.rule_bundle_staged -or -not [bool]$runner.rule_bundle_detect_only -or [int]$runner.rule_count -ne 2) {
    throw 'B13-2 signed rule delivery failed.'
}
if ([bool]$runner.ephemeral_private_key_persisted) { throw 'B13-2 persisted an acceptance private key.' }
if ([int]$runner.readiness_projection.release_blocker_count -ne 4) { throw 'B13-2 readiness blocker count changed.' }

& $py -c "import json; from sentinel.beta13_secure_updates import self_check; r=self_check(); p=r['readiness_projection']; assert r['passed']; assert p['pillar_counts']=={'READY':6,'PARTIAL':1,'BLOCKED':3}; assert p['release_blockers']==['INSTALLER_LIFECYCLE','CODE_SIGNING','LICENSING_TRIAL','PRIVACY_SUPPORT']; assert p['release_blocker_count']==4; assert r['secure_updates_ready']; assert r['private_key_embedded'] is False; assert r['network_required'] is False; assert r['cloud_required'] is False; assert r['payload_execution_available'] is False; assert r['installer_execution_available'] is False; assert r['coverage_promoted'] is False; assert r['authority_expanded'] is False; print(json.dumps({'b13_2_passed':True,'contract_digest':r['contract_digest'],'pillar_counts':p['pillar_counts'],'release_blockers':p['release_blockers'],'release_blocker_count':p['release_blocker_count'],'secure_updates_ready':r['secure_updates_ready'],'private_key_embedded':r['private_key_embedded'],'payload_execution_available':r['payload_execution_available']},indent=2,sort_keys=True))"
if ($LASTEXITCODE -ne 0) { throw 'B13-2 final acceptance assertions failed.' }

Write-Host 'BC SENTINEL v0.13.0 B13-2 SECURE UPDATE CHANNEL & RULE DELIVERY - PASS'
