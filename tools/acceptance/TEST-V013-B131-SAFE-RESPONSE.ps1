param([switch]$ConfirmSafeResponseNotifications)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot
$env:PYTHONPATH = $repoRoot

if (-not $ConfirmSafeResponseNotifications) {
    throw 'Explicit Beta13 B13-1 safe response and notification confirmation required.'
}

$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve B13-1 acceptance commit.' }
Write-Host ('B13-1 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B13-1 acceptance commit.' }

$frozen = '6c1a3dedd48d2b26b716c199f74ea45d827ee01a'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted Beta13 B13-0 predecessor missing.' }

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
$changes = @(& git diff --name-only $frozen HEAD)
$allowed = @(
    '.github/workflows/b131-safe-response-notification-ux.yml',
    'ROADMAP.md',
    'sentinel/beta13_response_ui.py',
    'sentinel/beta13_safe_response.py',
    'tests/test_v013_b131_safe_response_notifications.py',
    'tools/acceptance/TEST-V013-B131-SAFE-RESPONSE.ps1'
)
if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B13-1 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) { throw ('Unexpected B13-1 changed path: ' + $path) }
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B13-0 path changed: ' + $path)
    }
}
Write-Host 'Accepted B13-0 source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta13_safe_response.py sentinel/beta13_response_ui.py tests/test_v013_b131_safe_response_notifications.py
if ($LASTEXITCODE -ne 0) { throw 'B13-1 compile failed.' }

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
$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b131-' + [guid]::NewGuid().ToString('N'))
& $py -m pytest -q --basetemp $testBase @tests
if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta13 B13-1 regression failed.' }

& $py -m sentinel.beta13_safe_response
if ($LASTEXITCODE -ne 0) { throw 'B13-1 safe-response self-check failed.' }

& $py -c "import json; from sentinel import beta12_product_integration as b128; from sentinel import beta13_response_ui as ui; snap=b128.build_product_snapshot(); assert snap['passed']; r=ui.smoke_test_window(snap); print(json.dumps(r,indent=2,sort_keys=True)); assert r['passed']; assert r['page_count']==8; assert r['alert_card_count']==3; assert r['review_button_count']==3; assert r['unread_count']==3; assert r['automatic_quarantine'] is False; assert r['destructive_ui_action'] is False; assert all(v==0 for v in r['horizontal_overflow'].values())"
if ($LASTEXITCODE -ne 0) { throw 'B13-1 response-center UI smoke failed.' }

& $py -c "import json; from sentinel.beta13_safe_response import self_check; r=self_check(); p=r['readiness_projection']; assert r['passed']; assert p['pillar_counts']=={'READY':5,'PARTIAL':1,'BLOCKED':4}; assert p['release_blocker_count']==5; assert p['release_blockers']==['SECURE_UPDATES','INSTALLER_LIFECYCLE','CODE_SIGNING','LICENSING_TRIAL','PRIVACY_SUPPORT']; assert r['safe_response_ready']; assert r['background_alerts_ready']; assert r['automatic_quarantine'] is False; assert r['automatic_repair'] is False; assert r['terminate_process_authority'] is False; assert r['coverage_promoted'] is False; assert r['authority_expanded'] is False; print(json.dumps({'b13_1_passed':True,'contract_digest':r['contract_digest'],'pillar_counts':p['pillar_counts'],'release_blockers':p['release_blockers'],'release_blocker_count':p['release_blocker_count'],'safe_response_ready':r['safe_response_ready'],'background_alerts_ready':r['background_alerts_ready'],'automatic_quarantine':r['automatic_quarantine']},indent=2,sort_keys=True))"
if ($LASTEXITCODE -ne 0) { throw 'B13-1 final acceptance assertions failed.' }

Write-Host 'BC SENTINEL v0.13.0 B13-1 SAFE THREAT RESPONSE & NOTIFICATION UX - PASS'
