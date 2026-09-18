param([switch]$ConfirmProductIntegration)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot
$env:PYTHONPATH = $repoRoot

if (-not $ConfirmProductIntegration) {
    throw 'Explicit Beta12 B12-8 product integration confirmation required.'
}

$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve B12-8 acceptance commit.' }
Write-Host ('B12-8 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B12-8 acceptance commit.' }

$frozen = '8e5614c919611a7b072dd0a4f462c56751ba331d'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted Beta12 B12-7 predecessor missing.' }

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
$changes = @(& git diff --name-only $frozen HEAD)
$allowed = @(
    '.github/workflows/b128-verified-coverage-product-integration.yml',
    'ROADMAP.md',
    'sentinel/beta12_product_integration.py',
    'sentinel/beta12_product_integration_ui.py',
    'tests/test_v012_beta12_b128_product_integration.py',
    'tools/acceptance/TEST-V012-BETA12-B128.ps1'
)
if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B12-8 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) { throw ('Unexpected B12-8 changed path: ' + $path) }
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B12-7 path changed: ' + $path)
    }
}
Write-Host 'Accepted B12-7 source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta12_product_integration.py sentinel/beta12_product_integration_ui.py tests/test_v012_beta12_b128_product_integration.py
if ($LASTEXITCODE -ne 0) { throw 'B12-8 compile failed.' }

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
$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b128-' + [guid]::NewGuid().ToString('N'))
& $py -m pytest -q --basetemp $testBase @tests
if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta12 B12-8 regression failed.' }

& $py -c "import json; from sentinel.beta12_product_integration import self_check; r=self_check(); print(json.dumps(r,indent=2,sort_keys=True)); assert r['passed']; assert r['coverage_summary']=={'PARTIAL':4,'GAP':0,'VERIFIED':7}; assert r['scenario_count']==11; assert r['capability_count']==7; assert r['product_ui_read_only']; assert not r['coverage_promoted_by_presentation']; assert not r['new_verified_scenario_earned']; assert not r['authority_expanded']; assert not r['network_required']; assert not r['cloud_required']"
if ($LASTEXITCODE -ne 0) { throw 'B12-8 product snapshot self-check failed.' }

$liveBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b128-live-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $liveBase -Force | Out-Null
$impactFile = Join-Path $liveBase 'b127-impact.json'
$snapshotFile = Join-Path $liveBase 'b128-snapshot.json'
try {
    & $py -c "import json,sys; from sentinel.beta12_low_noise_performance import measure; r=measure(repeats=20); json.dump(r,open(sys.argv[1],'w',encoding='utf-8'),indent=2,sort_keys=True); print(json.dumps({'b127_replay_passed':r['passed'],'operational_metrics':r['operational_metrics'],'coverage_summary':r['coverage_summary']},indent=2,sort_keys=True)); raise SystemExit(0 if r['passed'] else 1)" $impactFile
    if ($LASTEXITCODE -ne 0) { throw 'B12-8 B12-7 measured replay failed.' }

    & $py -c "import json,sys; from sentinel.beta12_product_integration import build_product_snapshot,validate_snapshot; impact=json.load(open(sys.argv[1],encoding='utf-8')); snap=build_product_snapshot(impact_report=impact); v=validate_snapshot(snap); json.dump(snap,open(sys.argv[2],'w',encoding='utf-8'),indent=2,sort_keys=True); assert snap['passed']; assert v['passed']; assert snap['coverage_summary']=={'PARTIAL':4,'GAP':0,'VERIFIED':7}; assert len(snap['verified_scenarios'])==7; assert len(snap['scenarios'])==11; assert snap['operational_impact']['status']=='MEASURED'; assert snap['operational_impact']['false_positive_gate_passed']; assert snap['operational_impact']['outcome_stability_gate_passed']; assert snap['operational_impact']['performance_gate_passed']; assert snap['product_ui_read_only']; assert not snap['coverage_promoted_by_presentation']; assert not snap['broad_protection_claimed']; assert not snap['automatic_remediation_claimed']; assert not snap['trust_allowlist_mutated']; print(json.dumps({'product_snapshot_passed':True,'coverage_summary':snap['coverage_summary'],'verified_scenarios':snap['verified_scenarios'],'scenario_count':len(snap['scenarios']),'capability_count':len(snap['capabilities']),'operational_metrics':snap['operational_impact']['metrics']},indent=2,sort_keys=True))" $impactFile $snapshotFile
    if ($LASTEXITCODE -ne 0) { throw 'B12-8 measured product snapshot validation failed.' }

    & $py -c "import json,sys; from sentinel.beta12_product_integration_ui import smoke_test_window; snap=json.load(open(sys.argv[1],encoding='utf-8')); r=smoke_test_window(snap); print(json.dumps(r,indent=2,sort_keys=True)); assert r['passed']; assert r['page_count']==7; assert r['scenario_card_count']==11; assert r['capability_card_count']==7; assert r['action_button_count']==0; assert all(v==0 for v in r['horizontal_overflow'].values())" $snapshotFile
    if ($LASTEXITCODE -ne 0) { throw 'B12-8 Trust Center UI smoke test failed.' }

    & $py -c "import hashlib,json,sys; snap=json.load(open(sys.argv[1],encoding='utf-8')); material={'schema':snap['schema'],'profile':snap['profile'],'source_checkpoint':snap['source_checkpoint'],'source_checkpoint_commit':snap['source_checkpoint_commit'],'coverage_summary':snap['coverage_summary'],'verified_scenarios':snap['verified_scenarios'],'scenarios':snap['scenarios'],'capabilities':snap['capabilities'],'privacy':snap['privacy'],'authority':snap['authority']}; d=hashlib.sha256(json.dumps(material,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')).hexdigest(); print(json.dumps({'b12_8_passed':True,'product_evidence_digest':d,'coverage_summary':snap['coverage_summary'],'verified_count':len(snap['verified_scenarios']),'scenario_count':len(snap['scenarios']),'product_ui_read_only':snap['product_ui_read_only'],'coverage_promoted_by_presentation':snap['coverage_promoted_by_presentation']},indent=2,sort_keys=True))" $snapshotFile
    if ($LASTEXITCODE -ne 0) { throw 'B12-8 final evidence digest failed.' }
}
finally {
    if (Test-Path -LiteralPath $liveBase) {
        Remove-Item -LiteralPath $liveBase -Recurse -Force
    }
}

Write-Host 'BC SENTINEL v0.12.0-beta.12 B12-8 VERIFIED COVERAGE & PRODUCT INTEGRATION - PASS'
