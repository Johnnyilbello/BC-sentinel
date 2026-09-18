param([switch]$ConfirmLowNoisePerformance)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot
$env:PYTHONPATH = $repoRoot

if (-not $ConfirmLowNoisePerformance) {
    throw 'Explicit Beta12 B12-7 low-noise/performance confirmation required.'
}

$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve B12-7 acceptance commit.' }
Write-Host ('B12-7 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B12-7 acceptance commit.' }

$frozen = 'b1f55ea32564d72cae6056308f90f8b41137dc94'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted Beta12 B12-6 predecessor missing.' }

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate frozen B12-6 paths.' }
$changes = @(& git diff --name-only $frozen HEAD)
if ($LASTEXITCODE -ne 0) { throw 'Cannot compare frozen B12-6 sources.' }

$allowed = @(
    '.github/workflows/b127-low-noise-tuning-performance.yml',
    'ROADMAP.md',
    'sentinel/beta12_low_noise_performance.py',
    'tests/test_v012_beta12_b127_low_noise_performance.py',
    'tools/acceptance/TEST-V012-BETA12-B127.ps1'
)
if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B12-7 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) { throw ('Unexpected B12-7 changed path: ' + $path) }
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B12-6 path changed: ' + $path)
    }
}
Write-Host 'Accepted B12-6 source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta12_low_noise_performance.py tests/test_v012_beta12_b127_low_noise_performance.py
if ($LASTEXITCODE -ne 0) { throw 'B12-7 compile failed.' }

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
$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b127-' + [guid]::NewGuid().ToString('N'))
& $py -m pytest -q --basetemp $testBase @tests
if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta12 B12-7 regression failed.' }

& $py -m sentinel.beta12_low_noise_performance --self-check
if ($LASTEXITCODE -ne 0) { throw 'B12-7 self-check failed.' }

$liveBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b127-live-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $liveBase -Force | Out-Null
$reportFile = Join-Path $liveBase 'b127-performance.json'
try {
    $measureOutput = @(& $py -m sentinel.beta12_low_noise_performance --measure --repeats 20)
    $measureExit = $LASTEXITCODE
    [IO.File]::WriteAllText(
        $reportFile,
        (($measureOutput -join [Environment]::NewLine) + [Environment]::NewLine),
        (New-Object Text.UTF8Encoding($false))
    )
    if ($measureExit -ne 0) {
        Get-Content -LiteralPath $reportFile
        throw 'B12-7 measured performance/noise gate failed.'
    }
    Get-Content -LiteralPath $reportFile

    & $py -c "import json,sys; r=json.load(open(sys.argv[1],encoding='utf-8-sig')); assert r['passed']; assert r['coverage_summary']=={'PARTIAL':4,'GAP':0,'VERIFIED':7}; assert r['coverage_promoted'] is False; assert r['verified_count_preserved']==7; assert r['false_positive_gate_passed']; assert r['outcome_stability_gate_passed']; assert r['performance_gate_passed']; assert r['user_interruption_gate_passed']; assert r['operational_metrics']['max_false_positive_detections']==0; assert r['operational_metrics']['max_outcome_drift']==0; assert r['operational_metrics']['max_user_interruptions']==0; assert r['new_verified_scenario_earned'] is False; assert r['authority_expanded'] is False; assert r['network_required'] is False; assert r['cloud_required'] is False; print(json.dumps({'b12_7_passed':True,'coverage_summary':r['coverage_summary'],'operational_metrics':r['operational_metrics'],'budgets':r['budgets'],'false_positive_gate_passed':r['false_positive_gate_passed'],'outcome_stability_gate_passed':r['outcome_stability_gate_passed'],'performance_gate_passed':r['performance_gate_passed']},indent=2,sort_keys=True))" $reportFile
    if ($LASTEXITCODE -ne 0) { throw 'B12-7 final acceptance assertions failed.' }
}
finally {
    if (Test-Path -LiteralPath $liveBase) {
        Remove-Item -LiteralPath $liveBase -Recurse -Force
    }
}

Write-Host 'BC SENTINEL v0.12.0-beta.12 B12-7 LOW-NOISE TUNING & PERFORMANCE - PASS'
