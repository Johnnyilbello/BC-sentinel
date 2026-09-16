param([switch]$ConfirmPredictiveChainAcceptance)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

function Fail([string]$Stage, [string]$Message) {
    Write-Host ("B86 FAIL STAGE=" + $Stage + " | " + $Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.8 B8-6 PREDICTIVE MULTI-STAGE CHAIN ACCEPTANCE - FAIL' -ForegroundColor Red
    exit 1
}

if (-not $ConfirmPredictiveChainAcceptance) { Fail 'preflight' 'Pass -ConfirmPredictiveChainAcceptance to run B8-6 acceptance.' }
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot
$expectedBranch = 'feature/v011-beta8-b86-predictive-chains'
$branch = (& git branch --show-current | Select-Object -First 1)
$commit = (& git rev-parse HEAD | Select-Object -First 1)
$frozenBeta6 = 'eb08758a304eb838d08af890ef9c4786264afbc0'
$frozenB83 = 'ccb182f4869ec9ee050e86269a8a9b7269f9dbbf'
$frozenB84 = '7f1c339887225e12b5d032a7b1a4a127ad861123'
$frozenB85 = '28b105638af230c598fe2ab27542909496f225df'

$venvPython = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (Test-Path -LiteralPath $venvPython -PathType Leaf) { $py = $venvPython }
else {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCommand) { Fail 'preflight' 'Python is unavailable.' }
    $py = $pythonCommand.Source
}
& $py -c "import pytest, PySide6" 2>$null
if ($LASTEXITCODE -ne 0) { Fail 'preflight' ("Selected Python is missing pytest/PySide6: " + $py) }

Write-Host ''
Write-Host '## BC Sentinel B8-6 - Predictive Multi-Stage Attack Chain Acceptance'
Write-Host ('Branch: ' + $branch)
Write-Host ('Commit: ' + $commit)
Write-Host ('Python: ' + $py)
if ($branch -ne $expectedBranch) { Fail 'branch' ("Expected branch " + $expectedBranch + ", got " + $branch) }
foreach ($frozen in @($frozenBeta6, $frozenB83, $frozenB84, $frozenB85)) {
    & git cat-file -e ($frozen + '^{commit}') 2>$null
    if ($LASTEXITCODE -ne 0) { Fail 'predecessor' ("Frozen predecessor unavailable: " + $frozen) }
}
& git merge-base --is-ancestor $frozenB85 HEAD
if ($LASTEXITCODE -ne 0) { Fail 'predecessor' 'B8-6 does not descend from accepted B8-5.' }

foreach ($path in @('sentinel/protection_service_core.py','sentinel/realtime.py','sentinel/edr.py','sentinel/edr_service_bridge.py')) {
    & git diff --quiet $frozenBeta6 HEAD -- $path
    if ($LASTEXITCODE -ne 0) { Fail 'protected-b2' ("Protected B2 path changed: " + $path) }
}
Write-Host 'Protected B2 state unchanged from Beta6: PASS'

$acceptedB84Paths = @(& git diff --name-only $frozenB83 $frozenB84 | Where-Object { $_ -ne 'ROADMAP.md' })
foreach ($path in $acceptedB84Paths) {
    & git diff --quiet $frozenB84 HEAD -- $path
    if ($LASTEXITCODE -ne 0) { Fail 'b84-freeze' ("Accepted B8-4 path changed: " + $path) }
}
Write-Host ('Accepted B8-4 paths unchanged: PASS (' + $acceptedB84Paths.Count + ' paths)')
$acceptedB85Paths = @(& git diff --name-only $frozenB84 $frozenB85 | Where-Object { $_ -ne 'ROADMAP.md' })
foreach ($path in $acceptedB85Paths) {
    & git diff --quiet $frozenB85 HEAD -- $path
    if ($LASTEXITCODE -ne 0) { Fail 'b85-freeze' ("Accepted B8-5 path changed: " + $path) }
}
Write-Host ('Accepted B8-5 paths unchanged: PASS (' + $acceptedB85Paths.Count + ' paths)')

$rootFiles = @(git ls-files | Where-Object { $_ -notmatch '/' } | Sort-Object)
if ($rootFiles.Count -ne 10) { Fail 'hygiene-root' ("Expected compact 10-file root, got " + $rootFiles.Count) }
$roadmaps = @(git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') { Fail 'roadmap' 'ROADMAP.md must remain the single roadmap.' }
Write-Host 'Repository-hygiene contract: PASS'

$base = Join-Path ([System.IO.Path]::GetTempPath()) 'BCSentinel-TestTemp'
New-Item -ItemType Directory -Path $base -Force | Out-Null
$pytestBase = Join-Path $base ('b86-pytest-' + [guid]::NewGuid().ToString('N'))
Write-Host ('pytest basetemp: ' + $pytestBase)

Write-Host '[1/4] Compile B8-6...'
& $py -m compileall -q sentinel/predictive_attack_chain.py tests/test_v011_beta8_b86_predictive_attack_chain.py
if ($LASTEXITCODE -ne 0) { Fail 'compile' 'B8-6 compile gate failed.' }
Write-Host 'Compile gate: PASS'

Write-Host '[2/4] Beta5 + Beta6 + Beta7 + Beta8 regression...'
$tests = @(Get-ChildItem -Path 'tests/test_v011_beta5_*.py','tests/test_v011_beta6_*.py','tests/test_v011_beta7_*.py','tests/test_v011_beta8_*.py' | Sort-Object FullName | ForEach-Object { $_.FullName })
try {
    & $py -m pytest -q --basetemp "$pytestBase" @tests
    if ($LASTEXITCODE -ne 0) { Fail 'pytest' 'B8-6 regression failed.' }
}
finally {
    if (Test-Path -LiteralPath $pytestBase) { Remove-Item -LiteralPath $pytestBase -Recurse -Force -ErrorAction SilentlyContinue }
}
Write-Host 'Complete predecessor + B8-6 deterministic gate: PASS'

Write-Host '[3/4] Frozen B8-4 coverage verification self-check...'
& $py -m sentinel.beta8_coverage_verification --self-check
if ($LASTEXITCODE -ne 0) { Fail 'b84' 'Frozen B8-4 coverage verification self-check failed.' }

Write-Host '[4/4] B8-5 foundation + B8-6 predictive chain self-check...'
& $py -m sentinel.attack_prediction --self-check
if ($LASTEXITCODE -ne 0) { Fail 'b85' 'Frozen B8-5 prediction self-check failed.' }
& $py -m sentinel.predictive_attack_chain --self-check
if ($LASTEXITCODE -ne 0) { Fail 'b86' 'B8-6 predictive chain self-check failed.' }
& $py -c "from sentinel.predictive_attack_chain import self_check; r=self_check(); assert r['passed']; assert r['predicted_stages']==['PERSISTENCE','DNS','DETECTION']; assert r['accuracy']==1.0; assert r['confidence_monotonic']; assert r['deterministic_serialization']; assert r['advisory_only']; assert not r['predictions_are_evidence']; assert not r['graph_mutation']; assert not r['authority_granted']; assert not r['remediation_execution']"
if ($LASTEXITCODE -ne 0) { Fail 'b86-safety' 'B8-6 chain/calibration/safety assertions failed.' }

Write-Host 'B8-6 validates three incident-bound predictions across a controlled chain; predictions remain advisory and no authority is added.' -ForegroundColor DarkGray
Write-Host 'BC SENTINEL v0.11.0-beta.8 B8-6 PREDICTIVE MULTI-STAGE CHAIN ACCEPTANCE - PASS' -ForegroundColor Green
