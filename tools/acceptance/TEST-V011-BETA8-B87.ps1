param([switch]$ConfirmBeta8FinalAcceptance)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

function Fail([string]$Stage, [string]$Message) {
    Write-Host ("B87 FAIL STAGE=" + $Stage + " | " + $Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.8 B8-7 FINAL WINDOWS ACCEPTANCE - FAIL' -ForegroundColor Red
    exit 1
}

if (-not $ConfirmBeta8FinalAcceptance) { Fail 'preflight' 'Pass -ConfirmBeta8FinalAcceptance to run B8-7 acceptance.' }
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot
$expectedBranch = 'feature/v011-beta8-b87-windows-freeze'
$branch = (& git branch --show-current | Select-Object -First 1)
$commit = (& git rev-parse HEAD | Select-Object -First 1)
$frozenBeta6 = 'eb08758a304eb838d08af890ef9c4786264afbc0'
$frozenB83 = 'ccb182f4869ec9ee050e86269a8a9b7269f9dbbf'
$frozenB84 = '7f1c339887225e12b5d032a7b1a4a127ad861123'
$frozenB85 = '28b105638af230c598fe2ab27542909496f225df'
$frozenB86 = 'ee98c6fb908c4a8ff133e8fe94f0afd2c2bc08f6'

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
Write-Host '## BC Sentinel B8-7 - Beta8 Final Windows Acceptance and Freeze'
Write-Host ('Branch: ' + $branch)
Write-Host ('Commit: ' + $commit)
Write-Host ('Python: ' + $py)
if ($branch -ne $expectedBranch) { Fail 'branch' ("Expected branch " + $expectedBranch + ", got " + $branch) }
foreach ($frozen in @($frozenBeta6, $frozenB83, $frozenB84, $frozenB85, $frozenB86)) {
    & git cat-file -e ($frozen + '^{commit}') 2>$null
    if ($LASTEXITCODE -ne 0) { Fail 'predecessor' ("Frozen predecessor unavailable: " + $frozen) }
}
& git merge-base --is-ancestor $frozenB86 HEAD
if ($LASTEXITCODE -ne 0) { Fail 'predecessor' 'B8-7 does not descend from accepted B8-6.' }

foreach ($path in @('sentinel/protection_service_core.py','sentinel/realtime.py','sentinel/edr.py','sentinel/edr_service_bridge.py')) {
    & git diff --quiet $frozenBeta6 HEAD -- $path
    if ($LASTEXITCODE -ne 0) { Fail 'protected-b2' ("Protected B2 path changed: " + $path) }
}
Write-Host 'Protected B2 state unchanged from Beta6: PASS'

foreach ($range in @(
    @($frozenB83, $frozenB84, 'B8-4'),
    @($frozenB84, $frozenB85, 'B8-5'),
    @($frozenB85, $frozenB86, 'B8-6')
)) {
    $baseCommit, $acceptedCommit, $label = $range
    $acceptedPaths = @(& git diff --name-only $baseCommit $acceptedCommit | Where-Object { $_ -ne 'ROADMAP.md' })
    foreach ($path in $acceptedPaths) {
        & git diff --quiet $acceptedCommit HEAD -- $path
        if ($LASTEXITCODE -ne 0) { Fail 'accepted-source-freeze' ("Accepted " + $label + " path changed: " + $path) }
    }
    Write-Host ("Accepted " + $label + " paths unchanged: PASS (" + $acceptedPaths.Count + " paths)")
}

$rootFiles = @(git ls-files | Where-Object { $_ -notmatch '/' } | Sort-Object)
if ($rootFiles.Count -ne 10) { Fail 'hygiene-root' ("Expected compact 10-file root, got " + $rootFiles.Count) }
$roadmaps = @(git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') { Fail 'roadmap' 'ROADMAP.md must remain the single roadmap.' }
Write-Host 'Repository-hygiene contract: PASS'

$base = Join-Path ([System.IO.Path]::GetTempPath()) 'BCSentinel-TestTemp'
New-Item -ItemType Directory -Path $base -Force | Out-Null
$pytestBase = Join-Path $base ('b87-pytest-' + [guid]::NewGuid().ToString('N'))
Write-Host ('pytest basetemp: ' + $pytestBase)

Write-Host '[1/7] Compile final Beta8 acceptance...'
& $py -m compileall -q sentinel/beta8_final_acceptance.py tests/test_v011_beta8_b87_final_acceptance.py
if ($LASTEXITCODE -ne 0) { Fail 'compile' 'B8-7 compile gate failed.' }

Write-Host '[2/7] Complete Beta5 + Beta6 + Beta7 + Beta8 regression...'
$tests = @(Get-ChildItem -Path 'tests/test_v011_beta5_*.py','tests/test_v011_beta6_*.py','tests/test_v011_beta7_*.py','tests/test_v011_beta8_*.py' | Sort-Object FullName | ForEach-Object { $_.FullName })
try {
    & $py -m pytest -q --basetemp "$pytestBase" @tests
    if ($LASTEXITCODE -ne 0) { Fail 'pytest' 'B8-7 full regression failed.' }
}
finally {
    if (Test-Path -LiteralPath $pytestBase) { Remove-Item -LiteralPath $pytestBase -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host '[3/7] Accepted detector self-checks...'
& $py -m sentinel.ransomware_detector --self-check
if ($LASTEXITCODE -ne 0) { Fail 'b81' 'Ransomware detector self-check failed.' }
& $py -m sentinel.defense_evasion_detector --self-check
if ($LASTEXITCODE -ne 0) { Fail 'b82' 'Defense-evasion detector self-check failed.' }
& $py -m sentinel.credential_access_detector --self-check
if ($LASTEXITCODE -ne 0) { Fail 'b83' 'Credential-access detector self-check failed.' }

Write-Host '[4/7] Canonical coverage verification...'
& $py -m sentinel.beta8_coverage_verification --self-check
if ($LASTEXITCODE -ne 0) { Fail 'b84' 'Coverage verification self-check failed.' }

Write-Host '[5/7] Prediction foundation...'
& $py -m sentinel.attack_prediction --self-check
if ($LASTEXITCODE -ne 0) { Fail 'b85' 'Attack prediction self-check failed.' }

Write-Host '[6/7] Predictive multi-stage chain...'
& $py -m sentinel.predictive_attack_chain --self-check
if ($LASTEXITCODE -ne 0) { Fail 'b86' 'Predictive chain self-check failed.' }

Write-Host '[7/7] Final deterministic/resource/safety acceptance...'
& $py -m sentinel.beta8_final_acceptance --self-check
if ($LASTEXITCODE -ne 0) { Fail 'b87' 'Final Beta8 self-check failed.' }
& $py -c "from sentinel.beta8_final_acceptance import self_check; r=self_check(); assert r['passed']; assert r['deterministic_core']; assert r['coverage_summary']=={'PARTIAL':6,'GAP':0,'VERIFIED':0}; assert r['detector_count']==3; assert r['prediction_accuracy']==1.0; assert r['read_only']; assert r['synthetic_evidence_cannot_verify']; assert not r['predictions_are_evidence']; assert not r['authority_granted']; assert not r['execution_authority_added']; assert not r['remediation_execution']; assert not r['automatic_quarantine']"
if ($LASTEXITCODE -ne 0) { Fail 'b87-safety' 'Final Beta8 coverage/prediction/safety assertions failed.' }

Write-Host 'Beta8 closes with PARTIAL=6 / GAP=0 / VERIFIED=0; predictions remain advisory and no execution or remediation authority is added.' -ForegroundColor DarkGray
Write-Host 'BC SENTINEL v0.11.0-beta.8 B8-7 FINAL WINDOWS ACCEPTANCE - PASS' -ForegroundColor Green
