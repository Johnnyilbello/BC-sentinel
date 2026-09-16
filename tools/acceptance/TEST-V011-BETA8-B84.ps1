param(
    [switch]$ConfirmCoverageVerificationAcceptance
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

function Fail([string]$Stage, [string]$Message) {
    Write-Host ("B84 FAIL STAGE=" + $Stage + " | " + $Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.8 B8-4 COVERAGE VERIFICATION ACCEPTANCE - FAIL' -ForegroundColor Red
    exit 1
}

if (-not $ConfirmCoverageVerificationAcceptance) {
    Fail 'preflight' 'Pass -ConfirmCoverageVerificationAcceptance to run B8-4 acceptance.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot
$expectedBranch = 'feature/v011-beta8-b84-coverage-verification'
$branch = (& git branch --show-current | Select-Object -First 1)
$commit = (& git rev-parse HEAD | Select-Object -First 1)
$frozenBeta6 = 'eb08758a304eb838d08af890ef9c4786264afbc0'
$frozenB80 = '969781bd7633d0b2bc92840e8f12220f00de4279'
$frozenHygiene = 'c33a06d6487115f5ae080edede75f5e63c6bf188'
$frozenB81 = '5d25da3fcb8cd67d9faefbf2440eda19a6086eba'
$frozenB82 = 'a4f4b53bf2ea2dcd00744438c716a18ef5287262'
$frozenB83 = 'ccb182f4869ec9ee050e86269a8a9b7269f9dbbf'

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
Write-Host '## BC Sentinel B8-4 - Coverage Verification Campaign Acceptance'
Write-Host ('Branch: ' + $branch)
Write-Host ('Commit: ' + $commit)
Write-Host ('Python: ' + $py)

if ($branch -ne $expectedBranch) { Fail 'branch' ("Expected branch " + $expectedBranch + ", got " + $branch) }
foreach ($frozen in @($frozenBeta6, $frozenB80, $frozenHygiene, $frozenB81, $frozenB82, $frozenB83)) {
    & git cat-file -e ($frozen + '^{commit}') 2>$null
    if ($LASTEXITCODE -ne 0) { Fail 'predecessor' ("Frozen predecessor unavailable: " + $frozen) }
}
& git merge-base --is-ancestor $frozenB83 HEAD
if ($LASTEXITCODE -ne 0) { Fail 'predecessor' 'B8-4 does not descend from accepted B8-3.' }

$protectedB2 = @('sentinel/protection_service_core.py','sentinel/realtime.py','sentinel/edr.py','sentinel/edr_service_bridge.py')
foreach ($path in $protectedB2) {
    & git diff --quiet $frozenBeta6 HEAD -- $path
    if ($LASTEXITCODE -ne 0) { Fail 'protected-b2' ("Protected B2 path changed: " + $path) }
}
Write-Host 'Protected B2 state unchanged from Beta6: PASS'

$acceptedPaths = @(
    'coverage/beta8_coverage_baseline.json',
    'sentinel/beta8_coverage_baseline.py',
    'tests/test_v011_beta8_b80_coverage_baseline.py',
    'sentinel/ransomware_detector.py',
    'tests/test_v011_beta8_b81_ransomware_detector.py',
    'tools/acceptance/TEST-V011-BETA8-B81.ps1',
    '.github/workflows/b81-ransomware-detector.yml',
    'sentinel/defense_evasion_detector.py',
    'tests/test_v011_beta8_b82_defense_evasion_detector.py',
    'tools/acceptance/TEST-V011-BETA8-B82.ps1',
    '.github/workflows/b82-defense-evasion-tamper.yml',
    'sentinel/credential_access_detector.py',
    'tests/test_v011_beta8_b83_credential_access_detector.py',
    'tools/acceptance/TEST-V011-BETA8-B83.ps1',
    '.github/workflows/b83-credential-access-indicators.yml'
)
foreach ($path in $acceptedPaths) {
    $source = if ($path -match 'b83|credential') { $frozenB83 } elseif ($path -match 'b82|defense') { $frozenB82 } elseif ($path -match 'b81|ransomware') { $frozenB81 } else { $frozenB80 }
    & git diff --quiet $source HEAD -- $path
    if ($LASTEXITCODE -ne 0) { Fail 'accepted-source-freeze' ("Accepted source changed: " + $path) }
}
Write-Host 'Accepted B8-0/B8-1/B8-2/B8-3 sources unchanged: PASS'

$rootFiles = @(git ls-files | Where-Object { $_ -notmatch '/' } | Sort-Object)
if ($rootFiles.Count -ne 10) { Fail 'hygiene-root' ("Expected compact 10-file root, got " + $rootFiles.Count) }
$roadmaps = @(git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') { Fail 'roadmap' 'ROADMAP.md must remain the single roadmap.' }
Write-Host 'Repository-hygiene contract: PASS'

$systemTemp = [System.IO.Path]::GetTempPath()
$pytestBase = Join-Path $systemTemp ('BCSentinel-TestTemp\b84-pytest-' + [guid]::NewGuid().ToString('N'))
Write-Host ('pytest basetemp: ' + $pytestBase)

Write-Host '[1/6] Compile B8-4...'
& $py -m compileall -q sentinel/beta8_coverage_verification.py tests/test_v011_beta8_b84_coverage_verification.py
if ($LASTEXITCODE -ne 0) { Fail 'compile' 'B8-4 compile gate failed.' }
Write-Host 'Compile gate: PASS'

Write-Host '[2/6] Beta5 + Beta6 + Beta7 + Beta8 regression...'
$tests = @(Get-ChildItem -Path 'tests/test_v011_beta5_*.py','tests/test_v011_beta6_*.py','tests/test_v011_beta7_*.py','tests/test_v011_beta8_*.py' | Sort-Object FullName | ForEach-Object { $_.FullName })
try {
    & $py -m pytest -q --basetemp "$pytestBase" @tests
    if ($LASTEXITCODE -ne 0) { Fail 'pytest' 'B8-4 regression failed.' }
}
finally {
    if (Test-Path -LiteralPath $pytestBase) { Remove-Item -LiteralPath $pytestBase -Recurse -Force -ErrorAction SilentlyContinue }
}
Write-Host 'Complete predecessor + B8-4 deterministic gate: PASS'

Write-Host '[3/6] Frozen B8-1 detector self-check...'
& $py -m sentinel.ransomware_detector --self-check
if ($LASTEXITCODE -ne 0) { Fail 'b81' 'Frozen B8-1 detector self-check failed.' }

Write-Host '[4/6] Frozen B8-2 detector self-check...'
& $py -m sentinel.defense_evasion_detector --self-check
if ($LASTEXITCODE -ne 0) { Fail 'b82' 'Frozen B8-2 detector self-check failed.' }

Write-Host '[5/6] Frozen B8-3 detector self-check...'
& $py -m sentinel.credential_access_detector --self-check
if ($LASTEXITCODE -ne 0) { Fail 'b83' 'Frozen B8-3 detector self-check failed.' }

Write-Host '[6/6] B8-4 coverage verification self-check...'
& $py -m sentinel.beta8_coverage_verification --self-check
if ($LASTEXITCODE -ne 0) { Fail 'b84' 'B8-4 coverage verification self-check failed.' }
& $py -c "from sentinel.beta8_coverage_verification import self_check; r=self_check(); assert r['passed']; assert r['summary']=={'PARTIAL':6,'GAP':0,'VERIFIED':0}; assert r['accepted_detector_count']==3; assert r['deterministic_recomputation']; assert r['synthetic_evidence_cannot_verify']; assert r['read_only']; assert not r['authority_granted']; assert not r['execution_authority_added']; assert not r['remediation_execution']; assert not r['credential_access']"
if ($LASTEXITCODE -ne 0) { Fail 'b84-safety' 'B8-4 coverage/safety assertions failed.' }

Write-Host 'B8-4 recomputes PARTIAL=6 / GAP=0 / VERIFIED=0 from accepted evidence; synthetic detector evidence cannot support VERIFIED and no authority is added.' -ForegroundColor DarkGray
Write-Host 'BC SENTINEL v0.11.0-beta.8 B8-4 COVERAGE VERIFICATION ACCEPTANCE - PASS' -ForegroundColor Green
