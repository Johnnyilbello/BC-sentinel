param(
    [switch]$ConfirmDefenseEvasionAcceptance
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

function Fail([string]$Stage, [string]$Message) {
    Write-Host ("B82 FAIL STAGE=" + $Stage + " | " + $Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.8 B8-2 DEFENSE-EVASION / TAMPER DETECTOR ACCEPTANCE - FAIL' -ForegroundColor Red
    exit 1
}

if (-not $ConfirmDefenseEvasionAcceptance) {
    Fail 'preflight' 'Pass -ConfirmDefenseEvasionAcceptance to run B8-2 acceptance.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

$expectedBranch = 'feature/v011-beta8-b82-defense-evasion-tamper'
$branch = (& git branch --show-current | Select-Object -First 1)
$commit = (& git rev-parse HEAD | Select-Object -First 1)
$frozenBeta6 = 'eb08758a304eb838d08af890ef9c4786264afbc0'
$frozenB80 = '969781bd7633d0b2bc92840e8f12220f00de4279'
$frozenHygiene = 'c33a06d6487115f5ae080edede75f5e63c6bf188'
$frozenB81 = '5d25da3fcb8cd67d9faefbf2440eda19a6086eba'

$venvPython = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (Test-Path -LiteralPath $venvPython -PathType Leaf) {
    $py = $venvPython
}
else {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCommand) { Fail 'preflight' 'Python is unavailable.' }
    $py = $pythonCommand.Source
}

& $py -c "import pytest, PySide6" 2>$null
if ($LASTEXITCODE -ne 0) {
    Fail 'preflight' ("Selected Python is missing pytest/PySide6: " + $py)
}

Write-Host ''
Write-Host '## BC Sentinel B8-2 - Defense-Evasion / Tamper Detector Acceptance'
Write-Host ('Branch: ' + $branch)
Write-Host ('Commit: ' + $commit)
Write-Host ('Python: ' + $py)
Write-Host ('Frozen B8-0 predecessor: ' + $frozenB80)
Write-Host ('Frozen repository-hygiene predecessor: ' + $frozenHygiene)
Write-Host ('Frozen B8-1 predecessor: ' + $frozenB81)
Write-Host ''

if ($branch -ne $expectedBranch) { Fail 'branch' ("Expected branch " + $expectedBranch + ", got " + $branch) }
foreach ($frozen in @($frozenBeta6, $frozenB80, $frozenHygiene, $frozenB81)) {
    & git cat-file -e ($frozen + '^{commit}') 2>$null
    if ($LASTEXITCODE -ne 0) { Fail 'predecessor' ("Frozen predecessor unavailable: " + $frozen) }
}
& git merge-base --is-ancestor $frozenB81 HEAD
if ($LASTEXITCODE -ne 0) { Fail 'predecessor' 'B8-2 does not descend from accepted B8-1.' }

$protectedB2 = @(
    'sentinel/protection_service_core.py',
    'sentinel/realtime.py',
    'sentinel/edr.py',
    'sentinel/edr_service_bridge.py'
)
foreach ($path in $protectedB2) {
    & git diff --quiet $frozenBeta6 HEAD -- $path
    if ($LASTEXITCODE -ne 0) { Fail 'protected-b2' ("Protected B2 path changed: " + $path) }
}
Write-Host 'Protected B2 state unchanged from Beta6: PASS'

$acceptedB80 = @(
    'coverage/beta8_coverage_baseline.json',
    'sentinel/beta8_coverage_baseline.py',
    'tests/test_v011_beta8_b80_coverage_baseline.py'
)
foreach ($path in $acceptedB80) {
    & git diff --quiet $frozenB80 HEAD -- $path
    if ($LASTEXITCODE -ne 0) { Fail 'b80-freeze' ("Accepted B8-0 path changed: " + $path) }
}
Write-Host 'Accepted B8-0 baseline sources unchanged: PASS'

$acceptedB81 = @(
    'sentinel/ransomware_detector.py',
    'tests/test_v011_beta8_b81_ransomware_detector.py',
    'tools/acceptance/TEST-V011-BETA8-B81.ps1',
    '.github/workflows/b81-ransomware-detector.yml'
)
foreach ($path in $acceptedB81) {
    & git diff --quiet $frozenB81 HEAD -- $path
    if ($LASTEXITCODE -ne 0) { Fail 'b81-freeze' ("Accepted B8-1 path changed: " + $path) }
}
Write-Host 'Accepted B8-1 detector sources unchanged: PASS'

$hygieneBound = @(
    'BUILD-V011-BETA6-B67-PORTABLE-GUI.ps1',
    'README.md',
    'SECURITY.md',
    'STABLE-RELEASE.md',
    'STABLE_VERSION.json',
    'START-BC-SENTINEL-STABLE.bat',
    'START-BC-SENTINEL-STABLE.ps1',
    'pyproject.toml',
    'requirements.txt'
)
foreach ($path in $hygieneBound) {
    & git diff --quiet $frozenHygiene HEAD -- $path
    if ($LASTEXITCODE -ne 0) { Fail 'hygiene-freeze' ("Accepted repository-hygiene path changed: " + $path) }
}
$rootFiles = @(git ls-files | Where-Object { $_ -notmatch '/' } | Sort-Object)
if ($rootFiles.Count -ne 10) { Fail 'hygiene-root' ("Expected compact 10-file root, got " + $rootFiles.Count) }
$roadmaps = @(git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') { Fail 'roadmap' 'ROADMAP.md must remain the single roadmap.' }
Write-Host 'Accepted repository-hygiene contract: PASS'

$tempProbe = Join-Path $repoRoot ('.b82-python-temp-' + [guid]::NewGuid().ToString('N') + '.txt')
try {
    & $py -c "import pathlib,tempfile,sys; pathlib.Path(sys.argv[1]).write_text(tempfile.gettempdir(), encoding='utf-8')" $tempProbe
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $tempProbe -PathType Leaf)) { Fail 'pytest-temp' 'Python temp probe failed.' }
    $systemTemp = (Get-Content -Raw -LiteralPath $tempProbe -Encoding UTF8).Trim()
}
finally {
    Remove-Item -LiteralPath $tempProbe -Force -ErrorAction SilentlyContinue
}
if ([string]::IsNullOrWhiteSpace([string]$systemTemp)) { Fail 'pytest-temp' 'Python system temp root was empty.' }
$base = Join-Path $systemTemp 'BCSentinel-TestTemp'
New-Item -ItemType Directory -Path $base -Force | Out-Null
$pytestBase = Join-Path $base ('b82-pytest-' + [guid]::NewGuid().ToString('N'))
Write-Host ('pytest basetemp: ' + $pytestBase)

Write-Host '[1/5] Compile B8-2...'
& $py -m compileall -q sentinel/defense_evasion_detector.py tests/test_v011_beta8_b82_defense_evasion_detector.py
if ($LASTEXITCODE -ne 0) { Fail 'compile' 'B8-2 compile gate failed.' }
Write-Host 'Compile gate: PASS'
Write-Host ''

Write-Host '[2/5] Beta5 + Beta6 + Beta7 + B8-0/B8-1 regression + B8-2 deterministic tests...'
$tests = @(
    Get-ChildItem -Path 'tests/test_v011_beta5_*.py','tests/test_v011_beta6_*.py','tests/test_v011_beta7_*.py','tests/test_v011_beta8_b80_coverage_baseline.py','tests/test_v011_beta8_b81_ransomware_detector.py','tests/test_v011_beta8_b82_defense_evasion_detector.py' |
        Sort-Object FullName |
        ForEach-Object { $_.FullName }
)
try {
    & $py -m pytest -q --basetemp "$pytestBase" @tests
    if ($LASTEXITCODE -ne 0) { Fail 'pytest' 'B8-2 regression failed.' }
}
finally {
    if (Test-Path -LiteralPath $pytestBase) {
        Remove-Item -LiteralPath $pytestBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}
Write-Host 'Complete predecessor + B8-2 deterministic gate: PASS'
Write-Host ''

Write-Host '[3/5] Frozen B8-0 baseline self-check...'
& $py -m sentinel.beta8_coverage_baseline --self-check
if ($LASTEXITCODE -ne 0) { Fail 'b80' 'Frozen B8-0 baseline self-check failed.' }
Write-Host 'Frozen B8-0 baseline: PASS'
Write-Host ''

Write-Host '[4/5] Frozen B8-1 ransomware-like detector self-check...'
& $py -m sentinel.ransomware_detector --self-check
if ($LASTEXITCODE -ne 0) { Fail 'b81' 'Frozen B8-1 detector self-check failed.' }
Write-Host 'Frozen B8-1 detector: PASS'
Write-Host ''

Write-Host '[5/5] B8-2 defense-evasion / tamper detector self-check...'
& $py -m sentinel.defense_evasion_detector --self-check
if ($LASTEXITCODE -ne 0) { Fail 'b82' 'B8-2 detector self-check failed.' }
& $py -c "from sentinel.defense_evasion_detector import self_check; r=self_check(); assert r['passed']; assert r['target_scenario_id']=='B7-DEFENSE-EVASION-001'; assert r['coverage_status']=='PARTIAL'; assert r['positive_outcome']=='DETECTED'; assert r['admin_outcome']=='REVIEW_REQUIRED'; assert r['benign_outcome']=='NO_MATCH'; assert r['stable_round_trip']; assert r['deterministic_serialization']; assert r['evidence_ids_preserved']; assert r['resource_cost']['elapsed_seconds'] <= r['resource_cost']['max_seconds']; assert r['resource_cost']['peak_memory_bytes'] <= r['resource_cost']['max_peak_memory_bytes']; assert r['process_execution'] is False; assert r['file_read'] is False; assert r['file_write'] is False; assert r['file_rename'] is False; assert r['file_delete'] is False; assert r['network_io'] is False; assert r['registry_read'] is False; assert r['registry_mutation'] is False; assert r['service_control'] is False; assert r['security_control_mutation'] is False; assert r['credential_access'] is False; assert r['remediation_execution'] is False; assert r['automatic_quarantine'] is False; assert r['automatic_repair'] is False; assert r['automatic_restore'] is False; assert r['general_home_execution_authorized'] is False; assert r['delete_authorized'] is False; assert r['repair_authorized'] is False; assert r['terminate_process_authorized'] is False; assert r['trust_allowlist_mutation_authorized'] is False; assert r['privileged_system_mutation_authorized'] is False; assert r['authority_granted'] is False; assert r['execution_authority_added'] is False"
if ($LASTEXITCODE -ne 0) { Fail 'b82-safety' 'B8-2 detector safety/determinism/resource assertions failed.' }
Write-Host 'B8-2 detector provenance/determinism/resource/safety contract: PASS'
Write-Host ''

Write-Host 'B8-2 uses normalized synthetic in-memory control-tamper observations only; defense-evasion coverage becomes PARTIAL, never VERIFIED, and no security-control mutation or remediation authority is added.' -ForegroundColor DarkGray
Write-Host 'BC SENTINEL v0.11.0-beta.8 B8-2 DEFENSE-EVASION / TAMPER DETECTOR ACCEPTANCE - PASS' -ForegroundColor Green
