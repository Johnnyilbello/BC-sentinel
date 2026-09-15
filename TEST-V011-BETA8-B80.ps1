param(
    [switch]$ConfirmBeta8FoundationAcceptance
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = "1"
$env:QT_QPA_PLATFORM = "offscreen"
$env:BC_SENTINEL_REDUCED_MOTION = "1"

function Fail([string]$Stage, [string]$Message) {
    Write-Host ("B80 FAIL STAGE=" + $Stage + " | " + $Message) -ForegroundColor Red
    Write-Host "BC SENTINEL v0.11.0-beta.8 B8-0 FOUNDATION & COVERAGE BASELINE - FAIL" -ForegroundColor Red
    exit 1
}

if (-not $ConfirmBeta8FoundationAcceptance) {
    Fail "preflight" "B8-0 requires -ConfirmBeta8FoundationAcceptance."
}

$RepoRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (Test-Path -LiteralPath $VenvPython -PathType Leaf) {
    $Py = $VenvPython
}
else {
    $PythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $PythonCommand) { Fail "preflight" "Python non disponibile." }
    $Py = $PythonCommand.Source
}

& $Py -c "import pytest" 2>$null
if ($LASTEXITCODE -ne 0) { Fail "preflight" "pytest non disponibile nel Python selezionato." }

$ExpectedBranch = "feature/v011-beta8-b80-foundation"
$Branch = (& git branch --show-current | Select-Object -First 1)
$Commit = (& git rev-parse HEAD | Select-Object -First 1)
$FrozenBeta6 = "eb08758a304eb838d08af890ef9c4786264afbc0"
$FrozenBeta7 = "4d57f749276c588782147d47078ef4c52d1adc51"

Write-Host ""
Write-Host "## BC Sentinel B8-0 - Beta8 Foundation + New Coverage Baseline"
Write-Host ("Branch: " + $Branch)
Write-Host ("Commit: " + $Commit)
Write-Host ("Frozen Beta6 predecessor: " + $FrozenBeta6)
Write-Host ("Frozen Beta7 predecessor: " + $FrozenBeta7)
Write-Host ""

if ($Branch -ne $ExpectedBranch) {
    Fail "branch" ("Expected branch " + $ExpectedBranch + ", got " + $Branch)
}

foreach ($Frozen in @($FrozenBeta6, $FrozenBeta7)) {
    & git cat-file -e ($Frozen + "^{commit}") 2>$null
    if ($LASTEXITCODE -ne 0) { Fail "predecessor" ("Frozen predecessor commit not available locally: " + $Frozen) }
}

$ProtectedB2 = @(
    "sentinel/protection_service_core.py",
    "sentinel/realtime.py",
    "sentinel/edr.py",
    "sentinel/edr_service_bridge.py"
)
foreach ($GitPath in $ProtectedB2) {
    & git diff --quiet $FrozenBeta6 HEAD -- $GitPath
    if ($LASTEXITCODE -ne 0) {
        Fail "protected-b2" ("Protected B2 path differs from frozen Beta6: " + $GitPath)
    }
}
Write-Host "Protected B2 state unchanged from Beta6: PASS"

$AcceptedBeta7 = @(
    "coverage/attack_coverage_ledger.json",
    "sentinel/coverage_ledger.py",
    "sentinel/security_graph.py",
    "sentinel/incident_correlation.py",
    "sentinel/confidence_gate.py",
    "sentinel/attack_chain_harness.py",
    "sentinel/explainable_security.py",
    "sentinel/coverage_campaign.py",
    "sentinel/beta7_final_acceptance.py",
    "tests/test_v011_beta7_b70_coverage_ledger.py",
    "tests/test_v011_beta7_b71_security_graph.py",
    "tests/test_v011_beta7_b72_incident_correlation.py",
    "tests/test_v011_beta7_b73_confidence_gate.py",
    "tests/test_v011_beta7_b74_attack_chain_harness.py",
    "tests/test_v011_beta7_b75_explainable_security.py",
    "tests/test_v011_beta7_b76_coverage_campaign.py",
    "tests/test_v011_beta7_b77_final_acceptance.py"
)
foreach ($GitPath in $AcceptedBeta7) {
    & git diff --quiet $FrozenBeta7 HEAD -- $GitPath
    if ($LASTEXITCODE -ne 0) {
        Fail "beta7-freeze" ("Accepted Beta7 source changed after final freeze: " + $GitPath)
    }
}
Write-Host "Accepted Beta7 intelligence/final-gate sources unchanged: PASS"

$RoadmapFiles = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($RoadmapFiles.Count -ne 1 -or $RoadmapFiles[0] -ne "ROADMAP.md") {
    Fail "roadmap" ("Expected ROADMAP.md to be the only roadmap file. Found: " + ($RoadmapFiles -join ", "))
}
Write-Host "Canonical single-roadmap rule: PASS"

$TempProbe = Join-Path $RepoRoot (".b80-python-temp-" + [guid]::NewGuid().ToString("N") + ".txt")
try {
    & $Py -c "import pathlib,tempfile,sys; pathlib.Path(sys.argv[1]).write_text(tempfile.gettempdir(), encoding='utf-8')" $TempProbe
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $TempProbe -PathType Leaf)) {
        Fail "pytest-temp" "Python temp probe failed."
    }
    $SystemTemp = (Get-Content -Raw -LiteralPath $TempProbe -Encoding UTF8).Trim()
}
finally {
    Remove-Item -LiteralPath $TempProbe -Force -ErrorAction SilentlyContinue
}
if ([string]::IsNullOrWhiteSpace([string]$SystemTemp)) { Fail "pytest-temp" "Python system temp root was empty." }
$Base = Join-Path $SystemTemp "BCSentinel-TestTemp"
New-Item -ItemType Directory -Path $Base -Force | Out-Null
$PytestBase = Join-Path $Base ("b80-pytest-" + [guid]::NewGuid().ToString("N"))
Write-Host ("pytest basetemp: " + $PytestBase)

Write-Host "[1/4] Compile B8-0..."
& $Py -m compileall -q sentinel/beta8_coverage_baseline.py tests/test_v011_beta8_b80_coverage_baseline.py
if ($LASTEXITCODE -ne 0) { Fail "compile" "B8-0 compile gate failed." }
Write-Host "Compile gate: PASS"
Write-Host ""

Write-Host "[2/4] Beta5 + Beta6 + complete Beta7 predecessor regression + B8-0 tests..."
$Tests = @(
    Get-ChildItem -Path "tests/test_v011_beta5_*.py","tests/test_v011_beta6_*.py","tests/test_v011_beta7_*.py","tests/test_v011_beta8_b80_coverage_baseline.py" |
        Sort-Object FullName |
        ForEach-Object { $_.FullName }
)
try {
    & $Py -m pytest -q --basetemp "$PytestBase" @Tests
    if ($LASTEXITCODE -ne 0) { Fail "pytest" "B8-0 regression failed." }
}
finally {
    if (Test-Path -LiteralPath $PytestBase) {
        Remove-Item -LiteralPath $PytestBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "Complete predecessor + B8-0 deterministic gate: PASS"
Write-Host ""

Write-Host "[3/4] Frozen B7-7 final acceptance self-check..."
& $Py -m sentinel.beta7_final_acceptance --self-check
if ($LASTEXITCODE -ne 0) { Fail "b77" "Frozen Beta7 final acceptance self-check failed." }
& $Py -c "from sentinel.beta7_final_acceptance import self_check; r=self_check(); assert r['passed']; assert r['deterministic_core']; assert r['core_digest']=='dcd6a7ff975c2fbdce9549d4af630ab6c252acf26ca7b0c31e0c70e72db8ea4e'; assert r['campaign_summary']=={'GAP':3,'PARTIAL':3,'VERIFIED':0}; assert r['authority_granted'] is False"
if ($LASTEXITCODE -ne 0) { Fail "b77-binding" "Frozen Beta7 digest/safety binding changed." }
Write-Host "Frozen B7-7 source-of-truth binding: PASS"
Write-Host ""

Write-Host "[4/4] B8-0 coverage baseline self-check..."
& $Py -m sentinel.beta8_coverage_baseline --self-check
if ($LASTEXITCODE -ne 0) { Fail "b80" "Beta8 coverage baseline self-check failed." }
& $Py -c "from sentinel.beta8_coverage_baseline import self_check; r=self_check(); assert r['passed']; assert r['summary']=={'PARTIAL':3,'GAP':3,'VERIFIED':0}; assert r['scenario_count']==6; assert r['verification_target_count']==3; assert r['verification_targets']==['B7-RANSOMWARE-001','B7-DEFENSE-EVASION-001','B7-CREDENTIAL-001']; assert r['source_final_core_digest']==r['live_final_core_digest']=='dcd6a7ff975c2fbdce9549d4af630ab6c252acf26ca7b0c31e0c70e72db8ea4e'; assert r['source_campaign_digest']==r['live_campaign_digest']=='e85f96cdfd21f85390c18e1e75387508ce2453c10dfc1af782ede16faad9fc17'; assert r['stable_round_trip']; assert r['deterministic_serialization']; assert r['unsupported_positive_claims_allowed'] is False; assert r['verified_without_detector_acceptance_allowed'] is False; assert r['process_execution'] is False; assert r['file_write'] is False; assert r['network_io'] is False; assert r['registry_mutation'] is False; assert r['credential_access'] is False; assert r['remediation_execution'] is False; assert r['automatic_quarantine'] is False; assert r['automatic_repair'] is False; assert r['automatic_restore'] is False; assert r['general_home_execution_authorized'] is False; assert r['delete_authorized'] is False; assert r['repair_authorized'] is False; assert r['terminate_process_authorized'] is False; assert r['trust_allowlist_mutation_authorized'] is False; assert r['privileged_system_mutation_authorized'] is False; assert r['authority_granted'] is False; assert r['execution_authority_added'] is False"
if ($LASTEXITCODE -ne 0) { Fail "b80-safety" "B8-0 baseline binding/safety assertions failed." }
Write-Host "B8-0 baseline/determinism/safety contract: PASS"
Write-Host ""

Write-Host "B8-0 establishes a read-only evidence baseline only; VERIFIED remains zero and no remediation authority is added." -ForegroundColor DarkGray
Write-Host "BC SENTINEL v0.11.0-beta.8 B8-0 FOUNDATION & COVERAGE BASELINE - PASS" -ForegroundColor Green
