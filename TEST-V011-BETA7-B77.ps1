param(
    [switch]$ConfirmBeta7FinalAcceptance
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = "1"
$env:QT_QPA_PLATFORM = "offscreen"
$env:BC_SENTINEL_REDUCED_MOTION = "1"

function Fail([string]$Stage, [string]$Message) {
    Write-Host ("B77 FAIL STAGE=" + $Stage + " | " + $Message) -ForegroundColor Red
    Write-Host "BC SENTINEL v0.11.0-beta.7 B7-7 WINDOWS ACCEPTANCE & FREEZE - FAIL" -ForegroundColor Red
    exit 1
}

if (-not $ConfirmBeta7FinalAcceptance) {
    Fail "preflight" "B7-7 requires -ConfirmBeta7FinalAcceptance."
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

$Branch = (& git branch --show-current | Select-Object -First 1)
$Commit = (& git rev-parse HEAD | Select-Object -First 1)
$FrozenBeta6 = "eb08758a304eb838d08af890ef9c4786264afbc0"
$FrozenB76 = "1bd66f4f9e55313388e871e26c6a35d55a3dbb20"

Write-Host ""
Write-Host "## BC Sentinel B7-7 - Beta7 Windows Acceptance & Freeze"
Write-Host ("Branch: " + $Branch)
Write-Host ("Commit: " + $Commit)
Write-Host ("Frozen Beta6 predecessor: " + $FrozenBeta6)
Write-Host ("Frozen B7-6 predecessor: " + $FrozenB76)
Write-Host ""

foreach ($Frozen in @($FrozenBeta6, $FrozenB76)) {
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

$PortableBeta6 = @(
    "sentinel/portable_gui_release.py",
    "packaging/beta6_portable_gui_entry.py",
    "BUILD-V011-BETA6-B67-PORTABLE-GUI.ps1",
    "tools/v011_beta6_b67_artifact_acceptance.py",
    "tests/test_v011_beta6_b67_portable_gui.py"
)
foreach ($GitPath in $PortableBeta6) {
    & git diff --quiet $FrozenBeta6 HEAD -- $GitPath
    if ($LASTEXITCODE -ne 0) {
        Fail "portable-predecessor" ("Accepted Beta6 portable contract changed: " + $GitPath)
    }
}
Write-Host "Accepted Beta6 portable contract unchanged: PASS"

$FrozenBeta7 = @(
    "coverage/attack_coverage_ledger.json",
    "sentinel/coverage_ledger.py",
    "tests/test_v011_beta7_b70_coverage_ledger.py",
    "sentinel/security_graph.py",
    "tests/test_v011_beta7_b71_security_graph.py",
    "sentinel/incident_correlation.py",
    "tests/test_v011_beta7_b72_incident_correlation.py",
    "sentinel/confidence_gate.py",
    "tests/test_v011_beta7_b73_confidence_gate.py",
    "sentinel/attack_chain_harness.py",
    "tests/test_v011_beta7_b74_attack_chain_harness.py",
    "sentinel/explainable_security.py",
    "tests/test_v011_beta7_b75_explainable_security.py",
    "sentinel/coverage_campaign.py",
    "tests/test_v011_beta7_b76_coverage_campaign.py"
)
foreach ($GitPath in $FrozenBeta7) {
    & git diff --quiet $FrozenB76 HEAD -- $GitPath
    if ($LASTEXITCODE -ne 0) {
        Fail "beta7-freeze" ("Accepted Beta7 foundation changed after B7-6: " + $GitPath)
    }
}
Write-Host "Accepted B7-0 through B7-6 foundations unchanged: PASS"

$TempProbe = Join-Path $RepoRoot (".b77-python-temp-" + [guid]::NewGuid().ToString("N") + ".txt")
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
$PytestBase = Join-Path $Base ("b77-pytest-" + [guid]::NewGuid().ToString("N"))
Write-Host ("pytest basetemp: " + $PytestBase)

Write-Host "[1/10] Compile final Beta7 gate..."
& $Py -m compileall -q sentinel/coverage_ledger.py sentinel/security_graph.py sentinel/incident_correlation.py sentinel/confidence_gate.py sentinel/attack_chain_harness.py sentinel/explainable_security.py sentinel/coverage_campaign.py sentinel/beta7_final_acceptance.py tests/test_v011_beta7_b77_final_acceptance.py
if ($LASTEXITCODE -ne 0) { Fail "compile" "B7-7 compile gate failed." }
Write-Host "Compile gate: PASS"
Write-Host ""

Write-Host "[2/10] Beta5 + Beta6 + complete Beta7 deterministic regression..."
$Tests = @(
    Get-ChildItem -Path "tests/test_v011_beta5_*.py","tests/test_v011_beta6_*.py","tests/test_v011_beta7_*.py" |
        Sort-Object FullName |
        ForEach-Object { $_.FullName }
)
try {
    & $Py -m pytest -q --basetemp "$PytestBase" @Tests
    if ($LASTEXITCODE -ne 0) { Fail "pytest" "Complete Beta7 regression failed." }
}
finally {
    if (Test-Path -LiteralPath $PytestBase) {
        Remove-Item -LiteralPath $PytestBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "Complete Beta5/Beta6/Beta7 deterministic regression: PASS"
Write-Host ""

Write-Host "[3/10] B7-0 Coverage Ledger self-check..."
& $Py -m sentinel.coverage_ledger --self-check
if ($LASTEXITCODE -ne 0) { Fail "b70" "Coverage Ledger self-check failed." }
Write-Host "B7-0 Coverage Ledger: PASS"
Write-Host ""

Write-Host "[4/10] B7-1 Security Graph self-check..."
& $Py -m sentinel.security_graph --self-check
if ($LASTEXITCODE -ne 0) { Fail "b71" "Security Graph self-check failed." }
Write-Host "B7-1 Security Graph: PASS"
Write-Host ""

Write-Host "[5/10] B7-2 Incident Correlation self-check..."
& $Py -m sentinel.incident_correlation --self-check
if ($LASTEXITCODE -ne 0) { Fail "b72" "Incident Correlation self-check failed." }
Write-Host "B7-2 Incident Correlation: PASS"
Write-Host ""

Write-Host "[6/10] B7-3 Confidence Gate self-check..."
& $Py -m sentinel.confidence_gate --self-check
if ($LASTEXITCODE -ne 0) { Fail "b73" "Confidence Gate self-check failed." }
Write-Host "B7-3 Confidence Gate: PASS"
Write-Host ""

Write-Host "[7/10] B7-4 Attack-Chain Harness self-check..."
& $Py -m sentinel.attack_chain_harness --self-check
if ($LASTEXITCODE -ne 0) { Fail "b74" "Attack-Chain Harness self-check failed." }
Write-Host "B7-4 Attack-Chain Harness: PASS"
Write-Host ""

Write-Host "[8/10] B7-5 Explainable Security self-check..."
& $Py -m sentinel.explainable_security --self-check
if ($LASTEXITCODE -ne 0) { Fail "b75" "Explainable Security self-check failed." }
Write-Host "B7-5 Explainable Security: PASS"
Write-Host ""

Write-Host "[9/10] B7-6 Coverage Expansion Campaign self-check..."
& $Py -m sentinel.coverage_campaign --self-check
if ($LASTEXITCODE -ne 0) { Fail "b76" "Coverage Expansion Campaign self-check failed." }
Write-Host "B7-6 Coverage Expansion Campaign: PASS"
Write-Host ""

Write-Host "[10/10] B7-7 Final acceptance, resource measurement and inherited portable contract..."
& $Py -m sentinel.beta7_final_acceptance --self-check
if ($LASTEXITCODE -ne 0) { Fail "b77" "Final Beta7 acceptance self-check failed." }
& $Py -c "from sentinel.beta7_final_acceptance import self_check; r=self_check(); assert r['passed']; assert r['deterministic_core']; assert r['campaign_summary']=={'GAP':3,'PARTIAL':3,'VERIFIED':0}; assert r['base_ledger_summary']=={'GAP':0,'PARTIAL':0,'PLANNED':6,'VERIFIED':0}; assert r['beta6_portable_contract_passed']; assert r['attack_chain_safe']; assert r['explainable_security_grounded']; assert r['authority_granted'] is False; assert r['automatic_quarantine'] is False; assert r['automatic_repair'] is False; assert r['automatic_restore'] is False; assert r['general_home_execution_authorized'] is False"
if ($LASTEXITCODE -ne 0) { Fail "b77-safety" "Final Beta7 safety assertions failed." }
Write-Host "B7-7 final deterministic/resource/safety contract: PASS"
Write-Host ""

Write-Host "Beta7 final gate preserves the accepted Beta6 portable boundary and adds no remediation authority." -ForegroundColor DarkGray
Write-Host "BC SENTINEL v0.11.0-beta.7 B7-7 WINDOWS ACCEPTANCE & FREEZE - PASS" -ForegroundColor Green
