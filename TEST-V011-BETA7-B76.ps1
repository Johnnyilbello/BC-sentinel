param(
    [switch]$ConfirmCoverageExpansionAcceptance
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = "1"

function Fail([string]$Stage, [string]$Message) {
    Write-Host ("B76 FAIL STAGE=" + $Stage + " | " + $Message) -ForegroundColor Red
    Write-Host "BC SENTINEL v0.11.0-beta.7 B7-6 COVERAGE EXPANSION CAMPAIGN - FAIL" -ForegroundColor Red
    exit 1
}

if (-not $ConfirmCoverageExpansionAcceptance) { Fail "preflight" "B7-6 requires -ConfirmCoverageExpansionAcceptance." }

$RepoRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (Test-Path -LiteralPath $VenvPython -PathType Leaf) { $Py = $VenvPython }
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
$FrozenB75 = "40f1e9985905ceccc070e8f73d09308a8406d059"

Write-Host ""
Write-Host "## BC Sentinel B7-6 - Coverage Expansion Campaign Acceptance"
Write-Host ("Branch: " + $Branch)
Write-Host ("Commit: " + $Commit)
Write-Host ("Frozen B7-5 predecessor: " + $FrozenB75)
Write-Host ""

foreach ($Frozen in @($FrozenBeta6, $FrozenB75)) {
    & git cat-file -e ($Frozen + "^{commit}") 2>$null
    if ($LASTEXITCODE -ne 0) { Fail "predecessor" ("Frozen predecessor commit not available locally: " + $Frozen) }
}

$Protected = @("sentinel/protection_service_core.py","sentinel/realtime.py","sentinel/edr.py","sentinel/edr_service_bridge.py")
foreach ($GitPath in $Protected) {
    & git diff --quiet $FrozenBeta6 HEAD -- $GitPath
    if ($LASTEXITCODE -ne 0) { Fail "protected-preflight" ("Protected B2 path differs from frozen Beta6 checkpoint: " + $GitPath) }
}
Write-Host "Protected B2 state unchanged from Beta6: PASS"

$FrozenB75Files = @(
    "coverage/attack_coverage_ledger.json",
    "sentinel/coverage_ledger.py",
    "sentinel/security_graph.py",
    "sentinel/incident_correlation.py",
    "sentinel/confidence_gate.py",
    "sentinel/attack_chain_harness.py",
    "sentinel/explainable_security.py",
    "tests/test_v011_beta7_b70_coverage_ledger.py",
    "tests/test_v011_beta7_b71_security_graph.py",
    "tests/test_v011_beta7_b72_incident_correlation.py",
    "tests/test_v011_beta7_b73_confidence_gate.py",
    "tests/test_v011_beta7_b74_attack_chain_harness.py",
    "tests/test_v011_beta7_b75_explainable_security.py"
)
foreach ($GitPath in $FrozenB75Files) {
    & git diff --quiet $FrozenB75 HEAD -- $GitPath
    if ($LASTEXITCODE -ne 0) { Fail "predecessor-freeze" ("Accepted B7-0..B7-5 foundation changed: " + $GitPath) }
}
Write-Host "Accepted B7-0/B7-1/B7-2/B7-3/B7-4/B7-5 foundations unchanged: PASS"

$TempProbe = Join-Path $RepoRoot (".b76-python-temp-" + [guid]::NewGuid().ToString("N") + ".txt")
try {
    & $Py -c "import pathlib,tempfile,sys; pathlib.Path(sys.argv[1]).write_text(tempfile.gettempdir(), encoding='utf-8')" $TempProbe
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $TempProbe -PathType Leaf)) { Fail "pytest-temp" "Python temp probe failed." }
    $SystemTemp = (Get-Content -Raw -LiteralPath $TempProbe -Encoding UTF8).Trim()
}
finally { Remove-Item -LiteralPath $TempProbe -Force -ErrorAction SilentlyContinue }
if ([string]::IsNullOrWhiteSpace([string]$SystemTemp)) { Fail "pytest-temp" "Python system temp root was empty." }
$Base = Join-Path $SystemTemp "BCSentinel-TestTemp"
New-Item -ItemType Directory -Path $Base -Force | Out-Null
$PytestBase = Join-Path $Base ("b76-pytest-" + [guid]::NewGuid().ToString("N"))
Write-Host ("pytest basetemp: " + $PytestBase)

Write-Host "[1/9] Compile B7-6..."
& $Py -m compileall -q sentinel/coverage_ledger.py sentinel/security_graph.py sentinel/incident_correlation.py sentinel/confidence_gate.py sentinel/attack_chain_harness.py sentinel/explainable_security.py sentinel/coverage_campaign.py tests/test_v011_beta7_b76_coverage_campaign.py
if ($LASTEXITCODE -ne 0) { Fail "compile" "B7-6 compile gate failed." }
Write-Host "Compile gate: PASS"
Write-Host ""

Write-Host "[2/9] Beta5 + Beta6 + all accepted Beta7 predecessor regression + B7-6 tests..."
$Tests = @(
    Get-ChildItem -Path "tests/test_v011_beta5_*.py","tests/test_v011_beta6_*.py","tests/test_v011_beta7_b70_coverage_ledger.py","tests/test_v011_beta7_b71_security_graph.py","tests/test_v011_beta7_b72_incident_correlation.py","tests/test_v011_beta7_b73_confidence_gate.py","tests/test_v011_beta7_b74_attack_chain_harness.py","tests/test_v011_beta7_b75_explainable_security.py","tests/test_v011_beta7_b76_coverage_campaign.py" |
        Sort-Object FullName | ForEach-Object { $_.FullName }
)
try {
    & $Py -m pytest -q --basetemp "$PytestBase" @Tests
    if ($LASTEXITCODE -ne 0) { Fail "pytest" "Predecessor/B7-6 deterministic gate failed." }
}
finally {
    if (Test-Path -LiteralPath $PytestBase) { Remove-Item -LiteralPath $PytestBase -Recurse -Force -ErrorAction SilentlyContinue }
}
Write-Host "Predecessor + B7-6 deterministic gate: PASS"
Write-Host ""

$Checks = @(
    @{Label="B7-0 coverage ledger"; Module="sentinel.coverage_ledger"},
    @{Label="B7-1 Security Graph"; Module="sentinel.security_graph"},
    @{Label="B7-2 Incident Correlation"; Module="sentinel.incident_correlation"},
    @{Label="B7-3 Confidence Gate"; Module="sentinel.confidence_gate"},
    @{Label="B7-4 Attack-Chain Harness"; Module="sentinel.attack_chain_harness"},
    @{Label="B7-5 Explainable Security"; Module="sentinel.explainable_security"}
)
$Stage = 3
foreach ($Check in $Checks) {
    Write-Host ("[" + $Stage + "/9] " + $Check.Label + " self-check...")
    & $Py -m $Check.Module --self-check
    if ($LASTEXITCODE -ne 0) { Fail ("predecessor-self-check-" + $Stage) ($Check.Label + " self-check failed.") }
    Write-Host ($Check.Label + " self-check: PASS")
    Write-Host ""
    $Stage++
}

Write-Host "[9/9] B7-6 Coverage Expansion Campaign self-check..."
& $Py -m sentinel.coverage_campaign --self-check
if ($LASTEXITCODE -ne 0) { Fail "coverage-campaign" "B7-6 Coverage Expansion Campaign self-check failed." }
Write-Host "Coverage Expansion evidence/gap/determinism/safety contract: PASS"
Write-Host ""
Write-Host "B7-6 is synthetic and read-only: PARTIAL is evidence-bound; missing detector acceptance becomes GAP; VERIFIED remains zero." -ForegroundColor DarkGray
Write-Host "BC SENTINEL v0.11.0-beta.7 B7-6 COVERAGE EXPANSION CAMPAIGN - PASS" -ForegroundColor Green
