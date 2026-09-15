param(
    [switch]$ConfirmIncidentCorrelationAcceptance
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = "1"

function Fail([string]$Stage, [string]$Message) {
    Write-Host ("B72 FAIL STAGE=" + $Stage + " | " + $Message) -ForegroundColor Red
    Write-Host "BC SENTINEL v0.11.0-beta.7 B7-2 INCIDENT CORRELATION ENGINE - FAIL" -ForegroundColor Red
    exit 1
}

if (-not $ConfirmIncidentCorrelationAcceptance) {
    Fail "preflight" "B7-2 requires -ConfirmIncidentCorrelationAcceptance."
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
$FrozenB71 = "c75697b25c63e59bdfc2ad32374c4232c607fea0"

Write-Host ""
Write-Host "## BC Sentinel B7-2 - Incident Correlation Engine Acceptance"
Write-Host ("Branch: " + $Branch)
Write-Host ("Commit: " + $Commit)
Write-Host ("Frozen B7-1 predecessor: " + $FrozenB71)
Write-Host ""

foreach ($Frozen in @($FrozenBeta6, $FrozenB71)) {
    & git cat-file -e ($Frozen + "^{commit}") 2>$null
    if ($LASTEXITCODE -ne 0) { Fail "predecessor" ("Frozen predecessor commit not available locally: " + $Frozen) }
}

$Protected = @(
    "sentinel/protection_service_core.py",
    "sentinel/realtime.py",
    "sentinel/edr.py",
    "sentinel/edr_service_bridge.py"
)
foreach ($GitPath in $Protected) {
    & git diff --quiet $FrozenBeta6 HEAD -- $GitPath
    if ($LASTEXITCODE -ne 0) {
        Fail "protected-preflight" ("Protected B2 path differs from frozen Beta6 checkpoint: " + $GitPath)
    }
}
Write-Host "Protected B2 state unchanged from Beta6: PASS"

$FrozenB71Files = @(
    "coverage/attack_coverage_ledger.json",
    "sentinel/coverage_ledger.py",
    "tests/test_v011_beta7_b70_coverage_ledger.py",
    "sentinel/security_graph.py",
    "tests/test_v011_beta7_b71_security_graph.py"
)
foreach ($GitPath in $FrozenB71Files) {
    & git diff --quiet $FrozenB71 HEAD -- $GitPath
    if ($LASTEXITCODE -ne 0) {
        Fail "predecessor-freeze" ("Accepted B7-0/B7-1 foundation changed: " + $GitPath)
    }
}
Write-Host "Accepted B7-0/B7-1 foundations unchanged: PASS"

$TempProbe = Join-Path $RepoRoot (".b72-python-temp-" + [guid]::NewGuid().ToString("N") + ".txt")
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
$PytestBase = Join-Path $Base ("b72-pytest-" + [guid]::NewGuid().ToString("N"))
Write-Host ("pytest basetemp: " + $PytestBase)

Write-Host "[1/5] Compile B7-2..."
& $Py -m compileall -q sentinel/coverage_ledger.py sentinel/security_graph.py sentinel/incident_correlation.py tests/test_v011_beta7_b70_coverage_ledger.py tests/test_v011_beta7_b71_security_graph.py tests/test_v011_beta7_b72_incident_correlation.py
if ($LASTEXITCODE -ne 0) { Fail "compile" "B7-2 compile gate failed." }
Write-Host "Compile gate: PASS"
Write-Host ""

Write-Host "[2/5] Beta5 + Beta6 + B7-0/B7-1 predecessor regression + B7-2 deterministic tests..."
$Tests = @(
    Get-ChildItem -Path "tests/test_v011_beta5_*.py","tests/test_v011_beta6_*.py","tests/test_v011_beta7_b70_coverage_ledger.py","tests/test_v011_beta7_b71_security_graph.py","tests/test_v011_beta7_b72_incident_correlation.py" |
        Sort-Object FullName |
        ForEach-Object { $_.FullName }
)
try {
    & $Py -m pytest -q --basetemp "$PytestBase" @Tests
    if ($LASTEXITCODE -ne 0) { Fail "pytest" "Predecessor/B7-2 deterministic gate failed." }
}
finally {
    if (Test-Path -LiteralPath $PytestBase) {
        Remove-Item -LiteralPath $PytestBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "Predecessor + B7-2 deterministic gate: PASS"
Write-Host ""

Write-Host "[3/5] B7-0 coverage ledger self-check..."
& $Py -m sentinel.coverage_ledger --self-check
if ($LASTEXITCODE -ne 0) { Fail "ledger" "B7-0 coverage ledger self-check failed." }
Write-Host "B7-0 coverage ledger self-check: PASS"
Write-Host ""

Write-Host "[4/5] B7-1 Security Graph self-check..."
& $Py -m sentinel.security_graph --self-check
if ($LASTEXITCODE -ne 0) { Fail "security-graph" "B7-1 Security Graph self-check failed." }
Write-Host "B7-1 Security Graph self-check: PASS"
Write-Host ""

Write-Host "[5/5] B7-2 Incident Correlation semantic/determinism self-check..."
& $Py -m sentinel.incident_correlation --self-check
if ($LASTEXITCODE -ne 0) { Fail "incident-correlation" "B7-2 Incident Correlation self-check failed." }
Write-Host "Incident Correlation determinism + safety contract: PASS"
Write-Host ""
Write-Host "B7-2 correlates evidence read-only; temporal proximity alone is never sufficient and no remediation authority is added." -ForegroundColor DarkGray
Write-Host "BC SENTINEL v0.11.0-beta.7 B7-2 INCIDENT CORRELATION ENGINE - PASS" -ForegroundColor Green
