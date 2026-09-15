param(
    [switch]$ConfirmSecurityGraphAcceptance
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = "1"

function Fail([string]$Stage, [string]$Message) {
    Write-Host ("B71 FAIL STAGE=" + $Stage + " | " + $Message) -ForegroundColor Red
    Write-Host "BC SENTINEL v0.11.0-beta.7 B7-1 SENTINEL SECURITY GRAPH FOUNDATION - FAIL" -ForegroundColor Red
    exit 1
}

if (-not $ConfirmSecurityGraphAcceptance) {
    Fail "preflight" "B7-1 requires -ConfirmSecurityGraphAcceptance."
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
$FrozenB70 = "cd06f284525b3e0f70c121b6b97833cbf388c9ce"
$FrozenBeta6 = "eb08758a304eb838d08af890ef9c4786264afbc0"

Write-Host ""
Write-Host "## BC Sentinel B7-1 - Sentinel Security Graph Foundation Acceptance"
Write-Host ("Branch: " + $Branch)
Write-Host ("Commit: " + $Commit)
Write-Host ("Frozen B7-0 predecessor: " + $FrozenB70)
Write-Host ""

foreach ($Frozen in @($FrozenB70, $FrozenBeta6)) {
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

$B70Protected = @(
    "coverage/attack_coverage_ledger.json",
    "sentinel/coverage_ledger.py",
    "tests/test_v011_beta7_b70_coverage_ledger.py"
)
foreach ($GitPath in $B70Protected) {
    & git diff --quiet $FrozenB70 HEAD -- $GitPath
    if ($LASTEXITCODE -ne 0) {
        Fail "b70-predecessor" ("Accepted B7-0 coverage ledger path changed: " + $GitPath)
    }
}
Write-Host "Accepted B7-0 ledger foundation unchanged: PASS"

$TempProbe = Join-Path $RepoRoot (".b71-python-temp-" + [guid]::NewGuid().ToString("N") + ".txt")
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
$PytestBase = Join-Path $Base ("b71-pytest-" + [guid]::NewGuid().ToString("N"))
Write-Host ("pytest basetemp: " + $PytestBase)

Write-Host "[1/4] Compile B7-1..."
& $Py -m compileall -q sentinel/security_graph.py tests/test_v011_beta7_b71_security_graph.py
if ($LASTEXITCODE -ne 0) { Fail "compile" "B7-1 compile gate failed." }
Write-Host "Compile gate: PASS"
Write-Host ""

Write-Host "[2/4] Beta5 + Beta6 + B7-0 predecessor regression + B7-1 deterministic tests..."
$Tests = @(
    Get-ChildItem -Path "tests/test_v011_beta5_*.py","tests/test_v011_beta6_*.py","tests/test_v011_beta7_b70_coverage_ledger.py","tests/test_v011_beta7_b71_security_graph.py" |
        Sort-Object FullName |
        ForEach-Object { $_.FullName }
)
try {
    & $Py -m pytest -q --basetemp "$PytestBase" @Tests
    if ($LASTEXITCODE -ne 0) { Fail "pytest" "Predecessor/B7-1 deterministic gate failed." }
}
finally {
    if (Test-Path -LiteralPath $PytestBase) {
        Remove-Item -LiteralPath $PytestBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "Predecessor + B7-1 deterministic gate: PASS"
Write-Host ""

Write-Host "[3/4] B7-0 coverage ledger self-check..."
& $Py -m sentinel.coverage_ledger --self-check
if ($LASTEXITCODE -ne 0) { Fail "coverage-ledger" "Accepted B7-0 coverage ledger self-check failed." }
Write-Host "B7-0 coverage ledger self-check: PASS"
Write-Host ""

Write-Host "[4/4] Security Graph semantic/determinism self-check..."
& $Py -m sentinel.security_graph --self-check
if ($LASTEXITCODE -ne 0) { Fail "security-graph" "B7-1 Security Graph self-check failed." }
& $Py -c "from sentinel.security_graph import self_check; a=self_check(); b=self_check(); assert a['passed'] and a['stable_round_trip']; assert a['graph_digest']==b['graph_digest']; assert a['execution_authority_added'] is False; assert a['automatic_quarantine'] is False; assert a['automatic_repair'] is False; assert a['automatic_restore'] is False; assert a['general_home_execution_authorized'] is False"
if ($LASTEXITCODE -ne 0) { Fail "security-graph" "B7-1 determinism/safety assertions failed." }
Write-Host "Security Graph determinism + safety contract: PASS"
Write-Host ""
Write-Host "B7-1 adds read-only incident intelligence only; no remediation authority." -ForegroundColor DarkGray
Write-Host "BC SENTINEL v0.11.0-beta.7 B7-1 SENTINEL SECURITY GRAPH FOUNDATION - PASS" -ForegroundColor Green
