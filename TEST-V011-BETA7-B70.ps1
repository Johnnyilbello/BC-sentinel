param(
    [switch]$ConfirmCoverageLedgerAcceptance
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = "1"

function Fail([string]$Stage, [string]$Message) {
    Write-Host ("B70 FAIL STAGE=" + $Stage + " | " + $Message) -ForegroundColor Red
    Write-Host "BC SENTINEL v0.11.0-beta.7 B7-0 COVERAGE LEDGER FOUNDATION - FAIL" -ForegroundColor Red
    exit 1
}

if (-not $ConfirmCoverageLedgerAcceptance) {
    Fail "preflight" "B7-0 requires -ConfirmCoverageLedgerAcceptance."
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
$Frozen = "eb08758a304eb838d08af890ef9c4786264afbc0"

Write-Host ""
Write-Host "## BC Sentinel B7-0 - Coverage Ledger Foundation Acceptance"
Write-Host ("Branch: " + $Branch)
Write-Host ("Commit: " + $Commit)
Write-Host ("Frozen Beta6 predecessor: " + $Frozen)
Write-Host ""

& git cat-file -e ($Frozen + "^{commit}") 2>$null
if ($LASTEXITCODE -ne 0) { Fail "predecessor" "Frozen Beta6 checkpoint commit not available locally." }

$Protected = @(
    "sentinel/protection_service_core.py",
    "sentinel/realtime.py",
    "sentinel/edr.py",
    "sentinel/edr_service_bridge.py"
)
foreach ($GitPath in $Protected) {
    & git diff --quiet $Frozen HEAD -- $GitPath
    if ($LASTEXITCODE -ne 0) {
        Fail "protected-preflight" ("Protected B2 path differs from frozen Beta6 checkpoint: " + $GitPath)
    }
}
Write-Host "Protected B2 state unchanged from Beta6: PASS"

$TempProbe = Join-Path $RepoRoot (".b70-python-temp-" + [guid]::NewGuid().ToString("N") + ".txt")
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
$PytestBase = Join-Path $Base ("b70-pytest-" + [guid]::NewGuid().ToString("N"))
Write-Host ("pytest basetemp: " + $PytestBase)

Write-Host "[1/3] Compile B7-0..."
& $Py -m compileall -q sentinel/coverage_ledger.py tests/test_v011_beta7_b70_coverage_ledger.py
if ($LASTEXITCODE -ne 0) { Fail "compile" "B7-0 compile gate failed." }
Write-Host "Compile gate: PASS"
Write-Host ""

Write-Host "[2/3] Beta5 + Beta6 predecessor regression + B7-0 deterministic tests..."
$Tests = @(
    Get-ChildItem -Path "tests/test_v011_beta5_*.py","tests/test_v011_beta6_*.py","tests/test_v011_beta7_b70_coverage_ledger.py" |
        Sort-Object FullName |
        ForEach-Object { $_.FullName }
)
try {
    & $Py -m pytest -q --basetemp "$PytestBase" @Tests
    if ($LASTEXITCODE -ne 0) { Fail "pytest" "Predecessor/B7-0 deterministic gate failed." }
}
finally {
    if (Test-Path -LiteralPath $PytestBase) {
        Remove-Item -LiteralPath $PytestBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "Predecessor + B7-0 deterministic gate: PASS"
Write-Host ""

Write-Host "[3/3] Coverage ledger semantic self-check..."
& $Py -m sentinel.coverage_ledger --self-check
if ($LASTEXITCODE -ne 0) { Fail "ledger" "Coverage ledger self-check failed." }
Write-Host "Coverage ledger self-check: PASS"
Write-Host ""
Write-Host "B7-0 introduces no detector/remediation execution authority." -ForegroundColor DarkGray
Write-Host "BC SENTINEL v0.11.0-beta.7 B7-0 COVERAGE LEDGER FOUNDATION - PASS" -ForegroundColor Green
