param(
    [switch]$ConfirmHomeQuarantineAcceptance,
    [switch]$OpenUI,
    [string]$Output = ".\acceptance-v011-beta6-b657-home.json"
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = "1"

Write-Host ""
Write-Host "## BC Sentinel B6-5.7 - Home quarantine integration acceptance"
Write-Host ("Branch: " + (git branch --show-current))
Write-Host ("Commit: " + (git rev-parse --short HEAD))
Write-Host ""

if (-not $ConfirmHomeQuarantineAcceptance) {
    throw "B6-5.7 requires -ConfirmHomeQuarantineAcceptance. The acceptance uses only a test-owned temporary file."
}

$Py = "python"
$PytestAvailable = & $Py -c "import importlib.util; print('yes' if importlib.util.find_spec('pytest') else 'no')"
if ($LASTEXITCODE -ne 0) { throw "Impossibile interrogare il Python corrente." }
if ((($PytestAvailable | Out-String).Trim()) -ne "yes") {
    Write-Host "pytest non disponibile: installazione minima..."
    & $Py -m pip install --disable-pip-version-check "pytest>=8,<10"
    if ($LASTEXITCODE -ne 0) { throw "Impossibile installare pytest." }
}

$PytestBase = Join-Path $env:TEMP ("BCSentinel-B657-Pytest-" + [guid]::NewGuid().ToString("N"))
Write-Host ("pytest basetemp: " + $PytestBase)
Write-Host "[1/3] Regressione deterministica B6-5.7..."
try {
    & $Py -m pytest -q --basetemp "$PytestBase" tests/test_v011_beta6_b657_home_quarantine.py
    if ($LASTEXITCODE -ne 0) { throw "B6-5.7 deterministic regression failed." }
}
finally {
    if (Test-Path -LiteralPath $PytestBase) {
        Remove-Item -LiteralPath $PytestBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "Deterministic gate: PASS"
Write-Host ""

Write-Host "[2/3] Home flow controllato -> conferma -> quarantena -> lista -> rollback..."
& $Py -m tools.v011_beta6_b657_home_acceptance --confirm-home-quarantine-acceptance --output $Output
if ($LASTEXITCODE -ne 0) { throw "B6-5.7 controlled Home acceptance failed. Evidence: $Output" }
$Evidence = Get-Content -Raw -Encoding UTF8 $Output | ConvertFrom-Json
Write-Host ("Quarantena verificata: " + $Evidence.quarantine_verified)
Write-Host ("Lista Quarantena verificata: " + $Evidence.quarantine_page_rows_verified)
Write-Host ("Rollback verificato: " + $Evidence.rollback_verified)
Write-Host ("General Home execution autorizzata: " + $Evidence.general_home_execution_authorized)
Write-Host ""

if (-not $OpenUI) {
    Write-Host "[3/3] UI non richiesta. B6-5.7 acceptance PASS." -ForegroundColor Green
    exit 0
}

Write-Host "[3/3] Preflight runtime e apertura UI B6-5.7..."
$UiPy = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $UiPy -PathType Leaf)) { $UiPy = "python" }
& $UiPy -c "import PySide6" 2>$null
if ($LASTEXITCODE -ne 0) {
    throw "PySide6 non disponibile nel Python UI. Usa la .venv del progetto o installa requirements.txt."
}

$ExpectedScannerSha = "7874df734f6146f8848d8a55f5eb6be37bb5cbaee1638e051357f978f5275433"
$Downloads = Join-Path $env:USERPROFILE "Downloads"
$ScannerPath = $null
if (Test-Path -LiteralPath $Downloads -PathType Container) {
    $Candidates = @(& where.exe /R "$Downloads" scanner.py 2>$null)
    $ScannerPath = ($Candidates | Where-Object { $_ -match '\\sentinel\\scanner\.py$' -and $_ -like '*Consolidation_FULL*' } | Select-Object -First 1)
}
if (-not $ScannerPath) { throw "Runtime storico Consolidation_FULL non trovato." }
$RuntimeRoot = Split-Path -Parent (Split-Path -Parent $ScannerPath)
$ActualScannerSha = (Get-FileHash -LiteralPath $ScannerPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($ActualScannerSha -ne $ExpectedScannerSha) { throw "scanner.py storico non corrisponde allo SHA verificato." }

$env:BC_SENTINEL_FULL_RUNTIME_ROOT = $RuntimeRoot
$env:BC_SENTINEL_FULL_RUNTIME_SCANNER_SHA256 = $ExpectedScannerSha
$RuntimePython = Join-Path $RuntimeRoot ".venv\Scripts\python.exe"
$env:BC_SENTINEL_FULL_RUNTIME_PYTHON = $(if (Test-Path -LiteralPath $RuntimePython) { $RuntimePython } else { $UiPy })
$env:BC_SENTINEL_SMART_SCAN_MAX_FILES = "250"
$env:BC_SENTINEL_SMART_SCAN_MAX_TOTAL_BYTES = [string](128MB)
$env:BC_SENTINEL_SMART_SCAN_MAX_FILE_BYTES = [string](64MB)
$env:BC_SENTINEL_SMART_SCAN_RECENT_DAYS = "90"
Remove-Item Env:QT_QPA_PLATFORM -ErrorAction SilentlyContinue

& $UiPy -m sentinel.home_guided_resolution_window --self-check *> $null
if ($LASTEXITCODE -ne 0) { throw "B6-5.7 self-check fallito. UI non avviata." }

Write-Host "UI B6-5.7 pronta. Smart Scan resta esplicita." -ForegroundColor Cyan
Write-Host "La quarantena compare solo per HIGH/CRITICAL con SHA-256 verificato e file eleggibile."
Write-Host "Nessuna azione automatica; DELETE e REPAIR restano disabilitati."
& $UiPy -m sentinel.home_guided_resolution_window
if ($LASTEXITCODE -ne 0) { throw "La UI B6-5.7 si e chiusa con errore." }
Write-Host "Sessione UI B6-5.7 terminata correttamente." -ForegroundColor Green
