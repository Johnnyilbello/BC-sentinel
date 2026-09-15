param(
    [switch]$ConfirmQuarantineIntegrityAcceptance,
    [switch]$OpenUI,
    [string]$Output = ".\acceptance-v011-beta6-b659-home.json"
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = "1"

Write-Host ""
Write-Host "## BC Sentinel B6-5.9 - Quarantine integrity visibility acceptance"
Write-Host ("Branch: " + (git branch --show-current))
Write-Host ("Commit: " + (git rev-parse --short HEAD))
Write-Host ""

if (-not $ConfirmQuarantineIntegrityAcceptance) {
    throw "B6-5.9 requires -ConfirmQuarantineIntegrityAcceptance. The acceptance uses only test-owned temporary files."
}

$Py = "python"
$PytestAvailable = & $Py -c "import importlib.util; print('yes' if importlib.util.find_spec('pytest') else 'no')"
if ($LASTEXITCODE -ne 0) { throw "Impossibile interrogare il Python corrente." }
if ((($PytestAvailable | Out-String).Trim()) -ne "yes") {
    Write-Host "pytest non disponibile: installazione minima..."
    & $Py -m pip install --disable-pip-version-check "pytest>=8,<10"
    if ($LASTEXITCODE -ne 0) { throw "Impossibile installare pytest." }
}

$PytestBase = Join-Path $env:TEMP ("BCSentinel-B659-Pytest-" + [guid]::NewGuid().ToString("N"))
Write-Host ("pytest basetemp: " + $PytestBase)
Write-Host "[1/4] Regressione B6-5.8 + test deterministici B6-5.9..."
try {
    & $Py -m pytest -q --basetemp "$PytestBase" `
        tests/test_v011_beta6_b658_persistent_restore.py `
        tests/test_v011_beta6_b659_quarantine_integrity.py
    if ($LASTEXITCODE -ne 0) { throw "B6-5.9 deterministic regression failed." }
}
finally {
    if (Test-Path -LiteralPath $PytestBase) {
        Remove-Item -LiteralPath $PytestBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "Deterministic gate: PASS"
Write-Host ""

Write-Host "[2/4] Processo A -> due quarantene -> degrado controllato -> Processo B -> visibilita fail-closed -> restore valido..."
& $Py -m tools.v011_beta6_b659_home_acceptance --confirm-quarantine-integrity-acceptance --output $Output
if ($LASTEXITCODE -ne 0) { throw "B6-5.9 fresh-process acceptance failed. Evidence: $Output" }
$Evidence = Get-Content -Raw -Encoding UTF8 $Output | ConvertFrom-Json
Write-Host ("Nuovo processo verificato: " + $Evidence.fresh_process_verified)
Write-Host ("Riga verificata visibile: " + $Evidence.verified_row_visible)
Write-Host ("Stato degradato visibile: " + $Evidence.blocked_integrity_row_visible)
Write-Host ("Ripristino degradato rifiutato: " + $Evidence.blocked_restore_refused)
Write-Host ("Discovery read-only: " + $Evidence.restart_discovery_read_only)
Write-Host ("Restore valido verificato: " + $Evidence.valid_restore_verified)
Write-Host ("SHA-256 valido identico: " + $Evidence.valid_sha256_identical)
Write-Host ("General Home execution autorizzata: " + $Evidence.general_home_execution_authorized)
Write-Host ""

$UiPy = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $UiPy -PathType Leaf)) { $UiPy = "python" }

Write-Host "[3/4] Self-check B6-5.9..."
& $UiPy -c "import PySide6" 2>$null
if ($LASTEXITCODE -ne 0) {
    throw "PySide6 non disponibile nel Python UI. Usa la .venv del progetto o installa requirements.txt."
}
& $UiPy -m sentinel.home_guided_resolution_window --self-check *> $null
if ($LASTEXITCODE -ne 0) { throw "B6-5.9 self-check fallito." }
Write-Host "Self-check B6-5.9: PASS"
Write-Host ""

if (-not $OpenUI) {
    Write-Host "[4/4] UI non richiesta. B6-5.9 acceptance PASS." -ForegroundColor Green
    exit 0
}

Write-Host "[4/4] Preflight runtime storico e apertura UI B6-5.9..."
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

Write-Host "UI B6-5.9 pronta." -ForegroundColor Cyan
Write-Host "Quarantene verificate: Ripristina file resta disponibile dopo verifica persistente."
Write-Host "Stati persistenti degradati: Verifica richiesta / Ripristino bloccato, senza pulsante di restore."
Write-Host "Discovery e audit restano read-only; nessun cleanup automatico."
Write-Host "Nessuna nuova autorita: DELETE e REPAIR restano disabilitati."
& $UiPy -m sentinel.home_guided_resolution_window
if ($LASTEXITCODE -ne 0) { throw "La UI B6-5.9 si e chiusa con errore." }
Write-Host "Sessione UI B6-5.9 terminata correttamente." -ForegroundColor Green
