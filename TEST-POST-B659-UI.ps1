param(
    [switch]$OpenUI,
    [string]$Python = "",
    [string]$TestRoot = $env:TEMP,
    [string]$Output = ".\acceptance-post-b659-ui.xml"
)
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = "1"
$UiPy = $Python
if (-not $UiPy) {
    $UiPy = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $UiPy)) { $UiPy = "python" }
}
$Base = "72c18bbdf1c50c633343750ead0f2467d8705e12"
git merge-base --is-ancestor $Base HEAD
if ($LASTEXITCODE -ne 0) { throw "Il branch non discende dal checkpoint accettato." }
$Branch = (git branch --show-current)
if ($Branch -like "checkpoint/*") { throw "Usare il branch product polish separato." }
Write-Host ("Branch: " + $Branch)
Write-Host ("Commit: " + (git rev-parse HEAD))
$PreviousQt = $env:QT_QPA_PLATFORM
$env:QT_QPA_PLATFORM = "offscreen"
$TestBase = Join-Path $TestRoot ("BCSentinel-UI-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $TestBase) | Out-Null
try {
    & $UiPy -m pytest -q --basetemp $TestBase --junitxml $Output tests/test_post_b659_ui_polish.py tests/test_v011_beta6_b658_persistent_restore.py tests/test_v011_beta6_b659_quarantine_integrity.py tests/test_v011_beta6_b63_smart_scan_ui.py tests/test_v011_beta6_ui_quality_refinement.py
    if ($LASTEXITCODE -ne 0) { throw "Acceptance UI fallita." }
    & $UiPy -m sentinel.home_guided_resolution_window --self-check
    if ($LASTEXITCODE -ne 0) { throw "Self-check fallito." }
} finally {
    $env:QT_QPA_PLATFORM = $PreviousQt
}
Write-Host "Acceptance product polish: PASS"
if (-not $OpenUI) { exit 0 }
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

Write-Host "UI product polish pronta." -ForegroundColor Cyan
Write-Host "Quarantene verificate: Ripristina file resta disponibile dopo verifica persistente."
Write-Host "Stati persistenti degradati: Verifica richiesta / Ripristino bloccato, senza pulsante di restore."
Write-Host "Discovery e audit restano read-only; nessun cleanup automatico."
Write-Host "Nessuna nuova autorita: DELETE e REPAIR restano disabilitati."
& $UiPy -m sentinel.home_guided_resolution_window
if ($LASTEXITCODE -ne 0) { throw "La UI product polish si e chiusa con errore." }
Write-Host "Sessione UI product polish terminata correttamente." -ForegroundColor Green


