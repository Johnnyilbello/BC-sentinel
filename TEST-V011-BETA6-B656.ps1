param(
    [switch]$ConfirmRealFileAcceptance,
    [string]$Output = ".\acceptance-v011-beta6-b656-real-file.json"
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = "1"

Write-Host ""
Write-Host "## BC Sentinel B6-5.6 - real-file quarantine boundary acceptance"
Write-Host ""
Write-Host "Branch: feature/v011-beta6-b65-guided-resolution"
Write-Host ("Commit: " + (git rev-parse --short HEAD))
Write-Host ""

if (-not $ConfirmRealFileAcceptance) {
    throw "B6-5.6 requires -ConfirmRealFileAcceptance. The test creates its own controlled file under Documents and never selects an existing personal file."
}

# Local machines do not always have the repository test dependencies installed.
# Detect pytest without invoking `python -m pytest` first: on Windows PowerShell,
# a missing module writes to stderr and can terminate immediately because this
# launcher intentionally uses $ErrorActionPreference = 'Stop'.
Write-Host "[0/2] Verifica dipendenze di test locali..."
$PytestAvailable = python -c "import importlib.util; print('yes' if importlib.util.find_spec('pytest') else 'no')"
if ($LASTEXITCODE -ne 0) {
    throw "Impossibile interrogare il Python corrente."
}
$PytestAvailable = ($PytestAvailable | Out-String).Trim()

if ($PytestAvailable -ne "yes") {
    Write-Host "pytest non disponibile: installazione minima nel Python corrente..."
    python -m pip install --disable-pip-version-check "pytest>=8,<10"
    if ($LASTEXITCODE -ne 0) {
        throw "Impossibile installare pytest nel Python corrente."
    }
}

$PytestVersion = python -c "import pytest; print(pytest.__version__)"
if ($LASTEXITCODE -ne 0) { throw "pytest non disponibile dopo il bootstrap." }
Write-Host ("pytest: " + (($PytestVersion | Out-String).Trim()))
Write-Host "Dipendenze test: PASS"
Write-Host ""

Write-Host "[1/2] Contract + deterministic regression..."
python -m pytest -q tests/test_v011_beta6_b656_real_file_execution.py
if ($LASTEXITCODE -ne 0) { throw "B6-5.6 deterministic regression failed." }
Write-Host "Deterministic gate: PASS"
Write-Host ""

Write-Host "[2/2] Controlled user-profile file -> quarantine -> journal -> rollback -> verification..."
Write-Host "Scope: test-owned file under %USERPROFILE%\Documents\BCSentinel-B656-Acceptance-*"
Write-Host "Existing personal files are not selected automatically."
python -m tools.v011_beta6_b656_live_acceptance --confirm-real-file-acceptance --output $Output
$Exit = $LASTEXITCODE
if ($Exit -ne 0) {
    throw "B6-5.6 real-file acceptance FAIL (exit=$Exit). Evidence: $Output"
}

$Evidence = Get-Content -Raw -Encoding UTF8 $Output | ConvertFrom-Json
Write-Host ""
Write-Host "B6-5.6 real-file quarantine boundary acceptance PASS."
Write-Host ("Rollback verificato: " + $Evidence.restored_state_verified)
Write-Host ("Journal verificato: " + $Evidence.journal_validation.passed)
Write-Host ("Cleanup verificato: " + $Evidence.cleanup_verified)
Write-Host ("Live Home execution autorizzata: " + $Evidence.live_home_execution_authorized)
Write-Host ("Acceptance evidence: " + $Output)
