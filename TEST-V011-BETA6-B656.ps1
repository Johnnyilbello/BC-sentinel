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
