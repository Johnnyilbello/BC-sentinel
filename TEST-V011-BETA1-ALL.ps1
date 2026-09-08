param()
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Fail([string]$Message) {
    Write-Host "BC SENTINEL v0.11.0-beta.1 — ALL GATES FAIL" -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Avvia TEST-V011-BETA1-ALL.bat da una PowerShell normale: il launcher deve verificare anche il passaggio standard-user -> UAC."
    }

    Write-Host "BC Sentinel v0.11.0-beta.1 - ONE COMMAND FULL ORCHESTRATION (no reboot)" -ForegroundColor Cyan

    $requiredFullBaseline = @(
        ".\BUILD-SERVIZIO-PROTEZIONE.ps1",
        ".\AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1",
        ".\tools\windows_acceptance.py",
        ".\tools\service_hardening_benchmark.py",
        ".\tools\broker_acceptance.py",
        ".\tests\test_checkpoint4_authenticode_hardening_reconstructed.py",
        ".\tests\test_v062_privileged_broker_update.py"
    )
    $missing = @($requiredFullBaseline | Where-Object { -not (Test-Path -LiteralPath $_) })
    if ($missing.Count -gt 0) {
        throw ("Baseline FULL incompleta. Mancano file della RC1 Windows testata: " + ($missing -join ", ") + ". Non usare un branch GitHub delta come pacchetto FULL.")
    }

    if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
        py -3.12 -m venv .venv
        if ($LASTEXITCODE -ne 0) { throw "Creazione .venv fallita" }
    }
    $Py = ".\.venv\Scripts\python.exe"

    & $Py -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw "Installazione requirements fallita" }

    $Temp = Join-Path $env:TEMP "bc-sentinel-v011-beta1-all"
    Remove-Item $Temp -Recurse -Force -ErrorAction SilentlyContinue
    & $Py -m pytest -q --basetemp "$Temp"
    if ($LASTEXITCODE -ne 0) { throw "Full pytest fallito" }

    & $Py -m tools.v011_edr_acceptance --output acceptance-v011-beta1-edr-local.json
    if ($LASTEXITCODE -ne 0) { throw "EDR Beta1 acceptance locale fallita" }

    & $Py -m tools.v010_web_deception_acceptance --output acceptance-v011-regression-deception-local.json
    if ($LASTEXITCODE -ne 0) { throw "v0.10 Beta1 deception regression fallita" }
    & $Py -m tools.v010_web_response_acceptance --output acceptance-v011-regression-response-local.json
    if ($LASTEXITCODE -ne 0) { throw "v0.10 Beta2 response regression fallita" }
    & $Py -m tools.v010_clone_scam_acceptance --output acceptance-v011-regression-clone-scam-local.json
    if ($LASTEXITCODE -ne 0) { throw "v0.10 Beta3 clone/scam regression fallita" }
    & $Py -m tools.v010_rc1_acceptance --output acceptance-v011-regression-rc1-local.json
    if ($LASTEXITCODE -ne 0) { throw "v0.10 RC1 consolidation regression fallita" }

    & $Py -m compileall -q app sentinel tools tests
    if ($LASTEXITCODE -ne 0) { throw "Compileall fallito" }

    $adminScript = Join-Path $PSScriptRoot "TEST-V011-BETA1-ADMIN-PHASE.ps1"
    if (-not (Test-Path -LiteralPath $adminScript)) { throw "Script admin v0.11 Beta1 mancante" }
    Write-Host "Richiesta elevazione UAC automatica per la fase nativa/amministrativa..." -ForegroundColor Yellow
    try {
        $proc = Start-Process -FilePath powershell.exe -Verb RunAs -Wait -PassThru -ArgumentList @(
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ("`"" + $adminScript + "`"")
        )
    } catch {
        throw "Elevazione UAC annullata o fallita: $($_.Exception.Message)"
    }
    if ($proc.ExitCode -ne 0) { throw "Fase amministratore automatica fallita (exit $($proc.ExitCode))" }

    & $Py -m tools.broker_acceptance --output acceptance-v011-beta1-standard-user-uac.json
    if ($LASTEXITCODE -ne 0) { throw "Standard-user -> UAC broker acceptance fallita" }

    & $Py -m tools.v011_edr_acceptance --output acceptance-v011-beta1-edr-post-admin.json
    if ($LASTEXITCODE -ne 0) { throw "EDR Beta1 post-admin regression fallita" }

    Write-Host "REBOOT PERSISTENCE GATE: DEFERRED TO FINAL ROADMAP VALIDATION" -ForegroundColor Yellow
    Write-Host "BC SENTINEL v0.11.0-beta.1 — ALL GATES PASS" -ForegroundColor Green
    Write-Host "Inclusi: full suite, EDR Beta1, regressioni v0.10 RC1, native/admin, upgrade, repair e standard-user->UAC. Reboot escluso." -ForegroundColor Green
    exit 0
} catch {
    Fail $_.Exception.Message
}
