param()
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$id=[Security.Principal.WindowsIdentity]::GetCurrent(); $principal=New-Object Security.Principal.WindowsPrincipal($id)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Apri PowerShell come amministratore." }
if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    py -3.12 -m venv .venv
    & .\.venv\Scripts\python.exe -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw "Installazione requirements fallita" }
}
$Py=".\.venv\Scripts\python.exe"
Write-Host "BC Sentinel v0.10.0-beta.3 - ALL TESTS FROM ADMIN POWERSHELL (no reboot)" -ForegroundColor Cyan

# Full regression is included here too, not only targeted admin tests.
$Temp=Join-Path $env:TEMP "bc-sentinel-v010-beta3-all-admin"
Remove-Item $Temp -Recurse -Force -ErrorAction SilentlyContinue
& $Py -m pytest -q --basetemp "$Temp"
if ($LASTEXITCODE -ne 0) { throw "Full pytest fallito" }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\TEST-V010-BETA3-ADMIN-PHASE.ps1
if ($LASTEXITCODE -ne 0) { throw "Admin phase fallita" }

# True standard-user gate from an elevated shell. Use Explorer's filtered token
# from this interactive session rather than COM ShellExecute: on some Windows 11
# builds COM may execute the child with the caller's elevated token. The helper
# still fails closed unless it observes is_admin=false before invoking the broker.
$uacOut = Join-Path $env:TEMP ("bc-sentinel-beta3-standard-uac-" + [guid]::NewGuid().ToString("N") + ".json")
$helper = Join-Path $PSScriptRoot "TEST-V010-BETA3-STANDARD-UAC.ps1"
$launcher = Join-Path $PSScriptRoot "START-STANDARD-USER-PROCESS.ps1"
$psExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
$childArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$helper`" -Output `"$uacOut`""
$childPid = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $launcher -FilePath $psExe -ArgumentList $childArgs -WorkingDirectory $PSScriptRoot
if ($LASTEXITCODE -ne 0 -or -not $childPid) { throw "Avvio processo standard-user tramite token Explorer fallito." }
Write-Host "Standard-user helper avviato con token Explorer (PID $childPid)." -ForegroundColor DarkGray
$deadline=(Get-Date).AddMinutes(3)
while ((Get-Date) -lt $deadline -and -not (Test-Path $uacOut)) { Start-Sleep -Milliseconds 500 }
if (-not (Test-Path $uacOut)) { throw "Impossibile ottenere il risultato standard-user->UAC dal processo non elevato." }
$uac = Get-Content -Raw -LiteralPath $uacOut | ConvertFrom-Json
if (-not $uac.passed -or $uac.is_admin) { throw "Standard-user->UAC gate fallito o processo non de-elevato: $($uac | ConvertTo-Json -Compress)" }
Write-Host "STANDARD-USER -> UAC PASS" -ForegroundColor Green
Write-Host "ALL ADMIN-ORCHESTRATED TESTS PASS" -ForegroundColor Green
Write-Host "Inclusi: full suite, upgrade, repair e standard-user->UAC. Reboot volutamente rinviato a fine roadmap." -ForegroundColor Green
