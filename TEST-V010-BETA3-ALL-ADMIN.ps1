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

$Temp=Join-Path $env:TEMP "bc-sentinel-v010-beta3-all-admin"
Remove-Item $Temp -Recurse -Force -ErrorAction SilentlyContinue
& $Py -m pytest -q --basetemp "$Temp"
if ($LASTEXITCODE -ne 0) { throw "Full pytest fallito" }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\TEST-V010-BETA3-ADMIN-PHASE.ps1
if ($LASTEXITCODE -ne 0) { throw "Admin phase fallita" }

$uacOut = Join-Path $env:TEMP ("bc-sentinel-beta3-standard-uac-" + [guid]::NewGuid().ToString("N") + ".json")
$helper = Join-Path $PSScriptRoot "TEST-V010-BETA3-STANDARD-UAC.ps1"
$args = "-NoProfile -ExecutionPolicy Bypass -File `"$helper`" -Output `"$uacOut`""
$shell = New-Object -ComObject Shell.Application
$shell.ShellExecute("powershell.exe", $args, $PSScriptRoot, "open", 1)
$deadline=(Get-Date).AddMinutes(3)
while ((Get-Date) -lt $deadline -and -not (Test-Path $uacOut)) { Start-Sleep -Milliseconds 500 }
if (-not (Test-Path $uacOut)) { throw "Impossibile ottenere il risultato standard-user->UAC dal processo non elevato." }
$uac = Get-Content -Raw -LiteralPath $uacOut | ConvertFrom-Json
if (-not $uac.passed -or $uac.is_admin) { throw "Standard-user->UAC gate fallito o processo non de-elevato: $($uac | ConvertTo-Json -Compress)" }
Write-Host "STANDARD-USER -> UAC PASS" -ForegroundColor Green
Write-Host "ALL ADMIN-ORCHESTRATED TESTS PASS" -ForegroundColor Green
Write-Host "Inclusi: full suite, upgrade, repair e standard-user->UAC. Reboot volutamente rinviato a fine roadmap." -ForegroundColor Green
