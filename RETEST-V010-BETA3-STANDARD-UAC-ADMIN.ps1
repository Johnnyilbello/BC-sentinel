param()
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$id=[Security.Principal.WindowsIdentity]::GetCurrent(); $principal=New-Object Security.Principal.WindowsPrincipal($id)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Apri PowerShell come amministratore." }
if (-not (Test-Path ".\.venv\Scripts\python.exe")) { throw ".venv non disponibile: esegui prima il launcher completo." }

Write-Host "BC Sentinel v0.10.0-beta.3 - RETEST standard-user -> UAC from ADMIN" -ForegroundColor Cyan
$uacOut = Join-Path $env:TEMP ("bc-sentinel-beta3-standard-uac-retest-" + [guid]::NewGuid().ToString("N") + ".json")
$helper = Join-Path $PSScriptRoot "TEST-V010-BETA3-STANDARD-UAC.ps1"
$launcher = Join-Path $PSScriptRoot "START-STANDARD-USER-PROCESS.ps1"
$psExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
$childArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$helper`" -Output `"$uacOut`""
$childPid = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $launcher -FilePath $psExe -ArgumentList $childArgs -WorkingDirectory $PSScriptRoot
if ($LASTEXITCODE -ne 0 -or -not $childPid) { throw "Avvio processo standard-user tramite token Explorer fallito." }
Write-Host "Standard-user helper avviato con token Explorer (PID $childPid)." -ForegroundColor DarkGray
$deadline=(Get-Date).AddMinutes(3)
while ((Get-Date) -lt $deadline -and -not (Test-Path $uacOut)) { Start-Sleep -Milliseconds 500 }
if (-not (Test-Path $uacOut)) { throw "Nessun risultato standard-user->UAC." }
$uac = Get-Content -Raw -LiteralPath $uacOut | ConvertFrom-Json
$uac | ConvertTo-Json -Depth 10
if (-not $uac.passed -or $uac.is_admin) { throw "Standard-user->UAC gate fallito: $($uac | ConvertTo-Json -Compress)" }
Write-Host "STANDARD-USER -> UAC PASS" -ForegroundColor Green
