param()
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$id=[Security.Principal.WindowsIdentity]::GetCurrent(); $principal=New-Object Security.Principal.WindowsPrincipal($id)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Apri PowerShell come amministratore." }

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    Write-Host ".venv assente: preparo automaticamente l'ambiente per il retest UAC." -ForegroundColor DarkGray
    py -3.12 -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw "Creazione .venv fallita" }
    & .\.venv\Scripts\python.exe -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw "Installazione requirements fallita" }
}

Write-Host "BC Sentinel v0.10.0-beta.3 FIX2 - RETEST standard-user -> UAC from ADMIN" -ForegroundColor Cyan
$uacOut = Join-Path $env:TEMP ("bc-sentinel-beta3-standard-uac-retest-" + [guid]::NewGuid().ToString("N") + ".json")
$helper = Join-Path $PSScriptRoot "TEST-V010-BETA3-STANDARD-UAC.ps1"
$launcher = Join-Path $PSScriptRoot "START-STANDARD-USER-PROCESS.ps1"
$psExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
$childArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$helper`" -Output `"$uacOut`""
$taskName = $null
try {
    $launchOutput = @(& $launcher -FilePath $psExe -ArgumentList $childArgs -WorkingDirectory $PSScriptRoot)
    if (-not $launchOutput -or $launchOutput.Count -lt 1) { throw "Task standard-user non creato." }
    $taskName = [string]$launchOutput[-1]
    if ([string]::IsNullOrWhiteSpace($taskName)) { throw "Nome task standard-user non valido." }
    Write-Host "Helper standard-user avviato tramite task Limited: $taskName" -ForegroundColor DarkGray

    $deadline=(Get-Date).AddMinutes(3)
    while ((Get-Date) -lt $deadline -and -not (Test-Path $uacOut)) { Start-Sleep -Milliseconds 500 }
    if (-not (Test-Path $uacOut)) {
        $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
        $last = if ($taskInfo) { $taskInfo.LastTaskResult } else { "n/a" }
        throw "Nessun risultato standard-user->UAC. LastTaskResult=$last"
    }
    $uac = Get-Content -Raw -LiteralPath $uacOut | ConvertFrom-Json
    $uac | ConvertTo-Json -Depth 10
    if (-not $uac.passed -or $uac.is_admin) { throw "Standard-user->UAC gate fallito: $($uac | ConvertTo-Json -Compress)" }
    Write-Host "STANDARD-USER -> UAC PASS" -ForegroundColor Green
} finally {
    if ($taskName) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $uacOut -Force -ErrorAction SilentlyContinue
}
