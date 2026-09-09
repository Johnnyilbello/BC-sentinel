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
Write-Host "BC Sentinel v0.10.0-rc.1 - ALL TESTS FROM ADMIN POWERSHELL (no reboot)" -ForegroundColor Cyan

# Full regression is included here too, not only targeted admin tests.
$Temp=Join-Path $env:TEMP "bc-sentinel-v010-rc1-all-admin"
Remove-Item $Temp -Recurse -Force -ErrorAction SilentlyContinue
& $Py -m pytest -q --basetemp "$Temp"
if ($LASTEXITCODE -ne 0) { throw "Full pytest fallito" }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\TEST-V010-RC1-ADMIN-PHASE.ps1
if ($LASTEXITCODE -ne 0) { throw "Admin phase fallita" }

# True standard-user gate from an elevated shell. FIX2 delegates creation of
# the medium-integrity token to Windows Task Scheduler using an Interactive
# principal with RunLevel=Limited. The child still fails closed unless it sees
# is_admin=false before invoking the one-action UAC broker.
$uacOut = Join-Path $env:TEMP ("bc-sentinel-rc1-standard-uac-" + [guid]::NewGuid().ToString("N") + ".json")
$helper = Join-Path $PSScriptRoot "TEST-V010-RC1-STANDARD-UAC.ps1"
$launcher = Join-Path $PSScriptRoot "START-STANDARD-USER-PROCESS.ps1"
$psExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
$childArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$helper`" -Output `"$uacOut`""
$taskName = $null
try {
    $launchOutput = @(& $launcher -FilePath $psExe -ArgumentList $childArgs -WorkingDirectory $PSScriptRoot)
    if (-not $launchOutput -or $launchOutput.Count -lt 1) { throw "Task standard-user non creato." }
    $taskName = [string]$launchOutput[-1]
    if ([string]::IsNullOrWhiteSpace($taskName)) { throw "Nome task standard-user non valido." }
    Write-Host "Standard-user helper avviato tramite task Limited: $taskName" -ForegroundColor DarkGray

    $deadline=(Get-Date).AddMinutes(3)
    while ((Get-Date) -lt $deadline -and -not (Test-Path $uacOut)) { Start-Sleep -Milliseconds 500 }
    if (-not (Test-Path $uacOut)) {
        $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
        $last = if ($taskInfo) { $taskInfo.LastTaskResult } else { "n/a" }
        throw "Impossibile ottenere il risultato standard-user->UAC. LastTaskResult=$last"
    }
    $uac = Get-Content -Raw -LiteralPath $uacOut | ConvertFrom-Json
    if (-not $uac.passed -or $uac.is_admin) { throw "Standard-user->UAC gate fallito o processo non de-elevato: $($uac | ConvertTo-Json -Compress)" }
    Write-Host "STANDARD-USER -> UAC PASS" -ForegroundColor Green
    Write-Host "ALL ADMIN-ORCHESTRATED TESTS PASS" -ForegroundColor Green
    Write-Host "Inclusi: full suite, upgrade, repair e standard-user->UAC. Reboot volutamente rinviato a fine roadmap." -ForegroundColor Green
} finally {
    if ($taskName) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $uacOut -Force -ErrorAction SilentlyContinue
}
