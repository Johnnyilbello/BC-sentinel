param()
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$id=[Security.Principal.WindowsIdentity]::GetCurrent(); $principal=New-Object Security.Principal.WindowsPrincipal($id)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Questo launcher va avviato da PowerShell normale. Usa TEST-V010-BETA3-ALL-ADMIN.bat se sei gia elevato." }
Write-Host "BC Sentinel v0.10.0-beta.3 - ALL TESTS FROM NORMAL POWERSHELL (no reboot)" -ForegroundColor Cyan
if (-not (Test-Path ".\.venv\Scripts\python.exe")) { py -3.12 -m venv .venv }
$Py=".\.venv\Scripts\python.exe"
& $Py -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "Installazione requirements fallita" }
$Temp=Join-Path $env:TEMP "bc-sentinel-v010-beta3-all-normal"
Remove-Item $Temp -Recurse -Force -ErrorAction SilentlyContinue
& $Py -m pytest -q --basetemp "$Temp"
if ($LASTEXITCODE -ne 0) { throw "Full pytest fallito" }
& $Py -m tools.v010_web_deception_acceptance --output acceptance-v010-beta3-deception-local.json
if ($LASTEXITCODE -ne 0) { throw "Beta1 deception acceptance fallita" }
& $Py -m tools.v010_web_response_acceptance --output acceptance-v010-beta3-response-local.json
if ($LASTEXITCODE -ne 0) { throw "Beta2 response acceptance fallita" }
& $Py -m tools.v010_clone_scam_acceptance --output acceptance-v010-beta3-clone-scam-local.json
if ($LASTEXITCODE -ne 0) { throw "Beta3 clone/scam acceptance fallita" }
& $Py -m tools.web_threat_response_acceptance --output acceptance-v010-beta3-legacy-response-local.json
if ($LASTEXITCODE -ne 0) { throw "Legacy response regression fallita" }
& $Py -m compileall -q app sentinel tools tests
if ($LASTEXITCODE -ne 0) { throw "Compileall fallito" }

$adminScript = Join-Path $PSScriptRoot "TEST-V010-BETA3-ADMIN-PHASE.ps1"
$proc = Start-Process -FilePath powershell.exe -Verb RunAs -Wait -PassThru -ArgumentList @("-NoProfile","-ExecutionPolicy","Bypass","-File",("`""+$adminScript+"`""))
if ($proc.ExitCode -ne 0) { throw "Fase amministratore automatica fallita (exit $($proc.ExitCode))" }

& $Py -m tools.broker_acceptance --output acceptance-v010-beta3-standard-user-uac.json
if ($LASTEXITCODE -ne 0) { throw "Standard-user -> UAC broker acceptance fallita" }

Write-Host "ALL NORMAL-ORCHESTRATED TESTS PASS" -ForegroundColor Green
Write-Host "Inclusi: full suite, Beta1/Beta2/Beta3, native/admin, upgrade, repair e standard-user->UAC. Reboot volutamente rinviato a fine roadmap." -ForegroundColor Green
