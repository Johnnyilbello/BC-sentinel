$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PSScriptRoot\bootstrap.ps1" -Build
exit $LASTEXITCODE
