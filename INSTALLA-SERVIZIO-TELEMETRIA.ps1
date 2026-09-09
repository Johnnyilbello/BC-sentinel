param([switch]$Remove)
# v0.6 compatibility shim: the legacy telemetry-only Windows Service was
# retired. All privileged telemetry/protection now belongs to BCSentinelProtection.
$target = Join-Path $PSScriptRoot "INSTALLA-SERVIZIO-PROTEZIONE.ps1"
$forwardArgs = @("-NoProfile","-ExecutionPolicy","Bypass","-File","`"$target`"")
if ($Remove) { $forwardArgs += "-Remove" }
& powershell.exe @forwardArgs
exit $LASTEXITCODE
