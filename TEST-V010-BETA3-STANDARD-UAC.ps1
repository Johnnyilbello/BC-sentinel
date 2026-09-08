param([Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$id=[Security.Principal.WindowsIdentity]::GetCurrent(); $principal=New-Object Security.Principal.WindowsPrincipal($id)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $payload = @{ product="BC Sentinel"; version="0.10.0-beta.3"; is_admin=$true; passed=$false; error="standard_user_required" } | ConvertTo-Json -Depth 5
    Set-Content -LiteralPath $Output -Value $payload -Encoding UTF8
    exit 2
}
if (-not (Test-Path ".\.venv\Scripts\python.exe")) { throw ".venv non disponibile" }
$Py=".\.venv\Scripts\python.exe"
& $Py -m tools.broker_acceptance --output $Output
exit $LASTEXITCODE
