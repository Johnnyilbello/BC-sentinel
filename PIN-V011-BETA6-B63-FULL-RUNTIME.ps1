param(
    [Parameter(Mandatory=$true)][string]$RuntimeRoot,
    [string]$RuntimePython = "",
    [string[]]$ScanRoots = @(),
    [switch]$Execute,
    [string]$Output = ".\acceptance-v011-beta6-b63-live.json"
)

$ErrorActionPreference='Stop'
Set-Location -LiteralPath $PSScriptRoot

$resolved=(Resolve-Path -LiteralPath $RuntimeRoot).Path
$scanner=Join-Path $resolved 'sentinel\scanner.py'
if(-not(Test-Path -LiteralPath $scanner -PathType Leaf)){
    throw "sentinel\scanner.py non trovato in: $resolved"
}
$sha=(Get-FileHash -LiteralPath $scanner -Algorithm SHA256).Hash.ToLowerInvariant()

$env:BC_SENTINEL_FULL_RUNTIME_ROOT=$resolved
$env:BC_SENTINEL_FULL_RUNTIME_SCANNER_SHA256=$sha

if($RuntimePython){
    $pythonResolved=(Resolve-Path -LiteralPath $RuntimePython).Path
    $env:BC_SENTINEL_FULL_RUNTIME_PYTHON=$pythonResolved
}else{
    Remove-Item Env:BC_SENTINEL_FULL_RUNTIME_PYTHON -ErrorAction SilentlyContinue
}

if($ScanRoots.Count -gt 0){
    $resolvedRoots=@()
    foreach($root in $ScanRoots){
        $resolvedRoots += (Resolve-Path -LiteralPath $root).Path
    }
    $env:BC_SENTINEL_SMART_SCAN_ROOTS=($resolvedRoots -join [IO.Path]::PathSeparator)
}else{
    Remove-Item Env:BC_SENTINEL_SMART_SCAN_ROOTS -ErrorAction SilentlyContinue
}

$Py=Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if(-not(Test-Path -LiteralPath $Py -PathType Leaf)){
    throw ".venv Python non trovato: $Py"
}

Write-Host 'B6-3.2 pinned runtime configured.' -ForegroundColor Green
Write-Host ('Runtime root: '+$env:BC_SENTINEL_FULL_RUNTIME_ROOT)
Write-Host ('scanner.py SHA256: '+$env:BC_SENTINEL_FULL_RUNTIME_SCANNER_SHA256)
if($env:BC_SENTINEL_FULL_RUNTIME_PYTHON){Write-Host ('Runtime Python: '+$env:BC_SENTINEL_FULL_RUNTIME_PYTHON)}
if($env:BC_SENTINEL_SMART_SCAN_ROOTS){Write-Host ('Smart Scan roots: '+$env:BC_SENTINEL_SMART_SCAN_ROOTS)}else{Write-Host 'Smart Scan roots: Settings.defaults().monitored_dirs'}
Write-Host ''

# Important: when this helper is launched through `powershell.exe -File`, process
# environment variables cannot propagate back to the caller.  Therefore the
# passive preflight is intentionally executed here, in the same process that
# owns the runtime pin.  This does NOT start a scan.
Write-Host 'B6-3.2 passive runtime preflight...' -ForegroundColor Cyan
& $Py -m tools.v011_beta6_b63_live_runtime_probe
$PreflightExit=$LASTEXITCODE
if($PreflightExit -ne 0){
    throw "B6-3.2 preflight non accettato (exit=$PreflightExit). Nessuna scansione e stata avviata."
}

Write-Host 'B6-3.2 preflight PASS: provider accepted.' -ForegroundColor Green

if(-not $Execute){
    Write-Host 'Nessuna scansione avviata. Per eseguire esplicitamente la Smart Scan, rilancia questo helper con -Execute.' -ForegroundColor Yellow
    return
}

Write-Host 'B6-3.2 explicit live Smart Scan requested by user...' -ForegroundColor Yellow
if($Output){
    & $Py -m tools.v011_beta6_b63_live_runtime_probe --execute --output $Output
}else{
    & $Py -m tools.v011_beta6_b63_live_runtime_probe --execute
}
$ExecuteExit=$LASTEXITCODE
if($ExecuteExit -ne 0){
    throw "B6-3.2 live Smart Scan non completata con stato accettabile (exit=$ExecuteExit)."
}
Write-Host 'B6-3.2 live Smart Scan completed.' -ForegroundColor Green
if($Output){Write-Host ('Acceptance evidence: '+$Output)}
