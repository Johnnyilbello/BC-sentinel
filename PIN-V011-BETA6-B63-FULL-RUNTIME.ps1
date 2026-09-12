param(
    [Parameter(Mandatory=$true)][string]$RuntimeRoot,
    [string]$RuntimePython = "",
    [string[]]$ScanRoots = @()
)

$ErrorActionPreference='Stop'
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

Write-Host 'B6-3.2 pinned runtime configured for this PowerShell session.' -ForegroundColor Green
Write-Host ('Runtime root: '+$env:BC_SENTINEL_FULL_RUNTIME_ROOT)
Write-Host ('scanner.py SHA256: '+$env:BC_SENTINEL_FULL_RUNTIME_SCANNER_SHA256)
if($env:BC_SENTINEL_FULL_RUNTIME_PYTHON){Write-Host ('Runtime Python: '+$env:BC_SENTINEL_FULL_RUNTIME_PYTHON)}
if($env:BC_SENTINEL_SMART_SCAN_ROOTS){Write-Host ('Smart Scan roots: '+$env:BC_SENTINEL_SMART_SCAN_ROOTS)}else{Write-Host 'Smart Scan roots: Settings.defaults().monitored_dirs'}
Write-Host ''
Write-Host 'Preflight:' -ForegroundColor Cyan
Write-Host '.\.venv\Scripts\python.exe -m tools.v011_beta6_b63_live_runtime_probe'
Write-Host 'Explicit live scan only after preflight PASS:' -ForegroundColor Yellow
Write-Host '.\.venv\Scripts\python.exe -m tools.v011_beta6_b63_live_runtime_probe --execute --output .\acceptance-v011-beta6-b63-live.json'
