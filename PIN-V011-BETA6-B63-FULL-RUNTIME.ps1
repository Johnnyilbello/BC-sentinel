param(
    [Parameter(Mandatory=$true)][string]$RuntimeRoot,
    [string]$RuntimePython = "",
    [string[]]$ScanRoots = @(),
    [int]$MaxFiles = 0,
    [int]$MaxTotalMB = 0,
    [int]$MaxFileMB = 0,
    [int]$RecentDays = 0,
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

if($MaxFiles -gt 0){$env:BC_SENTINEL_SMART_SCAN_MAX_FILES=[string]$MaxFiles}else{Remove-Item Env:BC_SENTINEL_SMART_SCAN_MAX_FILES -ErrorAction SilentlyContinue}
if($MaxTotalMB -gt 0){$env:BC_SENTINEL_SMART_SCAN_MAX_TOTAL_BYTES=[string]($MaxTotalMB * 1MB)}else{Remove-Item Env:BC_SENTINEL_SMART_SCAN_MAX_TOTAL_BYTES -ErrorAction SilentlyContinue}
if($MaxFileMB -gt 0){$env:BC_SENTINEL_SMART_SCAN_MAX_FILE_BYTES=[string]($MaxFileMB * 1MB)}else{Remove-Item Env:BC_SENTINEL_SMART_SCAN_MAX_FILE_BYTES -ErrorAction SilentlyContinue}
if($RecentDays -gt 0){$env:BC_SENTINEL_SMART_SCAN_RECENT_DAYS=[string]$RecentDays}else{Remove-Item Env:BC_SENTINEL_SMART_SCAN_RECENT_DAYS -ErrorAction SilentlyContinue}

$Py=Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if(-not(Test-Path -LiteralPath $Py -PathType Leaf)){
    throw ".venv Python non trovato: $Py"
}

Write-Host 'B6-3.4 pinned runtime configured.' -ForegroundColor Green
Write-Host ('Runtime root: '+$env:BC_SENTINEL_FULL_RUNTIME_ROOT)
Write-Host ('scanner.py SHA256: '+$env:BC_SENTINEL_FULL_RUNTIME_SCANNER_SHA256)
if($env:BC_SENTINEL_FULL_RUNTIME_PYTHON){Write-Host ('Runtime Python: '+$env:BC_SENTINEL_FULL_RUNTIME_PYTHON)}
if($env:BC_SENTINEL_SMART_SCAN_ROOTS){Write-Host ('Smart Scan roots: '+$env:BC_SENTINEL_SMART_SCAN_ROOTS)}else{Write-Host 'Smart Scan roots: Settings.defaults().monitored_dirs'}
Write-Host ('Smart scope MaxFiles: '+$(if($env:BC_SENTINEL_SMART_SCAN_MAX_FILES){$env:BC_SENTINEL_SMART_SCAN_MAX_FILES}else{'default 1200'}))
Write-Host ('Smart scope MaxTotal: '+$(if($env:BC_SENTINEL_SMART_SCAN_MAX_TOTAL_BYTES){([math]::Round(([double]$env:BC_SENTINEL_SMART_SCAN_MAX_TOTAL_BYTES/1MB),0).ToString()+' MB')}else{'default 384 MB'}))
Write-Host ('Smart scope MaxFile: '+$(if($env:BC_SENTINEL_SMART_SCAN_MAX_FILE_BYTES){([math]::Round(([double]$env:BC_SENTINEL_SMART_SCAN_MAX_FILE_BYTES/1MB),0).ToString()+' MB')}else{'default 128 MB'}))
Write-Host ('Smart scope RecentDays: '+$(if($env:BC_SENTINEL_SMART_SCAN_RECENT_DAYS){$env:BC_SENTINEL_SMART_SCAN_RECENT_DAYS}else{'default 180'}))
Write-Host ''

# Environment variables created by a powershell.exe -File child cannot flow back
# to the caller. Keep preflight and the explicitly requested scan in this same
# process. Preflight is passive and never starts a scan.
Write-Host 'B6-3.4 passive runtime + scope preflight...' -ForegroundColor Cyan
& $Py -m tools.v011_beta6_b63_live_runtime_probe
$PreflightExit=$LASTEXITCODE
if($PreflightExit -ne 0){
    throw "B6-3.4 preflight non accettato (exit=$PreflightExit). Nessuna scansione e stata avviata."
}

Write-Host 'B6-3.4 preflight PASS: provider accepted.' -ForegroundColor Green

if(-not $Execute){
    Write-Host 'Nessuna scansione avviata. Per eseguire esplicitamente la Smart Scan, rilancia questo helper con -Execute.' -ForegroundColor Yellow
    return
}

Write-Host 'B6-3.4 explicit risk-prioritized Smart Scan requested by user...' -ForegroundColor Yellow
if($Output){
    & $Py -m tools.v011_beta6_b63_live_runtime_probe --execute --output $Output
}else{
    & $Py -m tools.v011_beta6_b63_live_runtime_probe --execute
}
$ExecuteExit=$LASTEXITCODE
if($ExecuteExit -ne 0){
    throw "B6-3.4 live Smart Scan non completata con stato accettabile (exit=$ExecuteExit)."
}
Write-Host 'B6-3.4 live Smart Scan completed.' -ForegroundColor Green
if($Output){Write-Host ('Acceptance evidence: '+$Output)}
