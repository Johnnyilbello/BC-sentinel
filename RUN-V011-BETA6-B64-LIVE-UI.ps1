param(
    [string]$RuntimeRoot = "",
    [string]$RuntimePython = "",
    [string[]]$ScanRoots = @(),
    [int]$MaxFiles = 250,
    [int]$MaxTotalMB = 128,
    [int]$MaxFileMB = 64,
    [int]$RecentDays = 90,
    [double]$TimeoutSeconds = 120.0,
    [double]$HoldSeconds = 2.0,
    [string]$Output = '.\acceptance-v011-beta6-b64-live-ui.json'
)

$ErrorActionPreference='Stop'
Set-Location -LiteralPath $PSScriptRoot

if($RuntimeRoot){
    $resolved=(Resolve-Path -LiteralPath $RuntimeRoot).Path
}else{
    $matches=@(
        where.exe /R "$env:USERPROFILE\Downloads" scanner.py 2>$null |
        Select-String -Pattern '\\sentinel\\scanner\.py$' |
        Where-Object { $_.Line -like '*Consolidation_FULL*' } |
        ForEach-Object { $_.Line }
    )
    if($matches.Count -ne 1){
        throw "Impossibile individuare in modo univoco il runtime FULL (trovati $($matches.Count) scanner.py). Specificare -RuntimeRoot esplicitamente."
    }
    $resolved=Split-Path -Parent (Split-Path -Parent $matches[0])
    $resolved=(Resolve-Path -LiteralPath $resolved).Path
}

$scanner=Join-Path $resolved 'sentinel\scanner.py'
if(-not(Test-Path -LiteralPath $scanner -PathType Leaf)){
    throw "sentinel\scanner.py non trovato in: $resolved"
}
$sha=(Get-FileHash -LiteralPath $scanner -Algorithm SHA256).Hash.ToLowerInvariant()

$env:BC_SENTINEL_FULL_RUNTIME_ROOT=$resolved
$env:BC_SENTINEL_FULL_RUNTIME_SCANNER_SHA256=$sha
if($RuntimePython){
    $env:BC_SENTINEL_FULL_RUNTIME_PYTHON=(Resolve-Path -LiteralPath $RuntimePython).Path
}else{
    Remove-Item Env:BC_SENTINEL_FULL_RUNTIME_PYTHON -ErrorAction SilentlyContinue
}
if($ScanRoots.Count -gt 0){
    $resolvedRoots=@()
    foreach($root in $ScanRoots){$resolvedRoots += (Resolve-Path -LiteralPath $root).Path}
    $env:BC_SENTINEL_SMART_SCAN_ROOTS=($resolvedRoots -join [IO.Path]::PathSeparator)
}else{
    Remove-Item Env:BC_SENTINEL_SMART_SCAN_ROOTS -ErrorAction SilentlyContinue
}
if($MaxFiles -gt 0){$env:BC_SENTINEL_SMART_SCAN_MAX_FILES=[string]$MaxFiles}
if($MaxTotalMB -gt 0){$env:BC_SENTINEL_SMART_SCAN_MAX_TOTAL_BYTES=[string]($MaxTotalMB * 1MB)}
if($MaxFileMB -gt 0){$env:BC_SENTINEL_SMART_SCAN_MAX_FILE_BYTES=[string]($MaxFileMB * 1MB)}
if($RecentDays -gt 0){$env:BC_SENTINEL_SMART_SCAN_RECENT_DAYS=[string]$RecentDays}

$Py=Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if(-not(Test-Path -LiteralPath $Py -PathType Leaf)){
    throw ".venv Python non trovato: $Py"
}

Write-Host 'B6-4 live Threat Cards UI acceptance configured.' -ForegroundColor Cyan
Write-Host ('Runtime root: '+$resolved)
Write-Host ('scanner.py SHA256: '+$sha)
Write-Host ('Scope: max '+$MaxFiles+' files / '+$MaxTotalMB+' MB total / '+$MaxFileMB+' MB per file / '+$RecentDays+' days')
Write-Host 'The probe starts the actual Smart Scan and verifies that live findings become truthful B6-4 cards. No remediation authority is enabled.' -ForegroundColor Yellow
Write-Host ''

& $Py -m tools.v011_beta6_b64_live_ui_probe --timeout-seconds $TimeoutSeconds --hold-seconds $HoldSeconds --output $Output
$Exit=$LASTEXITCODE
if($Exit -ne 0){
    throw "B6-4 live Threat Cards UI acceptance FAIL (exit=$Exit). Evidence: $Output"
}
Write-Host 'B6-4 live Threat Cards UI acceptance PASS.' -ForegroundColor Green
Write-Host ('Acceptance evidence: '+$Output)
