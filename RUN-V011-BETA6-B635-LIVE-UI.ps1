param(
    [Parameter(Mandatory=$true)][string]$RuntimeRoot,
    [string]$RuntimePython = "",
    [string[]]$ScanRoots = @(),
    [int]$MaxFiles = 250,
    [int]$MaxTotalMB = 128,
    [int]$MaxFileMB = 64,
    [int]$RecentDays = 90,
    [ValidateSet('complete','cancel')][string]$Mode = 'complete',
    [double]$CancelAfterSeconds = 2.0,
    [double]$TimeoutSeconds = 120.0,
    [double]$HoldSeconds = 2.0,
    [string]$Output = '.\acceptance-v011-beta6-b635-live-ui.json'
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

if($MaxFiles -gt 0){$env:BC_SENTINEL_SMART_SCAN_MAX_FILES=[string]$MaxFiles}else{Remove-Item Env:BC_SENTINEL_SMART_SCAN_MAX_FILES -ErrorAction SilentlyContinue}
if($MaxTotalMB -gt 0){$env:BC_SENTINEL_SMART_SCAN_MAX_TOTAL_BYTES=[string]($MaxTotalMB * 1MB)}else{Remove-Item Env:BC_SENTINEL_SMART_SCAN_MAX_TOTAL_BYTES -ErrorAction SilentlyContinue}
if($MaxFileMB -gt 0){$env:BC_SENTINEL_SMART_SCAN_MAX_FILE_BYTES=[string]($MaxFileMB * 1MB)}else{Remove-Item Env:BC_SENTINEL_SMART_SCAN_MAX_FILE_BYTES -ErrorAction SilentlyContinue}
if($RecentDays -gt 0){$env:BC_SENTINEL_SMART_SCAN_RECENT_DAYS=[string]$RecentDays}else{Remove-Item Env:BC_SENTINEL_SMART_SCAN_RECENT_DAYS -ErrorAction SilentlyContinue}

$Py=Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if(-not(Test-Path -LiteralPath $Py -PathType Leaf)){
    throw ".venv Python non trovato: $Py"
}

Write-Host 'B6-3.5 live Home UI acceptance configured.' -ForegroundColor Cyan
Write-Host ('Runtime root: '+$resolved)
Write-Host ('scanner.py SHA256: '+$sha)
Write-Host ('Mode: '+$Mode)
Write-Host ('Scope: max '+$MaxFiles+' files / '+$MaxTotalMB+' MB total / '+$MaxFileMB+' MB per file / '+$RecentDays+' days')
Write-Host 'The probe starts Smart Scan through the actual Home button. No remediation authority is enabled.' -ForegroundColor Yellow
if($Mode -eq 'cancel'){
    Write-Host ('The actual Home Cancel button will be clicked after '+$CancelAfterSeconds+' s of RUNNING.') -ForegroundColor Yellow
}
Write-Host ''

$ProbeArgs=@(
    '-m','tools.v011_beta6_b63_live_ui_probe',
    '--mode',$Mode,
    '--timeout-seconds',[string]$TimeoutSeconds,
    '--hold-seconds',[string]$HoldSeconds,
    '--output',$Output
)
if($Mode -eq 'cancel'){
    $ProbeArgs += @('--cancel-after-seconds',[string]$CancelAfterSeconds)
}

& $Py @ProbeArgs
$Exit=$LASTEXITCODE
if($Exit -ne 0){
    throw "B6-3.5 live Home UI acceptance FAIL (exit=$Exit). Evidence: $Output"
}
Write-Host 'B6-3.5 live Home UI acceptance PASS.' -ForegroundColor Green
Write-Host ('Acceptance evidence: '+$Output)
