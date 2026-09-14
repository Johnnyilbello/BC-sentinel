param(
    [switch]$SkipRuntime,
    [switch]$SkipSelfCheck
)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

try {
    $Utf8 = New-Object System.Text.UTF8Encoding($false)
    [Console]::OutputEncoding = $Utf8
    $OutputEncoding = $Utf8
} catch {
}

$ExpectedBranch = 'feature/v011-beta6-b65-guided-resolution'
$ExpectedScannerSha = '7874df734f6146f8848d8a55f5eb6be37bb5cbaee1638e051357f978f5275433'

Write-Host ''
Write-Host 'BC Sentinel B6-5.4 - live UI / execution-readiness test' -ForegroundColor Cyan
Write-Host '------------------------------------------------------'

$Py = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if(-not (Test-Path -LiteralPath $Py -PathType Leaf)){
    throw ".venv Python non trovato: $Py"
}

if(Test-Path -LiteralPath (Join-Path $PSScriptRoot '.git')){
    $CurrentBranch = (& git branch --show-current 2>$null | Select-Object -First 1).Trim()
    $CurrentCommit = (& git rev-parse --short HEAD 2>$null | Select-Object -First 1).Trim()
    Write-Host ('Branch: ' + $CurrentBranch)
    Write-Host ('Commit: ' + $CurrentCommit)
    if($CurrentBranch -ne $ExpectedBranch){
        Write-Warning "Sei su '$CurrentBranch'. Per il test B6-5.4 usa '$ExpectedBranch'."
    }
}

if($env:QT_QPA_PLATFORM -eq 'offscreen'){
    Remove-Item Env:QT_QPA_PLATFORM -ErrorAction SilentlyContinue
}

if(-not $SkipRuntime){
    Write-Host ''
    Write-Host '[1/3] Ricerca automatica del runtime storico verificato...' -ForegroundColor Cyan

    $ScannerPath = $null
    $Downloads = Join-Path $env:USERPROFILE 'Downloads'
    if(Test-Path -LiteralPath $Downloads -PathType Container){
        $Candidates = @(& where.exe /R "$Downloads" scanner.py 2>$null)
        $ScannerPath = ($Candidates |
            Where-Object { $_ -match '\\sentinel\\scanner\.py$' -and $_ -like '*Consolidation_FULL*' } |
            Select-Object -First 1)
    }

    if(-not $ScannerPath){
        throw 'Runtime storico Consolidation_FULL non trovato automaticamente. Nessuna UI live avviata.'
    }

    $RuntimeRoot = Split-Path -Parent (Split-Path -Parent $ScannerPath)
    $ActualScannerSha = (Get-FileHash -LiteralPath $ScannerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if($ActualScannerSha -ne $ExpectedScannerSha){
        throw ("scanner.py non corrisponde al runtime verificato. Atteso $ExpectedScannerSha, trovato $ActualScannerSha")
    }

    $env:BC_SENTINEL_FULL_RUNTIME_ROOT = $RuntimeRoot
    $env:BC_SENTINEL_FULL_RUNTIME_SCANNER_SHA256 = $ExpectedScannerSha

    $RuntimePython = Join-Path $RuntimeRoot '.venv\Scripts\python.exe'
    if(Test-Path -LiteralPath $RuntimePython -PathType Leaf){
        $env:BC_SENTINEL_FULL_RUNTIME_PYTHON = $RuntimePython
    }else{
        $env:BC_SENTINEL_FULL_RUNTIME_PYTHON = $Py
    }

    $env:BC_SENTINEL_SMART_SCAN_MAX_FILES = '250'
    $env:BC_SENTINEL_SMART_SCAN_MAX_TOTAL_BYTES = [string](128MB)
    $env:BC_SENTINEL_SMART_SCAN_MAX_FILE_BYTES = [string](64MB)
    $env:BC_SENTINEL_SMART_SCAN_RECENT_DAYS = '90'

    Write-Host ('Runtime: ' + $RuntimeRoot)
    Write-Host ('scanner.py SHA256: ' + $ActualScannerSha)
    Write-Host 'Smart Scan live test budget: 250 files / 128 MB / 64 MB per file / 90 days'

    $ProbeFile = Join-Path $env:TEMP ('bc-sentinel-b654-ui-preflight-' + [guid]::NewGuid().ToString('N') + '.json')
    try{
        & $Py -m tools.v011_beta6_b63_live_runtime_probe --output $ProbeFile | Out-Null
        if($LASTEXITCODE -ne 0){
            throw "Preflight runtime Smart Scan non accettato (exit=$LASTEXITCODE)."
        }
        if(-not (Test-Path -LiteralPath $ProbeFile -PathType Leaf)){
            throw 'Il preflight non ha prodotto evidenza JSON.'
        }
        $Probe = Get-Content -Raw -LiteralPath $ProbeFile -Encoding UTF8 | ConvertFrom-Json
        $Profile = [string]$Probe.provider_capabilities.provider_profile
        $Mode = [string]$Probe.provider_capabilities.scope_mode
        $ScanFileAvailable = [bool]$Probe.provider_capabilities.scan_file_available
        $FullFilesystem = [bool]$Probe.provider_capabilities.full_filesystem_coverage
        if(-not [bool]$Probe.accepted -or $Profile -ne 'v0.11.0-beta.6-b63.4-smart-scope' -or $Mode -ne 'risk_prioritized_v1' -or -not $ScanFileAvailable -or $FullFilesystem){
            throw ("Smart Scan live provider non accettato per la UI: accepted=" + [bool]$Probe.accepted + ", profile='" + $Profile + "', mode='" + $Mode + "', scan_file=" + $ScanFileAvailable + ", full_filesystem=" + $FullFilesystem)
        }
        Write-Host 'Runtime Smart Scan preflight: PASS' -ForegroundColor Green
    }
    finally{
        Remove-Item -LiteralPath $ProbeFile -Force -ErrorAction SilentlyContinue
    }
}else{
    Write-Host '[1/3] Runtime live saltato su richiesta.' -ForegroundColor Yellow
}

if(-not $SkipSelfCheck){
    Write-Host ''
    Write-Host '[2/3] B6-5.4 self-check prima di aprire la UI...' -ForegroundColor Cyan
    $SelfCheckFile = Join-Path $env:TEMP ('bc-sentinel-b654-self-check-' + [guid]::NewGuid().ToString('N') + '.json')
    try{
        & $Py -m sentinel.home_guided_resolution_window --self-check *> $SelfCheckFile
        if($LASTEXITCODE -ne 0){
            Get-Content -LiteralPath $SelfCheckFile -ErrorAction SilentlyContinue | Write-Host
            throw "B6-5.4 self-check fallito (exit=$LASTEXITCODE). UI non avviata."
        }
        Write-Host 'B6-5.4 self-check: PASS' -ForegroundColor Green
    }
    finally{
        Remove-Item -LiteralPath $SelfCheckFile -Force -ErrorAction SilentlyContinue
    }
}else{
    Write-Host '[2/3] Self-check saltato su richiesta.' -ForegroundColor Yellow
}

Write-Host ''
Write-Host '[3/3] Apertura della nuova UI BC Sentinel...' -ForegroundColor Cyan
Write-Host 'Controlla soprattutto Scansione, Quarantena e Cronologia: nessun testo deve essere tagliato.'
Write-Host 'La Smart Scan resta esplicita: parte solo quando premi tu il pulsante.'
Write-Host 'B6-5.4 resta fail-closed: nessuna remediation reale e disponibile.'
Write-Host ''

& $Py -m sentinel.home_guided_resolution_window
$UiExit = $LASTEXITCODE

if($UiExit -ne 0){
    throw "La UI BC Sentinel si e chiusa con exit code $UiExit."
}

Write-Host ''
Write-Host 'Sessione UI B6-5.4 terminata correttamente.' -ForegroundColor Green
