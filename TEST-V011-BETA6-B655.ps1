param(
    [switch]$ConfirmFixtureExecution,
    [string]$Output = ".\acceptance-v011-beta6-b655-fixture.json"
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
$Py = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'

Write-Host ''
Write-Host 'BC Sentinel B6-5.5 - harmless fixture execution + rollback acceptance' -ForegroundColor Cyan
Write-Host '---------------------------------------------------------------------'

if(-not (Test-Path -LiteralPath $Py -PathType Leaf)){
    throw ".venv Python non trovato: $Py"
}

if(Test-Path -LiteralPath (Join-Path $PSScriptRoot '.git')){
    $CurrentBranch = (& git branch --show-current 2>$null | Select-Object -First 1).Trim()
    $CurrentCommit = (& git rev-parse --short HEAD 2>$null | Select-Object -First 1).Trim()
    Write-Host ('Branch: ' + $CurrentBranch)
    Write-Host ('Commit: ' + $CurrentCommit)
    if($CurrentBranch -ne $ExpectedBranch){
        throw "Branch errato: '$CurrentBranch'. Usa '$ExpectedBranch'."
    }
}

if(-not $ConfirmFixtureExecution){
    throw 'Conferma esplicita richiesta. Riesegui aggiungendo -ConfirmFixtureExecution. Il test agisce solo su un file innocuo creato apposta sotto la cartella TEMP e lo ripristina subito.'
}

Write-Host ''
Write-Host '[1/2] Self-check B6-5.5 e predecessori...' -ForegroundColor Cyan
$SelfCheck = Join-Path $env:TEMP ('bc-sentinel-b655-self-check-' + [guid]::NewGuid().ToString('N') + '.json')
try {
    & $Py -m sentinel.home_guided_resolution_window --self-check *> $SelfCheck
    if($LASTEXITCODE -ne 0){
        Get-Content -LiteralPath $SelfCheck -ErrorAction SilentlyContinue | Write-Host
        throw "Self-check B6-5.5 fallito (exit=$LASTEXITCODE)."
    }
    Write-Host 'Self-check: PASS' -ForegroundColor Green
}
finally {
    Remove-Item -LiteralPath $SelfCheck -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host '[2/2] Esecuzione controllata fixture -> quarantena -> verifica -> rollback -> verifica...' -ForegroundColor Cyan
Write-Host 'Scope: SOLO file innocuo creato dal test sotto %TEMP%\BCSentinel-B655-*'
Write-Host 'Nessun file utente o di sistema rientra nello scope B6-5.5.'

& $Py -m tools.v011_beta6_b655_live_acceptance --confirm-fixture-execution --output $Output
$Exit = $LASTEXITCODE
if($Exit -ne 0){
    throw "B6-5.5 harmless fixture acceptance FAIL (exit=$Exit). Evidence: $Output"
}

$Evidence = Get-Content -Raw -LiteralPath $Output -Encoding UTF8 | ConvertFrom-Json
if(-not [bool]$Evidence.passed){
    throw "B6-5.5 evidence non PASS. Evidence: $Output"
}

Write-Host ''
Write-Host 'B6-5.5 harmless fixture execution + rollback acceptance PASS.' -ForegroundColor Green
Write-Host ('Rollback verificato: ' + [bool]$Evidence.restored_state_verified)
Write-Host ('Journal verificato: ' + [bool]$Evidence.journal_validation.passed)
Write-Host ('Cleanup verificato: ' + [bool]$Evidence.cleanup_verified)
Write-Host ('Live Home execution autorizzata: ' + [bool]$Evidence.live_home_execution_authorized)
Write-Host ('Acceptance evidence: ' + $Output)
