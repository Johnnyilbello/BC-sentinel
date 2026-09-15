param(
    [switch]$OpenUI,
    [string]$Python = "",
    [string]$TestRoot = $env:TEMP,
    [string]$Output = ".\acceptance-v011-beta6-b66.xml"
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
$env:PYTHONUTF8 = "1"
$UiPy = $Python
if (-not $UiPy) {
    $UiPy = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $UiPy)) { $UiPy = "python" }
}

$Base = "72c18bbdf1c50c633343750ead0f2467d8705e12"
git merge-base --is-ancestor $Base HEAD
if ($LASTEXITCODE -ne 0) { throw "Il branch deve discendere dal checkpoint B6-5.9 accettato." }
if ((git branch --show-current) -like "checkpoint/*") { throw "L'acceptance non può essere eseguita su un checkpoint." }

$ResolvedTestRoot = [System.IO.Path]::GetFullPath($TestRoot)
$RepoRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
if ($ResolvedTestRoot.StartsWith($RepoRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "TestRoot deve essere esterno al repository: le fixture B6-5 proteggono la root del progetto."
}
New-Item -ItemType Directory -Force -Path $ResolvedTestRoot | Out-Null
$TestBase = Join-Path $ResolvedTestRoot ("BCSentinel-B66-" + [guid]::NewGuid().ToString("N"))

$PreviousQt = $env:QT_QPA_PLATFORM
$PreviousTemp = $env:TEMP
$PreviousTmp = $env:TMP
$env:QT_QPA_PLATFORM = "offscreen"
$env:TEMP = $ResolvedTestRoot
$env:TMP = $ResolvedTestRoot

$Tests = @(
    Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot "tests") -Filter "test_v011_beta5_*.py"
) + @(
    Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot "tests") -Filter "test_v011_beta6_*.py"
) + @(
    Get-Item -LiteralPath (Join-Path $PSScriptRoot "tests\test_post_b659_ui_polish.py")
)

try {
    & $UiPy -m pytest -q @($Tests.FullName) --basetemp $TestBase --junitxml $Output
    if ($LASTEXITCODE -ne 0) { throw "La regressione Beta5/Beta6 o il gate B6-6 è fallito." }
    & $UiPy -m sentinel.rescue_technician_ui --self-check
    if ($LASTEXITCODE -ne 0) { throw "Il self-check B6-6 è fallito." }
    & $UiPy -m sentinel.rescue_technician_ui --offscreen-smoke
    if ($LASTEXITCODE -ne 0) { throw "Lo smoke Qt offscreen B6-6 è fallito." }
}
finally {
    $env:QT_QPA_PLATFORM = $PreviousQt
    $env:TEMP = $PreviousTemp
    $env:TMP = $PreviousTmp
}

Write-Host "B6-6 accessibility / low-spec / responsive gate: PASS" -ForegroundColor Green
if ($OpenUI) {
    & $UiPy -m sentinel.rescue_technician_ui
    if ($LASTEXITCODE -ne 0) { throw "La UI Technician B6-6 si è chiusa con errore." }
}
