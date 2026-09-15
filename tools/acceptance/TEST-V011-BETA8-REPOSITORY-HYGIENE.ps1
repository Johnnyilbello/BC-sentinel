param(
    [switch]$ConfirmRepositoryHygieneAcceptance
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

if (-not $ConfirmRepositoryHygieneAcceptance) {
    throw 'Pass -ConfirmRepositoryHygieneAcceptance to run the repository hygiene acceptance gate.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

$acceptedB80 = '969781bd7633d0b2bc92840e8f12220f00de4279'

$venvPython = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (Test-Path -LiteralPath $venvPython -PathType Leaf) {
    $py = $venvPython
}
else {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCommand) { throw 'Python is unavailable.' }
    $py = $pythonCommand.Source
}

& $py -c "import pytest, PySide6" 2>$null
if ($LASTEXITCODE -ne 0) {
    throw "Selected Python is missing required test dependencies (pytest/PySide6): $py. Install requirements with: & '$py' -m pip install -r requirements.txt"
}

Write-Host ''
Write-Host '## BC Sentinel Beta8 - Repository Hygiene Acceptance'
Write-Host ('Branch: ' + (git branch --show-current))
Write-Host ('Commit: ' + (git rev-parse HEAD))
Write-Host ('Python: ' + $py)
Write-Host ('Frozen B8-0 predecessor: ' + $acceptedB80)
Write-Host ''

git cat-file -e "$acceptedB80^{commit}"
if ($LASTEXITCODE -ne 0) { throw 'Frozen B8-0 predecessor is unavailable.' }
git merge-base --is-ancestor $acceptedB80 HEAD
if ($LASTEXITCODE -ne 0) { throw 'Current branch does not descend from frozen B8-0.' }

$preserved = @('coverage','packaging','sentinel','tests')
foreach ($path in $preserved) {
    git diff --quiet $acceptedB80 HEAD -- $path
    if ($LASTEXITCODE -ne 0) { throw "Accepted B8-0 engineering path changed during hygiene: $path" }
}
Write-Host 'Accepted B8-0 engineering paths unchanged: PASS'

$allowedRoot = @(
    'README.md',
    'ROADMAP.md',
    'SECURITY.md',
    'STABLE-RELEASE.md',
    'STABLE_VERSION.json',
    'START-BC-SENTINEL-STABLE.bat',
    'START-BC-SENTINEL-STABLE.ps1',
    'pyproject.toml',
    'requirements.txt'
)
$rootFiles = @(git ls-files | Where-Object { $_ -notmatch '/' } | Sort-Object)
$unexpected = @($rootFiles | Where-Object { $_ -notin $allowedRoot })
$missing = @($allowedRoot | Where-Object { $_ -notin $rootFiles })
if ($unexpected.Count -gt 0) { throw "Unexpected root files: $($unexpected -join ', ')" }
if ($missing.Count -gt 0) { throw "Missing required root files: $($missing -join ', ')" }
Write-Host ('Compact root allowlist: PASS (' + $rootFiles.Count + ' files)')

$roadmaps = @(git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw "ROADMAP.md must be the only roadmap file. Found: $($roadmaps -join ', ')"
}
Write-Host 'Canonical single-roadmap rule: PASS'

& $py -m compileall -q sentinel
if ($LASTEXITCODE -ne 0) { throw 'Compile gate failed.' }
Write-Host 'Compile gate: PASS'

$tempProbe = Join-Path $repoRoot ('.repository-hygiene-python-temp-' + [guid]::NewGuid().ToString('N') + '.txt')
try {
    & $py -c "import pathlib,tempfile,sys; pathlib.Path(sys.argv[1]).write_text(tempfile.gettempdir(), encoding='utf-8')" $tempProbe
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $tempProbe -PathType Leaf)) {
        throw 'Python temp probe failed.'
    }
    $systemTemp = (Get-Content -Raw -LiteralPath $tempProbe -Encoding UTF8).Trim()
}
finally {
    Remove-Item -LiteralPath $tempProbe -Force -ErrorAction SilentlyContinue
}
if ([string]::IsNullOrWhiteSpace([string]$systemTemp)) { throw 'Python system temp root was empty.' }
$base = Join-Path $systemTemp 'BCSentinel-TestTemp'
New-Item -ItemType Directory -Path $base -Force | Out-Null
$pytestBase = Join-Path $base ('repository-hygiene-pytest-' + [guid]::NewGuid().ToString('N'))
Write-Host ('pytest basetemp: ' + $pytestBase)

$tests = @(
    Get-ChildItem -Path 'tests/test_v011_beta5_*.py','tests/test_v011_beta6_*.py','tests/test_v011_beta7_*.py','tests/test_v011_beta8_b80_coverage_baseline.py' |
        Sort-Object FullName |
        ForEach-Object { $_.FullName }
)
try {
    & $py -m pytest -q --basetemp "$pytestBase" @tests
    if ($LASTEXITCODE -ne 0) { throw 'Regression gate failed.' }
}
finally {
    if (Test-Path -LiteralPath $pytestBase) {
        Remove-Item -LiteralPath $pytestBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}
Write-Host 'Beta5 + Beta6 + Beta7 + B8-0 regression: PASS'

& $py -m sentinel.beta7_final_acceptance --self-check
if ($LASTEXITCODE -ne 0) { throw 'Frozen B7-7 self-check failed.' }
& $py -m sentinel.beta8_coverage_baseline --self-check
if ($LASTEXITCODE -ne 0) { throw 'Frozen B8-0 baseline self-check failed.' }

& $py -c "from sentinel.beta8_coverage_baseline import self_check; r=self_check(); assert r['passed']; assert r['summary']=={'PARTIAL':3,'GAP':3,'VERIFIED':0}; assert r['authority_granted'] is False; assert r['automatic_quarantine'] is False; assert r['automatic_repair'] is False; assert r['automatic_restore'] is False; assert r['delete_authorized'] is False; assert r['repair_authorized'] is False; assert r['terminate_process_authorized'] is False; assert r['trust_allowlist_mutation_authorized'] is False; assert r['privileged_system_mutation_authorized'] is False"
if ($LASTEXITCODE -ne 0) { throw 'B8-0 safety assertions failed.' }

Write-Host ''
Write-Host 'Repository hygiene changes structure only; accepted B8-0 detector/intelligence state is unchanged.'
Write-Host 'BC SENTINEL BETA8 REPOSITORY HYGIENE - PASS'
