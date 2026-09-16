param([switch]$ConfirmTelemetryFoundationAcceptance)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot
if (-not $ConfirmTelemetryFoundationAcceptance) { throw 'Explicit acceptance switch required.' }
$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve acceptance commit.' }
Write-Host ('B9-0 Windows acceptance commit: ' + $commit)
& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from acceptance commit.' }
$frozen = '3c32157dd0c6bb852438319766a9345b0b9f5f1e'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted Beta8 predecessor missing.' }
$frozenPaths = @(& git ls-tree -r --name-only $frozen)
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate frozen paths.' }
$changes = @(& git diff --name-only $frozen HEAD)
if ($LASTEXITCODE -ne 0) { throw 'Cannot compare frozen sources.' }
foreach ($path in $changes) {
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) { throw ('Frozen Beta8 path changed: ' + $path) }
}
$rootFiles = @(& git ls-files | Where-Object { $_ -notmatch '/' })
$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($rootFiles.Count -ne 10 -or $roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') { throw 'Repository hygiene failed.' }
Write-Host 'All frozen Beta8 paths and repository hygiene: PASS'
$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) { $py = (Get-Command python -ErrorAction Stop).Source }
& $py -m compileall -q sentinel/beta9_telemetry_foundation.py tests/test_v011_beta9_b90_telemetry_foundation.py
if ($LASTEXITCODE -ne 0) { throw 'Compile failed.' }
$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b90-' + [guid]::NewGuid().ToString('N'))
$tests = @(Get-ChildItem tests/test_v011_beta5_*.py,tests/test_v011_beta6_*.py,tests/test_v011_beta7_*.py,tests/test_v011_beta8_*.py,tests/test_v011_beta9_*.py | Sort-Object FullName | ForEach-Object { $_.FullName })
& $py -m pytest -q --basetemp $testBase @tests
if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta9 regression failed.' }
# The file contains only the allowlisted inventory and remains local in test temp.
$inventory = Join-Path $testBase 'windows-channel-inventory.json'
$raw = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'GET-V011-BETA9-CHANNELS.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Live Windows inventory failed.' }
[IO.File]::WriteAllText($inventory, ($raw -join [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
& $py -m sentinel.beta9_telemetry_foundation --inventory $inventory
if ($LASTEXITCODE -ne 0) { throw 'Live inventory contract failed.' }
& $py -c "import json,sys; from sentinel.beta9_telemetry_foundation import summarize; r=summarize(json.load(open(sys.argv[1],encoding='utf-8'))); assert r['passed']; assert 'System' in r['available_channels'], 'System configuration unavailable; live foundation acceptance blocked'" $inventory
if ($LASTEXITCODE -ne 0) { throw 'Live baseline availability failed.' }
Write-Host 'BC SENTINEL v0.11.0-beta.9 B9-0 TELEMETRY FOUNDATION ACCEPTANCE - PASS'
