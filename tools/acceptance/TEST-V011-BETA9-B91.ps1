param([switch]$ConfirmBoundedMetadataAcceptance)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

if (-not $ConfirmBoundedMetadataAcceptance) { throw 'Explicit acceptance switch required.' }
$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve acceptance commit.' }
Write-Host ('B9-1 Windows acceptance commit: ' + $commit)
& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from acceptance commit.' }

$frozen = 'a5a6b08b5e9edfea4d0ce6021f8c9bdab9c5b9b0'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted B9-0 predecessor missing.' }
$frozenPaths = @(& git ls-tree -r --name-only $frozen)
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate frozen B9-0 paths.' }
$changes = @(& git diff --name-only $frozen HEAD)
if ($LASTEXITCODE -ne 0) { throw 'Cannot compare frozen B9-0 sources.' }
foreach ($path in $changes) {
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B9-0 path changed: ' + $path)
    }
}
$rootFiles = @(& git ls-files | Where-Object { $_ -notmatch '/' })
$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($rootFiles.Count -ne 10 -or $roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository hygiene failed.'
}
Write-Host 'Frozen B9-0 paths and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) { $py = (Get-Command python -ErrorAction Stop).Source }
& $py -m compileall -q sentinel/beta9_event_metadata.py tests/test_v011_beta9_b91_event_metadata.py
if ($LASTEXITCODE -ne 0) { throw 'Compile failed.' }

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b91-' + [guid]::NewGuid().ToString('N'))
$tests = @(Get-ChildItem tests/test_v011_beta5_*.py,tests/test_v011_beta6_*.py,tests/test_v011_beta7_*.py,tests/test_v011_beta8_*.py,tests/test_v011_beta9_*.py | Sort-Object FullName | ForEach-Object { $_.FullName })
& $py -m pytest -q --basetemp $testBase @tests
if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta9 regression failed.' }

$metadataFile = Join-Path $testBase 'windows-event-metadata.json'
$raw = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'GET-V011-BETA9-METADATA.ps1') -ConfirmBoundedMetadataRead -MaxEvents 4 -TimeoutSeconds 5
if ($LASTEXITCODE -ne 0) { throw 'Live bounded metadata read failed.' }
[IO.File]::WriteAllText($metadataFile, ($raw -join [Environment]::NewLine), [Text.UTF8Encoding]::new($false))

& $py -m sentinel.beta9_event_metadata --metadata $metadataFile
if ($LASTEXITCODE -ne 0) { throw 'Live metadata contract failed.' }

& $py -c "import json,sys; from sentinel.beta9_event_metadata import summarize; d=json.load(open(sys.argv[1],encoding='utf-8')); r=summarize(d); assert r['passed']; assert r['event_readability_tested'], 'No allowlisted event query completed'; assert r['readable_profile_count'] >= 1; assert not r['detector_verification_performed']; assert not r['threat_classification_performed']; assert r['coverage_summary']=={'PARTIAL':6,'GAP':0,'VERIFIED':0}; system=next(p for p in d['profiles'] if p['profile_id']=='system-kernel-general'); assert system['status'] in {'OK','EMPTY'}, 'System allowlisted metadata query did not complete'" $metadataFile
if ($LASTEXITCODE -ne 0) { throw 'Live bounded metadata baseline failed.' }

Write-Host 'BC SENTINEL v0.11.0-beta.9 B9-1 BOUNDED METADATA EVENT READER ACCEPTANCE - PASS'
