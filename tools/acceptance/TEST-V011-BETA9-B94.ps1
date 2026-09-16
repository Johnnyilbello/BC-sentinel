param([switch]$ConfirmBeta9FinalAcceptance)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

if (-not $ConfirmBeta9FinalAcceptance) { throw 'Explicit Beta9 final acceptance switch required.' }
$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve acceptance commit.' }
Write-Host ('B9-4 Windows final acceptance commit: ' + $commit)
& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from acceptance commit.' }

$frozen = '50bbe099ba146201864b8969c91149497df913fa'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted B9-3 predecessor missing.' }
$frozenPaths = @(& git ls-tree -r --name-only $frozen)
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate frozen B9-3 paths.' }
$changes = @(& git diff --name-only $frozen HEAD)
if ($LASTEXITCODE -ne 0) { throw 'Cannot compare frozen B9-3 sources.' }
foreach ($path in $changes) {
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B9-3 path changed: ' + $path)
    }
}
$rootFiles = @(& git ls-files | Where-Object { $_ -notmatch '/' })
$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($rootFiles.Count -ne 10 -or $roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository hygiene failed.'
}
Write-Host 'Frozen B9-3 paths and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) { $py = (Get-Command python -ErrorAction Stop).Source }
& $py -m compileall -q sentinel/beta9_final_acceptance.py tests/test_v011_beta9_b94_final_acceptance.py
if ($LASTEXITCODE -ne 0) { throw 'Compile failed.' }

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b94-' + [guid]::NewGuid().ToString('N'))
$tests = @(Get-ChildItem tests/test_v011_beta5_*.py,tests/test_v011_beta6_*.py,tests/test_v011_beta7_*.py,tests/test_v011_beta8_*.py,tests/test_v011_beta9_*.py | Sort-Object FullName | ForEach-Object { $_.FullName })
& $py -m pytest -q --basetemp $testBase @tests
if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta9 full regression failed.' }

New-Item -ItemType Directory -Path $testBase -Force | Out-Null
$inventoryFile = Join-Path $testBase 'b90-inventory.json'
$metadataFile = Join-Path $testBase 'b91-metadata.json'
$exerciseFile = Join-Path $testBase 'b92-exercise.json'
$controlsFile = Join-Path $testBase 'b93-controls.json'

$liveWatch = [Diagnostics.Stopwatch]::StartNew()

$rawInventory = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'GET-V011-BETA9-CHANNELS.ps1')
if ($LASTEXITCODE -ne 0) { throw 'B9-0 live channel inventory failed.' }
[IO.File]::WriteAllText($inventoryFile, ($rawInventory -join [Environment]::NewLine), [Text.UTF8Encoding]::new($false))

$rawMetadata = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'GET-V011-BETA9-METADATA.ps1') -ConfirmBoundedMetadataRead -MaxEvents 4 -TimeoutSeconds 5
if ($LASTEXITCODE -ne 0) { throw 'B9-1 bounded live metadata read failed.' }
[IO.File]::WriteAllText($metadataFile, ($rawMetadata -join [Environment]::NewLine), [Text.UTF8Encoding]::new($false))

$rawExercise = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'EXERCISE-V011-BETA9-B92.ps1') -ConfirmHarmlessEventExercise -QueryTimeoutSeconds 8
if ($LASTEXITCODE -ne 0) { throw 'B9-2 harmless live event exercise failed.' }
[IO.File]::WriteAllText($exerciseFile, ($rawExercise -join [Environment]::NewLine), [Text.UTF8Encoding]::new($false))

& $py (Join-Path $PSScriptRoot 'RUN-V011-BETA9-B93-LIVE-FILES.py') --output $controlsFile --confirm-live-controls
if ($LASTEXITCODE -ne 0) { throw 'B9-3 live false-positive controls failed.' }

$liveWatch.Stop()
$liveSeconds = [Math]::Round($liveWatch.Elapsed.TotalSeconds, 6)
Write-Host ('B9-4 independently measured live pipeline seconds: ' + $liveSeconds)

& $py -m sentinel.beta9_final_acceptance --inventory $inventoryFile --metadata $metadataFile --exercise $exerciseFile --controls $controlsFile --live-elapsed-seconds $liveSeconds
if ($LASTEXITCODE -ne 0) { throw 'Beta9 final composition contract failed.' }

& $py -c "import json,sys; from sentinel.beta9_final_acceptance import summarize; load=lambda p: json.load(open(p,encoding='utf-8-sig')); r=summarize(load(sys.argv[1]),load(sys.argv[2]),load(sys.argv[3]),load(sys.argv[4]),float(sys.argv[5])); assert r['passed']; assert r['deterministic_core']; assert r['coverage_summary']=={'PARTIAL':5,'GAP':0,'VERIFIED':1}; assert r['verified_scenario_id']=='B7-RANSOMWARE-001'; assert not r['broad_protection_claimed']; b=r['boundaries']; assert b['local_only'] and b['explicit_opt_in_required']; assert all(v is False for k,v in b.items() if k not in {'local_only','explicit_opt_in_required'})" $inventoryFile $metadataFile $exerciseFile $controlsFile $liveSeconds
if ($LASTEXITCODE -ne 0) { throw 'Beta9 final freeze assertions failed.' }

Write-Host 'BC SENTINEL v0.11.0-beta.9 B9-4 WINDOWS FINAL ACCEPTANCE & FREEZE - PASS'
