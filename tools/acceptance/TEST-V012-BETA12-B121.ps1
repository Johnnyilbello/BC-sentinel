param([switch]$ConfirmProcessFileCorrelation)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

if (-not $ConfirmProcessFileCorrelation) {
    throw 'Explicit Beta12 B12-1 process/file-correlation confirmation required.'
}

$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve B12-1 acceptance commit.' }
Write-Host ('B12-1 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B12-1 acceptance commit.' }

$frozen = '0015feb80c550b9c67707f24f4042a45412e7af3'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted Beta12 B12-0 predecessor missing.' }

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate frozen B12-0 paths.' }
$changes = @(& git diff --name-only $frozen HEAD)
if ($LASTEXITCODE -ne 0) { throw 'Cannot compare frozen B12-0 sources.' }

$allowed = @(
    '.github/workflows/b121-process-file-correlation.yml',
    'ROADMAP.md',
    'sentinel/beta12_process_file_correlation.py',
    'tests/test_v012_beta12_b121_process_file_correlation.py',
    'tools/acceptance/TEST-V012-BETA12-B121.ps1'
)

if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B12-1 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) {
        throw ('Unexpected B12-1 changed path: ' + $path)
    }
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B12-0 path changed: ' + $path)
    }
}

$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository roadmap hygiene failed.'
}
Write-Host 'Accepted B12-0 source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta12_process_file_correlation.py tests/test_v012_beta12_b121_process_file_correlation.py
if ($LASTEXITCODE -ne 0) { throw 'B12-1 compile failed.' }

$patterns = @(
    'tests/test_v011_beta5_*.py',
    'tests/test_v011_beta6_*.py',
    'tests/test_v011_beta7_*.py',
    'tests/test_v011_beta8_*.py',
    'tests/test_v011_beta9_*.py',
    'tests/test_v011_beta10_*.py',
    'tests/test_v011_beta11_*.py',
    'tests/test_v012_beta12_*.py'
)
$tests = @(
    $patterns |
        ForEach-Object { Get-ChildItem $_ } |
        Sort-Object FullName |
        ForEach-Object { $_.FullName }
)

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b121-' + [guid]::NewGuid().ToString('N'))
& $py -m pytest -q --basetemp $testBase @tests
if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta12 B12-1 regression failed.' }

& $py -m sentinel.beta12_process_file_correlation
if ($LASTEXITCODE -ne 0) { throw 'B12-1 process/file correlation self-check failed.' }

& $py -c "from sentinel.beta12_process_file_correlation import self_check,sample_observation,summarize; s=self_check(); assert s['passed']; assert s['source_coverage']=={'PARTIAL':4,'GAP':0,'VERIFIED':2}; assert s['process_file_binding']; assert s['optional_ancestry_binding']; assert s['unknown_ancestry_preserved']; assert not s['coverage_promoted']; assert not s['authority_expanded']; a=summarize(sample_observation(with_parent=True)); b=summarize(sample_observation(with_parent=False)); assert a['passed'] and b['passed']; assert a['graph_node_count']==3 and a['graph_edge_count']==2; assert b['graph_node_count']==2 and b['graph_edge_count']==1; assert not a['raw_path_collected']; assert not a['command_line_collected']; assert not a['username_collected']"
if ($LASTEXITCODE -ne 0) { throw 'B12-1 process/file correlation assertions failed.' }

Write-Host 'BC SENTINEL v0.12.0-beta.12 B12-1 PROCESS/FILE CORRELATION 2.0 - PASS'
