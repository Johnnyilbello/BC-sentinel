param([switch]$ConfirmLocalReputationIntelligence)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot
$env:PYTHONPATH = $repoRoot

if (-not $ConfirmLocalReputationIntelligence) {
    throw 'Explicit Beta12 B12-6 local reputation intelligence confirmation required.'
}

$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve B12-6 acceptance commit.' }
Write-Host ('B12-6 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B12-6 acceptance commit.' }

$frozen = '04dfef15f5cb5583fd49b878efc9de663e74cdcb'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted Beta12 B12-5 predecessor missing.' }

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate frozen B12-5 paths.' }
$changes = @(& git diff --name-only $frozen HEAD)
if ($LASTEXITCODE -ne 0) { throw 'Cannot compare frozen B12-5 sources.' }

$allowed = @(
    '.github/workflows/b126-local-reputation-hash-intelligence.yml',
    'ROADMAP.md',
    'sentinel/beta12_local_reputation.py',
    'tests/test_v012_beta12_b126_local_reputation.py',
    'tools/acceptance/RUN-V012-BETA12-B126-LOCAL-REPUTATION.ps1',
    'tools/acceptance/TEST-V012-BETA12-B126.ps1'
)

if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B12-6 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) {
        throw ('Unexpected B12-6 changed path: ' + $path)
    }
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B12-5 path changed: ' + $path)
    }
}

$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository roadmap hygiene failed.'
}
Write-Host 'Accepted B12-5 source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta12_local_reputation.py tests/test_v012_beta12_b126_local_reputation.py
if ($LASTEXITCODE -ne 0) { throw 'B12-6 compile failed.' }

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

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b126-' + [guid]::NewGuid().ToString('N'))
& $py -m pytest -q --basetemp $testBase @tests
if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta12 B12-6 regression failed.' }

& $py -m sentinel.beta12_local_reputation --self-check
if ($LASTEXITCODE -ne 0) { throw 'B12-6 self-check failed.' }

$liveBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b126-live-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $liveBase -Force | Out-Null
$evidence = Join-Path $liveBase 'local-reputation.json'

try {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\tools\acceptance\RUN-V012-BETA12-B126-LOCAL-REPUTATION.ps1' -ConfirmLocalReputationControls -Output $evidence
    if ($LASTEXITCODE -ne 0) { throw 'B12-6 harmless live local-reputation controls failed.' }

    & $py -m sentinel.beta12_local_reputation --evidence $evidence
    if ($LASTEXITCODE -ne 0) { throw 'B12-6 local reputation verification failed.' }

    & $py -c "import json,sys; from sentinel.beta12_local_reputation import summarize; d=json.load(open(sys.argv[1],encoding='utf-8-sig')); r=summarize(d); assert r['passed']; assert r['coverage_summary']=={'PARTIAL':4,'GAP':0,'VERIFIED':7}; o={k:v['outcome'] for k,v in r['control_results'].items()}; assert o=={'known-good-signed-allowlisted':'TRUSTED_LOCAL','signed-unknown':'UNKNOWN_SIGNED','unsigned-unknown':'UNKNOWN_UNSIGNED'}; assert r['local_reputation_to_graph_bound']; assert r['security_graph_to_incident_bound']; assert r['new_verified_scenario_earned']; assert not r['maliciousness_verdict_claimed']; assert not r['trust_allowlist_mutated']; assert not r['authority_expanded']; assert not r['network_required']; assert not r['cloud_required']; print(json.dumps({'b12_6_passed':True,'coverage_summary':r['coverage_summary'],'verified_scenarios':r['verified_scenarios'],'control_outcomes':o,'graph_digest':r['graph_digest'],'correlation_digest':r['correlation_digest'],'trust_allowlist_mutated':r['trust_allowlist_mutated']},indent=2,sort_keys=True))" $evidence
    if ($LASTEXITCODE -ne 0) { throw 'B12-6 final acceptance assertions failed.' }
}
finally {
    if (Test-Path -LiteralPath $liveBase) {
        Remove-Item -LiteralPath $liveBase -Recurse -Force
    }
}

Write-Host 'BC SENTINEL v0.12.0-beta.12 B12-6 LOCAL REPUTATION & HASH INTELLIGENCE - PASS'
