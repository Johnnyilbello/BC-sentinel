param(
    [switch]$ConfirmRepositoryHygieneAcceptance
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $ConfirmRepositoryHygieneAcceptance) {
    throw 'Pass -ConfirmRepositoryHygieneAcceptance to run the repository hygiene acceptance gate.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

$acceptedB80 = '969781bd7633d0b2bc92840e8f12220f00de4279'

Write-Host ''
Write-Host '## BC Sentinel Beta8 - Repository Hygiene Acceptance'
Write-Host ('Branch: ' + (git branch --show-current))
Write-Host ('Commit: ' + (git rev-parse HEAD))
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

python -m compileall -q sentinel
if ($LASTEXITCODE -ne 0) { throw 'Compile gate failed.' }
Write-Host 'Compile gate: PASS'

$tests = @(
    Get-ChildItem -Path 'tests/test_v011_beta5_*.py','tests/test_v011_beta6_*.py','tests/test_v011_beta7_*.py','tests/test_v011_beta8_b80_coverage_baseline.py' |
        Sort-Object FullName |
        ForEach-Object { $_.FullName }
)
python -m pytest -q @tests
if ($LASTEXITCODE -ne 0) { throw 'Regression gate failed.' }
Write-Host 'Beta5 + Beta6 + Beta7 + B8-0 regression: PASS'

python -m sentinel.beta7_final_acceptance --self-check
if ($LASTEXITCODE -ne 0) { throw 'Frozen B7-7 self-check failed.' }
python -m sentinel.beta8_coverage_baseline --self-check
if ($LASTEXITCODE -ne 0) { throw 'Frozen B8-0 baseline self-check failed.' }

python -c "from sentinel.beta8_coverage_baseline import self_check; r=self_check(); assert r['passed']; assert r['summary']=={'PARTIAL':3,'GAP':3,'VERIFIED':0}; assert r['authority_granted'] is False; assert r['automatic_quarantine'] is False; assert r['automatic_repair'] is False; assert r['automatic_restore'] is False; assert r['delete_authorized'] is False; assert r['repair_authorized'] is False; assert r['terminate_process_authorized'] is False; assert r['trust_allowlist_mutation_authorized'] is False; assert r['privileged_system_mutation_authorized'] is False"
if ($LASTEXITCODE -ne 0) { throw 'B8-0 safety assertions failed.' }

Write-Host ''
Write-Host 'Repository hygiene changes structure only; accepted B8-0 detector/intelligence state is unchanged.'
Write-Host 'BC SENTINEL BETA8 REPOSITORY HYGIENE - PASS'
