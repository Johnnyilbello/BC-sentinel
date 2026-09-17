param([switch]$ConfirmOperationalImpactAcceptance)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot
$env:PYTHONPATH = $repoRoot

if (-not $ConfirmOperationalImpactAcceptance) {
    throw 'Explicit Beta10 B10-7 Live Coverage Expansion II + Operational Impact confirmation required.'
}

$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve B10-7 acceptance commit.' }
Write-Host ('B10-7 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B10-7 acceptance commit.' }

$b106Candidate = '79293c641d1ecf5e1ce8d1fa313b9ea4b03f3868'
& git merge-base --is-ancestor $b106Candidate HEAD
if ($LASTEXITCODE -ne 0) { throw 'B10-6 CI-passed predecessor is missing.' }

$predecessorPaths = @(& git ls-tree -r --name-only $b106Candidate)
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate B10-6 predecessor paths.' }

$changes = @(& git diff --name-only $b106Candidate HEAD)
if ($LASTEXITCODE -ne 0) { throw 'Cannot compare B10-6 predecessor sources.' }

$allowedNew = @(
    'sentinel/beta10_operational_impact.py',
    'tests/test_v011_beta10_b107_operational_impact.py',
    'tools/acceptance/RUN-V011-BETA10-B107-IMPACT.py',
    'tools/acceptance/TEST-V011-BETA10-B107.ps1',
    '.github/workflows/b107-live-coverage-operational-impact.yml',
    'ROADMAP.md'
)

foreach ($path in $changes) {
    if ($predecessorPaths -contains $path -and $path -ne 'ROADMAP.md') {
        throw ('B10-6 predecessor path changed: ' + $path)
    }
    if ($allowedNew -notcontains $path) {
        throw ('Unexpected B10-7 path changed: ' + $path)
    }
}

$rootFiles = @(& git ls-files | Where-Object { $_ -notmatch '/' })
$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($rootFiles.Count -ne 10 -or $roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository hygiene failed.'
}
Write-Host 'B10-6 predecessor immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q `
    sentinel/beta10_operational_impact.py `
    tests/test_v011_beta10_b107_operational_impact.py `
    tools/acceptance/RUN-V011-BETA10-B107-IMPACT.py
if ($LASTEXITCODE -ne 0) { throw 'B10-7 compile failed.' }

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b107-pytest-' + [guid]::NewGuid().ToString('N'))
$tests = @(
    Get-ChildItem `
        tests/test_v011_beta5_*.py, `
        tests/test_v011_beta6_*.py, `
        tests/test_v011_beta7_*.py, `
        tests/test_v011_beta8_*.py, `
        tests/test_v011_beta9_*.py, `
        tests/test_v011_beta10_*.py |
    Sort-Object FullName |
    ForEach-Object { $_.FullName }
)

try {
    & $py -m pytest -q --basetemp $testBase @tests
    if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta10 B10-7 regression failed.' }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$evidencePath = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b107-live-evidence-' + [guid]::NewGuid().ToString('N') + '.json')
$reportPath = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b107-impact-' + [guid]::NewGuid().ToString('N') + '.json')
try {
    & '.\tools\acceptance\RUN-V011-BETA10-B103-POWERSHELL.ps1' `
        -ConfirmLivePowerShellControls `
        -Output $evidencePath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'B10-7 live PowerShell evidence generation failed.' }

    & $py '.\tools\acceptance\RUN-V011-BETA10-B107-IMPACT.py' `
        --evidence $evidencePath `
        --repeats 7 `
        --output $reportPath
    if ($LASTEXITCODE -ne 0) { throw 'B10-7 operational impact runner failed.' }

    $report = Get-Content -LiteralPath $reportPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not [bool]$report.passed) { throw 'B10-7 report did not pass.' }
    if ([int]$report.coverage_summary.PARTIAL -ne 4 -or [int]$report.coverage_summary.GAP -ne 0 -or [int]$report.coverage_summary.VERIFIED -ne 2) {
        throw 'B10-7 coverage changed without accepted live evidence.'
    }
    if (-not [bool]$report.coverage_expansion_attempted -or [bool]$report.coverage_promoted) {
        throw 'B10-7 coverage candidate evaluation contract failed.'
    }
    if (-not [bool]$report.false_positive_controls_passed) { throw 'B10-7 false-positive controls failed.' }
    if (-not [bool]$report.user_interruption_budget_passed) { throw 'B10-7 interruption budget failed.' }
    if (-not [bool]$report.performance_budget_passed) { throw 'B10-7 performance budget failed.' }
    if ([bool]$report.new_authority_expanded) { throw 'B10-7 unexpectedly expanded authority.' }
    Write-Host ('B10-7 operational metrics: p95_wall_ms=' + $report.operational_metrics.p95_wall_ms + '; p95_cpu_ms=' + $report.operational_metrics.p95_cpu_ms + '; max_rss_delta_mib=' + $report.operational_metrics.max_rss_delta_mib)
}
finally {
    Remove-Item -LiteralPath $evidencePath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $reportPath -Force -ErrorAction SilentlyContinue
}

$contractCode = @'
from sentinel.beta10_operational_impact import validate_b107_contract

c = validate_b107_contract()
assert c["passed"]
assert c["source_predecessor_commit"] == "79293c641d1ecf5e1ce8d1fa313b9ea4b03f3868"
assert c["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
assert c["coverage_expansion_attempted"] is True
assert c["coverage_promoted"] is False
assert c["remaining_candidate_count"] == 4
assert c["predecessor_b106_contract_preserved"] is True
assert c["b106_pilot_quarantine_authority_preserved"] is True
assert c["b106_pilot_rollback_authority_preserved"] is True
assert c["new_authority_expanded"] is False
assert c["broad_protection_claimed"] is False
assert c["privacy"]["network_io"] is False
assert c["privacy"]["credential_access"] is False
assert c["privacy"]["powershell_content_read"] is False
assert c["authority"]["network_test_authority"] is False
assert c["authority"]["protected_security_control_mutation"] is False
assert c["authority"]["broad_persistence_mutation"] is False
print("B10-7 contract assertions: PASS")
'@

$contractScript = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b107-contract-' + [guid]::NewGuid().ToString('N') + '.py')
try {
    Set-Content -LiteralPath $contractScript -Value $contractCode -Encoding UTF8
    & $py $contractScript
    if ($LASTEXITCODE -ne 0) { throw 'B10-7 contract assertions failed.' }
}
finally {
    Remove-Item -LiteralPath $contractScript -Force -ErrorAction SilentlyContinue
}

Write-Host 'BC SENTINEL v0.11.0-beta.10 B10-7 LIVE COVERAGE EXPANSION II + OPERATIONAL IMPACT - PASS'
