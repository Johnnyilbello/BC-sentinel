param([switch]$ConfirmBeta10FinalAcceptance)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot
$env:PYTHONPATH = $repoRoot

if (-not $ConfirmBeta10FinalAcceptance) {
    throw 'Explicit Beta10 B10-9 Windows Competitive Acceptance & Freeze confirmation required.'
}

$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve B10-9 acceptance commit.' }
Write-Host ('B10-9 Windows final acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B10-9 acceptance commit.' }

$b108Accepted = 'aa0c2b4e4b79381f9a20a5d69e99e972dee46971'
& git merge-base --is-ancestor $b108Accepted HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted B10-8 predecessor is missing.' }

$checkpointSha = (& git rev-parse 'refs/remotes/origin/checkpoint/v011-beta10-b108-pass' 2>$null)
if ($LASTEXITCODE -ne 0) {
    $checkpointSha = (& git rev-parse 'checkpoint/v011-beta10-b108-pass' 2>$null)
}
if ($LASTEXITCODE -ne 0 -or [string]$checkpointSha -ne $b108Accepted) {
    throw 'B10-8 immutable checkpoint is missing or points to the wrong commit.'
}

$predecessorPaths = @(& git ls-tree -r --name-only $b108Accepted)
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate accepted B10-8 predecessor paths.' }
$changes = @(& git diff --name-only $b108Accepted HEAD)
if ($LASTEXITCODE -ne 0) { throw 'Cannot compare accepted B10-8 predecessor sources.' }

$allowedNew = @(
    'sentinel/beta10_final_acceptance.py',
    'tests/test_v011_beta10_b109_final_acceptance.py',
    'tools/acceptance/RUN-V011-BETA10-B109-FINAL.py',
    'tools/acceptance/TEST-V011-BETA10-B109.ps1',
    '.github/workflows/b109-windows-competitive-acceptance-freeze.yml',
    'ROADMAP.md'
)

foreach ($path in $changes) {
    if ($predecessorPaths -contains $path -and $path -ne 'ROADMAP.md') {
        throw ('Accepted B10-8 predecessor path changed: ' + $path)
    }
    if ($allowedNew -notcontains $path) {
        throw ('Unexpected B10-9 path changed: ' + $path)
    }
}

$rootFiles = @(& git ls-files | Where-Object { $_ -notmatch '/' })
$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($rootFiles.Count -ne 10 -or $roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository hygiene failed.'
}
Write-Host 'Accepted B10-8 predecessor immutability, checkpoint identity and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q `
    sentinel/beta10_final_acceptance.py `
    tests/test_v011_beta10_b109_final_acceptance.py `
    tools/acceptance/RUN-V011-BETA10-B109-FINAL.py
if ($LASTEXITCODE -ne 0) { throw 'B10-9 compile failed.' }

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b109-pytest-' + [guid]::NewGuid().ToString('N'))
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
    if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta10 B10-9 full regression failed.' }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$runRoot = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b109-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $runRoot -Force | Out-Null
$evidencePath = Join-Path $runRoot 'powershell-live-evidence.json'
$impactPath = Join-Path $runRoot 'operational-impact.json'
$trustPath = Join-Path $runRoot 'trust-center.json'
$pilotPath = Join-Path $runRoot 'reversible-pilot.json'
$finalPath = Join-Path $runRoot 'beta10-final.json'
$pilotWorkspace = Join-Path $runRoot 'pilot-workspace'

try {
    & '.\tools\acceptance\RUN-V011-BETA10-B103-POWERSHELL.ps1' `
        -ConfirmLivePowerShellControls `
        -Output $evidencePath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'B10-9 fresh live PowerShell controls failed.' }

    & $py '.\tools\acceptance\RUN-V011-BETA10-B107-IMPACT.py' `
        --evidence $evidencePath `
        --repeats 7 `
        --output $impactPath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'B10-9 fresh operational-impact measurement failed.' }

    & $py '.\tools\acceptance\RUN-V011-BETA10-B108-TRUST-CENTER.py' `
        --impact-report $impactPath `
        --output $trustPath `
        --smoke-ui | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'B10-9 Trust Center acceptance failed.' }

    $rawPilot = @(& $py '.\tools\acceptance\RUN-V011-BETA10-B106-REVERSIBLE.py' `
        --workspace $pilotWorkspace `
        --confirm-reversible-response-pilot)
    if ($LASTEXITCODE -ne 0) { throw 'B10-9 harmless reversible-response exercise failed.' }
    [IO.File]::WriteAllText($pilotPath, ($rawPilot -join [Environment]::NewLine), [Text.UTF8Encoding]::new($false))

    & $py '.\tools\acceptance\RUN-V011-BETA10-B109-FINAL.py' `
        --trust-report $trustPath `
        --pilot-report $pilotPath `
        --output $finalPath
    if ($LASTEXITCODE -ne 0) { throw 'B10-9 final composition failed.' }

    $report = Get-Content -LiteralPath $finalPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not [bool]$report.passed -or -not [bool]$report.freeze_eligible) {
        throw 'B10-9 final report is not freeze-eligible.'
    }
    if ([int]$report.pillar_count -ne 6 -or [int]$report.milestone_count -ne 10) {
        throw 'B10-9 value contract inventory changed.'
    }
    if (-not [bool]$report.all_value_pillars_demonstrated -or -not [bool]$report.competitive_contract_passed) {
        throw 'B10-9 competitive value contract did not pass.'
    }
    if ([bool]$report.external_market_superiority_claimed) {
        throw 'B10-9 made an unsupported external market-superiority claim.'
    }
    if ([int]$report.coverage_summary.PARTIAL -ne 4 -or [int]$report.coverage_summary.GAP -ne 0 -or [int]$report.coverage_summary.VERIFIED -ne 2) {
        throw 'B10-9 canonical coverage changed.'
    }
    if ([bool]$report.general_response_execution_available) {
        throw 'B10-9 unexpectedly enabled general response execution.'
    }
    if ([string]$report.reversible_response_scope -ne 'DISPOSABLE_TEMP_WORKSPACE_ONLY') {
        throw 'B10-9 reversible response scope changed.'
    }
    if ([string]$report.reversible_response_final_state -ne 'ROLLED_BACK') {
        throw 'B10-9 reversible response did not finish rolled back.'
    }
    if (-not [bool]$report.rescue_continuity_non_executing) {
        throw 'B10-9 rescue continuity execution boundary changed.'
    }
    if ([bool]$report.new_authority_expanded_in_b109 -or [bool]$report.broad_protection_claimed -or [bool]$report.presentation_can_promote_coverage) {
        throw 'B10-9 claim or authority boundary changed.'
    }
    if ([int]$report.max_user_interruptions -ne 0) {
        throw 'B10-9 user interruption budget failed.'
    }
    if (-not [bool]$report.trust_center_no_horizontal_overflow) {
        throw 'B10-9 Trust Center horizontal overflow detected.'
    }

    Write-Host ('B10-9 operational metrics: p95_wall_ms=' + $report.operational_metrics.p95_wall_ms + '; p95_cpu_ms=' + $report.operational_metrics.p95_cpu_ms + '; max_rss_delta_mib=' + $report.operational_metrics.max_rss_delta_mib + '; user_interruptions=' + $report.max_user_interruptions)
    Write-Host ('B10-9 value pillars demonstrated: ' + $report.pillar_count + '/6; coverage=PARTIAL ' + $report.coverage_summary.PARTIAL + ' / GAP ' + $report.coverage_summary.GAP + ' / VERIFIED ' + $report.coverage_summary.VERIFIED)
}
finally {
    if (Test-Path -LiteralPath $runRoot) {
        Remove-Item -LiteralPath $runRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$contractCode = @'
from sentinel.beta10_final_acceptance import validate_b109_contract

c = validate_b109_contract()
assert c["passed"]
assert c["source_predecessor_checkpoint"] == "checkpoint/v011-beta10-b108-pass"
assert c["source_predecessor_commit"] == "aa0c2b4e4b79381f9a20a5d69e99e972dee46971"
assert c["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
assert c["verified_scenarios"] == ["B7-POWERSHELL-001", "B7-RANSOMWARE-001"]
assert c["pillar_count"] == 6
assert c["milestone_count"] == 10
assert c["competitive_contract_scope"] == "BETA10_INTERNAL_VALUE_AND_SAFETY_CONTRACT"
assert c["external_market_superiority_claimed"] is False
assert c["general_response_execution_available"] is False
assert c["reversible_response_scope"] == "DISPOSABLE_TEMP_WORKSPACE_ONLY"
assert c["rescue_continuity_non_executing"] is True
assert c["new_authority_expanded_in_b109"] is False
assert c["broad_protection_claimed"] is False
assert c["presentation_can_promote_coverage"] is False
print("B10-9 contract assertions: PASS")
'@
$contractScript = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b109-contract-' + [guid]::NewGuid().ToString('N') + '.py')
try {
    Set-Content -LiteralPath $contractScript -Value $contractCode -Encoding UTF8
    & $py $contractScript
    if ($LASTEXITCODE -ne 0) { throw 'B10-9 contract assertions failed.' }
}
finally {
    Remove-Item -LiteralPath $contractScript -Force -ErrorAction SilentlyContinue
}

Write-Host 'BC SENTINEL v0.11.0-beta.10 B10-9 WINDOWS COMPETITIVE ACCEPTANCE & FREEZE - PASS'
