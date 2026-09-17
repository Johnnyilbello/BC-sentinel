param([switch]$ConfirmTrustCenterAcceptance)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot
$env:PYTHONPATH = $repoRoot

if (-not $ConfirmTrustCenterAcceptance) {
    throw 'Explicit Beta10 B10-8 Trust Center Product Integration confirmation required.'
}

$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve B10-8 acceptance commit.' }
Write-Host ('B10-8 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B10-8 acceptance commit.' }

$b107Accepted = '2428817e99b9e0969fc00e4c76e383a1004ba26c'
& git merge-base --is-ancestor $b107Accepted HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted B10-7 predecessor is missing.' }

$predecessorPaths = @(& git ls-tree -r --name-only $b107Accepted)
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate accepted B10-7 predecessor paths.' }
$changes = @(& git diff --name-only $b107Accepted HEAD)
if ($LASTEXITCODE -ne 0) { throw 'Cannot compare B10-7 predecessor sources.' }

$allowedNew = @(
    'sentinel/beta10_trust_center.py',
    'sentinel/beta10_trust_center_ui.py',
    'tests/test_v011_beta10_b108_trust_center.py',
    'tools/acceptance/RUN-V011-BETA10-B108-TRUST-CENTER.py',
    'tools/acceptance/TEST-V011-BETA10-B108.ps1',
    '.github/workflows/b108-trust-center-product-integration.yml',
    'ROADMAP.md'
)

foreach ($path in $changes) {
    if ($predecessorPaths -contains $path -and $path -ne 'ROADMAP.md') {
        throw ('Accepted B10-7 predecessor path changed: ' + $path)
    }
    if ($allowedNew -notcontains $path) {
        throw ('Unexpected B10-8 path changed: ' + $path)
    }
}

$rootFiles = @(& git ls-files | Where-Object { $_ -notmatch '/' })
$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($rootFiles.Count -ne 10 -or $roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository hygiene failed.'
}
Write-Host 'Accepted B10-7 predecessor immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q `
    sentinel/beta10_trust_center.py `
    sentinel/beta10_trust_center_ui.py `
    tests/test_v011_beta10_b108_trust_center.py `
    tools/acceptance/RUN-V011-BETA10-B108-TRUST-CENTER.py
if ($LASTEXITCODE -ne 0) { throw 'B10-8 compile failed.' }

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b108-pytest-' + [guid]::NewGuid().ToString('N'))
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
    if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta10 B10-8 regression failed.' }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$evidencePath = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b108-live-evidence-' + [guid]::NewGuid().ToString('N') + '.json')
$impactPath = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b108-impact-' + [guid]::NewGuid().ToString('N') + '.json')
$trustPath = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b108-trust-' + [guid]::NewGuid().ToString('N') + '.json')
try {
    & '.\tools\acceptance\RUN-V011-BETA10-B103-POWERSHELL.ps1' `
        -ConfirmLivePowerShellControls `
        -Output $evidencePath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'B10-8 live PowerShell evidence generation failed.' }

    & $py '.\tools\acceptance\RUN-V011-BETA10-B107-IMPACT.py' `
        --evidence $evidencePath `
        --repeats 7 `
        --output $impactPath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'B10-8 predecessor operational-impact measurement failed.' }

    & $py '.\tools\acceptance\RUN-V011-BETA10-B108-TRUST-CENTER.py' `
        --impact-report $impactPath `
        --output $trustPath `
        --smoke-ui
    if ($LASTEXITCODE -ne 0) { throw 'B10-8 Trust Center integration runner failed.' }

    $report = Get-Content -LiteralPath $trustPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not [bool]$report.passed) { throw 'B10-8 Trust Center report did not pass.' }
    if ([int]$report.coverage_summary.PARTIAL -ne 4 -or [int]$report.coverage_summary.GAP -ne 0 -or [int]$report.coverage_summary.VERIFIED -ne 2) {
        throw 'B10-8 presentation changed canonical coverage.'
    }
    if ([int]$report.scenario_count -ne 6 -or [int]$report.capability_count -ne 6) {
        throw 'B10-8 Trust Center inventory is incomplete.'
    }
    if ([bool]$report.presentation_can_promote_coverage) { throw 'B10-8 presentation can promote coverage.' }
    if ([bool]$report.general_response_execution_available) { throw 'B10-8 unexpectedly enabled general response execution.' }
    if ([string]$report.reversible_response_scope -ne 'DISPOSABLE_TEMP_WORKSPACE_ONLY') { throw 'B10-8 reversible response scope changed.' }
    if ([bool]$report.new_authority_expanded) { throw 'B10-8 unexpectedly expanded authority.' }
    if ([bool]$report.broad_protection_claimed) { throw 'B10-8 made a broad protection claim.' }
    if (-not [bool]$report.ui_smoke.passed) { throw 'B10-8 UI smoke did not pass.' }
    foreach ($property in $report.ui_smoke.horizontal_overflow.PSObject.Properties) {
        if ([int]$property.Value -ne 0) { throw ('B10-8 horizontal overflow at width ' + $property.Name) }
    }
    Write-Host ('B10-8 UI smoke: pages=' + $report.ui_smoke.page_count + '; impact_status=' + $report.impact_status)
}
finally {
    Remove-Item -LiteralPath $evidencePath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $impactPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $trustPath -Force -ErrorAction SilentlyContinue
}

$contractCode = @'
from sentinel.beta10_trust_center import validate_b108_contract

c = validate_b108_contract()
assert c["passed"]
assert c["source_predecessor_commit"] == "2428817e99b9e0969fc00e4c76e383a1004ba26c"
assert c["source_predecessor_checkpoint"] == "checkpoint/v011-beta10-b107-pass"
assert c["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
assert c["verified_scenarios"] == ["B7-POWERSHELL-001", "B7-RANSOMWARE-001"]
assert c["scenario_count"] == 6
assert c["capability_count"] == 6
assert c["trust_center_ui_read_only"] is True
assert c["presentation_can_promote_coverage"] is False
assert c["attack_story_requires_evidence"] is True
assert c["general_response_execution_available"] is False
assert c["reversible_response_pilot_available"] is True
assert c["reversible_response_scope"] == "DISPOSABLE_TEMP_WORKSPACE_ONLY"
assert c["new_authority_expanded"] is False
assert c["broad_protection_claimed"] is False
assert c["privacy"]["credential_access"] is False
assert c["privacy"]["network_io"] is False
assert c["authority"]["automatic_quarantine"] is False
assert c["authority"]["general_home_execution"] is False
print("B10-8 contract assertions: PASS")
'@

$contractScript = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b108-contract-' + [guid]::NewGuid().ToString('N') + '.py')
try {
    Set-Content -LiteralPath $contractScript -Value $contractCode -Encoding UTF8
    & $py $contractScript
    if ($LASTEXITCODE -ne 0) { throw 'B10-8 contract assertions failed.' }
}
finally {
    Remove-Item -LiteralPath $contractScript -Force -ErrorAction SilentlyContinue
}

Write-Host 'BC SENTINEL v0.11.0-beta.10 B10-8 TRUST CENTER PRODUCT INTEGRATION - PASS'
