param([switch]$ConfirmReversibleResponsePilot)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot
$env:PYTHONPATH = $repoRoot

if (-not $ConfirmReversibleResponsePilot) {
    throw 'Explicit Beta10 B10-6 Reversible Response Pilot confirmation required.'
}

$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve B10-6 acceptance commit.' }
Write-Host ('B10-6 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B10-6 acceptance commit.' }

$b105Candidate = '259fdbf988e442366f0deb3a07b3de248cf309ba'
& git merge-base --is-ancestor $b105Candidate HEAD
if ($LASTEXITCODE -ne 0) { throw 'B10-5 CI-passed predecessor is missing.' }

$predecessorPaths = @(& git ls-tree -r --name-only $b105Candidate)
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate B10-5 predecessor paths.' }

$changes = @(& git diff --name-only $b105Candidate HEAD)
if ($LASTEXITCODE -ne 0) { throw 'Cannot compare B10-5 predecessor sources.' }

$allowedNew = @(
    'sentinel/beta10_reversible_response_pilot.py',
    'tests/test_v011_beta10_b106_reversible_response_pilot.py',
    'tools/acceptance/RUN-V011-BETA10-B106-REVERSIBLE.py',
    'tools/acceptance/TEST-V011-BETA10-B106.ps1',
    '.github/workflows/b106-reversible-response-pilot.yml',
    'ROADMAP.md'
)

foreach ($path in $changes) {
    if ($predecessorPaths -contains $path -and $path -ne 'ROADMAP.md') {
        throw ('B10-5 predecessor path changed: ' + $path)
    }
    if ($allowedNew -notcontains $path) {
        throw ('Unexpected B10-6 path changed: ' + $path)
    }
}

$rootFiles = @(& git ls-files | Where-Object { $_ -notmatch '/' })
$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($rootFiles.Count -ne 10 -or $roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository hygiene failed.'
}
Write-Host 'B10-5 predecessor immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q `
    sentinel/beta10_reversible_response_pilot.py `
    tests/test_v011_beta10_b106_reversible_response_pilot.py `
    tools/acceptance/RUN-V011-BETA10-B106-REVERSIBLE.py
if ($LASTEXITCODE -ne 0) { throw 'B10-6 compile failed.' }

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b106-pytest-' + [guid]::NewGuid().ToString('N'))
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
    if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta10 B10-6 regression failed.' }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$pilotWorkspace = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b106-pilot-' + [guid]::NewGuid().ToString('N'))
& $py '.\tools\acceptance\RUN-V011-BETA10-B106-REVERSIBLE.py' `
    --workspace $pilotWorkspace `
    --confirm-reversible-response-pilot
if ($LASTEXITCODE -ne 0) { throw 'B10-6 harmless reversible-response exercise failed.' }

$contractCode = @'
from sentinel.beta10_reversible_response_pilot import validate_b106_contract

c = validate_b106_contract()
assert c["passed"]
assert c["source_predecessor_commit"] == "259fdbf988e442366f0deb3a07b3de248cf309ba"
assert c["action"] == "QUARANTINE_SINGLE_FILE_REVERSIBLY"
assert c["scope"] == "DISPOSABLE_TEMP_WORKSPACE_ONLY"
assert c["explicit_operator_confirmation_required"] is True
assert c["target_identity_binding_required"] is True
assert c["journal_required"] is True
assert c["rollback_required"] is True
assert c["automatic_action"] is False
assert c["broad_home_execution"] is False
assert c["delete_authority"] is False
assert c["repair_authority"] is False
assert c["terminate_process_authority"] is False
assert c["privileged_system_mutation"] is False
assert c["rescue_write_authority"] is False
assert c["outside_disposable_workspace_execution"] is False
assert c["pilot_quarantine_authority"] is True
assert c["pilot_rollback_authority"] is True
assert c["authority_expanded"] is True
assert c["broad_remediation_claimed"] is False
assert c["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
assert c["privacy"]["local_only"] is True
assert c["privacy"]["personal_data_collected"] is False
assert c["privacy"]["file_content_exported"] is False
assert c["privacy"]["absolute_paths_exported"] is False
assert c["privacy"]["remote_access"] is False
assert c["privacy"]["network_required"] is False
assert c["privacy"]["cloud_required"] is False
print("B10-6 contract assertions: PASS")
'@

& $py -c $contractCode
if ($LASTEXITCODE -ne 0) { throw 'B10-6 contract assertions failed.' }

Write-Host 'BC SENTINEL v0.11.0-beta.10 B10-6 REVERSIBLE RESPONSE PILOT - PASS'
