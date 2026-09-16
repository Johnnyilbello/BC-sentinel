param([switch]$ConfirmAttackStory)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

if (-not $ConfirmAttackStory) { throw 'Explicit Beta10 B10-2 Attack Story confirmation required.' }
$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve B10-2 acceptance commit.' }
Write-Host ('B10-2 Windows acceptance commit: ' + $commit)
& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B10-2 acceptance commit.' }

$frozen = 'd1ea57abcc69407cf0e17d5ff1e008bcf48ca9af'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted B10-1 predecessor missing.' }
$frozenPaths = @(& git ls-tree -r --name-only $frozen)
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate frozen B10-1 paths.' }
$changes = @(& git diff --name-only $frozen HEAD)
if ($LASTEXITCODE -ne 0) { throw 'Cannot compare frozen B10-1 sources.' }
foreach ($path in $changes) {
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B10-1 path changed: ' + $path)
    }
}
$rootFiles = @(& git ls-files | Where-Object { $_ -notmatch '/' })
$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($rootFiles.Count -ne 10 -or $roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository hygiene failed.'
}
Write-Host 'Frozen B10-1 paths and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) { $py = (Get-Command python -ErrorAction Stop).Source }
& $py -m compileall -q sentinel/beta10_attack_story.py tests/test_v011_beta10_b102_attack_story.py
if ($LASTEXITCODE -ne 0) { throw 'B10-2 compile failed.' }

$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b102-pytest-' + [guid]::NewGuid().ToString('N'))
$tests = @(Get-ChildItem tests/test_v011_beta5_*.py,tests/test_v011_beta6_*.py,tests/test_v011_beta7_*.py,tests/test_v011_beta8_*.py,tests/test_v011_beta9_*.py,tests/test_v011_beta10_*.py | Sort-Object FullName | ForEach-Object { $_.FullName })
& $py -m pytest -q --basetemp $testBase @tests
if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta10 B10-2 regression failed.' }

$liveBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b102-live-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $liveBase -Force | Out-Null
$evidence = Join-Path $liveBase 'b93-live-evidence.json'
try {
    & $py '.\tools\acceptance\RUN-V011-BETA9-B93-LIVE-FILES.py' --output $evidence --confirm-live-controls
    if ($LASTEXITCODE -ne 0) { throw 'B10-2 live file-control exercise failed.' }

    & $py -m sentinel.beta10_attack_story --b93-evidence $evidence
    if ($LASTEXITCODE -ne 0) { throw 'B10-2 live Attack Story generation failed.' }

    $assertCode = @'
import json, sys
from pathlib import Path
from sentinel.beta10_attack_story import story_from_b93_evidence
p = Path(sys.argv[1])
evidence = json.loads(p.read_text(encoding="utf-8-sig"))
r = story_from_b93_evidence(evidence)
assert r["passed"], r
assert r["coverage_summary"] == {"PARTIAL": 5, "GAP": 0, "VERIFIED": 1}
assert r["coverage_changed"] is False
assert r["broad_protection_claimed"] is False
assert r["source_live_control"] is True
assert r["source_detector_outcome"] == "DETECTED"
assert r["source_detector_score"] == 10
assert r["detector_to_security_graph_bound"] is True
assert r["security_graph_to_incident_bound"] is True
assert r["synthetic_fallback_used"] is False
assert not any(r["authority_boundary"].values())
assert r["privacy"]["personal_data_collected"] is False
assert r["privacy"]["file_content_collected"] is False
assert r["privacy"]["absolute_paths_exported"] is False
assert r["privacy"]["remote_access"] is False
observed = [s["stage_id"] for s in r["stages"] if s["status"] == "OBSERVED"]
unknown = [s["stage_id"] for s in r["stages"] if s["status"] == "UNKNOWN"]
assert observed == ["FILE_ACTIVITY", "DETECTION"], observed
assert unknown == ["ENTRY_POINT", "EXECUTION", "PERSISTENCE", "NETWORK_ACTIVITY", "RESPONSE"], unknown
assert len(r["claims"]) == 2
assert all(c["evidence_ids"] for c in r["claims"])
assert "UNKNOWN" in r["plain_language_summary"]
print(json.dumps({
    "attack_story_passed": True,
    "observed_stages": observed,
    "unknown_stages": unknown,
    "claim_count": len(r["claims"]),
    "source_live_control": r["source_live_control"],
    "coverage_summary": r["coverage_summary"],
    "authority_expanded": any(r["authority_boundary"].values()),
    "broad_protection_claimed": r["broad_protection_claimed"],
}, indent=2, sort_keys=True))
'@
    & $py -c $assertCode $evidence
    if ($LASTEXITCODE -ne 0) { throw 'B10-2 Attack Story acceptance assertions failed.' }
}
finally {
    if (Test-Path -LiteralPath $liveBase) { Remove-Item -LiteralPath $liveBase -Recurse -Force }
}

Write-Host 'BC SENTINEL v0.11.0-beta.10 B10-2 ATTACK STORY 2.0 - PASS'
