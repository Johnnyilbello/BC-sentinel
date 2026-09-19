param([switch]$ConfirmBeta12FinalFreeze)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location -LiteralPath $repoRoot
$env:PYTHONPATH = $repoRoot

if (-not $ConfirmBeta12FinalFreeze) { throw 'Explicit Beta12 B12-9 Windows Active Protection Acceptance & Freeze confirmation required.' }

$commit = (& git rev-parse --verify HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') { throw 'Cannot resolve B12-9 acceptance commit.' }
Write-Host ('B12-9 Windows final acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B12-9 acceptance commit.' }

$b128Accepted = '88a7f3df43ba329cb632252ef03928b069cbcc3d'
& git merge-base --is-ancestor $b128Accepted HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted B12-8 predecessor is missing.' }

$accepted = [ordered]@{
    'checkpoint/v012-beta12-b120-pass' = '0015feb80c550b9c67707f24f4042a45412e7af3'
    'checkpoint/v012-beta12-b121-pass' = 'cd8b3e89211afe29bf32a2646f4210c73179bc1f'
    'checkpoint/v012-beta12-b122-pass' = 'dedf78ae920b87f44636a0b9bd0c9708d2ae760b'
    'checkpoint/v012-beta12-b123-pass' = '90776f9b0e3f1a9c034b79a5886b30df0db41e5c'
    'checkpoint/v012-beta12-b124-pass' = '8e1cb119ef225efbf89471bddc645dc5416c8e01'
    'checkpoint/v012-beta12-b125-pass' = '04dfef15f5cb5583fd49b878efc9de663e74cdcb'
    'checkpoint/v012-beta12-b126-pass' = 'b1f55ea32564d72cae6056308f90f8b41137dc94'
    'checkpoint/v012-beta12-b127-pass' = '8e5614c919611a7b072dd0a4f462c56751ba331d'
    'checkpoint/v012-beta12-b128-pass' = $b128Accepted
}
foreach ($name in $accepted.Keys) {
    $resolved = (& git rev-parse ('refs/remotes/origin/' + $name) 2>$null)
    if ($LASTEXITCODE -ne 0) { $resolved = (& git rev-parse $name 2>$null) }
    if ($LASTEXITCODE -ne 0 -or ([string]$resolved).Trim().ToLowerInvariant() -ne $accepted[$name]) { throw ('Accepted checkpoint mismatch: ' + $name) }
}
Write-Host 'All accepted Beta12 predecessor checkpoints: PASS'

$predecessorPaths = @(& git ls-tree -r --name-only $b128Accepted)
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate accepted B12-8 predecessor paths.' }
$changes = @(& git diff --name-only $b128Accepted HEAD)
if ($LASTEXITCODE -ne 0) { throw 'Cannot compare accepted B12-8 predecessor sources.' }

$allowed = @(
    '.github/workflows/b129-windows-active-protection-acceptance-freeze.yml',
    'ROADMAP.md',
    'sentinel/beta12_final_freeze.py',
    'tests/test_v012_beta12_b129_final_freeze.py',
    'tools/acceptance/RUN-V012-BETA12-B129-FINAL.py',
    'tools/acceptance/TEST-V012-BETA12-B129.ps1'
)
if (@($changes).Count -ne $allowed.Count) { throw ('Unexpected B12-9 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count) }
foreach ($path in $changes) {
    if ($allowed -notcontains $path) { throw ('Unexpected B12-9 changed path: ' + $path) }
    if ($path -ne 'ROADMAP.md' -and $predecessorPaths -contains $path) { throw ('Accepted B12-8 predecessor path changed: ' + $path) }
}

$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') { throw 'Repository roadmap hygiene failed.' }
Write-Host 'Accepted B12-8 source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) { $py = (Get-Command python -ErrorAction Stop).Source }

& $py -m compileall -q sentinel/beta12_final_freeze.py tests/test_v012_beta12_b129_final_freeze.py tools/acceptance/RUN-V012-BETA12-B129-FINAL.py
if ($LASTEXITCODE -ne 0) { throw 'B12-9 compile failed.' }

$patterns = @('tests/test_v011_beta5_*.py','tests/test_v011_beta6_*.py','tests/test_v011_beta7_*.py','tests/test_v011_beta8_*.py','tests/test_v011_beta9_*.py','tests/test_v011_beta10_*.py','tests/test_v011_beta11_*.py','tests/test_v012_beta12_*.py')
$tests = @($patterns | ForEach-Object { Get-ChildItem $_ } | Sort-Object FullName | ForEach-Object { $_.FullName })
$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b129-pytest-' + [guid]::NewGuid().ToString('N'))
try {
    & $py -m pytest -q --basetemp $testBase @tests
    if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta12 B12-9 full regression failed.' }
} finally {
    if (Test-Path -LiteralPath $testBase) { Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue }
}

& $py -m sentinel.beta12_final_freeze
if ($LASTEXITCODE -ne 0) { throw 'B12-9 final freeze contract self-check failed.' }

$runRoot = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b129-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $runRoot -Force | Out-Null
$impactPath = Join-Path $runRoot 'b127-impact.json'
$finalPath = Join-Path $runRoot 'b129-final.json'

try {
    & $py -c "import json,sys; from sentinel.beta12_low_noise_performance import measure; r=measure(repeats=20); json.dump(r,open(sys.argv[1],'w',encoding='utf-8'),indent=2,sort_keys=True); print(json.dumps({'b127_replay_passed':r['passed'],'coverage_summary':r['coverage_summary'],'operational_metrics':r['operational_metrics'],'false_positive_gate_passed':r['false_positive_gate_passed'],'outcome_stability_gate_passed':r['outcome_stability_gate_passed'],'performance_gate_passed':r['performance_gate_passed']},indent=2,sort_keys=True)); raise SystemExit(0 if r['passed'] else 1)" $impactPath
    if ($LASTEXITCODE -ne 0) { throw 'B12-9 fresh B12-7 low-noise measurement failed.' }

    & $py '.\tools\acceptance\RUN-V012-BETA12-B129-FINAL.py' --impact-report $impactPath --output $finalPath
    if ($LASTEXITCODE -ne 0) { throw 'B12-9 final product/UI composition failed.' }

    $payload = Get-Content -LiteralPath $finalPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $report = $payload.final_report
    $smoke = $payload.ui_smoke

    if (-not [bool]$report.passed -or -not [bool]$report.freeze_eligible) { throw 'B12-9 final report is not freeze-eligible.' }
    if ([int]$report.accepted_checkpoint_count -ne 9) { throw 'B12-9 accepted checkpoint inventory changed.' }
    if ([int]$report.coverage_summary.PARTIAL -ne 4 -or [int]$report.coverage_summary.GAP -ne 0 -or [int]$report.coverage_summary.VERIFIED -ne 7) { throw 'B12-9 canonical coverage changed.' }
    if (@($report.verified_scenarios).Count -ne 7) { throw 'B12-9 verified scenario inventory changed.' }
    if ([bool]$report.new_verified_scenario_earned) { throw 'B12-9 unexpectedly promoted coverage.' }
    if ([string]$report.product_evidence_digest -ne '91d812eb9bd41cd00402c39f03c61e61a11081ba46e21d993bff258b92f60fa0') { throw 'B12-9 B12-8 product evidence digest changed.' }
    if ([string]$report.freeze_evidence_digest -notmatch '^[0-9a-f]{64}$') { throw 'B12-9 freeze evidence digest is invalid.' }
    if ([int]$report.scenario_count -ne 11 -or [int]$report.capability_count -ne 7 -or [int]$report.trust_center_page_count -ne 7) { throw 'B12-9 product inventory changed.' }
    if (-not [bool]$report.trust_center_read_only -or -not [bool]$report.trust_center_no_horizontal_overflow) { throw 'B12-9 Trust Center safety/responsive gate failed.' }
    if ([int]$smoke.action_button_count -ne 0) { throw 'B12-9 Trust Center exposed action buttons.' }
    if ([bool]$report.installer_execution_performed -or [bool]$report.artifact_signing_performed -or [bool]$report.release_publication_performed) { throw 'B12-9 crossed the post-Beta12 installer/signing/publication boundary.' }
    if ([bool]$report.coverage_promoted -or [bool]$report.authority_expanded -or [bool]$report.network_required -or [bool]$report.cloud_required) { throw 'B12-9 authority/coverage/network/cloud boundary changed.' }

    Write-Host ('B12-9 final coverage: PARTIAL=' + $report.coverage_summary.PARTIAL + ' / GAP=' + $report.coverage_summary.GAP + ' / VERIFIED=' + $report.coverage_summary.VERIFIED)
    Write-Host ('B12-9 operational metrics: p95_wall_ms=' + $report.operational_metrics.p95_wall_ms + '; p95_cpu_ms=' + $report.operational_metrics.p95_cpu_ms + '; max_rss_delta_mib=' + $report.operational_metrics.max_rss_delta_mib + '; false_positives=' + $report.operational_metrics.max_false_positive_detections + '; outcome_drift=' + $report.operational_metrics.max_outcome_drift + '; user_interruptions=' + $report.operational_metrics.max_user_interruptions)
    Write-Host ('B12-9 product evidence digest: ' + $report.product_evidence_digest)
    Write-Host ('B12-9 freeze evidence digest: ' + $report.freeze_evidence_digest)
} finally {
    if (Test-Path -LiteralPath $runRoot) { Remove-Item -LiteralPath $runRoot -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host 'BC SENTINEL v0.12.0-beta.12 B12-9 WINDOWS ACTIVE PROTECTION ACCEPTANCE & FREEZE - PASS'