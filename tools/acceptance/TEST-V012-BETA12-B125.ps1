param([switch]$ConfirmRansomwareProtectionExpansion)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot
$env:PYTHONPATH = $repoRoot

if (-not $ConfirmRansomwareProtectionExpansion) {
    throw 'Explicit Beta12 B12-5 ransomware-expansion confirmation required.'
}

$commit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve B12-5 acceptance commit.' }
Write-Host ('B12-5 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B12-5 acceptance commit.' }

$frozen = '8e1cb119ef225efbf89471bddc645dc5416c8e01'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted Beta12 B12-4 predecessor missing.' }

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
$changes = @(& git diff --name-only $frozen HEAD)
$allowed = @(
    '.github/workflows/b125-ransomware-protection-expansion.yml',
    'ROADMAP.md',
    'sentinel/beta12_ransomware_expansion.py',
    'tests/test_v012_beta12_b125_ransomware_expansion.py',
    'tools/acceptance/TEST-V012-BETA12-B125.ps1'
)
if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B12-5 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) { throw ('Unexpected B12-5 changed path: ' + $path) }
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B12-4 path changed: ' + $path)
    }
}
Write-Host 'Accepted B12-4 source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta12_ransomware_expansion.py tests/test_v012_beta12_b125_ransomware_expansion.py
if ($LASTEXITCODE -ne 0) { throw 'B12-5 compile failed.' }

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
$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b125-' + [guid]::NewGuid().ToString('N'))
& $py -m pytest -q --basetemp $testBase @tests
if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta12 B12-5 regression failed.' }

& $py -m sentinel.beta12_ransomware_expansion --self-check
if ($LASTEXITCODE -ne 0) { throw 'B12-5 self-check failed.' }

function Get-TextDigest([string]$Value) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }
}

$liveBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b125-live-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $liveBase -Force | Out-Null
$b9Evidence = Join-Path $liveBase 'b9-live.json'
$b125Evidence = Join-Path $liveBase 'b125-live.json'
$runner = Join-Path $repoRoot 'tools\acceptance\RUN-V011-BETA9-B93-LIVE-FILES.py'
try {
    $args = @(
        ('"' + $runner + '"'),
        '--output',
        ('"' + $b9Evidence + '"'),
        '--confirm-live-controls'
    )
    $proc = Start-Process -FilePath $py -ArgumentList $args -PassThru -NoNewWindow
    $livePid = [int]$proc.Id
    $proc.WaitForExit()
    $exitCode = [int]$proc.ExitCode
    $proc.Dispose()
    if ($exitCode -ne 0) { throw 'Accepted B9 live harness failed during B12-5.' }

    $b9 = Get-Content -LiteralPath $b9Evidence -Raw | ConvertFrom-Json
    $payload = [ordered]@{
        schema = 'bc-sentinel-beta12-ransomware-process-attribution-v1'
        source = 'B9_ACCEPTED_LIVE_CONTROLS_WITH_PROCESS_ATTRIBUTION'
        b9_evidence = $b9
        process = [ordered]@{
            pid = $livePid
            image_sha256 = (Get-FileHash -LiteralPath $py -Algorithm SHA256).Hash.ToLowerInvariant()
            image_path_digest = Get-TextDigest $py
        }
        boundaries = [ordered]@{
            local_only = $true
            explicit_opt_in_required = $true
            reuses_accepted_b9_live_harness = $true
            new_file_mutation_harness_added = $false
            user_file_access = $false
            file_content_exported = $false
            absolute_paths_exported = $false
            command_line_exported = $false
            personal_data_collected = $false
            network_io = $false
            remote_access = $false
            real_malware_executed = $false
            remediation_authority = $false
            automatic_quarantine = $false
            automatic_repair = $false
            automatic_restore = $false
            terminate_process_authority = $false
            trust_allowlist_mutation = $false
            privileged_system_mutation = $false
        }
    }
    [IO.File]::WriteAllText(
        $b125Evidence,
        ($payload | ConvertTo-Json -Depth 12),
        (New-Object Text.UTF8Encoding($false))
    )

    & $py -m sentinel.beta12_ransomware_expansion --evidence $b125Evidence
    if ($LASTEXITCODE -ne 0) { throw 'B12-5 process-attributed ransomware verification failed.' }

    & $py -c "import json,sys; from sentinel.beta12_ransomware_expansion import summarize; d=json.load(open(sys.argv[1],encoding='utf-8-sig')); r=summarize(d); assert r['passed']; assert r['coverage_summary']=={'PARTIAL':4,'GAP':0,'VERIFIED':6}; assert r['b9_control_outcomes']=={'positive-ransomware-like':'DETECTED','administrative-backup-like':'REVIEW_REQUIRED','benign-save':'NO_MATCH'}; assert r['process_attribution_bound']; assert r['detector_to_security_graph_bound']; assert r['security_graph_to_incident_bound']; assert r['new_verified_scenario_earned']; assert not r['new_file_mutation_harness_added']; assert not r['broad_ransomware_protection_claimed']; assert not r['synthetic_fallback_used']; assert not r['authority_expanded']; assert not r['network_required']; assert not r['cloud_required']; print(json.dumps({'b12_5_passed':True,'coverage_summary':r['coverage_summary'],'verified_scenarios':r['verified_scenarios'],'b9_control_outcomes':r['b9_control_outcomes'],'graph_digest':r['graph_digest'],'correlation_digest':r['correlation_digest'],'process_attribution_bound':r['process_attribution_bound']},indent=2,sort_keys=True))" $b125Evidence
    if ($LASTEXITCODE -ne 0) { throw 'B12-5 final acceptance assertions failed.' }
}
finally {
    if (Test-Path -LiteralPath $liveBase) {
        Remove-Item -LiteralPath $liveBase -Recurse -Force
    }
}

Write-Host 'BC SENTINEL v0.12.0-beta.12 B12-5 RANSOMWARE PROTECTION EXPANSION - PASS'
