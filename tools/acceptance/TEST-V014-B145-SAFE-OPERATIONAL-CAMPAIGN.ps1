param(
    [switch]$ConfirmSafeOperationalCampaign
)

$ErrorActionPreference = 'Stop'

if (-not $ConfirmSafeOperationalCampaign) {
    throw 'B14-5 acceptance requires -ConfirmSafeOperationalCampaign.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

$commit = (& git rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Unable to resolve exact B14-5 acceptance commit.'
}
Write-Host ('B14-5 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Tracked working files differ from B14-5 acceptance commit.'
}

$frozen = 'bbaec9bfbe52c43483054185501239351781d29a'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Accepted B14-4 predecessor missing.'
}

$checkpoint = (& git rev-parse 'refs/remotes/origin/checkpoint/v014-b144-pass' 2>$null)
if ($LASTEXITCODE -ne 0) {
    $checkpoint = (& git rev-parse 'checkpoint/v014-b144-pass' 2>$null)
}
if ($LASTEXITCODE -ne 0 -or ([string]$checkpoint).Trim().ToLowerInvariant() -ne $frozen) {
    throw 'Accepted B14-4 checkpoint mismatch.'
}
Write-Host 'Accepted B14-4 checkpoint identity: PASS'

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
$changes = @(& git diff --name-only $frozen HEAD)
$allowed = @(
    '.github/workflows/b145-safe-operational-campaign.yml',
    'ROADMAP.md',
    'sentinel/beta14_safe_operational_campaign.py',
    'tests/test_v014_b145_safe_operational_campaign.py',
    'tools/acceptance/RUN-V014-B145-SAFE-OPERATIONAL-CAMPAIGN.ps1',
    'tools/acceptance/TEST-V014-B145-SAFE-OPERATIONAL-CAMPAIGN.ps1'
)
if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B14-5 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) {
        throw ('Unexpected B14-5 changed path: ' + $path)
    }
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B14-4 path changed: ' + $path)
    }
}
Write-Host 'Accepted B14-4 source immutability and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta14_safe_operational_campaign.py tests/test_v014_b145_safe_operational_campaign.py
if ($LASTEXITCODE -ne 0) {
    throw 'B14-5 compile failed.'
}

$patterns = @(
    'tests/test_v011_beta5_*.py',
    'tests/test_v011_beta6_*.py',
    'tests/test_v011_beta7_*.py',
    'tests/test_v011_beta8_*.py',
    'tests/test_v011_beta9_*.py',
    'tests/test_v011_beta10_*.py',
    'tests/test_v011_beta11_*.py',
    'tests/test_v012_beta12_*.py',
    'tests/test_v013_*.py',
    'tests/test_v014_*.py'
)
$tests = @(
    $patterns |
        ForEach-Object { Get-ChildItem $_ } |
        Sort-Object FullName |
        ForEach-Object { $_.FullName }
)
$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b145-pytest-' + [guid]::NewGuid().ToString('N'))
try {
    & $py -m pytest -q --basetemp $testBase @tests
    if ($LASTEXITCODE -ne 0) {
        throw 'Beta5 through Beta14 B14-5 regression failed.'
    }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

& $py -m sentinel.beta14_safe_operational_campaign
if ($LASTEXITCODE -ne 0) {
    throw 'B14-5 campaign contract self-check failed.'
}

$workspace = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b145-acceptance-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workspace -Force | Out-Null
$campaignPath = Join-Path $workspace 'campaign.json'

try {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'RUN-V014-B145-SAFE-OPERATIONAL-CAMPAIGN.ps1') -ConfirmSafeOperationalCampaign -Output $campaignPath
    if ($LASTEXITCODE -ne 0) {
        throw 'B14-5 safe live Windows campaign runner failed.'
    }

    $code = @'
import json
import sys
from pathlib import Path
from sentinel import beta14_safe_operational_campaign as b145

data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8-sig"))
result = b145.summarize(data)
print(json.dumps(result, sort_keys=True))
raise SystemExit(0 if result.get("passed") is True else 1)
'@
    $reportJson = @(& $py -c $code $campaignPath) -join [Environment]::NewLine
    if ($LASTEXITCODE -ne 0) {
        throw 'B14-5 safe operational campaign summary failed.'
    }
    $report = $reportJson | ConvertFrom-Json

    if (-not [bool]$report.passed) {
        throw 'B14-5 campaign report did not pass.'
    }
    if ([int]$report.live_control_count -ne 5 -or [int]$report.t0_control_count -ne 1 -or [int]$report.t1_control_count -ne 4) {
        throw 'B14-5 live control inventory mismatch.'
    }
    if (-not [bool]$report.b143_import_passed -or [int]$report.b143_import_accepted_count -ne 5 -or [int]$report.b143_import_authoritative_count -ne 5) {
        throw 'B14-5 B14-3 evidence bridge mismatch.'
    }
    if (
        [bool]$report.real_malware_executed -or
        [bool]$report.network_io -or
        [bool]$report.credential_access -or
        [bool]$report.real_persistence_mutation -or
        [bool]$report.security_control_impairment -or
        [bool]$report.user_file_access
    ) {
        throw 'B14-5 safe operational boundary violated.'
    }
    if ([bool]$report.coverage_promoted -or [bool]$report.authority_expanded) {
        throw 'B14-5 expanded coverage or authority.'
    }
    if ([int]$report.source_coverage.VERIFIED -ne 7 -or [int]$report.source_coverage.PARTIAL -ne 4 -or [int]$report.source_coverage.GAP -ne 0) {
        throw 'B14-5 canonical coverage changed unexpectedly.'
    }

    Write-Host ('B14-5 campaign digest: ' + [string]$report.campaign_digest)
    Write-Host ('B14-5 import batch digest: ' + [string]$report.import_batch_digest)
    Write-Host 'B14-5 live Windows controls: total=5 T0=1 T1=4 source_summaries=PASS'
    Write-Host 'B14-5 detector paths: script=PASS autostart=PASS process_tree=PASS local_reputation=PASS ransomware_like=PASS'
    Write-Host 'B14-5 B14-3 bridge: imported=5 authoritative=5 PASS'
    Write-Host 'B14-5 safety: real_malware=false network=false credentials=false real_persistence=false control_impairment=false user_files=false'
    Write-Host 'B14-5 coverage: PARTIAL=4 GAP=0 VERIFIED=7 / promoted=false'
    Write-Host 'BC SENTINEL v0.14.0 B14-5 SAFE OPERATIONAL T0/T1 CAMPAIGN - PASS'
}
finally {
    if (Test-Path -LiteralPath $workspace) {
        Remove-Item -LiteralPath $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'B14-5 acceptance modified tracked repository sources.'
}
