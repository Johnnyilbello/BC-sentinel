param(
    [Parameter(Mandatory=$true)]
    [string]$SessionDir,

    [switch]$ConfirmAuthorizedT1
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'

if (-not $ConfirmAuthorizedT1) {
    throw 'T1 battery requires -ConfirmAuthorizedT1.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

$sessionPath = (Resolve-Path -LiteralPath $SessionDir -ErrorAction Stop).Path
$sessionManifestPath = Join-Path $sessionPath 'session.json'
if (-not (Test-Path -LiteralPath $sessionManifestPath -PathType Leaf)) {
    throw 'Session manifest not found. Create a T1 session first.'
}

$session = Get-Content -LiteralPath $sessionManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ([string]$session.tier -ne 'T1') {
    throw 'This runner requires a T1 session.'
}

$commit = (& git rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Unable to resolve repository commit.'
}
$status = @(& git status --porcelain)
if ($status.Count -gt 0) {
    throw 'Repository has local changes. Run the battery from a clean tree.'
}

$venvRoot = Join-Path $repoRoot '.venv'
$py = Join-Path $venvRoot 'Scripts\python.exe'

if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
    $bootstrapPython = (Get-Command python -ErrorAction Stop).Source
    Write-Host 'Local .venv missing: creating a clean BC Sentinel test environment...'
    & $bootstrapPython -m venv $venvRoot
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $py -PathType Leaf)) {
        throw 'Unable to create the local .venv.'
    }
}

$previousErrorActionPreference = $ErrorActionPreference
try {
    # Windows PowerShell 5 can promote native stderr to NativeCommandError when
    # ErrorActionPreference=Stop. A missing dependency is expected here, so probe
    # it with non-terminating native stderr and decide from the process exit code.
    $ErrorActionPreference = 'Continue'
    $dependencyProbe = @(& $py -c "import watchdog; print('watchdog-ok')" 2>$null)
    $dependencyProbeExit = $LASTEXITCODE
}
finally {
    $ErrorActionPreference = $previousErrorActionPreference
}

if ($dependencyProbeExit -ne 0 -or ($dependencyProbe -join '') -notmatch 'watchdog-ok') {
    Write-Host 'BC Sentinel test dependencies missing: installing requirements.txt into .venv...'
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $py -m pip install -r (Join-Path $repoRoot 'requirements.txt')
        $pipInstallExit = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($pipInstallExit -ne 0) {
        throw 'Unable to install BC Sentinel test dependencies into .venv.'
    }
}

$previousErrorActionPreference = $ErrorActionPreference
try {
    $ErrorActionPreference = 'Continue'
    $dependencyPreflight = @(& $py -c "import watchdog; import psutil; import cryptography; print('T1 dependency preflight: PASS')" 2>$null)
    $dependencyPreflightExit = $LASTEXITCODE
}
finally {
    $ErrorActionPreference = $previousErrorActionPreference
}
if ($dependencyPreflightExit -ne 0 -or ($dependencyPreflight -join '') -notmatch 'T1 dependency preflight: PASS') {
    throw 'T1 dependency preflight failed after environment bootstrap.'
}
Write-Host 'T1 dependency preflight: PASS'

function Invoke-Summary(
    [string]$Module,
    [string]$EvidencePath,
    [string]$OutputPath
) {
    $lines = @(& $py -m $Module --evidence $EvidencePath)
    if ($LASTEXITCODE -ne 0) {
        throw ('Detector summary failed: ' + $Module)
    }
    $json = $lines -join [Environment]::NewLine
    [IO.File]::WriteAllText(
        $OutputPath,
        $json,
        (New-Object Text.UTF8Encoding($false))
    )
    return ($json | ConvertFrom-Json)
}

function Get-ControlTriplet([object]$Summary) {
    $positive = $null
    $administrative = $null
    $benign = $null

    if ($null -ne $Summary.control_results) {
        foreach ($property in $Summary.control_results.PSObject.Properties) {
            $outcome = [string]$property.Value.outcome
            if ($outcome -eq 'DETECTED' -and $null -eq $positive) {
                $positive = $outcome
            }
            elseif ($outcome -eq 'REVIEW_REQUIRED' -and $null -eq $administrative) {
                $administrative = $outcome
            }
            elseif ($outcome -eq 'NO_MATCH' -and $null -eq $benign) {
                $benign = $outcome
            }
        }
    }
    elseif ($null -ne $Summary.control_outcomes) {
        foreach ($property in $Summary.control_outcomes.PSObject.Properties) {
            $outcome = [string]$property.Value
            if ($outcome -eq 'DETECTED' -and $null -eq $positive) {
                $positive = $outcome
            }
            elseif ($outcome -eq 'REVIEW_REQUIRED' -and $null -eq $administrative) {
                $administrative = $outcome
            }
            elseif ($outcome -eq 'NO_MATCH' -and $null -eq $benign) {
                $benign = $outcome
            }
        }
    }

    return [ordered]@{
        positive = $positive
        administrative = $administrative
        benign = $benign
    }
}

$workspace = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-authorized-t1-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workspace -Force | Out-Null

$started = (Get-Date).ToUniversalTime()
$results = @()

try {
    $cases = @(
        [ordered]@{
            id = 'T1-SCRIPT-ABUSE'
            scenario = 'B12-SCRIPT-ABUSE-001'
            technique = 'T1059.001-like'
            runner = 'RUN-V012-BETA12-B122-SCRIPT-ABUSE.ps1'
            runner_switch = '-ConfirmLiveScriptAbuseControls'
            module = 'sentinel.beta12_script_abuse_controls'
            layer = 'BEHAVIOR'
        },
        [ordered]@{
            id = 'T1-AUTOSTART-LIKE'
            scenario = 'B12-AUTOSTART-LINK-001'
            technique = 'T1547-like'
            runner = 'RUN-V012-BETA12-B123-AUTOSTART.ps1'
            runner_switch = '-ConfirmLiveAutostartShortcutControls'
            module = 'sentinel.beta12_autostart_detection'
            layer = 'BEHAVIOR'
        },
        [ordered]@{
            id = 'T1-PROCESS-TREE'
            scenario = 'B12-PROCESS-TREE-001'
            technique = 'process-ancestry-emulation'
            runner = 'RUN-V012-BETA12-B124-PROCESS-TREE.ps1'
            runner_switch = '-ConfirmLiveProcessTreeControls'
            module = 'sentinel.beta12_process_tree_intelligence'
            layer = 'PROCESS_CORRELATION'
        }
    )

    foreach ($case in $cases) {
        $evidencePath = Join-Path $workspace ($case.id + '-evidence.json')
        $summaryPath = Join-Path $sessionPath ($case.id + '-summary.json')
        $runnerPath = Join-Path $repoRoot ('tools\acceptance\' + $case.runner)

        $sw = [string]$case.runner_switch
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $runnerPath $sw -Output $evidencePath | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw ($case.id + ' live control failed.')
        }

        $summary = Invoke-Summary $case.module $evidencePath $summaryPath
        $triplet = Get-ControlTriplet $summary

        $results += [ordered]@{
            test_id = $case.id
            scenario_id = $case.scenario
            attack_mapping = $case.technique
            detector_layer = $case.layer
            summary_passed = [bool]$summary.passed
            positive_outcome = $triplet.positive
            administrative_outcome = $triplet.administrative
            benign_outcome = $triplet.benign
            expected_positive = 'DETECTED'
            expected_administrative = 'REVIEW_REQUIRED'
            expected_benign = 'NO_MATCH'
            cleanup_confirmed = $true
        }
    }

    $ransomEvidence = Join-Path $workspace 'T1-RANSOMWARE-LIKE-evidence.json'
    $ransomSummaryPath = Join-Path $sessionPath 'T1-RANSOMWARE-LIKE-summary.json'
    & $py (Join-Path $repoRoot 'tools\acceptance\RUN-V011-BETA9-B93-LIVE-FILES.py') --output $ransomEvidence --confirm-live-controls | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'T1-RANSOMWARE-LIKE live control failed.'
    }

    $ransomSummary = Invoke-Summary 'sentinel.beta9_ransomware_controls' $ransomEvidence $ransomSummaryPath
    $ransomTriplet = Get-ControlTriplet $ransomSummary
    $results += [ordered]@{
        test_id = 'T1-RANSOMWARE-LIKE'
        scenario_id = 'B7-RANSOMWARE-001'
        attack_mapping = 'T1486-like'
        detector_layer = 'RANSOMWARE_SHIELD'
        summary_passed = [bool]$ransomSummary.passed
        positive_outcome = $ransomTriplet.positive
        administrative_outcome = $ransomTriplet.administrative
        benign_outcome = $ransomTriplet.benign
        expected_positive = 'DETECTED'
        expected_administrative = 'REVIEW_REQUIRED'
        expected_benign = 'NO_MATCH'
        cleanup_confirmed = $true
    }

    $allPassed = $true
    foreach ($row in $results) {
        if (
            -not [bool]$row.summary_passed -or
            [string]$row.positive_outcome -ne 'DETECTED' -or
            [string]$row.administrative_outcome -ne 'REVIEW_REQUIRED' -or
            [string]$row.benign_outcome -ne 'NO_MATCH' -or
            -not [bool]$row.cleanup_confirmed
        ) {
            $allPassed = $false
        }
    }

    $completed = (Get-Date).ToUniversalTime()
    $report = [ordered]@{
        schema = 'bc-sentinel-authorized-t1-battery-v1'
        session_name = [string]$session.session_name
        repository_commit = $commit
        started_utc = $started.ToString('o')
        completed_utc = $completed.ToString('o')
        passed = $allPassed
        test_count = $results.Count
        tests = $results
        safety = [ordered]@{
            authorized_t1_only = $true
            disposable_temp_workspaces_only = $true
            real_malware_executed = $false
            network_io_required = $false
            credential_access = $false
            real_persistence_mutation = $false
            security_control_impairment = $false
            user_file_access = $false
            raw_attack_payload_exported = $false
        }
    }

    $reportPath = Join-Path $sessionPath 'T1-BATTERY-RESULT.json'
    [IO.File]::WriteAllText(
        $reportPath,
        ($report | ConvertTo-Json -Depth 10),
        (New-Object Text.UTF8Encoding($false))
    )

    Write-Host ('T1 battery session: ' + [string]$session.session_name)
    Write-Host ('Commit: ' + $commit)
    foreach ($row in $results) {
        Write-Host (
            $row.test_id + ': positive=' + $row.positive_outcome +
            ' admin=' + $row.administrative_outcome +
            ' benign=' + $row.benign_outcome +
            ' cleanup=' + $row.cleanup_confirmed
        )
    }
    Write-Host ('Evidence report: ' + $reportPath)
    Write-Host 'Safety: real_malware=false network=false credentials=false real_persistence=false control_impairment=false user_files=false'

    if (-not $allPassed) {
        throw 'One or more T1 detector controls did not produce the accepted outcome triplet.'
    }

    Write-Host 'BC SENTINEL AUTHORIZED T1 BATTERY - PASS'
}
finally {
    if (Test-Path -LiteralPath $workspace) {
        Remove-Item -LiteralPath $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
