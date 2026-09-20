param(
    [switch]$ConfirmSafeOperationalCampaign,
    [Parameter(Mandatory=$true)][string]$Output
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'

if (-not $ConfirmSafeOperationalCampaign) {
    throw 'B14-5 requires -ConfirmSafeOperationalCampaign.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

function Get-FileSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Invoke-SourceSummary(
    [string]$Module,
    [string]$EvidencePath,
    [string]$SummaryPath
) {
    $code = @'
import importlib
import json
import sys
from pathlib import Path

module = importlib.import_module(sys.argv[1])
data = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8-sig"))
result = module.summarize(data)
print(json.dumps(result, sort_keys=True))
raise SystemExit(0 if result.get("passed") is True else 1)
'@
    $lines = @(& $py -c $code $Module $EvidencePath)
    if ($LASTEXITCODE -ne 0) {
        throw ('B14-5 source summary failed: ' + $Module)
    }
    $json = ($lines -join [Environment]::NewLine)
    [IO.File]::WriteAllText(
        $SummaryPath,
        $json,
        (New-Object Text.UTF8Encoding($false))
    )
    return ($json | ConvertFrom-Json)
}

$workspace = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b145-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workspace -Force | Out-Null

try {
    $scriptEvidence = Join-Path $workspace 'script-abuse.json'
    $autostartEvidence = Join-Path $workspace 'autostart.json'
    $processEvidence = Join-Path $workspace 'process-tree.json'
    $reputationEvidence = Join-Path $workspace 'local-reputation.json'
    $ransomEvidence = Join-Path $workspace 'ransomware-like.json'

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'RUN-V012-BETA12-B122-SCRIPT-ABUSE.ps1') -ConfirmLiveScriptAbuseControls -Output $scriptEvidence | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'B14-5 script-abuse live control failed.' }

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'RUN-V012-BETA12-B123-AUTOSTART.ps1') -ConfirmLiveAutostartShortcutControls -Output $autostartEvidence | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'B14-5 autostart live control failed.' }

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'RUN-V012-BETA12-B124-PROCESS-TREE.ps1') -ConfirmLiveProcessTreeControls -Output $processEvidence | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'B14-5 process-tree live control failed.' }

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'RUN-V012-BETA12-B126-LOCAL-REPUTATION.ps1') -ConfirmLocalReputationControls -Output $reputationEvidence | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'B14-5 local-reputation live control failed.' }

    & $py (Join-Path $PSScriptRoot 'RUN-V011-BETA9-B93-LIVE-FILES.py') --output $ransomEvidence --confirm-live-controls | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'B14-5 ransomware-like live control failed.' }

    $scriptSummaryPath = Join-Path $workspace 'script-abuse-summary.json'
    $autostartSummaryPath = Join-Path $workspace 'autostart-summary.json'
    $processSummaryPath = Join-Path $workspace 'process-tree-summary.json'
    $reputationSummaryPath = Join-Path $workspace 'local-reputation-summary.json'
    $ransomSummaryPath = Join-Path $workspace 'ransomware-like-summary.json'

    $scriptSummary = Invoke-SourceSummary 'sentinel.beta12_script_abuse_controls' $scriptEvidence $scriptSummaryPath
    $autostartSummary = Invoke-SourceSummary 'sentinel.beta12_autostart_detection' $autostartEvidence $autostartSummaryPath
    $processSummary = Invoke-SourceSummary 'sentinel.beta12_process_tree_intelligence' $processEvidence $processSummaryPath
    $reputationSummary = Invoke-SourceSummary 'sentinel.beta12_local_reputation' $reputationEvidence $reputationSummaryPath
    $ransomSummary = Invoke-SourceSummary 'sentinel.beta9_ransomware_controls' $ransomEvidence $ransomSummaryPath

    foreach ($summary in @($scriptSummary, $autostartSummary, $processSummary, $reputationSummary, $ransomSummary)) {
        if ($summary.passed -ne $true) {
            throw 'B14-5 one or more accepted detector summaries did not pass.'
        }
    }

    $controls = @(
        [ordered]@{
            control_id = 'b145-script-abuse-live'
            tier = 'T1_SAFE_ADVERSARY_EMULATION'
            scenario_id = 'B12-SCRIPT-ABUSE-001'
            source_module = 'sentinel.beta12_script_abuse_controls'
            detection_layer = 'BEHAVIOR'
            evidence_digest = Get-FileSha256 $scriptEvidence
            source_summary_digest = Get-FileSha256 $scriptSummaryPath
            source_summary_passed = $true
            live_windows_observation = $true
            cleanup_confirmed = $true
            real_malware_executed = $false
            network_io = $false
            credential_access = $false
            real_persistence_mutation = $false
            security_control_impairment = $false
            user_file_access = $false
        },
        [ordered]@{
            control_id = 'b145-autostart-live'
            tier = 'T1_SAFE_ADVERSARY_EMULATION'
            scenario_id = 'B12-AUTOSTART-LINK-001'
            source_module = 'sentinel.beta12_autostart_detection'
            detection_layer = 'BEHAVIOR'
            evidence_digest = Get-FileSha256 $autostartEvidence
            source_summary_digest = Get-FileSha256 $autostartSummaryPath
            source_summary_passed = $true
            live_windows_observation = $true
            cleanup_confirmed = $true
            real_malware_executed = $false
            network_io = $false
            credential_access = $false
            real_persistence_mutation = $false
            security_control_impairment = $false
            user_file_access = $false
        },
        [ordered]@{
            control_id = 'b145-process-tree-live'
            tier = 'T1_SAFE_ADVERSARY_EMULATION'
            scenario_id = 'B12-PROCESS-TREE-001'
            source_module = 'sentinel.beta12_process_tree_intelligence'
            detection_layer = 'PROCESS_CORRELATION'
            evidence_digest = Get-FileSha256 $processEvidence
            source_summary_digest = Get-FileSha256 $processSummaryPath
            source_summary_passed = $true
            live_windows_observation = $true
            cleanup_confirmed = $true
            real_malware_executed = $false
            network_io = $false
            credential_access = $false
            real_persistence_mutation = $false
            security_control_impairment = $false
            user_file_access = $false
        },
        [ordered]@{
            control_id = 'b145-local-reputation-live'
            tier = 'T0_HARMLESS_FEATURE_CHECKS'
            scenario_id = 'B12-LOCAL-REPUTATION-001'
            source_module = 'sentinel.beta12_local_reputation'
            detection_layer = 'STATIC'
            evidence_digest = Get-FileSha256 $reputationEvidence
            source_summary_digest = Get-FileSha256 $reputationSummaryPath
            source_summary_passed = $true
            live_windows_observation = $true
            cleanup_confirmed = $true
            real_malware_executed = $false
            network_io = $false
            credential_access = $false
            real_persistence_mutation = $false
            security_control_impairment = $false
            user_file_access = $false
        },
        [ordered]@{
            control_id = 'b145-ransomware-like-live'
            tier = 'T1_SAFE_ADVERSARY_EMULATION'
            scenario_id = 'B7-RANSOMWARE-001'
            source_module = 'sentinel.beta9_ransomware_controls'
            detection_layer = 'RANSOMWARE_SHIELD'
            evidence_digest = Get-FileSha256 $ransomEvidence
            source_summary_digest = Get-FileSha256 $ransomSummaryPath
            source_summary_passed = $true
            live_windows_observation = $true
            cleanup_confirmed = $true
            real_malware_executed = $false
            network_io = $false
            credential_access = $false
            real_persistence_mutation = $false
            security_control_impairment = $false
            user_file_access = $false
        }
    )

    $payload = [ordered]@{
        schema = 'bc-sentinel-beta14-safe-operational-campaign-v1'
        profile = 'v0.14.0-b145-safe-operational-campaign'
        source_checkpoint = 'checkpoint/v014-b144-pass'
        source_checkpoint_commit = 'bbaec9bfbe52c43483054185501239351781d29a'
        controls = $controls
        boundaries = [ordered]@{
            harmless_live_controls_only = $true
            disposable_temp_workspaces_only = $true
            real_malware_executed = $false
            real_sample_bytes_present = $false
            network_io = $false
            credential_access = $false
            real_persistence_mutation = $false
            security_control_impairment = $false
            user_file_access = $false
            coverage_promoted = $false
            authority_expanded = $false
        }
    }

    $json = $payload | ConvertTo-Json -Depth 12
    $parent = Split-Path -Parent $Output
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    [IO.File]::WriteAllText($Output, $json, (New-Object Text.UTF8Encoding($false)))

    [ordered]@{
        live_controls = 5
        t0_controls = 1
        t1_controls = 4
        source_summaries_passed = 5
        real_malware_executed = $false
        network_io = $false
        output_sha256 = Get-FileSha256 $Output
    } | ConvertTo-Json -Depth 5
}
finally {
    if (Test-Path -LiteralPath $workspace) {
        Remove-Item -LiteralPath $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
