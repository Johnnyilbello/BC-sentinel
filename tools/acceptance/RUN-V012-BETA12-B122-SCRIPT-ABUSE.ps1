param(
    [switch]$ConfirmLiveScriptAbuseControls,
    [Parameter(Mandatory=$true)][string]$Output
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'

if (-not $ConfirmLiveScriptAbuseControls) {
    throw 'Explicit B12-2 harmless live script-abuse control confirmation required.'
}

$exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path -LiteralPath $exe)) {
    throw 'Windows PowerShell executable unavailable.'
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Get-TextDigest([string]$Value) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Get-SignerInfo([string]$Path) {
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        if ($sig.Status -eq 'Valid' -and $null -ne $sig.SignerCertificate) {
            return [ordered]@{
                state = 'SIGNED_VERIFIED'
                subject_digest = Get-TextDigest ([string]$sig.SignerCertificate.Subject)
            }
        }
        if ($sig.Status -eq 'NotSigned') {
            return [ordered]@{ state = 'UNSIGNED'; subject_digest = $null }
        }
    }
    catch {}
    return [ordered]@{ state = 'UNKNOWN'; subject_digest = $null }
}

$workspace = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b122-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workspace -Force | Out-Null

$scriptPath = Join-Path $workspace 'harmless-control.ps1'
$scriptBody = @'
param(
    [Parameter(Mandatory=$true)][string]$OutDir,
    [Parameter(Mandatory=$true)][int]$Count
)
$ErrorActionPreference = 'Stop'
for ($i = 0; $i -lt $Count; $i++) {
    $target = Join-Path $OutDir ('artifact-{0:D2}.txt' -f $i)
    [IO.File]::WriteAllText(
        $target,
        ('BC Sentinel harmless script-control artifact {0}' -f $i),
        (New-Object Text.UTF8Encoding($false))
    )
}
'@
[IO.File]::WriteAllText($scriptPath, $scriptBody, (New-Object Text.UTF8Encoding($false)))

$scriptHash = Get-Sha256 $scriptPath
$scriptPathDigest = Get-TextDigest $scriptPath
$childImageHash = Get-Sha256 $exe
$childSigner = Get-SignerInfo $exe

$parentProcess = Get-Process -Id $PID -ErrorAction Stop
$parentPath = [string]$parentProcess.Path
if (-not $parentPath -or -not (Test-Path -LiteralPath $parentPath)) {
    throw 'Cannot resolve B12-2 parent PowerShell image.'
}
$parentHash = Get-Sha256 $parentPath
$parentSigner = Get-SignerInfo $parentPath

function Invoke-Control(
    [string]$ControlId,
    [int]$MutationCount,
    [bool]$KnownAdminAutomation,
    [bool]$UserBulk
) {
    $controlDir = Join-Path $workspace $ControlId
    New-Item -ItemType Directory -Path $controlDir -Force | Out-Null

    $startedAt = [DateTime]::UtcNow
    $child = $null
    try {
        $args = @(
            '-NoLogo',
            '-NoProfile',
            '-NonInteractive',
            '-ExecutionPolicy', 'Bypass',
            '-File', ('"' + $scriptPath + '"'),
            '-OutDir', ('"' + $controlDir + '"'),
            '-Count', ([string]$MutationCount)
        )
        $child = Start-Process -FilePath $exe -ArgumentList $args -WindowStyle Hidden -PassThru -ErrorAction Stop
        $childPid = [int]$child.Id
        if (-not $child.WaitForExit(10000)) {
            throw ('B12-2 child timeout: ' + $ControlId)
        }
        if ([int]$child.ExitCode -ne 0) {
            throw ('B12-2 child non-zero exit: ' + $ControlId)
        }
    }
    finally {
        if ($null -ne $child) { $child.Dispose() }
    }
    $completedAt = [DateTime]::UtcNow

    $files = @(Get-ChildItem -LiteralPath $controlDir -File -ErrorAction Stop | Sort-Object Name)
    if ($files.Count -ne $MutationCount) {
        throw ('B12-2 mutation count mismatch for ' + $ControlId + ': ' + $files.Count)
    }
    if ($files.Count -lt 1) {
        throw ('B12-2 representative artifact missing for ' + $ControlId)
    }

    $representative = $files[0]
    $observedAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0

    $correlation = [ordered]@{
        schema = 'bc-sentinel-beta12-process-file-correlation-v1'
        source = 'WINDOWS_PROCESS_FILE_CORRELATION_OBSERVATION'
        observation_id = ('b122-' + $ControlId)
        observed_at = $observedAt
        process = [ordered]@{
            pid = $childPid
            parent_pid = [int]$PID
            image_sha256 = $childImageHash
            signer_state = $childSigner.state
            signer_subject_digest = $childSigner.subject_digest
        }
        parent_process = [ordered]@{
            pid = [int]$PID
            image_sha256 = $parentHash
            signer_state = $parentSigner.state
            signer_subject_digest = $parentSigner.subject_digest
        }
        file = [ordered]@{
            operation = 'CREATED'
            target_path_digest = Get-TextDigest $representative.FullName
            sha256 = Get-Sha256 $representative.FullName
            signer_state = 'UNSIGNED'
            signer_subject_digest = $null
        }
        evidence = [ordered]@{
            process_evidence_id = ('b122-' + $ControlId + '-process')
            file_evidence_id = ('b122-' + $ControlId + '-file')
            relation_evidence_id = ('b122-' + $ControlId + '-relation')
        }
        provenance = [ordered]@{
            source = 'b122-windows-live-control'
            source_id = ('b122-' + $ControlId)
            collector = 'RUN-V012-BETA12-B122-SCRIPT-ABUSE.ps1'
            trust = 'DIRECT'
        }
        boundaries = [ordered]@{
            local_only = $true
            read_only = $true
            raw_path_collected = $false
            command_line_collected = $false
            username_collected = $false
            event_payload_collected = $false
            network_required = $false
            cloud_required = $false
            threat_classification = $false
            coverage_promoted = $false
            automatic_quarantine = $false
            automatic_repair = $false
            automatic_restore = $false
            terminate_process_authority = $false
            trust_allowlist_mutation = $false
            privileged_system_mutation = $false
        }
    }

    return [ordered]@{
        control_id = $ControlId
        live_observation = $true
        script_execution_observed = $true
        script_sha256 = $scriptHash
        script_path_digest = $scriptPathDigest
        file_mutation_count = $files.Count
        duration_seconds = [Math]::Round(($completedAt - $startedAt).TotalSeconds, 6)
        known_admin_automation = $KnownAdminAutomation
        user_initiated_bulk_operation = $UserBulk
        cleanup_state = 'EXITED'
        correlation_observation = $correlation
    }
}

try {
    $controls = @(
        Invoke-Control 'positive-script-mutation-burst' 6 $false $false
        Invoke-Control 'administrative-script-mutation-burst' 6 $true $true
        Invoke-Control 'benign-powershell-script' 1 $false $false
    )

    $report = [ordered]@{
        schema = 'bc-sentinel-beta12-script-abuse-live-controls-v1'
        source = 'WINDOWS_POWERSHELL_SCRIPT_ABUSE_LIVE_CONTROLS'
        controls = $controls
        boundaries = [ordered]@{
            local_only = $true
            explicit_opt_in_required = $true
            harmless_exercise_only = $true
            disposable_temp_workspace_only = $true
            script_content_exported = $false
            command_line_exported = $false
            raw_path_exported = $false
            username_collected = $false
            event_payload_collected = $false
            credential_access = $false
            network_io = $false
            remote_access = $false
            registry_mutation = $false
            logging_configuration_mutation = $false
            audit_policy_mutation = $false
            real_malware_executed = $false
            automatic_quarantine = $false
            automatic_repair = $false
            automatic_restore = $false
            terminate_process_authority = $false
            trust_allowlist_mutation = $false
            privileged_system_mutation = $false
        }
    }

    $json = $report | ConvertTo-Json -Depth 12
    $parent = Split-Path -Parent $Output
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    [IO.File]::WriteAllText($Output, $json, (New-Object Text.UTF8Encoding($false)))
    $json
}
finally {
    if (Test-Path -LiteralPath $workspace) {
        Remove-Item -LiteralPath $workspace -Recurse -Force
    }
}
