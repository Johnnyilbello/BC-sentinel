param(
    [switch]$ConfirmLiveProcessTreeControls,
    [Parameter(Mandatory=$true)][string]$Output
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'

if (-not $ConfirmLiveProcessTreeControls) {
    throw 'Explicit B12-4 harmless live process-tree control confirmation required.'
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

function New-ProcessEvidence(
    [string]$Role,
    [int]$PidValue,
    $ParentPidValue,
    [string]$ImagePath,
    [string]$ImageKind,
    [bool]$UserWritable
) {
    $signer = Get-SignerInfo $ImagePath
    return [ordered]@{
        role = $Role
        pid = $PidValue
        parent_pid = $ParentPidValue
        image_sha256 = Get-Sha256 $ImagePath
        image_path_digest = Get-TextDigest $ImagePath
        signer_state = $signer.state
        signer_subject_digest = $signer.subject_digest
        image_kind = $ImageKind
        image_user_writable = $UserWritable
    }
}

function Invoke-ThreeGenerationControl(
    [string]$ControlId,
    [string]$IntermediateExe,
    [string]$LeafExe,
    [bool]$UserWritableImages,
    [bool]$KnownAdmin,
    [bool]$UserInitiated,
    [string]$Workspace
) {
    $resultPath = Join-Path $Workspace ($ControlId + '-pids.json')
    $scriptPath = Join-Path $Workspace ($ControlId + '-child.ps1')

    $scriptBody = @'
param(
    [Parameter(Mandatory=$true)][string]$LeafExe,
    [Parameter(Mandatory=$true)][string]$ResultPath
)
$ErrorActionPreference = 'Stop'
$child = Start-Process -FilePath $LeafExe -ArgumentList @('/c', 'exit 0') -WindowStyle Hidden -PassThru
$payload = [ordered]@{
    intermediate_pid = [int]$PID
    leaf_pid = [int]$child.Id
}
$child.WaitForExit()
$child.Dispose()
[IO.File]::WriteAllText(
    $ResultPath,
    ($payload | ConvertTo-Json -Compress),
    (New-Object Text.UTF8Encoding($false))
)
'@
    [IO.File]::WriteAllText($scriptPath, $scriptBody, (New-Object Text.UTF8Encoding($false)))

    $intermediate = Start-Process -FilePath $IntermediateExe -ArgumentList @(
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy', 'Bypass',
        '-File', ('"' + $scriptPath + '"'),
        '-LeafExe', ('"' + $LeafExe + '"'),
        '-ResultPath', ('"' + $resultPath + '"')
    ) -WindowStyle Hidden -PassThru

    $intermediatePid = [int]$intermediate.Id
    if (-not $intermediate.WaitForExit(10000)) {
        throw ('B12-4 intermediate timeout: ' + $ControlId)
    }
    if ([int]$intermediate.ExitCode -ne 0) {
        throw ('B12-4 intermediate non-zero exit: ' + $ControlId)
    }
    $intermediate.Dispose()

    if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
        throw ('B12-4 child PID evidence missing: ' + $ControlId)
    }
    $pids = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    if ([int]$pids.intermediate_pid -ne $intermediatePid) {
        throw ('B12-4 intermediate PID mismatch: ' + $ControlId)
    }

    $rootPath = [string](Get-Process -Id $PID -ErrorAction Stop).Path
    return [ordered]@{
        control_id = $ControlId
        live_observation = $true
        processes = @(
            New-ProcessEvidence 'ROOT' ([int]$PID) $null $rootPath 'SCRIPT_HOST' $false
            New-ProcessEvidence 'INTERMEDIATE' $intermediatePid ([int]$PID) $IntermediateExe 'SCRIPT_HOST' $UserWritableImages
            New-ProcessEvidence 'LEAF' ([int]$pids.leaf_pid) $intermediatePid $LeafExe 'SHELL' $UserWritableImages
        )
        known_admin_automation = $KnownAdmin
        user_initiated_operation = $UserInitiated
        cleanup_state = 'EXITED'
    }
}

function Invoke-BenignControl(
    [string]$ControlId,
    [string]$LeafExe
) {
    $child = Start-Process -FilePath $LeafExe -ArgumentList @('/c', 'exit 0') -WindowStyle Hidden -PassThru
    $childPid = [int]$child.Id
    if (-not $child.WaitForExit(10000)) {
        throw ('B12-4 benign child timeout: ' + $ControlId)
    }
    if ([int]$child.ExitCode -ne 0) {
        throw ('B12-4 benign child non-zero exit: ' + $ControlId)
    }
    $child.Dispose()

    $rootPath = [string](Get-Process -Id $PID -ErrorAction Stop).Path
    return [ordered]@{
        control_id = $ControlId
        live_observation = $true
        processes = @(
            New-ProcessEvidence 'ROOT' ([int]$PID) $null $rootPath 'SCRIPT_HOST' $false
            New-ProcessEvidence 'LEAF' $childPid ([int]$PID) $LeafExe 'SHELL' $false
        )
        known_admin_automation = $false
        user_initiated_operation = $false
        cleanup_state = 'EXITED'
    }
}

$workspace = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b124-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workspace -Force | Out-Null

$systemPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$systemCmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
if (-not (Test-Path -LiteralPath $systemPowerShell -PathType Leaf)) { throw 'Windows PowerShell executable unavailable.' }
if (-not (Test-Path -LiteralPath $systemCmd -PathType Leaf)) { throw 'Windows cmd executable unavailable.' }

$copiedCmd = Join-Path $workspace 'control-cmd.exe'
Copy-Item -LiteralPath $systemCmd -Destination $copiedCmd -Force

try {
    $positive = Invoke-ThreeGenerationControl 'positive-user-writable-script-shell-chain' $systemPowerShell $copiedCmd $true $false $false $workspace
    $positive.processes[1].image_user_writable = $false
    $administrative = Invoke-ThreeGenerationControl 'administrative-script-shell-chain' $systemPowerShell $systemCmd $false $true $true $workspace
    $benign = Invoke-BenignControl 'benign-application-child' $systemCmd

    $report = [ordered]@{
        schema = 'bc-sentinel-beta12-process-tree-live-controls-v1'
        source = 'WINDOWS_PROCESS_TREE_LIVE_CONTROLS'
        controls = @($positive, $administrative, $benign)
        boundaries = [ordered]@{
            local_only = $true
            explicit_opt_in_required = $true
            harmless_exercise_only = $true
            disposable_temp_workspace_only = $true
            command_line_exported = $false
            raw_path_exported = $false
            username_collected = $false
            event_payload_collected = $false
            network_io = $false
            remote_access = $false
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
