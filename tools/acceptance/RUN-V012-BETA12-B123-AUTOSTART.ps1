param(
    [switch]$ConfirmLiveAutostartShortcutControls,
    [Parameter(Mandatory=$true)][string]$Output
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PYTHONUTF8 = '1'

if (-not $ConfirmLiveAutostartShortcutControls) {
    throw 'Explicit B12-3 harmless live autostart-shortcut control confirmation required.'
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

function New-ShortcutControl(
    [string]$ControlId,
    [string]$TargetPath,
    [string]$TargetKind,
    [bool]$TargetUserWritable,
    [string]$Arguments,
    [bool]$KnownAdminAutomation,
    [bool]$UserConfigured,
    [string]$Workspace
) {
    $shortcutPath = Join-Path $Workspace ($ControlId + '.lnk')
    $shell = $null
    $shortcut = $null
    try {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $TargetPath
        if ($Arguments) { $shortcut.Arguments = $Arguments }
        $shortcut.WorkingDirectory = $Workspace
        $shortcut.Save()
    }
    finally {
        if ($null -ne $shortcut) {
            [Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut) | Out-Null
        }
        if ($null -ne $shell) {
            [Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell) | Out-Null
        }
    }

    if (-not (Test-Path -LiteralPath $shortcutPath -PathType Leaf)) {
        throw ('B12-3 shortcut was not created: ' + $ControlId)
    }

    $readerShell = $null
    $resolved = $null
    $resolvedTarget = $null
    $resolvedArguments = $null
    try {
        $readerShell = New-Object -ComObject WScript.Shell
        $resolved = $readerShell.CreateShortcut($shortcutPath)
        $resolvedTarget = [string]$resolved.TargetPath
        $resolvedArguments = [string]$resolved.Arguments
    }
    finally {
        if ($null -ne $resolved) {
            [Runtime.InteropServices.Marshal]::FinalReleaseComObject($resolved) | Out-Null
        }
        if ($null -ne $readerShell) {
            [Runtime.InteropServices.Marshal]::FinalReleaseComObject($readerShell) | Out-Null
        }
    }

    if (-not $resolvedTarget -or -not (Test-Path -LiteralPath $resolvedTarget -PathType Leaf)) {
        throw ('B12-3 shortcut target did not resolve: ' + $ControlId)
    }

    $signer = Get-SignerInfo $resolvedTarget

    return [ordered]@{
        control_id = $ControlId
        live_observation = $true
        windows_shortcut_created = $true
        windows_shortcut_resolved = $true
        shortcut_sha256 = Get-Sha256 $shortcutPath
        shortcut_path_digest = Get-TextDigest $shortcutPath
        target_sha256 = Get-Sha256 $resolvedTarget
        target_path_digest = Get-TextDigest $resolvedTarget
        target_signer_state = $signer.state
        target_signer_subject_digest = $signer.subject_digest
        target_kind = $TargetKind
        target_user_writable = $TargetUserWritable
        arguments_present = [bool]$resolvedArguments
        known_admin_automation = $KnownAdminAutomation
        user_initiated_configuration = $UserConfigured
        startup_surface_mutated = $false
        workspace_scope = 'DISPOSABLE_TEMP_ONLY'
        cleanup_state = 'PENDING'
    }
}

$workspace = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b123-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workspace -Force | Out-Null

$positiveTarget = Join-Path $workspace 'harmless-positive.cmd'
$positiveBody = '@echo off' + [Environment]::NewLine + 'exit /b 0' + [Environment]::NewLine
[IO.File]::WriteAllText($positiveTarget, $positiveBody, (New-Object Text.UTF8Encoding($false)))

$powerShellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$notepadExe = Join-Path $env:SystemRoot 'System32\notepad.exe'
if (-not (Test-Path -LiteralPath $powerShellExe -PathType Leaf)) { throw 'Windows PowerShell executable unavailable.' }
if (-not (Test-Path -LiteralPath $notepadExe -PathType Leaf)) { throw 'Notepad executable unavailable.' }

try {
    $positive = New-ShortcutControl 'positive-autostart-like-shortcut' $positiveTarget 'SCRIPT_OR_BATCH' $true '' $false $false $workspace
    $administrative = New-ShortcutControl 'administrative-autostart-like-shortcut' $powerShellExe 'SCRIPT_HOST' $false '-NoLogo -NoProfile -NonInteractive -Command exit 0' $true $true $workspace
    $benign = New-ShortcutControl 'benign-shortcut' $notepadExe 'SIGNED_APPLICATION' $false '' $false $false $workspace
    $controls = @($positive, $administrative, $benign)

    Remove-Item -LiteralPath $workspace -Recurse -Force
    foreach ($control in $controls) {
        $control.cleanup_state = 'REMOVED'
    }

    $report = [ordered]@{
        schema = 'bc-sentinel-beta12-autostart-shortcut-live-controls-v1'
        source = 'WINDOWS_AUTOSTART_SHORTCUT_LIVE_CONTROLS'
        controls = $controls
        boundaries = [ordered]@{
            local_only = $true
            explicit_opt_in_required = $true
            harmless_exercise_only = $true
            disposable_temp_workspace_only = $true
            real_startup_folder_mutated = $false
            registry_run_key_mutated = $false
            scheduled_task_mutated = $false
            service_mutated = $false
            shell_extension_mutated = $false
            raw_path_exported = $false
            shortcut_arguments_exported = $false
            username_collected = $false
            credential_access = $false
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

    $json = $report | ConvertTo-Json -Depth 10
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
