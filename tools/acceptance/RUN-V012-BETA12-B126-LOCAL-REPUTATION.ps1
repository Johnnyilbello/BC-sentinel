param(
    [switch]$ConfirmLocalReputationControls,
    [Parameter(Mandatory=$true)][string]$Output
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $ConfirmLocalReputationControls) {
    throw 'Explicit B12-6 local reputation control confirmation required.'
}

function Get-TextDigest([string]$Value) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }
}

function Get-SignerInfo([string]$Path) {
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
    return [ordered]@{ state = 'SIGNED_UNVERIFIED'; subject_digest = if ($null -ne $sig.SignerCertificate) { Get-TextDigest ([string]$sig.SignerCertificate.Subject) } else { '0' * 64 } }
}

function New-Control(
    [string]$ControlId,
    [string]$Path,
    [bool]$AllowlistHit,
    $AllowlistEntryId
) {
    $signer = Get-SignerInfo $Path
    return [ordered]@{
        control_id = $ControlId
        live_observation = $true
        sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
        path_digest = Get-TextDigest $Path
        signer_state = $signer.state
        signer_subject_digest = $signer.subject_digest
        local_allowlist_hit = $AllowlistHit
        allowlist_entry_id = $AllowlistEntryId
        file_executed = $false
    }
}

$workspace = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b126-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workspace -Force | Out-Null

$knownGoodPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$signedUnknownPath = Join-Path $env:SystemRoot 'System32\cmd.exe'
$unsignedPath = Join-Path $workspace 'unsigned-control.ps1'
[IO.File]::WriteAllText(
    $unsignedPath,
    '# harmless unsigned B12-6 metadata control',
    (New-Object Text.UTF8Encoding($false))
)

if (-not (Test-Path -LiteralPath $knownGoodPath -PathType Leaf)) { throw 'Known-good signed Windows binary unavailable.' }
if (-not (Test-Path -LiteralPath $signedUnknownPath -PathType Leaf)) { throw 'Signed-unknown Windows binary unavailable.' }

try {
    $known = New-Control 'known-good-signed-allowlisted' $knownGoodPath $true 'b126-known-good-1'
    $signedUnknown = New-Control 'signed-unknown' $signedUnknownPath $false $null
    $unsignedUnknown = New-Control 'unsigned-unknown' $unsignedPath $false $null

    if ($known.signer_state -ne 'SIGNED_VERIFIED') { throw 'B12-6 known-good binary is not signed/verified on this Windows host.' }
    if ($signedUnknown.signer_state -ne 'SIGNED_VERIFIED') { throw 'B12-6 signed-unknown binary is not signed/verified on this Windows host.' }
    if ($unsignedUnknown.signer_state -ne 'UNSIGNED') { throw 'B12-6 unsigned control unexpectedly has a signature.' }

    $payload = [ordered]@{
        schema = 'bc-sentinel-beta12-local-reputation-v1'
        source = 'WINDOWS_LOCAL_HASH_SIGNER_CONTROLS'
        allowlist = @(
            [ordered]@{
                entry_id = 'b126-known-good-1'
                sha256 = $known.sha256
                signer_subject_digest = $known.signer_subject_digest
                source = 'EXPLICIT_EPHEMERAL_ACCEPTANCE_ALLOWLIST'
            }
        )
        controls = @($known, $signedUnknown, $unsignedUnknown)
        boundaries = [ordered]@{
            local_only = $true
            explicit_opt_in_required = $true
            cloud_required = $false
            network_io = $false
            remote_access = $false
            raw_path_exported = $false
            file_content_exported = $false
            username_collected = $false
            file_execution = $false
            trust_allowlist_mutation = $false
            automatic_quarantine = $false
            automatic_repair = $false
            automatic_restore = $false
            terminate_process_authority = $false
            privileged_system_mutation = $false
        }
    }

    $parent = Split-Path -Parent $Output
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    [IO.File]::WriteAllText(
        $Output,
        ($payload | ConvertTo-Json -Depth 10),
        (New-Object Text.UTF8Encoding($false))
    )

    [ordered]@{
        controls = @(
            [ordered]@{ control_id = $known.control_id; signer_state = $known.signer_state; local_allowlist_hit = $known.local_allowlist_hit },
            [ordered]@{ control_id = $signedUnknown.control_id; signer_state = $signedUnknown.signer_state; local_allowlist_hit = $signedUnknown.local_allowlist_hit },
            [ordered]@{ control_id = $unsignedUnknown.control_id; signer_state = $unsignedUnknown.signer_state; local_allowlist_hit = $unsignedUnknown.local_allowlist_hit }
        )
        raw_paths_exported = $false
        file_content_exported = $false
        trust_allowlist_mutation = $false
    } | ConvertTo-Json -Depth 6
}
finally {
    if (Test-Path -LiteralPath $workspace) {
        Remove-Item -LiteralPath $workspace -Recurse -Force
    }
}
