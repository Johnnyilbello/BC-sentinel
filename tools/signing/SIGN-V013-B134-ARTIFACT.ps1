param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][ValidateSet('APPLICATION_EXE','INSTALLER_EXE','UNINSTALLER_EXE')][string]$PathRole,
    [Parameter(Mandatory=$true)][ValidateSet('CERTIFICATE_STORE','MICROSOFT_ARTIFACT_SIGNING')][string]$Provider,
    [Parameter(Mandatory=$true)][ValidateSet('ENGINEERING_TEST','PUBLIC_TRUST')][string]$TrustLevel,
    [Parameter(Mandatory=$true)][string]$ExpectedPublisher,
    [string]$CertificateThumbprint,
    [string]$ArtifactSigningDlib,
    [string]$ArtifactSigningMetadata,
    [string]$TimestampUrl = 'http://timestamp.acs.microsoft.com',
    [string]$SignToolPath,
    [string]$OutputJson
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

function Resolve-SignTool([string]$ExplicitPath) {
    if ($ExplicitPath) {
        $resolved = (Resolve-Path -LiteralPath $ExplicitPath -ErrorAction Stop).Path
        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
            throw 'B13-4 SignTool path is not a file.'
        }
        return $resolved
    }

    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }

    $sdkRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    if (Test-Path -LiteralPath $sdkRoot) {
        $candidate = Get-ChildItem -LiteralPath $sdkRoot -Recurse -Filter signtool.exe -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }

    throw 'B13-4 SignTool.exe not found.'
}

function Normalize-Thumbprint([string]$Value) {
    if (-not $Value) { return '' }
    return (($Value -replace '\s','').ToLowerInvariant())
}

$ResolvedPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $ResolvedPath -PathType Leaf)) {
    throw 'B13-4 target artifact missing.'
}
$stream = [IO.File]::OpenRead($ResolvedPath)
try {
    $first = $stream.ReadByte()
    $second = $stream.ReadByte()
}
finally {
    $stream.Dispose()
}
if ($first -ne 0x4D -or $second -ne 0x5A) {
    throw 'B13-4 target is not a Windows PE artifact (MZ header missing).'
}
if ($PathRole -ne 'UNINSTALLER_EXE' -and [IO.Path]::GetExtension($ResolvedPath).ToLowerInvariant() -ne '.exe') {
    throw 'B13-4 application and installer artifacts must use the .exe extension.'
}

if ($Provider -eq 'CERTIFICATE_STORE') {
    if (-not $CertificateThumbprint) {
        throw 'B13-4 certificate-store provider requires CertificateThumbprint.'
    }
    $CertificateThumbprint = Normalize-Thumbprint $CertificateThumbprint
    if ($CertificateThumbprint -notmatch '^[0-9a-f]{40,64}$') {
        throw 'B13-4 certificate thumbprint is invalid.'
    }
    $cert = Get-ChildItem -LiteralPath ('Cert:\CurrentUser\My\' + $CertificateThumbprint) -ErrorAction SilentlyContinue
    if (-not $cert) {
        throw 'B13-4 certificate was not found in CurrentUser\My.'
    }
    if (-not $cert.HasPrivateKey) {
        throw 'B13-4 selected certificate has no private key.'
    }
    if ($cert.Subject -notlike ('*' + $ExpectedPublisher + '*')) {
        throw 'B13-4 selected certificate publisher does not match ExpectedPublisher.'
    }
}
else {
    if (-not $ArtifactSigningDlib -or -not $ArtifactSigningMetadata) {
        throw 'B13-4 Artifact Signing provider requires Dlib and metadata paths.'
    }
    $ArtifactSigningDlib = (Resolve-Path -LiteralPath $ArtifactSigningDlib -ErrorAction Stop).Path
    $ArtifactSigningMetadata = (Resolve-Path -LiteralPath $ArtifactSigningMetadata -ErrorAction Stop).Path
    if (-not (Test-Path -LiteralPath $ArtifactSigningDlib -PathType Leaf)) {
        throw 'B13-4 Artifact Signing Dlib missing.'
    }
    if (-not (Test-Path -LiteralPath $ArtifactSigningMetadata -PathType Leaf)) {
        throw 'B13-4 Artifact Signing metadata missing.'
    }
}

if ($TrustLevel -eq 'PUBLIC_TRUST' -and $ExpectedPublisher -match '(?i)engineering|test') {
    throw 'B13-4 engineering/test publisher cannot be used for PUBLIC_TRUST.'
}

$SignTool = Resolve-SignTool $SignToolPath
$PreHash = (Get-FileHash -LiteralPath $ResolvedPath -Algorithm SHA256).Hash.ToLowerInvariant()

$signArgs = @(
    'sign',
    '/v',
    '/fd', 'SHA256',
    '/tr', $TimestampUrl,
    '/td', 'SHA256'
)

if ($Provider -eq 'CERTIFICATE_STORE') {
    $signArgs += @('/sha1', $CertificateThumbprint, '/s', 'My')
}
else {
    $signArgs += @('/debug', '/dlib', $ArtifactSigningDlib, '/dmdf', $ArtifactSigningMetadata)
}
$signArgs += $ResolvedPath

& $SignTool @signArgs
if ($LASTEXITCODE -ne 0) {
    throw ('B13-4 SignTool sign failed with exit code ' + $LASTEXITCODE)
}

$PostHash = (Get-FileHash -LiteralPath $ResolvedPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($PostHash -eq $PreHash) {
    throw 'B13-4 signing did not change artifact hash.'
}

$signature = Get-AuthenticodeSignature -FilePath $ResolvedPath
$authenticodePresent = ($null -ne $signature.SignerCertificate)
$timestampPresent = ($null -ne $signature.TimeStamperCertificate)
$statusText = [string]$signature.Status
$modifiedAfterSigning = ($statusText -eq 'HashMismatch')

if (-not $authenticodePresent) {
    throw 'B13-4 Authenticode signer certificate is missing after signing.'
}
if (-not $timestampPresent) {
    throw 'B13-4 RFC3161 timestamp certificate is missing after signing.'
}
if ($modifiedAfterSigning -or $statusText -eq 'NotSigned') {
    throw ('B13-4 signed artifact integrity verification failed: ' + $statusText)
}

$signerSubject = [string]$signature.SignerCertificate.Subject
$signerThumbprint = Normalize-Thumbprint ([string]$signature.SignerCertificate.Thumbprint)
$timestampSubject = [string]$signature.TimeStamperCertificate.Subject

if ($signerSubject -notlike ('*' + $ExpectedPublisher + '*')) {
    throw ('B13-4 signed publisher mismatch: ' + $signerSubject)
}

$verifyArgs = @('verify','/pa','/all','/v',$ResolvedPath)
& $SignTool @verifyArgs
$verifyExit = $LASTEXITCODE
$verifyPassed = ($verifyExit -eq 0)

if ($TrustLevel -eq 'PUBLIC_TRUST') {
    if ($statusText -ne 'Valid') {
        throw ('B13-4 PUBLIC_TRUST signature is not Windows-valid: ' + $statusText)
    }
    if (-not $verifyPassed) {
        throw 'B13-4 PUBLIC_TRUST SignTool verification failed.'
    }
}

$record = [ordered]@{
    name = [IO.Path]::GetFileName($ResolvedPath)
    path_role = $PathRole
    pre_sign_sha256 = $PreHash
    post_sign_sha256 = $PostHash
    authenticode_present = $authenticodePresent
    windows_signature_status = $statusText
    signer_subject = $signerSubject
    signer_thumbprint = $signerThumbprint
    timestamp_present = $timestampPresent
    timestamp_subject = $timestampSubject
    signtool_verify_passed = $verifyPassed
    modified_after_signing = $modifiedAfterSigning
}

$json = $record | ConvertTo-Json -Depth 5
if ($TrustLevel -eq 'ENGINEERING_TEST' -and -not $verifyPassed) {
    # Expected for self-signed engineering certificates: the signature mechanics
    # and timestamp exist, but the public trust chain intentionally does not.
    $global:LASTEXITCODE = 0
}

if ($OutputJson) {
    $parent = Split-Path -Parent $OutputJson
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    [IO.File]::WriteAllText($OutputJson, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

Write-Output $json
