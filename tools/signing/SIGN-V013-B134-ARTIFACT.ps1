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

function Test-MicrosoftSignedTool([string]$ToolPath, [string]$Label) {
    if (-not (Test-Path -LiteralPath $ToolPath -PathType Leaf)) {
        throw ('B13-4 ' + $Label + ' tool file missing.')
    }
    $signature = Get-AuthenticodeSignature -FilePath $ToolPath
    if ([string]$signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate) {
        throw ('B13-4 ' + $Label + ' Authenticode verification failed: ' + [string]$signature.Status)
    }
    $subject = [string]$signature.SignerCertificate.Subject
    if ($subject -notmatch '(?i)Microsoft') {
        throw ('B13-4 ' + $Label + ' signer is not Microsoft: ' + $subject)
    }
}

function Install-PinnedSignTool {
    $buildToolsVersion = '10.0.28000.2705'
    $expectedPackageSha256 = '8bfdfb6ca2633f531cf80b5fa22512ba61a394d7988f0970db83baadc67929ed'
    $localAppData = [Environment]::GetFolderPath('LocalApplicationData')
    if (-not $localAppData) {
        throw 'B13-4 LOCALAPPDATA is unavailable for SignTool bootstrap.'
    }

    $cacheRoot = Join-Path $localAppData 'BCSentinel\ToolCache\B134'
    $packagePath = Join-Path $cacheRoot ('Microsoft.Windows.SDK.BuildTools.' + $buildToolsVersion + '.nupkg')
    $extractRoot = Join-Path $cacheRoot ('Microsoft.Windows.SDK.BuildTools.' + $buildToolsVersion)
    $packageUrl = 'https://www.nuget.org/api/v2/package/Microsoft.Windows.SDK.BuildTools/' + $buildToolsVersion

    function Find-PinnedSignTool([string]$Root) {
        if (-not (Test-Path -LiteralPath $Root -PathType Container)) { return $null }
        return Get-ChildItem -LiteralPath $Root -Recurse -Filter signtool.exe -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
            Sort-Object FullName -Descending |
            Select-Object -First 1
    }

    if ((Test-Path -LiteralPath $packagePath -PathType Leaf) -and (Test-Path -LiteralPath $extractRoot -PathType Container)) {
        $cachedHash = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()
        $cached = Find-PinnedSignTool $extractRoot
        if ($cachedHash -eq $expectedPackageSha256 -and $cached) {
            Test-MicrosoftSignedTool $cached.FullName 'cached SignTool'
            Write-Host ('B13-4 BuildTools package SHA256: ' + $cachedHash)
            Write-Host ('B13-4 SignTool source: PINNED_NUGET_CACHE ' + $cached.FullName)
            return $cached.FullName
        }
        Write-Host 'B13-4 pinned SignTool cache failed package-integrity validation; rebuilding.' -ForegroundColor DarkYellow
        if (Test-Path -LiteralPath $packagePath) { Remove-Item -LiteralPath $packagePath -Force -ErrorAction SilentlyContinue }
        if (Test-Path -LiteralPath $extractRoot) { Remove-Item -LiteralPath $extractRoot -Recurse -Force -ErrorAction SilentlyContinue }
    }

    New-Item -ItemType Directory -Path $cacheRoot -Force | Out-Null
    $bootstrapId = [guid]::NewGuid().ToString('N')
    $tempPackage = Join-Path $cacheRoot ('download-' + $bootstrapId + '.nupkg')
    $tempExtract = Join-Path $cacheRoot ('extract-' + $bootstrapId)

    try {
        $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
        if ($curl) {
            & $curl.Source -L --fail --silent --show-error --retry 4 --retry-delay 2 --output $tempPackage $packageUrl
            if ($LASTEXITCODE -ne 0) {
                throw ('B13-4 BuildTools package download failed with exit code ' + $LASTEXITCODE)
            }
        }
        else {
            Invoke-WebRequest -UseBasicParsing -Uri $packageUrl -OutFile $tempPackage
        }

        if (-not (Test-Path -LiteralPath $tempPackage -PathType Leaf)) {
            throw 'B13-4 BuildTools package download did not produce a file.'
        }

        $actualPackageSha256 = (Get-FileHash -LiteralPath $tempPackage -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualPackageSha256 -ne $expectedPackageSha256) {
            throw ('B13-4 BuildTools package SHA256 mismatch: ' + $actualPackageSha256)
        }

        New-Item -ItemType Directory -Path $tempExtract -Force | Out-Null
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::ExtractToDirectory($tempPackage, $tempExtract)

        $candidate = Find-PinnedSignTool $tempExtract
        if (-not $candidate) {
            throw 'B13-4 pinned Windows SDK BuildTools package did not contain x64 SignTool.exe.'
        }
        Test-MicrosoftSignedTool $candidate.FullName 'bootstrapped SignTool'

        if (Test-Path -LiteralPath $extractRoot) {
            Remove-Item -LiteralPath $extractRoot -Recurse -Force
        }
        if (Test-Path -LiteralPath $packagePath) {
            Remove-Item -LiteralPath $packagePath -Force
        }

        Move-Item -LiteralPath $tempExtract -Destination $extractRoot
        Move-Item -LiteralPath $tempPackage -Destination $packagePath

        $finalCandidate = Find-PinnedSignTool $extractRoot
        if (-not $finalCandidate) {
            throw 'B13-4 cached SignTool missing after atomic BuildTools bootstrap.'
        }
        Test-MicrosoftSignedTool $finalCandidate.FullName 'bootstrapped SignTool'
        Write-Host ('B13-4 BuildTools package SHA256: ' + $expectedPackageSha256)
        Write-Host ('B13-4 SignTool source: PINNED_NUGET_BOOTSTRAP ' + $finalCandidate.FullName)
        return $finalCandidate.FullName
    }
    finally {
        if (Test-Path -LiteralPath $tempPackage) {
            Remove-Item -LiteralPath $tempPackage -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $tempExtract) {
            Remove-Item -LiteralPath $tempExtract -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Resolve-SignTool([string]$ExplicitPath) {
    if ($ExplicitPath) {
        $resolved = (Resolve-Path -LiteralPath $ExplicitPath -ErrorAction Stop).Path
        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
            throw 'B13-4 SignTool path is not a file.'
        }
        return $resolved
    }

    $forceBootstrap = ([string]$env:BC_SENTINEL_B134_FORCE_SIGTOOL_BOOTSTRAP -eq '1')
    if (-not $forceBootstrap) {
        $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
        if ($command) {
            Write-Host ('B13-4 SignTool source: PATH ' + $command.Source)
            return $command.Source
        }

        $programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
        if ($programFilesX86) {
            $sdkRoot = Join-Path $programFilesX86 'Windows Kits\10\bin'
            if (Test-Path -LiteralPath $sdkRoot) {
                $candidate = Get-ChildItem -LiteralPath $sdkRoot -Recurse -Filter signtool.exe -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
                    Sort-Object FullName -Descending |
                    Select-Object -First 1
                if ($candidate) {
                    Write-Host ('B13-4 SignTool source: WINDOWS_SDK ' + $candidate.FullName)
                    return $candidate.FullName
                }
            }
        }
    }

    return Install-PinnedSignTool
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
