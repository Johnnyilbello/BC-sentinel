param(
    [string]$OutputRoot = ".\dist\B13-B134",
    [Parameter(Mandatory=$true)][ValidateSet('CERTIFICATE_STORE','MICROSOFT_ARTIFACT_SIGNING')][string]$Provider,
    [Parameter(Mandatory=$true)][ValidateSet('ENGINEERING_TEST','PUBLIC_TRUST')][string]$TrustLevel,
    [Parameter(Mandatory=$true)][string]$ExpectedPublisher,
    [string]$CertificateThumbprint,
    [string]$ArtifactSigningDlib,
    [string]$ArtifactSigningMetadata,
    [string]$TimestampUrl = 'http://timestamp.acs.microsoft.com',
    [string]$SignToolPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$RepoRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
Set-Location -LiteralPath $RepoRoot

function Remove-BestEffort([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    try { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop }
    catch { Write-Host ('B13-4 cleanup warning: ' + $_.Exception.Message) -ForegroundColor DarkYellow }
}

function Resolve-BuildCommit {
    $value = (& git rev-parse --verify HEAD).Trim().ToLowerInvariant()
    if ($LASTEXITCODE -ne 0 -or $value -notmatch '^[0-9a-f]{40}$') {
        throw 'Cannot resolve exact B13-4 build commit.'
    }
    return $value
}

$Py = Join-Path $RepoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $Py -PathType Leaf)) {
    $Py = (Get-Command python -ErrorAction Stop).Source
}
& $Py -c "import PyInstaller, PySide6, cryptography"
if ($LASTEXITCODE -ne 0) { throw 'B13-4 build dependencies unavailable.' }

$BuildCommit = Resolve-BuildCommit
$PythonVersion = (& $Py -c "import platform; print(platform.python_version())").Trim()
$PyInstallerVersion = (& $Py -c "import PyInstaller; print(PyInstaller.__version__)").Trim()

if ([IO.Path]::IsPathRooted($OutputRoot)) {
    $OutRoot = $OutputRoot
} else {
    $OutRoot = Join-Path $RepoRoot $OutputRoot
}
$PayloadRoot = Join-Path $OutRoot 'payload'
$ProductRoot = Join-Path $PayloadRoot 'BC-Sentinel'
$InstallerRoot = Join-Path $OutRoot 'installer'
$SigningRoot = Join-Path $OutRoot 'signing'
$InstallerPath = Join-Path $InstallerRoot 'BC-Sentinel-Setup-v0.13.0-b134.exe'
$PayloadManifest = Join-Path $ProductRoot 'install-payload-manifest.json'
$UninstallInclude = Join-Path $OutRoot 'payload-uninstall.nsh'
$ApplicationRecord = Join-Path $SigningRoot 'application-signature.json'
$InstallerRecord = Join-Path $SigningRoot 'installer-signature.json'
$UninstallerRecord = Join-Path $SigningRoot 'uninstaller-signature.json'
$SigningEvidence = Join-Path $SigningRoot 'signing-evidence.json'

Remove-BestEffort $OutRoot
New-Item -ItemType Directory -Path $PayloadRoot, $InstallerRoot, $SigningRoot -Force | Out-Null

$WorkBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b134-build-' + [guid]::NewGuid().ToString('N'))
$UnsignedRoot = Join-Path $WorkBase 'unsigned-b133'
$NsisRoot = Join-Path $WorkBase 'nsis'
$NsisZip = Join-Path $WorkBase 'nsis-3.12.zip'
$SigningConfig = Join-Path $WorkBase 'signing-config.json'
$UninstallWrapper = Join-Path $WorkBase 'sign-uninstaller.ps1'

try {
    $B133Build = Join-Path $RepoRoot 'BUILD-V013-B133-INSTALLER.ps1'
    & $B133Build -OutputRoot $UnsignedRoot
    if ($LASTEXITCODE -ne 0) { throw 'B13-4 precursor B13-3 payload build failed.' }

    $UnsignedProduct = Join-Path $UnsignedRoot 'payload\BC-Sentinel'
    if (-not (Test-Path -LiteralPath $UnsignedProduct -PathType Container)) {
        throw 'B13-4 precursor payload missing.'
    }
    Copy-Item -LiteralPath $UnsignedProduct -Destination $ProductRoot -Recurse -Force

    $ApplicationExe = Join-Path $ProductRoot 'BC-Sentinel.exe'
    if (-not (Test-Path -LiteralPath $ApplicationExe -PathType Leaf)) {
        throw 'B13-4 packaged application executable missing.'
    }

    $SignScript = Join-Path $RepoRoot 'tools\signing\SIGN-V013-B134-ARTIFACT.ps1'
    if (-not (Test-Path -LiteralPath $SignScript -PathType Leaf)) {
        throw 'B13-4 signing script missing.'
    }

    $CommonSign = @{
        Provider = $Provider
        TrustLevel = $TrustLevel
        ExpectedPublisher = $ExpectedPublisher
        TimestampUrl = $TimestampUrl
    }
    if ($CertificateThumbprint) { $CommonSign['CertificateThumbprint'] = $CertificateThumbprint }
    if ($ArtifactSigningDlib) { $CommonSign['ArtifactSigningDlib'] = $ArtifactSigningDlib }
    if ($ArtifactSigningMetadata) { $CommonSign['ArtifactSigningMetadata'] = $ArtifactSigningMetadata }
    if ($SignToolPath) { $CommonSign['SignToolPath'] = $SignToolPath }

    & $SignScript -Path $ApplicationExe -PathRole 'APPLICATION_EXE' -OutputJson $ApplicationRecord @CommonSign
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $ApplicationRecord -PathType Leaf)) {
        throw 'B13-4 application signing failed.'
    }

    $ManifestArgs = @(
        '-m','sentinel.beta13_installer',
        '--write-payload-manifest',
        '--root',$ProductRoot,
        '--build-commit',$BuildCommit,
        '--python-version',$PythonVersion,
        '--pyinstaller-version',$PyInstallerVersion
    )
    & $Py @ManifestArgs
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $PayloadManifest -PathType Leaf)) {
        throw 'B13-4 signed payload manifest generation failed.'
    }

    $ValidateManifestArgs = @(
        '-m','sentinel.beta13_installer',
        '--validate-payload-manifest',
        '--payload-manifest',$PayloadManifest,
        '--root',$ProductRoot,
        '--build-commit',$BuildCommit
    )
    & $Py @ValidateManifestArgs
    if ($LASTEXITCODE -ne 0) { throw 'B13-4 signed payload manifest verification failed.' }

    & $Py -c "import json,sys; from pathlib import Path; from sentinel.beta13_installer import uninstall_include; d=json.loads(Path(sys.argv[1]).read_text(encoding='utf-8')); Path(sys.argv[2]).write_text(uninstall_include(d),encoding='utf-8')" $PayloadManifest $UninstallInclude
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $UninstallInclude -PathType Leaf)) {
        throw 'B13-4 uninstall include generation failed.'
    }

    $config = [ordered]@{
        provider = $Provider
        trust_level = $TrustLevel
        expected_publisher = $ExpectedPublisher
        certificate_thumbprint = $CertificateThumbprint
        artifact_signing_dlib = $ArtifactSigningDlib
        artifact_signing_metadata = $ArtifactSigningMetadata
        timestamp_url = $TimestampUrl
        signtool_path = $SignToolPath
        sign_script = $SignScript
        output_json = $UninstallerRecord
    }
    [IO.File]::WriteAllText(
        $SigningConfig,
        (($config | ConvertTo-Json -Depth 5) + [Environment]::NewLine),
        [Text.UTF8Encoding]::new($false)
    )

    $wrapper = @'
param([Parameter(Mandatory=$true)][string]$TargetPath)
$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath '__CONFIG__' -Raw -Encoding UTF8 | ConvertFrom-Json
$params = @{
    Path = $TargetPath
    PathRole = 'UNINSTALLER_EXE'
    Provider = [string]$config.provider
    TrustLevel = [string]$config.trust_level
    ExpectedPublisher = [string]$config.expected_publisher
    TimestampUrl = [string]$config.timestamp_url
    OutputJson = [string]$config.output_json
}
if ($config.certificate_thumbprint) { $params['CertificateThumbprint'] = [string]$config.certificate_thumbprint }
if ($config.artifact_signing_dlib) { $params['ArtifactSigningDlib'] = [string]$config.artifact_signing_dlib }
if ($config.artifact_signing_metadata) { $params['ArtifactSigningMetadata'] = [string]$config.artifact_signing_metadata }
if ($config.signtool_path) { $params['SignToolPath'] = [string]$config.signtool_path }
& ([string]$config.sign_script) @params
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
'@
    $wrapper = $wrapper.Replace('__CONFIG__', $SigningConfig.Replace("'", "''"))
    [IO.File]::WriteAllText($UninstallWrapper, $wrapper, [Text.UTF8Encoding]::new($false))

    $NsisUrl = 'https://downloads.sourceforge.net/project/nsis/NSIS%203/3.12/nsis-3.12.zip'
    $ExpectedNsisHash = '56581f90db321581c5381193d796fffcf2d24b2f8fed2160a6c6a3baa67f2c4f'
    $Curl = (Get-Command curl.exe -ErrorAction Stop).Source
    & $Curl -L --fail --silent --show-error --retry 4 --retry-delay 2 --output $NsisZip $NsisUrl
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $NsisZip -PathType Leaf)) {
        throw 'B13-4 verified NSIS ZIP download failed.'
    }
    if ((Get-Item -LiteralPath $NsisZip).Length -ne 2362938) {
        throw 'B13-4 NSIS ZIP size mismatch.'
    }
    $NsisHash = (Get-FileHash -LiteralPath $NsisZip -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($NsisHash -ne $ExpectedNsisHash) {
        throw ('B13-4 NSIS ZIP SHA256 mismatch: ' + $NsisHash)
    }

    Expand-Archive -LiteralPath $NsisZip -DestinationPath $NsisRoot -Force
    $MakeNsis = Get-ChildItem -LiteralPath $NsisRoot -Recurse -Filter 'makensis.exe' -File |
        Where-Object { $_.FullName -notmatch '\\Bin\\' } |
        Select-Object -First 1
    if (-not $MakeNsis) {
        $MakeNsis = Get-ChildItem -LiteralPath $NsisRoot -Recurse -Filter 'makensis.exe' -File | Select-Object -First 1
    }
    if (-not $MakeNsis) { throw 'B13-4 makensis.exe missing from verified NSIS archive.' }

    $Nsi = Join-Path $RepoRoot 'packaging\beta13_b134_installer.nsi'
    $PayloadDefine = '/DPAYLOAD_DIR=' + $ProductRoot
    $OutputDefine = '/DOUTPUT_DIR=' + $InstallerRoot
    $UninstallDefine = '/DUNINSTALL_INCLUDE=' + $UninstallInclude
    $SignWrapperDefine = '/DUNINSTALL_SIGN_WRAPPER=' + $UninstallWrapper

    & $MakeNsis.FullName /V3 $PayloadDefine $OutputDefine $UninstallDefine $SignWrapperDefine $Nsi
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
        throw 'B13-4 signed-uninstaller NSIS compilation failed.'
    }
    if (-not (Test-Path -LiteralPath $UninstallerRecord -PathType Leaf)) {
        throw 'B13-4 uninstaller signing evidence missing.'
    }

    & $SignScript -Path $InstallerPath -PathRole 'INSTALLER_EXE' -OutputJson $InstallerRecord @CommonSign
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $InstallerRecord -PathType Leaf)) {
        throw 'B13-4 installer signing failed.'
    }

    & $Py -c "import json,sys; from pathlib import Path; from sentinel.beta13_code_signing import build_signing_evidence,validate_signing_evidence; app=json.loads(Path(sys.argv[1]).read_text(encoding='utf-8')); ins=json.loads(Path(sys.argv[2]).read_text(encoding='utf-8')); uni=json.loads(Path(sys.argv[3]).read_text(encoding='utf-8')); evidence=build_signing_evidence(build_commit=sys.argv[5],provider=sys.argv[6],trust_level=sys.argv[7],expected_publisher=sys.argv[8],artifacts=[app,ins,uni],timestamp_url=sys.argv[9]); Path(sys.argv[4]).write_text(json.dumps(evidence,indent=2,sort_keys=True)+'\n',encoding='utf-8'); failures=validate_signing_evidence(evidence,expected_build_commit=sys.argv[5]); assert not failures,failures; print(json.dumps(evidence,indent=2,sort_keys=True))" $ApplicationRecord $InstallerRecord $UninstallerRecord $SigningEvidence $BuildCommit $Provider $TrustLevel $ExpectedPublisher $TimestampUrl
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $SigningEvidence -PathType Leaf)) {
        throw 'B13-4 signing evidence generation failed.'
    }

    $evidence = Get-Content -LiteralPath $SigningEvidence -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not [bool]$evidence.pipeline_evidence_valid) {
        throw 'B13-4 signing pipeline evidence is invalid.'
    }
    if ($TrustLevel -eq 'PUBLIC_TRUST' -and -not [bool]$evidence.public_trust_signature_verified) {
        throw 'B13-4 PUBLIC_TRUST signing did not verify.'
    }
    if ($TrustLevel -eq 'ENGINEERING_TEST' -and [bool]$evidence.code_signing_release_blocker_resolved) {
        throw 'B13-4 engineering signing incorrectly resolved CODE_SIGNING.'
    }

    Write-Host ('B13-4 BUILD COMMIT=' + $BuildCommit)
    Write-Host ('B13-4 PROVIDER=' + $Provider + ' TRUST=' + $TrustLevel)
    Write-Host ('B13-4 APPLICATION SIGNED=' + $ApplicationRecord)
    Write-Host ('B13-4 UNINSTALLER SIGNED=' + $UninstallerRecord)
    Write-Host ('B13-4 INSTALLER SIGNED=' + $InstallerRecord)
    Write-Host ('B13-4 SIGNING EVIDENCE=' + $SigningEvidence)
    Write-Host ('B13-4 PUBLIC TRUST VERIFIED=' + [bool]$evidence.public_trust_signature_verified)
    Write-Host 'BC SENTINEL v0.13.0 B13-4 SIGNED WINDOWS BUILD - PASS'
}
finally {
    Remove-BestEffort $WorkBase
}
