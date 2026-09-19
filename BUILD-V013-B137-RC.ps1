param(
    [string]$OutputRoot = ".\dist\Beta13-B137-RC",
    [ValidateSet('CERTIFICATE_STORE')]
    [string]$Provider = 'CERTIFICATE_STORE',
    [ValidateSet('ENGINEERING_TEST')]
    [string]$TrustLevel = 'ENGINEERING_TEST',
    [string]$ExpectedPublisher = 'BC TECH Studio',
    [Parameter(Mandatory=$true)]
    [string]$CertificateThumbprint,
    [string]$TimestampUrl = 'http://timestamp.acs.microsoft.com'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = '1'

$repoRoot = (Resolve-Path $PSScriptRoot).Path
Set-Location -LiteralPath $repoRoot
$env:PYTHONPATH = $repoRoot

$commit = (& git rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Cannot resolve B13-7 build commit.'
}
& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Tracked working files differ from B13-7 build commit.'
}

if ([IO.Path]::IsPathRooted($OutputRoot)) {
    $resolvedOutput = $OutputRoot
} else {
    $resolvedOutput = Join-Path $repoRoot $OutputRoot
}
$resolvedOutput = [IO.Path]::GetFullPath($resolvedOutput)
$signingBuildRoot = Join-Path $resolvedOutput '_signed-build'
$bundleRoot = Join-Path $resolvedOutput 'BC-Sentinel-v0.13.0-RC1-Engineering'
$archivePath = Join-Path $resolvedOutput 'BC-Sentinel-v0.13.0-RC1-Engineering.zip'
$archiveHashPath = $archivePath + '.sha256'

if (Test-Path -LiteralPath $resolvedOutput) {
    Remove-Item -LiteralPath $resolvedOutput -Recurse -Force
}
New-Item -ItemType Directory -Path $bundleRoot -Force | Out-Null

$buildParams = @{
    OutputRoot = $signingBuildRoot
    Provider = $Provider
    TrustLevel = $TrustLevel
    ExpectedPublisher = $ExpectedPublisher
    CertificateThumbprint = $CertificateThumbprint
    TimestampUrl = $TimestampUrl
}
& (Join-Path $repoRoot 'BUILD-V013-B134-SIGNED-INSTALLER.ps1') @buildParams
if ($LASTEXITCODE -ne 0) {
    throw 'B13-7 inherited signed-installer build failed.'
}

$sourceInstaller = Join-Path $signingBuildRoot 'installer\BC-Sentinel-Setup-v0.13.0-b134.exe'
$sourceSigningEvidence = Join-Path $signingBuildRoot 'signing\signing-evidence.json'
if (-not (Test-Path -LiteralPath $sourceInstaller -PathType Leaf)) {
    throw 'B13-7 signed source installer missing.'
}
if (-not (Test-Path -LiteralPath $sourceSigningEvidence -PathType Leaf)) {
    throw 'B13-7 signing evidence missing.'
}

$installerTarget = Join-Path $bundleRoot 'BC-Sentinel-Setup-v0.13.0-RC1-Engineering.exe'
Copy-Item -LiteralPath $sourceInstaller -Destination $installerTarget -Force

$sourceHash = (Get-FileHash -LiteralPath $sourceInstaller -Algorithm SHA256).Hash.ToLowerInvariant()
$targetHash = (Get-FileHash -LiteralPath $installerTarget -Algorithm SHA256).Hash.ToLowerInvariant()
if ($sourceHash -ne $targetHash) {
    throw 'B13-7 installer bytes changed while assembling distribution.'
}

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m sentinel.beta13_release_candidate --write-metadata --root $bundleRoot --build-commit $commit --signing-evidence $sourceSigningEvidence
if ($LASTEXITCODE -ne 0) {
    throw 'B13-7 metadata generation failed.'
}

& $py -m sentinel.beta13_release_candidate --validate-root --root $bundleRoot --build-commit $commit
if ($LASTEXITCODE -ne 0) {
    throw 'B13-7 distribution-root validation failed.'
}

if (Test-Path -LiteralPath $archivePath) {
    Remove-Item -LiteralPath $archivePath -Force
}
Compress-Archive -Path (Join-Path $bundleRoot '*') -DestinationPath $archivePath -CompressionLevel Optimal -Force

if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
    throw 'B13-7 RC archive was not created.'
}
$archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath $archiveHashPath -Value ($archiveHash + '  ' + [IO.Path]::GetFileName($archivePath)) -Encoding ASCII

$manifest = Get-Content -LiteralPath (Join-Path $bundleRoot 'distribution-manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$provenance = Get-Content -LiteralPath (Join-Path $bundleRoot 'release-provenance.json') -Raw -Encoding UTF8 | ConvertFrom-Json

Write-Host ('B13-7 BUILD COMMIT=' + $commit)
Write-Host ('B13-7 DISTRIBUTION ROOT=' + $bundleRoot)
Write-Host ('B13-7 ARCHIVE=' + $archivePath)
Write-Host ('B13-7 ARCHIVE SHA256=' + $archiveHash)
Write-Host ('B13-7 INSTALLER SHA256=' + $manifest.installer_sha256)
Write-Host ('B13-7 MANIFEST DIGEST=' + $manifest.manifest_digest)
Write-Host ('B13-7 PROVENANCE DIGEST=' + $provenance.provenance_digest)
Write-Host 'B13-7 PUBLIC RELEASE READY=False / CODE_SIGNING BLOCKER REMAINS'
Write-Host 'BC SENTINEL v0.13.0 B13-7 ENGINEERING RELEASE CANDIDATE BUILD - PASS'
