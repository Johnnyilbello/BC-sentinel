param([switch]$ConfirmCodeSigningReadiness)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location -LiteralPath $repoRoot
$env:PYTHONPATH = $repoRoot

if (-not $ConfirmCodeSigningReadiness) {
    throw 'Explicit Beta13 B13-4 code-signing readiness confirmation required.'
}

$commit = (& git rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Cannot resolve B13-4 acceptance commit.'
}
Write-Host ('B13-4 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B13-4 acceptance commit.' }

$frozen = 'b6014ef74ffc77814f489532c8f2d09fb92fe17f'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted Beta13 B13-3 predecessor missing.' }

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
$changes = @(& git diff --name-only $frozen HEAD)
$allowed = @(
    '.github/workflows/b134-code-signing-smartscreen-readiness.yml',
    'BUILD-V013-B134-SIGNED-INSTALLER.ps1',
    'ROADMAP.md',
    'packaging/beta13_b134_installer.nsi',
    'sentinel/beta13_code_signing.py',
    'tests/test_v013_b134_code_signing.py',
    'tools/acceptance/TEST-V013-B134-CODE-SIGNING.ps1',
    'tools/signing/SIGN-V013-B134-ARTIFACT.ps1'
)
if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B13-4 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) { throw ('Unexpected B13-4 changed path: ' + $path) }
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B13-3 path changed: ' + $path)
    }
}
Write-Host 'Accepted B13-3 source immutability and repository hygiene: PASS'

$existingProductKey = 'Registry::HKEY_CURRENT_USER\Software\BC TECH Studio\BC Sentinel'
$existingUninstallKey = 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\BCSentinel'
$startMenuDir = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\BC Sentinel'
if ((Test-Path $existingProductKey) -or (Test-Path $existingUninstallKey) -or (Test-Path -LiteralPath $startMenuDir)) {
    throw 'An existing BC Sentinel per-user installation is present; B13-4 acceptance refuses to overwrite it.'
}

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta13_code_signing.py tests/test_v013_b134_code_signing.py
if ($LASTEXITCODE -ne 0) { throw 'B13-4 compile failed.' }

$patterns = @(
    'tests/test_v011_beta5_*.py',
    'tests/test_v011_beta6_*.py',
    'tests/test_v011_beta7_*.py',
    'tests/test_v011_beta8_*.py',
    'tests/test_v011_beta9_*.py',
    'tests/test_v011_beta10_*.py',
    'tests/test_v011_beta11_*.py',
    'tests/test_v012_beta12_*.py',
    'tests/test_v013_*.py'
)
$tests = @(
    $patterns |
        ForEach-Object { Get-ChildItem $_ } |
        Sort-Object FullName |
        ForEach-Object { $_.FullName }
)
$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b134-pytest-' + [guid]::NewGuid().ToString('N'))
try {
    & $py -m pytest -q --basetemp $testBase @tests
    if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta13 B13-4 regression failed.' }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

& $py -m sentinel.beta13_code_signing
if ($LASTEXITCODE -ne 0) { throw 'B13-4 code-signing contract self-check failed.' }

$acceptRoot = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b134-accept-' + [guid]::NewGuid().ToString('N'))
$buildRoot = Join-Path $acceptRoot 'build'
$lifecycleRoot = Join-Path $acceptRoot 'lifecycle'
$installRoot = Join-Path $lifecycleRoot 'installed-product'
$installer = Join-Path $buildRoot 'installer\BC-Sentinel-Setup-v0.13.0-b134.exe'
$appRecordPath = Join-Path $buildRoot 'signing\application-signature.json'
$installerRecordPath = Join-Path $buildRoot 'signing\installer-signature.json'
$uninstallerRecordPath = Join-Path $buildRoot 'signing\uninstaller-signature.json'
$evidencePath = Join-Path $buildRoot 'signing\signing-evidence.json'
$installedExe = Join-Path $installRoot 'BC-Sentinel.exe'
$uninstaller = Join-Path $installRoot 'Uninstall.exe'
$engineeringCert = $null
$installed = $false

New-Item -ItemType Directory -Path $lifecycleRoot -Force | Out-Null

try {
    $certParams = @{
        Type = 'CodeSigningCert'
        Subject = 'CN=BC TECH Studio Engineering Test'
        CertStoreLocation = 'Cert:\CurrentUser\My'
        KeyAlgorithm = 'RSA'
        KeyLength = 2048
        HashAlgorithm = 'SHA256'
        NotAfter = (Get-Date).AddDays(7)
    }
    $engineeringCert = New-SelfSignedCertificate @certParams

    if (-not $engineeringCert -or -not $engineeringCert.HasPrivateKey) {
        throw 'B13-4 failed to create ephemeral engineering code-signing certificate.'
    }
    $thumbprint = ([string]$engineeringCert.Thumbprint).Replace(' ','').ToLowerInvariant()

    $buildParams = @{
        OutputRoot = $buildRoot
        Provider = 'CERTIFICATE_STORE'
        TrustLevel = 'ENGINEERING_TEST'
        ExpectedPublisher = 'BC TECH Studio'
        CertificateThumbprint = $thumbprint
        TimestampUrl = 'http://timestamp.acs.microsoft.com'
    }
    $previousForceBootstrap = $env:BC_SENTINEL_B134_FORCE_SIGTOOL_BOOTSTRAP
    $env:BC_SENTINEL_B134_FORCE_SIGTOOL_BOOTSTRAP = '1'
    & (Join-Path $repoRoot 'BUILD-V013-B134-SIGNED-INSTALLER.ps1') @buildParams
    if ($LASTEXITCODE -ne 0) { throw 'B13-4 signed engineering build failed.' }

    foreach ($required in @($installer,$appRecordPath,$installerRecordPath,$uninstallerRecordPath,$evidencePath)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw ('B13-4 required signed-build artifact missing: ' + $required)
        }
    }

    $evidence = Get-Content -LiteralPath $evidencePath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not [bool]$evidence.pipeline_evidence_valid) {
        throw 'B13-4 engineering signing evidence is invalid.'
    }
    if ([bool]$evidence.public_trust_signature_verified) {
        throw 'B13-4 engineering certificate incorrectly classified as public trust.'
    }
    if ([bool]$evidence.code_signing_release_blocker_resolved) {
        throw 'B13-4 engineering signature incorrectly resolved CODE_SIGNING.'
    }
    if ([string]$evidence.trust_level -ne 'ENGINEERING_TEST') {
        throw 'B13-4 engineering trust level mismatch.'
    }

    $appRecord = Get-Content -LiteralPath $appRecordPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $installerRecord = Get-Content -LiteralPath $installerRecordPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $uninstallerRecord = Get-Content -LiteralPath $uninstallerRecordPath -Raw -Encoding UTF8 | ConvertFrom-Json

    foreach ($record in @($appRecord,$installerRecord,$uninstallerRecord)) {
        if (-not [bool]$record.authenticode_present -or -not [bool]$record.timestamp_present) {
            throw 'B13-4 engineering artifact is missing Authenticode or timestamp evidence.'
        }
        if (([string]$record.signer_thumbprint).ToLowerInvariant() -ne $thumbprint) {
            throw 'B13-4 engineering signer thumbprint drift.'
        }
        if ([bool]$record.modified_after_signing) {
            throw 'B13-4 engineering artifact was modified after signing.'
        }
    }

    $installerSignature = Get-AuthenticodeSignature -FilePath $installer
    if ($null -eq $installerSignature.SignerCertificate -or $null -eq $installerSignature.TimeStamperCertificate) {
        throw 'B13-4 final installer signature/timestamp missing.'
    }
    if ([string]$installerSignature.Status -in @('NotSigned','HashMismatch')) {
        throw ('B13-4 final installer signature integrity failed: ' + [string]$installerSignature.Status)
    }

    $installProcess = Start-Process -FilePath $installer -ArgumentList @('/S',('/D=' + $installRoot)) -Wait -PassThru
    if ($installProcess.ExitCode -ne 0) { throw ('B13-4 installer exited with ' + $installProcess.ExitCode) }
    $installed = $true

    if (-not (Test-Path -LiteralPath $installedExe -PathType Leaf)) { throw 'B13-4 installed application missing.' }
    if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) { throw 'B13-4 installed uninstaller missing.' }

    $installedAppHash = (Get-FileHash -LiteralPath $installedExe -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($installedAppHash -ne ([string]$appRecord.post_sign_sha256).ToLowerInvariant()) {
        throw 'B13-4 installed application hash differs from signed payload.'
    }
    $installedUninstallerHash = (Get-FileHash -LiteralPath $uninstaller -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($installedUninstallerHash -ne ([string]$uninstallerRecord.post_sign_sha256).ToLowerInvariant()) {
        throw 'B13-4 installed uninstaller hash differs from signed NSIS uninstaller.'
    }

    foreach ($artifactPath in @($installedExe,$uninstaller)) {
        $sig = Get-AuthenticodeSignature -FilePath $artifactPath
        if ($null -eq $sig.SignerCertificate -or $null -eq $sig.TimeStamperCertificate) {
            throw ('B13-4 installed Authenticode evidence missing: ' + $artifactPath)
        }
        if (([string]$sig.SignerCertificate.Thumbprint).Replace(' ','').ToLowerInvariant() -ne $thumbprint) {
            throw ('B13-4 installed publisher thumbprint mismatch: ' + $artifactPath)
        }
        if ([string]$sig.Status -in @('NotSigned','HashMismatch')) {
            throw ('B13-4 installed signature integrity failed: ' + [string]$sig.Status)
        }
    }

    $selfCheck = Start-Process -FilePath $installedExe -ArgumentList @('--self-check') -Wait -PassThru
    if ($selfCheck.ExitCode -ne 0) { throw ('B13-4 installed self-check failed exit=' + $selfCheck.ExitCode) }

    $smoke = Start-Process -FilePath $installedExe -ArgumentList @('--smoke') -Wait -PassThru
    if ($smoke.ExitCode -ne 0) { throw ('B13-4 installed UI smoke failed exit=' + $smoke.ExitCode) }

    $uninstallProcess = Start-Process -FilePath $uninstaller -ArgumentList @('/S') -Wait -PassThru
    if ($uninstallProcess.ExitCode -ne 0) { throw ('B13-4 uninstaller exited with ' + $uninstallProcess.ExitCode) }
    $installed = $false
    Start-Sleep -Milliseconds 800

    if (Test-Path -LiteralPath $installedExe) { throw 'B13-4 uninstall left application executable behind.' }
    if ((Test-Path $existingProductKey) -or (Test-Path $existingUninstallKey)) {
        throw 'B13-4 uninstall left per-user registry metadata behind.'
    }

    & $py -c "import json,sys; from pathlib import Path; from sentinel.beta13_code_signing import validate_signing_evidence,self_check; e=json.loads(Path(sys.argv[1]).read_text(encoding='utf-8')); f=validate_signing_evidence(e,expected_build_commit=sys.argv[2]); assert not f,f; assert e['pipeline_evidence_valid']; assert e['public_trust_signature_verified'] is False; assert e['code_signing_release_blocker_resolved'] is False; r=self_check(); p=r['engineering_readiness_projection']; assert p['pillar_counts']=={'READY':7,'PARTIAL':1,'BLOCKED':2}; assert p['release_blockers']==['CODE_SIGNING','LICENSING_TRIAL','PRIVACY_SUPPORT']; print(json.dumps({'b13_4_pipeline_passed':True,'contract_digest':r['contract_digest'],'signing_evidence_digest':e['evidence_digest'],'trust_level':e['trust_level'],'public_trust_signature_verified':e['public_trust_signature_verified'],'code_signing_release_blocker_resolved':e['code_signing_release_blocker_resolved'],'release_blockers':p['release_blockers']},indent=2,sort_keys=True))" $evidencePath $commit
    if ($LASTEXITCODE -ne 0) { throw 'B13-4 final signing-evidence assertions failed.' }

    Write-Host 'B13-4 engineering signing: application=SIGNED installer=SIGNED uninstaller=SIGNED timestamp=RFC3161'
    Write-Host 'B13-4 lifecycle: install=PASS packaged_self_check=PASS packaged_ui_smoke=PASS uninstall=PASS'
    Write-Host 'B13-4 public trust: NOT_CLAIMED / CODE_SIGNING BLOCKER REMAINS'
    Write-Host 'B13-4 SmartScreen: REPUTATION_NOT_GUARANTEED / CONSISTENT_SIGNER_POLICY_READY'
    Write-Host 'BC SENTINEL v0.13.0 B13-4 CODE SIGNING & SMARTSCREEN READINESS PIPELINE - PASS'
}
finally {
    if (Get-Variable -Name previousForceBootstrap -Scope Local -ErrorAction SilentlyContinue) {
        $env:BC_SENTINEL_B134_FORCE_SIGTOOL_BOOTSTRAP = $previousForceBootstrap
    }
    if ($installed -and (Test-Path -LiteralPath $uninstaller -PathType Leaf)) {
        try { Start-Process -FilePath $uninstaller -ArgumentList @('/S') -Wait | Out-Null } catch {}
    }
    if ($engineeringCert) {
        try {
            Remove-Item -LiteralPath ('Cert:\CurrentUser\My\' + $engineeringCert.Thumbprint) -Force -ErrorAction SilentlyContinue
        }
        catch {}
    }
    try {
        if (Test-Path $existingProductKey) { Remove-Item $existingProductKey -Recurse -Force -ErrorAction SilentlyContinue }
        if (Test-Path $existingUninstallKey) { Remove-Item $existingUninstallKey -Recurse -Force -ErrorAction SilentlyContinue }
        if (Test-Path -LiteralPath $startMenuDir) { Remove-Item -LiteralPath $startMenuDir -Recurse -Force -ErrorAction SilentlyContinue }
        if (Test-Path -LiteralPath $acceptRoot) { Remove-Item -LiteralPath $acceptRoot -Recurse -Force -ErrorAction SilentlyContinue }
    }
    catch {}
}
