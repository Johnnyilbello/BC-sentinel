param([switch]$ConfirmCleanPcLifecycleAcceptance)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location -LiteralPath $repoRoot
$env:PYTHONPATH = $repoRoot

if (-not $ConfirmCleanPcLifecycleAcceptance) {
    throw 'Explicit Beta13 B13-5 clean-PC lifecycle acceptance confirmation required.'
}

$commit = (& git rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Cannot resolve B13-5 acceptance commit.'
}
Write-Host ('B13-5 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B13-5 acceptance commit.' }

$frozen = 'c2dc1b0df4becc18afa56915bb47b29b533a9a55'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted Beta13 B13-4 predecessor missing.' }

$checkpointSha = (& git rev-parse 'refs/remotes/origin/checkpoint/v013-b134-pass' 2>$null)
if ($LASTEXITCODE -ne 0) {
    $checkpointSha = (& git rev-parse 'checkpoint/v013-b134-pass' 2>$null)
}
if ($LASTEXITCODE -ne 0 -or ([string]$checkpointSha).Trim().ToLowerInvariant() -ne $frozen) {
    throw 'B13-4 immutable checkpoint is missing or points to the wrong commit.'
}

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
$changes = @(& git diff --name-only $frozen HEAD)
$allowed = @(
    '.github/workflows/b135-clean-pc-lifecycle-acceptance.yml',
    'ROADMAP.md',
    'sentinel/beta13_clean_pc_lifecycle.py',
    'tests/test_v013_b135_clean_pc_lifecycle.py',
    'tools/acceptance/TEST-V013-B135-CLEAN-PC-LIFECYCLE.ps1'
)
if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B13-5 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) { throw ('Unexpected B13-5 changed path: ' + $path) }
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B13-4 path changed: ' + $path)
    }
}
Write-Host 'Accepted B13-4 source immutability and repository hygiene: PASS'

$environment = 'LOCAL_GUARDED_REHEARSAL'
$authoritativeCleanPc = $false
if ([string]$env:GITHUB_ACTIONS -eq 'true' -and [string]$env:RUNNER_OS -eq 'Windows') {
    $environment = 'DISPOSABLE_WINDOWS_CI_RUNNER'
    $authoritativeCleanPc = $true
}
Write-Host ('B13-5 environment classification: ' + $environment)
Write-Host ('B13-5 authoritative clean-PC evidence: ' + $authoritativeCleanPc)

$existingProductKey = 'Registry::HKEY_CURRENT_USER\Software\BC TECH Studio\BC Sentinel'
$existingUninstallKey = 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\BCSentinel'
$startMenuDir = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\BC Sentinel'
$serviceKey = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BCSentinel'
$runKey = 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'

if ((Test-Path $existingProductKey) -or (Test-Path $existingUninstallKey) -or (Test-Path -LiteralPath $startMenuDir)) {
    throw 'An existing BC Sentinel per-user installation is present; B13-5 refuses to overwrite it.'
}
if ((Get-Service -Name 'BCSentinel' -ErrorAction SilentlyContinue) -or (Test-Path $serviceKey)) {
    throw 'An existing BC Sentinel service/driver registration is present; B13-5 refuses to continue.'
}

function Test-BCSentinelRunEntry {
    if (-not (Test-Path $runKey)) { return $false }
    $props = Get-ItemProperty -Path $runKey -ErrorAction SilentlyContinue
    if (-not $props) { return $false }
    return (
        $null -ne $props.PSObject.Properties['BC Sentinel'] -or
        $null -ne $props.PSObject.Properties['BCSentinel']
    )
}
if (Test-BCSentinelRunEntry) {
    throw 'An existing BC Sentinel autostart entry is present; B13-5 refuses to continue.'
}

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta13_clean_pc_lifecycle.py tests/test_v013_b135_clean_pc_lifecycle.py
if ($LASTEXITCODE -ne 0) { throw 'B13-5 compile failed.' }

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
$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b135-pytest-' + [guid]::NewGuid().ToString('N'))
try {
    & $py -m pytest -q --basetemp $testBase @tests
    if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta13 B13-5 regression failed.' }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

& $py -m sentinel.beta13_clean_pc_lifecycle
if ($LASTEXITCODE -ne 0) { throw 'B13-5 lifecycle contract self-check failed.' }

$acceptRoot = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b135-accept-' + [guid]::NewGuid().ToString('N'))
$preBuildRoot = Join-Path $acceptRoot 'predecessor-build'
$targetBuildRoot = Join-Path $acceptRoot 'target-build'
$lifecycleRoot = Join-Path $acceptRoot 'lifecycle'
$installRoot = Join-Path $lifecycleRoot 'installed-product'
$persistentSentinel = Join-Path $lifecycleRoot 'persistent-data.keep'
$unknownChild = Join-Path $installRoot 'user-owned.keep'
$rawEvidencePath = Join-Path $acceptRoot 'b135-lifecycle-evidence.raw.json'
$evidencePath = Join-Path $acceptRoot 'b135-lifecycle-evidence.json'

$preInstaller = Join-Path $preBuildRoot 'installer\BC-Sentinel-Setup-v0.13.0-b133.exe'
$targetInstaller = Join-Path $targetBuildRoot 'installer\BC-Sentinel-Setup-v0.13.0-b134.exe'
$targetAppRecordPath = Join-Path $targetBuildRoot 'signing\application-signature.json'
$targetInstallerRecordPath = Join-Path $targetBuildRoot 'signing\installer-signature.json'
$targetUninstallerRecordPath = Join-Path $targetBuildRoot 'signing\uninstaller-signature.json'
$targetSigningEvidencePath = Join-Path $targetBuildRoot 'signing\signing-evidence.json'

$installedExe = Join-Path $installRoot 'BC-Sentinel.exe'
$installedManifest = Join-Path $installRoot 'install-payload-manifest.json'
$uninstaller = Join-Path $installRoot 'Uninstall.exe'

$engineeringCert = $null
$installed = $false
$previousForceBootstrap = $env:BC_SENTINEL_B134_FORCE_SIGTOOL_BOOTSTRAP

New-Item -ItemType Directory -Path $lifecycleRoot -Force | Out-Null
Set-Content -LiteralPath $persistentSentinel -Value 'b13-5-persistent-preserve-me' -Encoding UTF8

try {
    & (Join-Path $repoRoot 'BUILD-V013-B133-INSTALLER.ps1') -OutputRoot $preBuildRoot
    if ($LASTEXITCODE -ne 0) { throw 'B13-5 predecessor installer build failed.' }
    if (-not (Test-Path -LiteralPath $preInstaller -PathType Leaf)) {
        throw 'B13-5 predecessor installer artifact missing.'
    }

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
        throw 'B13-5 failed to create ephemeral engineering code-signing certificate.'
    }
    $thumbprint = ([string]$engineeringCert.Thumbprint).Replace(' ','').ToLowerInvariant()

    $env:BC_SENTINEL_B134_FORCE_SIGTOOL_BOOTSTRAP = '1'
    $targetBuildParams = @{
        OutputRoot = $targetBuildRoot
        Provider = 'CERTIFICATE_STORE'
        TrustLevel = 'ENGINEERING_TEST'
        ExpectedPublisher = 'BC TECH Studio'
        CertificateThumbprint = $thumbprint
        TimestampUrl = 'http://timestamp.acs.microsoft.com'
    }
    & (Join-Path $repoRoot 'BUILD-V013-B134-SIGNED-INSTALLER.ps1') @targetBuildParams
    if ($LASTEXITCODE -ne 0) { throw 'B13-5 target signed installer build failed.' }

    foreach ($required in @(
        $targetInstaller,
        $targetAppRecordPath,
        $targetInstallerRecordPath,
        $targetUninstallerRecordPath,
        $targetSigningEvidencePath
    )) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw ('B13-5 target build artifact missing: ' + $required)
        }
    }

    $targetSigningEvidence = Get-Content -LiteralPath $targetSigningEvidencePath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not [bool]$targetSigningEvidence.pipeline_evidence_valid) {
        throw 'B13-5 target signing evidence is invalid.'
    }
    if ([bool]$targetSigningEvidence.public_trust_signature_verified) {
        throw 'B13-5 engineering signer was incorrectly classified as Public Trust.'
    }

    $targetAppRecord = Get-Content -LiteralPath $targetAppRecordPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $targetUninstallerRecord = Get-Content -LiteralPath $targetUninstallerRecordPath -Raw -Encoding UTF8 | ConvertFrom-Json

    $preInstallProcess = Start-Process -FilePath $preInstaller -ArgumentList @('/S',('/D=' + $installRoot)) -Wait -PassThru
    if ($preInstallProcess.ExitCode -ne 0) {
        throw ('B13-5 predecessor installer exited with ' + $preInstallProcess.ExitCode)
    }
    $installed = $true

    foreach ($required in @($installedExe,$installedManifest,$uninstaller)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw ('B13-5 predecessor installation artifact missing: ' + $required)
        }
    }
    if (-not (Test-Path $existingProductKey) -or -not (Test-Path $existingUninstallKey)) {
        throw 'B13-5 predecessor registry metadata missing.'
    }
    if (-not (Test-Path -LiteralPath (Join-Path $startMenuDir 'BC Sentinel.lnk') -PathType Leaf)) {
        throw 'B13-5 predecessor Start Menu shortcut missing.'
    }

    $preSig = Get-AuthenticodeSignature -FilePath $installedExe
    $predecessorUnsignedObserved = ([string]$preSig.Status -eq 'NotSigned' -and $null -eq $preSig.SignerCertificate)
    if (-not $predecessorUnsignedObserved) {
        throw ('B13-5 predecessor application unexpectedly signed: ' + [string]$preSig.Status)
    }
    $predecessorAppHash = (Get-FileHash -LiteralPath $installedExe -Algorithm SHA256).Hash.ToLowerInvariant()

    $preSelfCheck = Start-Process -FilePath $installedExe -ArgumentList @('--self-check') -Wait -PassThru
    if ($preSelfCheck.ExitCode -ne 0) { throw ('B13-5 predecessor self-check failed exit=' + $preSelfCheck.ExitCode) }
    $preSmoke = Start-Process -FilePath $installedExe -ArgumentList @('--smoke') -Wait -PassThru
    if ($preSmoke.ExitCode -ne 0) { throw ('B13-5 predecessor UI smoke failed exit=' + $preSmoke.ExitCode) }

    Set-Content -LiteralPath $unknownChild -Value 'b13-5-user-owned-content' -Encoding UTF8
    $unknownHashBefore = (Get-FileHash -LiteralPath $unknownChild -Algorithm SHA256).Hash.ToLowerInvariant()
    $persistentHashBefore = (Get-FileHash -LiteralPath $persistentSentinel -Algorithm SHA256).Hash.ToLowerInvariant()

    $upgradeProcess = Start-Process -FilePath $targetInstaller -ArgumentList @('/S',('/D=' + $installRoot)) -Wait -PassThru
    if ($upgradeProcess.ExitCode -ne 0) {
        throw ('B13-5 target upgrade installer exited with ' + $upgradeProcess.ExitCode)
    }

    foreach ($required in @($installedExe,$installedManifest,$uninstaller)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw ('B13-5 upgraded installation artifact missing: ' + $required)
        }
    }

    $upgradedAppHash = (Get-FileHash -LiteralPath $installedExe -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($upgradedAppHash -eq $predecessorAppHash) {
        throw 'B13-5 upgrade did not change application hash.'
    }
    if ($upgradedAppHash -ne ([string]$targetAppRecord.post_sign_sha256).ToLowerInvariant()) {
        throw 'B13-5 upgraded application hash differs from signed target payload.'
    }
    $upgradedUninstallerHash = (Get-FileHash -LiteralPath $uninstaller -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($upgradedUninstallerHash -ne ([string]$targetUninstallerRecord.post_sign_sha256).ToLowerInvariant()) {
        throw 'B13-5 upgraded uninstaller hash differs from signed target uninstaller.'
    }

    $upgradedAppSig = Get-AuthenticodeSignature -FilePath $installedExe
    $upgradedUninstallerSig = Get-AuthenticodeSignature -FilePath $uninstaller
    foreach ($sig in @($upgradedAppSig,$upgradedUninstallerSig)) {
        if ($null -eq $sig.SignerCertificate -or $null -eq $sig.TimeStamperCertificate) {
            throw 'B13-5 upgraded signed artifact is missing signer or RFC3161 timestamp evidence.'
        }
        if (([string]$sig.SignerCertificate.Thumbprint).Replace(' ','').ToLowerInvariant() -ne $thumbprint) {
            throw 'B13-5 upgraded artifact signer thumbprint drift.'
        }
        if ([string]$sig.Status -in @('NotSigned','HashMismatch')) {
            throw ('B13-5 upgraded artifact signature integrity failed: ' + [string]$sig.Status)
        }
    }

    if (-not (Test-Path -LiteralPath $unknownChild -PathType Leaf)) {
        throw 'B13-5 upgrade removed unknown user-owned content.'
    }
    if ((Get-FileHash -LiteralPath $unknownChild -Algorithm SHA256).Hash.ToLowerInvariant() -ne $unknownHashBefore) {
        throw 'B13-5 upgrade modified unknown user-owned content.'
    }
    if ((Get-FileHash -LiteralPath $persistentSentinel -Algorithm SHA256).Hash.ToLowerInvariant() -ne $persistentHashBefore) {
        throw 'B13-5 upgrade modified external persistent data.'
    }
    if (-not (Test-Path $existingProductKey) -or -not (Test-Path $existingUninstallKey)) {
        throw 'B13-5 upgraded registry metadata missing.'
    }
    if (-not (Test-Path -LiteralPath (Join-Path $startMenuDir 'BC Sentinel.lnk') -PathType Leaf)) {
        throw 'B13-5 upgraded Start Menu shortcut missing.'
    }

    $upgradedSelfCheck = Start-Process -FilePath $installedExe -ArgumentList @('--self-check') -Wait -PassThru
    if ($upgradedSelfCheck.ExitCode -ne 0) { throw ('B13-5 upgraded self-check failed exit=' + $upgradedSelfCheck.ExitCode) }
    $upgradedSmoke = Start-Process -FilePath $installedExe -ArgumentList @('--smoke') -Wait -PassThru
    if ($upgradedSmoke.ExitCode -ne 0) { throw ('B13-5 upgraded UI smoke failed exit=' + $upgradedSmoke.ExitCode) }

    $uninstallProcess = Start-Process -FilePath $uninstaller -ArgumentList @('/S') -Wait -PassThru
    if ($uninstallProcess.ExitCode -ne 0) { throw ('B13-5 target uninstaller exited with ' + $uninstallProcess.ExitCode) }
    $installed = $false
    Start-Sleep -Milliseconds 800

    if (Test-Path -LiteralPath $installedExe) { throw 'B13-5 uninstall left product executable behind.' }
    if (Test-Path -LiteralPath $installedManifest) { throw 'B13-5 uninstall left payload manifest behind.' }
    if (-not (Test-Path -LiteralPath $unknownChild -PathType Leaf)) {
        throw 'B13-5 uninstall removed unknown user-owned content.'
    }
    if ((Get-FileHash -LiteralPath $unknownChild -Algorithm SHA256).Hash.ToLowerInvariant() -ne $unknownHashBefore) {
        throw 'B13-5 uninstall modified unknown user-owned content.'
    }
    if (-not (Test-Path -LiteralPath $persistentSentinel -PathType Leaf)) {
        throw 'B13-5 uninstall removed external persistent data.'
    }
    if ((Get-FileHash -LiteralPath $persistentSentinel -Algorithm SHA256).Hash.ToLowerInvariant() -ne $persistentHashBefore) {
        throw 'B13-5 uninstall modified external persistent data.'
    }

    $registryCleaned = -not ((Test-Path $existingProductKey) -or (Test-Path $existingUninstallKey))
    if (-not $registryCleaned) { throw 'B13-5 uninstall left per-user registry metadata behind.' }
    $startMenuCleaned = -not (Test-Path -LiteralPath $startMenuDir)
    if (-not $startMenuCleaned) { throw 'B13-5 uninstall left Start Menu metadata behind.' }

    $serviceRegistrationObserved = [bool]((Get-Service -Name 'BCSentinel' -ErrorAction SilentlyContinue) -or (Test-Path $serviceKey))
    $driverRegistrationObserved = [bool](Test-Path $serviceKey)
    $autostartRegistrationObserved = [bool](Test-BCSentinelRunEntry)
    if ($serviceRegistrationObserved -or $driverRegistrationObserved -or $autostartRegistrationObserved) {
        throw 'B13-5 observed forbidden service/driver/autostart registration.'
    }

    $rawEvidence = [ordered]@{
        schema = 'bc-sentinel-beta13-clean-pc-lifecycle-evidence-v1'
        profile = 'v0.13.0-b135-clean-pc-install-upgrade-uninstall-acceptance'
        source_checkpoint = 'checkpoint/v013-b134-pass'
        source_checkpoint_commit = $frozen
        build_commit = $commit
        environment = $environment
        authoritative_clean_pc_evidence = $authoritativeCleanPc
        predecessor_installer_format = 'B13-3_UNSIGNED_REAL_NSIS'
        target_installer_format = 'B13-4_ENGINEERING_SIGNED_REAL_NSIS'
        predecessor_install_passed = $true
        predecessor_unsigned_observed = $predecessorUnsignedObserved
        predecessor_self_check_passed = $true
        predecessor_ui_smoke_passed = $true
        upgrade_passed = $true
        target_signed_observed = $true
        signer_consistent = $true
        timestamp_present = $true
        target_hash_changed = ($upgradedAppHash -ne $predecessorAppHash)
        upgraded_self_check_passed = $true
        upgraded_ui_smoke_passed = $true
        unknown_child_preserved_across_upgrade = $true
        persistent_data_preserved_across_upgrade = $true
        uninstall_passed = $true
        unknown_child_preserved_after_uninstall = $true
        persistent_data_preserved_after_uninstall = $true
        registry_cleaned = $registryCleaned
        start_menu_cleaned = $startMenuCleaned
        service_registration_observed = $serviceRegistrationObserved
        driver_registration_observed = $driverRegistrationObserved
        autostart_registration_observed = $autostartRegistrationObserved
        administrator_required = $false
        public_trust_signature_verified = $false
        smartscreen_reputation_guaranteed = $false
        coverage_promoted = $false
        authority_expanded = $false
        predecessor_app_sha256 = $predecessorAppHash
        upgraded_app_sha256 = $upgradedAppHash
        target_signer_thumbprint = $thumbprint
    }
    [IO.File]::WriteAllText(
        $rawEvidencePath,
        (($rawEvidence | ConvertTo-Json -Depth 6) + [Environment]::NewLine),
        [Text.UTF8Encoding]::new($false)
    )

    & $py -c "import json,sys; from pathlib import Path; from sentinel.beta13_clean_pc_lifecycle import finalize_lifecycle_evidence,validate_lifecycle_evidence; src=Path(sys.argv[1]); dst=Path(sys.argv[2]); raw=json.loads(src.read_text(encoding='utf-8')); evidence=finalize_lifecycle_evidence(raw); failures=validate_lifecycle_evidence(evidence,expected_build_commit=sys.argv[3]); assert not failures,failures; dst.write_text(json.dumps(evidence,indent=2,sort_keys=True)+'\n',encoding='utf-8'); print(json.dumps(evidence,indent=2,sort_keys=True))" $rawEvidencePath $evidencePath $commit
    if ($LASTEXITCODE -ne 0) { throw 'B13-5 lifecycle evidence validation failed.' }

    $finalEvidence = Get-Content -LiteralPath $evidencePath -Raw -Encoding UTF8 | ConvertFrom-Json
    Write-Host ('B13-5 evidence digest: ' + [string]$finalEvidence.evidence_digest)
    Write-Host ('B13-5 lifecycle: predecessor_install=PASS upgrade_to_signed_target=PASS uninstall=PASS')
    Write-Host ('B13-5 packaged probes: predecessor_self_check=PASS predecessor_ui_smoke=PASS upgraded_self_check=PASS upgraded_ui_smoke=PASS')
    Write-Host ('B13-5 preservation: upgrade_unknown_child=PRESERVED upgrade_persistent_data=PRESERVED uninstall_unknown_child=PRESERVED uninstall_persistent_data=PRESERVED')
    Write-Host ('B13-5 boundaries: PER_USER / UAC_NOT_REQUIRED / SERVICE=false / DRIVER=false / AUTOSTART=false')
    Write-Host ('B13-5 clean-PC authority: ' + $environment + ' / authoritative=' + $authoritativeCleanPc)
    Write-Host 'BC SENTINEL v0.13.0 B13-5 CLEAN-PC INSTALL / UPGRADE / UNINSTALL ACCEPTANCE - PASS'
}
finally {
    $env:BC_SENTINEL_B134_FORCE_SIGTOOL_BOOTSTRAP = $previousForceBootstrap
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
