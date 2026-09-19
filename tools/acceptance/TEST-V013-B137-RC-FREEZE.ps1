param([switch]$ConfirmReleaseCandidateFreeze)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location -LiteralPath $repoRoot
$env:PYTHONPATH = $repoRoot

if (-not $ConfirmReleaseCandidateFreeze) {
    throw 'Explicit Beta13 B13-7 release-candidate freeze confirmation required.'
}

$commit = (& git rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Cannot resolve B13-7 acceptance commit.'
}
Write-Host ('B13-7 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Tracked working files differ from B13-7 acceptance commit.'
}

$frozen = 'b981afa453e6540e18e5ec1fac7da74ce9344829'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Accepted Beta13 B13-6 predecessor missing.'
}

$accepted = [ordered]@{
    'checkpoint/v013-b130-pass' = '6c1a3dedd48d2b26b716c199f74ea45d827ee01a'
    'checkpoint/v013-b131-pass' = 'cfb94fb65f90327504296809270bf3c573f083d0'
    'checkpoint/v013-b132-pass' = '3e64155858d9b8c7efebc28aecc9689795159ae9'
    'checkpoint/v013-b133-pass' = 'b6014ef74ffc77814f489532c8f2d09fb92fe17f'
    'checkpoint/v013-b134-pass' = 'c2dc1b0df4becc18afa56915bb47b29b533a9a55'
    'checkpoint/v013-b135-pass' = 'cbead4c4e01818f5764ebeb82f85eb69f64e1f67'
    'checkpoint/v013-b136-pass' = $frozen
}
foreach ($name in $accepted.Keys) {
    $resolved = (& git rev-parse ('refs/remotes/origin/' + $name) 2>$null)
    if ($LASTEXITCODE -ne 0) {
        $resolved = (& git rev-parse $name 2>$null)
    }
    if ($LASTEXITCODE -ne 0 -or ([string]$resolved).Trim().ToLowerInvariant() -ne $accepted[$name]) {
        throw ('Accepted Beta13 checkpoint mismatch: ' + $name)
    }
}
Write-Host 'All accepted Beta13 predecessor checkpoints: PASS'

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
$changes = @(& git diff --name-only $frozen HEAD)
$allowed = @(
    '.github/workflows/b137-distribution-package-rc-freeze.yml',
    'BUILD-V013-B137-RC.ps1',
    'ROADMAP.md',
    'sentinel/beta13_release_candidate.py',
    'tests/test_v013_b137_release_candidate.py',
    'tools/acceptance/TEST-V013-B137-RC-FREEZE.ps1'
)
if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B13-7 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) {
        throw ('Unexpected B13-7 changed path: ' + $path)
    }
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B13-6 path changed: ' + $path)
    }
}
$roadmaps = @(& git ls-files | Where-Object { $_ -match '(?i)roadmap' })
if ($roadmaps.Count -ne 1 -or $roadmaps[0] -ne 'ROADMAP.md') {
    throw 'Repository roadmap hygiene failed.'
}
Write-Host 'Accepted B13-6 source immutability and repository hygiene: PASS'

$environment = 'LOCAL_GUARDED_REHEARSAL'
$authoritativeCleanPc = $false
if ([string]$env:GITHUB_ACTIONS -eq 'true' -and [string]$env:RUNNER_OS -eq 'Windows') {
    $environment = 'DISPOSABLE_WINDOWS_CI_RUNNER'
    $authoritativeCleanPc = $true
}
Write-Host ('B13-7 environment classification: ' + $environment)
Write-Host ('B13-7 authoritative clean-PC evidence: ' + $authoritativeCleanPc)

$existingProductKey = 'Registry::HKEY_CURRENT_USER\Software\BC TECH Studio\BC Sentinel'
$existingUninstallKey = 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\BCSentinel'
$startMenuDir = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\BC Sentinel'
$serviceKey = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BCSentinel'
$runKey = 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'

function Test-BCSentinelRunEntry {
    if (-not (Test-Path $runKey)) { return $false }
    $props = Get-ItemProperty -Path $runKey -ErrorAction SilentlyContinue
    if (-not $props) { return $false }
    return (
        $null -ne $props.PSObject.Properties['BC Sentinel'] -or
        $null -ne $props.PSObject.Properties['BCSentinel']
    )
}

if ((Test-Path $existingProductKey) -or (Test-Path $existingUninstallKey) -or (Test-Path -LiteralPath $startMenuDir)) {
    throw 'An existing BC Sentinel per-user installation is present; B13-7 refuses to overwrite it.'
}
if ((Get-Service -Name 'BCSentinel' -ErrorAction SilentlyContinue) -or (Test-Path $serviceKey)) {
    throw 'An existing BC Sentinel service/driver registration is present; B13-7 refuses to continue.'
}
if (Test-BCSentinelRunEntry) {
    throw 'An existing BC Sentinel autostart entry is present; B13-7 refuses to continue.'
}

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta13_release_candidate.py tests/test_v013_b137_release_candidate.py
if ($LASTEXITCODE -ne 0) {
    throw 'B13-7 compile failed.'
}

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
$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b137-pytest-' + [guid]::NewGuid().ToString('N'))
try {
    & $py -m pytest -q --basetemp $testBase @tests
    if ($LASTEXITCODE -ne 0) {
        throw 'Beta5 through Beta13 B13-7 regression failed.'
    }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

& $py -m sentinel.beta13_release_candidate
if ($LASTEXITCODE -ne 0) {
    throw 'B13-7 release-candidate contract self-check failed.'
}

$acceptRoot = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b137-accept-' + [guid]::NewGuid().ToString('N'))
$distRoot = Join-Path $acceptRoot 'distribution'
$bundleRoot = Join-Path $distRoot 'BC-Sentinel-v0.13.0-RC1-Engineering'
$archivePath = Join-Path $distRoot 'BC-Sentinel-v0.13.0-RC1-Engineering.zip'
$archiveHashPath = $archivePath + '.sha256'
$extractRoot = Join-Path $acceptRoot 'archive-extracted'
$lifecycleRoot = Join-Path $acceptRoot 'lifecycle'
$installRoot = Join-Path $lifecycleRoot 'installed-product'
$productLocalAppData = Join-Path $lifecycleRoot 'localappdata'
$diagnosticsPath = Join-Path $lifecycleRoot 'support-diagnostics.json'
$freezeEvidencePath = Join-Path $acceptRoot 'b137-freeze-evidence.json'

$installerName = 'BC-Sentinel-Setup-v0.13.0-RC1-Engineering.exe'
$manifestName = 'distribution-manifest.json'
$provenanceName = 'release-provenance.json'
$signingEvidenceName = 'signing-evidence.json'
$hashesName = 'SHA256SUMS.txt'
$noticeName = 'RC-NOTICE.txt'

$engineeringCert = $null
$installed = $false
$previousForceBootstrap = $env:BC_SENTINEL_B134_FORCE_SIGTOOL_BOOTSTRAP
$previousLocalAppData = $env:LOCALAPPDATA

New-Item -ItemType Directory -Path $acceptRoot -Force | Out-Null
New-Item -ItemType Directory -Path $productLocalAppData -Force | Out-Null

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
        throw 'B13-7 failed to create ephemeral engineering code-signing certificate.'
    }
    $thumbprint = ([string]$engineeringCert.Thumbprint).Replace(' ','').ToLowerInvariant()

    $env:BC_SENTINEL_B134_FORCE_SIGTOOL_BOOTSTRAP = '1'
    $buildParams = @{
        OutputRoot = $distRoot
        Provider = 'CERTIFICATE_STORE'
        TrustLevel = 'ENGINEERING_TEST'
        ExpectedPublisher = 'BC TECH Studio'
        CertificateThumbprint = $thumbprint
        TimestampUrl = 'http://timestamp.acs.microsoft.com'
    }
    & (Join-Path $repoRoot 'BUILD-V013-B137-RC.ps1') @buildParams
    if ($LASTEXITCODE -ne 0) {
        throw 'B13-7 RC distribution build failed.'
    }

    foreach ($required in @($archivePath,$archiveHashPath,$bundleRoot)) {
        if (-not (Test-Path -LiteralPath $required)) {
            throw ('B13-7 distribution output missing: ' + $required)
        }
    }

    & $py -m sentinel.beta13_release_candidate --validate-root --root $bundleRoot --build-commit $commit
    if ($LASTEXITCODE -ne 0) {
        throw 'B13-7 built distribution root validation failed.'
    }

    $archiveSha = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $hashSidecar = (Get-Content -LiteralPath $archiveHashPath -Raw -Encoding ASCII).Trim()
    if (-not $hashSidecar.StartsWith($archiveSha + '  ', [StringComparison]::Ordinal)) {
        throw 'B13-7 archive SHA256 sidecar mismatch.'
    }

    Expand-Archive -LiteralPath $archivePath -DestinationPath $extractRoot -Force
    $archiveFiles = @(
        Get-ChildItem -LiteralPath $extractRoot -File |
            Sort-Object Name |
            ForEach-Object { $_.Name }
    )
    $expectedArchiveFiles = @(
        $hashesName,
        $installerName,
        $noticeName,
        $manifestName,
        $provenanceName,
        $signingEvidenceName
    ) | Sort-Object
    if (@($archiveFiles).Count -ne @($expectedArchiveFiles).Count) {
        throw 'B13-7 RC archive file count mismatch.'
    }
    for ($i = 0; $i -lt $expectedArchiveFiles.Count; $i++) {
        if ($archiveFiles[$i] -ne $expectedArchiveFiles[$i]) {
            throw ('B13-7 RC archive inventory mismatch: ' + ($archiveFiles -join ', '))
        }
    }

    & $py -m sentinel.beta13_release_candidate --validate-root --root $extractRoot --build-commit $commit
    if ($LASTEXITCODE -ne 0) {
        throw 'B13-7 extracted archive validation failed.'
    }

    $manifest = Get-Content -LiteralPath (Join-Path $extractRoot $manifestName) -Raw -Encoding UTF8 | ConvertFrom-Json
    $provenance = Get-Content -LiteralPath (Join-Path $extractRoot $provenanceName) -Raw -Encoding UTF8 | ConvertFrom-Json
    $signingEvidence = Get-Content -LiteralPath (Join-Path $extractRoot $signingEvidenceName) -Raw -Encoding UTF8 | ConvertFrom-Json

    if ($manifest.build_commit -ne $commit -or $provenance.build_commit -ne $commit) {
        throw 'B13-7 RC metadata is not bound to exact acceptance commit.'
    }
    if (-not [bool]$manifest.engineering_release_candidate -or [bool]$manifest.public_release_ready) {
        throw 'B13-7 manifest public-release boundary invalid.'
    }
    if ($signingEvidence.trust_level -ne 'ENGINEERING_TEST' -or [bool]$signingEvidence.public_trust_signature_verified) {
        throw 'B13-7 signing evidence incorrectly claims Public Trust.'
    }
    if (@($provenance.remaining_release_blockers).Count -ne 1 -or $provenance.remaining_release_blockers[0] -ne 'CODE_SIGNING') {
        throw 'B13-7 provenance release blocker mismatch.'
    }

    $installer = Join-Path $extractRoot $installerName
    $installerSha = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($installerSha -ne [string]$manifest.installer_sha256) {
        throw 'B13-7 extracted installer hash mismatch.'
    }

    $installProcess = Start-Process -FilePath $installer -ArgumentList @('/S',('/D=' + $installRoot)) -Wait -PassThru
    if ($installProcess.ExitCode -ne 0) {
        throw ('B13-7 RC installer exited with ' + $installProcess.ExitCode)
    }
    $installed = $true

    $installedExe = Join-Path $installRoot 'BC-Sentinel.exe'
    $uninstaller = Join-Path $installRoot 'Uninstall.exe'
    if (-not (Test-Path -LiteralPath $installedExe -PathType Leaf)) {
        throw 'B13-7 installed executable missing.'
    }
    if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) {
        throw 'B13-7 installed uninstaller missing.'
    }

    $env:LOCALAPPDATA = $productLocalAppData

    $selfCheck = Start-Process -FilePath $installedExe -ArgumentList @('--self-check') -Wait -PassThru
    if ($selfCheck.ExitCode -ne 0) {
        throw ('B13-7 installed self-check failed exit=' + $selfCheck.ExitCode)
    }

    $smoke = Start-Process -FilePath $installedExe -ArgumentList @('--smoke') -Wait -PassThru
    if ($smoke.ExitCode -ne 0) {
        throw ('B13-7 installed UI smoke failed exit=' + $smoke.ExitCode)
    }

    $diagnostics = Start-Process -FilePath $installedExe -ArgumentList @('--diagnostics-json', ('"' + $diagnosticsPath + '"')) -Wait -PassThru
    if ($diagnostics.ExitCode -ne 0) {
        throw ('B13-7 installed diagnostics export failed exit=' + $diagnostics.ExitCode)
    }
    if (-not (Test-Path -LiteralPath $diagnosticsPath -PathType Leaf)) {
        throw 'B13-7 installed diagnostics file missing.'
    }
    & $py -c "import json,sys; from pathlib import Path; from sentinel.beta13_commercial_readiness import validate_diagnostic_snapshot; d=json.loads(Path(sys.argv[1]).read_text(encoding='utf-8')); f=validate_diagnostic_snapshot(d); assert not f,f; assert d['core_protection_enabled']; assert d['raw_paths_included'] is False; assert d['command_lines_included'] is False; assert d['usernames_included'] is False; assert d['license_token_included'] is False; assert d['license_id_included'] is False; assert d['file_contents_included'] is False" $diagnosticsPath
    if ($LASTEXITCODE -ne 0) {
        throw 'B13-7 installed diagnostics privacy validation failed.'
    }

    if ((Get-Service -Name 'BCSentinel' -ErrorAction SilentlyContinue) -or (Test-Path $serviceKey)) {
        throw 'B13-7 RC unexpectedly registered a service/driver.'
    }
    if (Test-BCSentinelRunEntry) {
        throw 'B13-7 RC unexpectedly registered autostart.'
    }

    $trialStore = Join-Path $productLocalAppData 'BCSentinel\commercial\trial.json'
    if (-not (Test-Path -LiteralPath $trialStore -PathType Leaf)) {
        throw 'B13-7 packaged trial state was not initialized outside the install root.'
    }

    $uninstallProcess = Start-Process -FilePath $uninstaller -ArgumentList @('/S') -Wait -PassThru
    if ($uninstallProcess.ExitCode -ne 0) {
        throw ('B13-7 uninstaller exited with ' + $uninstallProcess.ExitCode)
    }
    $installed = $false
    Start-Sleep -Milliseconds 800

    if (Test-Path -LiteralPath $installedExe) {
        throw 'B13-7 uninstall left product executable behind.'
    }
    if (-not (Test-Path -LiteralPath $trialStore -PathType Leaf)) {
        throw 'B13-7 uninstall removed persistent commercial state unexpectedly.'
    }
    if ((Test-Path $existingProductKey) -or (Test-Path $existingUninstallKey) -or (Test-Path -LiteralPath $startMenuDir)) {
        throw 'B13-7 uninstall left product-owned per-user metadata behind.'
    }
    if ((Get-Service -Name 'BCSentinel' -ErrorAction SilentlyContinue) -or (Test-Path $serviceKey) -or (Test-BCSentinelRunEntry)) {
        throw 'B13-7 lifecycle left service/driver/autostart state behind.'
    }

    & $py -c "import json,sys; from pathlib import Path; from sentinel.beta13_release_candidate import build_freeze_evidence,validate_freeze_evidence; e=build_freeze_evidence(build_commit=sys.argv[1],environment_classification=sys.argv[2],authoritative_clean_pc_evidence=sys.argv[3].lower()=='true',archive_sha256=sys.argv[4],installer_sha256=sys.argv[5],manifest_digest=sys.argv[6],provenance_digest=sys.argv[7],install_passed=True,self_check_passed=True,ui_smoke_passed=True,diagnostics_passed=True,uninstall_passed=True); f=validate_freeze_evidence(e,expected_build_commit=sys.argv[1]); assert not f,f; Path(sys.argv[8]).write_text(json.dumps(e,indent=2,sort_keys=True)+'\n',encoding='utf-8'); print(json.dumps(e,indent=2,sort_keys=True))" $commit $environment ([string]$authoritativeCleanPc).ToLowerInvariant() $archiveSha $installerSha ([string]$manifest.manifest_digest) ([string]$provenance.provenance_digest) $freezeEvidencePath
    if ($LASTEXITCODE -ne 0) {
        throw 'B13-7 freeze evidence validation failed.'
    }

    $freezeEvidence = Get-Content -LiteralPath $freezeEvidencePath -Raw -Encoding UTF8 | ConvertFrom-Json
    Write-Host ('B13-7 ARCHIVE SHA256=' + $archiveSha)
    Write-Host ('B13-7 INSTALLER SHA256=' + $installerSha)
    Write-Host ('B13-7 MANIFEST DIGEST=' + $manifest.manifest_digest)
    Write-Host ('B13-7 PROVENANCE DIGEST=' + $provenance.provenance_digest)
    Write-Host ('B13-7 FREEZE EVIDENCE DIGEST=' + $freezeEvidence.evidence_digest)
    Write-Host ('B13-7 clean-PC authority: ' + $environment + ' / authoritative=' + $authoritativeCleanPc)
    Write-Host 'B13-7 packaged lifecycle: install=PASS self_check=PASS ui_smoke=PASS diagnostics=PASS uninstall=PASS'
    Write-Host 'B13-7 boundaries: PER_USER / SERVICE=false / DRIVER=false / AUTOSTART=false / coverage_unchanged=true'
    Write-Host 'B13-7 release status: ENGINEERING_RC=READY / PUBLIC_RELEASE=BLOCKED / remaining_release_blocker=CODE_SIGNING'
    Write-Host 'BC SENTINEL v0.13.0 B13-7 DISTRIBUTION PACKAGE & RELEASE CANDIDATE FREEZE - PASS'
}
finally {
    $env:BC_SENTINEL_B134_FORCE_SIGTOOL_BOOTSTRAP = $previousForceBootstrap
    $env:LOCALAPPDATA = $previousLocalAppData
    if ($installed) {
        $cleanupUninstaller = Join-Path $installRoot 'Uninstall.exe'
        if (Test-Path -LiteralPath $cleanupUninstaller -PathType Leaf) {
            try { Start-Process -FilePath $cleanupUninstaller -ArgumentList @('/S') -Wait | Out-Null } catch {}
        }
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

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'B13-7 acceptance modified tracked repository sources.'
}
