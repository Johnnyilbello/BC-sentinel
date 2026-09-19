param([switch]$ConfirmCommercialReadiness)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location -LiteralPath $repoRoot
$env:PYTHONPATH = $repoRoot

if (-not $ConfirmCommercialReadiness) {
    throw 'Explicit Beta13 B13-6 commercial readiness confirmation required.'
}

$commit = (& git rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Cannot resolve B13-6 acceptance commit.'
}
Write-Host ('B13-6 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B13-6 acceptance commit.' }

$frozen = 'cbead4c4e01818f5764ebeb82f85eb69f64e1f67'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted Beta13 B13-5 predecessor missing.' }

$checkpointSha = (& git rev-parse 'refs/remotes/origin/checkpoint/v013-b135-pass' 2>$null)
if ($LASTEXITCODE -ne 0) {
    $checkpointSha = (& git rev-parse 'checkpoint/v013-b135-pass' 2>$null)
}
if ($LASTEXITCODE -ne 0 -or ([string]$checkpointSha).Trim().ToLowerInvariant() -ne $frozen) {
    throw 'B13-5 immutable checkpoint is missing or points to the wrong commit.'
}

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
$changes = @(& git diff --name-only $frozen HEAD)
$allowed = @(
    '.github/workflows/b136-trial-licensing-privacy-support-readiness.yml',
    'ROADMAP.md',
    'packaging/beta13_desktop_entry.py',
    'sentinel/beta13_commercial_readiness.py',
    'sentinel/beta13_commercial_ui.py',
    'tests/test_v013_b136_commercial_readiness.py',
    'tools/acceptance/TEST-V013-B136-COMMERCIAL-READINESS.ps1'
)
$allowedExisting = @(
    'ROADMAP.md',
    'packaging/beta13_desktop_entry.py'
)
if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B13-6 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) { throw ('Unexpected B13-6 changed path: ' + $path) }
    if ($frozenPaths -contains $path -and $allowedExisting -notcontains $path) {
        throw ('Frozen B13-5 path changed unexpectedly: ' + $path)
    }
    if ($frozenPaths -notcontains $path -and $allowedExisting -contains $path) {
        throw ('Expected existing B13-5 path is missing from predecessor: ' + $path)
    }
}
Write-Host 'Accepted B13-5 checkpoint identity, source boundary and repository hygiene: PASS'

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta13_commercial_readiness.py sentinel/beta13_commercial_ui.py packaging/beta13_desktop_entry.py tests/test_v013_b136_commercial_readiness.py
if ($LASTEXITCODE -ne 0) { throw 'B13-6 compile failed.' }

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
$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b136-pytest-' + [guid]::NewGuid().ToString('N'))
try {
    & $py -m pytest -q --basetemp $testBase @tests
    if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta13 B13-6 regression failed.' }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

& $py -m sentinel.beta13_commercial_readiness
if ($LASTEXITCODE -ne 0) { throw 'B13-6 commercial readiness self-check failed.' }

& $py -c "import json; from sentinel import beta12_product_integration as p; from sentinel import beta13_commercial_ui as ui; s=p.build_product_snapshot(); r=ui.smoke_test_window(s); assert r['passed'],r; assert r['page_count']==9; assert r['core_protection_enabled']; assert all(v==0 for v in r['horizontal_overflow'].values()); print(json.dumps(r,indent=2,sort_keys=True))"
if ($LASTEXITCODE -ne 0) { throw 'B13-6 source UI smoke failed.' }

$acceptRoot = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b136-accept-' + [guid]::NewGuid().ToString('N'))
$buildRoot = Join-Path $acceptRoot 'build'
$lifecycleRoot = Join-Path $acceptRoot 'lifecycle'
$installRoot = Join-Path $lifecycleRoot 'installed-product'
$productLocalAppData = Join-Path $lifecycleRoot 'localappdata'
$diagnosticsPath = Join-Path $lifecycleRoot 'support-diagnostics.json'
$installer = Join-Path $buildRoot 'installer\BC-Sentinel-Setup-v0.13.0-b134.exe'
$installedExe = Join-Path $installRoot 'BC-Sentinel.exe'
$uninstaller = Join-Path $installRoot 'Uninstall.exe'
$signingEvidencePath = Join-Path $buildRoot 'signing\signing-evidence.json'

$existingProductKey = 'Registry::HKEY_CURRENT_USER\Software\BC TECH Studio\BC Sentinel'
$existingUninstallKey = 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\BCSentinel'
$startMenuDir = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\BC Sentinel'

if ((Test-Path $existingProductKey) -or (Test-Path $existingUninstallKey) -or (Test-Path -LiteralPath $startMenuDir)) {
    throw 'An existing BC Sentinel per-user installation is present; B13-6 refuses to overwrite it.'
}

$engineeringCert = $null
$installed = $false
$previousForceBootstrap = $env:BC_SENTINEL_B134_FORCE_SIGTOOL_BOOTSTRAP
$previousLocalAppData = $env:LOCALAPPDATA

New-Item -ItemType Directory -Path $lifecycleRoot -Force | Out-Null
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
        throw 'B13-6 failed to create ephemeral engineering code-signing certificate.'
    }
    $thumbprint = ([string]$engineeringCert.Thumbprint).Replace(' ','').ToLowerInvariant()

    $env:BC_SENTINEL_B134_FORCE_SIGTOOL_BOOTSTRAP = '1'
    $buildParams = @{
        OutputRoot = $buildRoot
        Provider = 'CERTIFICATE_STORE'
        TrustLevel = 'ENGINEERING_TEST'
        ExpectedPublisher = 'BC TECH Studio'
        CertificateThumbprint = $thumbprint
        TimestampUrl = 'http://timestamp.acs.microsoft.com'
    }
    & (Join-Path $repoRoot 'BUILD-V013-B134-SIGNED-INSTALLER.ps1') @buildParams
    if ($LASTEXITCODE -ne 0) { throw 'B13-6 packaged signed build failed.' }

    foreach ($required in @($installer,$signingEvidencePath)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw ('B13-6 packaged build artifact missing: ' + $required)
        }
    }

    $signingEvidence = Get-Content -LiteralPath $signingEvidencePath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not [bool]$signingEvidence.pipeline_evidence_valid) {
        throw 'B13-6 inherited engineering signing evidence invalid.'
    }
    if ([bool]$signingEvidence.public_trust_signature_verified) {
        throw 'B13-6 engineering signer incorrectly resolved Public Trust.'
    }

    $installProcess = Start-Process -FilePath $installer -ArgumentList @('/S',('/D=' + $installRoot)) -Wait -PassThru
    if ($installProcess.ExitCode -ne 0) { throw ('B13-6 installer exited with ' + $installProcess.ExitCode) }
    $installed = $true

    if (-not (Test-Path -LiteralPath $installedExe -PathType Leaf)) { throw 'B13-6 installed executable missing.' }
    if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) { throw 'B13-6 installed uninstaller missing.' }

    $env:LOCALAPPDATA = $productLocalAppData

    $selfCheck = Start-Process -FilePath $installedExe -ArgumentList @('--self-check') -Wait -PassThru
    if ($selfCheck.ExitCode -ne 0) { throw ('B13-6 installed self-check failed exit=' + $selfCheck.ExitCode) }

    $smoke = Start-Process -FilePath $installedExe -ArgumentList @('--smoke') -Wait -PassThru
    if ($smoke.ExitCode -ne 0) { throw ('B13-6 installed UI smoke failed exit=' + $smoke.ExitCode) }

    & $installedExe --diagnostics-json $diagnosticsPath
    if ($LASTEXITCODE -ne 0) { throw ('B13-6 installed diagnostics export failed exit=' + $LASTEXITCODE) }
    if (-not (Test-Path -LiteralPath $diagnosticsPath -PathType Leaf)) {
        throw 'B13-6 installed diagnostics file missing.'
    }

    & $py -c "import json,sys; from pathlib import Path; from sentinel.beta13_commercial_readiness import validate_diagnostic_snapshot; p=Path(sys.argv[1]); d=json.loads(p.read_text(encoding='utf-8')); f=validate_diagnostic_snapshot(d); assert not f,f; assert d['core_protection_enabled']; assert d['raw_paths_included'] is False; assert d['command_lines_included'] is False; assert d['usernames_included'] is False; assert d['license_token_included'] is False; assert d['license_id_included'] is False; assert d['file_contents_included'] is False; print(json.dumps(d,indent=2,sort_keys=True))" $diagnosticsPath
    if ($LASTEXITCODE -ne 0) { throw 'B13-6 installed diagnostics privacy validation failed.' }

    $trialStore = Join-Path $productLocalAppData 'BCSentinel\commercial\trial.json'
    if (-not (Test-Path -LiteralPath $trialStore -PathType Leaf)) {
        throw 'B13-6 packaged trial state was not initialized outside the install root.'
    }
    if ($trialStore.StartsWith($installRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'B13-6 trial state was written inside the install root.'
    }

    & $py -c "import json; from sentinel.beta13_commercial_readiness import self_check; r=self_check(); p=r['readiness_projection']; assert r['passed']; assert p['pillar_counts']=={'READY':9,'PARTIAL':0,'BLOCKED':1}; assert p['release_blockers']==['CODE_SIGNING']; assert r['expired_trial_keeps_protection']; assert r['activation_unavailable_keeps_protection']; print(json.dumps({'b13_6_passed':True,'contract_digest':r['contract_digest'],'pillar_counts':p['pillar_counts'],'release_blockers':p['release_blockers'],'trial_days':r['trial_days'],'diagnostic_export_privacy_valid':r['diagnostic_export_privacy_valid']},indent=2,sort_keys=True))"
    if ($LASTEXITCODE -ne 0) { throw 'B13-6 final readiness assertions failed.' }

    $uninstallProcess = Start-Process -FilePath $uninstaller -ArgumentList @('/S') -Wait -PassThru
    if ($uninstallProcess.ExitCode -ne 0) { throw ('B13-6 uninstaller exited with ' + $uninstallProcess.ExitCode) }
    $installed = $false
    Start-Sleep -Milliseconds 800

    if (Test-Path -LiteralPath $installedExe) { throw 'B13-6 uninstall left product executable behind.' }
    if (-not (Test-Path -LiteralPath $trialStore -PathType Leaf)) {
        throw 'B13-6 uninstall removed persistent trial/commercial state unexpectedly.'
    }
    if ((Test-Path $existingProductKey) -or (Test-Path $existingUninstallKey)) {
        throw 'B13-6 uninstall left per-user registry metadata behind.'
    }

    Write-Host 'B13-6 commercial lifecycle: trial=PASS signed_entitlement_verifier=PASS protection_on_license_failure=PASS'
    Write-Host 'B13-6 surfaces: licensing=PASS privacy=PASS eula=PASS support=PASS diagnostics_export=PASS'
    Write-Host 'B13-6 packaged UI: page_count=9 responsive=PASS horizontal_overflow=0'
    Write-Host 'B13-6 diagnostic privacy: raw_paths=false command_lines=false usernames=false license_token=false license_id=false file_contents=false'
    Write-Host 'B13-6 readiness: READY=9 PARTIAL=0 BLOCKED=1 remaining_release_blocker=CODE_SIGNING'
    Write-Host 'BC SENTINEL v0.13.0 B13-6 TRIAL / LICENSING / PRIVACY / SUPPORT READINESS - PASS'
}
finally {
    $env:BC_SENTINEL_B134_FORCE_SIGTOOL_BOOTSTRAP = $previousForceBootstrap
    $env:LOCALAPPDATA = $previousLocalAppData
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
