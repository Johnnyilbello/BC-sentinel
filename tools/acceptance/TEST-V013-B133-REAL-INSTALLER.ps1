param([switch]$ConfirmRealInstaller)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location -LiteralPath $repoRoot
$env:PYTHONPATH = $repoRoot

if (-not $ConfirmRealInstaller) {
    throw 'Explicit Beta13 B13-3 real installer confirmation required.'
}

$commit = (& git rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Cannot resolve B13-3 acceptance commit.'
}
Write-Host ('B13-3 Windows acceptance commit: ' + $commit)

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Tracked working files differ from B13-3 acceptance commit.' }

$frozen = '3e64155858d9b8c7efebc28aecc9689795159ae9'
& git merge-base --is-ancestor $frozen HEAD
if ($LASTEXITCODE -ne 0) { throw 'Accepted Beta13 B13-2 predecessor missing.' }

$frozenPaths = @(& git ls-tree -r --name-only $frozen)
$changes = @(& git diff --name-only $frozen HEAD)
$allowed = @(
    '.github/workflows/b133-real-windows-installer-foundation.yml',
    'BUILD-V013-B133-INSTALLER.ps1',
    'ROADMAP.md',
    'packaging/beta13_desktop_entry.py',
    'packaging/beta13_installer.nsi',
    'sentinel/beta13_installer.py',
    'tests/test_v013_b133_real_installer.py',
    'tools/acceptance/TEST-V013-B133-REAL-INSTALLER.ps1'
)
if (@($changes).Count -ne $allowed.Count) {
    throw ('Unexpected B13-3 diff count: ' + @($changes).Count + ' expected ' + $allowed.Count)
}
foreach ($path in $changes) {
    if ($allowed -notcontains $path) { throw ('Unexpected B13-3 changed path: ' + $path) }
    if ($path -ne 'ROADMAP.md' -and $frozenPaths -contains $path) {
        throw ('Frozen B13-2 path changed: ' + $path)
    }
}
Write-Host 'Accepted B13-2 source immutability and repository hygiene: PASS'

$existingProductKey = 'Registry::HKEY_CURRENT_USER\Software\BC TECH Studio\BC Sentinel'
$existingUninstallKey = 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\BCSentinel'
$startMenuDir = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\BC Sentinel'
if ((Test-Path $existingProductKey) -or (Test-Path $existingUninstallKey) -or (Test-Path -LiteralPath $startMenuDir)) {
    throw 'An existing BC Sentinel per-user installation is present; B13-3 acceptance refuses to overwrite it.'
}

$py = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) {
    $py = (Get-Command python -ErrorAction Stop).Source
}

& $py -m compileall -q sentinel/beta13_installer.py packaging/beta13_desktop_entry.py tests/test_v013_b133_real_installer.py
if ($LASTEXITCODE -ne 0) { throw 'B13-3 compile failed.' }

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
$testBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b133-pytest-' + [guid]::NewGuid().ToString('N'))
try {
    & $py -m pytest -q --basetemp $testBase @tests
    if ($LASTEXITCODE -ne 0) { throw 'Beta5 through Beta13 B13-3 regression failed.' }
}
finally {
    if (Test-Path -LiteralPath $testBase) {
        Remove-Item -LiteralPath $testBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

& $py -m sentinel.beta13_installer
if ($LASTEXITCODE -ne 0) { throw 'B13-3 installer contract self-check failed.' }

$acceptRoot = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b133-accept-' + [guid]::NewGuid().ToString('N'))
$buildRoot = Join-Path $acceptRoot 'build'
$lifecycleRoot = Join-Path $acceptRoot 'lifecycle'
$installRoot = Join-Path $lifecycleRoot 'installed-product'
$persistentSentinel = Join-Path $lifecycleRoot 'persistent-data.keep'
$unknownChild = Join-Path $installRoot 'user-owned.keep'
$installer = Join-Path $buildRoot 'installer\BC-Sentinel-Setup-v0.13.0-b133.exe'
$evidencePath = Join-Path $buildRoot 'installer\installer-evidence.json'
$payloadManifestPath = Join-Path $buildRoot 'payload\BC-Sentinel\install-payload-manifest.json'
$uninstaller = Join-Path $installRoot 'Uninstall.exe'
$installedExe = Join-Path $installRoot 'BC-Sentinel.exe'
$installedManifest = Join-Path $installRoot 'install-payload-manifest.json'
$installed = $false

New-Item -ItemType Directory -Path $lifecycleRoot -Force | Out-Null
Set-Content -LiteralPath $persistentSentinel -Value 'preserve-me' -Encoding UTF8

try {
    & (Join-Path $repoRoot 'BUILD-V013-B133-INSTALLER.ps1') -OutputRoot $buildRoot
    if ($LASTEXITCODE -ne 0) { throw 'B13-3 installer build pipeline failed.' }
    if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) { throw 'B13-3 installer artifact missing.' }
    if (-not (Test-Path -LiteralPath $evidencePath -PathType Leaf)) { throw 'B13-3 installer evidence missing.' }
    if (-not (Test-Path -LiteralPath $payloadManifestPath -PathType Leaf)) { throw 'B13-3 payload manifest missing.' }

    $evidence = Get-Content -LiteralPath $evidencePath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$evidence.build_commit -ne $commit) { throw 'B13-3 installer evidence build commit mismatch.' }
    if ([bool]$evidence.artifact_signed) { throw 'B13-3 falsely claims a signed installer.' }
    if (-not [bool]$evidence.installer_available -or -not [bool]$evidence.uninstaller_available) {
        throw 'B13-3 installer/uninstaller availability evidence failed.'
    }
    if (-not [bool]$evidence.persistent_data_preserved_by_default -or -not [bool]$evidence.unknown_install_children_preserved) {
        throw 'B13-3 preservation evidence failed.'
    }

    $installArgs = @('/S', ('/D=' + $installRoot))
    $installProcess = Start-Process -FilePath $installer -ArgumentList $installArgs -Wait -PassThru
    if ($installProcess.ExitCode -ne 0) { throw ('B13-3 installer exited with ' + $installProcess.ExitCode) }
    $installed = $true

    if (-not (Test-Path -LiteralPath $installedExe -PathType Leaf)) { throw 'B13-3 installed executable missing.' }
    if (-not (Test-Path -LiteralPath $installedManifest -PathType Leaf)) { throw 'B13-3 installed payload manifest missing.' }
    if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) { throw 'B13-3 installed uninstaller missing.' }
    if (-not (Test-Path $existingProductKey) -or -not (Test-Path $existingUninstallKey)) {
        throw 'B13-3 per-user installer registry metadata missing.'
    }
    if (-not (Test-Path -LiteralPath (Join-Path $startMenuDir 'BC Sentinel.lnk') -PathType Leaf)) {
        throw 'B13-3 Start Menu shortcut missing.'
    }

    $selfCheck = Start-Process -FilePath $installedExe -ArgumentList @('--self-check') -Wait -PassThru
    if ($selfCheck.ExitCode -ne 0) { throw ('B13-3 installed self-check failed exit=' + $selfCheck.ExitCode) }

    $smoke = Start-Process -FilePath $installedExe -ArgumentList @('--smoke') -Wait -PassThru
    if ($smoke.ExitCode -ne 0) { throw ('B13-3 installed UI smoke failed exit=' + $smoke.ExitCode) }

    Set-Content -LiteralPath $unknownChild -Value 'user-owned-content' -Encoding UTF8
    $unknownHashBefore = (Get-FileHash -LiteralPath $unknownChild -Algorithm SHA256).Hash.ToLowerInvariant()
    $persistentHashBefore = (Get-FileHash -LiteralPath $persistentSentinel -Algorithm SHA256).Hash.ToLowerInvariant()

    $uninstallProcess = Start-Process -FilePath $uninstaller -ArgumentList @('/S') -Wait -PassThru
    if ($uninstallProcess.ExitCode -ne 0) { throw ('B13-3 uninstaller exited with ' + $uninstallProcess.ExitCode) }
    $installed = $false
    Start-Sleep -Milliseconds 800

    if (Test-Path -LiteralPath $installedExe) { throw 'B13-3 uninstaller left product executable behind.' }
    if (Test-Path -LiteralPath $installedManifest) { throw 'B13-3 uninstaller left payload manifest behind.' }
    if (-not (Test-Path -LiteralPath $unknownChild -PathType Leaf)) { throw 'B13-3 uninstaller removed an unknown user-owned child.' }
    if ((Get-FileHash -LiteralPath $unknownChild -Algorithm SHA256).Hash.ToLowerInvariant() -ne $unknownHashBefore) {
        throw 'B13-3 uninstaller modified unknown user-owned content.'
    }
    if (-not (Test-Path -LiteralPath $persistentSentinel -PathType Leaf)) { throw 'B13-3 uninstaller removed external persistent data.' }
    if ((Get-FileHash -LiteralPath $persistentSentinel -Algorithm SHA256).Hash.ToLowerInvariant() -ne $persistentHashBefore) {
        throw 'B13-3 uninstaller modified external persistent data.'
    }
    if (Test-Path $existingProductKey -or Test-Path $existingUninstallKey) {
        throw 'B13-3 uninstaller left per-user registry metadata behind.'
    }
    if (Test-Path -LiteralPath $startMenuDir) { throw 'B13-3 uninstaller left Start Menu directory behind.' }

    & $py -c "import json,sys; from pathlib import Path; from sentinel.beta13_installer import validate_installer_evidence; e=json.loads(Path(sys.argv[1]).read_text(encoding='utf-8')); f=validate_installer_evidence(e,installer_path=Path(sys.argv[2]),expected_build_commit=sys.argv[3]); assert not f,f; print(json.dumps({'installer_sha256':e['installer_sha256'],'installer_bytes':e['installer_bytes'],'payload_tree_digest':e['payload_tree_digest'],'payload_file_count':e['payload_file_count'],'evidence_digest':e['evidence_digest']},indent=2,sort_keys=True))" $evidencePath $installer $commit
    if ($LASTEXITCODE -ne 0) { throw 'B13-3 final installer evidence validation failed.' }

    & $py -c "import json; from sentinel.beta13_installer import self_check; r=self_check(); p=r['readiness_projection']; assert r['passed']; assert p['pillar_counts']=={'READY':7,'PARTIAL':1,'BLOCKED':2}; assert p['release_blockers']==['CODE_SIGNING','LICENSING_TRIAL','PRIVACY_SUPPORT']; assert p['release_blocker_count']==3; assert r['installer_foundation_ready']; assert r['administrator_required'] is False; assert r['persistent_data_preserved_by_default']; assert r['unknown_install_children_preserved']; assert r['artifact_signed'] is False; print(json.dumps({'b13_3_passed':True,'contract_digest':r['contract_digest'],'pillar_counts':p['pillar_counts'],'release_blockers':p['release_blockers'],'release_blocker_count':p['release_blocker_count'],'installer_foundation_ready':r['installer_foundation_ready'],'artifact_signed':r['artifact_signed']},indent=2,sort_keys=True))"
    if ($LASTEXITCODE -ne 0) { throw 'B13-3 final readiness assertions failed.' }

    Write-Host 'B13-3 lifecycle: install=PASS packaged_self_check=PASS packaged_ui_smoke=PASS uninstall=PASS'
    Write-Host 'B13-3 preservation: unknown_child=PRESERVED external_persistent_data=PRESERVED'
    Write-Host 'B13-3 privilege boundary: PER_USER / UAC_NOT_REQUIRED / SERVICE=false / DRIVER=false / AUTOSTART=false'
    Write-Host 'BC SENTINEL v0.13.0 B13-3 REAL WINDOWS INSTALLER FOUNDATION - PASS'
}
finally {
    if ($installed -and (Test-Path -LiteralPath $uninstaller -PathType Leaf)) {
        try { Start-Process -FilePath $uninstaller -ArgumentList @('/S') -Wait | Out-Null } catch {}
    }
    try {
        if (Test-Path $existingProductKey) { Remove-Item $existingProductKey -Recurse -Force -ErrorAction SilentlyContinue }
        if (Test-Path $existingUninstallKey) { Remove-Item $existingUninstallKey -Recurse -Force -ErrorAction SilentlyContinue }
        if (Test-Path -LiteralPath $startMenuDir) { Remove-Item -LiteralPath $startMenuDir -Recurse -Force -ErrorAction SilentlyContinue }
        if (Test-Path -LiteralPath $acceptRoot) { Remove-Item -LiteralPath $acceptRoot -Recurse -Force -ErrorAction SilentlyContinue }
    }
    catch {}
}
