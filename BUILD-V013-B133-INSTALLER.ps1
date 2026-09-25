param(
    [string]$OutputRoot = ".\\dist\\B13-B133"
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

$RepoRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
Set-Location -LiteralPath $RepoRoot

function Remove-BestEffort([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    try { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop }
    catch { Write-Host ('B13-3 cleanup warning: ' + $_.Exception.Message) -ForegroundColor DarkYellow }
}

function Resolve-BuildCommit {
    $value = (& git rev-parse --verify HEAD).Trim().ToLowerInvariant()
    if ($LASTEXITCODE -ne 0 -or $value -notmatch '^[0-9a-f]{40}$') {
        throw 'Cannot resolve exact B13-3 build commit.'
    }
    return $value
}

$Py = Join-Path $RepoRoot '.venv\\Scripts\\python.exe'
if (-not (Test-Path -LiteralPath $Py -PathType Leaf)) {
    $Py = (Get-Command python -ErrorAction Stop).Source
}

& $Py -c "import PyInstaller, PySide6, cryptography"
if ($LASTEXITCODE -ne 0) { throw 'B13-3 build dependencies unavailable.' }

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
$InstallerPath = Join-Path $InstallerRoot 'BC-Sentinel-Setup-v0.13.0-b133.exe'
$EvidencePath = Join-Path $InstallerRoot 'installer-evidence.json'
$PayloadManifest = Join-Path $ProductRoot 'install-payload-manifest.json'
$UninstallInclude = Join-Path $OutRoot 'payload-uninstall.nsh'

Remove-BestEffort $OutRoot
New-Item -ItemType Directory -Path $PayloadRoot, $InstallerRoot -Force | Out-Null

$Entry = Join-Path $RepoRoot 'packaging\\beta13_desktop_entry.py'
$RuntimeHook = Join-Path $RepoRoot 'packaging\\beta11_windowed_runtime_hook.py'
if (-not (Test-Path -LiteralPath $Entry -PathType Leaf)) { throw 'B13-3 desktop entrypoint missing.' }
if (-not (Test-Path -LiteralPath $RuntimeHook -PathType Leaf)) { throw 'B13-3 runtime hook missing.' }

$WorkBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b133-build-' + [guid]::NewGuid().ToString('N'))
$WorkPath = Join-Path $WorkBase 'work'
$SpecPath = Join-Path $WorkBase 'spec'
$TempPath = Join-Path $WorkBase 'temp'
New-Item -ItemType Directory -Path $WorkPath, $SpecPath, $TempPath -Force | Out-Null

try {
    $OldTemp = $env:TEMP
    $OldTmp = $env:TMP
    $env:TEMP = $TempPath
    $env:TMP = $TempPath
    try {
        $PyInstallerArgs = @(
            '--noconfirm',
            '--clean',
            '--onedir',
            '--windowed',
            '--name', 'BC-Sentinel',
            '--distpath', $PayloadRoot,
            '--workpath', $WorkPath,
            '--specpath', $SpecPath,
            '--paths', $RepoRoot,
            '--runtime-hook', $RuntimeHook,
            '--hidden-import', 'sentinel.smart_scan_live_provider',
            '--hidden-import', 'sentinel.smart_scan_runtime_compat',
            '--hidden-import', 'sentinel.guided_resolution_live_provider',
            '--hidden-import', 'sentinel.guided_resolution_real_file_execution',
            '--hidden-import', 'sentinel.beta13_response_ui',
            '--hidden-import', 'sentinel.beta13_safe_response',
            '--hidden-import', 'sentinel.beta13_secure_updates',
            '--hidden-import', 'sentinel.beta13_installer',
            $Entry
        )
        & $Py (Join-Path $RepoRoot 'tools\windows_packaging.py') @PyInstallerArgs
        if ($LASTEXITCODE -ne 0) { throw 'PyInstaller B13-3 onedir build failed.' }
    }
    finally {
        $env:TEMP = $OldTemp
        $env:TMP = $OldTmp
    }

    $Exe = Join-Path $ProductRoot 'BC-Sentinel.exe'
    if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) { throw 'B13-3 packaged executable missing.' }

    # Contract-only self-check does not import QtWidgets. Exercise the frozen UI
    # before producing an installer so missing/incompatible DLLs fail the build.
    $SmokeProfile = Join-Path $WorkBase 'smoke-profile'
    New-Item -ItemType Directory -Path $SmokeProfile -Force | Out-Null
    $SavedLocalAppData = $env:LOCALAPPDATA
    try {
        $env:LOCALAPPDATA = $SmokeProfile
        $SmokeProcess = Start-Process -FilePath $Exe -ArgumentList '--smoke' -WindowStyle Hidden -PassThru
        if (-not $SmokeProcess.WaitForExit(120000)) {
            $SmokeProcess.Kill()
            throw 'Packaged UI smoke timed out.'
        }
        $SmokeProcess.Refresh()
        if ($SmokeProcess.ExitCode -ne 0) { throw ('Packaged UI smoke failed: ' + $SmokeProcess.ExitCode) }
    }
    finally { $env:LOCALAPPDATA = $SavedLocalAppData }

    $ManifestArgs = @(
        '-m', 'sentinel.beta13_installer',
        '--write-payload-manifest',
        '--root', $ProductRoot,
        '--build-commit', $BuildCommit,
        '--python-version', $PythonVersion,
        '--pyinstaller-version', $PyInstallerVersion
    )
    & $Py @ManifestArgs
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $PayloadManifest -PathType Leaf)) {
        throw 'B13-3 payload manifest generation failed.'
    }

    $ValidatePayloadArgs = @(
        '-m', 'sentinel.beta13_installer',
        '--validate-payload-manifest',
        '--payload-manifest', $PayloadManifest,
        '--root', $ProductRoot,
        '--build-commit', $BuildCommit
    )
    & $Py @ValidatePayloadArgs
    if ($LASTEXITCODE -ne 0) { throw 'B13-3 payload manifest verification failed.' }

    & $Py -c "import json,sys; from pathlib import Path; from sentinel.beta13_installer import uninstall_include; data=json.loads(Path(sys.argv[1]).read_text(encoding='utf-8')); Path(sys.argv[2]).write_text(uninstall_include(data),encoding='utf-8')" $PayloadManifest $UninstallInclude
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $UninstallInclude -PathType Leaf)) {
        throw 'B13-3 uninstall include generation failed.'
    }

    $NsisRoot = Join-Path $WorkBase 'nsis'
    $NsisZip = Join-Path $WorkBase 'nsis-3.12.zip'
    $NsisUrl = 'https://downloads.sourceforge.net/project/nsis/NSIS%203/3.12/nsis-3.12.zip'
    $ExpectedNsisHash = '56581f90db321581c5381193d796fffcf2d24b2f8fed2160a6c6a3baa67f2c4f'

    $Curl = (Get-Command curl.exe -ErrorAction Stop).Source
    & $Curl -L --fail --silent --show-error --retry 4 --retry-delay 2 --output $NsisZip $NsisUrl
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $NsisZip -PathType Leaf)) {
        throw 'B13-3 verified NSIS ZIP download failed.'
    }
    $NsisSize = (Get-Item -LiteralPath $NsisZip).Length
    if ($NsisSize -ne 2362938) {
        throw ('B13-3 NSIS ZIP size mismatch: ' + $NsisSize)
    }
    $ActualNsisHash = (Get-FileHash -LiteralPath $NsisZip -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ActualNsisHash -ne $ExpectedNsisHash) {
        throw ('B13-3 NSIS ZIP SHA256 mismatch: ' + $ActualNsisHash)
    }

    Expand-Archive -LiteralPath $NsisZip -DestinationPath $NsisRoot -Force
    $MakeNsis = Get-ChildItem -LiteralPath $NsisRoot -Recurse -Filter 'makensis.exe' -File | Select-Object -First 1
    if (-not $MakeNsis) { throw 'B13-3 makensis.exe missing from verified NSIS archive.' }

    $Nsi = Join-Path $RepoRoot 'packaging\\beta13_installer.nsi'
    if (-not (Test-Path -LiteralPath $Nsi -PathType Leaf)) { throw 'B13-3 NSIS installer script missing.' }

    $PayloadDefine = '/DPAYLOAD_DIR=' + $ProductRoot
    $OutputDefine = '/DOUTPUT_DIR=' + $InstallerRoot
    $UninstallDefine = '/DUNINSTALL_INCLUDE=' + $UninstallInclude

    & $MakeNsis.FullName /V3 $PayloadDefine $OutputDefine $UninstallDefine $Nsi
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
        throw 'B13-3 NSIS installer compilation failed.'
    }

    $EvidenceArgs = @(
        '-m', 'sentinel.beta13_installer',
        '--write-installer-evidence',
        '--installer', $InstallerPath,
        '--payload-manifest', $PayloadManifest,
        '--output', $EvidencePath,
        '--build-commit', $BuildCommit,
        '--nsis-version', '3.12'
    )
    & $Py @EvidenceArgs
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $EvidencePath -PathType Leaf)) {
        throw 'B13-3 installer evidence generation failed.'
    }

    $ValidateInstallerArgs = @(
        '-m', 'sentinel.beta13_installer',
        '--validate-installer-evidence',
        '--installer', $InstallerPath,
        '--output', $EvidencePath,
        '--build-commit', $BuildCommit
    )
    & $Py @ValidateInstallerArgs
    if ($LASTEXITCODE -ne 0) { throw 'B13-3 installer evidence verification failed.' }

    $Evidence = Get-Content -LiteralPath $EvidencePath -Raw -Encoding UTF8 | ConvertFrom-Json
    Write-Host ('B13-3 BUILD COMMIT=' + $BuildCommit)
    Write-Host ('B13-3 PYTHON=' + $PythonVersion + ' PYINSTALLER=' + $PyInstallerVersion + ' NSIS=3.12')
    Write-Host ('B13-3 INSTALLER SHA256=' + $Evidence.installer_sha256)
    Write-Host ('B13-3 PAYLOAD TREE DIGEST=' + $Evidence.payload_tree_digest)
    Write-Host ('B13-3 INSTALLER=' + $InstallerPath)
    Write-Host ('B13-3 EVIDENCE=' + $EvidencePath)
    Write-Host 'BC SENTINEL v0.13.0 B13-3 REAL WINDOWS INSTALLER BUILD - PASS'
}
finally {
    Remove-BestEffort $WorkBase
}
