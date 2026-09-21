param(
    [string]$OutputRoot = ".\\dist\\B13-B133",
    [switch]$UseCurrentEnvironment
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

function Assert-BootstrapPython([string]$PythonPath) {
    & $PythonPath -c "import platform,struct,sys; assert sys.version_info[:2] == (3,12), sys.version; assert struct.calcsize('P')*8 == 64, platform.architecture(); print(platform.python_version())"
    if ($LASTEXITCODE -ne 0) {
        throw 'B13-3 requires a 64-bit Python 3.12 bootstrap runtime.'
    }
}

function Assert-QtEnvironment([string]$PythonPath) {
    $probe = @'
import importlib.metadata as metadata
import json
import PySide6.QtCore
import PySide6.QtGui
import PySide6.QtWidgets

names = ("PySide6", "PySide6-Essentials", "PySide6-Addons", "shiboken6")
versions = {name: metadata.version(name) for name in names}
if len(set(versions.values())) != 1:
    raise SystemExit("Qt package version mismatch: " + json.dumps(versions, sort_keys=True))
print(json.dumps({
    "packages": versions,
    "qt_runtime": PySide6.QtCore.qVersion(),
}, sort_keys=True))
'@
    $result = (& $PythonPath -c $probe).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($result)) {
        throw 'B13-3 Qt build environment preflight failed.'
    }
    $parsed = $result | ConvertFrom-Json
    Write-Host ('B13-3 QT BUILD PREFLIGHT=' + $result)
    return $parsed
}

function Assert-BundledQtRuntime([string]$Root) {
    $required = @('Qt6Core.dll', 'Qt6Gui.dll', 'Qt6Widgets.dll')
    $versions = @()
    foreach ($name in $required) {
        $matches = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Filter $name)
        if ($matches.Count -ne 1) {
            throw ('B13-3 packaged Qt runtime expected exactly one ' + $name + ', found ' + $matches.Count)
        }
        $fileVersion = [string]$matches[0].VersionInfo.FileVersion
        if ([string]::IsNullOrWhiteSpace($fileVersion)) {
            throw ('B13-3 packaged Qt runtime missing file version for ' + $name)
        }
        $versions += $fileVersion
        Write-Host ('B13-3 QT DLL ' + $name + ' version=' + $fileVersion + ' sha256=' + (Get-FileHash -LiteralPath $matches[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant())
    }
    if (@($versions | Select-Object -Unique).Count -ne 1) {
        throw ('B13-3 packaged Qt DLL version mismatch: ' + ($versions -join ', '))
    }

    $widgetsModules = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Filter 'QtWidgets*.pyd')
    if ($widgetsModules.Count -lt 1) {
        throw 'B13-3 packaged PySide6 QtWidgets extension missing.'
    }
}

function Invoke-CleanPackagedCheck(
    [string]$Executable,
    [string[]]$Arguments,
    [string]$Label
) {
    $names = @(
        'PATH',
        'PYTHONHOME',
        'PYTHONPATH',
        'QT_PLUGIN_PATH',
        'QT_QPA_PLATFORM_PLUGIN_PATH',
        'QML2_IMPORT_PATH'
    )
    $saved = @{}
    foreach ($name in $names) {
        $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    }

    try {
        $env:PATH = (Join-Path $env:SystemRoot 'System32') + ';' + $env:SystemRoot
        foreach ($name in @('PYTHONHOME','PYTHONPATH','QT_PLUGIN_PATH','QT_QPA_PLATFORM_PLUGIN_PATH','QML2_IMPORT_PATH')) {
            Remove-Item -LiteralPath ('Env:' + $name) -ErrorAction SilentlyContinue
        }

        $process = Start-Process -FilePath $Executable -ArgumentList $Arguments -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw ('B13-3 clean packaged ' + $Label + ' failed exit=' + $process.ExitCode)
        }
        Write-Host ('B13-3 CLEAN PACKAGED ' + $Label + '=PASS')
    }
    finally {
        foreach ($name in $names) {
            $value = $saved[$name]
            if ($null -eq $value) {
                Remove-Item -LiteralPath ('Env:' + $name) -ErrorAction SilentlyContinue
            } else {
                Set-Item -LiteralPath ('Env:' + $name) -Value ([string]$value)
            }
        }
    }
}

$BuildCommit = Resolve-BuildCommit
$WorkBase = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-b133-build-' + [guid]::NewGuid().ToString('N'))
$WorkPath = Join-Path $WorkBase 'work'
$SpecPath = Join-Path $WorkBase 'spec'
$TempPath = Join-Path $WorkBase 'temp'
$BuildVenv = Join-Path $WorkBase 'build-venv'
New-Item -ItemType Directory -Path $WorkPath, $SpecPath, $TempPath -Force | Out-Null

$BootstrapPy = Join-Path $RepoRoot '.venv\\Scripts\\python.exe'
if (-not (Test-Path -LiteralPath $BootstrapPy -PathType Leaf)) {
    $BootstrapPy = (Get-Command python -ErrorAction Stop).Source
}
Assert-BootstrapPython $BootstrapPy

if ($UseCurrentEnvironment) {
    $Py = $BootstrapPy
    Write-Host 'B13-3 BUILD ENVIRONMENT=current (explicit override)'
} else {
    & $BootstrapPy -m venv $BuildVenv
    if ($LASTEXITCODE -ne 0) { throw 'B13-3 isolated build environment creation failed.' }
    $Py = Join-Path $BuildVenv 'Scripts\\python.exe'
    if (-not (Test-Path -LiteralPath $Py -PathType Leaf)) {
        throw 'B13-3 isolated build Python missing.'
    }

    & $Py -m pip install --disable-pip-version-check --upgrade pip
    if ($LASTEXITCODE -ne 0) { throw 'B13-3 isolated pip bootstrap failed.' }
    & $Py -m pip install --disable-pip-version-check -r (Join-Path $RepoRoot 'requirements.txt')
    if ($LASTEXITCODE -ne 0) { throw 'B13-3 isolated dependency installation failed.' }
    & $Py -m pip check
    if ($LASTEXITCODE -ne 0) { throw 'B13-3 isolated dependency consistency check failed.' }
    Write-Host 'B13-3 BUILD ENVIRONMENT=isolated-clean-venv'
}

& $Py -c "import PyInstaller, PySide6, cryptography"
if ($LASTEXITCODE -ne 0) { throw 'B13-3 build dependencies unavailable.' }
$QtEnvironment = Assert-QtEnvironment $Py

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
$RuntimeHook = Join-Path $RepoRoot 'packaging\\windows_qt_runtime_hook.py'
if (-not (Test-Path -LiteralPath $Entry -PathType Leaf)) { throw 'B13-3 desktop entrypoint missing.' }
if (-not (Test-Path -LiteralPath $RuntimeHook -PathType Leaf)) { throw 'B13-3 Qt runtime hardening hook missing.' }

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
            '--noupx',
            '--name', 'BC-Sentinel',
            '--distpath', $PayloadRoot,
            '--workpath', $WorkPath,
            '--specpath', $SpecPath,
            '--paths', $RepoRoot,
            '--runtime-hook', $RuntimeHook,
            '--hidden-import', 'PySide6.QtCore',
            '--hidden-import', 'PySide6.QtGui',
            '--hidden-import', 'PySide6.QtWidgets',
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
        & $Py -m PyInstaller @PyInstallerArgs
        if ($LASTEXITCODE -ne 0) { throw 'PyInstaller B13-3 onedir build failed.' }
    }
    finally {
        $env:TEMP = $OldTemp
        $env:TMP = $OldTmp
    }

    $Exe = Join-Path $ProductRoot 'BC-Sentinel.exe'
    if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) { throw 'B13-3 packaged executable missing.' }

    Assert-BundledQtRuntime $ProductRoot
    Invoke-CleanPackagedCheck $Exe @('--self-check') 'SELF-CHECK'
    Invoke-CleanPackagedCheck $Exe @('--smoke') 'QT-SMOKE'

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
    $QtPackageVersion = [string]$QtEnvironment.packages.PySide6
    Write-Host ('B13-3 BUILD COMMIT=' + $BuildCommit)
    Write-Host ('B13-3 PYTHON=' + $PythonVersion + ' PYINSTALLER=' + $PyInstallerVersion + ' PYSIDE6=' + $QtPackageVersion + ' NSIS=3.12')
    Write-Host ('B13-3 INSTALLER SHA256=' + $Evidence.installer_sha256)
    Write-Host ('B13-3 PAYLOAD TREE DIGEST=' + $Evidence.payload_tree_digest)
    Write-Host ('B13-3 INSTALLER=' + $InstallerPath)
    Write-Host ('B13-3 EVIDENCE=' + $EvidencePath)
    Write-Host 'BC SENTINEL v0.13.0 B13-3 WINDOWS QT RUNTIME HARDENED BUILD - PASS'
}
finally {
    Remove-BestEffort $WorkBase
}
