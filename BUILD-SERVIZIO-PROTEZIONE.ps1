$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$pyinstaller = Join-Path $PSScriptRoot ".venv\Scripts\pyinstaller.exe"
if (-not (Test-Path $venvPython) -or -not (Test-Path $pyinstaller)) {
    throw ".venv non pronta. Eseguire prima: python -m venv .venv ; .\.venv\Scripts\python.exe -m pip install -r requirements.txt"
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "PyInstaller non richiede privilegi amministrativi. Per le build future usare una PowerShell standard; continuo per compatibilità."
}

$projectRoot = $PSScriptRoot
$buildDir = Join-Path $projectRoot "build\BC-Sentinel-Protection"
$distDir = Join-Path $projectRoot "dist\BC-Sentinel-Protection"
$spec = Join-Path $projectRoot "BC-Sentinel-Protection.spec"
$brokerBuildDir = Join-Path $projectRoot "build\BC-Sentinel-Broker"
$brokerSpec = Join-Path $projectRoot "BC-Sentinel-Broker.spec"
Remove-Item $buildDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $distDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $spec -Force -ErrorAction SilentlyContinue
Remove-Item $brokerBuildDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $brokerSpec -Force -ErrorAction SilentlyContinue

$args = @(
    "--noconfirm",
    "--clean",
    "--paths", $projectRoot,
    "--collect-submodules", "sentinel",
    "--add-data", "rules;rules",
    "--name", "BC-Sentinel-Protection",
    "--hidden-import", "win32timezone",
    "--hidden-import", "win32service",
    "--hidden-import", "win32serviceutil",
    "--hidden-import", "win32event",
    "--hidden-import", "servicemanager",
    "--hidden-import", "win32pipe",
    "--hidden-import", "win32file",
    "--hidden-import", "win32security",
    "--hidden-import", "win32api",
    "--hidden-import", "win32con",
    "--hidden-import", "win32com",
    "--hidden-import", "win32com.client",
    "--hidden-import", "pythoncom",
    "--hidden-import", "pywintypes",
    "--hidden-import", "etw",
    "packaging\protection_service_entry.py"
)

& $pyinstaller @args
if ($LASTEXITCODE -ne 0) { throw "Build BC-Sentinel-Protection fallita." }

$exe = Join-Path $distDir "BC-Sentinel-Protection.exe"
if (-not (Test-Path $exe)) { throw "EXE del Protection Service non trovato dopo la build." }

# Build the narrow one-action UAC broker as a separate frozen executable. It
# accepts only an opaque ticket id and never a command/path payload.
$brokerArgs = @(
    "--noconfirm",
    "--clean",
    "--paths", $projectRoot,
    "--distpath", $distDir,
    "--workpath", $brokerBuildDir,
    "--specpath", $projectRoot,
    "--name", "BC-Sentinel-Broker",
    "--hidden-import", "win32pipe",
    "--hidden-import", "win32file",
    "--hidden-import", "win32security",
    "--hidden-import", "win32api",
    "--hidden-import", "win32con",
    "--hidden-import", "pywintypes",
    "packaging\privileged_broker_entry.py"
)
& $pyinstaller @brokerArgs
if ($LASTEXITCODE -ne 0) { throw "Build BC-Sentinel-Broker fallita." }
$brokerExe = Join-Path $distDir "BC-Sentinel-Broker\BC-Sentinel-Broker.exe"
if (-not (Test-Path $brokerExe)) { throw "EXE Privileged Broker non trovato dopo la build." }

# Build an immutable-file SHA-256 manifest. It is authenticated only after the
# tree has been deployed under Program Files and the machine integrity key has
# been created by the elevated installer.
& $venvPython -m tools.build_protection_manifest $distDir
if ($LASTEXITCODE -ne 0) { throw "Generazione protection-integrity.json fallita." }
$manifest = Join-Path $distDir "protection-integrity.json"
if (-not (Test-Path $manifest)) { throw "Manifest di integrità non trovato dopo la build." }

& $exe pipe-selftest
if ($LASTEXITCODE -ne 0) { throw "Il frozen Protection Service non riesce a creare la Named Pipe protetta." }

Write-Host ""
Write-Host "BUILD PROTECTION SERVICE + UAC BROKER + FIREWALL OK" -ForegroundColor Green
Write-Host $exe -ForegroundColor Green
Write-Host $brokerExe -ForegroundColor Green
Write-Host $manifest -ForegroundColor Green
