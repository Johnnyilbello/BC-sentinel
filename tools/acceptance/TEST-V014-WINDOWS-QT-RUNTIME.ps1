param(
    [switch]$ConfirmWindowsQtRuntime,
    [string]$OutputRoot = ".\\dist\\V014-WINDOWS-QT-RUNTIME"
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

if (-not $ConfirmWindowsQtRuntime) {
    throw 'Explicit Windows Qt runtime hardening confirmation required.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\\..')).Path
Set-Location -LiteralPath $repoRoot

$commit = (& git rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Cannot resolve Windows Qt runtime acceptance commit.'
}

& git diff --quiet HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Tracked working files differ from the Windows Qt runtime acceptance commit.'
}

$baseline = 'e42044fd86aeddf6a176ac8e16ca93da14c6230f'
& git merge-base --is-ancestor $baseline HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Accepted T1-H2 baseline is not an ancestor.'
}

$py = Join-Path $repoRoot '.venv\\Scripts\\python.exe'
if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
    $bootstrap = (Get-Command python -ErrorAction Stop).Source
    & $bootstrap -m venv (Join-Path $repoRoot '.venv')
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $py -PathType Leaf)) {
        throw 'Unable to create local acceptance .venv.'
    }
}

& $py -c "import pytest,PySide6,PyInstaller,cryptography"
if ($LASTEXITCODE -ne 0) {
    Write-Host 'Installing BC Sentinel acceptance dependencies into .venv...'
    & $py -m pip install --disable-pip-version-check -r (Join-Path $repoRoot 'requirements.txt')
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to install Windows Qt runtime acceptance dependencies.'
    }
}

& $py -m pip check
if ($LASTEXITCODE -ne 0) {
    throw 'Acceptance environment dependency consistency check failed.'
}

& $py -m compileall -q packaging/windows_qt_runtime_hook.py tests/test_v014_windows_qt_runtime_hardening.py
if ($LASTEXITCODE -ne 0) {
    throw 'Windows Qt runtime hardening compile failed.'
}

& $py -m pytest -q tests/test_v014_windows_qt_runtime_hardening.py tests/test_v013_b133_real_installer.py
if ($LASTEXITCODE -ne 0) {
    throw 'Focused Windows Qt runtime regression failed.'
}

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repoRoot 'tools\\acceptance\\TEST-V014-T1-INPUT-HARDENING.ps1')
if ($LASTEXITCODE -ne 0) {
    throw 'Full Beta5-Beta14 regression failed before packaging.'
}

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repoRoot 'BUILD-V013-B133-INSTALLER.ps1') -OutputRoot $OutputRoot
if ($LASTEXITCODE -ne 0) {
    throw 'Windows Qt runtime hardened installer build failed.'
}

if ([IO.Path]::IsPathRooted($OutputRoot)) {
    $outRoot = $OutputRoot
} else {
    $outRoot = Join-Path $repoRoot $OutputRoot
}

$installer = Join-Path $outRoot 'installer\\BC-Sentinel-Setup-v0.13.0-b133.exe'
$evidence = Join-Path $outRoot 'installer\\installer-evidence.json'
if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) {
    throw 'Windows Qt runtime hardened installer missing.'
}
if (-not (Test-Path -LiteralPath $evidence -PathType Leaf)) {
    throw 'Windows Qt runtime hardened installer evidence missing.'
}

$hash = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host ('Windows Qt runtime acceptance commit: ' + $commit)
Write-Host ('Installer: ' + $installer)
Write-Host ('Installer SHA256: ' + $hash)
Write-Host 'Clean build venv=PASS Qt package consistency=PASS bundled DLL validation=PASS packaged self-check=PASS packaged Qt smoke=PASS'
Write-Host 'BC SENTINEL v0.14 WINDOWS QT RUNTIME HARDENING - PASS'
