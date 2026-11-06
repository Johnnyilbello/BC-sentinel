param(
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [Parameter(Mandatory=$true)][string]$PythonPath,
    [string]$Name = 'BC Sentinel'
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$buildRoot = Join-Path $repoRoot 'build\single-exe'
& (Join-Path $PSScriptRoot 'BUILD-STORAGE-ANALYZER.ps1')
$arguments = @(
    '--noconfirm', '--onefile', '--windowed', '--name', $Name,
    '--distpath', $OutputDirectory,
    '--workpath', (Join-Path $buildRoot 'work'),
    '--specpath', (Join-Path $buildRoot 'spec'),
    '--paths', $repoRoot,
    '--add-binary', ((Join-Path $repoRoot 'build\storage_analyzer') + ';storage_analyzer'),
    '--runtime-hook', (Join-Path $repoRoot 'packaging\beta11_windowed_runtime_hook.py'),
    '--hidden-import', 'sentinel.smart_scan_live_provider',
    '--hidden-import', 'sentinel.smart_scan_runtime_compat',
    '--hidden-import', 'sentinel.guided_resolution_live_provider',
    '--hidden-import', 'sentinel.guided_resolution_real_file_execution',
    '--hidden-import', 'yara',
    (Join-Path $repoRoot 'packaging\beta13_desktop_entry.py')
)
& $PythonPath (Join-Path $PSScriptRoot 'windows_packaging.py') @arguments
if ($LASTEXITCODE -ne 0) { throw 'Single EXE build failed.' }
