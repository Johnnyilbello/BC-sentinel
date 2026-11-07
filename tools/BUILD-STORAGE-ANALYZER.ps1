param([string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repoRoot 'build\storage_analyzer' }
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw '.NET Framework 4.8 compiler unavailable.' }
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$sourceDirectory = Join-Path $PSScriptRoot 'storage_analyzer'
$sources = @('Main.cs', 'Storage.cs', 'Removal.cs', 'Uninstall.cs') | ForEach-Object {
    Join-Path $sourceDirectory $_
}
$target = Join-Path $OutputDirectory 'BC Storage Analyzer.exe'
& $compiler /nologo /target:winexe /optimize+ /codepage:65001 "/out:$target" /r:System.Windows.Forms.dll /r:System.Drawing.dll @sources
if ($LASTEXITCODE -ne 0) { throw 'Storage Analyzer compilation failed.' }
Write-Host "Storage Analyzer built at $target"
