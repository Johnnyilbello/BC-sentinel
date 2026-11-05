#Requires -Version 7.0
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('BCSentinel-storage-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$sourceRoot = Join-Path $PSScriptRoot 'storage_analyzer'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$checksExe = Join-Path $testRoot 'Checks.exe'
$removalExe = Join-Path $testRoot 'RemovalChecks.exe'
& $compiler /nologo "/out:$checksExe" (Join-Path $sourceRoot 'Storage.cs') (Join-Path $sourceRoot 'Uninstall.cs') (Join-Path $sourceRoot 'Checks.cs')
if ($LASTEXITCODE -ne 0) { throw 'Scan checks compilation failed.' }
& $compiler /nologo "/out:$removalExe" (Join-Path $sourceRoot 'Removal.cs') (Join-Path $sourceRoot 'RemovalChecks.cs')
if ($LASTEXITCODE -ne 0) { throw 'Removal checks compilation failed.' }
$fixture = Join-Path $testRoot 'fixture'
$alpha = Join-Path $fixture 'Alpha'
$beta = Join-Path $fixture 'Beta'
$deep = Join-Path (Join-Path $alpha ('a' * 180)) ('b' * 80)
New-Item -ItemType Directory -Force -Path $deep,$beta | Out-Null
[IO.File]::WriteAllBytes((Join-Path $deep 'big.BIN'), [byte[]]::new(4096))
[IO.File]::WriteAllBytes((Join-Path $beta 'small.bin'), [byte[]]::new(3072))
[IO.File]::WriteAllBytes((Join-Path $alpha 'no-extension'), [byte[]]::new(7))
[IO.File]::WriteAllBytes((Join-Path $fixture 'root.txt'), [byte[]]::new(777))
New-Item -ItemType Junction -Path (Join-Path $beta 'linked') -Target $alpha | Out-Null
& $checksExe $fixture (Join-Path $testRoot 'export.csv')
if ($LASTEXITCODE -ne 0) { throw 'Storage scan/CSV checks failed.' }
$removalRoot = Join-Path $testRoot 'removal'
New-Item -ItemType Directory -Path $removalRoot | Out-Null
# Only the newly created sample paths below testRoot are passed to deletion.
$resolvedRoot = [IO.Path]::GetFullPath($removalRoot)
if (-not $resolvedRoot.StartsWith($testRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Removal fixture escaped the test workspace.'
}
$recycled = & $removalExe $resolvedRoot
if ($LASTEXITCODE -ne 0) { throw 'Native removal checks failed.' }
$shell = New-Object -ComObject Shell.Application
$found = @($shell.NameSpace(10).Items() | Where-Object {
    $_.Name -eq [IO.Path]::GetFileNameWithoutExtension($recycled) -or $_.Name -eq $recycled
})
if ($found.Count -ne 1) { throw 'Sample file not found in Windows Recycle Bin.' }
Write-Host 'PASS: sample file recycled; sample folder permanently removed; protected paths rejected.'
Write-Host "Test artifacts retained at $testRoot"
