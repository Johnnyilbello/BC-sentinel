param(
    [Parameter(Mandatory=$true)][string]$ArtifactDirectory,
    [Parameter(Mandatory=$true)][string]$EvidenceDirectory
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$artifact = (Resolve-Path -LiteralPath $ArtifactDirectory).Path
$evidence = [IO.Path]::GetFullPath($EvidenceDirectory)
New-Item -ItemType Directory -Path $evidence -Force | Out-Null
$manifest = Get-Content -LiteralPath (Join-Path $artifact 'candidate-manifest.json') -Raw | ConvertFrom-Json
$zip = Join-Path $artifact 'BC-Sentinel-Offline-Candidate.zip'
if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant() -ne $manifest.zip_sha256) { throw 'Package hash mismatch.' }
$fixtureParent = 'D:\a\_temp'
if (-not (Test-Path -LiteralPath $fixtureParent -PathType Container)) { throw 'Second-volume fixture directory unavailable.' }
$instance = 'BCSentinel-VM-' + [guid]::NewGuid().ToString('N')
$installParent = [IO.Path]::GetFullPath($env:LOCALAPPDATA)
$install = Join-Path $installParent $instance
$fixture = Join-Path $fixtureParent $instance
$profile = Join-Path $install 'profile'
$reports = Join-Path $install 'reports'
if ((Test-Path -LiteralPath $install) -or (Test-Path -LiteralPath $fixture)) { throw 'Disposable paths already exist.' }
New-Item -ItemType Directory -Path $install,$fixture,$profile -Force | Out-Null
$oldProfile = $env:LOCALAPPDATA
$oldPath = $env:PATH
$oldPythonPath = $env:PYTHONPATH
$oldPythonHome = $env:PYTHONHOME
$oldQt = $env:QT_QPA_PLATFORM
$result = [ordered]@{
    source_commit = $manifest.source_commit
    zip_sha256 = $manifest.zip_sha256
    executable_sha256 = $manifest.exe_sha256
    environment = 'separate-fresh-GitHub-hosted-Windows-VM'
    windows_version = [Environment]::OSVersion.VersionString
    runner_image = $env:ImageVersion
    real_malware_used = $false
    public_stable_promoted = $false
    passed = $false
}
function Invoke-Candidate([string[]]$Arguments, [int]$ExpectedExit=0) {
    $quoted = $Arguments | ForEach-Object { '"' + $_ + '"' }
    $process = Start-Process -FilePath $script:exe -ArgumentList $quoted -WindowStyle Hidden -PassThru
    if (-not $process.WaitForExit(120000)) { $process.Kill(); throw 'Candidate test timeout.' }
    $process.Refresh()
    if ($process.ExitCode -ne $ExpectedExit) { throw ('Unexpected exit: ' + $process.ExitCode) }
}
try {
    Expand-Archive -LiteralPath $zip -DestinationPath $install
    $package = Join-Path $install 'BC-Sentinel-Offline-Candidate'
    $script:exe = Join-Path $package 'BC-Sentinel-Offline-Candidate.exe'
    if ((Get-FileHash -LiteralPath $script:exe -Algorithm SHA256).Hash.ToLowerInvariant() -ne $manifest.exe_sha256) { throw 'Installed executable hash mismatch.' }
    $identity = Get-Content -LiteralPath (Join-Path $package 'candidate-identity.json') -Raw | ConvertFrom-Json
    if ($identity.source_commit -ne $manifest.source_commit) { throw 'Installed commit mismatch.' }
    $env:LOCALAPPDATA = $profile
    $env:PATH = (Join-Path $env:SystemRoot 'System32') + ';' + $env:SystemRoot
    $env:PYTHONPATH = $null
    $env:PYTHONHOME = $null
    $env:QT_QPA_PLATFORM = 'offscreen'
    Invoke-Candidate @('--self-check')
    Invoke-Candidate @('--smoke')
    $result.installation_and_startup = $true
    $system32 = Join-Path $fixture 'Windows\System32'
    New-Item -ItemType Directory -Path (Join-Path $system32 'config') -Force | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $system32 'config\SYSTEM'), [byte[]](1,2,3))
    [IO.File]::WriteAllBytes((Join-Path $system32 'ntoskrnl.exe'), [byte[]](77,90,0,0))
    $sample = Join-Path $system32 'harmless.ps1'
    [IO.File]::WriteAllText($sample, '# BC_SENTINEL_VM_HARMLESS_MARKER')
    $before = @{}
    Get-ChildItem -LiteralPath $fixture -File -Recurse | ForEach-Object { $before[$_.FullName] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
    $catalog = Join-Path $install 'catalog.json'
    @{ schema='bc-sentinel-offline-intel-v1'; approved=$true; sha256=@(@{value=$before[$sample].ToLowerInvariant(); name='VM.Harmless.Marker'; source='synthetic-acceptance'}) } |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $catalog -Encoding ASCII
    $rules = Join-Path $install 'rules.yar'
    'rule BC_VM_HARMLESS { strings: $m = "BC_SENTINEL_VM_HARMLESS_MARKER" condition: $m }' | Set-Content -LiteralPath $rules -Encoding ASCII
    Invoke-Candidate @('--offline-root',$fixture,'--offline-output',$reports,'--intel-catalog',$catalog,'--yara-rules',$rules)
    $reportPath = Join-Path $reports 'rr3-offline-scan.json'
    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if ($report.state -ne 'completed' -or $report.clean_claimed -ne $false -or $report.report_volume_enforced -ne $true) { throw 'Invalid completion semantics.' }
    if ($report.intel.yara_status -ne 'available' -or $report.summary.ioc_hits -ne 1 -or $report.summary.yara_hits -ne 1) { throw 'Packaged engines did not match harmless marker.' }
    $after = @(Get-ChildItem -LiteralPath $fixture -File -Recurse)
    if ($after.Count -ne $before.Count) { throw 'Target file set changed.' }
    foreach ($file in $after) {
        if ($before[$file.FullName] -ne (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash) { throw 'Target content changed.' }
    }
    Copy-Item -LiteralPath $reportPath -Destination (Join-Path $evidence 'packaged-scan.json')
    Copy-Item -LiteralPath (Join-Path $reports 'rr3-audit.jsonl') -Destination $evidence
    $result.cross_volume_scan = $true
    $result.target_integrity_preserved = $true
    $sameVolume = Join-Path $fixtureParent ($instance + '-forbidden-report')
    Invoke-Candidate @('--offline-root',$fixture,'--offline-output',$sameVolume) 2
    if (Test-Path -LiteralPath $sameVolume) { throw 'Same-volume rejection wrote a report.' }
    $result.same_volume_rejection = $true
}
finally {
    $env:LOCALAPPDATA = $oldProfile
    $env:PATH = $oldPath
    $env:PYTHONPATH = $oldPythonPath
    $env:PYTHONHOME = $oldPythonHome
    $env:QT_QPA_PLATFORM = $oldQt
}
# Portable uninstall: validate generated boundaries, reject links, remove only
# enumerated files and then empty directories. Never recursively delete a tree.
foreach ($pair in @(@($install,$installParent), @($fixture,$fixtureParent))) {
    $target = [IO.Path]::GetFullPath($pair[0])
    $parent = [IO.Path]::GetFullPath($pair[1]).TrimEnd('\') + '\'
    if (-not $target.StartsWith($parent,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($target) -ne $instance) { throw 'Uninstall boundary rejected.' }
    $entries = @(Get-ChildItem -LiteralPath $target -Recurse -Force)
    foreach ($entry in $entries) {
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Uninstall refuses links.' }
        if (-not $entry.FullName.StartsWith($target + '\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Uninstall entry escaped boundary.' }
    }
    foreach ($entry in $entries | Where-Object { -not $_.PSIsContainer }) { Remove-Item -LiteralPath $entry.FullName -Force }
    foreach ($entry in $entries | Where-Object PSIsContainer | Sort-Object { $_.FullName.Length } -Descending) { [IO.Directory]::Delete($entry.FullName) }
    [IO.Directory]::Delete($target)
}
$result.uninstallation = (-not (Test-Path -LiteralPath $install)) -and (-not (Test-Path -LiteralPath $fixture))
$result.passed = $result.installation_and_startup -and $result.cross_volume_scan -and $result.target_integrity_preserved -and $result.same_volume_rejection -and $result.uninstallation
$result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $evidence 'vm-acceptance.json') -Encoding UTF8
if (-not $result.passed) { throw 'Fresh VM portable lifecycle failed.' }
$result | ConvertTo-Json -Depth 5
