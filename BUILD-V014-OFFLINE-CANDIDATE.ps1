param([Parameter(Mandatory=$true)][string]$OutputRoot, [string]$PythonPath)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$out = [IO.Path]::GetFullPath($OutputRoot)
if ($out.StartsWith($repoRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Build output must be outside the source repository.'
}
if (Test-Path -LiteralPath $out) { throw 'Build output already exists; choose a new directory.' }
$py = if ($PythonPath) { $PythonPath } else { Join-Path $repoRoot '.venv\Scripts\python.exe' }
if (-not (Test-Path -LiteralPath $py)) { $py = (Get-Command python -ErrorAction Stop).Source }
& $py -c 'import PyInstaller, PySide6, pefile, yara, psutil'
if ($LASTEXITCODE -ne 0) { throw 'Offline build dependencies are missing.' }
$commit = (& git -C $repoRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') { throw 'Source commit unavailable.' }
$untracked = @(& git -C $repoRoot ls-files --others --exclude-standard)
if ($untracked.Count -gt 0) { throw 'Untracked source files must be committed before packaging.' }
& git -C $repoRoot diff --quiet HEAD
if ($LASTEXITCODE -ne 0) { throw 'Commit all source changes before packaging.' }

New-Item -ItemType Directory -Force -Path $out | Out-Null
$payload = Join-Path $out 'payload'
$build = Join-Path $out 'build'
$spec = Join-Path $out 'spec'
$profile = Join-Path $out 'disposable-profile'
New-Item -ItemType Directory -Force -Path $payload,$build,$spec,$profile | Out-Null
$args = @(
    '--noconfirm','--onedir','--windowed','--name','BC-Sentinel-Offline-Candidate',
    '--distpath',$payload,'--workpath',$build,'--specpath',$spec,
    '--paths',$repoRoot,
    '--runtime-hook',(Join-Path $repoRoot 'packaging\beta11_windowed_runtime_hook.py'),
    '--hidden-import','sentinel.offline_scan_dialog',
    '--hidden-import','sentinel.rescue_offline_scanner',
    '--hidden-import','sentinel.static_pe_preflight',
    '--hidden-import','sentinel.smart_scan_live_provider',
    '--hidden-import','sentinel.smart_scan_runtime_compat',
    '--hidden-import','sentinel.guided_resolution_live_provider',
    '--hidden-import','sentinel.guided_resolution_real_file_execution',
    '--hidden-import','sentinel.beta13_response_ui',
    '--hidden-import','sentinel.beta13_safe_response',
    '--hidden-import','sentinel.beta13_secure_updates',
    '--hidden-import','sentinel.beta13_installer',
    (Join-Path $repoRoot 'packaging\beta13_desktop_entry.py')
)
& $py (Join-Path $repoRoot 'tools\windows_packaging.py') @args
if ($LASTEXITCODE -ne 0) { throw 'Frozen build failed.' }
$root = Join-Path $payload 'BC-Sentinel-Offline-Candidate'
$exe = Join-Path $root 'BC-Sentinel-Offline-Candidate.exe'
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'Frozen executable missing.' }
@{ profile = 'internal-offline-candidate'; source_commit = $commit; signed = $false } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'candidate-identity.json') -Encoding UTF8

$oldProfile = $env:LOCALAPPDATA
$oldPlatform = $env:QT_QPA_PLATFORM
try {
    $env:LOCALAPPDATA = $profile
    $env:QT_QPA_PLATFORM = 'offscreen'
    foreach ($option in @('--self-check','--smoke')) {
        $process = Start-Process -FilePath $exe -ArgumentList $option -WindowStyle Hidden -PassThru
        if (-not $process.WaitForExit(120000)) {
            $process.Kill()
            throw ('Frozen runtime timed out: ' + $option)
        }
        $process.Refresh()
        if ($process.ExitCode -ne 0) { throw ('Frozen runtime failed: ' + $option) }
    }
    $offlineRoot = Join-Path $profile 'offline'
    $system32 = Join-Path $offlineRoot 'Windows\System32'
    New-Item -ItemType Directory -Force -Path (Join-Path $system32 'config') | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $system32 'config\SYSTEM'), [byte[]](1,2,3))
    [IO.File]::WriteAllBytes((Join-Path $system32 'ntoskrnl.exe'), [byte[]](77,90,0,0))
    $offlineOutput = Join-Path $profile 'offline-report'
    $scan = Start-Process -FilePath $exe -ArgumentList @('--offline-root', ('"' + $offlineRoot + '"'), '--offline-output', ('"' + $offlineOutput + '"')) -WindowStyle Hidden -PassThru
    if (-not $scan.WaitForExit(120000)) { $scan.Kill(); throw 'Packaged offline CLI timed out.' }
    $scan.Refresh()
    if ($scan.ExitCode -ne 2 -or (Test-Path -LiteralPath $offlineOutput)) {
        throw 'Packaged offline CLI did not reject reports on the target volume.'
    }
}
finally {
    $env:LOCALAPPDATA = $oldProfile
    $env:QT_QPA_PLATFORM = $oldPlatform
}

$zip = Join-Path $out 'BC-Sentinel-Offline-Candidate.zip'
& $py -c 'import pathlib,sys,zipfile; root=pathlib.Path(sys.argv[1]); z=zipfile.ZipFile(sys.argv[2], "x", zipfile.ZIP_DEFLATED); [z.write(p,p.relative_to(root.parent)) for p in sorted(root.rglob("*")) if p.is_file()]; z.close()' $root $zip
if ($LASTEXITCODE -ne 0) { throw 'Portable archive creation failed.' }
$manifest = [ordered]@{
    profile = 'internal-offline-candidate'
    source_commit = $commit
    exe_sha256 = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
    zip_sha256 = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
    frozen_self_check = $true
    frozen_ui_smoke = $true
    frozen_same_volume_rejection = $true
    frozen_cross_volume_scan_verified = $false
    clean_vm_install_uninstall_verified = $false
    signed = $false
    production_release = $false
    active_protection_claimed = $false
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $out 'candidate-manifest.json') -Encoding UTF8
$manifest | ConvertTo-Json -Depth 4
