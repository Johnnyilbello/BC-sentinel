param(
    [string]$DistRoot = ".\dist\Beta11-B112"
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Set-Location -LiteralPath $PSScriptRoot
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = '1'
$env:QT_QPA_PLATFORM = 'offscreen'
$env:BC_SENTINEL_REDUCED_MOTION = '1'

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL B11-2 REPRODUCIBLE WINDOWS ONEDIR BUILD - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

function Remove-BestEffort([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    try { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop }
    catch { Write-Host ('B11-2 cleanup warning path=' + $Path + ' reason=' + $_.Exception.Message) -ForegroundColor DarkYellow }
}

function Resolve-ExactBuildCommit([string]$RepoRoot) {
    $gitLines = @()
    $gitExit = -1
    try {
        $oldEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $gitLines = @(& git -C $RepoRoot rev-parse --verify HEAD 2>&1)
        $gitExit = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $oldEap
    }

    $candidate = @(
        $gitLines |
        ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } |
        Where-Object { $_ -match '^[0-9a-f]{40}$' }
    ) | Select-Object -Last 1
    if ($gitExit -eq 0 -and -not [string]::IsNullOrWhiteSpace([string]$candidate)) {
        return [string]$candidate
    }

    # Fail-safe fallback for local Windows shells where nested native git output
    # can be wrapped/redirected unexpectedly. The parent acceptance gate already
    # verifies repository cleanliness and exact HEAD; this fallback only resolves
    # the same immutable commit directly from .git metadata.
    $dotGit = Join-Path $RepoRoot '.git'
    if (-not (Test-Path -LiteralPath $dotGit)) {
        throw ('Cannot resolve exact build commit. git_exit=' + $gitExit + '; .git missing.')
    }

    $gitDir = $dotGit
    if (Test-Path -LiteralPath $dotGit -PathType Leaf) {
        $pointer = (Get-Content -LiteralPath $dotGit -Raw -Encoding UTF8).Trim()
        if ($pointer -notmatch '^gitdir:\s*(.+)$') { throw 'Cannot resolve .git indirection.' }
        $gitDirCandidate = $Matches[1].Trim()
        if ([IO.Path]::IsPathRooted($gitDirCandidate)) { $gitDir = $gitDirCandidate }
        else { $gitDir = (Join-Path $RepoRoot $gitDirCandidate) }
    }

    $headPath = Join-Path $gitDir 'HEAD'
    if (-not (Test-Path -LiteralPath $headPath -PathType Leaf)) { throw 'Cannot resolve exact build commit: HEAD missing.' }
    $head = (Get-Content -LiteralPath $headPath -Raw -Encoding UTF8).Trim()
    if ($head -match '^[0-9a-fA-F]{40}$') { return $head.ToLowerInvariant() }
    if ($head -notmatch '^ref:\s*(.+)$') { throw 'Cannot resolve exact build commit: HEAD invalid.' }

    $refName = $Matches[1].Trim().Replace('/', [IO.Path]::DirectorySeparatorChar)
    $refPath = Join-Path $gitDir $refName
    if (Test-Path -LiteralPath $refPath -PathType Leaf) {
        $refValue = (Get-Content -LiteralPath $refPath -Raw -Encoding UTF8).Trim().ToLowerInvariant()
        if ($refValue -match '^[0-9a-f]{40}$') { return $refValue }
    }

    $packedRefs = Join-Path $gitDir 'packed-refs'
    if (Test-Path -LiteralPath $packedRefs -PathType Leaf) {
        $refUnix = $Matches[1]
        foreach ($line in Get-Content -LiteralPath $packedRefs -Encoding UTF8) {
            if ($line -match '^([0-9a-fA-F]{40})\s+(.+)$' -and $Matches[2] -eq $refUnix) {
                return $Matches[1].ToLowerInvariant()
            }
        }
    }
    throw ('Cannot resolve exact build commit. git_exit=' + $gitExit + '; no valid HEAD ref found.')
}

try {
    $RepoRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
    $VenvPython = Join-Path $RepoRoot '.venv\Scripts\python.exe'
    if (Test-Path -LiteralPath $VenvPython -PathType Leaf) {
        $Py = $VenvPython
    } else {
        $PythonCommand = Get-Command python -ErrorAction SilentlyContinue
        if (-not $PythonCommand) { throw 'Python 3.12 runtime unavailable.' }
        $Py = $PythonCommand.Source
    }

    & $Py -c 'import PyInstaller, PySide6' 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller/PySide6 unavailable in selected Python runtime.' }

    $Entry = Join-Path $RepoRoot 'packaging\beta11_desktop_entry.py'
    $RuntimeHook = Join-Path $RepoRoot 'packaging\beta11_windowed_runtime_hook.py'
    if (-not (Test-Path -LiteralPath $Entry -PathType Leaf)) { throw 'B11-1 canonical desktop entrypoint missing.' }
    if (-not (Test-Path -LiteralPath $RuntimeHook -PathType Leaf)) { throw 'B11-2 windowed runtime hook missing.' }

    $Name = 'BC-Sentinel-Beta11'
    if ([IO.Path]::IsPathRooted($DistRoot)) { $FinalDist = $DistRoot } else { $FinalDist = Join-Path $RepoRoot $DistRoot }
    $FinalFolder = Join-Path $FinalDist $Name
    $Exe = Join-Path $FinalFolder ($Name + '.exe')
    $Manifest = Join-Path $FinalFolder 'artifact-integrity.json'

    $BuildCommit = Resolve-ExactBuildCommit $RepoRoot
    if ($BuildCommit -notmatch '^[0-9a-f]{40}$') { throw 'Cannot resolve exact build commit.' }
    $PythonVersion = (& $Py -c 'import platform; print(platform.python_version())' | Select-Object -First 1).Trim()
    $PyInstallerVersion = (& $Py -c 'import PyInstaller; print(PyInstaller.__version__)' | Select-Object -First 1).Trim()

    New-Item -ItemType Directory -Path $FinalDist -Force | Out-Null
    $ShortBase = Join-Path $env:USERPROFILE 'BCSBuild\b112'
    New-Item -ItemType Directory -Path $ShortBase -Force | Out-Null

    Write-Host ('B11-2 BUILD COMMIT=' + $BuildCommit) -ForegroundColor Cyan
    Write-Host ('B11-2 PYTHON=' + $PythonVersion + ' PYINSTALLER=' + $PyInstallerVersion) -ForegroundColor DarkCyan
    Write-Host 'B11-2 MODE=onedir windowed=true installer=false signed=false' -ForegroundColor DarkCyan

    $Built = $false
    $LastFailure = ''
    $MaxAttempts = 3
    for ($Attempt = 1; $Attempt -le $MaxAttempts; $Attempt++) {
        $AttemptRoot = Join-Path $ShortBase ('a' + $Attempt + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $WorkPath = Join-Path $AttemptRoot 'w'
        $SpecPath = Join-Path $AttemptRoot 's'
        $TempPath = Join-Path $AttemptRoot 't'
        $LogPath = Join-Path $AttemptRoot 'pyinstaller.log'
        New-Item -ItemType Directory -Path $WorkPath, $SpecPath, $TempPath -Force | Out-Null
        Remove-BestEffort $FinalFolder

        $OldTemp = $env:TEMP
        $OldTmp = $env:TMP
        $env:TEMP = $TempPath
        $env:TMP = $TempPath
        $ExitCode = -999
        $OldEap = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            & $Py -m PyInstaller `
                --noconfirm `
                --clean `
                --onedir `
                --windowed `
                --name $Name `
                --distpath $FinalDist `
                --workpath $WorkPath `
                --specpath $SpecPath `
                --paths $RepoRoot `
                --runtime-hook $RuntimeHook `
                --hidden-import sentinel.smart_scan_live_provider `
                --hidden-import sentinel.smart_scan_runtime_compat `
                --hidden-import sentinel.guided_resolution_live_provider `
                --hidden-import sentinel.guided_resolution_real_file_execution `
                $Entry 2>&1 | Tee-Object -FilePath $LogPath
            $ExitCode = $LASTEXITCODE
        }
        catch {
            $LastFailure = 'attempt=' + $Attempt + ' wrapper_exception=' + $_.Exception.Message + ' log=' + $LogPath
        }
        finally {
            $ErrorActionPreference = $OldEap
            $env:TEMP = $OldTemp
            $env:TMP = $OldTmp
        }

        if ($ExitCode -eq 0 -and (Test-Path -LiteralPath $Exe -PathType Leaf)) {
            Write-Host ('B11-2 BUILD ATTEMPT=' + $Attempt + ' RESULT=PASS') -ForegroundColor Green
            $Built = $true
            break
        }

        $Tail = @()
        if (Test-Path -LiteralPath $LogPath) { $Tail = @(Get-Content -LiteralPath $LogPath -Tail 60 -ErrorAction SilentlyContinue) }
        $TailText = $Tail -join [Environment]::NewLine
        $FailureClass = 'pyinstaller_nonzero_exit'
        if ($TailText -match 'EndUpdateResourceW' -and $TailText -match 'WinError 122|\(122,') { $FailureClass = 'windows_resource_update_winerror_122' }
        elseif ($TailText -match 'BeginUpdateResourceW|EndUpdateResourceW') { $FailureClass = 'windows_resource_update_failure' }
        elseif ($TailText -match 'Permission denied|Access is denied|WinError 5') { $FailureClass = 'build_file_lock_or_access_denied' }
        $LastFailure = 'attempt=' + $Attempt + ' exit_code=' + $ExitCode + ' class=' + $FailureClass + ' log=' + $LogPath
        Write-Host ('B11-2 BUILD ATTEMPT=' + $Attempt + ' RESULT=FAIL ' + $LastFailure) -ForegroundColor Yellow
        if ($Tail.Count -gt 0) { $Tail | ForEach-Object { Write-Host $_ -ForegroundColor DarkGray } }
        Remove-BestEffort $FinalFolder
        if ($Attempt -lt $MaxAttempts) { Start-Sleep -Milliseconds (750 * $Attempt) }
    }

    if (-not $Built) { throw ('PyInstaller B11-2 build failed after ' + $MaxAttempts + ' attempts. ' + $LastFailure) }
    if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) { throw 'B11-2 executable missing after build.' }

    & $Py -m sentinel.beta11_artifact_manifest `
        --write `
        --root $FinalFolder `
        --build-commit $BuildCommit `
        --python-version $PythonVersion `
        --pyinstaller-version $PyInstallerVersion
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Manifest -PathType Leaf)) { throw 'B11-2 artifact manifest generation failed.' }

    & $Py -m sentinel.beta11_artifact_manifest --validate --root $FinalFolder --build-commit $BuildCommit
    if ($LASTEXITCODE -ne 0) { throw 'B11-2 artifact manifest verification failed.' }

    $ManifestObject = Get-Content -LiteralPath $Manifest -Raw -Encoding UTF8 | ConvertFrom-Json
    Write-Host ('B11-2 ARTIFACT SHA256=' + $ManifestObject.artifact_sha256) -ForegroundColor Green
    Write-Host ('B11-2 TREE DIGEST=' + $ManifestObject.tree_digest) -ForegroundColor Green
    Write-Host ('B11-2 FILES=' + $ManifestObject.file_count + ' BYTES=' + $ManifestObject.total_bytes) -ForegroundColor Green
    Write-Host ('B11-2 OUTPUT=' + $FinalFolder) -ForegroundColor Green
    Write-Host 'BC SENTINEL B11-2 REPRODUCIBLE WINDOWS ONEDIR BUILD - PASS' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
