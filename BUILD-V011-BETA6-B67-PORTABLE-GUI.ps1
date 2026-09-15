param(
    [string]$DistRoot = ".\dist\Beta6"
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = "1"

function Fail([string]$Message) {
    Write-Host "BC SENTINEL B6-7 PORTABLE GUI BUILD - FAIL" -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

function Remove-BestEffort([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    try { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop }
    catch { Write-Host ("B67 BUILD CLEANUP WARNING path=" + $Path + " reason=" + $_.Exception.Message) -ForegroundColor DarkYellow }
}

try {
    $RepoRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
    $VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $VenvPython -PathType Leaf) {
        $Py = $VenvPython
    } else {
        $PythonCommand = Get-Command python -ErrorAction SilentlyContinue
        if (-not $PythonCommand) { throw "Python 3.12 runtime non disponibile." }
        $Py = $PythonCommand.Source
    }

    & $Py -c "import PyInstaller, PySide6" 2>$null
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller/PySide6 non disponibili nel Python selezionato." }

    $Entry = Join-Path $RepoRoot "packaging\beta6_portable_gui_entry.py"
    if (-not (Test-Path -LiteralPath $Entry -PathType Leaf)) { throw "B6-7 GUI entrypoint mancante." }

    $Name = "BC-Sentinel-Beta6-Portable"
    if ([IO.Path]::IsPathRooted($DistRoot)) { $FinalDist = $DistRoot } else { $FinalDist = Join-Path $RepoRoot $DistRoot }
    $FinalFolder = Join-Path $FinalDist $Name
    $Exe = Join-Path $FinalFolder ($Name + ".exe")
    $ManifestPath = Join-Path $FinalFolder "portable-gui-integrity.json"

    $ShortBase = Join-Path $env:USERPROFILE "BCSBuild\b67"
    New-Item -ItemType Directory -Path $ShortBase -Force | Out-Null
    New-Item -ItemType Directory -Path $FinalDist -Force | Out-Null

    $PyInstallerVersion = (& $Py -c "import PyInstaller; print(PyInstaller.__version__)" | Select-Object -First 1)
    $PythonVersion = (& $Py -c "import platform; print(platform.python_version())" | Select-Object -First 1)
    $BuildCommit = (& git rev-parse HEAD 2>$null | Select-Object -First 1)
    if ([string]::IsNullOrWhiteSpace($BuildCommit)) { $BuildCommit = "unknown" }

    Write-Host "Building BC Sentinel Beta6 B6-7 Portable Technician GUI (PyInstaller onedir/windowed)..." -ForegroundColor Cyan
    Write-Host ("B67 BUILD REPO=" + $RepoRoot) -ForegroundColor DarkCyan
    Write-Host ("B67 BUILD PYTHON=" + $PythonVersion) -ForegroundColor DarkCyan
    Write-Host ("B67 BUILD PYINSTALLER=" + $PyInstallerVersion) -ForegroundColor DarkCyan
    Write-Host ("B67 BUILD COMMIT=" + $BuildCommit) -ForegroundColor DarkCyan
    Write-Host ("B67 BUILD SHORT_BASE=" + $ShortBase) -ForegroundColor DarkCyan
    Write-Host "B67 BUILD MODE=onedir windowed=true installer=false service=false driver=false" -ForegroundColor DarkCyan

    $Built = $false
    $LastFailure = ""
    $MaxAttempts = 3
    for ($Attempt = 1; $Attempt -le $MaxAttempts; $Attempt++) {
        $AttemptId = "a" + $Attempt + "-" + [guid]::NewGuid().ToString("N").Substring(0, 8)
        $AttemptRoot = Join-Path $ShortBase $AttemptId
        $WorkPath = Join-Path $AttemptRoot "w"
        $SpecPath = Join-Path $AttemptRoot "s"
        $TempPath = Join-Path $AttemptRoot "t"
        $LogPath = Join-Path $AttemptRoot "pyinstaller.log"
        New-Item -ItemType Directory -Path $WorkPath, $SpecPath, $TempPath -Force | Out-Null
        Remove-BestEffort $FinalFolder

        $OldTemp = $env:TEMP
        $OldTmp = $env:TMP
        $env:TEMP = $TempPath
        $env:TMP = $TempPath
        $ExitCode = -999
        $OldEap = $ErrorActionPreference
        Write-Host ("B67 BUILD ATTEMPT=" + $Attempt + "/" + $MaxAttempts) -ForegroundColor Cyan
        try {
            $ErrorActionPreference = "Continue"
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
                --hidden-import sentinel.smart_scan_live_provider `
                --hidden-import sentinel.smart_scan_runtime_compat `
                --hidden-import sentinel.guided_resolution_live_provider `
                --hidden-import sentinel.guided_resolution_real_file_execution `
                $Entry 2>&1 | Tee-Object -FilePath $LogPath
            $ExitCode = $LASTEXITCODE
        }
        catch {
            $LastFailure = "attempt=$Attempt wrapper_exception=$($_.Exception.GetType().FullName) message=$($_.Exception.Message) log=$LogPath"
            Write-Host ("B67 BUILD WRAPPER EXCEPTION " + $LastFailure) -ForegroundColor Yellow
        }
        finally {
            $ErrorActionPreference = $OldEap
            $env:TEMP = $OldTemp
            $env:TMP = $OldTmp
        }

        if ($ExitCode -eq 0 -and (Test-Path -LiteralPath $Exe -PathType Leaf)) {
            Write-Host ("B67 BUILD ATTEMPT=" + $Attempt + " RESULT=PASS exit_code=0") -ForegroundColor Green
            $Built = $true
            break
        }

        $Tail = @()
        if (Test-Path -LiteralPath $LogPath) { $Tail = @(Get-Content -LiteralPath $LogPath -Tail 60 -ErrorAction SilentlyContinue) }
        $TailText = $Tail -join [Environment]::NewLine
        $FailureClass = "pyinstaller_nonzero_exit"
        if ($TailText -match "EndUpdateResourceW" -and $TailText -match "WinError 122|\(122,") { $FailureClass = "windows_resource_update_winerror_122" }
        elseif ($TailText -match "BeginUpdateResourceW|EndUpdateResourceW") { $FailureClass = "windows_resource_update_failure" }
        elseif ($TailText -match "Permission denied|Access is denied|WinError 5") { $FailureClass = "build_file_lock_or_access_denied" }
        elseif ($LastFailure -match "wrapper_exception=") { $FailureClass = "powershell_wrapper_exception" }
        $LastFailure = "attempt=$Attempt exit_code=$ExitCode class=$FailureClass log=$LogPath"
        Write-Host ("B67 BUILD ATTEMPT=" + $Attempt + " RESULT=FAIL " + $LastFailure) -ForegroundColor Yellow
        if ($Tail.Count -gt 0) {
            Write-Host "B67 BUILD FAILURE TAIL BEGIN" -ForegroundColor DarkYellow
            $Tail | ForEach-Object { Write-Host $_ -ForegroundColor DarkGray }
            Write-Host "B67 BUILD FAILURE TAIL END" -ForegroundColor DarkYellow
        }
        Remove-BestEffort $FinalFolder
        if ($Attempt -lt $MaxAttempts) { Start-Sleep -Milliseconds (750 * $Attempt) }
    }

    if (-not $Built) { throw ("PyInstaller B6-7 GUI build failed after $MaxAttempts attempts. LastFailure=$LastFailure") }
    if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) { throw "B6-7 GUI executable missing after build." }

    $ExeHash = (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLowerInvariant()
    $FileCount = @(Get-ChildItem -LiteralPath $FinalFolder -File -Recurse).Count
    $TotalBytes = (Get-ChildItem -LiteralPath $FinalFolder -File -Recurse | Measure-Object -Property Length -Sum).Sum
    if ($null -eq $TotalBytes) { $TotalBytes = 0 }

    $Manifest = [ordered]@{
        schema = "bc-sentinel-beta6-portable-gui-manifest-v1"
        profile = "v0.11.0-beta.6-b67-portable-gui"
        artifact = $Name + ".exe"
        sha256 = $ExeHash
        build_mode = "onedir"
        windowed = $true
        portable = $true
        build_commit = [string]$BuildCommit
        source_checkpoint = "checkpoint/v011-beta6-b659-pass"
        source_checkpoint_commit = "72c18bbdf1c50c633343750ead0f2467d8705e12"
        python_version = [string]$PythonVersion
        pyinstaller_version = [string]$PyInstallerVersion
        file_count = [int]$FileCount
        total_bytes = [long]$TotalBytes
        installer_required = $false
        service_install = $false
        driver_install = $false
        network_required = $false
        cloud_required = $false
        startup_command_dispatch = $false
        explicit_operator_action_required = $true
        general_home_execution_authorized = $false
        home_quarantine_action_available = $true
        persistent_restore_after_restart = $true
        automatic_cleanup = $false
        automatic_quarantine = $false
        automatic_restore = $false
        automatic_repair = $false
        delete_authorized = $false
        repair_authorized = $false
        terminate_process_authorized = $false
        trust_allowlist_mutation_authorized = $false
        privileged_system_file_mutation_authorized = $false
        max_build_attempts = $MaxAttempts
        build_isolation = "short-per-attempt-work-temp"
    }
    $Json = $Manifest | ConvertTo-Json -Depth 6
    [IO.File]::WriteAllText($ManifestPath, $Json + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))

    Write-Host ("B67 PORTABLE GUI SHA256=" + $ExeHash) -ForegroundColor Green
    Write-Host ("B67 PORTABLE GUI FILES=" + $FileCount + " BYTES=" + $TotalBytes) -ForegroundColor Green
    Write-Host ("B67 Portable GUI folder: " + $FinalFolder) -ForegroundColor Green
    Write-Host "BC SENTINEL B6-7 PORTABLE GUI BUILD - PASS" -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
