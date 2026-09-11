param()
$ErrorActionPreference='Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message){
    Write-Host 'BC SENTINEL B5-7 TECHNICIAN RELEASE BUILD - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}
function Remove-BestEffort([string]$Path){
    if(-not(Test-Path -LiteralPath $Path)){return}
    try{Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop}
    catch{Write-Host ('B57 BUILD CLEANUP WARNING path='+$Path+' reason='+$_.Exception.Message) -ForegroundColor DarkYellow}
}

try{
    if(-not(Test-Path -LiteralPath '.\.venv\Scripts\python.exe')){throw '.venv not available'}
    $Py=(Resolve-Path -LiteralPath '.\.venv\Scripts\python.exe').Path
    $RepoRoot=(Resolve-Path -LiteralPath $PSScriptRoot).Path
    $Entry=Join-Path $RepoRoot 'packaging\rescue_technician_portable_entry.py'
    if(-not(Test-Path -LiteralPath $Entry)){throw 'B5-7 technician portable entrypoint missing'}

    $FinalDist=Join-Path $RepoRoot 'dist\Rescue'
    $Name='BC-Sentinel-Technician-Portable'
    $FinalFolder=Join-Path $FinalDist $Name
    $ShortBase=Join-Path $env:USERPROFILE 'BCSBuild\b57'
    New-Item -ItemType Directory -Path $ShortBase -Force|Out-Null

    $PyInstallerVersion=(& $Py -c "import PyInstaller; print(PyInstaller.__version__)" 2>$null|Select-Object -First 1)
    Write-Host 'Building BC Sentinel Beta5 Portable Technician Release (onedir)...' -ForegroundColor Cyan
    Write-Host ('B57 BUILD PYINSTALLER='+$PyInstallerVersion) -ForegroundColor DarkCyan
    Write-Host ('B57 BUILD REPO='+$RepoRoot) -ForegroundColor DarkCyan
    Write-Host ('B57 BUILD SHORT_BASE='+$ShortBase) -ForegroundColor DarkCyan
    Write-Host ('B57 BUILD REPO_PATH_LENGTH='+$RepoRoot.Length) -ForegroundColor DarkCyan
    Write-Host 'B57 BUILD NATIVE_STDERR_POLICY=capture-without-terminating' -ForegroundColor DarkCyan

    $Built=$false;$LastFailure='';$MaxAttempts=3
    for($Attempt=1;$Attempt -le $MaxAttempts;$Attempt++){
        $AttemptId=('a'+$Attempt+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
        $AttemptRoot=Join-Path $ShortBase $AttemptId
        $WorkPath=Join-Path $AttemptRoot 'w';$SpecPath=Join-Path $AttemptRoot 's';$TempPath=Join-Path $AttemptRoot 't';$LogPath=Join-Path $AttemptRoot 'pyinstaller.log'
        New-Item -ItemType Directory -Path $WorkPath,$SpecPath,$TempPath -Force|Out-Null
        Remove-BestEffort $FinalFolder
        $OldTemp=$env:TEMP;$OldTmp=$env:TMP;$env:TEMP=$TempPath;$env:TMP=$TempPath
        Write-Host ('B57 BUILD ATTEMPT='+$Attempt+'/'+$MaxAttempts) -ForegroundColor Cyan
        Write-Host ('B57 BUILD WORKPATH='+$WorkPath+' length='+$WorkPath.Length) -ForegroundColor DarkCyan
        Write-Host ('B57 BUILD TEMPPATH='+$TempPath+' length='+$TempPath.Length) -ForegroundColor DarkCyan
        Write-Host ('B57 BUILD LOG='+$LogPath) -ForegroundColor DarkCyan
        $ExitCode=-999;$OldEap=$ErrorActionPreference
        try{
            $ErrorActionPreference='Continue'
            & $Py -m PyInstaller --noconfirm --clean --onedir --name $Name --distpath $FinalDist --workpath $WorkPath --specpath $SpecPath --paths $RepoRoot $Entry 2>&1|Tee-Object -FilePath $LogPath
            $ExitCode=$LASTEXITCODE
        }catch{
            $LastFailure=('attempt='+$Attempt+' wrapper_exception='+$_.Exception.GetType().FullName+' message='+$_.Exception.Message+' log='+$LogPath)
            Write-Host ('B57 BUILD WRAPPER EXCEPTION '+$LastFailure) -ForegroundColor Yellow
        }finally{$ErrorActionPreference=$OldEap;$env:TEMP=$OldTemp;$env:TMP=$OldTmp}
        $ExeCandidate=Join-Path $FinalFolder ($Name+'.exe')
        if($ExitCode -eq 0 -and(Test-Path -LiteralPath $ExeCandidate)){
            Write-Host ('B57 BUILD ATTEMPT='+$Attempt+' RESULT=PASS exit_code='+$ExitCode) -ForegroundColor Green;$Built=$true;break
        }
        $Tail=@();if(Test-Path -LiteralPath $LogPath){$Tail=@(Get-Content -LiteralPath $LogPath -Tail 45 -ErrorAction SilentlyContinue)}
        $TailText=($Tail -join [Environment]::NewLine);$FailureClass='pyinstaller_nonzero_exit'
        if($TailText -match 'EndUpdateResourceW' -and $TailText -match 'WinError 122|\(122,'){$FailureClass='windows_resource_update_winerror_122'}
        elseif($TailText -match 'BeginUpdateResourceW|EndUpdateResourceW'){$FailureClass='windows_resource_update_failure'}
        elseif($TailText -match 'Permission denied|Access is denied|WinError 5'){$FailureClass='build_file_lock_or_access_denied'}
        elseif($LastFailure -match 'wrapper_exception='){$FailureClass='powershell_wrapper_exception'}
        $LastFailure=('attempt='+$Attempt+' exit_code='+$ExitCode+' class='+$FailureClass+' log='+$LogPath)
        Write-Host ('B57 BUILD ATTEMPT='+$Attempt+' RESULT=FAIL '+$LastFailure) -ForegroundColor Yellow
        if($Tail.Count -gt 0){Write-Host 'B57 BUILD FAILURE TAIL BEGIN' -ForegroundColor DarkYellow;$Tail|ForEach-Object{Write-Host $_ -ForegroundColor DarkGray};Write-Host 'B57 BUILD FAILURE TAIL END' -ForegroundColor DarkYellow}
        Remove-BestEffort $FinalFolder
        if($Attempt -lt $MaxAttempts){$DelayMs=750*$Attempt;Write-Host ('B57 BUILD RETRY delay_ms='+$DelayMs+' next_attempt='+($Attempt+1)) -ForegroundColor DarkYellow;Start-Sleep -Milliseconds $DelayMs}
    }
    if(-not$Built){throw ('PyInstaller B5-7 technician release build failed after '+$MaxAttempts+' isolated attempts. LastFailure='+$LastFailure)}

    $Exe=Join-Path $FinalFolder ($Name+'.exe')
    if(-not(Test-Path -LiteralPath $Exe)){throw 'B5-7 technician executable missing after build'}
    $Hash=(Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLowerInvariant()
    $Manifest=[ordered]@{
        profile='v0.11.0-beta.5-b57';artifact=($Name+'.exe');sha256=$Hash;build_mode='onedir'
        commands=@('plan','scan','repair-handoff','data-rescue','certify','discover','assess','stress','resume','decide','report','status')
        installer_required=$false;service_install=$false;driver_install=$false;network_required=$false;cloud_required=$false
        automatic_repair=$false;automatic_quarantine=$false;automatic_destructive_action=$false
        repair_execution_exposed_by_launcher=$false;repair_handoff_only=$true;unlock_exposed=$false;format_exposed=$false;reimage_execution_exposed=$false
        format_or_reimage_suppressed=$false;build_isolation='short-per-attempt-work-temp';native_stderr_policy='captured_without_terminating_windows_powershell_5_1';max_build_attempts=$MaxAttempts
    }
    $Json=$Manifest|ConvertTo-Json -Depth 6
    [IO.File]::WriteAllText((Join-Path $FinalFolder 'technician-release-integrity.json'),$Json+[Environment]::NewLine,(New-Object Text.UTF8Encoding($false)))
    Write-Host ('B57 TECHNICIAN RELEASE SHA256='+$Hash) -ForegroundColor Green
    Write-Host ('B57 Technician Release folder: '+$FinalFolder) -ForegroundColor Green
    Write-Host 'BC SENTINEL B5-7 TECHNICIAN RELEASE BUILD - PASS' -ForegroundColor Green
    exit 0
}catch{Fail $_.Exception.Message}
