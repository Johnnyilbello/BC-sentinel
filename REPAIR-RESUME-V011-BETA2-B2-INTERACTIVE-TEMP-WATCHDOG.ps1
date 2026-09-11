param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.2 B2 NATIVE-INGESTION REPAIR - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

function Download-RequiredFile(
    [string]$Destination,
    [string]$PrimaryUri,
    [string]$FallbackUri
) {
    $parent = Split-Path -Parent $Destination
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    Write-Host ('Downloading: ' + $PrimaryUri) -ForegroundColor DarkGray
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $PrimaryUri -OutFile $Destination -ErrorAction Stop
        return
    }
    catch {
        Write-Host ('Pinned RAW download failed: ' + $_.Exception.Message) -ForegroundColor Yellow
        Write-Host ('Retrying branch fallback: ' + $FallbackUri) -ForegroundColor DarkGray
        Invoke-WebRequest -UseBasicParsing -Uri $FallbackUri -OutFile $Destination -ErrorAction Stop
    }
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this repair from normal PowerShell. The existing B2 resume will request UAC when needed.'
    }

    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }
    if (-not (Test-Path -LiteralPath '.\sentinel\realtime.py')) { throw 'sentinel\realtime.py missing from FULL tree' }
    if (-not (Test-Path -LiteralPath '.\BUILD-SERVIZIO-PROTEZIONE.ps1')) { throw 'BUILD-SERVIZIO-PROTEZIONE.ps1 missing' }
    if (-not (Test-Path -LiteralPath '.\AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1')) { throw 'AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1 missing' }

    $Py = '.\.venv\Scripts\python.exe'
    $PatchRef = 'dcb8c7c19901236031d0711e46dabe00e6139458'
    $PatchBranch = 'fix/v011-beta2-b2-interactive-temp-watchdog'
    $ResumeRef = '1cfc20346c77148b5497b2a4dd2794ce06cc273e'
    $ResumeBranch = 'checkpoint/v011-beta2-b2-current-1cfc203'
    $RepoRaw = 'https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/'

    Write-Host 'BC Sentinel v0.11.0-beta.2 - B2 NATIVE INGESTION REPAIR' -ForegroundColor Cyan
    Write-Host 'Fixes interactive TEMP watchdog classification and retention-safe EDR timestamps. No timeout or 25/10/250 threshold relaxation.' -ForegroundColor Yellow

    Download-RequiredFile `
        '.\tools\v011_beta2_b2_temp_root_compat.py' `
        ($RepoRaw + $PatchRef + '/tools/v011_beta2_b2_temp_root_compat.py') `
        ($RepoRaw + $PatchBranch + '/tools/v011_beta2_b2_temp_root_compat.py')

    Download-RequiredFile `
        '.\tests\test_v011_beta2_b2_temp_root_compat.py' `
        ($RepoRaw + $PatchRef + '/tests/test_v011_beta2_b2_temp_root_compat.py') `
        ($RepoRaw + $PatchBranch + '/tests/test_v011_beta2_b2_temp_root_compat.py')

    Download-RequiredFile `
        '.\sentinel\edr_adapter.py' `
        ($RepoRaw + $PatchRef + '/sentinel/edr_adapter.py') `
        ($RepoRaw + $PatchBranch + '/sentinel/edr_adapter.py')

    Download-RequiredFile `
        '.\tests\test_v011_beta1_edr_adapter.py' `
        ($RepoRaw + $PatchRef + '/tests/test_v011_beta1_edr_adapter.py') `
        ($RepoRaw + $PatchBranch + '/tests/test_v011_beta1_edr_adapter.py')

    $realtimePath = Join-Path $PSScriptRoot 'sentinel\realtime.py'
    $beforeHash = (Get-FileHash -LiteralPath $realtimePath -Algorithm SHA256).Hash.ToLowerInvariant()

    Write-Host 'Applying account-independent TEMP/AppData watchdog root classification...' -ForegroundColor DarkCyan
    & $Py -m tools.v011_beta2_b2_temp_root_compat
    if ($LASTEXITCODE -ne 0) { throw 'Interactive TEMP watchdog compatibility migration failed' }

    $afterHash = (Get-FileHash -LiteralPath $realtimePath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host (('Realtime source: {0} -> {1}' -f $beforeHash,$afterHash)) -ForegroundColor Green

    Write-Host 'Running focused regression tests with isolated neutral basetemp...' -ForegroundColor DarkCyan
    $FocusedPytestBase = Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    if (-not (Test-Path -LiteralPath $FocusedPytestBase)) { New-Item -ItemType Directory -Path $FocusedPytestBase -Force | Out-Null }
    $FocusedPytestTemp = Join-Path $FocusedPytestBase ('b2-focused-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $FocusedPytestTemp -Force | Out-Null
    try {
        & $Py -m pytest -q --basetemp $FocusedPytestTemp `
            tests/test_v011_beta2_b2_temp_root_compat.py `
            tests/test_v011_beta1_edr_adapter.py `
            tests/test_v011_beta1_low_cpu_runtime_compat.py `
            tests/test_v011_beta1_watchdog_coalescing.py `
            tests/test_v011_beta1_service_performance.py
        if ($LASTEXITCODE -ne 0) { throw 'Focused EDR/watchdog/low-CPU/service-performance regression failed' }
    }
    finally {
        Remove-Item -LiteralPath $FocusedPytestTemp -Recurse -Force -ErrorAction SilentlyContinue
    }

    & $Py -m compileall -q sentinel tools tests
    if ($LASTEXITCODE -ne 0) { throw 'compileall failed after native-ingestion repair' }

    Write-Host 'Building a fresh Protection Service with corrected native EDR ingestion...' -ForegroundColor Cyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\BUILD-SERVIZIO-PROTEZIONE.ps1'
    if ($LASTEXITCODE -ne 0) { throw 'Fresh Protection Service build failed after native-ingestion repair' }

    $distService = Join-Path $PSScriptRoot 'dist\BC-Sentinel-Protection\BC-Sentinel-Protection.exe'
    if (-not (Test-Path -LiteralPath $distService)) { throw 'Corrected Protection Service executable missing after build' }
    $distHash = (Get-FileHash -LiteralPath $distService -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host ('CORRECTED NATIVE-INGESTION BUILD: SHA256=' + $distHash) -ForegroundColor Green

    Write-Host 'Deploying the freshly rebuilt Protection Service through UAC Repair...' -ForegroundColor Yellow
    $maintenance = Join-Path $PSScriptRoot 'AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1'
    $repairArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $maintenance + '"'),'-Mode','Repair')
    try {
        $repairProc = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList $repairArgs
    }
    catch {
        throw ('Repair deployment UAC cancelled or failed: ' + $_.Exception.Message)
    }
    if ($null -eq $repairProc -or $repairProc.ExitCode -ne 0) {
        throw 'Repair deployment of freshly rebuilt Protection Service failed'
    }

    $installedService = Join-Path $env:ProgramFiles 'BC Sentinel\Protection\BC-Sentinel-Protection.exe'
    if (-not (Test-Path -LiteralPath $installedService)) { throw 'Installed Protection Service missing after Repair' }
    $installedHash = (Get-FileHash -LiteralPath $installedService -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($installedHash -ne $distHash) { throw 'Installed Protection Service does not match freshly rebuilt dist after Repair' }
    Write-Host ('DEPLOYED NATIVE-INGESTION BUILD: SHA256=' + $installedHash) -ForegroundColor Green

    $resume = Join-Path $PSScriptRoot 'RESUME-V011-BETA2-B2-AFTER-IDLE-STABILIZATION.ps1'
    Download-RequiredFile `
        $resume `
        ($RepoRaw + $ResumeRef + '/RESUME-V011-BETA2-B2-AFTER-IDLE-STABILIZATION.ps1') `
        ($RepoRaw + $ResumeBranch + '/RESUME-V011-BETA2-B2-AFTER-IDLE-STABILIZATION.ps1')

    Write-Host 'Launching the existing stabilized B2 resume against the freshly corrected and deployed build...' -ForegroundColor Yellow
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $resume
    if ($LASTEXITCODE -ne 0) { throw 'Stabilized B2 resume still failed after native-ingestion repair' }

    Write-Host 'BC SENTINEL v0.11.0-beta.2 B2 NATIVE-INGESTION REPAIR - PASS' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
