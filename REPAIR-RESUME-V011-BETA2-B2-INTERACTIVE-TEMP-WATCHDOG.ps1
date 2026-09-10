param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.2 B2 INTERACTIVE-TEMP WATCHDOG REPAIR - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
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
    $PatchRef = 'fef9ef62934130f1558079be44a305a83065f1a6'
    $ResumeRef = '1cfc20346c77148b5497b2a4dd2794ce06cc273e'
    $RepoRaw = 'https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/'

    Write-Host 'BC Sentinel v0.11.0-beta.2 - B2 INTERACTIVE TEMP WATCHDOG REPAIR' -ForegroundColor Cyan
    Write-Host 'Fixes service-account vs interactive-user TEMP classification. No timeout or 25/10/250 threshold relaxation.' -ForegroundColor Yellow

    $downloads = @(
        @('.\tools\v011_beta2_b2_temp_root_compat.py', $RepoRaw + $PatchRef + '/tools/v011_beta2_b2_temp_root_compat.py'),
        @('.\tests\test_v011_beta2_b2_temp_root_compat.py', $RepoRaw + $PatchRef + '/tests/test_v011_beta2_b2_temp_root_compat.py')
    )
    foreach ($item in $downloads) {
        $parent = Split-Path -Parent $item[0]
        if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        Invoke-WebRequest -Uri $item[1] -OutFile $item[0]
    }

    $realtimePath = Join-Path $PSScriptRoot 'sentinel\realtime.py'
    $beforeHash = (Get-FileHash -LiteralPath $realtimePath -Algorithm SHA256).Hash.ToLowerInvariant()

    Write-Host 'Applying account-independent TEMP/AppData watchdog root classification...' -ForegroundColor DarkCyan
    & $Py -m tools.v011_beta2_b2_temp_root_compat
    if ($LASTEXITCODE -ne 0) { throw 'Interactive TEMP watchdog compatibility migration failed' }

    $afterHash = (Get-FileHash -LiteralPath $realtimePath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host (('Realtime source: {0} -> {1}' -f $beforeHash,$afterHash)) -ForegroundColor Green

    Write-Host 'Running focused regression tests...' -ForegroundColor DarkCyan
    & $Py -m pytest -q `
        tests/test_v011_beta2_b2_temp_root_compat.py `
        tests/test_v011_beta1_low_cpu_runtime_compat.py `
        tests/test_v011_beta1_watchdog_coalescing.py `
        tests/test_v011_beta1_service_performance.py
    if ($LASTEXITCODE -ne 0) { throw 'Focused watchdog/low-CPU/service-performance regression failed' }

    & $Py -m compileall -q sentinel tools tests
    if ($LASTEXITCODE -ne 0) { throw 'compileall failed after interactive TEMP watchdog repair' }

    Write-Host 'Building a fresh Protection Service with the corrected realtime watcher...' -ForegroundColor Cyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\BUILD-SERVIZIO-PROTEZIONE.ps1'
    if ($LASTEXITCODE -ne 0) { throw 'Fresh Protection Service build failed after TEMP watchdog repair' }

    $distService = Join-Path $PSScriptRoot 'dist\BC-Sentinel-Protection\BC-Sentinel-Protection.exe'
    if (-not (Test-Path -LiteralPath $distService)) { throw 'Corrected Protection Service executable missing after build' }
    $distHash = (Get-FileHash -LiteralPath $distService -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host ('CORRECTED TEMP-WATCHDOG BUILD: SHA256=' + $distHash) -ForegroundColor Green

    $resume = Join-Path $PSScriptRoot 'RESUME-V011-BETA2-B2-AFTER-IDLE-STABILIZATION.ps1'
    Invoke-WebRequest -Uri ($RepoRaw + $ResumeRef + '/RESUME-V011-BETA2-B2-AFTER-IDLE-STABILIZATION.ps1') -OutFile $resume

    Write-Host 'Launching the existing stabilized B2 resume against the freshly corrected build...' -ForegroundColor Yellow
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $resume
    if ($LASTEXITCODE -ne 0) { throw 'Stabilized B2 resume still failed after interactive TEMP watchdog repair' }

    Write-Host 'BC SENTINEL v0.11.0-beta.2 B2 INTERACTIVE-TEMP WATCHDOG REPAIR - PASS' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
