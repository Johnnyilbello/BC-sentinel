param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL RR4B PORTABLE REPAIR BUILD - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

try {
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'
    Write-Host 'Building BC Sentinel Rescue Portable Repair Engine (onedir, offline-target only)...' -ForegroundColor Cyan

    & $Py -m PyInstaller --noconfirm --clean --onedir `
        --name 'BC-Sentinel-Rescue-Repair-Portable' `
        --distpath 'dist\Rescue' `
        --workpath 'build\Rescue-Repair-Portable' `
        --specpath 'packaging' `
        --paths '.' `
        'packaging\rescue_repair_portable_entry.py'
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller RR4B portable repair build failed' }

    $Folder = Join-Path $PSScriptRoot 'dist\Rescue\BC-Sentinel-Rescue-Repair-Portable'
    $Exe = Join-Path $Folder 'BC-Sentinel-Rescue-Repair-Portable.exe'
    if (-not (Test-Path -LiteralPath $Exe)) { throw 'RR4B executable missing after build' }
    $Hash = (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLowerInvariant()
    $Manifest = [ordered]@{
        profile = 'v0.11.0-beta.3-rr4b'
        artifact = 'BC-Sentinel-Rescue-Repair-Portable.exe'
        sha256 = $Hash
        build_mode = 'onedir'
        offline_target_only = $true
        exact_plan_confirmation_required = $true
        rollback_required = $true
        installer_required = $false
        service_install = $false
        driver_install = $false
        live_host_repair = $false
        registry_write = $false
        boot_write = $false
        automatic_repair = $false
        recovery_certification = $false
    }
    $Json = $Manifest | ConvertTo-Json -Depth 6
    [IO.File]::WriteAllText((Join-Path $Folder 'repair-portable-integrity.json'), $Json + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
    Write-Host ('RR4B PORTABLE REPAIR BUILD SHA256=' + $Hash) -ForegroundColor Green
    Write-Host ('Portable repair folder: ' + $Folder) -ForegroundColor Green
    Write-Host 'BC SENTINEL RR4B PORTABLE REPAIR BUILD - PASS' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
