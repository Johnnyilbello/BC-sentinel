param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL RR6 CERTIFICATION BUILD - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

try {
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'
    Write-Host 'Building BC Sentinel Rescue Integrity Certification (onedir, read-only target)...' -ForegroundColor Cyan

    & $Py -m PyInstaller --noconfirm --clean --onedir `
        --name 'BC-Sentinel-Rescue-Certification-Portable' `
        --distpath 'dist\Rescue' `
        --workpath 'build\Rescue-Certification-Portable' `
        --specpath 'packaging' `
        --paths '.' `
        'packaging\rescue_integrity_certification_entry.py'
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller RR6 certification build failed' }

    $Folder = Join-Path $PSScriptRoot 'dist\Rescue\BC-Sentinel-Rescue-Certification-Portable'
    $Exe = Join-Path $Folder 'BC-Sentinel-Rescue-Certification-Portable.exe'
    if (-not (Test-Path -LiteralPath $Exe)) { throw 'RR6 certification executable missing after build' }
    $Hash = (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLowerInvariant()
    $Manifest = [ordered]@{
        profile = 'v0.11.0-beta.3-rr6'
        artifact = 'BC-Sentinel-Rescue-Certification-Portable.exe'
        sha256 = $Hash
        build_mode = 'onedir'
        target_read_only = $true
        installer_required = $false
        service_install = $false
        driver_install = $false
        registry_write = $false
        boot_write = $false
        repair_execution = $false
        destructive_action = $false
    }
    $Json = $Manifest | ConvertTo-Json -Depth 5
    [IO.File]::WriteAllText((Join-Path $Folder 'certification-integrity.json'), $Json + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
    Write-Host ('RR6 CERTIFICATION BUILD SHA256=' + $Hash) -ForegroundColor Green
    Write-Host ('Certification folder: ' + $Folder) -ForegroundColor Green
    Write-Host 'BC SENTINEL RR6 CERTIFICATION BUILD - PASS' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
