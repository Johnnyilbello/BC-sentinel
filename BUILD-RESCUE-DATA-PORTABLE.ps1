param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL RR5 SAFE DATA RESCUE BUILD - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

try {
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    Write-Host 'Building BC Sentinel Safe Data Rescue (onedir, source read-only)...' -ForegroundColor Cyan

    & $Py -m PyInstaller --noconfirm --clean --onedir `
        --name 'BC-Sentinel-Rescue-Data-Portable' `
        --distpath 'dist\Rescue' `
        --workpath 'build\Rescue-Data-Portable' `
        --specpath 'packaging' `
        --paths '.' `
        'packaging\rescue_data_rescue_entry.py'
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller RR5 safe data rescue build failed' }

    $Folder = Join-Path $PSScriptRoot 'dist\Rescue\BC-Sentinel-Rescue-Data-Portable'
    $Exe = Join-Path $Folder 'BC-Sentinel-Rescue-Data-Portable.exe'
    if (-not (Test-Path -LiteralPath $Exe)) { throw 'RR5 safe data rescue executable missing after build' }
    $Hash = (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLowerInvariant()
    $Manifest = [ordered]@{
        profile = 'v0.11.0-beta.3-rr5'
        artifact = 'BC-Sentinel-Rescue-Data-Portable.exe'
        sha256 = $Hash
        build_mode = 'onedir'
        source_read_only = $true
        installer_required = $false
        service_install = $false
        driver_install = $false
        automatic_restore = $false
        recovery_certification = $false
    }
    $Json = $Manifest | ConvertTo-Json -Depth 5
    [IO.File]::WriteAllText((Join-Path $Folder 'safe-data-rescue-integrity.json'), $Json + [Environment]::NewLine, $Utf8NoBom)
    Write-Host ('RR5 SAFE DATA RESCUE BUILD SHA256=' + $Hash) -ForegroundColor Green
    Write-Host ('Safe data rescue folder: ' + $Folder) -ForegroundColor Green
    Write-Host 'BC SENTINEL RR5 SAFE DATA RESCUE BUILD - PASS' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
