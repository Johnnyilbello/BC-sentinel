param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL RR3 OFFLINE SCANNER BUILD - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

try {
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'
    Write-Host 'Building BC Sentinel Rescue Offline Scanner (onedir, read-only target)...' -ForegroundColor Cyan

    $YaraArgs = @()
    & $Py -c "import yara" 2>$null
    if ($LASTEXITCODE -eq 0) {
        $YaraArgs = @('--hidden-import', 'yara')
        Write-Host 'RR3 BUILD: local yara runtime detected; including optional YARA support.' -ForegroundColor DarkCyan
    }
    else {
        Write-Host 'RR3 BUILD: local yara runtime unavailable; building hash/heuristic scanner without YARA dependency.' -ForegroundColor DarkYellow
    }

    $Args = @(
        '-m','PyInstaller',
        '--noconfirm','--clean','--onedir',
        '--name','BC-Sentinel-Rescue-Offline-Scanner',
        '--distpath','dist\Rescue',
        '--workpath','build\Rescue-Offline-Scanner',
        '--specpath','packaging',
        '--paths','.',
        'packaging\rescue_offline_scanner_entry.py'
    ) + $YaraArgs

    & $Py @Args
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller RR3 offline scanner build failed' }

    $Folder = Join-Path $PSScriptRoot 'dist\Rescue\BC-Sentinel-Rescue-Offline-Scanner'
    $Exe = Join-Path $Folder 'BC-Sentinel-Rescue-Offline-Scanner.exe'
    if (-not (Test-Path -LiteralPath $Exe)) { throw 'RR3 scanner executable missing after build' }
    $Hash = (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLowerInvariant()
    $Manifest = [ordered]@{
        profile = 'v0.11.0-beta.3-rr3'
        artifact = 'BC-Sentinel-Rescue-Offline-Scanner.exe'
        sha256 = $Hash
        build_mode = 'onedir'
        target_read_only = $true
        installer_required = $false
        service_install = $false
        driver_install = $false
        yara_optional = $true
    }
    $Manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Folder 'offline-scanner-integrity.json') -Encoding UTF8
    Write-Host ('RR3 OFFLINE SCANNER BUILD SHA256=' + $Hash) -ForegroundColor Green
    Write-Host ('Offline scanner folder: ' + $Folder) -ForegroundColor Green
    Write-Host 'BC SENTINEL RR3 OFFLINE SCANNER BUILD - PASS' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
