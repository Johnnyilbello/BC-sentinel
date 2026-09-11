param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL RR1 PORTABLE BUILD - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

try {
    $PyInstaller = '.\.venv\Scripts\pyinstaller.exe'
    if (-not (Test-Path -LiteralPath $PyInstaller)) { throw '.venv PyInstaller not available' }
    if (-not (Test-Path -LiteralPath '.\packaging\rescue_portable_entry.py')) { throw 'portable entrypoint missing' }
    if (-not (Test-Path -LiteralPath '.\sentinel\rescue_portable.py')) { throw 'RR1 runtime missing' }
    if (-not (Test-Path -LiteralPath '.\sentinel\rescue_contract.py')) { throw 'RR0 safety contract missing' }

    $Dist = Join-Path $PSScriptRoot 'dist\Rescue'
    $Work = Join-Path $PSScriptRoot 'build\Rescue-Portable'
    Remove-Item -LiteralPath $Dist -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host 'Building BC Sentinel Rescue Portable (onedir, no installer/service/driver)...' -ForegroundColor Cyan
    & $PyInstaller `
        --noconfirm `
        --clean `
        --onedir `
        --console `
        --name 'BC-Sentinel-Rescue-Portable' `
        --distpath $Dist `
        --workpath $Work `
        --specpath (Join-Path $PSScriptRoot 'packaging') `
        --paths $PSScriptRoot `
        '.\packaging\rescue_portable_entry.py'
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller portable build failed' }

    $Exe = Join-Path $Dist 'BC-Sentinel-Rescue-Portable\BC-Sentinel-Rescue-Portable.exe'
    if (-not (Test-Path -LiteralPath $Exe)) { throw 'portable executable missing after build' }
    $Hash = (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLowerInvariant()

    $Manifest = [ordered]@{
        product = 'BC Sentinel Rescue Portable'
        profile = 'v0.11.0-beta.3-rr1'
        packaging = 'pyinstaller-onedir'
        installer_required = $false
        service_install = $false
        driver_install = $false
        executable = $Exe
        sha256 = $Hash
    }
    $ManifestPath = Join-Path $Dist 'BC-Sentinel-Rescue-Portable\portable-integrity.json'
    $Manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ManifestPath -Encoding UTF8

    Write-Host ('RR1 PORTABLE BUILD SHA256=' + $Hash) -ForegroundColor Green
    Write-Host ('Portable folder: ' + (Split-Path -Parent $Exe)) -ForegroundColor Green
    Write-Host 'BC SENTINEL RR1 PORTABLE BUILD - PASS' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
