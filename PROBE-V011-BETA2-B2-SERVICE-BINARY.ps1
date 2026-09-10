param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.2 B2 BINARY PROBE - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

function Resolve-ServiceExe([string]$PathName) {
    $value = [string]$PathName
    if ([string]::IsNullOrWhiteSpace($value)) { return '' }
    $value = $value.Trim()
    if ($value.StartsWith('"')) {
        $end = $value.IndexOf('"', 1)
        if ($end -gt 1) { return $value.Substring(1, $end - 1) }
    }
    $m = [regex]::Match($value, '^(.*?\.exe)(?:\s|$)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($m.Success) { return $m.Groups[1].Value.Trim('"') }
    return ''
}

function Get-ArchiveListing([string]$ExePath) {
    $viewer = Join-Path $PSScriptRoot '.venv\Scripts\pyi-archive_viewer.exe'
    if (-not (Test-Path -LiteralPath $viewer)) {
        throw ('PyInstaller archive viewer missing: ' + $viewer)
    }
    $lines = @(& $viewer -r -b $ExePath 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw ('pyi-archive-viewer failed for ' + $ExePath + ' with exit code ' + $LASTEXITCODE)
    }
    return ($lines -join "`n")
}

function Module-Flags([string]$Listing) {
    $folded = $Listing.ToLowerInvariant()
    return [ordered]@{
        protection_protocol = $folded.Contains('sentinel.protection_protocol')
        edr_service_bridge = $folded.Contains('sentinel.edr_service_bridge')
        edr_hunting = $folded.Contains('sentinel.edr_hunting')
        edr_adapter = $folded.Contains('sentinel.edr_adapter')
        edr_core = $folded.Contains('sentinel.edr')
    }
}

try {
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }
    $dist = Join-Path $PSScriptRoot 'dist\BC-Sentinel-Protection\BC-Sentinel-Protection.exe'
    if (-not (Test-Path -LiteralPath $dist)) { throw ('Fresh B2 dist executable missing: ' + $dist) }

    $services = @(Get-CimInstance Win32_Service | Where-Object {
        $p = [string]$_.PathName
        (-not [string]::IsNullOrWhiteSpace($p)) -and $p.ToLowerInvariant().Contains('bc-sentinel-protection.exe')
    })
    if ($services.Count -ne 1) { throw ('Expected exactly one BC Sentinel Protection service; found ' + $services.Count) }
    $svc = $services[0]
    $installed = Resolve-ServiceExe ([string]$svc.PathName)
    if ([string]::IsNullOrWhiteSpace($installed) -or -not (Test-Path -LiteralPath $installed)) {
        throw ('Installed service executable could not be resolved from SCM PathName: ' + [string]$svc.PathName)
    }

    $distHash = (Get-FileHash -LiteralPath $dist -Algorithm SHA256).Hash.ToLowerInvariant()
    $installedHash = (Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash.ToLowerInvariant()
    $distItem = Get-Item -LiteralPath $dist
    $installedItem = Get-Item -LiteralPath $installed

    $distListing = Get-ArchiveListing $dist
    $installedListing = Get-ArchiveListing $installed
    $distModules = Module-Flags $distListing
    $installedModules = Module-Flags $installedListing

    $same = $distHash -eq $installedHash
    $distBeta2 = [bool]$distModules.edr_service_bridge -and [bool]$distModules.protection_protocol
    $installedBeta2 = [bool]$installedModules.edr_service_bridge -and [bool]$installedModules.protection_protocol
    $classification = if ($distBeta2 -and -not $same) {
        'fresh_dist_beta2_but_installed_binary_differs'
    }
    elseif (-not $distBeta2) {
        'fresh_dist_missing_beta2_edr_modules'
    }
    elseif ($same -and $installedBeta2) {
        'dist_and_installed_binary_identical_with_beta2_modules'
    }
    elseif ($same -and -not $installedBeta2) {
        'identical_binary_but_beta2_modules_not_discovered'
    }
    else {
        'binary_provenance_inconclusive'
    }

    $result = [ordered]@{
        profile = 'v0.11.0-beta.2'
        probe = 'service_binary_provenance'
        passed = $true
        classification = $classification
        service = [ordered]@{
            name = [string]$svc.Name
            state = [string]$svc.State
            start_mode = [string]$svc.StartMode
            path_name = [string]$svc.PathName
            resolved_exe = $installed
        }
        dist = [ordered]@{
            path = $dist
            sha256 = $distHash
            size = [int64]$distItem.Length
            last_write_utc = $distItem.LastWriteTimeUtc.ToString('o')
            modules = $distModules
        }
        installed = [ordered]@{
            path = $installed
            sha256 = $installedHash
            size = [int64]$installedItem.Length
            last_write_utc = $installedItem.LastWriteTimeUtc.ToString('o')
            modules = $installedModules
        }
        dist_equals_installed = $same
    }
    $out = Join-Path $PSScriptRoot 'probe-v011-beta2-b2-service-binary.json'
    $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $out -Encoding UTF8
    $result | ConvertTo-Json -Depth 8
    Write-Host ('B2 BINARY PROBE CLASSIFICATION: ' + $classification) -ForegroundColor Cyan
    Write-Host 'BC SENTINEL v0.11.0-beta.2 B2 BINARY PROBE - PASS' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
