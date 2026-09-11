param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Stage,[string]$Message) {
    Write-Host ('RR5 FAIL STAGE=' + $Stage + ' | ' + $Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.3 RR-5 SAFE DATA RESCUE - FAIL' -ForegroundColor Red
    exit 1
}

function Read-JsonSafe([string]$Path) {
    try {
        if (Test-Path -LiteralPath $Path) { return (Get-Content -Raw -LiteralPath $Path -Encoding UTF8 | ConvertFrom-Json) }
    } catch { }
    return $null
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Fail 'preflight' 'Run RR5 acceptance from normal non-elevated PowerShell.'
    }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { Fail 'preflight' '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

    Write-Host 'BC Sentinel v0.11.0-beta.3 - RR-5 SAFE DATA RESCUE' -ForegroundColor Cyan
    Write-Host 'Explicit user-data extraction only: source read-only, active/unknown content isolated, no execution/repair/certification.' -ForegroundColor Yellow

    $Protected = @(
        '.\sentinel\protection_service_core.py',
        '.\sentinel\realtime.py',
        '.\sentinel\edr.py',
        '.\sentinel\edr_service_bridge.py'
    )
    $BeforeProtected = @{}
    foreach ($path in $Protected) {
        if (-not (Test-Path -LiteralPath $path)) { Fail 'preflight' ('protected source missing: ' + $path) }
        $BeforeProtected[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    $Base = Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    if (-not (Test-Path -LiteralPath $Base)) { New-Item -ItemType Directory -Path $Base -Force | Out-Null }
    $ProcessTemp = Join-Path $Base ('rr5-process-temp-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $ProcessTemp -Force | Out-Null
    $OriginalTemp = $env:TEMP
    $OriginalTmp = $env:TMP
    $env:TEMP = $ProcessTemp
    $env:TMP = $ProcessTemp

    try {
        & $Py -m compileall -q sentinel\rescue_contract.py sentinel\rescue_portable.py sentinel\rescue_usb.py sentinel\rescue_offline_scanner.py sentinel\rescue_repair_engine.py sentinel\rescue_repair_portable.py sentinel\rescue_data_rescue.py tools\v011_beta3_rr5_acceptance.py tests\test_v011_beta3_rr5_safe_data_rescue.py
        if ($LASTEXITCODE -ne 0) { Fail 'compileall' 'RR5 compileall failed' }

        $PytestRoot = Join-Path $Base ('rr5-pytest-' + [guid]::NewGuid().ToString('N'))
        Write-Host ('RR5 PYTEST BASETEMP=' + $PytestRoot) -ForegroundColor DarkGray
        try {
            & $Py -m pytest -q --basetemp $PytestRoot `
                tests/test_v011_beta3_rr0_rescue_contract.py `
                tests/test_v011_beta3_rr1_portable.py `
                tests/test_v011_beta3_rr2_rescue_usb.py `
                tests/test_v011_beta3_rr3_offline_scanner.py `
                tests/test_v011_beta3_rr4a_repair_engine.py `
                tests/test_v011_beta3_rr4b_portable_repair.py `
                tests/test_v011_beta3_rr5_safe_data_rescue.py
            if ($LASTEXITCODE -ne 0) { Fail 'pytest' 'RR0-RR5 regression failed' }
        }
        finally {
            Remove-Item -LiteralPath $PytestRoot -Recurse -Force -ErrorAction SilentlyContinue
        }

        foreach ($spec in @(
            @('rr0','tools.v011_beta3_rr0_acceptance','acceptance-v011-beta3-rr0-regression.json'),
            @('rr1','tools.v011_beta3_rr1_acceptance','acceptance-v011-beta3-rr1-regression.json'),
            @('rr2','tools.v011_beta3_rr2_acceptance','acceptance-v011-beta3-rr2-regression.json'),
            @('rr3','tools.v011_beta3_rr3_acceptance','acceptance-v011-beta3-rr3-regression.json'),
            @('rr4a','tools.v011_beta3_rr4a_acceptance','acceptance-v011-beta3-rr4a-regression.json'),
            @('rr4b','tools.v011_beta3_rr4b_acceptance','acceptance-v011-beta3-rr4b-regression.json'),
            @('rr5','tools.v011_beta3_rr5_acceptance','acceptance-v011-beta3-rr5.json')
        )) {
            & $Py -m $spec[1] --output $spec[2]
            if ($LASTEXITCODE -ne 0) { Fail ('acceptance-' + $spec[0]) ($spec[0] + ' deterministic acceptance failed') }
        }

        Write-Host 'Building portable RR5 safe data rescue...' -ForegroundColor DarkCyan
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\BUILD-RESCUE-DATA-PORTABLE.ps1'
        if ($LASTEXITCODE -ne 0) { Fail 'build' 'RR5 safe data rescue build failed' }

        $Folder = Join-Path $PSScriptRoot 'dist\Rescue\BC-Sentinel-Rescue-Data-Portable'
        $Exe = Join-Path $Folder 'BC-Sentinel-Rescue-Data-Portable.exe'
        $IntegrityPath = Join-Path $Folder 'safe-data-rescue-integrity.json'
        $Integrity = Read-JsonSafe $IntegrityPath
        if ($null -eq $Integrity) { Fail 'provenance' 'RR5 integrity manifest missing/unreadable' }
        if ([string]$Integrity.profile -ne 'v0.11.0-beta.3-rr5') { Fail 'provenance' 'RR5 integrity profile mismatch' }
        $ActualHash = (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($ActualHash -ne ([string]$Integrity.sha256).ToLowerInvariant()) { Fail 'provenance' 'RR5 portable binary hash mismatch' }

        $RunRoot = Join-Path $Base ('rr5-live-' + [guid]::NewGuid().ToString('N'))
        $Offline = Join-Path $RunRoot 'offline-target'
        $Output = Join-Path $RunRoot 'rescued-output'
        $Config = Join-Path $Offline 'Windows\System32\config'
        $System32 = Join-Path $Offline 'Windows\System32'
        $Docs = Join-Path $Offline 'Users\Alice\Documents'
        $Downloads = Join-Path $Offline 'Users\Alice\Downloads'
        New-Item -ItemType Directory -Path $Config -Force | Out-Null
        New-Item -ItemType Directory -Path $Docs -Force | Out-Null
        New-Item -ItemType Directory -Path $Downloads -Force | Out-Null
        [IO.File]::WriteAllBytes((Join-Path $Config 'SYSTEM'), [Text.Encoding]::UTF8.GetBytes('RR5 LIVE SYSTEM'))
        [IO.File]::WriteAllBytes((Join-Path $System32 'ntoskrnl.exe'), [Text.Encoding]::UTF8.GetBytes('MZ RR5 LIVE KERNEL'))
        [IO.File]::WriteAllText((Join-Path $Docs 'notes.txt'), 'RR5 harmless notes', $Utf8NoBom)
        [IO.File]::WriteAllBytes((Join-Path $Docs 'photo.jpg'), [Text.Encoding]::UTF8.GetBytes('RR5 harmless IOC photo'))
        [IO.File]::WriteAllBytes((Join-Path $Downloads 'harmless-tool.exe'), [Text.Encoding]::UTF8.GetBytes('MZ RR5 harmless executable'))
        [IO.File]::WriteAllText((Join-Path $Downloads 'harmless.ps1'), "Write-Output 'RR5 harmless'", $Utf8NoBom)
        [IO.File]::WriteAllBytes((Join-Path $Docs 'budget.xlsm'), [Text.Encoding]::UTF8.GetBytes('RR5 harmless macro document'))
        [IO.File]::WriteAllBytes((Join-Path $Docs 'archive.custom'), [Text.Encoding]::UTF8.GetBytes('RR5 harmless unknown extension'))

        $Photo = Join-Path $Docs 'photo.jpg'
        $PhotoHash = (Get-FileHash -LiteralPath $Photo -Algorithm SHA256).Hash.ToLowerInvariant()
        $IntelPath = Join-Path $RunRoot 'approved-intel.json'
        $Intel = [ordered]@{
            schema = 'bc-sentinel-offline-intel-v1'
            approved = $true
            sha256 = @([ordered]@{ value = $PhotoHash; name = 'RR5.Live.IOC'; source = 'windows_acceptance' })
        } | ConvertTo-Json -Depth 6
        [IO.File]::WriteAllText($IntelPath, $Intel + [Environment]::NewLine, $Utf8NoBom)

        $BeforeSource = @{}
        Get-ChildItem -LiteralPath $Offline -Recurse -File | ForEach-Object {
            $BeforeSource[$_.FullName] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }

        Write-Host ('RR5 LIVE SOURCE=' + $Offline) -ForegroundColor DarkGray
        Write-Host ('RR5 LIVE DESTINATION=' + $Output) -ForegroundColor DarkGray
        & $Exe --source $Offline --destination $Output --include 'Users/Alice/Documents' --include 'Users/Alice/Downloads' --intel-catalog $IntelPath --max-files 64 --max-total-bytes 1048576 --max-file-bytes 1048576 --max-depth 16
        if ($LASTEXITCODE -ne 0) { Fail 'live-rescue' 'built RR5 data rescue executable returned failure' }

        $Manifest = Read-JsonSafe (Join-Path $Output 'rr5-rescue-manifest.json')
        if ($null -eq $Manifest) { Fail 'live-result' 'RR5 live manifest missing/unreadable' }
        if ([string]$Manifest.profile -ne 'v0.11.0-beta.3-rr5') { Fail 'live-result' 'RR5 live profile mismatch' }
        if ([int]$Manifest.summary.copied -ne 6 -or [int]$Manifest.summary.errors -ne 0) { Fail 'live-result' 'RR5 expected 6 copied / 0 errors' }
        if ([int]$Manifest.summary.contained -ne 5) { Fail 'live-result' ('RR5 expected 5 contained items, got ' + [string]$Manifest.summary.contained) }

        $CleanFiles = @(Get-ChildItem -LiteralPath (Join-Path $Output 'rescued-data') -Recurse -File)
        $ContainedFiles = @(Get-ChildItem -LiteralPath (Join-Path $Output 'containment') -Recurse -File)
        if ($CleanFiles.Count -ne 1 -or $CleanFiles[0].Name -ne 'notes.txt') { Fail 'live-isolation' 'RR5 clean tree must contain only notes.txt fixture' }
        if ($ContainedFiles.Count -ne 5) { Fail 'live-isolation' ('RR5 containment expected 5 files, got ' + $ContainedFiles.Count) }

        foreach ($record in @($Manifest.records)) {
            if ([string]$record.status -ne 'copied') { Fail 'live-result' ('unexpected record status: ' + [string]$record.status) }
            $SourceFile = Join-Path $Offline (([string]$record.relative_path).Replace('/','\'))
            $DestinationFile = Join-Path $Output (([string]$record.destination_relative_path).Replace('/','\'))
            if (-not (Test-Path -LiteralPath $DestinationFile)) { Fail 'live-hash' ('copied file missing: ' + $DestinationFile) }
            $SourceHash = (Get-FileHash -LiteralPath $SourceFile -Algorithm SHA256).Hash.ToLowerInvariant()
            $DestinationHash = (Get-FileHash -LiteralPath $DestinationFile -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($SourceHash -ne $DestinationHash -or $DestinationHash -ne ([string]$record.sha256).ToLowerInvariant()) { Fail 'live-hash' ('SHA256 mismatch: ' + [string]$record.relative_path) }
        }

        foreach ($entry in $BeforeSource.GetEnumerator()) {
            if (-not (Test-Path -LiteralPath $entry.Key)) { Fail 'source-integrity' ('source file disappeared: ' + $entry.Key) }
            $after = (Get-FileHash -LiteralPath $entry.Key -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($after -ne $entry.Value) { Fail 'source-integrity' ('offline source changed: ' + $entry.Key) }
        }
        $AfterFiles = @(Get-ChildItem -LiteralPath $Offline -Recurse -File)
        if ($AfterFiles.Count -ne $BeforeSource.Count) { Fail 'source-integrity' 'offline source file count changed' }

        if (-not [bool]$Manifest.safety.source_read_only -or [bool]$Manifest.safety.source_file_execution -or [bool]$Manifest.safety.source_delete -or [bool]$Manifest.safety.repair_engine_execution -or [bool]$Manifest.safety.recovery_certification_enabled) {
            Fail 'live-safety' 'RR5 safety flags invalid'
        }
        $Services = @(Get-CimInstance Win32_Service | Where-Object { ([string]$_.PathName).ToLowerInvariant().Contains('bc-sentinel-rescue-data-portable.exe') })
        if ($Services.Count -ne 0) { Fail 'live-safety' 'RR5 unexpectedly registered a Windows service' }

        foreach ($path in $Protected) {
            $after = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($after -ne $BeforeProtected[$path]) { Fail 'protected-source' ('RR5 modified protected B2 source: ' + $path) }
        }

        Write-Host ('RR5 SAFE DATA RESCUE BINARY SHA256=' + $ActualHash) -ForegroundColor Green
        Write-Host 'RR5 LIVE: passive data rescued | active/unknown/IOC content contained | 6/6 SHA256 verified | source unchanged | no service | B2 sources unchanged' -ForegroundColor Green
        Write-Host 'BC SENTINEL v0.11.0-beta.3 RR-5 SAFE DATA RESCUE - PASS' -ForegroundColor Green
        exit 0
    }
    finally {
        $env:TEMP = $OriginalTemp
        $env:TMP = $OriginalTmp
        Remove-Item -LiteralPath $ProcessTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
catch {
    Fail 'unhandled' $_.Exception.Message
}
