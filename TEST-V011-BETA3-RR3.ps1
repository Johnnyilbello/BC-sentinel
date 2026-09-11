param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Stage,[string]$Message) {
    Write-Host ('RR3 FAIL STAGE=' + $Stage + ' | ' + $Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.3 RR-3 OFFLINE THREAT SCANNER - FAIL' -ForegroundColor Red
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
        Fail 'preflight' 'Run RR3 acceptance from normal non-elevated PowerShell.'
    }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { Fail 'preflight' '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.3 - RR-3 OFFLINE THREAT SCANNER' -ForegroundColor Cyan
    Write-Host 'Read-only offline detection: no target execution, delete/quarantine/repair/registry/boot write or recovery certification.' -ForegroundColor Yellow

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

    & $Py -m compileall -q sentinel\rescue_contract.py sentinel\rescue_portable.py sentinel\rescue_usb.py sentinel\rescue_offline_scanner.py tools\v011_beta3_rr0_acceptance.py tools\v011_beta3_rr1_acceptance.py tools\v011_beta3_rr2_acceptance.py tools\v011_beta3_rr3_acceptance.py tests\test_v011_beta3_rr3_offline_scanner.py
    if ($LASTEXITCODE -ne 0) { Fail 'compileall' 'RR3 compileall failed' }

    $Base = Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    if (-not (Test-Path -LiteralPath $Base)) { New-Item -ItemType Directory -Path $Base -Force | Out-Null }
    $PytestRoot = Join-Path $Base ('rr3-pytest-' + [guid]::NewGuid().ToString('N'))
    Write-Host ('RR3 PYTEST BASETEMP=' + $PytestRoot) -ForegroundColor DarkGray
    try {
        & $Py -m pytest -q --basetemp $PytestRoot tests/test_v011_beta3_rr0_rescue_contract.py tests/test_v011_beta3_rr1_portable.py tests/test_v011_beta3_rr2_rescue_usb.py tests/test_v011_beta3_rr3_offline_scanner.py
        if ($LASTEXITCODE -ne 0) { Fail 'pytest' 'RR0/RR1/RR2/RR3 regression failed' }
    }
    finally {
        Remove-Item -LiteralPath $PytestRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    foreach ($spec in @(
        @('rr0','tools.v011_beta3_rr0_acceptance','acceptance-v011-beta3-rr0-regression.json'),
        @('rr1','tools.v011_beta3_rr1_acceptance','acceptance-v011-beta3-rr1-regression.json'),
        @('rr2','tools.v011_beta3_rr2_acceptance','acceptance-v011-beta3-rr2-regression.json'),
        @('rr3','tools.v011_beta3_rr3_acceptance','acceptance-v011-beta3-rr3.json')
    )) {
        & $Py -m $spec[1] --output $spec[2]
        if ($LASTEXITCODE -ne 0) { Fail ('acceptance-' + $spec[0]) ($spec[0] + ' deterministic acceptance failed') }
    }

    Write-Host 'Building portable RR3 offline scanner...' -ForegroundColor DarkCyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\BUILD-RESCUE-OFFLINE-SCANNER.ps1'
    if ($LASTEXITCODE -ne 0) { Fail 'build' 'RR3 offline scanner build failed' }

    $ScannerFolder = Join-Path $PSScriptRoot 'dist\Rescue\BC-Sentinel-Rescue-Offline-Scanner'
    $Exe = Join-Path $ScannerFolder 'BC-Sentinel-Rescue-Offline-Scanner.exe'
    $IntegrityPath = Join-Path $ScannerFolder 'offline-scanner-integrity.json'
    $Integrity = Read-JsonSafe $IntegrityPath
    if ($null -eq $Integrity) { Fail 'provenance' 'RR3 integrity manifest missing/unreadable' }
    if ([string]$Integrity.profile -ne 'v0.11.0-beta.3-rr3') { Fail 'provenance' 'RR3 integrity profile mismatch' }
    $ActualHash = (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ActualHash -ne ([string]$Integrity.sha256).ToLowerInvariant()) { Fail 'provenance' 'RR3 scanner binary hash mismatch' }

    $RunRoot = Join-Path $Base ('rr3-live-' + [guid]::NewGuid().ToString('N'))
    $Offline = Join-Path $RunRoot 'offline-target'
    $Evidence = Join-Path $RunRoot 'evidence'
    $Drivers = Join-Path $Offline 'Windows\System32\drivers'
    $Config = Join-Path $Offline 'Windows\System32\config'
    $Startup = Join-Path $Offline 'Users\Alice\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
    $UserTemp = Join-Path $Offline 'Users\Alice\AppData\Local\Temp'
    New-Item -ItemType Directory -Path $Drivers -Force | Out-Null
    New-Item -ItemType Directory -Path $Config -Force | Out-Null
    New-Item -ItemType Directory -Path $Startup -Force | Out-Null
    New-Item -ItemType Directory -Path $UserTemp -Force | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $Config 'SYSTEM'), [Text.Encoding]::UTF8.GetBytes('RR3 LIVE SYSTEM HIVE'))
    [IO.File]::WriteAllBytes((Join-Path $Config 'SOFTWARE'), [Text.Encoding]::UTF8.GetBytes('RR3 LIVE SOFTWARE HIVE'))
    [IO.File]::WriteAllBytes((Join-Path $Offline 'Windows\System32\ntoskrnl.exe'), [Text.Encoding]::UTF8.GetBytes('MZ RR3 harmless live kernel fixture'))
    $IocFile = Join-Path $Drivers 'rr3-live-ioc.sys'
    [IO.File]::WriteAllBytes($IocFile, [Text.Encoding]::UTF8.GetBytes('RR3 harmless live deterministic IOC fixture'))
    Set-Content -LiteralPath (Join-Path $Startup 'harmless.ps1') -Value "Write-Output 'RR3 harmless'" -Encoding UTF8
    [IO.File]::WriteAllBytes((Join-Path $UserTemp 'invoice.pdf.exe'), [Text.Encoding]::UTF8.GetBytes('MZ RR3 harmless lure fixture'))
    [IO.File]::WriteAllBytes((Join-Path $Offline 'Users\Alice\NTUSER.DAT'), [Text.Encoding]::UTF8.GetBytes('RR3 LIVE NTUSER HIVE'))

    $IocHash = (Get-FileHash -LiteralPath $IocFile -Algorithm SHA256).Hash.ToLowerInvariant()
    $IntelPath = Join-Path $RunRoot 'approved-intel.json'
    [ordered]@{
        schema = 'bc-sentinel-offline-intel-v1'
        approved = $true
        sha256 = @([ordered]@{ value = $IocHash; name = 'RR3.Live.IOC'; source = 'windows_acceptance' })
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $IntelPath -Encoding UTF8

    $YaraPath = Join-Path $RunRoot 'harmless-test.yar'
    @'
rule RR3_Harmless_Live_Marker {
    strings:
        $a = "RR3 harmless live deterministic IOC fixture" ascii
    condition:
        $a
}
'@ | Set-Content -LiteralPath $YaraPath -Encoding ASCII

    $Tracked = @(
        (Join-Path $Config 'SYSTEM'),
        (Join-Path $Config 'SOFTWARE'),
        (Join-Path $Offline 'Windows\System32\ntoskrnl.exe'),
        $IocFile,
        (Join-Path $Startup 'harmless.ps1'),
        (Join-Path $UserTemp 'invoice.pdf.exe'),
        (Join-Path $Offline 'Users\Alice\NTUSER.DAT')
    )
    $BeforeTarget = @{}
    foreach ($p in $Tracked) { $BeforeTarget[$p] = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash }

    try {
        Write-Host ('RR3 LIVE ROOT=' + $Offline) -ForegroundColor DarkGray
        Write-Host ('RR3 LIVE OUTPUT=' + $Evidence) -ForegroundColor DarkGray
        & $Exe --root $Offline --output $Evidence --intel-catalog $IntelPath --yara-rules $YaraPath --max-files 256 --max-file-bytes 1048576
        if ($LASTEXITCODE -ne 0) { Fail 'live-scan' 'built RR3 scanner returned failure' }

        $Result = Read-JsonSafe (Join-Path $Evidence 'rr3-offline-scan.json')
        if ($null -eq $Result) { Fail 'live-result' 'RR3 live result missing/unreadable' }
        if ([string]$Result.profile -ne 'v0.11.0-beta.3-rr3') { Fail 'live-result' 'RR3 live profile mismatch' }
        if ([int]$Result.summary.ioc_hits -ne 1) { Fail 'live-result' ('expected one deterministic IOC hit, got ' + [string]$Result.summary.ioc_hits) }
        if ([bool]$Result.safety.target_filesystem_write -or [bool]$Result.safety.registry_write -or [bool]$Result.safety.boot_write) { Fail 'live-safety' 'RR3 unexpectedly enabled target writes' }
        if ([bool]$Result.safety.file_delete -or [bool]$Result.safety.process_kill -or [bool]$Result.safety.quarantine_execution -or [bool]$Result.safety.repair_engine_enabled) { Fail 'live-safety' 'RR3 unexpectedly enabled destructive/repair behavior' }
        if ([bool]$Result.safety.automatic_action) { Fail 'live-safety' 'RR3 unexpectedly enabled automatic action' }

        $IocFindings = @($Result.findings | Where-Object { [string]$_.ioc_name -eq 'RR3.Live.IOC' })
        if ($IocFindings.Count -ne 1) { Fail 'live-result' ('expected exactly one RR3.Live.IOC finding, got ' + $IocFindings.Count) }
        if ([bool]$IocFindings[0].automatic_action) { Fail 'live-safety' 'deterministic IOC finding attempted automatic action' }
        if (@($Result.findings | Where-Object { @($_.reasons) -contains 'startup_location_artifact' }).Count -lt 1) { Fail 'live-result' 'startup evidence not surfaced' }
        if (@($Result.findings | Where-Object { @($_.reasons) -contains 'double_extension_lure' }).Count -lt 1) { Fail 'live-result' 'double-extension evidence not surfaced' }

        foreach ($p in $Tracked) {
            $after = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
            if ($after -ne $BeforeTarget[$p]) { Fail 'target-integrity' ('offline target changed: ' + $p) }
        }

        $Services = @(Get-CimInstance Win32_Service | Where-Object { ([string]$_.PathName).ToLowerInvariant().Contains('bc-sentinel-rescue-offline-scanner.exe') })
        if ($Services.Count -ne 0) { Fail 'live-safety' 'RR3 scanner unexpectedly registered a Windows service' }
    }
    finally {
        Remove-Item -LiteralPath $RunRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    foreach ($path in $Protected) {
        $after = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($after -ne $BeforeProtected[$path]) { Fail 'protected-source' ('RR3 modified protected B2 source: ' + $path) }
    }

    Write-Host ('RR3 OFFLINE SCANNER BINARY SHA256=' + $ActualHash) -ForegroundColor Green
    Write-Host 'RR3 LIVE: deterministic IOC detected | startup/lure evidence surfaced | target unchanged | no service | B2 sources unchanged' -ForegroundColor Green
    Write-Host 'BC SENTINEL v0.11.0-beta.3 RR-3 OFFLINE THREAT SCANNER - PASS' -ForegroundColor Green
    exit 0
}
catch {
    Fail 'unhandled' $_.Exception.Message
}
