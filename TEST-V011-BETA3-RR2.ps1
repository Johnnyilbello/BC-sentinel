param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Stage,[string]$Message) {
    Write-Host ('RR2 FAIL STAGE=' + $Stage + ' | ' + $Message) -ForegroundColor Red
    Write-Host 'BC SENTINEL v0.11.0-beta.3 RR-2 RESCUE USB - FAIL' -ForegroundColor Red
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
        throw 'RR2 acceptance must run from normal non-elevated PowerShell.'
    }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.3 - RR-2 RESCUE USB' -ForegroundColor Cyan
    Write-Host 'Safe-media scope only: no format, partition/boot-sector/bootloader/BCD/firmware write and no repair execution.' -ForegroundColor Yellow

    $Protected = @(
        '.\sentinel\protection_service_core.py',
        '.\sentinel\realtime.py',
        '.\sentinel\edr.py',
        '.\sentinel\edr_service_bridge.py'
    )
    $ProtectedBefore = @{}
    foreach ($path in $Protected) {
        if (-not (Test-Path -LiteralPath $path)) { Fail 'protected_source_preflight' ('missing ' + $path) }
        $ProtectedBefore[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    & $Py -m compileall -q sentinel\rescue_contract.py sentinel\rescue_portable.py sentinel\rescue_usb.py tools\v011_beta3_rr0_acceptance.py tools\v011_beta3_rr1_acceptance.py tools\v011_beta3_rr2_acceptance.py tests\test_v011_beta3_rr0_rescue_contract.py tests\test_v011_beta3_rr1_portable.py tests\test_v011_beta3_rr2_rescue_usb.py
    if ($LASTEXITCODE -ne 0) { Fail 'compileall' 'RR0/RR1/RR2 compileall failed' }

    $BaseTempRoot = Join-Path $env:USERPROFILE 'BCSentinel-TestTemp'
    if (-not (Test-Path -LiteralPath $BaseTempRoot)) { New-Item -ItemType Directory -Path $BaseTempRoot -Force | Out-Null }
    $PytestBase = Join-Path $BaseTempRoot ('rr2-pytest-' + [guid]::NewGuid().ToString('N'))
    Write-Host ('RR2 PYTEST BASETEMP=' + $PytestBase) -ForegroundColor DarkGray
    & $Py -m pytest -q --basetemp $PytestBase tests/test_v011_beta3_rr0_rescue_contract.py tests/test_v011_beta3_rr1_portable.py tests/test_v011_beta3_rr2_rescue_usb.py
    $pytestExit = $LASTEXITCODE
    Remove-Item -LiteralPath $PytestBase -Recurse -Force -ErrorAction SilentlyContinue
    if ($pytestExit -ne 0) { Fail 'pytest_regression' ('RR0/RR1/RR2 pytest failed exit=' + $pytestExit) }

    & $Py -m tools.v011_beta3_rr0_acceptance --output acceptance-v011-beta3-rr0-regression.json
    if ($LASTEXITCODE -ne 0) { Fail 'rr0_acceptance' 'RR0 regression acceptance failed' }
    & $Py -m tools.v011_beta3_rr1_acceptance --output acceptance-v011-beta3-rr1-regression.json
    if ($LASTEXITCODE -ne 0) { Fail 'rr1_acceptance' 'RR1 regression acceptance failed' }
    & $Py -m tools.v011_beta3_rr2_acceptance --output acceptance-v011-beta3-rr2.json
    if ($LASTEXITCODE -ne 0) { Fail 'rr2_acceptance' 'RR2 deterministic acceptance failed' }

    Write-Host 'Rebuilding frozen RR1 portable payload used as RR2 source...' -ForegroundColor DarkCyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\BUILD-RESCUE-PORTABLE.ps1'
    if ($LASTEXITCODE -ne 0) { Fail 'portable_build' 'RR1 portable rebuild failed' }

    $Portable = Join-Path $PSScriptRoot 'dist\Rescue\BC-Sentinel-Rescue-Portable'
    $PortableExe = Join-Path $Portable 'BC-Sentinel-Rescue-Portable.exe'
    if (-not (Test-Path -LiteralPath $PortableExe)) { Fail 'portable_source' 'RR1 portable executable missing' }
    $PortableHashBefore = (Get-FileHash -LiteralPath $PortableExe -Algorithm SHA256).Hash.ToLowerInvariant()

    $RunRoot = Join-Path $BaseTempRoot ('rr2-live-' + [guid]::NewGuid().ToString('N'))
    $UsbSim = Join-Path $RunRoot 'usb-sim'
    $Offline = Join-Path $RunRoot 'offline-target'
    New-Item -ItemType Directory -Path $UsbSim -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $Offline 'Windows\System32\config') -Force | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $Offline 'Windows\System32\config\SYSTEM'), [Text.Encoding]::UTF8.GetBytes('RR2 harmless fake SYSTEM hive'))
    [IO.File]::WriteAllBytes((Join-Path $Offline 'Windows\System32\ntoskrnl.exe'), [Text.Encoding]::UTF8.GetBytes('RR2 harmless fake kernel'))
    $OfflineHiveBefore = (Get-FileHash -LiteralPath (Join-Path $Offline 'Windows\System32\config\SYSTEM') -Algorithm SHA256).Hash
    $OfflineKernelBefore = (Get-FileHash -LiteralPath (Join-Path $Offline 'Windows\System32\ntoskrnl.exe') -Algorithm SHA256).Hash

    try {
        Write-Host ('RR2 LIVE SOURCE=' + $Portable) -ForegroundColor DarkGray
        Write-Host ('RR2 LIVE DESTINATION=' + $UsbSim) -ForegroundColor DarkGray
        & $Py -m sentinel.rescue_usb prepare --source $Portable --destination $UsbSim --simulation --max-files 20000 --max-total-bytes 4294967296
        if ($LASTEXITCODE -ne 0) { Fail 'live_prepare' 'safe USB simulation preparation failed' }

        & $Py -m sentinel.rescue_usb verify --destination $UsbSim
        if ($LASTEXITCODE -ne 0) { Fail 'live_verify' 'prepared USB payload verification failed' }

        $ManifestPath = Join-Path $UsbSim 'rescue-usb-manifest.json'
        $Manifest = Read-JsonSafe $ManifestPath
        if ($null -eq $Manifest) { Fail 'manifest' 'RR2 manifest missing/unreadable' }
        if ([string]$Manifest.profile -ne 'v0.11.0-beta.3-rr2') { Fail 'manifest' 'RR2 profile mismatch' }
        if ([int]$Manifest.summary.files -lt 2) { Fail 'manifest' ('unexpected payload file count=' + [string]$Manifest.summary.files) }
        $Safety = $Manifest.safety
        if ([bool]$Safety.format_disk -or [bool]$Safety.partition_write -or [bool]$Safety.boot_sector_write -or [bool]$Safety.bootloader_install -or [bool]$Safety.bcd_write -or [bool]$Safety.firmware_write) { Fail 'safety' 'destructive disk/boot capability unexpectedly enabled' }
        if ([bool]$Safety.registry_write -or [bool]$Safety.target_filesystem_write -or [bool]$Safety.file_delete -or [bool]$Safety.repair_engine_enabled -or [bool]$Safety.quarantine_execution_enabled -or [bool]$Safety.recovery_certification_enabled) { Fail 'safety' 'repair/write capability unexpectedly enabled' }

        $AuditPath = Join-Path $UsbSim 'rescue-usb-audit.jsonl'
        if (-not (Test-Path -LiteralPath $AuditPath)) { Fail 'audit' 'RR2 structured audit missing' }
        $AuditText = Get-Content -Raw -LiteralPath $AuditPath -Encoding UTF8
        if (-not $AuditText.Contains('"stage": "prepare_start"') -or -not $AuditText.Contains('"stage": "prepare_complete"')) { Fail 'audit' 'RR2 audit does not expose expected stages' }
        if (-not $AuditText.Contains('"reason"') -or -not $AuditText.Contains('"correlation_id"')) { Fail 'audit' 'RR2 audit missing reason/correlation_id' }

        $DiscoverJson = Join-Path $RunRoot 'discover.json'
        $discoverOutput = & $Py -m sentinel.rescue_usb discover $Offline 2>&1
        $discoverExit = $LASTEXITCODE
        $discoverOutput | Set-Content -LiteralPath $DiscoverJson -Encoding UTF8
        if ($discoverExit -ne 0) { Fail 'offline_discovery' ('RR2 discovery failed exit=' + $discoverExit) }
        $Discover = Read-JsonSafe $DiscoverJson
        if ($null -eq $Discover -or -not [bool]$Discover.passed -or @($Discover.candidates).Count -ne 1) { Fail 'offline_discovery' 'expected exactly one harmless offline Windows candidate' }

        $OfflineHiveAfter = (Get-FileHash -LiteralPath (Join-Path $Offline 'Windows\System32\config\SYSTEM') -Algorithm SHA256).Hash
        $OfflineKernelAfter = (Get-FileHash -LiteralPath (Join-Path $Offline 'Windows\System32\ntoskrnl.exe') -Algorithm SHA256).Hash
        if ($OfflineHiveBefore -ne $OfflineHiveAfter -or $OfflineKernelBefore -ne $OfflineKernelAfter) { Fail 'offline_discovery' 'offline target changed during discovery' }

        $PortableHashAfter = (Get-FileHash -LiteralPath $PortableExe -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($PortableHashBefore -ne $PortableHashAfter) { Fail 'source_integrity' 'RR1 portable source changed during RR2 preparation' }
    }
    finally {
        Remove-Item -LiteralPath $RunRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    foreach ($path in $Protected) {
        $after = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($after -ne $ProtectedBefore[$path]) { Fail 'protected_source_postcheck' ('RR2 modified protected B2 source: ' + $path) }
    }

    Write-Host ('RR2 SOURCE PORTABLE SHA256=' + $PortableHashBefore) -ForegroundColor Green
    Write-Host 'RR2 LIVE: payload prepared+verified | offline Windows discovered read-only | source unchanged | B2 sources unchanged' -ForegroundColor Green
    Write-Host 'BC SENTINEL v0.11.0-beta.3 RR-2 RESCUE USB - PASS' -ForegroundColor Green
    exit 0
}
catch {
    Fail 'unhandled' $_.Exception.Message
}
