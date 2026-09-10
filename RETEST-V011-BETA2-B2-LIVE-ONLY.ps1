param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.2 B2 LIVE-ONLY RESUME - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

function Read-JsonSafe([string]$Path) {
    try {
        if (Test-Path -LiteralPath $Path) { return (Get-Content -Raw -LiteralPath $Path -Encoding UTF8 | ConvertFrom-Json) }
    }
    catch { }
    return $null
}

function Require-PassedJson([string]$Path, [string]$Label) {
    $value = Read-JsonSafe $Path
    if ($null -eq $value) { throw ($Label + ' result missing/unreadable: ' + $Path) }
    if (-not [bool]$value.passed) { throw ($Label + ' result is not PASS: ' + $Path) }
    return $value
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this live-only resume from normal PowerShell so standard-user/UAC separation remains testable.'
    }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.2 - B2 LIVE-ONLY RESUME' -ForegroundColor Cyan
    Write-Host 'Reuses already verified 656-test/build/Beta1-admin evidence and executes only the remaining Beta2 live/restart/least-privilege gates.' -ForegroundColor Yellow

    $required = @(
        '.\sentinel\protection_service_core.py',
        '.\sentinel\protection_protocol.py',
        '.\sentinel\protection_client.py',
        '.\tools\v011_beta2_b1b_patch.py',
        '.\tools\broker_acceptance.py',
        '.\tools\v011_edr_acceptance.py',
        '.\dist\BC-Sentinel-Protection\BC-Sentinel-Protection.exe',
        '.\dist\BC-Sentinel-Protection\BC-Sentinel-Broker\BC-Sentinel-Broker.exe',
        '.\dist\BC-Sentinel-Protection\protection-integrity.json'
    )
    foreach ($item in $required) {
        if (-not (Test-Path -LiteralPath $item)) { throw ('B2 live-only prerequisite missing: ' + $item) }
    }

    $beta1 = Read-JsonSafe '.\acceptance-v011-beta1-admin-phase-result.json'
    if ($null -eq $beta1 -or [string]$beta1.status -ne 'PASS') {
        throw 'The immediately preceding Beta1 administrator gate is not recorded as PASS; use RETEST-V011-BETA2-B2-FROM-ADMIN.ps1 instead.'
    }
    $benchmark = Read-JsonSafe '.\benchmark-v011-beta1-service.json'
    if ($null -eq $benchmark -or -not [bool]$benchmark.passed) {
        throw 'The enforced Beta1 25/10/250 service benchmark is missing or failed.'
    }

    Require-PassedJson '.\acceptance-v011-beta2-b2-edr-local.json' 'Beta1 EDR local regression' | Out-Null
    Require-PassedJson '.\acceptance-v011-beta2-b2-deception-local.json' 'v0.10 deception local regression' | Out-Null
    Require-PassedJson '.\acceptance-v011-beta2-b2-response-local.json' 'v0.10 response local regression' | Out-Null
    Require-PassedJson '.\acceptance-v011-beta2-b2-clone-scam-local.json' 'v0.10 clone/scam local regression' | Out-Null
    Require-PassedJson '.\acceptance-v011-beta2-b2-rc1-local.json' 'v0.10 RC1 local regression' | Out-Null

    & $Py -m tools.v011_beta2_b1b_patch --verify-only --output integration-v011-beta2-b1b-before-b2-live-only-resume.json
    if ($LASTEXITCODE -ne 0) { throw 'B1b structural/source verification failed before live-only resume' }

    # Refresh the live acceptance plus every harness referenced by the B2
    # contract suite. These are test/orchestration files only: no FULL source,
    # installed service binary or accepted B1b integration file is overlaid.
    $LiveAcceptance = Join-Path $PSScriptRoot 'tools\v011_beta2_b2_live_acceptance.py'
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/v0.11.0-beta.2-checkpoint-b/tools/v011_beta2_b2_live_acceptance.py' -OutFile $LiveAcceptance
    $FrozenProbe = Join-Path $PSScriptRoot 'tools\v011_beta2_b2_frozen_runtime_probe.py'
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/v0.11.0-beta.2-checkpoint-b/tools/v011_beta2_b2_frozen_runtime_probe.py' -OutFile $FrozenProbe
    $AdminLiveScript = Join-Path $PSScriptRoot 'TEST-V011-BETA2-CHECKPOINT-B2-LIVE-ADMIN.ps1'
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/v0.11.0-beta.2-checkpoint-b/TEST-V011-BETA2-CHECKPOINT-B2-LIVE-ADMIN.ps1' -OutFile $AdminLiveScript
    $FullAdminScript = Join-Path $PSScriptRoot 'TEST-V011-BETA2-CHECKPOINT-B2-ADMIN.ps1'
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/v0.11.0-beta.2-checkpoint-b/TEST-V011-BETA2-CHECKPOINT-B2-ADMIN.ps1' -OutFile $FullAdminScript
    $FromAdminResume = Join-Path $PSScriptRoot 'RETEST-V011-BETA2-B2-FROM-ADMIN.ps1'
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/v0.11.0-beta.2-checkpoint-b/RETEST-V011-BETA2-B2-FROM-ADMIN.ps1' -OutFile $FromAdminResume
    $ContractTest = Join-Path $PSScriptRoot 'tests\test_v011_beta2_b2_contract.py'
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/v0.11.0-beta.2-checkpoint-b/tests/test_v011_beta2_b2_contract.py' -OutFile $ContractTest

    # Use a unique temp root so pytest never touches its shared pytest-current
    # junction/symlink on Windows. This mirrors the hardened full B2/Beta1 gates.
    $ContractPytestTemp = Join-Path $env:TEMP ('bc-sentinel-v011-beta2-b2-live-contract-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $ContractPytestTemp -Force | Out-Null
    try {
        & $Py -m pytest -q --basetemp $ContractPytestTemp tests\test_v011_beta2_b2_contract.py
        if ($LASTEXITCODE -ne 0) { throw 'B2 live-only contract test failed before UAC' }
    }
    finally {
        Remove-Item -LiteralPath $ContractPytestTemp -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Inspect the actual frozen Python code before touching SCM. Module presence
    # alone is insufficient: stale PyInstaller cache can package pre-B1b code
    # while still including the new EDR modules.
    $DistService = Join-Path $PSScriptRoot 'dist\BC-Sentinel-Protection\BC-Sentinel-Protection.exe'
    $InstalledService = Join-Path $env:ProgramFiles 'BC Sentinel\Protection\BC-Sentinel-Protection.exe'
    if (-not (Test-Path -LiteralPath $InstalledService)) { throw ('Installed Protection Service executable missing: ' + $InstalledService) }
    $distHash = (Get-FileHash -LiteralPath $DistService -Algorithm SHA256).Hash.ToLowerInvariant()
    $installedHash = (Get-FileHash -LiteralPath $InstalledService -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($distHash -ne $installedHash) { throw 'Fresh dist and installed Protection Service binaries differ before frozen-runtime probe' }

    $FrozenDistResult = Join-Path $PSScriptRoot 'probe-v011-beta2-b2-frozen-dist.json'
    & $Py -m tools.v011_beta2_b2_frozen_runtime_probe --exe $DistService --output $FrozenDistResult
    $frozenExit = $LASTEXITCODE
    $frozen = Read-JsonSafe $FrozenDistResult
    if ($frozenExit -ne 0 -or $null -eq $frozen -or -not [bool]$frozen.passed) {
        $classification = if ($null -ne $frozen -and $frozen.classification) { [string]$frozen.classification } else { 'probe_unreadable' }
        $detail = if ($null -ne $frozen -and $frozen.error) { [string]$frozen.error } else { '' }
        throw ('Frozen Protection Service B1b probe failed before UAC: ' + $classification + $(if ($detail) { ' | ' + $detail } else { '' }))
    }
    Write-Host ('B2 FROZEN RUNTIME PROBE PASS: ' + [string]$frozen.classification) -ForegroundColor Green
    if ($frozen.service_dispatch_validated_callers_in_module) {
        Write-Host ('dispatch_validated callers in frozen service module: ' + (($frozen.service_dispatch_validated_callers_in_module | ForEach-Object { [string]$_ }) -join ', ')) -ForegroundColor DarkCyan
    }

    $adminResultPath = Join-Path $PSScriptRoot 'acceptance-v011-beta2-b2-live-admin-result.json'
    Remove-Item -LiteralPath $adminResultPath -Force -ErrorAction SilentlyContinue
    Write-Host 'Opening B2 live-only UAC phase...' -ForegroundColor Yellow
    $adminArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $AdminLiveScript + '"'))
    $proc = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList $adminArgs
    if ($null -eq $proc) { throw 'B2 live-only administrator process was not created' }
    $adminResult = Read-JsonSafe $adminResultPath
    if ($null -ne $adminResult) {
        $color = if ([string]$adminResult.status -eq 'PASS') { 'Green' } else { 'Red' }
        Write-Host (('B2 LIVE ADMIN RESULT: status={0} | stage={1} | message={2}') -f $adminResult.status,$adminResult.stage,$adminResult.message) -ForegroundColor $color
    }
    if ($proc.ExitCode -ne 0) {
        if ($null -ne $adminResult) { throw ('B2 live admin failed at ' + [string]$adminResult.stage + ': ' + [string]$adminResult.message) }
        throw ('B2 live admin failed with exit code ' + $proc.ExitCode + ' and no readable result JSON')
    }
    if ($null -eq $adminResult -or [string]$adminResult.status -ne 'PASS') { throw 'B2 live administrator PASS result missing' }

    & $Py -m tools.broker_acceptance --output acceptance-v011-beta2-b2-standard-user-uac.json
    if ($LASTEXITCODE -ne 0) { throw 'Standard-user to UAC broker regression failed under B2 live-only resume' }

    & $Py -m tools.v011_beta2_b2_live_acceptance --mode standard-user --output acceptance-v011-beta2-b2-standard-user-edr.json
    if ($LASTEXITCODE -ne 0) {
        $detail = Read-JsonSafe '.\acceptance-v011-beta2-b2-standard-user-edr.json'
        throw ('B2 standard-user EDR least-privilege acceptance failed: ' + $(if ($null -ne $detail -and $detail.error) { [string]$detail.error } else { 'no detail' }))
    }

    & $Py -m tools.v011_edr_acceptance --output acceptance-v011-beta2-b2-edr-post-admin.json
    if ($LASTEXITCODE -ne 0) { throw 'Beta1 EDR post-admin regression failed under B2 live-only resume' }

    $benchmark = Read-JsonSafe '.\benchmark-v011-beta1-service.json'
    if ($null -eq $benchmark -or -not [bool]$benchmark.passed) { throw 'Enforced 25/10/250 service-performance result missing or failed' }
    Write-Host (('B2 PERFORMANCE CONFIRMED: idle={0:N2}% | IPC={1:N2}/s | storm={2:N2}%') -f [double]$benchmark.idle.cpu_percent_of_one_core,[double]$benchmark.ipc.requests_per_second,[double]$benchmark.benign_event_storm.cpu_percent_of_one_core) -ForegroundColor Green

    Write-Host 'BC SENTINEL v0.11.0-beta.2 B2 LIVE-ONLY RESUME - PASS' -ForegroundColor Green
    Write-Host 'Combine with the preceding 656-test + fresh-build + Beta1-admin PASS evidence to satisfy complete B2 acceptance.' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
