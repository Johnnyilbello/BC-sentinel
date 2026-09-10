param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.2 B2 RESUME - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

function Read-JsonSafe([string]$Path) {
    try {
        if (Test-Path -LiteralPath $Path) { return (Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json) }
    }
    catch { }
    return $null
}

function Require-PassedJson([string]$Path, [string]$Label) {
    $value = Read-JsonSafe $Path
    if ($null -eq $value) { throw ($Label + ' result missing/unreadable: ' + $Path) }
    if (-not [bool]$value.passed) { throw ($Label + ' result is not PASS: ' + $Path) }
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run the B2 resume gate from a normal PowerShell; it must prove standard-user to UAC separation.'
    }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.2 - B2 RESUME FROM VERIFIED PRE-ADMIN STATE' -ForegroundColor Cyan
    Write-Host 'This resume does not replace the preceding 656-test/build evidence; it completes the failed UAC/live half of the same B2 attempt.' -ForegroundColor Yellow

    $required = @(
        '.\sentinel\protection_service_core.py',
        '.\sentinel\protection_protocol.py',
        '.\sentinel\protection_client.py',
        '.\tools\v011_beta2_b1b_patch.py',
        '.\tools\v011_beta2_b2_live_acceptance.py',
        '.\tools\broker_acceptance.py',
        '.\dist\BC-Sentinel-Protection\BC-Sentinel-Protection.exe',
        '.\dist\BC-Sentinel-Protection\BC-Sentinel-Broker\BC-Sentinel-Broker.exe',
        '.\dist\BC-Sentinel-Protection\protection-integrity.json'
    )
    foreach ($item in $required) {
        if (-not (Test-Path -LiteralPath $item)) { throw ('B2 resume prerequisite missing: ' + $item) }
    }

    # Prove the accepted B1b source anchors are still intact.
    & $Py -m tools.v011_beta2_b1b_patch --verify-only --output integration-v011-beta2-b1b-before-b2-resume.json
    if ($LASTEXITCODE -ne 0) { throw 'B1b source guards are not intact; full B2 must be rerun instead of resuming' }

    # Require the local acceptance evidence created by the immediately preceding
    # B2 pre-admin run. These do not substitute for pytest; the paired console
    # log is the 656-test evidence for this resume workflow.
    Require-PassedJson '.\acceptance-v011-beta2-b2-edr-local.json' 'Beta1 EDR local regression'
    Require-PassedJson '.\acceptance-v011-beta2-b2-deception-local.json' 'v0.10 deception local regression'
    Require-PassedJson '.\acceptance-v011-beta2-b2-response-local.json' 'v0.10 response local regression'
    Require-PassedJson '.\acceptance-v011-beta2-b2-clone-scam-local.json' 'v0.10 clone/scam local regression'
    Require-PassedJson '.\acceptance-v011-beta2-b2-rc1-local.json' 'v0.10 RC1 local regression'

    # Pull only the corrected admin harness. Do not overlay or rebuild the FULL
    # tree; the already-built service/broker are the artifacts under test.
    $AdminScript = Join-Path $PSScriptRoot 'TEST-V011-BETA2-CHECKPOINT-B2-ADMIN.ps1'
    $AdminUrl = 'https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/v0.11.0-beta.2-checkpoint-b/TEST-V011-BETA2-CHECKPOINT-B2-ADMIN.ps1'
    Invoke-WebRequest -Uri $AdminUrl -OutFile $AdminScript

    $adminResultPath = Join-Path $PSScriptRoot 'acceptance-v011-beta2-b2-admin-result.json'
    Remove-Item -LiteralPath $adminResultPath -Force -ErrorAction SilentlyContinue
    Write-Host 'Opening corrected B2 UAC administrator live phase...' -ForegroundColor Yellow
    $adminArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $AdminScript + '"'))
    $proc = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList $adminArgs
    if ($null -eq $proc) { throw 'B2 administrator process was not created' }

    $adminResult = Read-JsonSafe $adminResultPath
    if ($null -ne $adminResult) {
        $color = if ([string]$adminResult.status -eq 'PASS') { 'Green' } else { 'Red' }
        Write-Host (('B2 ADMIN RESULT: status={0} | stage={1} | message={2}') -f $adminResult.status,$adminResult.stage,$adminResult.message) -ForegroundColor $color
    }
    if ($proc.ExitCode -ne 0) {
        if ($null -ne $adminResult) { throw ('B2 admin failed at ' + [string]$adminResult.stage + ': ' + [string]$adminResult.message) }
        throw ('B2 admin failed with exit code ' + $proc.ExitCode + ' and no readable result JSON')
    }
    if ($null -eq $adminResult -or [string]$adminResult.status -ne 'PASS') { throw 'B2 administrator PASS result missing' }

    # Complete the same post-admin standard-user gates as the full B2 launcher.
    & $Py -m tools.broker_acceptance --output acceptance-v011-beta2-b2-standard-user-uac.json
    if ($LASTEXITCODE -ne 0) { throw 'Standard-user to UAC broker regression failed under B2 resume' }

    & $Py -m tools.v011_beta2_b2_live_acceptance --mode standard-user --output acceptance-v011-beta2-b2-standard-user-edr.json
    if ($LASTEXITCODE -ne 0) { throw 'B2 standard-user EDR least-privilege acceptance failed' }

    & $Py -m tools.v011_edr_acceptance --output acceptance-v011-beta2-b2-edr-post-admin.json
    if ($LASTEXITCODE -ne 0) { throw 'Beta1 EDR post-admin regression failed under B2 resume' }

    $benchmark = Read-JsonSafe (Join-Path $PSScriptRoot 'benchmark-v011-beta1-service.json')
    if ($null -eq $benchmark -or -not [bool]$benchmark.passed) {
        throw 'Enforced 25/10/250 service-performance result missing or failed in B2 resume'
    }
    Write-Host (('B2 PERFORMANCE CONFIRMED: idle={0:N2}% | IPC={1:N2}/s | storm={2:N2}%') -f [double]$benchmark.idle.cpu_percent_of_one_core,[double]$benchmark.ipc.requests_per_second,[double]$benchmark.benign_event_storm.cpu_percent_of_one_core) -ForegroundColor Green

    Write-Host 'BC SENTINEL v0.11.0-beta.2 B2 RESUME - PASS' -ForegroundColor Green
    Write-Host 'Combine this PASS with the immediately preceding 656-test + fresh-build B2 log to satisfy the complete B2 acceptance evidence.' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
