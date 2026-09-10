param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.2 B2 STABILIZED RESUME - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
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
        throw 'Run this resume from normal PowerShell; UAC separation is part of B2 acceptance.'
    }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }
    if (-not (Test-Path -LiteralPath '.\AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1')) { throw 'AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1 missing' }
    if (-not (Test-Path -LiteralPath '.\dist\BC-Sentinel-Protection\BC-Sentinel-Protection.exe')) { throw 'Corrected Protection Service dist executable missing' }
    if (-not (Test-Path -LiteralPath '.\tools\broker_acceptance.py')) { throw 'FULL-only tools\broker_acceptance.py missing' }
    $Py = '.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.2 - B2 STABILIZED PERFORMANCE/LIVE RESUME' -ForegroundColor Cyan
    Write-Host 'Reuses verified request.op lineage, 34 targeted tests and corrected build. No rebuild and no threshold relaxation.' -ForegroundColor Yellow

    # Immutable snapshot containing the post-restart stabilization fix.
    $PinnedRef = '6d833d08912b64bd0d14d4f21d7838a3718c40f7'
    $BaseUri = 'https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/' + $PinnedRef + '/'
    $downloads = @(
        @('TEST-V011-BETA2-B2-REQUEST-OP-ADMIN.ps1','TEST-V011-BETA2-B2-REQUEST-OP-ADMIN.ps1'),
        @('tools\v011_beta2_b2_request_op_compat.py','tools/v011_beta2_b2_request_op_compat.py'),
        @('tools\v011_beta2_b2_live_acceptance.py','tools/v011_beta2_b2_live_acceptance.py'),
        @('tools\v011_beta2_b2_live_acceptance_compat.py','tools/v011_beta2_b2_live_acceptance_compat.py'),
        @('tools\v011_service_readiness.py','tools/v011_service_readiness.py'),
        @('tools\service_hardening_benchmark.py','tools/service_hardening_benchmark.py'),
        @('tools\v011_edr_acceptance.py','tools/v011_edr_acceptance.py')
    )
    foreach ($item in $downloads) {
        $local = Join-Path $PSScriptRoot $item[0]
        $uri = $BaseUri + $item[1]
        Invoke-WebRequest -Uri $uri -OutFile $local
    }

    $adminText = Get-Content -Raw -LiteralPath '.\TEST-V011-BETA2-B2-REQUEST-OP-ADMIN.ps1' -Encoding UTF8
    if (-not $adminText.Contains("Start-Sleep -Seconds 15")) { throw 'Pinned administrator gate is missing the verified 15-second stabilization window' }
    if (-not $adminText.Contains('--max-idle-cpu-percent 25') -or -not $adminText.Contains('--min-ipc-rps 10') -or -not $adminText.Contains('--max-storm-cpu-percent 250')) {
        throw 'Frozen 25/10/250 benchmark thresholds are missing from the administrator gate'
    }
    Write-Host ('PINNED STABILIZED GATE PASS: ' + $PinnedRef) -ForegroundColor Green

    & $Py -m tools.v011_beta2_b2_request_op_compat --verify-only --output acceptance-v011-beta2-b2-request-op-lineage-stabilized-resume.json
    if ($LASTEXITCODE -ne 0) { throw 'Corrected request.op lineage verification failed before stabilized resume' }

    $distService = Join-Path $PSScriptRoot 'dist\BC-Sentinel-Protection\BC-Sentinel-Protection.exe'
    $installedService = Join-Path $env:ProgramFiles 'BC Sentinel\Protection\BC-Sentinel-Protection.exe'
    if (-not (Test-Path -LiteralPath $installedService)) { throw 'Installed corrected Protection Service executable missing' }
    $distHash = (Get-FileHash -LiteralPath $distService -Algorithm SHA256).Hash.ToLowerInvariant()
    $installedHash = (Get-FileHash -LiteralPath $installedService -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($distHash -ne $installedHash) { throw 'Corrected dist and installed Protection Service differ before stabilized resume' }
    Write-Host ('CORRECTED BINARY PROVENANCE PASS: SHA256=' + $distHash) -ForegroundColor Green

    $adminScript = Join-Path $PSScriptRoot 'TEST-V011-BETA2-B2-REQUEST-OP-ADMIN.ps1'
    $adminResultPath = Join-Path $PSScriptRoot 'acceptance-v011-beta2-b2-request-op-admin-result.json'
    Remove-Item -LiteralPath $adminResultPath -Force -ErrorAction SilentlyContinue
    Write-Host 'Opening stabilized B2 UAC phase...' -ForegroundColor Yellow
    $adminArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $adminScript + '"'))
    $proc = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList $adminArgs
    if ($null -eq $proc) { throw 'Stabilized B2 administrator process was not created' }
    $admin = Read-JsonSafe $adminResultPath
    if ($null -ne $admin) {
        $color = if ([string]$admin.status -eq 'PASS') { 'Green' } else { 'Red' }
        Write-Host (('STABILIZED ADMIN RESULT: status={0} | stage={1} | message={2}') -f $admin.status,$admin.stage,$admin.message) -ForegroundColor $color
    }
    if ($proc.ExitCode -ne 0) {
        if ($null -ne $admin) { throw ('Stabilized B2 admin failed at ' + [string]$admin.stage + ': ' + [string]$admin.message) }
        throw ('Stabilized B2 administrator process failed with exit code ' + $proc.ExitCode)
    }
    if ($null -eq $admin -or [string]$admin.status -ne 'PASS') { throw 'Stabilized B2 administrator PASS result missing' }

    & $Py -m tools.broker_acceptance --output acceptance-v011-beta2-b2-stabilized-standard-user-uac.json
    if ($LASTEXITCODE -ne 0) { throw 'Standard-user to UAC broker regression failed after stabilized admin PASS' }

    & $Py -m tools.v011_beta2_b2_live_acceptance_compat --mode standard-user --output acceptance-v011-beta2-b2-stabilized-standard-user-edr.json
    if ($LASTEXITCODE -ne 0) {
        $detail = Read-JsonSafe '.\acceptance-v011-beta2-b2-stabilized-standard-user-edr.json'
        throw ('Standard-user EDR least-privilege acceptance failed: ' + $(if ($null -ne $detail -and $detail.error) { [string]$detail.error } else { 'no detail' }))
    }

    & $Py -m tools.v011_edr_acceptance --output acceptance-v011-beta2-b2-stabilized-edr-post-admin.json
    if ($LASTEXITCODE -ne 0) { throw 'Beta1 EDR regression failed after stabilized admin PASS' }

    $benchmark = Read-JsonSafe '.\benchmark-v011-beta2-b2-request-op-fix.json'
    if ($null -eq $benchmark -or -not [bool]$benchmark.passed) { throw 'Stabilized corrected-service 25/10/250 benchmark evidence missing or failed' }
    Write-Host (('B2 STABILIZED PERFORMANCE: idle={0:N2}% | IPC={1:N2}/s | storm={2:N2}%') -f [double]$benchmark.idle.cpu_percent_of_one_core,[double]$benchmark.ipc.requests_per_second,[double]$benchmark.benign_event_storm.cpu_percent_of_one_core) -ForegroundColor Green

    Write-Host 'BC SENTINEL v0.11.0-beta.2 B2 STABILIZED RESUME - PASS' -ForegroundColor Green
    Write-Host 'Combine with the preceding 656-test evidence, request.op 34-test PASS, corrected clean build and frozen-runtime probe PASS to complete B2 acceptance.' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
