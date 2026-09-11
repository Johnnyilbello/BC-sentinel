param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.2 B2 COMPOSITE-LINEAGE RESUME - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

function Read-JsonSafe([string]$Path) {
    try {
        if (Test-Path -LiteralPath $Path) { return (Get-Content -Raw -LiteralPath $Path -Encoding UTF8 | ConvertFrom-Json) }
    } catch { }
    return $null
}

function Download-RequiredFile([string]$Destination, [string]$Uri) {
    $parent = Split-Path -Parent $Destination
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Write-Host ('Downloading: ' + $Uri) -ForegroundColor DarkGray
    Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $Destination
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
    $PinnedRef = '6d833d08912b64bd0d14d4f21d7838a3718c40f7'
    $CompositeRef = '71ead6c3cff5058ce4403ebeb6ac5da52112c9a5'
    $RepoRaw = 'https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/'
    $ExpectedServiceSourceHash = '55302443fd488c4f6da28010f25a23c9e37e930943109ae4984f9719ba4187ed'
    $ExpectedBinaryHash = 'ba5691ed320c66bed4d3aae54928f1a557d4c191bc7fa4d031875f4e0a1aeb3a'

    Write-Host 'BC Sentinel v0.11.0-beta.2 - B2 COMPOSITE-LINEAGE LIVE RESUME' -ForegroundColor Cyan
    Write-Host 'No rebuild. Reuses the already deployed service-settings build and the frozen B2 live/performance gate.' -ForegroundColor Yellow
    Write-Host 'No timeout or 25/10/250 threshold relaxation.' -ForegroundColor Yellow

    $pinnedFiles = @(
        @('TEST-V011-BETA2-B2-REQUEST-OP-ADMIN.ps1','TEST-V011-BETA2-B2-REQUEST-OP-ADMIN.ps1'),
        @('tools\v011_beta2_b2_live_acceptance.py','tools/v011_beta2_b2_live_acceptance.py'),
        @('tools\v011_beta2_b2_live_acceptance_compat.py','tools/v011_beta2_b2_live_acceptance_compat.py'),
        @('tools\v011_service_readiness.py','tools/v011_service_readiness.py'),
        @('tools\service_hardening_benchmark.py','tools/service_hardening_benchmark.py'),
        @('tools\v011_edr_acceptance.py','tools/v011_edr_acceptance.py')
    )
    foreach ($item in $pinnedFiles) {
        Download-RequiredFile $item[0] ($RepoRaw + $PinnedRef + '/' + $item[1])
    }

    # The frozen admin gate imports this historical module name. Supply the
    # strict composite verifier under that exact path without changing the gate.
    Download-RequiredFile `
        '.\tools\v011_beta2_b2_request_op_compat.py' `
        ($RepoRaw + $CompositeRef + '/tools/v011_beta2_b2_composite_lineage.py')

    $adminText = Get-Content -Raw -LiteralPath '.\TEST-V011-BETA2-B2-REQUEST-OP-ADMIN.ps1' -Encoding UTF8
    if (-not $adminText.Contains('Start-Sleep -Seconds 15')) { throw 'Frozen administrator gate is missing the verified 15-second stabilization window' }
    if (-not $adminText.Contains('--max-idle-cpu-percent 25') -or -not $adminText.Contains('--min-ipc-rps 10') -or -not $adminText.Contains('--max-storm-cpu-percent 250')) {
        throw 'Frozen 25/10/250 benchmark thresholds are missing from the administrator gate'
    }

    $lineageText = Get-Content -Raw -LiteralPath '.\tools\v011_beta2_b2_request_op_compat.py' -Encoding UTF8
    if (-not $lineageText.Contains($ExpectedServiceSourceHash)) { throw 'Composite verifier does not pin the accepted service-core hash' }
    if (-not $lineageText.Contains('bc-sentinel-v011-beta2-settings-ownership-v1')) { throw 'Composite verifier is missing settings-ownership marker validation' }

    Write-Host ('PINNED LIVE GATE PASS: ' + $PinnedRef) -ForegroundColor Green
    Write-Host ('COMPOSITE LINEAGE VERIFIER PASS: ' + $CompositeRef) -ForegroundColor Green

    & $Py -m tools.v011_beta2_b2_request_op_compat --verify-only --output acceptance-v011-beta2-b2-composite-lineage-resume.json
    if ($LASTEXITCODE -ne 0) { throw 'Strict composite source-lineage verification failed before live resume' }

    $distService = Join-Path $PSScriptRoot 'dist\BC-Sentinel-Protection\BC-Sentinel-Protection.exe'
    $installedService = Join-Path $env:ProgramFiles 'BC Sentinel\Protection\BC-Sentinel-Protection.exe'
    if (-not (Test-Path -LiteralPath $installedService)) { throw 'Installed corrected Protection Service executable missing' }
    $distHash = (Get-FileHash -LiteralPath $distService -Algorithm SHA256).Hash.ToLowerInvariant()
    $installedHash = (Get-FileHash -LiteralPath $installedService -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($distHash -ne $installedHash) { throw 'Corrected dist and installed Protection Service differ before live resume' }
    if ($distHash -ne $ExpectedBinaryHash) { throw ('Current corrected build hash is not the accepted service-settings build: ' + $distHash) }
    Write-Host ('COMPOSITE BINARY PROVENANCE PASS: SHA256=' + $distHash) -ForegroundColor Green

    $adminScript = Join-Path $PSScriptRoot 'TEST-V011-BETA2-B2-REQUEST-OP-ADMIN.ps1'
    $adminResultPath = Join-Path $PSScriptRoot 'acceptance-v011-beta2-b2-request-op-admin-result.json'
    Remove-Item -LiteralPath $adminResultPath -Force -ErrorAction SilentlyContinue
    Write-Host 'Opening frozen B2 UAC live phase...' -ForegroundColor Yellow
    $adminArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $adminScript + '"'))
    $proc = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList $adminArgs
    if ($null -eq $proc) { throw 'B2 administrator process was not created' }

    $admin = Read-JsonSafe $adminResultPath
    if ($null -ne $admin) {
        $color = if ([string]$admin.status -eq 'PASS') { 'Green' } else { 'Red' }
        Write-Host (('COMPOSITE ADMIN RESULT: status={0} | stage={1} | message={2}') -f $admin.status,$admin.stage,$admin.message) -ForegroundColor $color
    }
    if ($proc.ExitCode -ne 0) {
        if ($null -ne $admin) { throw ('B2 admin failed at ' + [string]$admin.stage + ': ' + [string]$admin.message) }
        throw ('B2 administrator process failed with exit code ' + $proc.ExitCode)
    }
    if ($null -eq $admin -or [string]$admin.status -ne 'PASS') { throw 'B2 administrator PASS result missing' }

    & $Py -m tools.broker_acceptance --output acceptance-v011-beta2-b2-composite-standard-user-uac.json
    if ($LASTEXITCODE -ne 0) { throw 'Standard-user to UAC broker regression failed after admin PASS' }

    & $Py -m tools.v011_beta2_b2_live_acceptance_compat --mode standard-user --output acceptance-v011-beta2-b2-composite-standard-user-edr.json
    if ($LASTEXITCODE -ne 0) {
        $detail = Read-JsonSafe '.\acceptance-v011-beta2-b2-composite-standard-user-edr.json'
        throw ('Standard-user EDR least-privilege acceptance failed: ' + $(if ($null -ne $detail -and $detail.error) { [string]$detail.error } else { 'no detail' }))
    }

    & $Py -m tools.v011_edr_acceptance --output acceptance-v011-beta2-b2-composite-edr-post-admin.json
    if ($LASTEXITCODE -ne 0) { throw 'Beta1 EDR regression failed after admin PASS' }

    $benchmark = Read-JsonSafe '.\benchmark-v011-beta2-b2-request-op-fix.json'
    if ($null -eq $benchmark -or -not [bool]$benchmark.passed) { throw 'Frozen corrected-service 25/10/250 benchmark evidence missing or failed' }
    Write-Host (('B2 COMPOSITE PERFORMANCE: idle={0:N2}% | IPC={1:N2}/s | storm={2:N2}%') -f [double]$benchmark.idle.cpu_percent_of_one_core,[double]$benchmark.ipc.requests_per_second,[double]$benchmark.benign_event_storm.cpu_percent_of_one_core) -ForegroundColor Green

    Write-Host 'BC SENTINEL v0.11.0-beta.2 B2 COMPOSITE-LINEAGE RESUME - PASS' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
