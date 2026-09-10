param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$ResultPath = Join-Path $PSScriptRoot 'acceptance-v011-beta2-b2-admin-result.json'
$PreRestartPath = Join-Path $PSScriptRoot 'acceptance-v011-beta2-b2-live-pre-restart.json'
$PostRestartPath = Join-Path $PSScriptRoot 'acceptance-v011-beta2-b2-live-post-restart.json'
$script:CurrentStage = 'initialization'
Remove-Item -LiteralPath $ResultPath -Force -ErrorAction SilentlyContinue

function Write-Result([string]$Status, [string]$Stage, [string]$Message) {
    $payload = [ordered]@{
        product = 'BC Sentinel'
        version = '0.11.0-beta.2'
        checkpoint = 'B2'
        status = $Status
        stage = $Stage
        message = $Message
        timestamp = (Get-Date).ToString('o')
    }
    $payload | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
}

function Fail([string]$Message) {
    try { Write-Result 'FAIL' $script:CurrentStage $Message } catch { }
    Write-Host ('V0.11 BETA2 B2 ADMIN FAIL [' + $script:CurrentStage + ']: ' + $Message) -ForegroundColor Red
    exit 1
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'B2 administrator gate requires UAC elevation from TEST-V011-BETA2-CHECKPOINT-B2.bat.'
    }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.2 - CHECKPOINT B2 ADMIN LIVE GATE' -ForegroundColor Cyan

    # Reuse the already certified Beta1 Windows hardening gate. This performs
    # real Repair/readiness, measures performance BEFORE synthetic workloads,
    # then executes native/Web/EDR regressions without weakening 25/10/250.
    $script:CurrentStage = 'beta1_admin_regression'
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\TEST-V011-BETA1-ADMIN-PHASE.ps1'
    if ($LASTEXITCODE -ne 0) { throw 'Frozen Beta1 administrator regression/performance gate failed under Beta2 build' }

    $beta1ResultPath = Join-Path $PSScriptRoot 'acceptance-v011-beta1-admin-phase-result.json'
    if (-not (Test-Path -LiteralPath $beta1ResultPath)) { throw 'Beta1 administrator result JSON is missing' }
    $beta1Result = Get-Content -Raw -LiteralPath $beta1ResultPath | ConvertFrom-Json
    if ([string]$beta1Result.status -ne 'PASS') { throw ('Beta1 administrator result is not PASS: ' + $beta1Result.message) }

    # B2 live production Named Pipe: authenticated EDR reads, same-policy
    # privileged retention round-trip, native TEMP marker ingestion and
    # Security Center review-only visibility.
    $script:CurrentStage = 'b2_live_pre_restart'
    Remove-Item -LiteralPath $PreRestartPath -Force -ErrorAction SilentlyContinue
    & $Py -m tools.v011_beta2_b2_live_acceptance --mode pre-restart --output $PreRestartPath
    if ($LASTEXITCODE -ne 0) { throw 'B2 pre-restart production EDR IPC/native-ingestion acceptance failed' }
    $pre = Get-Content -Raw -LiteralPath $PreRestartPath | ConvertFrom-Json
    if (-not [bool]$pre.passed) { throw 'B2 pre-restart result is not PASS' }
    $marker = [string]$pre.marker_path
    $incidentId = [string]$pre.incident_id
    if ([string]::IsNullOrWhiteSpace($marker) -or [string]::IsNullOrWhiteSpace($incidentId)) {
        throw 'B2 pre-restart persistence anchors are missing'
    }

    # Identify the installed Protection Service by its executable path instead
    # of hard-coding a service name, then perform a real SCM restart.
    $script:CurrentStage = 'service_restart'
    $expectedExe = (Join-Path $env:ProgramFiles 'BC Sentinel\Protection\BC-Sentinel-Protection.exe').ToLowerInvariant()
    $services = @(Get-CimInstance Win32_Service | Where-Object {
        $p = [string]$_.PathName
        (-not [string]::IsNullOrWhiteSpace($p)) -and ($p.ToLowerInvariant().Contains('bc-sentinel-protection.exe'))
    })
    if ($services.Count -ne 1) {
        throw ('Expected exactly one installed BC Sentinel Protection Service, found ' + $services.Count)
    }
    $serviceName = [string]$services[0].Name
    Write-Host ('Restarting installed Protection Service through SCM: ' + $serviceName) -ForegroundColor Cyan
    Restart-Service -Name $serviceName -Force -ErrorAction Stop
    $deadline = (Get-Date).AddSeconds(15)
    do {
        Start-Sleep -Milliseconds 350
        $svc = Get-Service -Name $serviceName -ErrorAction Stop
    } while ($svc.Status -ne 'Running' -and (Get-Date) -lt $deadline)
    if ($svc.Status -ne 'Running') { throw 'Protection Service did not return to Running after restart' }

    $script:CurrentStage = 'post_restart_readiness'
    & $Py -m tools.v011_service_readiness --timeout-seconds 12 --poll-seconds 0.5 --output acceptance-v011-beta2-b2-post-restart-readiness.json
    if ($LASTEXITCODE -ne 0) { throw 'Protection Service readiness failed after B2 restart' }

    $script:CurrentStage = 'b2_live_post_restart'
    Remove-Item -LiteralPath $PostRestartPath -Force -ErrorAction SilentlyContinue
    & $Py -m tools.v011_beta2_b2_live_acceptance --mode post-restart --marker $marker --incident-id $incidentId --output $PostRestartPath
    if ($LASTEXITCODE -ne 0) { throw 'B2 EDR store/hunting/Security Center persistence failed after service restart' }

    try { Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue } catch { }

    $script:CurrentStage = 'completed'
    Write-Result 'PASS' $script:CurrentStage 'Fresh Beta2 service passed Beta1 hardening/performance plus production EDR IPC, native ingestion, Security Center and restart persistence.'
    Write-Host 'B2 ADMIN LIVE GATE PASS' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
