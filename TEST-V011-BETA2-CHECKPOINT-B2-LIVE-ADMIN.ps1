param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$ResultPath = Join-Path $PSScriptRoot 'acceptance-v011-beta2-b2-live-admin-result.json'
$PreRestartPath = Join-Path $PSScriptRoot 'acceptance-v011-beta2-b2-live-pre-restart.json'
$PostRestartPath = Join-Path $PSScriptRoot 'acceptance-v011-beta2-b2-live-post-restart.json'
$script:CurrentStage = 'initialization'
Remove-Item -LiteralPath $ResultPath -Force -ErrorAction SilentlyContinue

function Write-Result([string]$Status, [string]$Stage, [string]$Message) {
    [ordered]@{
        product = 'BC Sentinel'
        version = '0.11.0-beta.2'
        checkpoint = 'B2-live-only'
        status = $Status
        stage = $Stage
        message = $Message
        timestamp = (Get-Date).ToString('o')
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
}

function Read-JsonSafe([string]$Path) {
    try {
        if (Test-Path -LiteralPath $Path) { return (Get-Content -Raw -LiteralPath $Path -Encoding UTF8 | ConvertFrom-Json) }
    }
    catch { }
    return $null
}

function Fail([string]$Message) {
    try { Write-Result 'FAIL' $script:CurrentStage $Message } catch { }
    Write-Host ('V0.11 BETA2 B2 LIVE ADMIN FAIL [' + $script:CurrentStage + ']: ' + $Message) -ForegroundColor Red
    exit 1
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'B2 live-only administrator gate requires UAC elevation from the standard-user resume launcher.'
    }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.2 - B2 LIVE-ONLY ADMIN GATE' -ForegroundColor Cyan

    $script:CurrentStage = 'prerequisite_beta1_admin'
    $beta1 = Read-JsonSafe (Join-Path $PSScriptRoot 'acceptance-v011-beta1-admin-phase-result.json')
    if ($null -eq $beta1 -or [string]$beta1.status -ne 'PASS') {
        throw 'Verified Beta1 administrator PASS result is missing; use the full B2 resume instead.'
    }
    $benchmark = Read-JsonSafe (Join-Path $PSScriptRoot 'benchmark-v011-beta1-service.json')
    if ($null -eq $benchmark -or -not [bool]$benchmark.passed) {
        throw 'Verified Beta1 25/10/250 performance result is missing or failed.'
    }

    $script:CurrentStage = 'b1b_integrity'
    & $Py -m tools.v011_beta2_b1b_patch --verify-only --output integration-v011-beta2-b1b-before-b2-live-only.json
    if ($LASTEXITCODE -ne 0) { throw 'B1b structural/source verification failed before live-only gate' }

    $script:CurrentStage = 'b2_live_pre_restart'
    Remove-Item -LiteralPath $PreRestartPath -Force -ErrorAction SilentlyContinue
    & $Py -m tools.v011_beta2_b2_live_acceptance --mode pre-restart --output $PreRestartPath
    $preExit = $LASTEXITCODE
    $pre = Read-JsonSafe $PreRestartPath
    if ($preExit -ne 0 -or $null -eq $pre -or -not [bool]$pre.passed) {
        $detail = if ($null -ne $pre -and $pre.error) { [string]$pre.error } else { 'pre-restart result missing/unreadable' }
        throw ('B2 pre-restart live acceptance failed: ' + $detail)
    }
    $marker = [string]$pre.marker_path
    $incidentId = [string]$pre.incident_id
    if ([string]::IsNullOrWhiteSpace($marker) -or [string]::IsNullOrWhiteSpace($incidentId)) {
        throw 'B2 pre-restart persistence anchors are missing'
    }

    $script:CurrentStage = 'service_restart'
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
    $postExit = $LASTEXITCODE
    $post = Read-JsonSafe $PostRestartPath
    if ($postExit -ne 0 -or $null -eq $post -or -not [bool]$post.passed) {
        $detail = if ($null -ne $post -and $post.error) { [string]$post.error } else { 'post-restart result missing/unreadable' }
        throw ('B2 post-restart live acceptance failed: ' + $detail)
    }

    try { Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue } catch { }

    $script:CurrentStage = 'completed'
    Write-Result 'PASS' $script:CurrentStage 'B2 production EDR IPC/native ingestion/Security Center persistence survived a real SCM restart.'
    Write-Host 'B2 LIVE-ONLY ADMIN GATE PASS' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
