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

function Get-ProtectionServiceRecord {
    $services = @(Get-CimInstance Win32_Service | Where-Object {
        $p = [string]$_.PathName
        (-not [string]::IsNullOrWhiteSpace($p)) -and ($p.ToLowerInvariant().Contains('bc-sentinel-protection.exe'))
    })
    if ($services.Count -ne 1) {
        throw ('Expected exactly one installed BC Sentinel Protection Service, found ' + $services.Count)
    }
    return $services[0]
}

function Restart-ProtectionService([string]$ServiceName, [uint32]$PreviousPid, [string]$Label) {
    Write-Host (('Restarting installed Protection Service through SCM ({0}): {1}') -f $Label,$ServiceName) -ForegroundColor Cyan
    Restart-Service -Name $ServiceName -Force -ErrorAction Stop
    $deadline = (Get-Date).AddSeconds(15)
    $record = $null
    do {
        Start-Sleep -Milliseconds 350
        $record = Get-CimInstance Win32_Service -Filter ("Name='" + $ServiceName.Replace("'","''") + "'") -ErrorAction Stop
    } while (($null -eq $record -or [string]$record.State -ne 'Running' -or [uint32]$record.ProcessId -eq 0) -and (Get-Date) -lt $deadline)
    if ($null -eq $record -or [string]$record.State -ne 'Running' -or [uint32]$record.ProcessId -eq 0) {
        throw ('Protection Service did not return to Running after ' + $Label + ' restart')
    }
    $newPid = [uint32]$record.ProcessId
    if ($PreviousPid -gt 0 -and $newPid -eq $PreviousPid) {
        throw ('Protection Service PID did not change after ' + $Label + ' restart; runtime image freshness is unproven')
    }
    Write-Host (('Protection Service runtime synchronized: old PID={0}, new PID={1}') -f $PreviousPid,$newPid) -ForegroundColor Green
    return $record
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

    # The installed file may already be the fresh Beta2 build while SCM still
    # hosts an older process image. Force one synchronization restart before the
    # first Beta2 IPC assertion, and prove that Windows assigned a fresh PID.
    $script:CurrentStage = 'runtime_sync_restart'
    $service = Get-ProtectionServiceRecord
    $serviceName = [string]$service.Name
    $initialPid = [uint32]$service.ProcessId
    $service = Restart-ProtectionService -ServiceName $serviceName -PreviousPid $initialPid -Label 'runtime synchronization'

    $script:CurrentStage = 'runtime_sync_readiness'
    & $Py -m tools.v011_service_readiness --timeout-seconds 12 --poll-seconds 0.5 --output acceptance-v011-beta2-b2-runtime-sync-readiness.json
    if ($LASTEXITCODE -ne 0) { throw 'Protection Service readiness failed after runtime synchronization restart' }

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

    # Second restart is the actual persistence gate. The first restart above
    # only synchronizes the process image with the already-installed Beta2 file.
    $script:CurrentStage = 'service_restart'
    $prePersistencePid = [uint32](Get-ProtectionServiceRecord).ProcessId
    $service = Restart-ProtectionService -ServiceName $serviceName -PreviousPid $prePersistencePid -Label 'persistence validation'

    $script:CurrentStage = 'post_restart_readiness'
    & $Py -m tools.v011_service_readiness --timeout-seconds 12 --poll-seconds 0.5 --output acceptance-v011-beta2-b2-post-restart-readiness.json
    if ($LASTEXITCODE -ne 0) { throw 'Protection Service readiness failed after B2 persistence restart' }

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
    Write-Result 'PASS' $script:CurrentStage 'B2 production EDR IPC/native ingestion/Security Center persistence passed after runtime synchronization and survived a second real SCM restart.'
    Write-Host 'B2 LIVE-ONLY ADMIN GATE PASS' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
