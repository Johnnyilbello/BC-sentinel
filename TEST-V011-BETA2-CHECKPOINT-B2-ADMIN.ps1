param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$ResultPath = Join-Path $PSScriptRoot 'acceptance-v011-beta2-b2-admin-result.json'
$PreRestartPath = Join-Path $PSScriptRoot 'acceptance-v011-beta2-b2-live-pre-restart.json'
$PostRestartPath = Join-Path $PSScriptRoot 'acceptance-v011-beta2-b2-live-post-restart.json'
$Beta1ResultPath = Join-Path $PSScriptRoot 'acceptance-v011-beta1-admin-phase-result.json'
$Beta1StdoutPath = Join-Path $PSScriptRoot 'acceptance-v011-beta2-b2-beta1-admin.stdout.log'
$Beta1StderrPath = Join-Path $PSScriptRoot 'acceptance-v011-beta2-b2-beta1-admin.stderr.log'
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

function Read-JsonSafe([string]$Path) {
    try {
        if (Test-Path -LiteralPath $Path) { return (Get-Content -Raw -LiteralPath $Path -Encoding UTF8 | ConvertFrom-Json) }
    } catch { }
    return $null
}

function Read-LogTail([string]$Path, [int]$Lines = 60) {
    try {
        if (Test-Path -LiteralPath $Path) { return ((Get-Content -LiteralPath $Path -Encoding UTF8 -Tail $Lines) -join ' | ') }
    } catch { }
    return ''
}

function Write-LogTail([string]$Label, [string]$Path, [int]$Lines = 30) {
    try {
        if (Test-Path -LiteralPath $Path) {
            Write-Host ($Label + ':') -ForegroundColor DarkCyan
            Get-Content -LiteralPath $Path -Encoding UTF8 -Tail $Lines | ForEach-Object { Write-Host $_ }
        }
    } catch { }
}

function Get-ProtectionServiceRecord {
    $services = @(Get-CimInstance Win32_Service | Where-Object {
        $p = [string]$_.PathName
        (-not [string]::IsNullOrWhiteSpace($p)) -and ($p.ToLowerInvariant().Contains('bc-sentinel-protection.exe'))
    })
    if ($services.Count -ne 1) { throw ('Expected exactly one installed BC Sentinel Protection Service, found ' + $services.Count) }
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
        throw 'B2 administrator gate requires UAC elevation from TEST-V011-BETA2-CHECKPOINT-B2.bat.'
    }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }
    $Py = '.\.venv\Scripts\python.exe'

    Write-Host 'BC Sentinel v0.11.0-beta.2 - CHECKPOINT B2 ADMIN LIVE GATE' -ForegroundColor Cyan

    $script:CurrentStage = 'beta1_admin_regression'
    Remove-Item -LiteralPath $Beta1StdoutPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Beta1StderrPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Beta1ResultPath -Force -ErrorAction SilentlyContinue
    $AdminPytestTemp = Join-Path $env:TEMP ('bc-sentinel-v011-beta2-b2-admin-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $AdminPytestTemp -Force | Out-Null
    $PreviousPytestAddopts = $env:PYTEST_ADDOPTS
    $PreviousPythonUtf8 = $env:PYTHONUTF8
    $PreviousPythonIoEncoding = $env:PYTHONIOENCODING
    try {
        $env:PYTEST_ADDOPTS = ('--basetemp="' + $AdminPytestTemp + '"')
        $env:PYTHONUTF8 = '1'
        $env:PYTHONIOENCODING = 'utf-8'
        $childArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + (Join-Path $PSScriptRoot 'TEST-V011-BETA1-ADMIN-PHASE.ps1') + '"'))
        $child = Start-Process -FilePath 'powershell.exe' -ArgumentList $childArgs -WorkingDirectory $PSScriptRoot -Wait -PassThru -NoNewWindow -RedirectStandardOutput $Beta1StdoutPath -RedirectStandardError $Beta1StderrPath
        if ($null -eq $child) { throw 'Beta1 administrator child process was not created' }
        $beta1Exit = [int]$child.ExitCode
    }
    finally {
        if ($null -eq $PreviousPytestAddopts) { Remove-Item Env:PYTEST_ADDOPTS -ErrorAction SilentlyContinue } else { $env:PYTEST_ADDOPTS = $PreviousPytestAddopts }
        if ($null -eq $PreviousPythonUtf8) { Remove-Item Env:PYTHONUTF8 -ErrorAction SilentlyContinue } else { $env:PYTHONUTF8 = $PreviousPythonUtf8 }
        if ($null -eq $PreviousPythonIoEncoding) { Remove-Item Env:PYTHONIOENCODING -ErrorAction SilentlyContinue } else { $env:PYTHONIOENCODING = $PreviousPythonIoEncoding }
        Remove-Item -LiteralPath $AdminPytestTemp -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-LogTail 'Beta1 admin stdout tail' $Beta1StdoutPath 25
    $stderrTail = Read-LogTail $Beta1StderrPath 40
    if ($stderrTail) { Write-LogTail 'Beta1 admin stderr tail' $Beta1StderrPath 25 }
    $beta1Result = Read-JsonSafe $Beta1ResultPath
    if ($beta1Exit -ne 0) {
        $stdoutTail = Read-LogTail $Beta1StdoutPath 60
        if ($null -ne $beta1Result) {
            $detail = ('Frozen Beta1 administrator gate failed at stage {0}: {1}' -f [string]$beta1Result.stage,[string]$beta1Result.message)
            if ($stderrTail) { $detail += ' | stderr tail: ' + $stderrTail }
            if ($stdoutTail) { $detail += ' | stdout tail: ' + $stdoutTail }
            throw $detail
        }
        $detail = 'Frozen Beta1 administrator gate failed without readable result JSON'
        if ($stderrTail) { $detail += ' | stderr tail: ' + $stderrTail }
        if ($stdoutTail) { $detail += ' | stdout tail: ' + $stdoutTail }
        throw $detail
    }
    if ($null -eq $beta1Result) { throw 'Beta1 administrator result JSON is missing after successful child exit' }
    if ([string]$beta1Result.status -ne 'PASS') {
        throw ('Beta1 administrator result is not PASS at stage ' + [string]$beta1Result.stage + ': ' + [string]$beta1Result.message)
    }

    $script:CurrentStage = 'request_op_lineage'
    & $Py -m tools.v011_beta2_b2_request_op_compat --verify-only --output acceptance-v011-beta2-b2-request-op-lineage-admin-full.json
    if ($LASTEXITCODE -ne 0) { throw 'B2 request.op source lineage failed after Beta1 administrator regression' }

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
    & $Py -m tools.v011_beta2_b2_live_acceptance_compat --mode pre-restart --output $PreRestartPath
    $preExit = $LASTEXITCODE
    $pre = Read-JsonSafe $PreRestartPath
    if ($preExit -ne 0 -or $null -eq $pre -or -not [bool]$pre.passed) {
        $detail = if ($null -ne $pre -and $pre.error) { [string]$pre.error } else { 'pre-restart result missing/unreadable' }
        throw ('B2 pre-restart production EDR IPC/native-ingestion acceptance failed: ' + $detail)
    }
    $marker = [string]$pre.marker_path
    $incidentId = [string]$pre.incident_id
    if ([string]::IsNullOrWhiteSpace($marker) -or [string]::IsNullOrWhiteSpace($incidentId)) { throw 'B2 pre-restart persistence anchors are missing' }

    $script:CurrentStage = 'service_restart'
    $prePersistencePid = [uint32](Get-ProtectionServiceRecord).ProcessId
    $service = Restart-ProtectionService -ServiceName $serviceName -PreviousPid $prePersistencePid -Label 'persistence validation'

    $script:CurrentStage = 'post_restart_readiness'
    & $Py -m tools.v011_service_readiness --timeout-seconds 12 --poll-seconds 0.5 --output acceptance-v011-beta2-b2-post-restart-readiness.json
    if ($LASTEXITCODE -ne 0) { throw 'Protection Service readiness failed after B2 persistence restart' }

    $script:CurrentStage = 'b2_live_post_restart'
    Remove-Item -LiteralPath $PostRestartPath -Force -ErrorAction SilentlyContinue
    & $Py -m tools.v011_beta2_b2_live_acceptance_compat --mode post-restart --marker $marker --incident-id $incidentId --output $PostRestartPath
    $postExit = $LASTEXITCODE
    $post = Read-JsonSafe $PostRestartPath
    if ($postExit -ne 0 -or $null -eq $post -or -not [bool]$post.passed) {
        $detail = if ($null -ne $post -and $post.error) { [string]$post.error } else { 'post-restart result missing/unreadable' }
        throw ('B2 EDR store/hunting/Security Center persistence failed after service restart: ' + $detail)
    }

    try { Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue } catch { }

    $script:CurrentStage = 'completed'
    Write-Result 'PASS' $script:CurrentStage 'Fresh Beta2 service passed Beta1 hardening/performance, request.op lineage, synchronized SCM runtime, production EDR IPC/native ingestion/Security Center and second-restart persistence.'
    Write-Host 'B2 ADMIN LIVE GATE PASS' -ForegroundColor Green
    exit 0
}
catch {
    Fail $_.Exception.Message
}
