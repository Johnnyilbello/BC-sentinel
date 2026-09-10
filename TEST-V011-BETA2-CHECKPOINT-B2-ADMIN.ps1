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
        if (Test-Path -LiteralPath $Path) {
            return (Get-Content -Raw -LiteralPath $Path -Encoding UTF8 | ConvertFrom-Json)
        }
    }
    catch { }
    return $null
}

function Read-LogTail([string]$Path, [int]$Lines = 60) {
    try {
        if (Test-Path -LiteralPath $Path) {
            return ((Get-Content -LiteralPath $Path -Encoding UTF8 -Tail $Lines) -join ' | ')
        }
    }
    catch { }
    return ''
}

function Write-LogTail([string]$Label, [string]$Path, [int]$Lines = 30) {
    try {
        if (Test-Path -LiteralPath $Path) {
            Write-Host ($Label + ':') -ForegroundColor DarkCyan
            Get-Content -LiteralPath $Path -Encoding UTF8 -Tail $Lines | ForEach-Object { Write-Host $_ }
        }
    }
    catch { }
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

    # Reuse the certified Beta1 Windows hardening gate. Pytest temp is isolated,
    # and the child process is intentionally NOT invoked through a PowerShell
    # stderr-merging pipeline. Python UTF-8 mode is forced only for this child
    # tree so acceptance JSON containing Unicode cannot fail on Windows cp1252.
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
        if ($null -eq $PreviousPytestAddopts) { Remove-Item Env:PYTEST_ADDOPTS -ErrorAction SilentlyContinue }
        else { $env:PYTEST_ADDOPTS = $PreviousPytestAddopts }
        if ($null -eq $PreviousPythonUtf8) { Remove-Item Env:PYTHONUTF8 -ErrorAction SilentlyContinue }
        else { $env:PYTHONUTF8 = $PreviousPythonUtf8 }
        if ($null -eq $PreviousPythonIoEncoding) { Remove-Item Env:PYTHONIOENCODING -ErrorAction SilentlyContinue }
        else { $env:PYTHONIOENCODING = $PreviousPythonIoEncoding }
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

    # B2 live production Named Pipe: authenticated EDR reads, same-policy
    # privileged retention round-trip, native TEMP marker ingestion and
    # Security Center review-only visibility.
    $script:CurrentStage = 'b2_live_pre_restart'
    Remove-Item -LiteralPath $PreRestartPath -Force -ErrorAction SilentlyContinue
    & $Py -m tools.v011_beta2_b2_live_acceptance --mode pre-restart --output $PreRestartPath
    if ($LASTEXITCODE -ne 0) { throw 'B2 pre-restart production EDR IPC/native-ingestion acceptance failed' }
    $pre = Get-Content -Raw -LiteralPath $PreRestartPath -Encoding UTF8 | ConvertFrom-Json
    if (-not [bool]$pre.passed) { throw 'B2 pre-restart result is not PASS' }
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
