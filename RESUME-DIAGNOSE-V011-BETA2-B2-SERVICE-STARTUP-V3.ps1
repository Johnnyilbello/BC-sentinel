param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Fail([string]$Message) {
    Write-Host 'BC SENTINEL v0.11.0-beta.2 B2 SERVICE STARTUP DIAGNOSTIC V3 - FAIL' -ForegroundColor Red
    Write-Host $Message -ForegroundColor Red
    exit 1
}

function Download-RequiredFile([string]$Destination,[string]$Uri) {
    $parent = Split-Path -Parent $Destination
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    Write-Host ('Downloading: ' + $Uri) -ForegroundColor DarkGray
    Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $Destination -ErrorAction Stop
}

function Get-BcService {
    $items = @(Get-CimInstance Win32_Service | Where-Object {
        ($_.PathName -match 'BC-Sentinel-Protection\.exe') -or
        ($_.Name -match '(?i)BC.*Sentinel.*Protection') -or
        ($_.DisplayName -match '(?i)BC.*Sentinel.*Protection')
    })
    if ($items.Count -eq 0) { return $null }
    $exact = @($items | Where-Object { $_.PathName -match 'BC-Sentinel-Protection\.exe' })
    if ($exact.Count -eq 1) { return $exact[0] }
    return $items[0]
}

function Service-Snapshot([string]$Name) {
    $svc = Get-CimInstance Win32_Service -Filter ("Name='" + $Name.Replace("'","''") + "'")
    if ($null -eq $svc) { return $null }
    [ordered]@{
        name = [string]$svc.Name
        display_name = [string]$svc.DisplayName
        state = [string]$svc.State
        status = [string]$svc.Status
        start_mode = [string]$svc.StartMode
        process_id = [int]$svc.ProcessId
        exit_code = [int]$svc.ExitCode
        service_specific_exit_code = [int]$svc.ServiceSpecificExitCode
        path_name = [string]$svc.PathName
        timestamp = (Get-Date).ToString('o')
    }
}

function Collect-EventEvidence([string]$ServiceName,[datetime]$Since) {
    $system = @()
    $application = @()
    try {
        $system = @(Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$Since} -ErrorAction SilentlyContinue |
            Where-Object { $_.ProviderName -eq 'Service Control Manager' -and ($_.Message -match [regex]::Escape($ServiceName) -or $_.Message -match 'BC Sentinel') } |
            Select-Object -First 30 @{n='time';e={$_.TimeCreated.ToString('o')}},Id,LevelDisplayName,ProviderName,Message)
    } catch { }
    try {
        $application = @(Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$Since} -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -match 'BC-Sentinel-Protection|BC Sentinel' } |
            Select-Object -First 30 @{n='time';e={$_.TimeCreated.ToString('o')}},Id,LevelDisplayName,ProviderName,Message)
    } catch { }
    [ordered]@{ system = $system; application = $application }
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this diagnostic from normal PowerShell; UAC is requested only if one controlled service start/restart is needed.'
    }
    if (-not (Test-Path -LiteralPath '.\.venv\Scripts\python.exe')) { throw '.venv not available' }

    $Py = '.\.venv\Scripts\python.exe'
    $PatchRef = 'f7b40ffdbfcd223a949d547aab495529ab44fb74'
    $DiagRef = 'ea5bc44f2bfc272d62718c79f8ac4613b96613b0'
    $PinnedRef = '6d833d08912b64bd0d14d4f21d7838a3718c40f7'
    $RepoRaw = 'https://raw.githubusercontent.com/Johnnyilbello/BC-sentinel/'
    $Started = Get-Date

    Write-Host 'BC Sentinel v0.11.0-beta.2 - SERVICE STARTUP / NAMED PIPE DIAGNOSTIC V3' -ForegroundColor Cyan
    Write-Host 'First checks for a post-deploy startup race. If needed, performs one controlled UAC start/restart and captures service/event evidence.' -ForegroundColor Yellow

    Download-RequiredFile '.\tools\v011_beta2_b2_service_startup_probe.py' ($RepoRaw + $PatchRef + '/tools/v011_beta2_b2_service_startup_probe.py')
    Download-RequiredFile '.\tools\v011_beta2_b2_live_acceptance.py' ($RepoRaw + $PinnedRef + '/tools/v011_beta2_b2_live_acceptance.py')
    Download-RequiredFile '.\tools\v011_beta2_b2_trace_probe.py' ($RepoRaw + $DiagRef + '/tools/v011_beta2_b2_trace_probe.py')
    Download-RequiredFile '.\tools\v011_beta2_b2_path_alias_probe.py' ($RepoRaw + $DiagRef + '/tools/v011_beta2_b2_path_alias_probe.py')

    $service = Get-BcService
    if ($null -eq $service) { throw 'BC Sentinel Protection Service could not be discovered in Win32_Service.' }
    $serviceName = [string]$service.Name
    Write-Host (('SERVICE DISCOVERED: name={0} | display={1} | state={2} | pid={3}') -f $service.Name,$service.DisplayName,$service.State,$service.ProcessId) -ForegroundColor Cyan

    $before = Service-Snapshot $serviceName
    $before | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath '.\acceptance-v011-beta2-b2-service-state-before.json' -Encoding UTF8

    Write-Host 'Polling named pipe for up to 20 seconds before changing service state...' -ForegroundColor DarkCyan
    & $Py -m tools.v011_beta2_b2_service_startup_probe --timeout-seconds 20 --interval-seconds 0.5 --output acceptance-v011-beta2-b2-service-startup-initial.json
    $initialReady = ($LASTEXITCODE -eq 0)

    if (-not $initialReady) {
        $mid = Service-Snapshot $serviceName
        Write-Host (('PIPE STILL ABSENT: service state={0} | pid={1} | exit={2} | svcExit={3}') -f $mid.state,$mid.process_id,$mid.exit_code,$mid.service_specific_exit_code) -ForegroundColor Yellow

        $helper = Join-Path $env:TEMP ('bcs-service-start-' + [guid]::NewGuid().ToString('N') + '.ps1')
        $helperResult = Join-Path $env:TEMP ('bcs-service-start-result-' + [guid]::NewGuid().ToString('N') + '.json')
        $helperText = @'
param([string]$ServiceName,[string]$ResultPath)
$ErrorActionPreference='Stop'
$result=[ordered]@{ok=$false;action='';before='';after='';error=''}
try {
  $svc=Get-Service -Name $ServiceName -ErrorAction Stop
  $result.before=[string]$svc.Status
  if ($svc.Status -eq 'Running') { $result.action='restart'; Restart-Service -Name $ServiceName -Force -ErrorAction Stop }
  else { $result.action='start'; Start-Service -Name $ServiceName -ErrorAction Stop }
  $svc=Get-Service -Name $ServiceName -ErrorAction Stop
  $svc.WaitForStatus('Running',[TimeSpan]::FromSeconds(15))
  $svc=Get-Service -Name $ServiceName -ErrorAction Stop
  $result.after=[string]$svc.Status
  $result.ok=($svc.Status -eq 'Running')
} catch { $result.error=$_.Exception.Message }
$result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
if (-not $result.ok) { exit 2 }
'@
        Set-Content -LiteralPath $helper -Value $helperText -Encoding UTF8
        Write-Host 'Requesting one controlled service start/restart through UAC...' -ForegroundColor Yellow
        $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $helper + '"'),'-ServiceName',('"' + $serviceName + '"'),'-ResultPath',('"' + $helperResult + '"'))
        $p = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList $args
        if (Test-Path -LiteralPath $helperResult) {
            $helperData = Get-Content -Raw -LiteralPath $helperResult -Encoding UTF8 | ConvertFrom-Json
            Write-Host (('SERVICE UAC ACTION: action={0} | before={1} | after={2} | ok={3} | error={4}') -f $helperData.action,$helperData.before,$helperData.after,$helperData.ok,$helperData.error) -ForegroundColor Cyan
        }
        Remove-Item -LiteralPath $helper -Force -ErrorAction SilentlyContinue

        Write-Host 'Polling named pipe for 30 seconds after controlled service action...' -ForegroundColor DarkCyan
        & $Py -m tools.v011_beta2_b2_service_startup_probe --timeout-seconds 30 --interval-seconds 0.5 --output acceptance-v011-beta2-b2-service-startup-after-action.json
        $afterActionReady = ($LASTEXITCODE -eq 0)
        if (-not $afterActionReady) {
            $afterFail = Service-Snapshot $serviceName
            $events = Collect-EventEvidence $serviceName $Started
            $evidence = [ordered]@{
                profile = 'v0.11.0-beta.2-service-startup-evidence-v1'
                passed = $false
                service_before = $before
                service_after = $afterFail
                event_logs = $events
                initial_probe = if (Test-Path '.\acceptance-v011-beta2-b2-service-startup-initial.json') { Get-Content -Raw '.\acceptance-v011-beta2-b2-service-startup-initial.json' | ConvertFrom-Json } else { $null }
                after_action_probe = if (Test-Path '.\acceptance-v011-beta2-b2-service-startup-after-action.json') { Get-Content -Raw '.\acceptance-v011-beta2-b2-service-startup-after-action.json' | ConvertFrom-Json } else { $null }
            }
            $evidence | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath '.\acceptance-v011-beta2-b2-service-startup-evidence.json' -Encoding UTF8
            Write-Host (('FINAL SERVICE STATE: state={0} | pid={1} | exit={2} | svcExit={3}') -f $afterFail.state,$afterFail.process_id,$afterFail.exit_code,$afterFail.service_specific_exit_code) -ForegroundColor Red
            Write-Host 'Evidence saved: acceptance-v011-beta2-b2-service-startup-evidence.json' -ForegroundColor Yellow
            throw 'Named pipe remained unavailable after bounded startup wait and one controlled service action.'
        }
    }

    $ready = Service-Snapshot $serviceName
    Write-Host (('NAMED PIPE READY: service state={0} | pid={1} | exit={2}') -f $ready.state,$ready.process_id,$ready.exit_code) -ForegroundColor Green

    Write-Host 'Running multi-root marker trace probe...' -ForegroundColor Cyan
    & $Py -m tools.v011_beta2_b2_trace_probe --poll-seconds 12 --output acceptance-v011-beta2-b2-marker-trace-probe-v3.json
    if ($LASTEXITCODE -ne 0) { throw 'Marker trace probe failed after named-pipe readiness.' }

    Write-Host 'Running Windows short-path/long-path alias probe...' -ForegroundColor Cyan
    & $Py -m tools.v011_beta2_b2_path_alias_probe --poll-seconds 10 --output acceptance-v011-beta2-b2-path-alias-probe-v3.json
    if ($LASTEXITCODE -ne 0) { throw 'Path alias probe failed after named-pipe readiness.' }

    $trace = Get-Content -Raw '.\acceptance-v011-beta2-b2-marker-trace-probe-v3.json' -Encoding UTF8 | ConvertFrom-Json
    $alias = Get-Content -Raw '.\acceptance-v011-beta2-b2-path-alias-probe-v3.json' -Encoding UTF8 | ConvertFrom-Json
    Write-Host '--- AUTOMATIC ROOT-CAUSE SUMMARY ---' -ForegroundColor Cyan
    foreach ($property in $trace.records.PSObject.Properties) {
        $r = $property.Value
        Write-Host (('- {0}: diagnosis={1} | last={2} | trace={3} | hunt={4} | timeline={5}') -f $property.Name,$r.diagnosis,$r.last_stage,$r.trace_count,$r.hunt.count,$r.timeline.match_count) -ForegroundColor Green
    }
    Write-Host ('PATH ALIAS DIAGNOSIS: ' + [string]$alias.diagnosis) -ForegroundColor Green
    Write-Host (('EDR INGEST DELTA DURING ALIAS PROBE: {0}') -f [int]$alias.status.service_ingested_delta) -ForegroundColor Green
    Write-Host 'BC SENTINEL v0.11.0-beta.2 B2 SERVICE STARTUP DIAGNOSTIC V3 - COMPLETE' -ForegroundColor Green
    exit 0
}
catch { Fail $_.Exception.Message }
