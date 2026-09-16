param(
    [switch]$ConfirmLivePowerShellControls,
    [Parameter(Mandatory=$true)][string]$Output,
    [ValidateRange(2, 12)][int]$QueryTimeoutSeconds = 8
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $ConfirmLivePowerShellControls) { throw 'Explicit B10-3 live PowerShell control confirmation required.' }

$logName = 'Windows PowerShell'
$provider = 'PowerShell'
$eventIds = @(400, 403)
$exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw 'Windows PowerShell executable unavailable.' }
try {
    $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
    if (-not [bool]$log.IsEnabled) { throw 'Windows PowerShell log is disabled.' }
    $null = Get-WinEvent -ListProvider $provider -ErrorAction Stop
}
catch { throw 'Required Windows PowerShell event source unavailable.' }

function Get-BaselineRecordId {
    try {
        $latest = @(Get-WinEvent -FilterHashtable @{ LogName=$logName; ProviderName=$provider; Id=$eventIds } -MaxEvents 1 -ErrorAction Stop)
        if ($latest.Count -gt 0 -and $null -ne $latest[0].RecordId) { return [long]$latest[0].RecordId }
    }
    catch {
        if ([string]$_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
    }
    return $null
}

function Invoke-Control([string]$ControlId, [int]$SessionCount, [bool]$KnownAdminAutomation, [bool]$UserBulk) {
    $baseline = Get-BaselineRecordId
    $launchedAt = [DateTime]::UtcNow
    $children = New-Object System.Collections.Generic.List[object]
    $pids = New-Object System.Collections.Generic.List[int]
    try {
        for ($i = 0; $i -lt $SessionCount; $i++) {
            $child = Start-Process -FilePath $exe -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-Command','exit 0') -WindowStyle Hidden -PassThru -ErrorAction Stop
            $children.Add($child)
            $pids.Add([int]$child.Id)
        }
        foreach ($child in $children) {
            if (-not $child.WaitForExit(10000)) { throw ('PowerShell control child timeout: ' + $ControlId) }
            if ([int]$child.ExitCode -ne 0) { throw ('PowerShell control child non-zero exit: ' + $ControlId) }
        }
    }
    finally {
        foreach ($child in $children) { $child.Dispose() }
    }
    $completedAt = [DateTime]::UtcNow
    $pidSet = @{}
    foreach ($id in $pids) { $pidSet[$id] = $true }

    $matched = @()
    $deadline = [DateTime]::UtcNow.AddSeconds($QueryTimeoutSeconds)
    do {
        Start-Sleep -Milliseconds 150
        try {
            $filter = @{ LogName=$logName; ProviderName=$provider; Id=$eventIds; StartTime=$launchedAt.AddSeconds(-2) }
            $matched = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 256 -ErrorAction Stop | Where-Object {
                $pidOk = ($null -ne $_.ProcessId -and $pidSet.ContainsKey([int]$_.ProcessId))
                $recordOk = ($null -eq $baseline -or ($null -ne $_.RecordId -and [long]$_.RecordId -gt $baseline))
                $pidOk -and $recordOk
            })
        }
        catch {
            if ([string]$_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
            $matched = @()
        }
        $starts = @($matched | Where-Object { [int]$_.Id -eq 400 }).Count
        $stops = @($matched | Where-Object { [int]$_.Id -eq 403 }).Count
        if ($starts -ge $SessionCount -and $stops -ge $SessionCount) { break }
    } while ([DateTime]::UtcNow -lt $deadline)

    $safeEvents = @($matched | Where-Object {
        $null -ne $_.TimeCreated -and $null -ne $_.RecordId -and $null -ne $_.ProcessId
    })
    $unique = @($safeEvents | ForEach-Object { [int]$_.ProcessId } | Sort-Object -Unique)
    $startCount = @($safeEvents | Where-Object { [int]$_.Id -eq 400 }).Count
    $stopCount = @($safeEvents | Where-Object { [int]$_.Id -eq 403 }).Count
    if ($unique.Count -lt $SessionCount -or $startCount -lt $SessionCount -or $stopCount -lt $SessionCount) {
        throw ('B10-3 did not observe complete lifecycle metadata for control ' + $ControlId)
    }

    return [ordered]@{
        control_id = $ControlId
        live_observation = $true
        channel = $logName
        provider = $provider
        session_count = $SessionCount
        start_event_count = $startCount
        stop_event_count = $stopCount
        unique_process_count = $unique.Count
        duration_seconds = [Math]::Round(($completedAt - $launchedAt).TotalSeconds, 6)
        known_admin_automation = $KnownAdminAutomation
        user_initiated_bulk_operation = $UserBulk
        started_at_utc = $launchedAt.ToString('o')
        completed_at_utc = $completedAt.ToString('o')
        cleanup_state = 'EXITED'
    }
}

$controls = @(
    Invoke-Control 'positive-powershell-burst' 8 $false $false
    Invoke-Control 'administrative-powershell-burst' 8 $true $true
    Invoke-Control 'benign-powershell-session' 1 $false $false
)

$report = [ordered]@{
    schema = 'bc-sentinel-beta10-powershell-live-controls-v1'
    source = 'WINDOWS_POWERSHELL_METADATA_LIVE_CONTROLS'
    controls = $controls
    boundaries = [ordered]@{
        local_only = $true
        explicit_opt_in_required = $true
        harmless_exercise_only = $true
        event_message_read = $false
        event_payload_read = $false
        event_properties_read = $false
        powershell_command_read = $false
        powershell_script_read = $false
        personal_data_collected = $false
        user_file_access = $false
        file_content_collected = $false
        absolute_paths_exported = $false
        remote_access = $false
        network_io = $false
        logging_configuration_mutation = $false
        audit_policy_mutation = $false
        registry_mutation = $false
        credential_access = $false
        real_malware_executed = $false
        product_process_launch_authority = $false
        product_process_termination_authority = $false
        remediation_authority = $false
        automatic_quarantine = $false
        privileged_system_mutation = $false
    }
}
$json = $report | ConvertTo-Json -Depth 8
$parent = Split-Path -Parent $Output
if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
[IO.File]::WriteAllText($Output, $json, (New-Object Text.UTF8Encoding($false)))
$json
