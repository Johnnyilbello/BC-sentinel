param(
    [switch]$ConfirmHarmlessEventExercise,
    [ValidateRange(1, 10)][int]$QueryTimeoutSeconds = 8
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $ConfirmHarmlessEventExercise) {
    throw 'Explicit harmless event exercise confirmation is required.'
}

$logName = 'Windows PowerShell'
$provider = 'PowerShell'
$eventIds = @(400, 403)

try {
    $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
    if (-not [bool]$log.IsEnabled) { throw 'B9-2 classic PowerShell log is disabled.' }
    $null = Get-WinEvent -ListProvider $provider -ErrorAction Stop
}
catch {
    throw 'B9-2 required classic PowerShell event source is unavailable.'
}

$baselineRecordId = $null
try {
    $baseline = @(Get-WinEvent -FilterHashtable @{ LogName = $logName; ProviderName = $provider; Id = $eventIds } -MaxEvents 1 -ErrorAction Stop)
    if ($baseline.Count -gt 0 -and $null -ne $baseline[0].RecordId) {
        $baselineRecordId = [long]$baseline[0].RecordId
    }
}
catch {
    $id = [string]$_.FullyQualifiedErrorId
    if ($id -notlike 'NoMatchingEventsFound*') {
        throw 'B9-2 baseline event metadata query failed.'
    }
}

$exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw 'B9-2 Windows PowerShell executable unavailable.' }

$launchedAt = [DateTime]::UtcNow
$child = $null
try {
    $child = Start-Process -FilePath $exe -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'exit 0') -WindowStyle Hidden -PassThru -ErrorAction Stop
    $childPid = [int]$child.Id
    $exited = $child.WaitForExit(10000)
    if (-not $exited) {
        throw 'B9-2 harmless child did not exit within its bounded lifetime.'
    }
    $exitCode = [int]$child.ExitCode
    if ($exitCode -ne 0) { throw 'B9-2 harmless child returned a non-zero exit code.' }
}
finally {
    if ($null -ne $child) { $child.Dispose() }
}
$completedAt = [DateTime]::UtcNow

$matched = $null
$deadline = [DateTime]::UtcNow.AddSeconds($QueryTimeoutSeconds)
do {
    Start-Sleep -Milliseconds 150
    try {
        $filter = @{
            LogName = $logName
            ProviderName = $provider
            Id = $eventIds
            StartTime = $launchedAt.AddSeconds(-2)
        }
        $candidates = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 64 -ErrorAction Stop | Where-Object {
            $pidMatches = ($null -ne $_.ProcessId -and [int]$_.ProcessId -eq $childPid)
            $recordIsFresh = ($null -eq $baselineRecordId -or ($null -ne $_.RecordId -and [long]$_.RecordId -gt $baselineRecordId))
            $pidMatches -and $recordIsFresh
        } | Sort-Object RecordId)
        if ($candidates.Count -gt 0) {
            $matched = $candidates[0]
            break
        }
    }
    catch {
        $id = [string]$_.FullyQualifiedErrorId
        if ($id -notlike 'NoMatchingEventsFound*') {
            throw 'B9-2 bounded fresh-event query failed.'
        }
    }
} while ([DateTime]::UtcNow -lt $deadline)

if ($null -eq $matched) {
    throw 'B9-2 did not observe a fresh engine lifecycle event bound to the harmless child process.'
}
if ($null -eq $matched.TimeCreated -or $null -eq $matched.RecordId -or $null -eq $matched.ProcessId) {
    throw 'B9-2 matched event lacks required safe metadata.'
}

[ordered]@{
    schema = 'bc-sentinel-beta9-harmless-event-v1'
    source = 'WINDOWS_POWERSHELL_ENGINE_LIVE_EXERCISE'
    exercise = [ordered]@{
        live_observation = $true
        child_process_id = $childPid
        baseline_record_id = $baselineRecordId
        launched_at_utc = $launchedAt.ToString('o')
        completed_at_utc = $completedAt.ToString('o')
        cleanup_state = 'EXITED'
        exit_code = $exitCode
    }
    event = [ordered]@{
        channel = [string]$matched.LogName
        provider = [string]$matched.ProviderName
        event_id = [int]$matched.Id
        level = if ($null -eq $matched.Level) { $null } else { [int]$matched.Level }
        record_id = [long]$matched.RecordId
        process_id = [int]$matched.ProcessId
        time_created_utc = $matched.TimeCreated.ToUniversalTime().ToString('o')
    }
    boundaries = [ordered]@{
        local_only = $true
        explicit_opt_in_required = $true
        harmless_exercise_only = $true
        event_message_read = $false
        event_payload_read = $false
        event_properties_read = $false
        personal_data_collected = $false
        remote_access = $false
        logging_configuration_mutation = $false
        audit_policy_mutation = $false
        elevation_requested = $false
        product_process_launch_authority = $false
        product_process_termination_authority = $false
        remediation_authority = $false
        threat_classification = $false
        verified_coverage = $false
    }
} | ConvertTo-Json -Depth 6
