param(
    [switch]$ConfirmBoundedMetadataRead,
    [ValidateRange(1, 8)][int]$MaxEvents = 4,
    [ValidateRange(1, 10)][int]$TimeoutSeconds = 5
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $ConfirmBoundedMetadataRead) {
    throw 'Explicit bounded metadata read confirmation is required.'
}

$profiles = @(
    [ordered]@{
        profile_id = 'system-kernel-general'
        channel = 'System'
        provider = 'Microsoft-Windows-Kernel-General'
        event_ids = @(12, 13)
    },
    [ordered]@{
        profile_id = 'powershell-operational'
        channel = 'Microsoft-Windows-PowerShell/Operational'
        provider = 'Microsoft-Windows-PowerShell'
        event_ids = @(4103, 4104)
    },
    [ordered]@{
        profile_id = 'defender-operational'
        channel = 'Microsoft-Windows-Windows Defender/Operational'
        provider = 'Microsoft-Windows-Windows Defender'
        event_ids = @(1000, 1001, 1002, 1116, 1117)
    },
    [ordered]@{
        profile_id = 'sysmon-operational'
        channel = 'Microsoft-Windows-Sysmon/Operational'
        provider = 'Microsoft-Windows-Sysmon'
        event_ids = @(1, 3, 7, 11)
    },
    [ordered]@{
        profile_id = 'security-auditing'
        channel = 'Security'
        provider = 'Microsoft-Windows-Security-Auditing'
        event_ids = @(4624, 4625)
    }
)

function Get-FixedFailureState {
    param($ErrorRecord)
    if ($ErrorRecord.CategoryInfo.Category -eq 'PermissionDenied' -or
        $ErrorRecord.Exception -is [System.UnauthorizedAccessException] -or
        $ErrorRecord.Exception.InnerException -is [System.UnauthorizedAccessException]) {
        return 'ACCESS_DENIED'
    }
    $id = [string]$ErrorRecord.FullyQualifiedErrorId
    if ($id -like 'NoMatchingLogsFound*' -or $id -like 'NoMatchingProvidersFound*') {
        return 'UNSUPPORTED'
    }
    return 'ERROR'
}

$rows = @(foreach ($profile in $profiles) {
    $status = $null
    $events = @()

    try {
        $log = Get-WinEvent -ListLog $profile.channel -ErrorAction Stop
        if (-not [bool]$log.IsEnabled) {
            $status = 'UNSUPPORTED'
        }
    }
    catch {
        $status = Get-FixedFailureState $_
    }

    if ($null -eq $status) {
        try {
            $null = Get-WinEvent -ListProvider $profile.provider -ErrorAction Stop
        }
        catch {
            $status = Get-FixedFailureState $_
        }
    }

    if ($null -eq $status) {
        $job = Start-Job -ScriptBlock {
            param($channel, $provider, $eventIds, $maxEvents)
            $ErrorActionPreference = 'Stop'
            $safeEvents = @()
            $fixedStatus = 'ERROR'
            try {
                $filter = @{ LogName = $channel; ProviderName = $provider; Id = $eventIds }
                $rawEvents = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $maxEvents -ErrorAction Stop)
                $safeEvents = @($rawEvents | ForEach-Object {
                    [ordered]@{
                        channel = [string]$_.LogName
                        provider = [string]$_.ProviderName
                        event_id = [int]$_.Id
                        level = if ($null -eq $_.Level) { $null } else { [int]$_.Level }
                        record_id = if ($null -eq $_.RecordId) { $null } else { [long]$_.RecordId }
                        time_created_utc = $_.TimeCreated.ToUniversalTime().ToString('o')
                    }
                })
                $fixedStatus = if ($safeEvents.Count -gt 0) { 'OK' } else { 'EMPTY' }
            }
            catch {
                $id = [string]$_.FullyQualifiedErrorId
                if ($_.CategoryInfo.Category -eq 'PermissionDenied' -or
                    $_.Exception -is [System.UnauthorizedAccessException] -or
                    $_.Exception.InnerException -is [System.UnauthorizedAccessException]) {
                    $fixedStatus = 'ACCESS_DENIED'
                }
                elseif ($id -like 'NoMatchingEventsFound*') {
                    $fixedStatus = 'EMPTY'
                }
                elseif ($id -like 'NoMatchingLogsFound*' -or $id -like 'NoMatchingProvidersFound*') {
                    $fixedStatus = 'UNSUPPORTED'
                }
            }
            [ordered]@{ status = $fixedStatus; events = $safeEvents } | ConvertTo-Json -Depth 4 -Compress
        } -ArgumentList $profile.channel, $profile.provider, @($profile.event_ids), $MaxEvents

        try {
            $completed = Wait-Job -Job $job -Timeout $TimeoutSeconds
            if ($null -eq $completed) {
                Stop-Job -Job $job -ErrorAction SilentlyContinue
                $status = 'TIMEOUT'
                $events = @()
            }
            else {
                $safeJson = @(Receive-Job -Job $job -ErrorAction SilentlyContinue) | Select-Object -Last 1
                if ([string]::IsNullOrWhiteSpace([string]$safeJson)) {
                    $status = 'ERROR'
                    $events = @()
                }
                else {
                    try {
                        $safeResult = $safeJson | ConvertFrom-Json -ErrorAction Stop
                        $status = [string]$safeResult.status
                        $events = @($safeResult.events)
                    }
                    catch {
                        $status = 'ERROR'
                        $events = @()
                    }
                }
            }
        }
        finally {
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }

    [ordered]@{
        profile_id = $profile.profile_id
        channel = $profile.channel
        provider = $profile.provider
        event_ids = @($profile.event_ids)
        max_events = $MaxEvents
        timeout_seconds = $TimeoutSeconds
        status = $status
        events = @($events)
    }
})

[ordered]@{
    schema = 'bc-sentinel-beta9-event-metadata-v1'
    source = 'WINDOWS_EVENT_METADATA_BOUNDED'
    profiles = $rows
    boundaries = [ordered]@{
        local_only = $true
        explicit_opt_in_required = $true
        bounded_event_count = $true
        bounded_query_timeout = $true
        event_message_read = $false
        event_payload_read = $false
        personal_data_collected = $false
        remote_access = $false
        logging_configuration_mutation = $false
        detector_classification = $false
        remediation_authority = $false
        verified_coverage = $false
    }
} | ConvertTo-Json -Depth 8
