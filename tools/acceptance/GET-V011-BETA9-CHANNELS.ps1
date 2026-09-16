# Read only channel configuration; never access event records or messages.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$channels = @('System', 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-Windows Defender/Operational', 'Microsoft-Windows-Sysmon/Operational', 'Security')
$rows = @(foreach ($channel in $channels) {
    $enabled = $null
    $state = 'ERROR'
    try {
        $configuration = Get-WinEvent -ListLog $channel -ErrorAction Stop
        $enabled = [bool]$configuration.IsEnabled
        $state = if ($enabled) { 'AVAILABLE' } else { 'DISABLED' }
    }
    catch {
        # Fixed states only: raw errors can disclose local paths or identities.
        if ($_.CategoryInfo.Category -eq 'PermissionDenied' -or $_.Exception -is [System.UnauthorizedAccessException] -or $_.Exception.InnerException -is [System.UnauthorizedAccessException]) { $state = 'ACCESS_DENIED' }
        elseif ($_.FullyQualifiedErrorId -like 'NoMatchingLogsFound*') { $state = 'MISSING' }
    }
    [ordered]@{ channel = $channel; state = $state; enabled = $enabled }
})
[ordered]@{
    schema = 'bc-sentinel-beta9-channel-inventory-v1'
    source = 'WINDOWS_CHANNEL_CONFIGURATION'
    channels = $rows
    boundaries = [ordered]@{
        configuration_read_only = $true
        event_payload_read = $false
        personal_data_collected = $false
        channel_configuration_mutation = $false
        remediation_authority = $false
        verified_coverage = $false
    }
} | ConvertTo-Json -Depth 6
