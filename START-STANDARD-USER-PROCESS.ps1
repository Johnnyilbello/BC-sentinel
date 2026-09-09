param(
    [Parameter(Mandatory=$true)][string]$FilePath,
    [Parameter(Mandatory=$true)][string]$ArgumentList,
    [Parameter(Mandatory=$true)][string]$WorkingDirectory
)
$ErrorActionPreference = "Stop"

# ADMIN-only acceptance helper.
# A temporary Scheduled Task is registered for the currently interactive user
# with RunLevel=Limited and LogonType=Interactive. This delegates token creation
# to the Windows Task Scheduler instead of trying to manufacture a filtered
# token with CreateProcessWithTokenW. The child acceptance script still verifies
# is_admin=false independently before it can report PASS.

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$principalNow = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $principalNow.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Questo launcher deve essere avviato dal test ADMIN."
}

Import-Module ScheduledTasks -ErrorAction Stop

$interactiveUser = $null
try {
    $interactiveUser = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName
} catch {}
if ([string]::IsNullOrWhiteSpace($interactiveUser)) {
    $interactiveUser = $id.Name
}
if ([string]::IsNullOrWhiteSpace($interactiveUser)) {
    throw "Utente interattivo non determinabile; impossibile creare il processo standard-user."
}

$taskName = "BCSentinel-StdUAC-" + [guid]::NewGuid().ToString("N")
$action = New-ScheduledTaskAction -Execute $FilePath -Argument $ArgumentList -WorkingDirectory $WorkingDirectory
$taskPrincipal = New-ScheduledTaskPrincipal -UserId $interactiveUser -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

try {
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $taskPrincipal -Settings $settings -Force -ErrorAction Stop | Out-Null
    $registered = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    if ($registered.Principal.RunLevel -ne "Limited") {
        throw "Il task standard-user non risulta registrato con RunLevel Limited."
    }
    Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
    Write-Output $taskName
} catch {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    throw
}
