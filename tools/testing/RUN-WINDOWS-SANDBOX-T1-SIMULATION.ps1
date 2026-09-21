param(
    [switch]$ConfirmDisposableSandbox,
    [switch]$AllowEquivalentDisposableVM,
    [string]$OutputRoot = ".\\pentest-evidence",
    [string]$SessionName = "windows-sandbox-t1"
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $ConfirmDisposableSandbox) {
    throw 'Explicit confirmation required: use -ConfirmDisposableSandbox only inside Windows Sandbox or an equivalent disposable VM.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\\..')).Path
Set-Location -LiteralPath $repoRoot

$isWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
if (-not $isWindows) {
    throw 'This runner is Windows-only.'
}

$isWindowsSandbox = [string]$env:USERNAME -ieq 'WDAGUtilityAccount'
if (-not $isWindowsSandbox -and -not $AllowEquivalentDisposableVM) {
    throw 'Windows Sandbox was not detected. Refusing to run. For an equivalent disposable VM, add -AllowEquivalentDisposableVM after verifying snapshot/revert and isolation.'
}

$commit = (& git rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Unable to resolve repository commit.'
}

$status = @(& git status --porcelain)
if ($status.Count -gt 0) {
    throw 'Repository has local changes. Start the sandbox battery from a clean tree.'
}

if ([IO.Path]::IsPathRooted($OutputRoot)) {
    $evidenceRoot = $OutputRoot
} else {
    $evidenceRoot = Join-Path $repoRoot $OutputRoot
}
New-Item -ItemType Directory -Path $evidenceRoot -Force | Out-Null

$startScript = Join-Path $repoRoot 'tools\\testing\\START-AUTHORIZED-PENTEST-SESSION.ps1'
$batteryScript = Join-Path $repoRoot 'tools\\testing\\RUN-AUTHORIZED-T1-BATTERY.ps1'
if (-not (Test-Path -LiteralPath $startScript -PathType Leaf)) {
    throw 'Authorized pentest session launcher missing.'
}
if (-not (Test-Path -LiteralPath $batteryScript -PathType Leaf)) {
    throw 'Authorized T1 battery missing.'
}

$safeName = ($SessionName -replace '[^A-Za-z0-9._-]', '_')
$before = @(
    Get-ChildItem -LiteralPath $evidenceRoot -Directory -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty FullName
)

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $startScript -Tier T1 -SessionName $safeName -OutputRoot $evidenceRoot
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to create the sandbox T1 session.'
}

$sessionCandidates = @(
    Get-ChildItem -LiteralPath $evidenceRoot -Directory -ErrorAction Stop |
        Where-Object {
            $before -notcontains $_.FullName -and
            $_.Name -like ('*-T1-' + $safeName)
        } |
        Sort-Object LastWriteTimeUtc -Descending
)
if ($sessionCandidates.Count -ne 1) {
    throw ('Expected exactly one new T1 session directory, found ' + $sessionCandidates.Count)
}

$sessionDir = $sessionCandidates[0].FullName
$manifest = Join-Path $sessionDir 'session.json'
if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
    throw 'Sandbox session manifest missing.'
}

Write-Host ('BC Sentinel sandbox T1 session: ' + $sessionDir)
Write-Host ('Repository commit: ' + $commit)
Write-Host ('Environment: ' + $(if ($isWindowsSandbox) { 'WINDOWS_SANDBOX' } else { 'EQUIVALENT_DISPOSABLE_VM' }))
Write-Host 'Safety boundary: inert T1 emulation only; no real malware, credential access, C2, propagation, real persistence, defense impairment, or user-file targeting.'

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $batteryScript -SessionDir $sessionDir -ConfirmAuthorizedT1
if ($LASTEXITCODE -ne 0) {
    throw 'Authorized sandbox T1 battery failed.'
}

$resultPath = Join-Path $sessionDir 'T1-BATTERY-RESULT.json'
if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
    throw 'Sandbox T1 result file missing.'
}

$result = Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8 | ConvertFrom-Json
if (-not [bool]$result.passed) {
    throw 'Sandbox T1 result did not pass.'
}
if ([bool]$result.safety.real_malware_executed -or
    [bool]$result.safety.network_io_required -or
    [bool]$result.safety.credential_access -or
    [bool]$result.safety.real_persistence_mutation -or
    [bool]$result.safety.security_control_impairment -or
    [bool]$result.safety.user_file_access) {
    throw 'Sandbox T1 safety contract was violated.'
}

Write-Host ('Evidence: ' + $resultPath)
Write-Host 'BC SENTINEL WINDOWS SANDBOX AUTHORIZED T1 SIMULATION - PASS'
