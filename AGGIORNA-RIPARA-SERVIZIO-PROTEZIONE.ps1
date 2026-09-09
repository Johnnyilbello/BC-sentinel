param(
    [ValidateSet("Upgrade", "Repair")][string]$Mode = "Upgrade"
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Test-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Apply-ProtectedTreeAcl {
    param([Parameter(Mandatory=$true)][string]$InstallDir)
    & icacls.exe $InstallDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" "*S-1-5-32-545:(OI)(CI)(RX)" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "ACL root update fallita." }
    $children = Join-Path $InstallDir "*"
    if (Test-Path $children) {
        & icacls.exe $children /reset /T /C | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "ACL child update fallita." }
    }
    & icacls.exe $InstallDir /verify /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Verifica ACL update fallita." }
}

function Wait-ServiceStopped {
    param([string]$Name)
    for ($i=0; $i -lt 30; $i++) {
        $svc = Get-Service $Name -ErrorAction SilentlyContinue
        if (-not $svc -or $svc.Status -eq "Stopped") { return }
        Start-Sleep -Milliseconds 500
    }
    throw "Protection Service non si arresta per la transazione."
}

function Start-ServiceVerified {
    param([string]$Name)
    sc.exe start $Name | Out-Null
    for ($i=0; $i -lt 30; $i++) {
        Start-Sleep -Milliseconds 500
        $svc = Get-Service $Name -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") {
            Start-Sleep -Seconds 1
            $svc = Get-Service $Name -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq "Running") { return }
        }
    }
    throw "Protection Service non RUNNING/stabile dopo la transazione."
}

$nativePowerShell = Join-Path $PSHOME "powershell.exe"
if (-not (Test-Path $nativePowerShell)) { $nativePowerShell = "powershell.exe" }
if (-not (Test-Administrator)) {
    # No execution-policy relaxation: request elevation of this exact script only.
    $args = @("-NoProfile", "-File", "`"$PSCommandPath`"", "-Mode", $Mode)
    Start-Process -FilePath $nativePowerShell -Verb RunAs -ArgumentList $args
    exit
}

$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$source = Join-Path $PSScriptRoot "dist\BC-Sentinel-Protection"
$target = Join-Path $env:ProgramFiles "BC Sentinel\Protection"
$backupRoot = Join-Path $env:PROGRAMDATA "BCSentinel\Protection\Updates"
$serviceName = "BCSentinelProtection"
if (-not (Test-Path $python)) { throw ".venv non disponibile." }
if (-not (Test-Path (Join-Path $source "BC-Sentinel-Protection.exe"))) { throw "Build Protection Service non trovata." }
if (-not (Test-Path (Join-Path $source "BC-Sentinel-Broker\BC-Sentinel-Broker.exe"))) { throw "Build Privileged Broker non trovata." }
if (-not (Test-Path $target)) { throw "Installazione protetta corrente non trovata." }

$modeArg = $Mode.ToLowerInvariant()
$validationRaw = & $python -m tools.service_update validate --source $source --target $target --mode $modeArg
if ($LASTEXITCODE -ne 0) { throw "Validazione update/repair fallita: $validationRaw" }
$validation = $validationRaw | ConvertFrom-Json
Write-Host "BC Sentinel ${Mode}: $($validation.current_version) -> $($validation.target_version)" -ForegroundColor Cyan

try { sc.exe stop $serviceName | Out-Null } catch {}
Wait-ServiceStopped -Name $serviceName

$journal = $null
$applyCompleted = $false
try {
    $applyRaw = & $python -m tools.service_update apply --source $source --target $target --backup-root $backupRoot --mode $modeArg
    $applyExit = $LASTEXITCODE
    $apply = $null
    try { $apply = $applyRaw | ConvertFrom-Json } catch {}
    if ($apply -and $apply.journal) { $journal = [string]$apply.journal }

    if ($applyExit -ne 0) {
        $detail = if ($apply -and $apply.error) { [string]$apply.error } else { "Applicazione transazionale fallita." }
        # The Python transaction normally restores the old target itself. If an
        # interrupted promotion left target missing, schema-2 recovery is idempotent.
        if ($journal) {
            $recoverRaw = & $python -m tools.service_update recover --journal $journal
            if ($LASTEXITCODE -ne 0) { throw "Recovery helper fallito: $recoverRaw" }
        }
        $verifyRaw = & $python -m tools.service_update verify-current --target $target
        if ($LASTEXITCODE -ne 0) { throw "Installazione corrente non verificabile dopo errore apply: $verifyRaw" }
        Start-ServiceVerified -Name $serviceName
        throw $detail
    }

    $applyCompleted = $true
    Apply-ProtectedTreeAcl -InstallDir $target

    $deployed = Join-Path $target "BC-Sentinel-Protection.exe"
    & $deployed init-config
    if ($LASTEXITCODE -ne 0) { throw "Migrazione config post-update fallita." }
    & $deployed seal-integrity
    if ($LASTEXITCODE -ne 0) { throw "Sealing integrità post-update fallito." }
    & $deployed pipe-selftest
    if ($LASTEXITCODE -ne 0) { throw "Pipe self-test post-update fallito." }

    Start-ServiceVerified -Name $serviceName

    & $python -m tools.service_update mark --journal $journal --status completed | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Marcatura transazione completata fallita." }
    Write-Host "BC Sentinel $Mode completato con transazione verificata." -ForegroundColor Green
    sc.exe query $serviceName | Out-Host
}
catch {
    $failure = $_.Exception.Message
    Write-Warning "Update/repair fallito: $failure"

    if ($applyCompleted -and $journal) {
        try {
            try { sc.exe stop $serviceName | Out-Null } catch {}
            Wait-ServiceStopped -Name $serviceName
            $rollbackRaw = & $python -m tools.service_update rollback --journal $journal
            if ($LASTEXITCODE -ne 0) { throw "Rollback helper fallito: $rollbackRaw" }
            Apply-ProtectedTreeAcl -InstallDir $target
            $restored = Join-Path $target "BC-Sentinel-Protection.exe"
            & $restored seal-integrity
            if ($LASTEXITCODE -ne 0) { throw "Re-seal del rollback fallito." }
            Start-ServiceVerified -Name $serviceName
            Write-Host "Rollback alla versione precedente completato." -ForegroundColor Yellow
        } catch {
            throw "UPDATE FALLITO e rollback non completato: $failure / $($_.Exception.Message)"
        }
    }
    elseif (-not $applyCompleted) {
        # Early apply failures are permitted to restart only after the exact
        # current tree has passed authenticated integrity verification.
        $verifyRaw = & $python -m tools.service_update verify-current --target $target
        if ($LASTEXITCODE -eq 0) {
            $svc = Get-Service $serviceName -ErrorAction SilentlyContinue
            if (-not $svc -or $svc.Status -ne "Running") {
                Start-ServiceVerified -Name $serviceName
            }
        }
    }
    throw "Update/repair annullato: $failure"
}
