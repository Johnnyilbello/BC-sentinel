param(
    [switch]$Remove
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Test-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-IcaclsChecked {
    param(
        [Parameter(Mandatory=$true)][string[]]$Arguments,
        [Parameter(Mandatory=$true)][string]$Description
    )
    & icacls.exe @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "ACL hardening fallito ($Description), icacls exit code $LASTEXITCODE."
    }
}

function Repair-TreeAclForAdministrators {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Description
    )
    if (-not (Test-Path $Path)) { return }
    # Locale-neutral recovery.  Do not pass a localized TAKEOWN default-answer flag; the expected response token varies by Windows language.
    # First take ownership through icacls, then give SYSTEM/Admins direct Full
    # Control on every existing object so a broken inherited ACL cannot strand
    # an old service DB/key or frozen binary.
    & icacls.exe $Path /setowner "*S-1-5-32-544" /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Owner recovery parziale ($Description); provo comunque il grant ACL diretto."
    }
    & icacls.exe $Path /grant:r "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Riparazione ACL fallita ($Description)."
    }
}


function Repair-KnownProgramDataStateFiles {
    param([Parameter(Mandatory=$true)][string]$ProtectionDir)
    # Some v0.6.1 prereleases could leave individual service-owned files with
    # protected DACLs that an elevated administrator could not rewrite using
    # icacls /setowner alone. TAKEOWN is used only on explicit BC Sentinel
    # paths and never with localized /D answers. This enables SeTakeOwnership
    # for the target object, after which SYSTEM/Admin full-control is restored.
    $known = @(
        "quarantine.key",
        "sentinel-service.db",
        "sentinel-service.db-wal",
        "sentinel-service.db-shm",
        "protection.secret",
        "protection-integrity.key",
        "protection-integrity.sig",
        "protection-config.json",
        "protection-config.sig",
        "service-audit.jsonl",
        "service-audit.chain"
    )
    foreach ($name in $known) {
        $item = Join-Path $ProtectionDir $name
        if (-not (Test-Path -LiteralPath $item)) { continue }
        & takeown.exe /F $item /A | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Ownership recovery non riuscita per $item; provo comunque ACL SYSTEM/Admin."
        }
        & icacls.exe $item /inheritance:r /grant:r "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Riparazione ACL del file persistente fallita: $item"
        }
        try { Get-Acl -LiteralPath $item -ErrorAction Stop | Out-Null } catch {
            throw "Il file persistente resta non interrogabile dopo recovery ACL: $item"
        }
    }
}

function Remove-InstallTreeSafely {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path $Path)) { return }
    try {
        Remove-Item $Path -Recurse -Force -ErrorAction Stop
        return
    } catch {
        Write-Warning "ACL del precedente deployment non permettono la rimozione normale; riparo solo il tree BC Sentinel e riprovo."
    }
    Repair-TreeAclForAdministrators -Path $Path -Description "Program Files legacy tree"
    Remove-Item $Path -Recurse -Force -ErrorAction Stop
}

function Show-ServiceStartDiagnostics {
    param([string]$ServiceName)
    Write-Host "Diagnostica avvio Protection Service:" -ForegroundColor Yellow
    try { sc.exe query $ServiceName | Out-Host } catch {}
    try {
        Get-WinEvent -FilterHashtable @{
            LogName = "Application"
            StartTime = (Get-Date).AddMinutes(-8)
        } -ErrorAction Stop |
            Where-Object {
                $_.ProviderName -match 'Python|BC Sentinel' -or
                $_.Message -match 'BCSentinelProtection|BC Sentinel Protection|ProtectionRuntime'
            } |
            Select-Object -First 12 TimeCreated, ProviderName, Id, LevelDisplayName, Message |
            Format-List | Out-Host
    } catch {
        Write-Host "Nessun evento Application specifico leggibile." -ForegroundColor DarkYellow
    }
    try {
        Get-WinEvent -FilterHashtable @{
            LogName = "System"
            ProviderName = "Service Control Manager"
            StartTime = (Get-Date).AddMinutes(-8)
        } -ErrorAction Stop |
            Where-Object { $_.Message -match 'BCSentinelProtection|BC Sentinel Protection' } |
            Select-Object -First 8 TimeCreated, Id, LevelDisplayName, Message |
            Format-List | Out-Host
    } catch {}
}

if (-not (Test-Administrator)) {
    $args = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
    if ($Remove) { $args += "-Remove" }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $args
    exit
}

$serviceName = "BCSentinelProtection"
$builtDir = Join-Path $PSScriptRoot "dist\BC-Sentinel-Protection"
$built = Join-Path $builtDir "BC-Sentinel-Protection.exe"
$installDir = Join-Path $env:ProgramFiles "BC Sentinel\Protection"
$deployed = Join-Path $installDir "BC-Sentinel-Protection.exe"
$protectionDir = Join-Path $env:PROGRAMDATA "BCSentinel\Protection"
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentSid = $currentIdentity.User.Value

function Remove-ServiceRegistration {
    try { sc.exe stop $serviceName 2>$null | Out-Null } catch {}
    for ($i = 0; $i -lt 20; $i++) {
        $svc = Get-Service $serviceName -ErrorAction SilentlyContinue
        if (-not $svc -or $svc.Status -eq "Stopped") { break }
        Start-Sleep -Milliseconds 500
    }
    try { sc.exe delete $serviceName 2>$null | Out-Null } catch {}
    for ($i = 0; $i -lt 20; $i++) {
        if (-not (Get-Service $serviceName -ErrorAction SilentlyContinue)) { break }
        Start-Sleep -Milliseconds 500
    }
}

if ($Remove) {
    Write-Host "Arresto e rimuovo BC Sentinel Protection..." -ForegroundColor Yellow
    Remove-ServiceRegistration
    if (Test-Path $installDir) {
        try { Remove-InstallTreeSafely -Path $installDir } catch {
            Write-Warning "Impossibile rimuovere subito tutti i binari protetti: $($_.Exception.Message)"
        }
    }
    Write-Host "Servizio e binari rimossi. I dati in ProgramData vengono preservati." -ForegroundColor Green
    exit
}

if (-not (Test-Path $built)) {
    throw "Protection Service compilato non trovato. Eseguire prima .\BUILD-SERVIZIO-PROTEZIONE.ps1."
}
if (-not (Test-Path (Join-Path $builtDir "protection-integrity.json"))) {
    throw "Manifest protection-integrity.json non trovato. Ricostruire il servizio con BUILD-SERVIZIO-PROTEZIONE.ps1."
}
if (-not (Test-Path (Join-Path $builtDir "BC-Sentinel-Broker\BC-Sentinel-Broker.exe"))) {
    throw "Privileged Broker compilato non trovato. Ricostruire con BUILD-SERVIZIO-PROTEZIONE.ps1."
}

# Never run the service from Downloads/a developer-writable tree. Stop/delete
# the previous registration, then deploy the entire PyInstaller onedir image to
# Program Files before installing it with SCM.
Remove-ServiceRegistration
$staging = "$installDir.staging-$PID"
Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $staging | Out-Null
Copy-Item -Path (Join-Path $builtDir "*") -Destination $staging -Recurse -Force
if (Test-Path $installDir) { Remove-InstallTreeSafely -Path $installDir }
Move-Item -Path $staging -Destination $installDir

# Immutable install tree: set inheritable ACLs on the root directory only.
# Then reset child ACLs so files/directories inherit from that hardened root.
# Do NOT recursively pass (OI)(CI) grants to files: those inheritance flags
# are directory semantics and can leave a frozen onedir payload non-executable
# when inheritance has already been stripped.
$installSystem = "*S-1-5-18:(OI)(CI)(F)"
$installAdmins = "*S-1-5-32-544:(OI)(CI)(F)"
$installUsers = "*S-1-5-32-545:(OI)(CI)(RX)"
Invoke-IcaclsChecked -Description "Program Files root" -Arguments @(
    $installDir, "/inheritance:r", "/grant:r", $installSystem, $installAdmins, $installUsers
)
$installChildren = Join-Path $installDir "*"
if (Test-Path $installChildren) {
    Invoke-IcaclsChecked -Description "Program Files child inheritance" -Arguments @(
        $installChildren, "/reset", "/T", "/C"
    )
}
& icacls.exe $installDir /verify /T /C | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Verifica ACL del deployment Protection Service fallita." }

if (-not (Test-Path $deployed)) { throw "Deployment in Program Files incompleto." }

New-Item -ItemType Directory -Force -Path $protectionDir | Out-Null
# v0.6.1-beta.1 could leave existing DB/quarantine/key objects with unusable
# ACLs. Repair the service-owned ProgramData tree before applying the final
# hardened inheritance model. This is intentionally limited to our own path.
if (Test-Path (Join-Path $protectionDir "*")) {
    # First recover the exact runtime-critical files that old prereleases could
    # strand. Then do best-effort tree recovery for the remaining BC Sentinel
    # state. The explicit-file step is what guarantees DB/quarantine bootstrap.
    Repair-KnownProgramDataStateFiles -ProtectionDir $protectionDir
    Repair-TreeAclForAdministrators -Path $protectionDir -Description "ProgramData Protection legacy state"
}
# Users may traverse the service data directory but do not inherit read access
# to DB/quarantine/keys. The installing interactive user receives read access
# only to the IPC token below.
$dataSystem = "*S-1-5-18:(OI)(CI)(F)"
$dataAdmins = "*S-1-5-32-544:(OI)(CI)(F)"
$dataUserTraverse = "*$currentSid`:(RX)"
Invoke-IcaclsChecked -Description "ProgramData Protection root" -Arguments @(
    $protectionDir, "/inheritance:r", "/grant:r", $dataSystem, $dataAdmins, $dataUserTraverse
)
# Remove stale inherited read grants from v0.6.x data/quarantine/DB. Children
# are reset to inherit only SYSTEM/Admins because the interactive user's RX ACE
# on the parent is deliberately non-inheritable.
$dataChildren = Join-Path $protectionDir "*"
if (Test-Path $dataChildren) {
    Invoke-IcaclsChecked -Description "ProgramData child inheritance" -Arguments @(
        $dataChildren, "/reset", "/T", "/C"
    )
}
# Fail installation before service registration if the two runtime-critical
# legacy objects are still inaccessible to an elevated administrator. SYSTEM
# receives Full Control through the same DACL model.
foreach ($criticalState in @("quarantine.key", "sentinel-service.db")) {
    $criticalPath = Join-Path $protectionDir $criticalState
    if (Test-Path -LiteralPath $criticalPath) {
        try { Get-Acl -LiteralPath $criticalPath -ErrorAction Stop | Out-Null } catch {
            throw "ACL recovery incompleta per $criticalPath"
        }
    }
}

try {
    & $deployed init-config
} catch {
    $bootstrapError = $_.Exception.Message
    Write-Host "ACL del binario distribuito:" -ForegroundColor Yellow
    & icacls.exe $deployed | Out-Host
    Write-Host "Eventuali blocchi Code Integrity recenti:" -ForegroundColor Yellow
    try {
        Get-WinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-CodeIntegrity/Operational"
            StartTime = (Get-Date).AddMinutes(-5)
        } -ErrorAction Stop | Select-Object -First 8 TimeCreated, Id, LevelDisplayName, Message | Format-List | Out-Host
    } catch {
        Write-Host "Nessun evento Code Integrity leggibile nel periodo." -ForegroundColor DarkYellow
    }
    throw "Bootstrap del Protection Service non eseguibile dopo il deployment: $bootstrapError"
}
if ($LASTEXITCODE -ne 0) { throw "Inizializzazione/migrazione configurazione Protection Service fallita." }

# Apply strict file ACLs after keys/config exist. Only the IPC token is readable
# by the interactive user; the integrity HMAC key is machine-private.
foreach ($name in @("protection-integrity.key", "protection-config.json", "protection-config.sig")) {
    $path = Join-Path $protectionDir $name
    if (Test-Path $path) {
        & icacls.exe $path /inheritance:r /grant:r "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" | Out-Null
    }
}
$tokenPath = Join-Path $protectionDir "protection.secret"
if (Test-Path $tokenPath) {
    & icacls.exe $tokenPath /inheritance:r /grant:r "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" "*$currentSid`:(R)" | Out-Null
}

# Authenticate the build manifest only after deployment + ACL hardening. The
# runtime refuses to start when the authenticated immutable tree is modified.
& $deployed seal-integrity
if ($LASTEXITCODE -ne 0) { throw "Sealing del manifest di integrità fallito." }
& $deployed pipe-selftest
if ($LASTEXITCODE -ne 0) { throw "Self-test Named Pipe del Protection Service fallito." }

Write-Host "Configuro BC Sentinel Protection v0.6.2..." -ForegroundColor Cyan
& $deployed --startup auto install
if ($LASTEXITCODE -ne 0) { throw "Installazione servizio fallita." }

# Conservative recovery: restart twice with increasing delays; reset the
# failure counter daily. Never create an infinite rapid crash loop.
sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/15000 | Out-Null
sc.exe failureflag $serviceName 1 | Out-Null
try { sc.exe sidtype $serviceName unrestricted | Out-Null } catch {}

& $deployed start
if ($LASTEXITCODE -ne 0) {
    Show-ServiceStartDiagnostics -ServiceName $serviceName
    throw "Avvio servizio fallito."
}
# pywin32 can return from the start command before the service finishes its
# runtime bootstrap.  Do not report success unless SCM still sees RUNNING.
$running = $false
for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Milliseconds 500
    $svc = Get-Service $serviceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        # Require stability for one additional observation; this catches a
        # service that reaches RUNNING and immediately exits during bootstrap.
        Start-Sleep -Milliseconds 750
        $svc = Get-Service $serviceName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") { $running = $true; break }
    }
}
if (-not $running) {
    Show-ServiceStartDiagnostics -ServiceName $serviceName
    throw "BC Sentinel Protection non e rimasto RUNNING dopo il bootstrap."
}
sc.exe query $serviceName | Out-Host
sc.exe qc $serviceName | Out-Host

Write-Host ""
Write-Host "BC Sentinel Protection v0.6.2 installato in Program Files, ACL hardened e AUTO_START." -ForegroundColor Green
Write-Host "IPC token/HMAC separati; UAC broker one-action installato e service state/quarantine restano protetti." -ForegroundColor Green
