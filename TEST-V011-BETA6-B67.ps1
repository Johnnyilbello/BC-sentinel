param(
    [switch]$ConfirmPortableGuiAcceptance,
    [switch]$OpenArtifactUI,
    [string]$Output = ".\acceptance-v011-beta6-b67-artifact.json"
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = "1"

function Fail([string]$Stage, [string]$Message) {
    Write-Host ("B67 FAIL STAGE=" + $Stage + " | " + $Message) -ForegroundColor Red
    Write-Host "BC SENTINEL v0.11.0-beta.6 B6-7 PORTABLE TECHNICIAN GUI RELEASE - FAIL" -ForegroundColor Red
    exit 1
}

if (-not $ConfirmPortableGuiAcceptance) {
    Fail "preflight" "B6-7 requires -ConfirmPortableGuiAcceptance."
}

try {
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
    if ($Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Fail "preflight" "Run B6-7 from normal non-elevated PowerShell. The portable GUI must not require elevation."
    }

    $RepoRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
    $VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $VenvPython -PathType Leaf) { $Py = $VenvPython }
    else {
        $PythonCommand = Get-Command python -ErrorAction SilentlyContinue
        if (-not $PythonCommand) { Fail "preflight" "Python non disponibile." }
        $Py = $PythonCommand.Source
    }

    & $Py -c "import pytest, PyInstaller, PySide6" 2>$null
    if ($LASTEXITCODE -ne 0) { Fail "preflight" "pytest/PyInstaller/PySide6 non disponibili nel Python selezionato." }

    $Branch = (& git branch --show-current | Select-Object -First 1)
    $Commit = (& git rev-parse HEAD | Select-Object -First 1)
    Write-Host ""
    Write-Host "## BC Sentinel B6-7 - Portable Technician GUI Release Acceptance"
    Write-Host ("Branch: " + $Branch)
    Write-Host ("Commit: " + $Commit)
    Write-Host ""

    $Protected = @(
        ".\sentinel\protection_service_core.py",
        ".\sentinel\realtime.py",
        ".\sentinel\edr.py",
        ".\sentinel\edr_service_bridge.py"
    )
    $BeforeProtected = @{}
    foreach ($Path in $Protected) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Fail "protected-preflight" ("protected B2 source missing: " + $Path) }
        $BeforeProtected[$Path] = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    $Base = Join-Path $env:USERPROFILE "BCSentinel-TestTemp"
    New-Item -ItemType Directory -Path $Base -Force | Out-Null
    $PytestBase = Join-Path $Base ("b67-pytest-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $PytestBase -Force | Out-Null

    Write-Host "[1/6] Compile B6-7 packaging/acceptance code..."
    & $Py -m compileall -q `
        sentinel\portable_gui_release.py `
        packaging\beta6_portable_gui_entry.py `
        tools\v011_beta6_b67_artifact_acceptance.py `
        tests\test_v011_beta6_b67_portable_gui.py
    if ($LASTEXITCODE -ne 0) { Fail "compileall" "B6-7 compileall failed." }
    Write-Host "Compile gate: PASS" -ForegroundColor Green
    Write-Host ""

    Write-Host "[2/6] Complete deterministic predecessor regression (Beta5 + Beta6) + B6-7 tests..."
    try {
        $Beta5Tests = @(Get-ChildItem -LiteralPath ".\tests" -Filter "test_v011_beta5_*.py" -File | Sort-Object Name | ForEach-Object { $_.FullName })
        $Beta6Tests = @(Get-ChildItem -LiteralPath ".\tests" -Filter "test_v011_beta6_*.py" -File | Sort-Object Name | ForEach-Object { $_.FullName })
        if ($Beta5Tests.Count -eq 0) { Fail "pytest" "No Beta5 predecessor tests discovered." }
        if ($Beta6Tests.Count -eq 0) { Fail "pytest" "No Beta6 tests discovered." }
        Write-Host ("Beta5 tests files: " + $Beta5Tests.Count + " | Beta6 test files: " + $Beta6Tests.Count) -ForegroundColor DarkCyan
        & $Py -m pytest -q --basetemp $PytestBase @Beta5Tests @Beta6Tests
        if ($LASTEXITCODE -ne 0) { Fail "pytest" "Beta5/Beta6/B6-7 deterministic regression failed." }
    }
    finally {
        Remove-Item -LiteralPath $PytestBase -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host "Deterministic predecessor + B6-7 gate: PASS" -ForegroundColor Green
    Write-Host ""

    Write-Host "[3/6] Build reale PyInstaller onedir/windowed..."
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\BUILD-V011-BETA6-B67-PORTABLE-GUI.ps1"
    if ($LASTEXITCODE -ne 0) { Fail "build" "B6-7 PyInstaller GUI build failed." }

    $ArtifactFolder = Join-Path $RepoRoot "dist\Beta6\BC-Sentinel-Beta6-Portable"
    $Exe = Join-Path $ArtifactFolder "BC-Sentinel-Beta6-Portable.exe"
    $Manifest = Join-Path $ArtifactFolder "portable-gui-integrity.json"
    if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) { Fail "build" "Portable GUI EXE missing." }
    if (-not (Test-Path -LiteralPath $Manifest -PathType Leaf)) { Fail "build" "Portable GUI integrity manifest missing." }
    $ExeHash = (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLowerInvariant()
    $M = Get-Content -Raw -LiteralPath $Manifest -Encoding UTF8 | ConvertFrom-Json
    if ([string]$M.sha256 -ne $ExeHash) { Fail "manifest" "EXE SHA-256 does not match manifest." }
    if ([string]$M.profile -ne "v0.11.0-beta.6-b67-portable-gui") { Fail "manifest" "Unexpected B6-7 build profile." }
    if ([string]$M.build_commit -ne [string]$Commit) { Fail "manifest" "Manifest build commit does not match tested checkout." }
    if ([string]$M.build_mode -ne "onedir" -or -not [bool]$M.windowed -or -not [bool]$M.portable) { Fail "manifest" "Artifact is not onedir/windowed/portable." }
    if ([bool]$M.installer_required -or [bool]$M.service_install -or [bool]$M.driver_install) { Fail "manifest" "Installer/service/driver requirement appeared." }
    if ([bool]$M.network_required -or [bool]$M.cloud_required) { Fail "manifest" "Network/cloud requirement appeared." }
    if ([bool]$M.general_home_execution_authorized -or [bool]$M.automatic_quarantine -or [bool]$M.automatic_restore -or [bool]$M.automatic_repair -or [bool]$M.delete_authorized -or [bool]$M.repair_authorized) { Fail "manifest" "Unexpected remediation authority appeared." }
    Write-Host ("Built EXE SHA256: " + $ExeHash) -ForegroundColor Green
    Write-Host ""

    Write-Host "[4/6] Acceptance dell'artefatto copiato fuori dalla directory di build..."
    & $Py -m tools.v011_beta6_b67_artifact_acceptance `
        --artifact-dir $ArtifactFolder `
        --expected-build-commit $Commit `
        --output $Output
    if ($LASTEXITCODE -ne 0) { Fail "artifact-acceptance" ("B6-7 built artifact acceptance failed. Evidence: " + $Output) }
    $A = Get-Content -Raw -LiteralPath $Output -Encoding UTF8 | ConvertFrom-Json
    if (-not [bool]$A.passed) { Fail "artifact-acceptance" "B6-7 artifact payload reports passed=false." }
    if (-not [bool]$A.checks.portable_copy_integrity) { Fail "artifact-acceptance" "Portable copy integrity failed." }
    if (-not [bool]$A.checks.gui_offscreen_smoke_exit_zero) { Fail "artifact-acceptance" "Built GUI offscreen smoke failed." }
    if (-not [bool]$A.checks.runtime_contract_passed) { Fail "artifact-acceptance" "Built GUI safety/capability contract failed." }
    if (-not [bool]$A.checks.target_byte_identical) { Fail "artifact-acceptance" "Read-only artifact workflow modified target fixture." }
    Write-Host "Portable copied-artifact GUI acceptance: PASS" -ForegroundColor Green
    Write-Host ""

    Write-Host "[5/6] Verify no service registration and protected B2 sources unchanged..."
    $Services = @(Get-CimInstance Win32_Service | Where-Object {
        ([string]$_.PathName).ToLowerInvariant().Contains("bc-sentinel-beta6-portable") -or
        ([string]$_.PathName).ToLowerInvariant().Contains("beta6_portable_gui_entry")
    })
    if ($Services.Count -ne 0) { Fail "service-check" "B6-7 unexpectedly registered a Windows service." }
    foreach ($Path in $Protected) {
        $After = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($After -ne $BeforeProtected[$Path]) { Fail "protected-source" ("B6-7 modified protected B2 source: " + $Path) }
    }
    Write-Host "No service + protected B2 sources byte-identical: PASS" -ForegroundColor Green
    Write-Host ""

    if ($OpenArtifactUI) {
        Write-Host "[6/6] Apertura dell'artefatto GUI reale..." -ForegroundColor Cyan
        Write-Host "Chiudi normalmente BC Sentinel dopo la verifica visiva per completare il gate." -ForegroundColor Cyan

        # The artifact itself does not require a historical runtime to start.
        # For local visual acceptance only, reuse the pinned historical runtime
        # if the same previously accepted scanner can be found on this PC.
        $ExpectedScannerSha = "7874df734f6146f8848d8a55f5eb6be37bb5cbaee1638e051357f978f5275433"
        $Downloads = Join-Path $env:USERPROFILE "Downloads"
        $ScannerPath = $null
        if (Test-Path -LiteralPath $Downloads -PathType Container) {
            $Candidates = @(& where.exe /R "$Downloads" scanner.py 2>$null)
            $ScannerPath = ($Candidates | Where-Object { $_ -match "\\sentinel\\scanner\.py$" -and $_ -like "*Consolidation_FULL*" } | Select-Object -First 1)
        }
        if ($ScannerPath) {
            $ActualScannerSha = (Get-FileHash -LiteralPath $ScannerPath -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($ActualScannerSha -eq $ExpectedScannerSha) {
                $RuntimeRoot = Split-Path -Parent (Split-Path -Parent $ScannerPath)
                $env:BC_SENTINEL_FULL_RUNTIME_ROOT = $RuntimeRoot
                $env:BC_SENTINEL_FULL_RUNTIME_SCANNER_SHA256 = $ExpectedScannerSha
                $RuntimePython = Join-Path $RuntimeRoot ".venv\Scripts\python.exe"
                if (Test-Path -LiteralPath $RuntimePython -PathType Leaf) { $env:BC_SENTINEL_FULL_RUNTIME_PYTHON = $RuntimePython }
                Write-Host "Pinned historical Smart Scan runtime attached for visual acceptance." -ForegroundColor DarkCyan
            }
        }
        Remove-Item Env:QT_QPA_PLATFORM -ErrorAction SilentlyContinue
        $UiProcess = Start-Process -FilePath $Exe -PassThru -Wait
        if ($UiProcess.ExitCode -ne 0) { Fail "artifact-ui" ("Built GUI exited with code " + $UiProcess.ExitCode) }
        Write-Host "Built GUI opened and closed normally: PASS" -ForegroundColor Green
    } else {
        Write-Host "[6/6] Real UI opening not requested; automated built-artifact smoke already PASS." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host ("B67 ARTIFACT=" + $ArtifactFolder) -ForegroundColor Green
    Write-Host ("B67 EXE SHA256=" + $ExeHash) -ForegroundColor Green
    Write-Host "B67: Beta5 predecessor tests PASS | Beta6 tests PASS | PyInstaller onedir/windowed PASS | copied artifact integrity PASS | GUI smoke PASS | exact runtime safety contract PASS | target byte-identical | no service/installer/driver/network/cloud requirement | B2 sources unchanged" -ForegroundColor Green
    Write-Host "BC SENTINEL v0.11.0-beta.6 B6-7 PORTABLE TECHNICIAN GUI RELEASE - PASS" -ForegroundColor Green
    exit 0
}
catch {
    Fail "unhandled" $_.Exception.Message
}
