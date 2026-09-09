param([switch]$Build)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

# Logging must never be able to abort setup/build.
$script:LogPath = Join-Path $PSScriptRoot "BC-Sentinel-install.log"

function Write-BCLog {
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$Message
    )

    try {
        if (-not [string]::IsNullOrWhiteSpace($script:LogPath)) {
            Add-Content `
                -Path $script:LogPath `
                -Value $Message `
                -ErrorAction SilentlyContinue
        }
    }
    catch {
        # Intentionally ignored: logging is non-critical.
    }
}

$Log = Join-Path $PSScriptRoot "BC-Sentinel-install.log"

try { Start-Transcript -Path $Log -Append | Out-Null } catch {}

function Finish-Log {
    try { Stop-Transcript | Out-Null } catch {}
}

function Fail([string]$Message) {
    Write-Host ""
    Write-Host "ERRORE: $Message" -ForegroundColor Red
    Write-Host "Log: $Log" -ForegroundColor Yellow
    Finish-Log
    Read-Host "Premi INVIO per chiudere"
    exit 1
}

try {
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "       BC Sentinel v0.6.1 Beta Setup" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan

    # Directly use the Python Launcher. This avoids PATH / Store alias issues.
    if (-not (Get-Command py.exe -ErrorAction SilentlyContinue)) {
        Fail "Python Launcher (py.exe) non trovato."
    }

    Write-Host "Verifico Python 3.12..." -ForegroundColor Cyan
    & py.exe -3.12 -c "import sys; print('Python', sys.version); print(sys.executable)"
    if ($LASTEXITCODE -ne 0) {
        Fail "py.exe è presente ma Python 3.12 non è disponibile."
    }

    # Recover from any broken venv created by previous attempts.
    if (Test-Path ".venv") {
        $valid = $false
        if (Test-Path ".venv\Scripts\python.exe") {
            try {
                & ".\.venv\Scripts\python.exe" -c "import sys; assert sys.version_info[:2] == (3,12)" *> $null
                if ($LASTEXITCODE -eq 0) { $valid = $true }
            } catch {}
        }
        if (-not $valid) {
            Write-Host "Rimuovo .venv precedente/non valida..." -ForegroundColor Yellow
            Remove-Item ".venv" -Recurse -Force
        }
    }

    if (-not (Test-Path ".venv\Scripts\python.exe")) {
        Write-Host "Creo .venv con Python 3.12..." -ForegroundColor Cyan
        & py.exe -3.12 -m venv .venv
        if ($LASTEXITCODE -ne 0) {
            Fail "Creazione .venv fallita."
        }
    }

    $venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
    if (-not (Test-Path $venvPython)) {
        Fail "python.exe non trovato dentro .venv."
    }

    Write-Host "Aggiorno pip..." -ForegroundColor Cyan
    & $venvPython -m pip install --upgrade pip setuptools wheel
    if ($LASTEXITCODE -ne 0) {
        Fail "Aggiornamento pip fallito."
    }

    Write-Host "Installo dipendenze principali..." -ForegroundColor Cyan
    & $venvPython -m pip install -r requirements-core.txt
    if ($LASTEXITCODE -ne 0) {
        Fail "Installazione dipendenze principali fallita."
    }

    Write-Host "Installo YARA (opzionale)..." -ForegroundColor Cyan
    & $venvPython -m pip install -r requirements-optional.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Host "YARA non disponibile: continuo senza YARA." -ForegroundColor Yellow
    }

    Write-Host "Installo ETW Python backend (opzionale)..." -ForegroundColor Cyan
    & $venvPython -m pip install -r requirements-etw.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Host "pywintrace non disponibile: uso fallback psutil/watchdog." -ForegroundColor Yellow
    }

    Write-Host "Installo notifiche Windows native (opzionale)..." -ForegroundColor Cyan
    & $venvPython -m pip install -r requirements-notifications.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Windows-Toasts non disponibile: uso la tray come fallback." -ForegroundColor Yellow
    }

    Write-Host "Installo supporto Windows Service (opzionale)..." -ForegroundColor Cyan
    & $venvPython -m pip install -r requirements-service.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Host "pywin32 non disponibile: il Protection Service non potra essere installato." -ForegroundColor Yellow
    }

    Write-Host "Verifico i moduli..." -ForegroundColor Cyan
    & $venvPython -c "import PySide6, psutil, watchdog, pefile, cryptography; print('Ambiente BC Sentinel OK')"
    if ($LASTEXITCODE -ne 0) {
        Fail "Verifica dipendenze fallita."
    }

    if ($Build) {
        Write-Host ""
        Write-Host "Eseguo i test..." -ForegroundColor Cyan

        $testOut = Join-Path $env:TEMP "bc-sentinel-pytest-out-$PID.txt"
        $testErr = Join-Path $env:TEMP "bc-sentinel-pytest-err-$PID.txt"
        Remove-Item $testOut,$testErr -ErrorAction SilentlyContinue

        $testProc = Start-Process `
            -FilePath $venvPython `
            -ArgumentList @("-m","pytest","-q") `
            -WorkingDirectory $PSScriptRoot `
            -NoNewWindow `
            -Wait `
            -PassThru `
            -RedirectStandardOutput $testOut `
            -RedirectStandardError $testErr

        if (Test-Path $testOut) {
            Get-Content $testOut | ForEach-Object {
                Write-Host $_
                Write-BCLog -Message ([string]$_)
            }
        }
        if (Test-Path $testErr) {
            Get-Content $testErr | ForEach-Object {
                Write-Host $_ -ForegroundColor Yellow
                Write-BCLog -Message ([string]$_)
            }
        }

        $testExit = $testProc.ExitCode
        Remove-Item $testOut,$testErr -ErrorAction SilentlyContinue

        if ($testExit -ne 0) {
            Fail "Test falliti. Build annullata."
        }

        Write-Host "Creo BC-Sentinel.exe..." -ForegroundColor Cyan
        $piArgs = @(
            "--noconfirm",
            "--clean",
            "--windowed",
            "--name", "BC-Sentinel",
            "--icon", (Join-Path $PSScriptRoot "app\assets\bc_sentinel.ico"),
            "--add-data", "rules;rules",
            "--add-data", "app\assets;app\assets"
        )

        & $venvPython -c "import etw" *> $null
        if ($LASTEXITCODE -eq 0) { $piArgs += @("--hidden-import","etw") }

        & $venvPython -c "import windows_toasts" *> $null
        if ($LASTEXITCODE -eq 0) { $piArgs += @("--collect-all","windows_toasts") }

        & ".\.venv\Scripts\pyinstaller.exe" @piArgs app\main.py
        if ($LASTEXITCODE -ne 0) {
            Fail "Build BC-Sentinel.exe fallita."
        }

        Write-Host "Creo BC-Sentinel-Protection.exe hardened..." -ForegroundColor Cyan
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "BUILD-SERVIZIO-PROTEZIONE.ps1")
        if ($LASTEXITCODE -ne 0) {
            Fail "Build hardened Protection Service fallita."
        }

        $output = Join-Path $PSScriptRoot "dist\BC-Sentinel\BC-Sentinel.exe"
        Write-Host ""
        Write-Host "BUILD COMPLETATA" -ForegroundColor Green
        Write-Host $output -ForegroundColor Green
        Finish-Log
        Start-Process explorer.exe (Split-Path $output -Parent)
        exit 0
    }

    Write-Host ""
    Write-Host "Avvio BC Sentinel..." -ForegroundColor Green

    $stdoutFile = Join-Path $env:TEMP "bc-sentinel-stdout-$PID.txt"
    $stderrFile = Join-Path $env:TEMP "bc-sentinel-stderr-$PID.txt"

    Remove-Item $stdoutFile,$stderrFile -ErrorAction SilentlyContinue

    $proc = Start-Process `
        -FilePath $venvPython `
        -ArgumentList "app\main.py" `
        -WorkingDirectory $PSScriptRoot `
        -NoNewWindow `
        -Wait `
        -PassThru `
        -RedirectStandardOutput $stdoutFile `
        -RedirectStandardError $stderrFile

    if (Test-Path $stdoutFile) {
        Get-Content $stdoutFile | ForEach-Object {
            Write-Host $_
            Write-BCLog -Message ([string]$_)
        }
    }

    if (Test-Path $stderrFile) {
        Get-Content $stderrFile | ForEach-Object {
            Write-Host $_ -ForegroundColor Red
            Write-BCLog -Message ([string]$_)
        }
    }

    $appExit = $proc.ExitCode
    Remove-Item $stdoutFile,$stderrFile -ErrorAction SilentlyContinue

    if ($appExit -ne 0) {
        Fail "L'app si è chiusa con codice $appExit."
    }

    Finish-Log
}
catch {
    Fail $_.Exception.Message
}
