param(
    [switch]$NoInstall,
    [switch]$SelfCheckOnly
)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$StableCheckpoint = 'cf82b062ee8a95a116a449a0daf03bebd0b67cea'
$StableProfile = 'v0.11.0-beta.6-b60'

function Fail([string]$Stage, [string]$Message) {
    Write-Host ('BC SENTINEL STABLE FAIL STAGE=' + $Stage + ' | ' + $Message) -ForegroundColor Red
    exit 1
}

function Get-BasePython {
    $py = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($null -ne $py) {
        & $py.Source -3.12 -c "import sys; assert sys.version_info >= (3,12); print(sys.executable)" *> $null
        if ($LASTEXITCODE -eq 0) { return @($py.Source, '-3.12') }
    }

    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($null -ne $python) {
        & $python.Source -c "import sys; assert sys.version_info >= (3,12)" *> $null
        if ($LASTEXITCODE -eq 0) { return @($python.Source) }
    }

    throw 'Python 3.12+ not found. Install Python 3.12 and run this launcher again.'
}

try {
    if ($env:OS -ne 'Windows_NT') { Fail 'preflight' 'This stable launcher targets Windows.' }
    if (-not (Test-Path -LiteralPath '.\requirements.txt')) { Fail 'preflight' 'requirements.txt missing.' }
    if (-not (Test-Path -LiteralPath '.\sentinel\rescue_technician_ui.py')) { Fail 'preflight' 'Stable Technician UI source missing.' }
    if (-not (Test-Path -LiteralPath '.\sentinel\rescue_technician_ui_model.py')) { Fail 'preflight' 'Stable Technician UI model missing.' }
    if (-not (Test-Path -LiteralPath '.\sentinel\rescue_technician_portable.py')) { Fail 'preflight' 'Frozen Beta5 Technician engine missing.' }

    Write-Host 'BC Sentinel - Stable Technician Launcher' -ForegroundColor Cyan
    Write-Host ('PROFILE=' + $StableProfile + ' CHECKPOINT=' + $StableCheckpoint) -ForegroundColor DarkGray

    $VenvPython = '.\.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $VenvPython)) {
        Write-Host 'Creating local .venv with Python 3.12+...' -ForegroundColor Yellow
        $base = Get-BasePython
        if ($base.Count -eq 2) {
            & $base[0] $base[1] -m venv '.\.venv'
        } else {
            & $base[0] -m venv '.\.venv'
        }
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $VenvPython)) {
            Fail 'venv' 'Unable to create .venv.'
        }
    }

    if (-not $NoInstall) {
        & $VenvPython -c "import PySide6, psutil, watchdog, yara, pefile, cryptography; import win32api" *> $null
        if ($LASTEXITCODE -ne 0) {
            Write-Host 'Installing missing dependencies from requirements.txt...' -ForegroundColor Yellow
            Write-Host 'Network access is used only for dependency setup when packages are missing; Rescue runtime remains local.' -ForegroundColor DarkGray
            & $VenvPython -m pip install --disable-pip-version-check -r '.\requirements.txt'
            if ($LASTEXITCODE -ne 0) { Fail 'dependencies' 'pip install -r requirements.txt failed.' }
        }
    }

    Write-Host 'Running stable UI self-check...' -ForegroundColor DarkCyan
    & $VenvPython -m sentinel.rescue_technician_ui --self-check
    if ($LASTEXITCODE -ne 0) { Fail 'self-check' ('Technician UI self-check failed exit=' + $LASTEXITCODE) }

    if ($SelfCheckOnly) {
        Write-Host 'BC SENTINEL STABLE SELF-CHECK - PASS' -ForegroundColor Green
        exit 0
    }

    Write-Host 'Launching BC Sentinel Rescue Technician...' -ForegroundColor Green
    & $VenvPython -m sentinel.rescue_technician_ui
    if ($LASTEXITCODE -ne 0) { Fail 'launch' ('Technician UI exited with code ' + $LASTEXITCODE) }
    exit 0
}
catch {
    Fail 'unhandled' $_.Exception.Message
}
