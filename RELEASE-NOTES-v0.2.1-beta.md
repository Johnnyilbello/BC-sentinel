# BC Sentinel v0.2.1-beta

## Privileged Telemetry Service
BC Sentinel now separates privileged Windows telemetry from the desktop UI.

- `BC Sentinel` desktop UI runs normally as the signed-in user.
- `BC Sentinel Telemetry` is an optional Windows Service installed once with UAC.
- The service runs ETW process/file telemetry and persistence observation.
- The UI communicates over a loopback-only authenticated, read-only protocol.
- A random telemetry secret is stored under `%PROGRAMDATA%\BCSentinel`.
- The install script restricts the secret ACL to SYSTEM, Administrators and the
  installing user.
- If the service is unavailable, BC Sentinel stays functional with
  psutil/watchdog and local persistence fallback.

The service never accepts shell execution, file deletion, quarantine or process
termination commands from the UI protocol.

## Activity timeline
New **Attività** page:
- timeline for process → file → behavior events;
- process name;
- PID;
- category and action;
- touched resource;
- score;
- selected-event process tree / parent chain;
- subtle fade animation when telemetry updates;
- subtle correlation/detail animation.

## Security UI
- green `Telemetria avanzata attiva` state when privileged ETW is connected;
- amber `Fallback locale attivo` state when safe fallback is in use;
- one-click `Installa servizio telemetria` button prompts UAC only for the
  one-time service installation;
- ransomware/threat details can use privileged service attribution.

## Windows taskbar icon
- QApplication icon is set explicitly;
- the main window icon is set explicitly;
- Windows AppUserModelID is set for correct taskbar grouping/icon behavior;
- the PyInstaller executable continues to embed the `.ico` resource.

## Build
`CREA-EXE.bat` now builds both:
- `dist\BC-Sentinel\BC-Sentinel.exe`
- `dist\BC-Sentinel-Telemetry\BC-Sentinel-Telemetry.exe`

Use `INSTALLA-SERVIZIO-TELEMETRIA.bat` once after building, or directly during
source testing after `INSTALLA-E-AVVIA.bat`.

The UI should not be routinely run as Administrator.
